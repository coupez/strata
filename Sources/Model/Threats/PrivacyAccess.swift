import AppKit
import Foundation
import SQLite3

struct PrivacyGrant: Hashable, Sendable, Identifiable {
    enum Service: String, CaseIterable, Identifiable, Sendable {
        case screen = "kTCCServiceScreenCapture"
        case keystrokes = "kTCCServiceListenEvent"
        case accessibility = "kTCCServiceAccessibility"
        case camera = "kTCCServiceCamera"
        case microphone = "kTCCServiceMicrophone"

        var id: String { rawValue }

        var title: String {
            switch self {
            case .screen: "Screen Recording"
            case .keystrokes: "Input Monitoring"
            case .accessibility: "Accessibility"
            case .camera: "Camera"
            case .microphone: "Microphone"
            }
        }

        var symbol: String {
            switch self {
            case .screen: "rectangle.dashed.badge.record"
            case .keystrokes: "keyboard"
            case .accessibility: "accessibility"
            case .camera: "camera.fill"
            case .microphone: "mic.fill"
            }
        }

        var settingsAnchor: String {
            switch self {
            case .screen: "Privacy_ScreenCapture"
            case .keystrokes: "Privacy_ListenEvent"
            case .accessibility: "Privacy_Accessibility"
            case .camera: "Privacy_Camera"
            case .microphone: "Privacy_Microphone"
            }
        }

        /// Can see what you type or what's on screen, the permissions spyware needs.
        var canWatch: Bool { self == .screen || self == .keystrokes || self == .accessibility }
    }

    let client: String
    let isPath: Bool
    let service: Service

    var id: String { service.rawValue + client }
}

/// Reads macOS's privacy database. Needs Full Disk Access; returns nil without it.
enum PrivacyAccess {
    static func databases(home: String = NSHomeDirectory()) -> [URL] {
        [URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db"),
         URL(fileURLWithPath: "/Library/Application Support/com.apple.TCC/TCC.db")]
    }

    static func load(from databases: [URL]) -> [PrivacyGrant]? {
        var grants = Set<PrivacyGrant>()
        var readAny = false
        for url in databases {
            guard let rows = read(url) else { continue }
            readAny = true
            grants.formUnion(rows)
        }
        guard readAny else { return nil }
        return grants.sorted { ($0.client, $0.service.rawValue) < ($1.client, $1.service.rawValue) }
    }

    private static func read(_ url: URL) -> [PrivacyGrant]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            sqlite3_close(db)
            return nil
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 500)
        let services = PrivacyGrant.Service.allCases.map { "'\($0.rawValue)'" }.joined(separator: ",")
        let sql = "SELECT client, client_type, service FROM access WHERE auth_value = 2 AND service IN (\(services))"
        var statement: OpaquePointer?
        // A schema change or missing permission shows up here; treat it as unreadable.
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(statement) }
        var rows: [PrivacyGrant] = []
        var step = sqlite3_step(statement)
        while step == SQLITE_ROW {
            defer { step = sqlite3_step(statement) }
            guard let client = sqlite3_column_text(statement, 0), let service = sqlite3_column_text(statement, 2),
                  let kind = PrivacyGrant.Service(rawValue: String(cString: service)) else { continue }
            rows.append(PrivacyGrant(client: String(cString: client), isPath: sqlite3_column_int(statement, 1) == 1, service: kind))
        }
        // A busy or locked database must not look like "no grants".
        return step == SQLITE_DONE ? rows : nil
    }

    static func resolveApp(_ id: String) -> URL? { NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) }

    /// Where the client lives on disk, or nil if it's gone.
    static func location(of grant: PrivacyGrant, resolve: (String) -> URL?) -> String? {
        if grant.isPath { return DirectorySizer.exists(grant.client) ? grant.client : nil }
        return resolve(grant.client)?.path
    }

    /// Untrusted programs that can see your screen or keystrokes. A program that can't be safely removed
    /// (a folder, a system or package-manager file) gets no hit, though its grant is still listed.
    static func hits(_ grants: [PrivacyGrant], resolve: (String) -> URL?, signature: (String) -> Signature) -> [ThreatHit] {
        let watching = Dictionary(grouping: grants.filter { $0.service.canWatch }, by: \.client)
        return watching.keys.sorted().compactMap { client in
            let clientGrants = watching[client] ?? []
            guard let first = clientGrants.first, let path = location(of: first, resolve: resolve) else { return nil }
            let clientSignature = signature(path)
            guard !clientSignature.isTrusted,
                  let target = Heuristics.removalTarget(forProgram: path, orBundle: true) else { return nil }
            let services = clientGrants.map(\.service.title).sorted().joined(separator: ", ")
            return ThreatHit(paths: [target], verdict: .suspicious, reason: "\(clientSignature.summary) and allowed to use \(services)",
                             title: (target as NSString).lastPathComponent)
        }
    }

    static func openSettings(for service: PrivacyGrant.Service) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(service.settingsAnchor)") {
            NSWorkspace.shared.open(url)
        }
    }
}
