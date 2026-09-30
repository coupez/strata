import Foundation
import SwiftUI

enum FindingGroup: String, CaseIterable, Identifiable, Sendable {
    case threat, unused, bloatware, leftover, background

    var id: String { rawValue }
    var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }

    var title: String {
        switch self {
        case .threat: "Threats"
        case .unused: "Unused apps"
        case .bloatware: "Bloatware"
        case .leftover: "Leftovers"
        case .background: "Background items"
        }
    }

    var caption: String {
        switch self {
        case .threat: "Matches Apple's malware rules, known adware, or behaves like it."
        case .unused: "Apps you haven't opened in a while, with their support files."
        case .bloatware: "Optional apps and content that came with your Mac."
        case .leftover: "Files and launch items from apps that are already gone."
        case .background: "Everything else that starts on its own. Remove only what you recognize."
        }
    }

    var symbol: String {
        switch self {
        case .threat: "exclamationmark.shield.fill"
        case .unused: "moon.zzz.fill"
        case .bloatware: "shippingbox.fill"
        case .leftover: "tray.full.fill"
        case .background: "gearshape.2.fill"
        }
    }

    var tint: Color {
        switch self {
        case .threat: .red
        case .unused: .indigo
        case .bloatware: .orange
        case .leftover: .teal
        case .background: .gray
        }
    }
}

enum Verdict: Int, Comparable, Sendable {
    case suspicious, adware, malicious

    static func < (lhs: Verdict, rhs: Verdict) -> Bool { lhs.rawValue < rhs.rawValue }

    var label: String {
        switch self {
        case .suspicious: "Suspicious"
        case .adware: "Adware"
        case .malicious: "Malicious"
        }
    }

    var color: Color {
        switch self {
        case .suspicious: .yellow
        case .adware: .orange
        case .malicious: .red
        }
    }
}

struct FindingPart: Identifiable, Hashable, Sendable {
    enum Kind: Hashable, Sendable {
        case app, support, file
        case launchItem(label: String, domain: LaunchDomain)
    }

    let url: URL
    let size: Int64
    let kind: Kind

    var id: String { url.path }

    var isLaunchItem: Bool {
        guard case .launchItem = kind else { return false }
        return true
    }
}

struct Finding: Identifiable, Hashable, Sendable {
    let id: String
    var group: FindingGroup
    var verdict: Verdict? = nil
    let title: String
    var reasons: [String]
    /// A path whose Finder icon represents this finding.
    let iconPath: String?
    var parts: [FindingPart]
    var risk: Risk
    var lastUsed: Date? = nil
    var isRunning = false

    var size: Int64 { parts.reduce(0) { $0 + $1.size } }

    /// Only confirmed threats and launch items that can't run anyway start ticked.
    var preselected: Bool {
        if let verdict { return verdict >= .adware }
        return group == .leftover && parts.allSatisfy(\.isLaunchItem)
    }

    func contains(_ path: String) -> Bool {
        parts.contains { path == $0.url.path || path.hasPrefix($0.url.path + "/") }
    }
}

struct ThreatHit: Hashable, Sendable {
    /// What to remove; the first path is the thing the hit is about.
    let paths: [String]
    let verdict: Verdict
    let reason: String
    let title: String

    var primary: String { paths.first ?? "" }
}
