import Foundation

enum LaunchDomain: String, Hashable, Sendable {
    case userAgent, systemAgent, systemDaemon

    var title: String {
        switch self {
        case .userAgent: "Starts when you log in"
        case .systemAgent: "Starts when anyone logs in"
        case .systemDaemon: "Runs in the background as root"
        }
    }
}

struct LaunchItem: Hashable, Sendable {
    let plist: URL
    let label: String
    let domain: LaunchDomain
    /// Absolute path of the program launchd starts, when it could be worked out.
    let program: String?
    /// Arguments after the program itself.
    let arguments: [String]
    let associatedBundleID: String?
    let runsAtLoad: Bool
    /// Points at a program (or app) that no longer exists, so it can never run.
    let isOrphaned: Bool

    /// When it runs: the domain's title only applies to items that start on their own.
    var schedule: String {
        if runsAtLoad { return domain.title }
        return domain == .systemDaemon ? "Runs on demand as root" : "Runs on demand"
    }
}

enum LaunchItems {
    static func standardDirectories(home: String = NSHomeDirectory()) -> [(URL, LaunchDomain)] {
        [
            (URL(fileURLWithPath: home).appendingPathComponent("Library/LaunchAgents"), .userAgent),
            (URL(fileURLWithPath: "/Library/LaunchAgents"), .systemAgent),
            (URL(fileURLWithPath: "/Library/LaunchDaemons"), .systemDaemon),
        ]
    }

    /// `resolveBundle` maps a bundle ID to where that app is installed (for `BundleProgram`).
    static func load(from directories: [(URL, LaunchDomain)], resolveBundle: (String) -> URL?) -> [LaunchItem] {
        directories.flatMap { directory, domain -> [LaunchItem] in
            let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
            return names.filter { $0.hasSuffix(".plist") }.sorted().compactMap {
                parse(directory.appendingPathComponent($0), domain: domain, resolveBundle: resolveBundle)
            }
        }
    }

    static func parse(_ url: URL, domain: LaunchDomain, resolveBundle: (String) -> URL?) -> LaunchItem? {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        let label = plist["Label"] as? String ?? url.deletingPathExtension().lastPathComponent
        let programArguments = plist["ProgramArguments"] as? [String] ?? []
        let associated = (plist["AssociatedBundleIdentifiers"] as? [String])?.first
            ?? plist["AssociatedBundleIdentifiers"] as? String

        var program: String?
        var orphaned = false
        if let bundleProgram = plist["BundleProgram"] as? String {
            // Without an associated app there is no way to tell where the program lives, so it
            // isn't provably orphaned (orphans get pre-selected for removal).
            if let associated {
                if let bundle = resolveBundle(associated) {
                    let path = bundle.appendingPathComponent(bundleProgram).path
                    program = path
                    orphaned = isMissing(path)
                } else {
                    orphaned = true
                }
            }
        } else if let path = (plist["Program"] as? String) ?? programArguments.first {
            if path.hasPrefix("/") {
                program = path
                orphaned = isMissing(path)
            } else {
                // launchd searches PATH for bare names like "sh"; not finding one isn't proof it's gone.
                program = Shell.locate(path)
            }
        }

        let keepAlive: Bool = switch plist["KeepAlive"] {
        case let flag as Bool: flag
        case is [String: Any]: true
        default: false
        }
        return LaunchItem(plist: url, label: label, domain: domain, program: program,
                          arguments: Array(programArguments.dropFirst()), associatedBundleID: associated,
                          runsAtLoad: (plist["RunAtLoad"] as? Bool ?? false) || keepAlive, isOrphaned: orphaned)
    }

    /// Orphans are pre-selected, so only a program that is provably gone counts: not one we can't
    /// reach, and not one on a drive that simply isn't plugged in.
    static func isMissing(_ program: String) -> Bool {
        !program.lowercased().hasPrefix("/volumes/") && PathProbe.isGone(program)
    }
}
