import Foundation

struct SupportEntry: Hashable, Sendable {
    let url: URL
    /// The reverse-DNS ID this entry is named after, without extensions like .plist or .savedState.
    let bundleID: String?

    var name: String { url.lastPathComponent }
}

enum SupportFiles {
    static let userFolders = [
        "Library/Application Support", "Library/Caches", "Library/Containers", "Library/Preferences",
        "Library/Saved Application State", "Library/HTTPStorages", "Library/WebKit", "Library/Logs", "Library/Cookies",
    ]
    static let systemFolders = [
        "/Library/Application Support", "/Library/Caches", "/Library/Preferences", "/Library/PrivilegedHelperTools",
    ]

    static func standardFolders(home: String = NSHomeDirectory()) -> [URL] {
        userFolders.map { URL(fileURLWithPath: home).appendingPathComponent($0) } + systemFolders.map { URL(fileURLWithPath: $0) }
    }

    static func index(_ folders: [URL]) -> [SupportEntry] {
        folders.flatMap { folder in
            ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [])
                .filter { !$0.hasPrefix(".") }
                .sorted()
                .map { SupportEntry(url: folder.appendingPathComponent($0), bundleID: bundleID(fromName: $0)) }
        }
    }

    private static let strippedExtensions = ["plist", "savedState", "binarycookies"]
    private static let topLevelDomains: Set<String> = [
        "com", "org", "net", "io", "dev", "app", "co", "me", "info", "biz", "tv", "ai", "so", "sh", "xyz", "cc", "eu",
    ]

    /// "com.foo.Bar.plist" → "com.foo.Bar", "ABCDE12345.com.foo.bar" → "com.foo.bar", "Discord" → nil.
    static func bundleID(fromName name: String) -> String? {
        var id = name
        for suffix in strippedExtensions where id.hasSuffix("." + suffix) { id = String(id.dropLast(suffix.count + 1)) }
        var parts = id.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if let first = parts.first, first.count == 10, first.allSatisfy({ $0.isUppercase || $0.isNumber }) { parts.removeFirst() }
        guard parts.count >= 3, let tld = parts.first?.lowercased(), topLevelDomains.contains(tld) || tld.count == 2,
              parts.allSatisfy({ part in !part.isEmpty && part.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" } })
        else { return nil }
        return parts.joined(separator: ".")
    }

    /// The installed app an entry belongs to: by bundle ID (including helpers), or an
    /// Application Support folder named exactly like the app.
    static func owner(of entry: SupportEntry, among apps: [InstalledApp]) -> InstalledApp? {
        if let id = entry.bundleID {
            return apps.first { app in IDs.owns(app.bundleID, id) || app.nestedBundleIDs.contains { IDs.owns($0, id) } }
        }
        guard entry.url.deletingLastPathComponent().lastPathComponent == "Application Support" else { return nil }
        return apps.first { $0.name == entry.name }
    }
}

enum IDs {
    /// True when `id` is `owner` itself or a dotted child or parent of it ("com.foo.app" ~ "com.foo.app.helper").
    static func owns(_ owner: String, _ id: String) -> Bool {
        let owner = owner.lowercased(), id = id.lowercased()
        return owner == id || id.hasPrefix(owner + ".") || owner.hasPrefix(id + ".")
    }

    /// "com.microsoft.EdgeUpdater.update" → "com.microsoft"
    static func vendor(_ id: String) -> String { id.lowercased().split(separator: ".").prefix(2).joined(separator: ".") }

    /// "com.microsoft.EdgeUpdater.update" → "com.microsoft.EdgeUpdater"
    static func product(_ id: String) -> String { id.split(separator: ".").prefix(3).joined(separator: ".") }
}
