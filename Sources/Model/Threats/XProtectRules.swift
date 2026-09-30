import Foundation

struct XProtectInfo: Hashable, Sendable {
    let bundle: URL
    let version: Int
    let updated: Date?
    let ruleFiles: [URL]
    /// Safari extensions Apple blocks.
    let blockedExtensionIDs: Set<String>
}

/// Apple's malware rules, read straight from the system. Newer macOS updates them in
/// /var/protected; the copy in /Library/Apple can lag a version behind.
enum XProtectRules {
    static let candidates = [
        URL(fileURLWithPath: "/var/protected/xprotect/XProtect.bundle"),
        URL(fileURLWithPath: "/Library/Apple/System/Library/CoreServices/XProtect.bundle"),
    ]

    static func locate(_ candidates: [URL] = candidates) -> XProtectInfo? {
        candidates.compactMap(read).max { $0.version < $1.version }
    }

    static func read(_ bundle: URL) -> XProtectInfo? {
        let contents = bundle.appendingPathComponent("Contents")
        let resources = contents.appendingPathComponent("Resources")
        let yara = resources.appendingPathComponent("XProtect.yara")
        guard FileManager.default.isReadableFile(atPath: yara.path),
              let info = NSDictionary(contentsOf: contents.appendingPathComponent("Info.plist")) as? [String: Any],
              let text = info["CFBundleShortVersionString"] as? String,
              let version = Int(text) ?? Double(text).map({ Int($0) }) else { return nil }
        let scripts = resources.appendingPathComponent("XPScripts.yr")
        let files = [yara] + (FileManager.default.isReadableFile(atPath: scripts.path) ? [scripts] : [])
        let updated = (try? FileManager.default.attributesOfItem(atPath: yara.path))?[.modificationDate] as? Date
        return XProtectInfo(bundle: bundle, version: version, updated: updated, ruleFiles: files,
                            blockedExtensionIDs: blockedExtensions(in: resources.appendingPathComponent("XProtect.meta.plist")))
    }

    static func blockedExtensions(in meta: URL) -> Set<String> {
        guard let plist = NSDictionary(contentsOf: meta) as? [String: Any],
              let blacklist = plist["ExtensionBlacklist"] as? [String: Any],
              let extensions = blacklist["Extensions"] as? [[String: Any]] else { return [] }
        return Set(extensions.compactMap { $0["CFBundleIdentifier"] as? String })
    }
}
