import Foundation

/// Signs that a launch item is up to no good. Trust comes from the program's signature, never from
/// the launch label; package-manager installs (Homebrew bottles are ad-hoc signed by design) are left alone.
enum Heuristics {
    // Prefix lists are lower-case: paths are compared case-insensitively (default macOS volumes are).
    static let trustedPrefixes = ["/opt/homebrew/", "/usr/local/cellar/", "/usr/local/opt/", "/usr/local/homebrew/", "/opt/local/", "/nix/store/"]
    static let riskyLocations = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/var/tmp/", "/private/var/folders/", "/var/folders/", "/users/shared/"]
    static let systemPrefixes = ["/system/", "/usr/", "/bin/", "/sbin/", "/library/apple/"]
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "env", "osascript", "node"]
    static let interpreterFamilies = ["python", "perl", "ruby"]

    static func reasons(for item: LaunchItem, signature: (String) -> Signature) -> [String] {
        guard let raw = item.program, !item.isOrphaned else { return [] }
        // A program with no usable location can't run; it is still classified by name, never by place.
        let location = resolved(raw)
        let program = location ?? standardized(raw)
        if isGenuineInterpreter(program, signature: signature) {
            guard let script = riskyScript(in: item) else { return [] }
            let name = (program as NSString).lastPathComponent.lowercased()
            let article = "aeiou".contains(name.first ?? "x") ? "an" : "a"
            return ["Runs \(article) \(name) script from \(locationName(script))"]
        }
        if hasPrefix(program, in: trustedPrefixes) { return [] }
        let programSignature = signature(program)
        if programSignature.isTrusted { return [] }

        var reasons: [String] = []
        if let location, isRisky(location) { reasons.append("Runs from \(locationName(location))") }
        switch programSignature.kind {
        case .unsigned: reasons.append("Program isn't signed")
        case .adhoc: reasons.append("Program has no developer signature")
        case .invalid: reasons.append("Program's signature is broken")
        case .unidentified: reasons.append("Program is from an unidentified developer")
        case .apple, .identified: break
        }
        return reasons
    }

    /// The plist plus any program or script file that isn't part of macOS or of an app bundle, at its real
    /// location. An untrusted app bundle sitting in a risky folder is removed whole rather than just its
    /// executable; that is the only way a folder is ever listed.
    static func removablePaths(of item: LaunchItem, signature: (String) -> Signature) -> [String] {
        var paths = [item.plist.path]
        guard let raw = item.program else { return paths }
        let location = resolved(raw)
        let program = location ?? standardized(raw)
        if isGenuineInterpreter(program, signature: signature) {
            if let script = riskyScript(in: item), isFileOrLink(script) { paths.append(script) }
        } else if hasPrefix(program, in: systemPrefixes) || hasPrefix(program, in: trustedPrefixes) {
            // Belongs to macOS or a package manager.
        } else if let location {
            if let bundle = appBundle(containing: location) {
                if isRisky(bundle), !signature(location).isTrusted { paths.append(bundle) }
            } else if isFileOrLink(location) {
                paths.append(location)
            }
        }
        return paths
    }

    /// Judged where the path really leads: `/tmp/lnk/Documents` with `lnk` pointing home is not a temp file.
    static func isRiskyLocation(_ path: String) -> Bool {
        resolved(path).map(isRisky) ?? false
    }

    /// Where a path really is: its folder with every symlink resolved, plus its last component as
    /// written, so a symlinked item is judged and removed as the link itself, never its target.
    /// nil (unusable: never risky, never the script, never removable) when the folder doesn't exist
    /// or the path has a `..` in it. `realpath` keeps /private, which the risky list spells out.
    static func resolved(_ path: String) -> String? {
        guard path.hasPrefix("/"), !hasParentComponent(path) else { return nil }
        let path = standardized(path)
        let name = (path as NSString).lastPathComponent
        guard name != "/", let parent = PrivilegedRemover.realpathOf((path as NSString).deletingLastPathComponent) else { return nil }
        return (parent == "/" ? "" : parent) + "/" + name
    }

    /// launchd can't run a folder, so one named as a program or script is never a deletion target.
    private static func isFileOrLink(_ path: String) -> Bool {
        var info = stat()
        guard lstat(path, &info) == 0 else { return false }
        let type = info.st_mode & S_IFMT
        return type == S_IFREG || type == S_IFLNK
    }

    /// For a path already resolved.
    private static func isRisky(_ path: String) -> Bool {
        hasPrefix(path, in: riskyLocations) || path.split(separator: "/").contains { $0.hasPrefix(".") && $0 != "." }
    }

    private static func standardized(_ path: String) -> String { (path as NSString).standardizingPath }

    private static func hasParentComponent(_ path: String) -> Bool { path.split(separator: "/").contains("..") }

    /// A shell or scripting runtime that macOS or a package manager installed (or a developer signed).
    /// A file merely named `bash` in /tmp is a program, not an interpreter.
    private static func isGenuineInterpreter(_ program: String, signature: (String) -> Signature) -> Bool {
        let name = (program as NSString).lastPathComponent.lowercased()
        guard interpreters.contains(name) || interpreterFamilies.contains(where: name.hasPrefix) else { return false }
        // /usr/local is admin-writable rather than SIP-protected, so it only counts with a package manager or signature.
        let isSystem = hasPrefix(program, in: systemPrefixes) && !hasPrefix(program, in: ["/usr/local/"])
        return isSystem || hasPrefix(program, in: trustedPrefixes) || signature(program).isTrusted
    }

    /// The script an interpreter runs is its first absolute-path argument; later paths (logs, config) are data.
    private static func riskyScript(in item: LaunchItem) -> String? {
        item.arguments.first { $0.hasPrefix("/") }.flatMap(resolved).flatMap { isRisky($0) ? $0 : nil }
    }

    /// The `.app` folder a path lives in, if any.
    private static func appBundle(containing path: String) -> String? {
        guard let range = path.range(of: ".app/", options: .caseInsensitive) else { return nil }
        return String(path[..<range.upperBound].dropLast())
    }

    private static func hasPrefix(_ path: String, in prefixes: [String]) -> Bool {
        let lowered = path.lowercased()
        return prefixes.contains(where: lowered.hasPrefix)
    }

    private static func locationName(_ path: String) -> String {
        if hasPrefix(path, in: ["/users/shared/"]) { return "the shared Users folder" }
        if hasPrefix(path, in: riskyLocations) { return "a temporary folder" }
        return "a hidden folder"
    }
}

/// Threats found without scanning file contents: known adware, Apple-blocked extensions and
/// suspicious launch items.
enum StaticThreats {
    static func hits(_ input: AppScanInput, blockedExtensions: [String: Set<String>],
                     signature: (String) -> Signature = CodeSignature.check) -> [ThreatHit] {
        var hits: [ThreatHit] = []
        for app in input.apps {
            let ids = [app.bundleID] + app.nestedBundleIDs
            let blockedIDs = ids.filter { blockedExtensions[$0] != nil }
            if let first = blockedIDs.first {
                // Apple blocks an ID for specific developers; the same ID from anyone else is only a warning sign.
                let team = signature(app.path).teamID
                if let match = blockedIDs.first(where: { id in team.map { blockedExtensions[id]?.contains($0) ?? false } ?? false }) {
                    hits.append(ThreatHit(paths: [app.path], verdict: .malicious, reason: "Contains an extension Apple blocks (\(match))", title: app.name))
                } else {
                    let unlisted = blockedExtensions[first]?.isEmpty ?? true
                    hits.append(ThreatHit(paths: [app.path], verdict: .suspicious,
                                          reason: unlisted ? "Contains an extension ID Apple blocks (\(first))"
                                                           : "Contains an extension ID Apple blocks for another developer (\(first))",
                                          title: app.name))
                }
            } else if let known = ids.lazy.compactMap(KnownThreats.match).first {
                hits.append(ThreatHit(paths: [app.path], verdict: .adware, reason: "Known adware: \(known.family)", title: app.name))
            }
        }
        for item in input.launchItems {
            if let known = KnownThreats.match(item.label) {
                hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item, signature: signature), verdict: .adware, reason: "Known adware: \(known.family)", title: item.label))
            } else {
                let reasons = Heuristics.reasons(for: item, signature: signature)
                if !reasons.isEmpty {
                    hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item, signature: signature), verdict: .suspicious,
                                          reason: reasons.joined(separator: " · "), title: item.label))
                }
            }
        }
        for entry in input.support {
            if let id = entry.bundleID, let known = KnownThreats.match(id) {
                hits.append(ThreatHit(paths: [entry.url.path], verdict: .adware, reason: "Known adware: \(known.family)", title: id))
            }
        }
        return hits
    }
}
