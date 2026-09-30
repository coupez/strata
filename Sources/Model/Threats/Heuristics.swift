import Foundation

/// Signs that a launch item is up to no good. Signed-by-an-identified-developer programs and
/// package-manager installs (Homebrew bottles are ad-hoc signed by design) are left alone.
enum Heuristics {
    static let trustedPrefixes = ["/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/usr/local/Homebrew/", "/opt/local/", "/nix/store/"]
    static let riskyLocations = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/var/tmp/", "/Users/Shared/"]
    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"]
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "osascript", "node"]

    static func reasons(for item: LaunchItem, signature: (String) -> Signature) -> [String] {
        guard let program = item.program, !item.isOrphaned, !item.label.hasPrefix("com.apple.") else { return [] }
        let name = (program as NSString).lastPathComponent
        if interpreters.contains(name) {
            guard let script = item.arguments.first(where: { $0.hasPrefix("/") }), isRiskyLocation(script) else { return [] }
            return ["Runs a \(name) script from \(locationName(script))"]
        }
        if trustedPrefixes.contains(where: program.hasPrefix) { return [] }
        let programSignature = signature(program)
        if programSignature.isTrusted { return [] }

        var reasons: [String] = []
        if isRiskyLocation(program) { reasons.append("Runs from \(locationName(program))") }
        switch programSignature.kind {
        case .unsigned: reasons.append("Program isn't signed")
        case .adhoc: reasons.append("Program has no developer signature")
        case .invalid: reasons.append("Program's signature is broken")
        case .unidentified: reasons.append("Program is from an unidentified developer")
        case .apple, .identified: break
        }
        return reasons
    }

    /// The plist plus any program or script that isn't part of macOS or of an app bundle.
    static func removablePaths(of item: LaunchItem) -> [String] {
        var paths = [item.plist.path]
        guard let program = item.program else { return paths }
        if !systemPrefixes.contains(where: program.hasPrefix), !trustedPrefixes.contains(where: program.hasPrefix),
           !program.contains(".app/") {
            paths.append(program)
        }
        if interpreters.contains((program as NSString).lastPathComponent) {
            paths += item.arguments.filter { $0.hasPrefix("/") && isRiskyLocation($0) }
        }
        return paths
    }

    static func isRiskyLocation(_ path: String) -> Bool {
        riskyLocations.contains(where: path.hasPrefix) || path.split(separator: "/").dropLast().contains { $0.hasPrefix(".") }
    }

    private static func locationName(_ path: String) -> String {
        if path.hasPrefix("/Users/Shared/") { return "the shared Users folder" }
        if riskyLocations.contains(where: path.hasPrefix) { return "a temporary folder" }
        return "a hidden folder"
    }
}

/// Threats found without scanning file contents: known adware, Apple-blocked extensions and
/// suspicious launch items.
enum StaticThreats {
    static func hits(_ input: AppScanInput, blockedExtensionIDs: Set<String>,
                     signature: (String) -> Signature = CodeSignature.check) -> [ThreatHit] {
        var hits: [ThreatHit] = []
        for app in input.apps {
            let ids = [app.bundleID] + app.nestedBundleIDs
            if let blocked = ids.first(where: blockedExtensionIDs.contains) {
                hits.append(ThreatHit(paths: [app.path], verdict: .malicious, reason: "Contains an extension Apple blocks (\(blocked))", title: app.name))
            } else if let known = ids.lazy.compactMap(KnownThreats.match).first {
                hits.append(ThreatHit(paths: [app.path], verdict: .adware, reason: "Known adware: \(known.family)", title: app.name))
            }
        }
        for item in input.launchItems {
            if let known = KnownThreats.match(item.label) {
                hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item), verdict: .adware, reason: "Known adware: \(known.family)", title: item.label))
            } else {
                let reasons = Heuristics.reasons(for: item, signature: signature)
                if !reasons.isEmpty {
                    hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item), verdict: .suspicious,
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
