import Foundation

struct ElevatedOperation: Hashable, Sendable {
    let url: URL
    let trash: Bool
}

/// Removes root-owned items with one administrator prompt per batch. Every path must pass
/// `isAllowed` and every argument is single-quoted, so the elevated shell only sees literal
/// names inside a handful of known system locations. Nothing under a user's home is ever
/// removed as root, and root never chowns anything: items go into a root-made folder in the
/// user's Trash.
enum PrivilegedRemover {
    enum ElevationRun: Equatable {
        case finished([Bool])
        case cancelled
        case failed
    }

    static let allowedRoots = [
        "/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools",
        "/Library/Application Support", "/Library/Caches", "/Library/Preferences", "/Library/Audio/Apple Loops",
        "/Library/Audio/Impulse Responses",
    ]

    /// Inside a root but never removable, even as a whole folder.
    private static let untouchable = ["/applications/utilities"]
    private static let untouchableTrees = ["/library/preferences/systemconfiguration", "/library/application support/apple"]
    /// The only places where a folder named "Apple" is third-party-removable content.
    private static let appleContentTrees = ["/library/audio/impulse responses/apple", "/library/audio/apple loops/apple"]

    /// `realpath(3)`: unlike `resolvingSymlinksInPath` it keeps /private and matches `pwd -P`.
    static func realpathOf(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func isInside(_ path: String, _ tree: String) -> Bool { path == tree || path.hasPrefix(tree + "/") }

    /// Comparison is case-insensitive because the volume is: `/APPLICATIONS/utilities` is the same folder.
    static func isAllowed(_ path: String, resolve: (String) -> String? = PrivilegedRemover.realpathOf) -> Bool {
        guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("\n"), !path.contains("\r"), !path.contains("\0") else { return false }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, !components.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { return false }

        // Resolve the parent (not the item: removing a symlink only removes the link).
        let parentPath = (path as NSString).deletingLastPathComponent
        guard let parent = resolve(parentPath), parent.hasPrefix("/") else { return false }
        let name = (path as NSString).lastPathComponent
        let target = (parent == "/" ? "" : parent) + "/" + name
        let lowered = target.lowercased()

        guard allowedRoots.contains(where: { lowered.hasPrefix($0.lowercased() + "/") }) else { return false }
        guard !untouchable.contains(lowered), !untouchableTrees.contains(where: { isInside(lowered, $0) }) else { return false }
        let parts = lowered.split(separator: "/")
        guard !parts.contains(where: { $0.hasPrefix("com.apple.") }) else { return false }
        if parts.contains("apple") { return appleContentTrees.contains { isInside(lowered, $0) } }
        return true
    }

    /// Root-owned and allowed: the only things worth asking for a password for.
    static func needsRoot(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && info.st_uid == 0 && isAllowed(path)
    }

    static func quote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }

    /// A /bin/sh script that prints "OK <index>" or "FAIL <index>" for each operation.
    /// Each item is handled relative to its physically resolved parent, re-verified with
    /// `pwd -P` at run time, so a folder swapped for a symlink during the password prompt
    /// makes the item fail instead of redirecting root elsewhere.
    static func script(for operations: [ElevatedOperation], trashDirectory: String,
                       resolve: (String) -> String? = PrivilegedRemover.realpathOf) -> String {
        var lines = ["cd /"]
        if operations.contains(where: \.trash) {
            lines.append("bin=$(/usr/bin/mktemp -d \(quote(trashDirectory + "/Removed by Strata.XXXXXX"))) || bin=''")
        } else {
            lines.append("bin=''")
        }
        for (index, operation) in operations.enumerated() {
            guard let parent = resolve((operation.url.path as NSString).deletingLastPathComponent) else {
                lines.append("echo FAIL \(index)")
                continue
            }
            let name = operation.url.lastPathComponent
            let quotedParent = quote(parent)
            let relative = quote("./" + name)
            let full = quote((parent == "/" ? "" : parent) + "/" + name)
            lines.append("if cd -P -- \(quotedParent) 2>/dev/null && [ \"$(pwd -P)\" = \(quotedParent) ]; then")
            if operation.url.path.hasPrefix("/Library/LaunchDaemons/") {
                lines.append("/bin/launchctl bootout system \(relative) 2>/dev/null")
            }
            if operation.trash {
                lines.append("if [ -n \"$bin\" ] && /bin/mv -n -- \(relative) \"$bin/\" && [ ! -e \(full) ] && [ ! -L \(full) ]; then echo OK \(index); else echo FAIL \(index); fi")
            } else {
                lines.append("if /bin/rm -rf -- \(relative); then echo OK \(index); else echo FAIL \(index); fi")
            }
            lines.append("else echo FAIL \(index); fi")
            lines.append("cd /")
        }
        return lines.joined(separator: "\n")
    }

    static func appleScript(for script: String) -> String {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "do shell script \"\(escaped)\" with administrator privileges without altering line endings"
    }

    static func parse(_ output: String, count: Int) -> [Bool] {
        var succeeded = [Bool](repeating: false, count: count)
        for line in output.split(whereSeparator: \.isNewline) {
            let words = line.split(separator: " ")
            if words.count == 2, words[0] == "OK", let index = Int(words[1]), succeeded.indices.contains(index) {
                succeeded[index] = true
            }
        }
        return succeeded
    }

    /// Failed trash/remove operations whose item is root-owned, still there, and allowed.
    static func elevationCandidates(_ operations: [DeletionOperation], outcomes: [DeletionOutcome],
                                    isEligible: (String) -> Bool = PrivilegedRemover.needsRoot) -> [(index: Int, operation: ElevatedOperation)] {
        zip(operations, outcomes).enumerated().compactMap { index, pair in
            let (operation, outcome) = pair
            guard case .failed = outcome, let url = operation.url, isEligible(url.path) else { return nil }
            if case .trash = operation.kind { return (index, ElevatedOperation(url: url, trash: true)) }
            return (index, ElevatedOperation(url: url, trash: false))
        }
    }

    /// Runs the batch as admin (one prompt). osascript shows the password prompt itself, so the UI never blocks on it.
    static func run(_ operations: [ElevatedOperation]) async -> ElevationRun {
        guard !operations.isEmpty, operations.allSatisfy({ isAllowed($0.url.path) }) else { return .failed }
        let script = script(for: operations, trashDirectory: NSHomeDirectory() + "/.Trash")
        let run = await Shell.run("/usr/bin/osascript", ["-e", appleScript(for: script)], timeout: 900)
        guard run.status == 0 else { return run.output.contains("-128") ? .cancelled : .failed }
        return .finished(parse(run.output, count: operations.count))
    }

    /// `elevated` holds the indices that really went through the admin script.
    static func retry(_ operations: [DeletionOperation], outcomes: [DeletionOutcome]) async -> (outcomes: [DeletionOutcome], elevated: Set<Int>) {
        let candidates = elevationCandidates(operations, outcomes: outcomes)
        guard !candidates.isEmpty else { return (outcomes, []) }
        var outcomes = outcomes
        switch await run(candidates.map(\.operation)) {
        case .finished(let results):
            for (position, candidate) in candidates.enumerated() where results[position] {
                outcomes[candidate.index] = .removed
            }
            return (outcomes, Set(candidates.map(\.index)))
        case .cancelled:
            for candidate in candidates { outcomes[candidate.index] = .failed("Administrator access was cancelled") }
        case .failed:
            for candidate in candidates { outcomes[candidate.index] = .failed("Couldn't get administrator access") }
        }
        return (outcomes, [])
    }
}
