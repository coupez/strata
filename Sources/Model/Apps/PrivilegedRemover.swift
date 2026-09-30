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
    private static let untouchable = ["/applications/utilities", "/library/preferences/.globalpreferences.plist"]
    private static let untouchableTrees = ["/library/preferences/systemconfiguration", "/library/preferences/opendirectory",
                                           "/library/application support/apple"]
    /// The only places where a folder named "Apple" is third-party-removable content.
    private static let appleContentTrees = ["/library/audio/impulse responses/apple", "/library/audio/apple loops/apple"]

    /// `realpath(3)`: unlike `resolvingSymlinksInPath` it keeps /private and matches `pwd -P`.
    static func realpathOf(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func isInside(_ path: String, _ tree: String) -> Bool { path == tree || path.hasPrefix(tree + "/") }

    /// Resolves the parent once and applies every rule to the resolved target; the script is
    /// built from the returned values only, so nothing unchecked ever reaches root.
    /// Comparison is case-insensitive because the volume is: `/APPLICATIONS/utilities` is the same folder.
    static func vetted(_ path: String, resolve: (String) -> String? = PrivilegedRemover.realpathOf) -> (parent: String, name: String)? {
        guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("\n"), !path.contains("\r"), !path.contains("\0") else { return nil }
        let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, !components.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { return nil }

        // Resolve the parent (not the item: removing a symlink only removes the link).
        let parentPath = (path as NSString).deletingLastPathComponent
        guard let parent = resolve(parentPath), parent.hasPrefix("/"), !parent.contains("\n"), !parent.contains("\r") else { return nil }
        let name = (path as NSString).lastPathComponent
        let target = (parent == "/" ? "" : parent) + "/" + name
        let lowered = target.lowercased()

        guard allowedRoots.contains(where: { lowered.hasPrefix($0.lowercased() + "/") }) else { return nil }
        guard !untouchable.contains(lowered), !untouchableTrees.contains(where: { isInside(lowered, $0) }) else { return nil }
        let parts = lowered.split(separator: "/")
        guard !parts.contains(where: { $0.hasPrefix("com.apple.") }) else { return nil }
        if parts.contains("apple"), !appleContentTrees.contains(where: { isInside(lowered, $0) }) { return nil }
        return (parent, name)
    }

    static func isAllowed(_ path: String, resolve: (String) -> String? = PrivilegedRemover.realpathOf) -> Bool {
        vetted(path, resolve: resolve) != nil
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
    /// Each item is vetted once here and handled relative to that physically resolved parent,
    /// re-verified with `pwd -P` at run time, so a folder swapped for a symlink during the
    /// password prompt makes the item fail instead of redirecting root elsewhere.
    static func script(for operations: [ElevatedOperation], trashDirectory: String,
                       resolve: (String) -> String? = PrivilegedRemover.realpathOf) -> String {
        var lines = ["cd /"]
        if operations.contains(where: \.trash) {
            // The Trash is re-verified the same way, and mktemp runs inside it, so a Trash swapped for a
            // symlink during the password prompt can't make root create the folder anywhere else.
            let trash = quote(trashDirectory)
            lines.append("if cd -P -- \(trash) 2>/dev/null && [ \"$(pwd -P)\" = \(trash) ] && bin=$(/usr/bin/mktemp -d './Removed by Strata.XXXXXX'); then bin=\(trash)/\"${bin#./}\"; else bin=''; fi")
            lines.append("cd /")
        } else {
            lines.append("bin=''")
        }
        for (index, operation) in operations.enumerated() {
            guard let (parent, name) = vetted(operation.url.path, resolve: resolve) else {
                lines.append("echo FAIL \(index)")
                continue
            }
            let quotedParent = quote(parent)
            let relative = quote("./" + name)
            lines.append("if cd -P -- \(quotedParent) 2>/dev/null && [ \"$(pwd -P)\" = \(quotedParent) ]; then")
            if parent.lowercased() == "/library/launchdaemons" {
                lines.append("/bin/launchctl bootout system \(quote(parent + "/" + name)) 2>/dev/null")
            }
            if operation.trash {
                // One folder per item: same-named items from different places must not collide.
                lines.append("if [ -n \"$bin\" ] && /bin/mkdir -- \"$bin/\(index)\" && /bin/mv -n -- \(relative) \"$bin/\(index)/\" && [ ! -e \(relative) ] && [ ! -L \(relative) ]; then echo OK \(index); else echo FAIL \(index); fi")
            } else {
                lines.append("if /bin/rm -rf -- \(relative); then echo OK \(index); else echo FAIL \(index); fi")
            }
            lines.append("else echo FAIL \(index); fi")
            lines.append("cd /")
        }
        return lines.joined(separator: "\n")
    }

    /// The prompt names Strata; without one macOS says "osascript wants to make changes".
    static func appleScript(for script: String, itemCount: Int) -> String {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        let items = itemCount == 1 ? "1 item that needs" : "\(itemCount) items that need"
        return "do shell script \"\(escaped)\" with prompt \"Strata wants to remove \(items) administrator access.\""
            + " with administrator privileges without altering line endings"
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
        // Trash items only go into a real ~/.Trash: if it is a symlink or missing, root must not follow it.
        let home = NSHomeDirectory()
        let trashDirectory = realpathOf(home).map { $0 + "/.Trash" }
        let trashIsSafe = trashDirectory != nil && realpathOf(home + "/.Trash") == trashDirectory
        let included = operations.indices.filter { trashIsSafe || !operations[$0].trash }
        guard !included.isEmpty else { return .failed }

        let script = script(for: included.map { operations[$0] }, trashDirectory: trashDirectory ?? home + "/.Trash")
        let run = await Shell.run("/usr/bin/osascript", ["-e", appleScript(for: script, itemCount: included.count)], timeout: 900)
        guard run.status == 0 else { return run.output.contains("-128") ? .cancelled : .failed }
        let ran = parse(run.output, count: included.count)
        var results = [Bool](repeating: false, count: operations.count)
        for (position, index) in included.enumerated() { results[index] = ran[position] }
        return .finished(results)
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
