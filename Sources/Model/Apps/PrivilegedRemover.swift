import Foundation

struct ElevatedOperation: Hashable, Sendable {
    let url: URL
    let trash: Bool
}

/// Removes root-owned items with one administrator prompt per batch. Every path must pass
/// `isAllowed`, and every argument is single-quoted, so the elevated shell only ever sees
/// literal paths inside a handful of known locations.
enum PrivilegedRemover {
    static func allowedRoots(home: String) -> [String] {
        ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools",
         "/Library/Application Support", "/Library/Caches", "/Library/Preferences", "/Library/Audio/Apple Loops",
         "/Library/Audio/Impulse Responses", home]
    }

    static func protectedPaths(home: String) -> [String] {
        allowedRoots(home: home)
            + ["Library", "Applications", "Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Library/LaunchAgents"]
                .map { home + "/" + $0 }
            + SupportFiles.userFolders.map { home + "/" + $0 }
    }

    static func isAllowed(_ path: String, home: String = NSHomeDirectory()) -> Bool {
        guard path.hasPrefix("/"), !path.contains("\n"), !path.contains("\r"), !path.contains("\0") else { return false }
        let components = path.split(separator: "/")
        guard !components.contains(".."), !components.contains(".") else { return false }

        func resolved(_ path: String) -> String { URL(fileURLWithPath: path).resolvingSymlinksInPath().path }
        // Resolve the parent (not the item: removing a symlink only removes the link).
        let target = (resolved((path as NSString).deletingLastPathComponent) as NSString)
            .appendingPathComponent((path as NSString).lastPathComponent)
        let roots = allowedRoots(home: home).map(resolved)
        let protected = Set(protectedPaths(home: home).map(resolved))
        return roots.contains { target.hasPrefix($0 + "/") } && !protected.contains(target)
    }

    static func quote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }

    /// A /bin/sh script that prints "OK <index>" or "FAIL <index>" for each operation.
    static func script(for operations: [ElevatedOperation], owner: String, trashDirectory: String, stamp: String) -> String {
        var lines = ["cd /"]
        for (index, operation) in operations.enumerated() {
            let path = quote(operation.url.path)
            if operation.url.path.hasPrefix("/Library/LaunchDaemons/") {
                lines.append("/bin/launchctl bootout system \(path) 2>/dev/null")
            }
            if operation.trash {
                let base = operation.url.deletingPathExtension().lastPathComponent
                let ext = operation.url.pathExtension
                let destination = quote(trashDirectory + "/" + base + " \(stamp)-\(index)" + (ext.isEmpty ? "" : "." + ext))
                lines.append("if /bin/mv \(path) \(destination) && /usr/sbin/chown -R \(quote(owner)) \(destination); then echo OK \(index); else echo FAIL \(index); fi")
            } else {
                lines.append("if /bin/rm -rf \(path); then echo OK \(index); else echo FAIL \(index); fi")
            }
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

    /// Failed trash/remove operations whose item still exists and may be removed as admin.
    static func elevationCandidates(_ operations: [DeletionOperation], outcomes: [DeletionOutcome],
                                    home: String = NSHomeDirectory()) -> [(index: Int, operation: ElevatedOperation)] {
        zip(operations, outcomes).enumerated().compactMap { index, pair in
            let (operation, outcome) = pair
            guard case .failed = outcome, let url = operation.url, DirectorySizer.exists(url.path),
                  isAllowed(url.path, home: home) else { return nil }
            if case .trash = operation.kind { return (index, ElevatedOperation(url: url, trash: true)) }
            return (index, ElevatedOperation(url: url, trash: false))
        }
    }

    /// Runs the batch as admin. nil means the prompt was cancelled or something refused to run.
    static func run(_ operations: [ElevatedOperation]) async -> [Bool]? {
        guard !operations.isEmpty, operations.allSatisfy({ isAllowed($0.url.path) }) else { return nil }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH.mm.ss"
        let stamp = formatter.string(from: .now)
        let script = script(for: operations, owner: NSUserName(), trashDirectory: NSHomeDirectory() + "/.Trash", stamp: stamp)
        // osascript shows the password prompt itself, so the UI never blocks on it.
        let run = await Shell.run("/usr/bin/osascript", ["-e", appleScript(for: script)], timeout: 900)
        guard run.status == 0 else { return nil }
        return parse(run.output, count: operations.count)
    }

    static func retry(_ operations: [DeletionOperation], outcomes: [DeletionOutcome]) async -> [DeletionOutcome] {
        let candidates = elevationCandidates(operations, outcomes: outcomes)
        guard !candidates.isEmpty else { return outcomes }
        var outcomes = outcomes
        let results = await run(candidates.map(\.operation))
        for (position, candidate) in candidates.enumerated() {
            if let results {
                if results[position] { outcomes[candidate.index] = .removed }
            } else {
                outcomes[candidate.index] = .failed("Administrator access was cancelled")
            }
        }
        return outcomes
    }
}
