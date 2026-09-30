import Foundation

final class ScanCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var next = 0
    private var done = 0
    private var skipped = 0
    private var found: [(URL, [YaraMatch])] = []

    func claim(below limit: Int) -> Int? {
        lock.withLock {
            guard next < limit else { return nil }
            defer { next += 1 }
            return next
        }
    }

    func record(_ url: URL, _ matches: [YaraMatch]?) {
        lock.withLock {
            done += 1
            if let matches {
                if !matches.isEmpty { found.append((url, matches)) }
            } else {
                skipped += 1
            }
        }
    }

    func snapshot() -> (done: Int, skipped: Int) { lock.withLock { (done, skipped) } }
    var results: [(URL, [YaraMatch])] { lock.withLock { found } }
}

final class CancelFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.withLock { cancelled = true } }
    var isCancelled: Bool { lock.withLock { cancelled } }
}

/// Runs XProtect's rules over the executables that matter: apps' own binaries and helpers,
/// everything launchd starts, and loose programs in the usual drop spots.
enum ThreatScanner {
    static let maxFileSize: Int64 = 256 * 1024 * 1024
    static let nestedFolders = ["Library/LoginItems", "Library/LaunchServices", "Helpers", "XPCServices", "PlugIns"]

    static func looseFolders(home: String = NSHomeDirectory()) -> [URL] {
        [URL(fileURLWithPath: home).appendingPathComponent("Downloads"), URL(fileURLWithPath: "/Users/Shared"),
         URL(fileURLWithPath: "/private/tmp"), URL(fileURLWithPath: "/private/var/tmp")]
    }

    static func targets(apps: [InstalledApp], launchItems: [LaunchItem], looseFolders: [URL]) -> [URL] {
        var seen = Set<String>()
        var result: [URL] = []
        func add(_ path: String) {
            guard !seen.contains(path) else { return }
            seen.insert(path)
            if isScannable(path) { result.append(URL(fileURLWithPath: path)) }
        }
        for app in apps { executables(in: app.url).forEach(add) }
        for item in launchItems where !item.isOrphaned {
            if let program = item.program { add(program) }
            item.arguments.filter { $0.hasPrefix("/") }.forEach(add)
        }
        for folder in looseFolders {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [] where !name.hasPrefix(".") {
                let url = folder.appendingPathComponent(name)
                if name.hasSuffix(".app") { executables(in: url).forEach(add) } else { add(url.path) }
            }
        }
        return result
    }

    static func executables(in bundle: URL) -> [String] {
        let contents = bundle.appendingPathComponent("Contents")
        var paths = files(in: contents.appendingPathComponent("MacOS"))
        for folder in nestedFolders {
            let directory = contents.appendingPathComponent(folder)
            for name in (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [] {
                let nested = directory.appendingPathComponent(name)
                paths += files(in: nested.appendingPathComponent("Contents/MacOS"))
                paths.append(nested.path) // Helpers can hold bare executables; isScannable filters directories.
            }
        }
        // iPhone and iPad apps keep their binary flat inside the wrapped bundle, not in Contents/MacOS.
        paths += files(in: bundle.appendingPathComponent("WrappedBundle"))
        return paths
    }

    private static func files(in directory: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { !$0.hasPrefix(".") }
            .map { directory.appendingPathComponent($0).path }
    }

    /// Regular files under the size cap that are Mach-O binaries or scripts. One we can't open (a root-only
    /// daemon, say) is kept too, so the scan reports it as not scanned instead of silently passing it.
    static func isScannable(_ path: String) -> Bool {
        var info = stat()
        guard stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0,
              Int64(info.st_size) <= maxFileSize else { return false }
        guard let handle = FileHandle(forReadingAtPath: path) else { return true }
        defer { try? handle.close() }
        let head = [UInt8](handle.readData(ofLength: 4))
        guard head.count == 4 else { return false }
        let magic = UInt32(head[0]) | UInt32(head[1]) << 8 | UInt32(head[2]) << 16 | UInt32(head[3]) << 24
        let machO: Set<UInt32> = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca]
        return machO.contains(magic) || head.starts(with: Array("#!".utf8))
            || head.starts(with: Array("Fasd".utf8)) || head.starts(with: Array("JsOs".utf8))
    }

    static func scan(_ targets: [URL], engine: YaraEngine, counter: ScanCounter, workers: Int = 4,
                     isCancelled: @escaping @Sendable () -> Bool) {
        DispatchQueue.concurrentPerform(iterations: workers) { _ in
            while !isCancelled(), let index = counter.claim(below: targets.count) {
                counter.record(targets[index], engine.scan(file: targets[index]))
            }
        }
    }

    /// A match inside a listed app removes the app; one on a launch item's program or script removes the
    /// plist and that file. Anything else is only reported when it can be safely removed (its `.app`, or
    /// the file itself), never a system or package-manager file.
    static func hits(for matches: [(URL, [YaraMatch])], apps: [InstalledApp], launchItems: [LaunchItem]) -> [ThreatHit] {
        matches.compactMap { url, found in
            let path = url.path
            let reason = "Matches Apple's XProtect signature \(found.map(\.displayName).joined(separator: ", "))"
            if let app = apps.first(where: { path.hasPrefix($0.path + "/") }) {
                return ThreatHit(paths: [app.path], verdict: .malicious, reason: reason, title: app.name)
            }
            if let item = launchItems.first(where: { $0.program == path || $0.arguments.contains(path) }) {
                let file = Heuristics.removalTarget(forProgram: path)
                return ThreatHit(paths: [item.plist.path] + (file.map { [$0] } ?? []), verdict: .malicious, reason: reason, title: item.label)
            }
            guard let target = Heuristics.removalTarget(forProgram: path) else { return nil }
            return ThreatHit(paths: [target], verdict: .malicious, reason: reason, title: (target as NSString).lastPathComponent)
        }
    }
}
