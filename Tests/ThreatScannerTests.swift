import Foundation
import Testing
@testable import Strata

struct ThreatScannerTests {
    let dir = TempDir()

    @discardableResult
    func machO(_ relative: String) -> URL {
        let url = dir.url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! FileManager.default.copyItem(atPath: "/bin/ls", toPath: url.path)
        return url
    }

    func installed(_ url: URL) -> InstalledApp {
        InstalledApp(url: url, bundleID: "com.a", name: "A", version: nil, nestedBundleIDs: [], size: 1, lastUsed: nil, dateAdded: nil)
    }

    let found = [YaraMatch(rule: "Bad", description: "TEST.BAD")]

    /// Hits carry the path where the file really is, which spells out /private.
    func real(_ url: URL) -> String { PrivilegedRemover.realpathOf(url.path)! }

    @Test func picksExecutablesAndScriptsOnly() {
        let app = dir.app("A.app", id: "com.a")
        machO("A.app/Contents/Library/LoginItems/L.app/Contents/MacOS/L")
        machO("A.app/Contents/Frameworks/F.framework/F")
        dir.file("A.app/Contents/Resources/data.bin", "plain")
        dir.file("Loose/notes.txt", "hello")
        machO("Loose/tool")
        let agent = LaunchItem(plist: dir.url.appendingPathComponent("x.plist"), label: "com.x", domain: .userAgent,
                               program: machO("bin/agent").path, arguments: [], associatedBundleID: nil, runsAtLoad: true, isOrphaned: false)
        let targets = ThreatScanner.targets(apps: [installed(app)], launchItems: [agent],
                                            looseFolders: [dir.url.appendingPathComponent("Loose")])
        #expect(Set(targets.map(\.lastPathComponent)) == ["main", "L", "tool", "agent"])
        #expect(targets.count == 4)
    }

    @Test func scansWrappedIOSApps() throws {
        let app = dir.directory("W.app")
        machO("W.app/Wrapper/W.app/W")
        dir.file("W.app/Wrapper/W.app/Info.plist", "<plist/>")
        try FileManager.default.createSymbolicLink(atPath: app.appendingPathComponent("WrappedBundle").path,
                                                   withDestinationPath: "Wrapper/W.app")
        let targets = ThreatScanner.targets(apps: [installed(app)], launchItems: [], looseFolders: [])
        #expect(targets.map(\.lastPathComponent) == ["W"])
        #expect(targets.allSatisfy { $0.path.hasPrefix(app.path + "/") })
    }

    @Test func scansInParallelAndMapsHitsToTheirOwners() throws {
        let engine = try YaraEngine(source: #"rule Bad { meta: description = "TEST.BAD" strings: $a = "BAD_MARKER" condition: $a }"#)
        let app = dir.app("A.app", id: "com.a")
        let inApp = dir.file("A.app/Contents/MacOS/helper", "#!/bin/sh\n# BAD_MARKER\n")
        let loose = dir.file("Loose/run.sh", "#!/bin/sh\necho BAD_MARKER\n")
        let clean = dir.file("Loose/ok.sh", "#!/bin/sh\necho ok\n")
        let counter = ScanCounter()
        ThreatScanner.scan([inApp, loose, clean, dir.url.appendingPathComponent("missing")], engine: engine, counter: counter, isCancelled: { false })
        #expect(counter.snapshot().done == 4)
        #expect(counter.snapshot().skipped == 1)
        let hits = ThreatScanner.hits(for: counter.results, apps: [installed(app)], launchItems: [])
        #expect(Set(hits.map(\.primary)) == [app.path, real(loose)])
        #expect(hits.allSatisfy { $0.verdict == .malicious && $0.reason == "Matches Apple's XProtect signature TEST.BAD" })
    }

    @Test func launchItemHitsRemoveThePlistAndTheProgram() {
        let program = dir.file("bin/agent", "#!/bin/sh\n")
        let plist = dir.url.appendingPathComponent("x.plist")
        let agent = LaunchItem(plist: plist, label: "com.x", domain: .userAgent, program: program.path, arguments: [],
                               associatedBundleID: nil, runsAtLoad: true, isOrphaned: false)
        let hits = ThreatScanner.hits(for: [(program, found)], apps: [], launchItems: [agent])
        #expect(hits.map(\.paths) == [[plist.path, real(program)]])
        #expect(hits.map(\.title) == ["com.x"])

        // A system program run by an agent: only the plist goes.
        let system = LaunchItem(plist: plist, label: "com.y", domain: .userAgent, program: "/bin/sh", arguments: [],
                                associatedBundleID: nil, runsAtLoad: true, isOrphaned: false)
        let systemHits = ThreatScanner.hits(for: [(URL(fileURLWithPath: "/bin/sh"), found)], apps: [], launchItems: [system])
        #expect(systemHits.map(\.paths) == [[plist.path]])
    }

    @Test func looseFilesThatCantBeSafelyRemovedGetNoHit() {
        let loose = dir.file("Loose/run.sh", "#!/bin/sh\n")
        let dotted = URL(fileURLWithPath: dir.path + "/Loose/../Loose/run.sh")
        #expect(dotted.path.contains(".."))
        let hits = ThreatScanner.hits(for: [(URL(fileURLWithPath: "/bin/ls"), found), (dotted, found)], apps: [], launchItems: [])
        #expect(hits.isEmpty)
        #expect(ThreatScanner.hits(for: [(loose, found)], apps: [], launchItems: []).map(\.paths) == [[real(loose)]])
    }

    @Test func looseFilesInsideAnUnlistedBundleRemoveTheBundle() {
        let bundle = dir.app("Loose/X.app", id: "com.x")
        let inner = dir.file("Loose/X.app/Contents/MacOS/x", "#!/bin/sh\n")
        let hits = ThreatScanner.hits(for: [(inner, found)], apps: [], launchItems: [])
        #expect(hits.map(\.paths) == [[real(bundle)]])
        #expect(hits.map(\.title) == ["X.app"])
    }

    @Test func cancellationStopsEarly() throws {
        let engine = try YaraEngine(source: "rule A { condition: false }")
        let files = (0..<50).map { dir.file("f\($0).sh", "#!/bin/sh\n") }
        let counter = ScanCounter()
        ThreatScanner.scan(files, engine: engine, counter: counter, isCancelled: { true })
        #expect(counter.snapshot().done == 0)
    }
}
