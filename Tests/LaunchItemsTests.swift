import Foundation
import Testing
@testable import Strata

struct LaunchItemsTests {
    let dir = TempDir()

    private func load(_ resolve: @escaping (String) -> URL? = { _ in nil }) -> [LaunchItem] {
        LaunchItems.load(from: [(dir.url, .userAgent)], resolveBundle: resolve)
    }

    @Test func readsProgramAndRunAtLoad() throws {
        dir.plist("a.plist", ["Label": "com.example.a", "Program": "/bin/ls", "RunAtLoad": true])
        let item = try #require(load().first)
        #expect(item.label == "com.example.a")
        #expect(item.program == "/bin/ls")
        #expect(item.runsAtLoad)
        #expect(!item.isOrphaned)
        #expect(item.domain == .userAgent)
        #expect(item.plist == dir.url.appendingPathComponent("a.plist"))
    }

    @Test func usesFirstProgramArgument() throws {
        dir.plist("b.plist", ["Label": "com.example.b", "ProgramArguments": ["/bin/sh", "/tmp/x.sh", "-v"]])
        let item = try #require(load().first)
        #expect(item.program == "/bin/sh")
        #expect(item.arguments == ["/tmp/x.sh", "-v"])
        #expect(!item.runsAtLoad)
    }

    @Test func missingProgramIsOrphaned() throws {
        dir.plist("c.plist", ["Label": "com.example.c", "Program": dir.path + "/gone/agent"])
        #expect(try #require(load().first).isOrphaned)
    }

    @Test func unreachableProgramIsNotOrphaned() throws {
        let program = dir.file("locked/agent", "#!/bin/sh\n")
        let locked = program.deletingLastPathComponent().path
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked) }
        dir.plist("c.plist", ["Label": "com.example.c", "Program": program.path])
        #expect(try !#require(load().first).isOrphaned)
    }

    @Test func programOnAnUnmountedDriveIsNotOrphaned() throws {
        dir.plist("c.plist", ["Label": "com.example.c", "Program": "/Volumes/NoSuchDrive/x"])
        #expect(try !#require(load().first).isOrphaned)
    }

    @Test func pathProbeOnlyCallsMissingPathsGone() throws {
        let file = dir.file("present")
        #expect(!PathProbe.isGone(file.path))
        #expect(PathProbe.isGone(dir.path + "/missing"))
        #expect(PathProbe.isGone(file.path + "/under-a-file"))
        let hidden = dir.file("locked/inner")
        let locked = hidden.deletingLastPathComponent().path
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked) }
        #expect(!PathProbe.isGone(hidden.path))
        #expect(!PathProbe.isGone(locked + "/never-there"))
    }

    @Test func relativeProgramIsResolvedAndNotOrphaned() throws {
        dir.plist("d.plist", ["Label": "com.example.d", "ProgramArguments": ["sh", "-c", "echo hi"]])
        let item = try #require(load().first)
        #expect(item.program?.hasSuffix("/sh") == true)
        #expect(!item.isOrphaned)
    }

    @Test func bundleProgramResolvesThroughItsApp() throws {
        let app = dir.app("Foo.app", id: "com.example.foo")
        dir.plist("e.plist", [
            "Label": "com.example.foo.helper", "BundleProgram": "Contents/MacOS/main",
            "AssociatedBundleIdentifiers": ["com.example.foo"],
        ])
        let found = try #require(load { $0 == "com.example.foo" ? app : nil }.first)
        #expect(found.program == app.appendingPathComponent("Contents/MacOS/main").path)
        #expect(found.associatedBundleID == "com.example.foo")
        #expect(!found.isOrphaned)
        #expect(try #require(load().first).isOrphaned)
    }

    @Test func bundleProgramWithoutAssociatedAppIsNotOrphaned() throws {
        dir.plist("g.plist", ["Label": "com.example.g", "BundleProgram": "Contents/MacOS/main"])
        let item = try #require(load().first)
        #expect(item.program == nil)
        #expect(!item.isOrphaned)
    }

    @Test func keepAliveDictionaryCountsAsRunAtLoad() throws {
        dir.plist("f.plist", ["Label": "com.example.f", "Program": "/bin/ls", "KeepAlive": ["SuccessfulExit": false]])
        #expect(try #require(load().first).runsAtLoad)
    }

    @Test func skipsBrokenPlistsAndFallsBackToFileName() {
        dir.file("broken.plist", "not a plist")
        dir.plist("com.example.nolabel.plist", ["Program": "/bin/ls"])
        dir.file("readme.txt")
        let items = load()
        #expect(items.map(\.label) == ["com.example.nolabel"])
    }
}
