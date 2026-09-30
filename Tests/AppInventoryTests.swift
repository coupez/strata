import Foundation
import Testing
@testable import Strata

struct AppInventoryTests {
    let dir = TempDir()
    let noUsage: (URL) -> (lastUsed: Date?, added: Date?) = { _ in (nil, nil) }

    @Test func findsAppsInLocationsAndOneLevelOfSubfolders() {
        dir.app("Apps/One.app", id: "com.example.one")
        dir.app("Apps/Utilities/Two.app", id: "com.example.two")
        dir.app("Apps/Deep/Nested/Three.app", id: "com.example.three")
        dir.file("Apps/readme.txt")
        let names = AppInventory.bundles(in: [dir.url.appendingPathComponent("Apps")]).map(\.lastPathComponent)
        #expect(names == ["One.app", "Two.app"])
    }

    @Test func readsBundleDetailsAndNestedIDs() throws {
        let app = dir.app("One.app", id: "com.example.one")
        dir.app("One.app/Contents/Frameworks/One Helper.app", id: "com.example.one.helper")
        dir.app("One.app/Contents/Library/LoginItems/Launcher.app", id: "com.example.one.launcher")
        dir.plist("One.app/Contents/PlugIns/Share.appex/Contents/Info.plist", ["CFBundleIdentifier": "com.example.one.share"])
        dir.plist("One.app/Contents/Resources/Ignored.app/Contents/Info.plist", ["CFBundleIdentifier": "com.example.ignored"])
        let used = Date(timeIntervalSince1970: 1_000)

        let installed = try #require(AppInventory.read(app, usage: { _ in (used, nil) }))
        #expect(installed.bundleID == "com.example.one")
        #expect(installed.name == "One")
        #expect(installed.version == "1.0")
        #expect(installed.lastUsed == used)
        #expect(installed.dateAdded == nil)
        #expect(Set(installed.nestedBundleIDs) == ["com.example.one.helper", "com.example.one.launcher", "com.example.one.share"])
        #expect(installed.size > 0)
        #expect(installed.path == app.path)
    }

    @Test func readsWrappedIOSApps() throws {
        dir.plist("Wrapped.app/Wrapper/Wrapped.app/Info.plist",
                  ["CFBundleIdentifier": "com.example.wrapped", "CFBundleShortVersionString": "2.0"])
        let app = dir.url.appendingPathComponent("Wrapped.app")
        try FileManager.default.createSymbolicLink(atPath: app.appendingPathComponent("WrappedBundle").path,
                                                   withDestinationPath: "Wrapper/Wrapped.app")
        let installed = try #require(AppInventory.read(app, usage: noUsage))
        #expect(installed.bundleID == "com.example.wrapped")
        #expect(installed.version == "2.0")
        #expect(installed.name == "Wrapped")
    }

    @Test func skipsBundlesWithoutIdentifier() {
        dir.file("Broken.app/Contents/MacOS/x")
        #expect(AppInventory.read(dir.url.appendingPathComponent("Broken.app"), usage: noUsage) == nil)
    }

    @Test func loadReadsEveryBundle() {
        dir.app("A.app", id: "com.example.a")
        dir.app("B.app", id: "com.example.b")
        dir.file("C.app/Contents/MacOS/x")
        let apps = AppInventory.load(locations: [dir.url], usage: noUsage)
        #expect(apps.map(\.bundleID).sorted() == ["com.example.a", "com.example.b"])
    }

    @Test func skipsSymlinkedApps() throws {
        let real = dir.app("Real/Tool.app", id: "com.example.tool")
        dir.directory("Apps")
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("Apps/Tool.app"), withDestinationURL: real)
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("Apps/Alias"), withDestinationURL: dir.url.appendingPathComponent("Real"))
        dir.app("Apps/Sub/Inner.app", id: "com.example.inner")
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("Apps/Sub/Link.app"), withDestinationURL: real)
        let names = AppInventory.bundles(in: [dir.url.appendingPathComponent("Apps")]).map(\.lastPathComponent)
        #expect(names == ["Inner.app"])
    }
}
