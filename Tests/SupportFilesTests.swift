import Foundation
import Testing
@testable import Strata

struct SupportFilesTests {
    let dir = TempDir()

    @Test(arguments: zip(
        ["com.foo.Bar", "com.foo.Bar.plist", "com.foo.Bar.savedState", "com.foo.Bar.binarycookies",
         "ABCDE12345.com.foo.bar", "at.obdev.littlesnitch", "io.tailscale.ipn.macos"],
        ["com.foo.Bar", "com.foo.Bar", "com.foo.Bar", "com.foo.Bar",
         "com.foo.bar", "at.obdev.littlesnitch", "io.tailscale.ipn.macos"]))
    func parsesIDs(name: String, id: String) {
        #expect(SupportFiles.bundleID(fromName: name) == id)
    }

    @Test(arguments: ["Discord", "Google", "com.foo", "homebrew.mxcl.mysql", "foo..bar.baz", "com.foo bar.baz", "ByHost", "UBF8T346G9.Office"])
    func rejectsNonIDs(name: String) {
        #expect(SupportFiles.bundleID(fromName: name) == nil)
    }

    @Test func indexListsVisibleEntries() {
        dir.directory("Library/Caches/com.example.one")
        dir.file("Library/Caches/.hidden")
        dir.file("Library/Preferences/com.example.one.plist")
        let entries = SupportFiles.index([dir.url.appendingPathComponent("Library/Caches"),
                                          dir.url.appendingPathComponent("Library/Preferences")])
        #expect(entries.map(\.name) == ["com.example.one", "com.example.one.plist"])
        #expect(entries.map(\.bundleID) == ["com.example.one", "com.example.one"])
    }

    @Test func ownerMatchesByIDOrExactAppSupportName() {
        let app = InstalledApp(url: URL(fileURLWithPath: "/Applications/One.app"), bundleID: "com.example.one", name: "One",
                               version: nil, nestedBundleIDs: ["com.example.helperone"], size: 1, lastUsed: nil, dateAdded: nil)
        func entry(_ path: String) -> SupportEntry {
            SupportEntry(url: URL(fileURLWithPath: path), bundleID: SupportFiles.bundleID(fromName: (path as NSString).lastPathComponent))
        }
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.one"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Preferences/com.example.one.helper.plist"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.helperone"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Application Support/One"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/One"), among: [app]) == nil)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.onething"), among: [app]) == nil)
    }

    @Test func ownerPrefersTheClosestSiblingApp() {
        func app(_ id: String, _ name: String) -> InstalledApp {
            InstalledApp(url: URL(fileURLWithPath: "/Applications/\(name).app"), bundleID: id, name: name,
                         version: nil, nestedBundleIDs: [], size: 1, lastUsed: nil, dateAdded: nil)
        }
        func entry(_ name: String) -> SupportEntry {
            SupportEntry(url: URL(fileURLWithPath: "/u/Library/Caches/\(name)"), bundleID: SupportFiles.bundleID(fromName: name))
        }
        let chrome = app("com.google.Chrome", "Google Chrome"), canary = app("com.google.Chrome.canary", "Google Chrome Canary")
        for apps in [[chrome, canary], [canary, chrome]] {
            #expect(SupportFiles.owner(of: entry("com.google.Chrome.canary"), among: apps) == canary)
            #expect(SupportFiles.owner(of: entry("com.google.Chrome"), among: apps) == chrome)
            #expect(SupportFiles.owner(of: entry("com.google.Chrome.canary.helper.plist"), among: apps) == canary)
        }
    }
}
