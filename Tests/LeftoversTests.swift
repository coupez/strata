import Foundation
import Testing
@testable import Strata

struct LeftoversTests {
    func entry(_ path: String) -> SupportEntry {
        SupportEntry(url: URL(fileURLWithPath: path), bundleID: SupportFiles.bundleID(fromName: (path as NSString).lastPathComponent))
    }

    func item(_ label: String, orphaned: Bool) -> LaunchItem {
        LaunchItem(plist: URL(fileURLWithPath: "/L/\(label).plist"), label: label, domain: .userAgent, program: "/x",
                   arguments: [], associatedBundleID: nil, runsAtLoad: true, isOrphaned: orphaned)
    }

    func find(_ entries: [SupportEntry], items: [LaunchItem] = [], installed: [String] = [], running: Set<String> = []) -> [LeftoverGroup] {
        Leftovers.find(entries: entries, launchItems: items, installedIDs: installed, runningIDs: running, ownID: "com.lucascoupez.strata")
    }

    @Test func groupsEntriesOfAnUninstalledApp() {
        let groups = find([entry("/S/com.gone.app"), entry("/C/com.gone.app.cache"), entry("/P/com.gone.app.plist")])
        #expect(groups.map(\.key) == ["com.gone.app"])
        #expect(groups.first?.entries.count == 3)
    }

    @Test func skipsAppleOwnAndNonIDs() {
        #expect(find([entry("/S/com.apple.Safari"), entry("/S/com.lucascoupez.strata"), entry("/S/Discord")]).isEmpty)
    }

    @Test func skipsWhenVendorStillInstalled() {
        #expect(find([entry("/S/com.google.Keystone")], installed: ["com.google.Chrome"]).isEmpty)
        #expect(find([entry("/S/com.Google.Keystone")], installed: ["com.google.Chrome"]).isEmpty)
    }

    @Test func teamPrefixedEntriesMatchInstalledApps() {
        #expect(find([entry("/G/ABCDE12345.com.example.one")], installed: ["com.example.one"]).isEmpty)
    }

    @Test func skipsRunningAndLiveLaunchItemVendors() {
        #expect(find([entry("/S/com.cli.tool")], running: ["com.cli.tool"]).isEmpty)
        #expect(find([entry("/S/com.github.facebook.watchman")], items: [item("com.github.facebook.watchman", orphaned: false)]).isEmpty)
    }

    @Test func groupsOrphanedLaunchItemsWithTheirFiles() {
        let groups = find([entry("/S/com.gone.app")], items: [item("com.gone.app.updater", orphaned: true), item("com.apple.x", orphaned: true), item("Fing", orphaned: true)])
        #expect(groups.map(\.key) == ["Fing", "com.gone.app"])
        #expect(groups.last?.launchItems.map(\.label) == ["com.gone.app.updater"])
        #expect(groups.last?.entries.count == 1)
    }
}
