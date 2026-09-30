import Foundation
import Testing
@testable import Strata

struct ClassifierTests {
    let now = Date(timeIntervalSince1970: 2_000_000_000)
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let size: (URL) -> Int64 = { _ in 10 }

    func days(_ count: Double) -> Date { now.addingTimeInterval(-count * 86_400) }

    func input(apps: [InstalledApp] = [], items: [LaunchItem] = [], support: [SupportEntry] = [],
               running: Set<String> = [], sounds: [URL] = []) -> AppScanInput {
        AppScanInput(apps: apps, launchItems: items, support: support, running: running,
                     ownID: "com.lucascoupez.strata", now: now, soundLibraries: sounds)
    }

    func classify(_ input: AppScanInput, days: Int = 90, hits: [ThreatHit] = [],
                  signature: ((String) -> Signature)? = nil) -> [Finding] {
        Classifier.findings(input, unusedAfter: days, hits: hits, signature: signature ?? trusted, size: size)
    }

    @Test func unusedAppsRespectTheThreshold() {
        let apps = [
            makeApp("/Applications/A.app", id: "com.a", lastUsed: days(100)),
            makeApp("/Applications/B.app", id: "com.b", lastUsed: days(10)),
            makeApp("/Applications/C.app", id: "com.c", added: days(200)),
            makeApp("/Applications/D.app", id: "com.d"),
        ]
        #expect(Set(classify(input(apps: apps)).map(\.title)) == ["A", "C"])
        #expect(Set(classify(input(apps: apps), days: 5).map(\.title)) == ["A", "B", "C"])
        let a = classify(input(apps: apps)).first { $0.title == "A" }
        #expect(a?.group == .unused)
        #expect(a?.risk == .review)
        #expect(a?.preselected == false)
        #expect(a?.reasons.first?.hasPrefix("Last opened") == true)
    }

    @Test func runningAndOwnAppsAreNeverListed() {
        let apps = [makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400)),
                    makeApp("/Applications/Strata.app", id: "com.lucascoupez.strata", lastUsed: days(400))]
        #expect(classify(input(apps: apps, running: ["com.a"])).isEmpty)
    }

    @Test func unusedFindingIncludesSupportFilesAndLaunchItems() throws {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let support = [SupportEntry(url: URL(fileURLWithPath: "/S/com.a"), bundleID: "com.a")]
        let agent = makeItem("com.a.agent", program: "/Applications/A.app/Contents/MacOS/agent")
        let finding = try #require(classify(input(apps: [app], items: [agent], support: support)).first)
        #expect(finding.parts.map(\.kind) == [.app, .support, .launchItem(label: "com.a.agent", domain: .userAgent)])
        #expect(finding.size == 100 + 10 + 10)
        #expect(finding.id == "app:/Applications/A.app")
    }

    @Test func bloatwareNeedsTheAppleTeam() {
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let apple: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "F3LWYJ7GM7") }
        let found = classify(input(apps: [garageBand]), signature: apple)
        #expect(found.map(\.group) == [.bloatware])
        #expect(found.first?.risk == .caution)
        #expect(classify(input(apps: [garageBand]), signature: { _ in Signature(kind: .identified, teamID: "EVIL") }).isEmpty)
    }

    @Test func soundLibrariesFollowGarageBandUnlessLogicIsInstalled() {
        let sounds = [URL(fileURLWithPath: "/Library/Application Support/GarageBand")]
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let logic = makeApp("/Applications/Logic Pro.app", id: Bloatware.logicID, lastUsed: days(1))
        let apple: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "F3LWYJ7GM7") }

        let withGarageBand = classify(input(apps: [garageBand], sounds: sounds), signature: apple)
        #expect(withGarageBand.first?.parts.map(\.url) == [garageBand.url] + sounds)

        let withLogic = classify(input(apps: [garageBand, logic], sounds: sounds), signature: apple)
        #expect(withLogic.first?.parts.map(\.url) == [garageBand.url])

        let alone = classify(input(sounds: sounds))
        #expect(alone.map(\.id) == ["bloat:sounds"])
    }

    @Test func leftoversBecomeFindings() {
        let orphan = makeItem("com.gone.updater", orphaned: true)
        let onlyItem = classify(input(items: [orphan]))
        #expect(onlyItem.map(\.group) == [.leftover])
        #expect(onlyItem.first?.risk == .safe)
        #expect(onlyItem.first?.preselected == true)

        let onlyFiles = classify(input(support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.gone.app"), bundleID: "com.gone.app")]))
        #expect(onlyFiles.first?.risk == .review)
        #expect(onlyFiles.first?.preselected == false)
    }

    @Test func backgroundItemsSkipAppleAndClaimedItems() {
        let unused = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let items = [
            makeItem("com.apple.thing"),
            makeItem("com.vendor.agent", program: "/usr/local/bin/agent"),
            makeItem("com.a.agent", program: "/Applications/A.app/Contents/MacOS/agent"),
        ]
        let found = classify(input(apps: [unused], items: items))
        #expect(found.filter { $0.group == .background }.map(\.title) == ["com.vendor.agent"])
        #expect(found.filter { $0.group == .unused }.count == 1)
    }

    @Test func duplicateBundleIDsStaySeparate() {
        let apps = [makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400)),
                    makeApp("/Users/me/Applications/A.app", id: "com.a", lastUsed: days(400))]
        let found = classify(input(apps: apps, support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.a"), bundleID: "com.a")]))
        #expect(Set(found.map(\.id)).count == 2)
        let allPaths = found.flatMap { $0.parts.map(\.url.path) }
        #expect(allPaths.count == Set(allPaths).count)
    }

    @Test func threatHitConvertsTheAppsFinding() throws {
        let active = makeApp("/Applications/Evil.app", id: "com.evil", lastUsed: days(1))
        let hit = ThreatHit(paths: ["/Applications/Evil.app"], verdict: .malicious, reason: "Matches XProtect", title: "Evil")
        let finding = try #require(classify(input(apps: [active]), hits: [hit]).first)
        #expect(finding.group == .threat)
        #expect(finding.verdict == .malicious)
        #expect(finding.reasons.first == "Matches XProtect")
        #expect(finding.preselected)
    }

    @Test func threatHitElsewhereCreatesItsOwnFinding() {
        let hit = ThreatHit(paths: ["/Users/Shared/.x/agent", "/L/com.x.plist"], verdict: .suspicious, reason: "Hidden", title: "com.x")
        let found = classify(input(), hits: [hit])
        #expect(found.map(\.id) == ["threat:/Users/Shared/.x/agent"])
        #expect(found.first?.parts.count == 2)
        #expect(found.first?.preselected == false)
    }

    @Test func strongestVerdictWins() {
        let app = makeApp("/Applications/Keeper.app", id: "com.keeper", lastUsed: days(1))
        let hits = [ThreatHit(paths: [app.path], verdict: .suspicious, reason: "a", title: "Keeper"),
                    ThreatHit(paths: [app.path], verdict: .adware, reason: "b", title: "Keeper")]
        #expect(classify(input(apps: [app]), hits: hits).first?.verdict == .adware)
    }

    @Test func untrustedAppsSayWhy() {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let found = classify(input(apps: [app]), signature: { _ in Signature(kind: .unsigned, teamID: nil) })
        #expect(found.first?.reasons.last == "Not signed")
    }
}
