import Foundation
import Testing
@testable import Strata

struct ClassifierTests {
    let now = Date(timeIntervalSince1970: 2_000_000_000)
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let size: (URL) -> Int64 = { _ in 10 }

    func days(_ count: Double) -> Date { now.addingTimeInterval(-count * 86_400) }

    func input(apps: [InstalledApp] = [], items: [LaunchItem] = [], support: [SupportEntry] = [],
               running: Set<String> = [], sounds: [URL] = [], runningBundles: Set<String> = []) -> AppScanInput {
        AppScanInput(apps: apps, launchItems: items, support: support, running: running,
                     ownID: "com.lucascoupez.strata", now: now, soundLibraries: sounds, runningBundlePaths: runningBundles)
    }

    /// Paths here are made up, so everything exists unless a test says otherwise.
    func classify(_ input: AppScanInput, days: Int = 90, hits: [ThreatHit] = [],
                  signature: ((String) -> Signature)? = nil, exists: @escaping (String) -> Bool = { _ in true }) -> [Finding] {
        Classifier.findings(input, unusedAfter: days, hits: hits, signature: signature ?? trusted, size: size, exists: exists)
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

    // MARK: Fix round 1

    static let appleSigned: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "F3LWYJ7GM7") }

    @Test func orphanedItemsStayOutOfInstalledAppFindings() {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let orphan = makeItem("com.a.updater", orphaned: true)
        let found = classify(input(apps: [app], items: [orphan]))
        #expect(Set(found.map(\.group)) == [.unused, .leftover])
        let paths = found.flatMap { $0.parts.map(\.url.path) }
        #expect(paths.count == Set(paths).count)
        #expect(found.filter { $0.group == .unused }.first?.parts.map(\.kind) == [.app])
        #expect(found.filter { $0.group == .leftover }.first?.parts.map(\.url.path) == [orphan.plist.path])
    }

    @Test func threatHitMovesPathsOutOfOtherFindings() {
        let item = makeItem("com.x.agent", program: "/Users/Shared/.x/agent")
        let hit = ThreatHit(paths: ["/Users/Shared/.x/agent", item.plist.path], verdict: .suspicious, reason: "Hidden", title: "com.x")
        let found = classify(input(items: [item]), hits: [hit])
        #expect(found.count == 1)
        #expect(found.first?.group == .threat)
        #expect(Set(found.first?.parts.map(\.url.path) ?? []) == ["/Users/Shared/.x/agent", item.plist.path])
        #expect(found.first?.parts.first { $0.url.path == item.plist.path }?.isLaunchItem == true)
    }

    @Test(arguments: [true, false])
    func launchItemOwnerIsTheClosestApp(chromeFirst: Bool) {
        let chrome = makeApp("/Applications/Google Chrome.app", id: "com.google.Chrome")
        let canary = makeApp("/Applications/Google Chrome Canary.app", id: "com.google.Chrome.canary")
        let item = makeItem("com.google.Chrome.canary.agent", program: "/usr/local/bin/agent")
        let owner = Classifier.owner(of: item, among: chromeFirst ? [chrome, canary] : [canary, chrome])
        #expect(owner?.bundleID == "com.google.Chrome.canary")
        let associated = makeItem("other.label", program: nil, associated: "com.google.Chrome.canary.helper")
        #expect(Classifier.owner(of: associated, among: chromeFirst ? [chrome, canary] : [canary, chrome])?.bundleID == "com.google.Chrome.canary")
    }

    @Test func appWithRunningHelperIsNotUnused() {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400), nested: ["com.a.helper"])
        #expect(classify(input(apps: [app], running: ["com.a.helper"])).isEmpty)
        #expect(classify(input(apps: [app])).count == 1)
    }

    @Test func appleSignedAppsAreNeverFlagged() {
        let old = makeApp("/Applications/Safari.app", id: "com.apple.Safari", lastUsed: days(400))
        #expect(classify(input(apps: [old]), signature: { _ in Signature(kind: .apple, teamID: nil) }).isEmpty)
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        #expect(classify(input(apps: [garageBand]), signature: { _ in Signature(kind: .apple, teamID: nil) }).map(\.group) == [.bloatware])
    }

    @Test func soundLibrariesBelongToMainStageToo() {
        let sounds = [URL(fileURLWithPath: "/Library/Application Support/GarageBand")]
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let mainStage = makeApp("/Applications/MainStage.app", id: Bloatware.mainStageID, lastUsed: days(1))
        let withGarageBand = classify(input(apps: [garageBand, mainStage], sounds: sounds), signature: Self.appleSigned)
        #expect(withGarageBand.flatMap { $0.parts.map(\.url) } == [garageBand.url])
        let alone = classify(input(apps: [mainStage], sounds: sounds), signature: Self.appleSigned)
        #expect(alone.isEmpty)
    }

    @Test func soundLibrariesAttachToTheFirstGarageBandOnly() {
        let sounds = [URL(fileURLWithPath: "/Library/Application Support/GarageBand")]
        let apps = [makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1)),
                    makeApp("/Users/me/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))]
        let found = classify(input(apps: apps, sounds: sounds), signature: Self.appleSigned)
        let paths = found.flatMap { $0.parts.map(\.url.path) }
        #expect(found.count == 2)
        #expect(paths.count == Set(paths).count)
        #expect(paths.filter { $0 == sounds[0].path }.count == 1)
    }

    @Test func runningFindingsAreNeverPreselected() {
        let running = Finding(id: "x", group: .threat, verdict: .malicious, title: "x", reasons: [], iconPath: nil,
                              parts: [], risk: .review, isRunning: true)
        #expect(!running.preselected)
        var idle = running
        idle.isRunning = false
        #expect(idle.preselected)
    }

    @Test func adwareIsCautionAndOtherThreatsReview() {
        func risk(_ verdict: Verdict) -> Risk? {
            let hit = ThreatHit(paths: ["/Users/Shared/x"], verdict: verdict, reason: "r", title: "x")
            return classify(input(), hits: [hit]).first?.risk
        }
        #expect(risk(.adware) == .caution)
        #expect(risk(.malicious) == .review)
        #expect(risk(.suspicious) == .review)
    }

    @Test func leftoverTitleKeepsOriginalCasing() {
        let entry = SupportEntry(url: URL(fileURLWithPath: "/S/com.Gone.App"), bundleID: "com.Gone.App")
        let finding = classify(input(support: [entry])).first
        #expect(finding?.title == "com.Gone.App")
        #expect(finding?.id == "leftover:com.gone.app")
    }

    // MARK: Fix round 2

    @Test func mergingKeepsTheStrongestEarlierVerdict() throws {
        let item = makeItem("com.x.agent", program: "/Users/Shared/.x/agent")
        let hits = [ThreatHit(paths: ["/Users/Shared/.x/agent"], verdict: .malicious, reason: "Matches XProtect", title: "agent"),
                    ThreatHit(paths: [item.plist.path, "/Users/Shared/.x/agent"], verdict: .suspicious, reason: "Hidden", title: "com.x")]
        let found = classify(input(items: [item]), hits: hits)
        let finding = try #require(found.first)
        #expect(found.count == 1)
        #expect(finding.group == .threat)
        #expect(finding.verdict == .malicious)
        #expect(finding.reasons.contains("Matches XProtect"))
        #expect(finding.reasons.contains("Hidden"))
        #expect(finding.preselected)
        #expect(Set(finding.parts.map(\.url.path)) == ["/Users/Shared/.x/agent", item.plist.path])
    }

    @Test func hitPathThatIsAParentAbsorbsExistingParts() {
        let first = ThreatHit(paths: ["/Users/Shared/.x/agent"], verdict: .adware, reason: "a", title: "agent")
        let parent = ThreatHit(paths: ["/Users/Shared/.x"], verdict: .suspicious, reason: "b", title: "x")
        let found = classify(input(), hits: [first, parent])
        #expect(found.count == 1)
        #expect(found.first?.parts.map(\.url.path) == ["/Users/Shared/.x"])
        #expect(found.first?.verdict == .adware)
        #expect(found.first?.risk == .caution)
    }

    // MARK: Final review

    @Test func findingsTouchingARunningBundleAreRunning() throws {
        let hits = [ThreatHit(paths: ["/Users/Shared/.x"], verdict: .malicious, reason: "a", title: "x"),
                    ThreatHit(paths: ["/Users/u/Downloads/Y.app/Contents/MacOS/y"], verdict: .malicious, reason: "b", title: "y"),
                    ThreatHit(paths: ["/Users/Shared/.z"], verdict: .malicious, reason: "c", title: "z")]
        let running = input(runningBundles: ["/Users/Shared/.x/Evil.app", "/Users/u/Downloads/Y.app"])
        let found = classify(running, hits: hits)
        let byID = Dictionary(uniqueKeysWithValues: found.map { ($0.id, $0) })
        let containing = try #require(byID["threat:/Users/Shared/.x"])
        let inside = try #require(byID["threat:/Users/u/Downloads/Y.app/Contents/MacOS/y"])
        let unrelated = try #require(byID["threat:/Users/Shared/.z"])
        #expect(containing.isRunning && !containing.preselected)
        #expect(inside.isRunning && !inside.preselected)
        #expect(!unrelated.isRunning && unrelated.preselected)
    }

    @Test func removedSoundLibrariesAreIgnored() {
        let kept = URL(fileURLWithPath: "/Library/Application Support/GarageBand")
        let removed = URL(fileURLWithPath: "/Library/Audio/Apple Loops/Apple")
        let some = classify(input(sounds: [kept, removed]), exists: { $0 == kept.path })
        #expect(some.map(\.id) == ["bloat:sounds"])
        #expect(some.first?.parts.map(\.url) == [kept])
        #expect(classify(input(sounds: [kept, removed]), exists: { _ in false }).isEmpty)

        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let attached = classify(input(apps: [garageBand], sounds: [kept, removed]), signature: Self.appleSigned,
                                exists: { $0 == kept.path })
        #expect(attached.first?.parts.map(\.url) == [garageBand.url, kept])
    }

    @Test func backgroundItemsSayWhenTheyRun() {
        func title(_ domain: LaunchDomain, atLoad: Bool) -> String? {
            let item = LaunchItem(plist: URL(fileURLWithPath: "/L/com.v.plist"), label: "com.v", domain: domain, program: "/x",
                                  arguments: [], associatedBundleID: nil, runsAtLoad: atLoad, isOrphaned: false)
            return classify(input(items: [item])).first { $0.group == .background }?.reasons.first
        }
        #expect(title(.userAgent, atLoad: true) == "Starts when you log in")
        #expect(title(.systemAgent, atLoad: true) == "Starts when anyone logs in")
        #expect(title(.systemDaemon, atLoad: true) == "Runs in the background as root")
        #expect(title(.userAgent, atLoad: false) == "Runs on demand")
        #expect(title(.systemAgent, atLoad: false) == "Runs on demand")
        #expect(title(.systemDaemon, atLoad: false) == "Runs on demand as root")
    }
}
