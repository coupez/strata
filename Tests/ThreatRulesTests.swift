import Foundation
import Testing
@testable import Strata

struct ThreatRulesTests {
    let unsigned: (String) -> Signature = { _ in Signature(kind: .unsigned, teamID: nil) }
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let apple: (String) -> Signature = { _ in Signature(kind: .apple, teamID: nil) }

    @Test func knownAdwareMatchesByPrefix() {
        #expect(KnownThreats.match("com.mackeeper.MacKeeper")?.family == "MacKeeper")
        #expect(KnownThreats.match("COM.MACKEEPER.helper") != nil)
        #expect(KnownThreats.match("com.mackeeperish.app") == nil)
        #expect(KnownThreats.match("com.google.Chrome") == nil)
    }

    @Test func unsignedProgramInAHiddenFolderIsSuspicious() {
        let reasons = Heuristics.reasons(for: makeItem("com.x.agent", program: "/Users/me/.hidden/agent"), signature: unsigned)
        #expect(reasons == ["Runs from a hidden folder", "Program isn't signed"])
    }

    @Test func trustedPackageManagerAppleAndOrphanedItemsAreFine() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/.hidden/agent"), signature: trusted).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("homebrew.mxcl.redis", program: "/opt/homebrew/opt/redis/bin/redis-server"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.apple.x", program: "/tmp/x"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/gone", orphaned: true), signature: unsigned).isEmpty)
    }

    @Test func interpreterRunningAScriptFromTempIsSuspicious() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs a bash script from a temporary folder"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["-c", "echo hi"]), signature: apple).isEmpty)
    }

    @Test func removablePathsSkipSystemAndAppPrograms() {
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"])) == ["/L/com.x.plist", "/tmp/run.sh"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Applications/X.app/Contents/MacOS/x")) == ["/L/com.x.plist"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Users/me/.hidden/agent")) == ["/L/com.x.plist", "/Users/me/.hidden/agent"])
    }

    @Test func staticHitsCoverAdwareBlockedExtensionsAndSuspiciousItems() {
        let adware = makeApp("/Applications/MacKeeper.app", id: "com.mackeeper.MacKeeper")
        let blocked = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.searchnt.safari"])
        let fine = makeApp("/Applications/Fine.app", id: "com.example.fine")
        let input = AppScanInput(apps: [adware, blocked, fine],
                                 launchItems: [makeItem("com.x.agent", program: "/Users/me/.hidden/agent")],
                                 support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.zeobit.keeper"), bundleID: "com.zeobit.keeper")],
                                 running: [], ownID: "com.lucascoupez.strata", now: .now, soundLibraries: [])
        let hits = StaticThreats.hits(input, blockedExtensionIDs: ["com.searchnt.safari"], signature: unsigned)
        #expect(hits.map(\.verdict) == [.adware, .malicious, .suspicious, .adware])
        #expect(hits.map(\.primary) == ["/Applications/MacKeeper.app", "/Applications/Search.app", "/L/com.x.agent.plist", "/S/com.zeobit.keeper"])
        #expect(hits[2].paths == ["/L/com.x.agent.plist", "/Users/me/.hidden/agent"])
    }
}
