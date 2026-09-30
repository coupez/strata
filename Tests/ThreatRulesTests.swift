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

    @Test func trustedPackageManagerAndOrphanedItemsAreFine() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/.hidden/agent"), signature: trusted).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("homebrew.mxcl.redis", program: "/opt/homebrew/opt/redis/bin/redis-server"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/gone", orphaned: true), signature: unsigned).isEmpty)
    }

    @Test func trustComesFromTheSignatureNeverTheLabel() {
        #expect(Heuristics.reasons(for: makeItem("com.apple.x", program: "/tmp/x"), signature: unsigned)
            == ["Runs from a temporary folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.evil.x", program: "/tmp/x"), signature: apple).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.apple.x", program: "/tmp/x"), signature: apple).isEmpty)
    }

    @Test func interpreterRunningAScriptFromTempIsSuspicious() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs a bash script from a temporary folder"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["-c", "echo hi"]), signature: apple).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/opt/homebrew/bin/python3.12", arguments: ["/tmp/run.py"]), signature: unsigned)
            == ["Runs a python3.12 script from a temporary folder"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/usr/bin/env", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs an env script from a temporary folder"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/usr/bin/osascript", arguments: ["/tmp/run.scpt"]), signature: apple)
            == ["Runs an osascript script from a temporary folder"])
    }

    @Test func usrLocalIsNotASystemFolderForInterpreters() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/usr/local/bin/python3.12", arguments: ["/tmp/run.py"]), signature: unsigned)
            == ["Program isn't signed"])
    }

    @Test func onlyTheFirstPathArgumentIsTheScript() {
        let vendor = makeItem("com.x", program: "/usr/bin/python3",
                              arguments: ["/Library/Application Support/Vendor/agent.py", "--log", "/tmp/agent.log"])
        #expect(Heuristics.reasons(for: vendor, signature: apple).isEmpty)
        #expect(Heuristics.removablePaths(of: vendor, signature: apple) == ["/L/com.x.plist"])
        let temp = makeItem("com.x", program: "/bin/zsh", arguments: ["/tmp/run.sh", "/Users/me/.config"])
        #expect(Heuristics.reasons(for: temp, signature: apple) == ["Runs a zsh script from a temporary folder"])
        #expect(Heuristics.removablePaths(of: temp, signature: apple) == ["/L/com.x.plist", "/tmp/run.sh"])
    }

    @Test func aFakeInterpreterIsJudgedAsAProgram() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/tmp/bash"), signature: unsigned)
            == ["Runs from a temporary folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/.hidden/python3"), signature: unsigned)
            == ["Runs from a hidden folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/perl5.30", arguments: ["/tmp/x.pl"]), signature: unsigned)
            == ["Program isn't signed"])
    }

    @Test func pathChecksIgnoreCaseAndSeeHiddenFiles() {
        #expect(Heuristics.isRiskyLocation("/TMP/x"))
        #expect(Heuristics.isRiskyLocation("/private/var/folders/ab/cd/T/x"))
        #expect(Heuristics.isRiskyLocation("/Users/me/Library/Application Support/.updater"))
        #expect(!Heuristics.isRiskyLocation("/Applications/Foo.app/Contents/MacOS/foo"))
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/Library/Application Support/.updater"), signature: unsigned)
            == ["Runs from a hidden folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/OPT/HOMEBREW/bin/x"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/BIN/BASH", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs a bash script from a temporary folder"])
    }

    @Test func removablePathsSkipSystemAndAppPrograms() {
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"]), signature: apple) == ["/L/com.x.plist", "/tmp/run.sh"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Applications/X.app/Contents/MacOS/x"), signature: unsigned) == ["/L/com.x.plist"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Users/me/.hidden/agent"), signature: unsigned) == ["/L/com.x.plist", "/Users/me/.hidden/agent"])
    }

    @Test func removablePathsNeverIncludeARealInterpreter() {
        let python = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: python, arguments: ["/tmp/x.py"]), signature: trusted)
            == ["/L/com.x.plist", "/tmp/x.py"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/tmp/bash", arguments: ["/tmp/x.sh"]), signature: unsigned)
            == ["/L/com.x.plist", "/tmp/bash"])
    }

    @Test func removablePathsTakeTheWholeBundleWhenItSitsInARiskyFolder() {
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/tmp/Evil.app/Contents/MacOS/evil"), signature: unsigned)
            == ["/L/com.x.plist", "/tmp/Evil.app"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/tmp/Evil.app/Contents/MacOS/evil"), signature: trusted)
            == ["/L/com.x.plist"])
    }

    @Test func staticHitsCoverAdwareBlockedExtensionsAndSuspiciousItems() {
        let adware = makeApp("/Applications/MacKeeper.app", id: "com.mackeeper.MacKeeper")
        let blocked = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.searchnt.safari"])
        let fine = makeApp("/Applications/Fine.app", id: "com.example.fine")
        let input = AppScanInput(apps: [adware, blocked, fine],
                                 launchItems: [makeItem("com.x.agent", program: "/Users/me/.hidden/agent")],
                                 support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.zeobit.keeper"), bundleID: "com.zeobit.keeper")],
                                 running: [], ownID: "com.lucascoupez.strata", now: .now, soundLibraries: [])
        let hits = StaticThreats.hits(input, blockedExtensions: ["com.searchnt.safari": ["T"]], signature: { path in
            path == "/Applications/Search.app" ? Signature(kind: .identified, teamID: "T") : Signature(kind: .unsigned, teamID: nil)
        })
        #expect(hits.map(\.verdict) == [.adware, .malicious, .suspicious, .adware])
        #expect(hits.map(\.primary) == ["/Applications/MacKeeper.app", "/Applications/Search.app", "/L/com.x.agent.plist", "/S/com.zeobit.keeper"])
        #expect(hits[2].paths == ["/L/com.x.agent.plist", "/Users/me/.hidden/agent"])
    }

    @Test func aBlockedExtensionIDFromAnotherDeveloperIsOnlySuspicious() {
        let app = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.searchnt.safari"])
        let input = AppScanInput(apps: [app], launchItems: [], support: [], running: [], ownID: "x", now: .now, soundLibraries: [])
        let otherTeam = StaticThreats.hits(input, blockedExtensions: ["com.searchnt.safari": ["T"]], signature: { _ in Signature(kind: .identified, teamID: "OTHER") })
        #expect(otherTeam.map(\.verdict) == [.suspicious])
        #expect(otherTeam.first?.reason == "Contains an extension ID Apple blocks for another developer (com.searchnt.safari)")
        let noDeveloperListed = StaticThreats.hits(input, blockedExtensions: ["com.searchnt.safari": []], signature: unsigned)
        #expect(noDeveloperListed.map(\.verdict) == [.suspicious])
        let match = StaticThreats.hits(input, blockedExtensions: ["com.searchnt.safari": ["T"]], signature: trusted)
        #expect(match.map(\.verdict) == [.malicious])
        #expect(match.first?.reason == "Contains an extension Apple blocks (com.searchnt.safari)")
    }

    @Test func anyMatchingBlockedIDMakesItMaliciousAndUnlistedDevelopersReadPlainly() {
        let app = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.first.ext", "com.second.ext"])
        let input = AppScanInput(apps: [app], launchItems: [], support: [], running: [], ownID: "x", now: .now, soundLibraries: [])
        let blocked: [String: Set<String>] = ["com.first.ext": ["OTHER"], "com.second.ext": ["T"]]
        let hits = StaticThreats.hits(input, blockedExtensions: blocked, signature: trusted)
        #expect(hits.map(\.verdict) == [.malicious])
        #expect(hits.first?.reason == "Contains an extension Apple blocks (com.second.ext)")
        let unlisted = StaticThreats.hits(input, blockedExtensions: ["com.first.ext": []], signature: trusted)
        #expect(unlisted.first?.reason == "Contains an extension ID Apple blocks (com.first.ext)")
    }
}
