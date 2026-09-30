import Foundation
import Testing
@testable import Strata

struct ThreatRulesTests {
    let unsigned: (String) -> Signature = { _ in Signature(kind: .unsigned, teamID: nil) }
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let apple: (String) -> Signature = { _ in Signature(kind: .apple, teamID: nil) }
    /// A hidden item whose folder really exists and isn't a temporary one (only the parent has to exist).
    let hiddenAgent = NSHomeDirectory() + "/.agent"

    private func real(_ path: String) -> String { PrivilegedRemover.realpathOf(path)! }

    @Test func knownAdwareMatchesByPrefix() {
        #expect(KnownThreats.match("com.mackeeper.MacKeeper")?.family == "MacKeeper")
        #expect(KnownThreats.match("COM.MACKEEPER.helper") != nil)
        #expect(KnownThreats.match("com.mackeeperish.app") == nil)
        #expect(KnownThreats.match("com.google.Chrome") == nil)
    }

    @Test func unsignedProgramInAHiddenFolderIsSuspicious() {
        let reasons = Heuristics.reasons(for: makeItem("com.x.agent", program: hiddenAgent), signature: unsigned)
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
        #expect(Heuristics.removablePaths(of: temp, signature: apple) == ["/L/com.x.plist", "/private/tmp/run.sh"])
    }

    @Test func aFakeInterpreterIsJudgedAsAProgram() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/tmp/bash"), signature: unsigned)
            == ["Runs from a temporary folder", "Program isn't signed"])
        // TempDir lives in /var/folders, so the temporary folder is named before the hidden one.
        let temp = TempDir()
        temp.directory(".hidden")
        #expect(Heuristics.reasons(for: makeItem("com.x", program: temp.path + "/.hidden/python3"), signature: unsigned)
            == ["Runs from a temporary folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/perl5.30", arguments: ["/tmp/x.pl"]), signature: unsigned)
            == ["Program isn't signed"])
    }

    @Test func pathChecksIgnoreCaseAndSeeHiddenFiles() {
        #expect(Heuristics.isRiskyLocation("/TMP/x"))
        #expect(Heuristics.isRiskyLocation(real(NSTemporaryDirectory()) + "/x"))
        #expect(real(NSTemporaryDirectory()).hasPrefix("/private/var/folders/"))
        #expect(Heuristics.isRiskyLocation(NSHomeDirectory() + "/Library/Application Support/.updater"))
        #expect(!Heuristics.isRiskyLocation("/Applications/Foo.app/Contents/MacOS/foo"))
        #expect(Heuristics.reasons(for: makeItem("com.x", program: NSHomeDirectory() + "/Library/Application Support/.updater"), signature: unsigned)
            == ["Runs from a hidden folder", "Program isn't signed"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/OPT/HOMEBREW/bin/x"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/BIN/BASH", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs a bash script from a temporary folder"])
    }

    @Test func removablePathsSkipSystemAndAppPrograms() {
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"]), signature: apple) == ["/L/com.x.plist", "/private/tmp/run.sh"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Applications/X.app/Contents/MacOS/x"), signature: unsigned) == ["/L/com.x.plist"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: hiddenAgent), signature: unsigned) == ["/L/com.x.plist", hiddenAgent])
    }

    @Test func removablePathsNeverIncludeARealInterpreter() {
        let python = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: python, arguments: ["/tmp/x.py"]), signature: trusted)
            == ["/L/com.x.plist", "/private/tmp/x.py"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/tmp/bash", arguments: ["/tmp/x.sh"]), signature: unsigned)
            == ["/L/com.x.plist", "/private/tmp/bash"])
    }

    @Test func removablePathsTakeTheWholeBundleWhenItSitsInARiskyFolder() {
        let temp = TempDir()
        temp.directory("Evil.app/Contents/MacOS")
        let evil = makeItem("com.x", program: temp.path + "/Evil.app/Contents/MacOS/evil")
        #expect(Heuristics.removablePaths(of: evil, signature: unsigned) == ["/L/com.x.plist", real(temp.path) + "/Evil.app"])
        #expect(Heuristics.removablePaths(of: evil, signature: trusted) == ["/L/com.x.plist"])
    }

    @Test func dotDotPathsAreNeverTheScriptNorRemovable() {
        let sneaky = makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/../Users/me/Documents"])
        #expect(Heuristics.reasons(for: sneaky, signature: apple).isEmpty)
        #expect(Heuristics.removablePaths(of: sneaky, signature: apple) == ["/L/com.x.plist"])
        #expect(!Heuristics.isRiskyLocation("/tmp/../Users/me/Documents"))

        let adware = makeItem("com.vsearch.agent", program: "/tmp/../Users/me/bin/x")
        let paths = Heuristics.removablePaths(of: adware, signature: unsigned)
        #expect(paths == ["/L/com.vsearch.agent.plist"])
        #expect(!paths.contains { $0.contains("..") })
        // Judged by where it really is, not by the path as written.
        #expect(Heuristics.reasons(for: adware, signature: unsigned) == ["Program isn't signed"])
    }

    @Test func symlinkedFoldersAreJudgedWhereTheyReallyLead() throws {
        let temp = TempDir()
        try FileManager.default.createSymbolicLink(atPath: temp.path + "/lnk", withDestinationPath: NSHomeDirectory())
        let redirected = makeItem("com.x", program: "/bin/bash", arguments: [temp.path + "/lnk/Documents"])
        #expect(!Heuristics.isRiskyLocation(temp.path + "/lnk/Documents"))
        #expect(Heuristics.reasons(for: redirected, signature: apple).isEmpty)
        #expect(Heuristics.removablePaths(of: redirected, signature: apple) == ["/L/com.x.plist"])

        // A symlinked item itself is judged and removed as the link, never its target.
        try FileManager.default.createSymbolicLink(atPath: temp.path + "/evil-link", withDestinationPath: NSHomeDirectory() + "/Documents")
        let link = real(temp.path) + "/evil-link"
        let script = makeItem("com.x", program: "/bin/bash", arguments: [temp.path + "/evil-link"])
        #expect(Heuristics.reasons(for: script, signature: apple) == ["Runs a bash script from a temporary folder"])
        #expect(Heuristics.removablePaths(of: script, signature: apple) == ["/L/com.x.plist", link])
        let program = makeItem("com.x", program: temp.path + "/evil-link")
        #expect(Heuristics.reasons(for: program, signature: unsigned) == ["Runs from a temporary folder", "Program isn't signed"])
        #expect(Heuristics.removablePaths(of: program, signature: unsigned) == ["/L/com.x.plist", link])
    }

    @Test func pathsWhoseFolderIsMissingAreUnusable() {
        let missing = "/tmp/strata-missing-\(UUID().uuidString)/run.sh"
        #expect(!Heuristics.isRiskyLocation(missing))
        let item = makeItem("com.x", program: "/bin/bash", arguments: [missing, "/tmp/run.sh"])
        #expect(Heuristics.reasons(for: item, signature: apple).isEmpty)
        #expect(Heuristics.removablePaths(of: item, signature: apple) == ["/L/com.x.plist"])
    }

    @Test func staticHitsCoverAdwareBlockedExtensionsAndSuspiciousItems() {
        let adware = makeApp("/Applications/MacKeeper.app", id: "com.mackeeper.MacKeeper")
        let blocked = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.searchnt.safari"])
        let fine = makeApp("/Applications/Fine.app", id: "com.example.fine")
        let input = AppScanInput(apps: [adware, blocked, fine],
                                 launchItems: [makeItem("com.x.agent", program: hiddenAgent)],
                                 support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.zeobit.keeper"), bundleID: "com.zeobit.keeper")],
                                 running: [], ownID: "com.lucascoupez.strata", now: .now, soundLibraries: [])
        let hits = StaticThreats.hits(input, blockedExtensions: ["com.searchnt.safari": ["T"]], signature: { path in
            path == "/Applications/Search.app" ? Signature(kind: .identified, teamID: "T") : Signature(kind: .unsigned, teamID: nil)
        })
        #expect(hits.map(\.verdict) == [.adware, .malicious, .suspicious, .adware])
        #expect(hits.map(\.primary) == ["/Applications/MacKeeper.app", "/Applications/Search.app", "/L/com.x.agent.plist", "/S/com.zeobit.keeper"])
        #expect(hits[2].paths == ["/L/com.x.agent.plist", hiddenAgent])
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
