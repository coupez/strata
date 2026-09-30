import Foundation
import Testing
@testable import Strata

struct PrivilegedRemoverTests {
    /// Paths here needn't exist, so most tests resolve nothing (identity).
    private let identity: (String) -> String? = { $0 }

    @Test(arguments: ["/Applications/Foo.app", "/Applications/Utilities/Foo.app", "/Library/LaunchDaemons/com.x.plist",
                      "/Library/LaunchAgents/com.x.plist", "/Library/PrivilegedHelperTools/com.x.helper",
                      "/Library/Application Support/Foo", "/Library/Audio/Apple Loops/Apple",
                      "/Library/Audio/Impulse Responses/Apple"])
    func allowsKnownLocations(path: String) {
        #expect(PrivilegedRemover.isAllowed(path, resolve: identity))
    }

    @Test(arguments: ["/Applications", "/Library/LaunchDaemons", "/System/Library/CoreServices/Finder.app", "/usr/bin/ls",
                      "/bin/sh", "/Library/Apple/System", "/private/var/db/foo", "relative/path", "/Applications/../usr/bin",
                      "/Applications/./Foo.app", "/Applications/Bad\nName.app", "/Library/Keychains/x",
                      "/Applications/Foo.app/", "/Applications//Foo.app", "/APPLICATIONS/Utilities", "/applications/utilities",
                      "/Library/Preferences/SystemConfiguration/preferences.plist", "/Library/Application Support/Apple/ParentalControls",
                      "/Library/Application Support/com.apple.TCC", "/Library/Caches/com.apple.amsengagementd",
                      "/Users/me/Library/Caches/com.x", "/Users/me/.ssh",
                      "/Library/Preferences/.GlobalPreferences.plist", "/Library/Preferences/OpenDirectory",
                      "/Library/Preferences/OpenDirectory/Configurations"])
    func rejectsEverythingElse(path: String) {
        #expect(!PrivilegedRemover.isAllowed(path, resolve: identity))
    }

    @Test(arguments: Bloatware.soundLibraryPaths)
    func soundLibrariesCanBeRemovedAsRoot(path: String) {
        #expect(PrivilegedRemover.isAllowed(path, resolve: identity))
    }

    @Test func realResolverAcceptsExistingApplicationsChildren() {
        #expect(PrivilegedRemover.isAllowed("/Applications/Foo.app"))
        #expect(!PrivilegedRemover.isAllowed("/Applications/Missing/Foo.app"))
    }

    @Test func symlinkedParentCantEscape() {
        #expect(!PrivilegedRemover.isAllowed("/Applications/Evil/ls", resolve: { $0 == "/Applications/Evil" ? "/usr/bin" : $0 }))
    }

    @Test func quotesAwkwardPaths() {
        #expect(PrivilegedRemover.quote("/Applications/Bob's \"App\" $HOME `x`.app") == #"'/Applications/Bob'\''s "App" $HOME `x`.app'"#)
    }

    @Test func scriptTrashesIntoAFreshRootMadeFolderAndReportsEachItem() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Library/LaunchDaemons/com.x.plist"), trash: true),
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/My App.app"), trash: false),
        ], trashDirectory: "/Users/me/.Trash", resolve: identity)
        #expect(script == [
            "cd /",
            "if cd -P -- '/Users/me/.Trash' 2>/dev/null && [ \"$(pwd -P)\" = '/Users/me/.Trash' ] && bin=$(/usr/bin/mktemp -d './Removed by Strata.XXXXXX'); then bin='/Users/me/.Trash'/\"${bin#./}\"; else bin=''; fi",
            "cd /",
            "if cd -P -- '/Library/LaunchDaemons' 2>/dev/null && [ \"$(pwd -P)\" = '/Library/LaunchDaemons' ]; then",
            "/bin/launchctl bootout system '/Library/LaunchDaemons/com.x.plist' 2>/dev/null",
            "if [ -n \"$bin\" ] && /bin/mkdir -- \"$bin/0\" && /bin/mv -n -- './com.x.plist' \"$bin/0/\" && [ ! -e './com.x.plist' ] && [ ! -L './com.x.plist' ]; then echo OK 0; else echo FAIL 0; fi",
            "else echo FAIL 0; fi",
            "cd /",
            "if cd -P -- '/Applications' 2>/dev/null && [ \"$(pwd -P)\" = '/Applications' ]; then",
            "if /bin/rm -rf -- './My App.app'; then echo OK 1; else echo FAIL 1; fi",
            "else echo FAIL 1; fi",
            "cd /",
        ].joined(separator: "\n"))
        #expect(!script.contains("chown"))
    }

    /// Runs the script's Trash setup as the current user (the one item fails vetting, so nothing is touched).
    private func trashFolder(for trashDirectory: String) throws -> String {
        let script = PrivilegedRemover.script(for: [ElevatedOperation(url: URL(fileURLWithPath: "/Applications/x.app"), trash: true)],
                                              trashDirectory: trashDirectory, resolve: { _ in nil })
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", script + "\necho \"BIN=$bin\""]
        process.standardOutput = output
        try process.run()
        process.waitUntilExit()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(text.hasPrefix("FAIL 0\n"))
        return text.components(separatedBy: "BIN=").last?.trimmingCharacters(in: .newlines) ?? ""
    }

    @Test func trashFolderIsMadeInsideTheVerifiedTrash() throws {
        let dir = TempDir()
        // As in `run`, the Trash path is fully resolved (TempDir's /var is really /private/var).
        let trash = try #require(PrivilegedRemover.realpathOf(dir.directory("Trash it's \"$x\"").path))
        let bin = try trashFolder(for: trash)
        #expect(bin.hasPrefix(trash + "/Removed by Strata."))
        var isDirectory: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: bin, isDirectory: &isDirectory) && isDirectory.boolValue)
        #expect(try FileManager.default.contentsOfDirectory(atPath: trash).count == 1)
    }

    @Test func trashFolderIsNeverMadeThroughASymlink() throws {
        let dir = TempDir()
        let root = try #require(PrivilegedRemover.realpathOf(dir.path))
        let elsewhere = dir.directory("elsewhere")
        let link = root + "/Trash"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: elsewhere.path)
        #expect(try trashFolder(for: link) == "")
        #expect(try FileManager.default.contentsOfDirectory(atPath: elsewhere.path).isEmpty)
        #expect(try trashFolder(for: root + "/missing") == "")
    }

    @Test func scriptNeverTrustsASecondResolution() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/Evil/x.app"), trash: false),
        ], trashDirectory: "/Users/me/.Trash", resolve: { $0 == "/Applications/Evil" ? "/Library/Keychains" : $0 })
        #expect(script == "cd /\nbin=''\necho FAIL 0")
        #expect(!script.contains("Keychains"))
    }

    @Test func vettedReturnsTheResolvedParentAndName() {
        let vetted = PrivilegedRemover.vetted("/Applications/Link/x.app", resolve: { $0 == "/Applications/Link" ? "/Applications/Real" : $0 })
        #expect(vetted?.parent == "/Applications/Real")
        #expect(vetted?.name == "x.app")
    }

    @Test func sameNamedTrashItemsGetTheirOwnFolders() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/A/x.app"), trash: true),
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/B/x.app"), trash: true),
        ], trashDirectory: "/Users/me/.Trash", resolve: identity)
        #expect(script.contains(#"/bin/mkdir -- "$bin/0""#))
        #expect(script.contains(#"/bin/mkdir -- "$bin/1""#))
    }

    @Test func scriptWithoutTrashHasNoTrashFolder() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/Foo.app"), trash: false),
        ], trashDirectory: "/Users/me/.Trash", resolve: identity)
        #expect(script.hasPrefix("cd /\nbin=''\n"))
        #expect(!script.contains("mktemp"))
        #expect(!script.contains("chown"))
    }

    @Test func scriptFailsItemsWhoseParentCantBeResolved() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/Foo.app"), trash: false),
        ], trashDirectory: "/Users/me/.Trash", resolve: { _ in nil })
        #expect(script == "cd /\nbin=''\necho FAIL 0")
    }

    @Test func scriptQuotesAwkwardNames() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/Bob's $HOME `x`.app"), trash: false),
        ], trashDirectory: "/Users/me/.Trash", resolve: identity)
        #expect(script.contains(#"/bin/rm -rf -- './Bob'\''s $HOME `x`.app'"#))
    }

    @Test func appleScriptEscapesQuotesBackslashesAndNewlines() {
        #expect(PrivilegedRemover.appleScript(for: "echo \"a\\b\"\nnext")
            == #"do shell script "echo \"a\\b\"\nnext" with administrator privileges without altering line endings"#)
    }

    @Test func parsesPerItemResults() {
        #expect(PrivilegedRemover.parse("OK 0\nFAIL 1\rOK 2\n", count: 4) == [true, false, true, false])
    }

    @Test func elevationCandidatesAreFailedEligibleItems() {
        let stuck = URL(fileURLWithPath: "/Applications/stuck")
        let operations = [
            DeletionOperation(label: "a", kind: .trash(stuck), estimatedBytes: 1),
            DeletionOperation(label: "b", kind: .remove(URL(fileURLWithPath: "/Applications/other")), estimatedBytes: 1),
            DeletionOperation(label: "c", kind: .remove(stuck), estimatedBytes: 1),
            DeletionOperation(label: "d", kind: .unload(target: "gui/501/x"), estimatedBytes: 0),
            DeletionOperation(label: "e", kind: .trash(stuck), estimatedBytes: 1),
        ]
        let outcomes: [DeletionOutcome] = [.failed("denied"), .failed("denied"), .removed, .failed("x"), .removed]
        let candidates = PrivilegedRemover.elevationCandidates(operations, outcomes: outcomes, isEligible: { $0.hasSuffix("stuck") })
        #expect(candidates.map(\.index) == [0])
        #expect(candidates.first?.operation == ElevatedOperation(url: stuck, trash: true))
    }

    @Test func needsRootRejectsUserOwnedAndMissingItems() throws {
        #expect(!PrivilegedRemover.needsRoot("/Applications/Definitely Missing.app"))
        let mine = TempDir().file("x")
        #expect(!PrivilegedRemover.needsRoot(mine.path))
    }
}
