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
            "bin=$(/usr/bin/mktemp -d '/Users/me/.Trash/Removed by Strata.XXXXXX') || bin=''",
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
