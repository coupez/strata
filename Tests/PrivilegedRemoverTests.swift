import Foundation
import Testing
@testable import Strata

struct PrivilegedRemoverTests {
    let home = TempDir()

    @Test(arguments: ["/Applications/Foo.app", "/Applications/Utilities/Foo.app", "/Library/LaunchDaemons/com.x.plist",
                      "/Library/LaunchAgents/com.x.plist", "/Library/PrivilegedHelperTools/com.x.helper",
                      "/Library/Application Support/Foo", "/Library/Audio/Apple Loops/Apple"])
    func allowsKnownLocations(path: String) {
        #expect(PrivilegedRemover.isAllowed(path, home: home.path))
    }

    @Test(arguments: ["/Applications", "/Library/LaunchDaemons", "/System/Library/CoreServices/Finder.app", "/usr/bin/ls",
                      "/bin/sh", "/Library/Apple/System", "/private/var/db/foo", "relative/path", "/Applications/../usr/bin",
                      "/Applications/./Foo.app", "/Applications/Bad\nName.app", "/Library/Keychains/x"])
    func rejectsEverythingElse(path: String) {
        #expect(!PrivilegedRemover.isAllowed(path, home: home.path))
    }

    @Test func homeRules() {
        #expect(PrivilegedRemover.isAllowed(home.path + "/Library/Caches/com.x", home: home.path))
        #expect(!PrivilegedRemover.isAllowed(home.path, home: home.path))
        #expect(!PrivilegedRemover.isAllowed(home.path + "/Library", home: home.path))
        #expect(!PrivilegedRemover.isAllowed(home.path + "/Library/Caches", home: home.path))
        #expect(!PrivilegedRemover.isAllowed(home.path + "/Documents", home: home.path))
    }

    @Test func symlinksCantEscape() throws {
        try FileManager.default.createSymbolicLink(atPath: home.path + "/link", withDestinationPath: "/usr/bin")
        #expect(!PrivilegedRemover.isAllowed(home.path + "/link/ls", home: home.path))
    }

    @Test func quotesAwkwardPaths() {
        #expect(PrivilegedRemover.quote("/Applications/Bob's \"App\" $HOME `x`.app") == #"'/Applications/Bob'\''s "App" $HOME `x`.app'"#)
    }

    @Test func scriptTrashesIntoTheUsersTrashAndReportsEachItem() {
        let script = PrivilegedRemover.script(for: [
            ElevatedOperation(url: URL(fileURLWithPath: "/Library/LaunchDaemons/com.x.plist"), trash: true),
            ElevatedOperation(url: URL(fileURLWithPath: "/Applications/My App.app"), trash: false),
        ], owner: "me", trashDirectory: "/Users/me/.Trash", stamp: "11.03.12")
        #expect(script == """
        cd /
        /bin/launchctl bootout system '/Library/LaunchDaemons/com.x.plist' 2>/dev/null
        if /bin/mv '/Library/LaunchDaemons/com.x.plist' '/Users/me/.Trash/com.x 11.03.12-0.plist' && /usr/sbin/chown -R 'me' '/Users/me/.Trash/com.x 11.03.12-0.plist'; then echo OK 0; else echo FAIL 0; fi
        if /bin/rm -rf '/Applications/My App.app'; then echo OK 1; else echo FAIL 1; fi
        """)
    }

    @Test func appleScriptEscapesQuotesBackslashesAndNewlines() {
        #expect(PrivilegedRemover.appleScript(for: "echo \"a\\b\"\nnext")
            == #"do shell script "echo \"a\\b\"\nnext" with administrator privileges without altering line endings"#)
    }

    @Test func parsesPerItemResults() {
        #expect(PrivilegedRemover.parse("OK 0\nFAIL 1\rOK 2\n", count: 4) == [true, false, true, false])
    }

    @Test func elevationCandidatesAreFailedExistingAllowedItems() {
        let stuck = home.directory("Library/Caches/com.x")
        let gone = home.url.appendingPathComponent("Library/Caches/com.gone")
        let operations = [
            DeletionOperation(label: "a", kind: .trash(stuck), estimatedBytes: 1),
            DeletionOperation(label: "b", kind: .remove(gone), estimatedBytes: 1),
            DeletionOperation(label: "c", kind: .remove(URL(fileURLWithPath: "/usr/bin/true")), estimatedBytes: 1),
            DeletionOperation(label: "d", kind: .unload(target: "gui/501/x"), estimatedBytes: 0),
            DeletionOperation(label: "e", kind: .trash(stuck), estimatedBytes: 1),
        ]
        let outcomes: [DeletionOutcome] = [.failed("denied"), .failed("denied"), .failed("denied"), .failed("x"), .removed]
        let candidates = PrivilegedRemover.elevationCandidates(operations, outcomes: outcomes, home: home.path)
        #expect(candidates.map(\.index) == [0])
        #expect(candidates.first?.operation == ElevatedOperation(url: stuck, trash: true))
    }
}
