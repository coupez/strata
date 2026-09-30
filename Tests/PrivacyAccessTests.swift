import Foundation
import SQLite3
import Testing
@testable import Strata

struct PrivacyAccessTests {
    let dir = TempDir()

    /// Hits carry the path where the file really is, which spells out /private.
    private func real(_ path: String) -> String { PrivilegedRemover.realpathOf(path)! }

    func database(_ rows: [(service: String, client: String, type: Int, auth: Int)]) -> URL {
        let url = dir.url.appendingPathComponent("TCC.db")
        var db: OpaquePointer?
        sqlite3_open(url.path, &db)
        sqlite3_exec(db, "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER)", nil, nil, nil)
        for row in rows {
            sqlite3_exec(db, "INSERT INTO access VALUES ('\(row.service)', '\(row.client)', \(row.type), \(row.auth))", nil, nil, nil)
        }
        sqlite3_close(db)
        return url
    }

    @Test func readsAllowedGrantsForWatchedServices() throws {
        let db = database([
            ("kTCCServiceScreenCapture", "com.example.rec", 0, 2),
            ("kTCCServiceCamera", "/usr/local/bin/cam", 1, 2),
            ("kTCCServiceScreenCapture", "com.example.denied", 0, 0),
            ("kTCCServiceAddressBook", "com.example.contacts", 0, 2),
        ])
        let grants = try #require(PrivacyAccess.load(from: [db]))
        #expect(grants == [PrivacyGrant(client: "/usr/local/bin/cam", isPath: true, service: .camera),
                           PrivacyGrant(client: "com.example.rec", isPath: false, service: .screen)])
    }

    @Test func unreadableDatabasesMeanNil() {
        #expect(PrivacyAccess.load(from: [dir.url.appendingPathComponent("missing.db")]) == nil)
    }

    @Test func untrustedWatchersAreSuspicious() {
        let tool = dir.file("bin/keylogger", "#!/bin/sh\n")
        let camera = dir.file("bin/cam", "#!/bin/sh\n")
        let trustedApp = dir.app("Trusted.app", id: "com.example.trusted")
        let grants = [
            PrivacyGrant(client: tool.path, isPath: true, service: .keystrokes),
            PrivacyGrant(client: tool.path, isPath: true, service: .screen),
            PrivacyGrant(client: "com.apple.Terminal", isPath: false, service: .accessibility),
            PrivacyGrant(client: "com.example.trusted", isPath: false, service: .screen),
            PrivacyGrant(client: "com.example.gone", isPath: false, service: .screen),
            PrivacyGrant(client: camera.path, isPath: true, service: .camera),
        ]
        let hits = PrivacyAccess.hits(grants, resolve: { $0 == "com.example.trusted" ? trustedApp : nil }, signature: { path in
            path == trustedApp.path ? Signature(kind: .identified, teamID: "T") : Signature(kind: .unsigned, teamID: nil)
        })
        #expect(hits.map(\.primary) == [real(tool.path)])
        #expect(hits.first?.verdict == .suspicious)
        #expect(hits.first?.reason == "Not signed and allowed to use Input Monitoring, Screen Recording")
    }

    private static let unsigned = Signature(kind: .unsigned, teamID: nil)

    @Test func aProgramInsideAnAppIsRemovedAsTheWholeApp() {
        let app = dir.app("Foo.app", id: "com.example.foo", executable: "Foo")
        let inner = app.appendingPathComponent("Contents/MacOS/Foo")
        let hits = PrivacyAccess.hits([PrivacyGrant(client: inner.path, isPath: true, service: .screen)],
                                      resolve: { _ in nil }, signature: { _ in Self.unsigned })
        #expect(hits.map(\.paths) == [[real(app.path)]])
        #expect(hits.first?.title == "Foo.app")
    }

    @Test func anAppResolvedFromItsBundleIDIsRemovedWhole() {
        let app = dir.app("Bar.app", id: "com.example.bar")
        let hits = PrivacyAccess.hits([PrivacyGrant(client: "com.example.bar", isPath: false, service: .keystrokes)],
                                      resolve: { _ in app }, signature: { _ in Self.unsigned })
        #expect(hits.map(\.paths) == [[real(app.path)]])
    }

    @Test func unremovableClientsGetNoHit() {
        let folder = dir.directory("bin/tools")
        let file = dir.file("bin/keylogger", "#!/bin/sh\n")
        let grants = [
            PrivacyGrant(client: folder.path, isPath: true, service: .screen),
            PrivacyGrant(client: dir.path + "/bin/../bin/keylogger", isPath: true, service: .screen),
            PrivacyGrant(client: "/usr/bin/true", isPath: true, service: .screen),
        ]
        #expect(FileManager.default.fileExists(atPath: file.path))
        #expect(PrivacyAccess.hits(grants, resolve: { _ in nil }, signature: { _ in Self.unsigned }).isEmpty)
    }

    @Test func appleIsJudgedBySignatureNotByBundleIDPrefix() {
        let fake = dir.app("Fake.app", id: "com.apple.fake")
        let genuine = dir.app("Real.app", id: "com.apple.real")
        let grants = [PrivacyGrant(client: "com.apple.fake", isPath: false, service: .screen),
                      PrivacyGrant(client: "com.apple.real", isPath: false, service: .screen)]
        let hits = PrivacyAccess.hits(grants, resolve: { $0 == "com.apple.fake" ? fake : genuine }, signature: { path in
            path == genuine.path ? Signature(kind: .apple, teamID: nil) : Self.unsigned
        })
        #expect(hits.map(\.primary) == [real(fake.path)])
    }
}
