import Foundation
import SQLite3
import Testing
@testable import Strata

struct PrivacyAccessTests {
    let dir = TempDir()

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
        #expect(hits.map(\.primary) == [tool.path])
        #expect(hits.first?.verdict == .suspicious)
        #expect(hits.first?.reason == "Not signed and allowed to use Input Monitoring, Screen Recording")
    }
}
