import Foundation
import Testing
@testable import Strata

struct CodeSignatureTests {
    let dir = TempDir()

    @Test func appleBinary() {
        let signature = CodeSignature.check("/bin/ls")
        #expect(signature.kind == .apple)
        #expect(signature.isTrusted)
    }

    @Test(.enabled(if: FileManager.default.fileExists(atPath: "/Applications/Keynote.app")))
    func developerIDOrAppStoreAppIsIdentified() {
        let signature = CodeSignature.check("/Applications/Keynote.app")
        #expect(signature.kind == .identified)
        #expect(signature.teamID == "74J34U3R6X")
        #expect(signature.isTrusted)
    }

    @Test func unsignedAndAdhocCopies() throws {
        let unsigned = dir.url.appendingPathComponent("ls-unsigned")
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: unsigned.path)
        try shell("/usr/bin/codesign", "--remove-signature", unsigned.path)
        #expect(CodeSignature.check(unsigned.path).kind == .unsigned)

        let adhoc = dir.url.appendingPathComponent("ls-adhoc")
        try FileManager.default.copyItem(at: unsigned, to: adhoc)
        try shell("/usr/bin/codesign", "-s", "-", adhoc.path)
        let signature = CodeSignature.check(adhoc.path)
        #expect(signature.kind == .adhoc)
        #expect(!signature.isTrusted)
    }

    @Test func scriptsAndMissingFilesAreUnsigned() {
        let script = dir.file("run.sh", "#!/bin/sh\necho hi\n")
        #expect(CodeSignature.check(script.path).kind == .unsigned)
        #expect(CodeSignature.check(dir.path + "/missing").kind == .unsigned)
    }

    @Test func summaries() {
        #expect(Signature(kind: .identified, teamID: "ABC").summary == "Identified developer (ABC)")
        #expect(Signature(kind: .unidentified, teamID: nil).summary == "Unidentified developer")
        #expect(Signature(kind: .identified, teamID: "ABC").isTrusted)
        #expect(!Signature(kind: .invalid, teamID: "ABC").isTrusted)
    }
}
