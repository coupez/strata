import Foundation
import Testing
@testable import Strata

struct XProtectRulesTests {
    let dir = TempDir()

    func bundle(_ name: String, version: String, withRules: Bool = true, withScripts: Bool = false) -> URL {
        dir.plist(name + "/Contents/Info.plist", ["CFBundleShortVersionString": version])
        if withRules { dir.file(name + "/Contents/Resources/XProtect.yara", "rule a { condition: false }") }
        if withScripts { dir.file(name + "/Contents/Resources/XPScripts.yr", "rule b { condition: false }") }
        dir.plist(name + "/Contents/Resources/XProtect.meta.plist", [
            "ExtensionBlacklist": ["Extensions": [["CFBundleIdentifier": "com.bad.ext", "Developer Identifier": "X"], ["CFBundleIdentifier": "com.nodev.ext"]]],
        ])
        return dir.url.appendingPathComponent(name)
    }

    @Test func picksTheNewestReadableBundle() throws {
        let old = bundle("Old.bundle", version: "5362")
        let new = bundle("New.bundle", version: "5363", withScripts: true)
        let broken = bundle("Broken.bundle", version: "9999", withRules: false)
        let info = try #require(XProtectRules.locate([old, broken, new]))
        #expect(info.version == 5363)
        #expect(info.bundle == new)
        #expect(info.ruleFiles.map(\.lastPathComponent) == ["XProtect.yara", "XPScripts.yr"])
        #expect(info.blockedExtensions == ["com.bad.ext": ["X"], "com.nodev.ext": []])
        #expect(info.updated != nil)
    }

    @Test func nonFiniteOrHugeVersionsAreIgnored() throws {
        let good = bundle("Good.bundle", version: "5363")
        let huge = bundle("Huge.bundle", version: "1e30")
        let inf = bundle("Inf.bundle", version: "inf")
        let nan = bundle("Nan.bundle", version: "nan")
        let info = try #require(XProtectRules.locate([huge, inf, nan, good]))
        #expect(info.bundle == good)
        #expect(XProtectRules.read(huge) == nil)
    }

    @Test func equalVersionsKeepTheEarlierCandidate() throws {
        let first = bundle("First.bundle", version: "5363")
        let second = bundle("Second.bundle", version: "5363")
        #expect(try #require(XProtectRules.locate([first, second])).bundle == first)
    }

    @Test func nothingReadableMeansNil() {
        #expect(XProtectRules.locate([dir.url.appendingPathComponent("none")]) == nil)
    }
}
