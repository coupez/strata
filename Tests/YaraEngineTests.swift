import Foundation
import Testing
@testable import Strata

struct YaraEngineTests {
    let dir = TempDir()
    static let xprotect = URL(fileURLWithPath: "/var/protected/xprotect/XProtect.bundle/Contents/Resources")

    func engine() throws -> YaraEngine {
        try YaraEngine(source: """
        rule Evil { meta: description = "TEST.EVIL.A" strings: $a = "EVIL_MARKER" condition: $a }
        private rule Hidden { condition: true }
        """)
    }

    @Test func matchesAFixtureAndIgnoresPrivateRules() throws {
        let engine = try engine()
        #expect(engine.ruleCount == 2)
        let bad = dir.file("bad.bin", "xxEVIL_MARKERxx")
        let good = dir.file("good.bin", "hello")
        #expect(engine.scan(file: bad) == [YaraMatch(rule: "Evil", description: "TEST.EVIL.A")])
        #expect(engine.scan(file: good) == [])
        #expect(engine.scan(file: dir.url.appendingPathComponent("missing.bin")) == nil)
    }

    @Test func compileErrorsSurface() {
        #expect(throws: YaraError.self) { try YaraEngine(source: "rule broken { condition: nope }") }
    }

    @Test func concurrentScansShareRules() throws {
        let engine = try engine()
        let bad = dir.file("bad.bin", "EVIL_MARKER")
        let results = ResultBox()
        DispatchQueue.concurrentPerform(iterations: 16) { _ in results.add(engine.scan(file: bad)?.count ?? -1) }
        #expect(results.values == Array(repeating: 1, count: 16))
    }

    @Test(.enabled(if: FileManager.default.isReadableFile(atPath: xprotect.appendingPathComponent("XProtect.yara").path)))
    func compilesApplesLiveRules() throws {
        let engine = try YaraEngine(ruleFiles: [Self.xprotect.appendingPathComponent("XProtect.yara"),
                                                Self.xprotect.appendingPathComponent("XPScripts.yr")])
        #expect(engine.ruleCount > 400)
        #expect(engine.scan(file: URL(fileURLWithPath: "/bin/ls")) == [])
    }
}

private final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [Int] = []
    func add(_ value: Int) { lock.withLock { stored.append(value) } }
    var values: [Int] { lock.withLock { stored } }
}
