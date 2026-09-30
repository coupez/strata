import Foundation
import yara

struct YaraMatch: Hashable, Sendable {
    let rule: String
    let description: String?

    var displayName: String { description ?? rule }
}

enum YaraError: Error, Equatable {
    case compile([String])
    case initialization(Int32)
}

/// Compiles YARA rules once; `scan` may then be called from several threads at once.
final class YaraEngine: @unchecked Sendable {
    private static let initialized: Int32 = yr_initialize()
    private let rules: UnsafeMutablePointer<YR_RULES>

    let ruleCount: Int

    init(ruleFiles: [URL]) throws {
        guard Self.initialized == ERROR_SUCCESS else { throw YaraError.initialization(Self.initialized) }
        var compiler: UnsafeMutablePointer<YR_COMPILER>?
        guard yr_compiler_create(&compiler) == ERROR_SUCCESS, let compiler else { throw YaraError.initialization(-1) }
        defer { yr_compiler_destroy(compiler) }

        let messages = CompilerMessages()
        yr_compiler_set_callback(compiler, { level, file, line, _, message, context in
            guard level == YARA_ERROR_LEVEL_ERROR, let context, let message else { return }
            let messages = Unmanaged<CompilerMessages>.fromOpaque(context).takeUnretainedValue()
            let name = file.map { URL(fileURLWithPath: String(cString: $0)).lastPathComponent } ?? "rules"
            messages.errors.append("\(name):\(line): \(String(cString: message))")
        }, Unmanaged.passUnretained(messages).toOpaque())

        for (index, url) in ruleFiles.enumerated() {
            guard let handle = fopen(url.path, "r") else { throw YaraError.compile(["Can't read \(url.lastPathComponent)"]) }
            let failures = yr_compiler_add_file(compiler, handle, "ns\(index)", url.path)
            fclose(handle)
            // A compiler that reported errors can't be used again, so stop at the first bad file.
            if failures > 0 { throw YaraError.compile(messages.errors) }
        }

        var compiled: UnsafeMutablePointer<YR_RULES>?
        guard yr_compiler_get_rules(compiler, &compiled) == ERROR_SUCCESS, let compiled else {
            throw YaraError.compile(messages.errors)
        }
        rules = compiled
        ruleCount = Int(compiled.pointee.num_rules)
    }

    convenience init(source: String) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("strata-\(UUID().uuidString).yar")
        try source.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }
        try self.init(ruleFiles: [url])
    }

    deinit { yr_rules_destroy(rules) }

    /// Public rules matching the file, or nil if it couldn't be read or timed out.
    func scan(file: URL, timeout: Int32 = 10) -> [YaraMatch]? {
        let collector = MatchCollector()
        let status = yr_rules_scan_file(rules, file.path, Int32(SCAN_FLAGS_FAST_MODE), { _, message, data, context in
            guard message == CALLBACK_MSG_RULE_MATCHING, let data, let context else { return CALLBACK_CONTINUE }
            let rule = data.assumingMemoryBound(to: YR_RULE.self)
            let collector = Unmanaged<MatchCollector>.fromOpaque(context).takeUnretainedValue()
            collector.matches.append(YaraMatch(rule: String(cString: rule.pointee.identifier), description: YaraEngine.description(of: rule)))
            return CALLBACK_CONTINUE
        }, Unmanaged.passUnretained(collector).toOpaque(), timeout)
        return status == ERROR_SUCCESS ? collector.matches : nil
    }

    private static func description(of rule: UnsafeMutablePointer<YR_RULE>) -> String? {
        guard var meta = rule.pointee.metas else { return nil }
        while true {
            if meta.pointee.type == META_TYPE_STRING, let key = meta.pointee.identifier, String(cString: key) == "description",
               let value = meta.pointee.string {
                return String(cString: value)
            }
            if meta.pointee.flags & Int32(META_FLAGS_LAST_IN_RULE) != 0 { return nil }
            meta += 1
        }
    }
}

private final class CompilerMessages { var errors: [String] = [] }
private final class MatchCollector { var matches: [YaraMatch] = [] }
