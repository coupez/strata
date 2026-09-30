import Foundation
import Security

struct Signature: Hashable, Sendable {
    enum Kind: Hashable, Sendable { case apple, identified, adhoc, unidentified, unsigned, invalid }

    let kind: Kind
    let teamID: String?

    /// Signed by Apple, or by a developer Apple identified (Developer ID or App Store).
    var isTrusted: Bool { kind == .apple || kind == .identified }

    var summary: String {
        switch kind {
        case .apple: "Signed by Apple"
        case .identified: teamID.map { "Identified developer (\($0))" } ?? "Identified developer"
        case .adhoc: "No developer signature"
        case .unidentified: "Unidentified developer"
        case .unsigned: "Not signed"
        case .invalid: "Broken signature"
        }
    }
}

/// Offline code-signature checks. Resources aren't hashed, so even huge apps take milliseconds.
enum CodeSignature {
    private static let apple = requirement("anchor apple")
    private static let identified = requirement("anchor apple generic")
    private static let cache = SignatureCache()

    static func check(_ path: String) -> Signature {
        let modified = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        if let cached = cache.value(for: path, modified: modified) { return cached }
        let signature = evaluate(path)
        cache.store(signature, for: path, modified: modified)
        return signature
    }

    private static func evaluate(_ path: String) -> Signature {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return Signature(kind: .unsigned, teamID: nil)
        }
        let flags = SecCSFlags(rawValue: kSecCSDoNotValidateResources)
        let status = SecStaticCodeCheckValidity(code, flags, nil)
        if status == errSecCSUnsigned { return Signature(kind: .unsigned, teamID: nil) }

        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let details = info as? [String: Any] ?? [:]
        let team = details[kSecCodeInfoTeamIdentifier as String] as? String
        let codeFlags = (details[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0

        guard status == errSecSuccess else { return Signature(kind: .invalid, teamID: team) }
        if codeFlags & SecCodeSignatureFlags.adhoc.rawValue != 0 { return Signature(kind: .adhoc, teamID: nil) }
        if let apple, SecStaticCodeCheckValidity(code, flags, apple) == errSecSuccess { return Signature(kind: .apple, teamID: team) }
        if let identified, SecStaticCodeCheckValidity(code, flags, identified) == errSecSuccess {
            return Signature(kind: .identified, teamID: team)
        }
        return Signature(kind: .unidentified, teamID: team)
    }

    private static func requirement(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        return SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess ? requirement : nil
    }
}

private final class SignatureCache: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String: (modified: Date?, signature: Signature)] = [:]

    func value(for path: String, modified: Date?) -> Signature? {
        lock.withLock {
            guard let entry = entries[path], entry.modified == modified else { return nil }
            return entry.signature
        }
    }

    func store(_ signature: Signature, for path: String, modified: Date?) {
        lock.withLock { entries[path] = (modified, signature) }
    }
}
