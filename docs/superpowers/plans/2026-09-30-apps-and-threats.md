# Apps & Threats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an "Apps & Threats" tab to Strata that finds malware, adware, spyware signals, bloatware, unused apps and leftovers of uninstalled apps, and removes them through the existing countdown-and-delete flow (with one admin prompt for root-owned items).

**Architecture:** Pure, parameterised scanners (`AppInventory`, `LaunchItems`, `SupportFiles`, `CodeSignature`, `XProtectRules`, `PrivacyAccess`, `ThreatScanner`) feed a pure `Classifier` that turns everything into `Finding`s; a `@MainActor @Observable AppsModel` orchestrates the scan and builds `DeletionJob`s; `DeletionController` gains an elevated retry via `PrivilegedRemover`. Threat detection runs Apple's on-disk XProtect YARA rules through a vendored libyara 4.5.8 static library.

**Tech Stack:** Swift 5 / SwiftUI (macOS 26, Liquid Glass), XcodeGen, Security.framework (`SecStaticCode`), CoreServices (`MDItem`), SQLite3, libyara 4.5.8 (C, BSD-3), Swift Testing.

**Spec:** `docs/superpowers/specs/2026-09-30-apps-and-threats-design.md` (read the "Refinements from verification" section — it supersedes earlier sections where they differ).

## Global Constraints

- Deployment target macOS 26.0; `SWIFT_VERSION: "5.0"`; `SWIFT_STRICT_CONCURRENCY: minimal` (match `project.yml`).
- The only new third-party code is **libyara 4.5.8** (tarball SHA-256 `c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa`), vendored under `Vendor/yara/`, built with `HASH_MODULE` on CommonCrypto, no OpenSSL.
- XProtect rules are read from disk at scan time (`/var/protected/xprotect/XProtect.bundle` or `/Library/Apple/System/Library/CoreServices/XProtect.bundle`, newest version wins) and are **never** copied into the repo or app.
- Nothing is removed without `DeletionController`'s 5-second countdown; the admin prompt appears at most **once per removal batch**.
- Elevated operations only touch paths accepted by `PrivilegedRemover.isAllowed`.
- Pre-selected by default: only `Malicious` and `Adware` threats, and leftover findings made solely of launch items whose program is gone. Everything else starts unticked. Running apps can never be selected.
- Leftovers are matched by **bundle ID only** — never by display name.
- Copy: header footnote reads "Uses Apple's XProtect rules v<version>, updated <day month>. No scanner catches everything."; never claim a Mac is "clean" or "safe".
- Code style: enums as namespaces, `@MainActor @Observable final class` for models, sparse comments explaining *why*, `Int64.bytes` for sizes, glass UI patterns copied from `CleanupView`.
- Run tests with `scripts/test.sh [SuiteName]` (created in Task 1). Build the app with `scripts/build.sh`.

## Review Focus

1. **Two copies of one app** (same bundle ID in `/Applications` and `~/Applications`) — both are listed as separate findings, no crash, no shared parts. Pinned in Task 5 (`duplicateBundleIDsStaySeparate`).
2. **Awkward paths in the admin script** (spaces, `'`, `"`, `$`, backticks) — quoted so the shell sees exactly one literal path; newlines rejected. Pinned in Task 6 (`quotesAwkwardPaths`, `rejectsEverythingElse`).
3. **A running app ticked for removal** — the checkbox is disabled, and even if selected it is left out of the job. Pinned in Task 7 (`removalJobSkipsRunningAppsAndUnloadsUserAgents`, `selectionKeepsUserChoices`).
4. **Vendor still present** (`com.google.Keystone` while Chrome is installed; team-prefixed IDs) — not reported as a leftover. Pinned in Task 4 (`skipsWhenVendorStillInstalled`, `teamPrefixedEntriesMatchInstalledApps`).
5. **User choices vs. re-classification** (changing "Unused after" or XProtect results arriving mid-scan) — explicit checkbox choices survive; defaults only apply to untouched findings. Pinned in Task 7 (`selectionKeepsUserChoices`); stale scans are dropped by the `scanID` guard in `AppsModel`.

---

# Milestone 1 — Apps

### Task 1: Test target and launch-item parsing

**Files:**
- Modify: `project.yml`
- Create: `scripts/test.sh`
- Create: `Tests/Support/TempDir.swift`
- Create: `Sources/Model/Apps/LaunchItems.swift`
- Test: `Tests/LaunchItemsTests.swift`

**Interfaces:**
- Consumes: `DirectorySizer.exists(_:)` (`Sources/Model/Scanner.swift`), `Shell.locate(_:)` (`Sources/Model/Deletion.swift`).
- Produces:
  - `enum LaunchDomain: String, Hashable, Sendable { case userAgent, systemAgent, systemDaemon; var title: String }`
  - `struct LaunchItem: Hashable, Sendable { plist: URL; label: String; domain: LaunchDomain; program: String?; arguments: [String]; associatedBundleID: String?; runsAtLoad: Bool; isOrphaned: Bool }` (memberwise init in that order)
  - `enum LaunchItems { static func standardDirectories(home: String = NSHomeDirectory()) -> [(URL, LaunchDomain)]; static func load(from: [(URL, LaunchDomain)], resolveBundle: (String) -> URL?) -> [LaunchItem] }`
  - Test helpers: `final class TempDir { url; path; file(_:_:) -> URL; directory(_:) -> URL; plist(_:_:) -> URL; app(_:id:executable:) -> URL }`, `func shell(_ tool: String, _ arguments: String...) throws`

- [ ] **Step 1: Add the test target and scheme to `project.yml`**

Append under `targets:` (same indentation as `Strata:`) and add a top-level `schemes:` block at the end of the file:

```yaml
  StrataTests:
    type: bundle.unit-test
    platform: macOS
    sources:
      - Tests
    dependencies:
      - target: Strata
    settings:
      base:
        GENERATE_INFOPLIST_FILE: YES
        PRODUCT_BUNDLE_IDENTIFIER: com.lucascoupez.strata.tests
        CODE_SIGN_IDENTITY: "-"
        CODE_SIGN_STYLE: Manual
        TEST_HOST: "$(BUILT_PRODUCTS_DIR)/Strata.app/Contents/MacOS/Strata"
        BUNDLE_LOADER: "$(TEST_HOST)"
        SWIFT_STRICT_CONCURRENCY: minimal
schemes:
  Strata:
    build:
      targets:
        Strata: all
    test:
      targets:
        - StrataTests
```

- [ ] **Step 2: Create `scripts/test.sh`**

```sh
#!/bin/zsh
# Generates the project and runs the unit tests. Pass a suite name to run only that suite:
#   scripts/test.sh LaunchItemsTests
set -euo pipefail
cd "$(dirname "$0")/.."
xcodegen generate --quiet
only=()
[[ $# -gt 0 ]] && only=(-only-testing:StrataTests/$1)
xcodebuild -project Strata.xcodeproj -scheme Strata -derivedDataPath build/DerivedData \
  -destination 'platform=macOS,arch=arm64' test "${only[@]}" 2>&1 \
  | grep -E "✔|✘|error:|Expectation failed|TEST (SUCCEEDED|FAILED)|Test run"
```

Run: `chmod +x scripts/test.sh`

- [ ] **Step 3: Create the test helpers `Tests/Support/TempDir.swift`**

```swift
import Foundation

/// A scratch directory that disappears with the test. Paths are symlink-resolved so they
/// compare equal to what the code under test computes.
final class TempDir {
    let url: URL
    var path: String { url.path }

    init() {
        let raw = FileManager.default.temporaryDirectory.appendingPathComponent("StrataTests-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        url = raw.resolvingSymlinksInPath()
    }

    deinit { try? FileManager.default.removeItem(at: url) }

    @discardableResult
    func file(_ relative: String, _ contents: String = "x") -> URL {
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! Data(contents.utf8).write(to: target)
        return target
    }

    @discardableResult
    func directory(_ relative: String) -> URL {
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        return target
    }

    @discardableResult
    func plist(_ relative: String, _ object: [String: Any]) -> URL {
        let data = try! PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! data.write(to: target)
        return target
    }

    /// A minimal .app bundle: Info.plist plus a shell-script executable.
    @discardableResult
    func app(_ relative: String, id: String, executable: String = "main") -> URL {
        plist(relative + "/Contents/Info.plist", [
            "CFBundleIdentifier": id, "CFBundleExecutable": executable, "CFBundleShortVersionString": "1.0",
        ])
        file(relative + "/Contents/MacOS/" + executable, "#!/bin/sh\n")
        return url.appendingPathComponent(relative)
    }
}

struct ShellError: Error { let status: Int32 }

func shell(_ tool: String, _ arguments: String...) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: tool)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw ShellError(status: process.terminationStatus) }
}
```

- [ ] **Step 4: Write the failing tests `Tests/LaunchItemsTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct LaunchItemsTests {
    let dir = TempDir()

    private func load(_ resolve: @escaping (String) -> URL? = { _ in nil }) -> [LaunchItem] {
        LaunchItems.load(from: [(dir.url, .userAgent)], resolveBundle: resolve)
    }

    @Test func readsProgramAndRunAtLoad() throws {
        dir.plist("a.plist", ["Label": "com.example.a", "Program": "/bin/ls", "RunAtLoad": true])
        let item = try #require(load().first)
        #expect(item.label == "com.example.a")
        #expect(item.program == "/bin/ls")
        #expect(item.runsAtLoad)
        #expect(!item.isOrphaned)
        #expect(item.domain == .userAgent)
        #expect(item.plist == dir.url.appendingPathComponent("a.plist"))
    }

    @Test func usesFirstProgramArgument() throws {
        dir.plist("b.plist", ["Label": "com.example.b", "ProgramArguments": ["/bin/sh", "/tmp/x.sh", "-v"]])
        let item = try #require(load().first)
        #expect(item.program == "/bin/sh")
        #expect(item.arguments == ["/tmp/x.sh", "-v"])
        #expect(!item.runsAtLoad)
    }

    @Test func missingProgramIsOrphaned() throws {
        dir.plist("c.plist", ["Label": "com.example.c", "Program": dir.path + "/gone/agent"])
        #expect(try #require(load().first).isOrphaned)
    }

    @Test func relativeProgramIsResolvedAndNotOrphaned() throws {
        dir.plist("d.plist", ["Label": "com.example.d", "ProgramArguments": ["sh", "-c", "echo hi"]])
        let item = try #require(load().first)
        #expect(item.program?.hasSuffix("/sh") == true)
        #expect(!item.isOrphaned)
    }

    @Test func bundleProgramResolvesThroughItsApp() throws {
        let app = dir.app("Foo.app", id: "com.example.foo")
        dir.plist("e.plist", [
            "Label": "com.example.foo.helper", "BundleProgram": "Contents/MacOS/main",
            "AssociatedBundleIdentifiers": ["com.example.foo"],
        ])
        let found = try #require(load { $0 == "com.example.foo" ? app : nil }.first)
        #expect(found.program == app.appendingPathComponent("Contents/MacOS/main").path)
        #expect(found.associatedBundleID == "com.example.foo")
        #expect(!found.isOrphaned)
        #expect(try #require(load().first).isOrphaned)
    }

    @Test func keepAliveDictionaryCountsAsRunAtLoad() throws {
        dir.plist("f.plist", ["Label": "com.example.f", "Program": "/bin/ls", "KeepAlive": ["SuccessfulExit": false]])
        #expect(try #require(load().first).runsAtLoad)
    }

    @Test func skipsBrokenPlistsAndFallsBackToFileName() {
        dir.file("broken.plist", "not a plist")
        dir.plist("com.example.nolabel.plist", ["Program": "/bin/ls"])
        dir.file("readme.txt")
        let items = load()
        #expect(items.map(\.label) == ["com.example.nolabel"])
    }
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `scripts/test.sh LaunchItemsTests`
Expected: FAIL — `error: cannot find 'LaunchItems' in scope` (and `LaunchItem`, `LaunchDomain`).

- [ ] **Step 6: Implement `Sources/Model/Apps/LaunchItems.swift`**

```swift
import Foundation

enum LaunchDomain: String, Hashable, Sendable {
    case userAgent, systemAgent, systemDaemon

    var title: String {
        switch self {
        case .userAgent: "Starts when you log in"
        case .systemAgent: "Starts when anyone logs in"
        case .systemDaemon: "Runs in the background as root"
        }
    }
}

struct LaunchItem: Hashable, Sendable {
    let plist: URL
    let label: String
    let domain: LaunchDomain
    /// Absolute path of the program launchd starts, when it could be worked out.
    let program: String?
    /// Arguments after the program itself.
    let arguments: [String]
    let associatedBundleID: String?
    let runsAtLoad: Bool
    /// Points at a program (or app) that no longer exists, so it can never run.
    let isOrphaned: Bool
}

enum LaunchItems {
    static func standardDirectories(home: String = NSHomeDirectory()) -> [(URL, LaunchDomain)] {
        [
            (URL(fileURLWithPath: home).appendingPathComponent("Library/LaunchAgents"), .userAgent),
            (URL(fileURLWithPath: "/Library/LaunchAgents"), .systemAgent),
            (URL(fileURLWithPath: "/Library/LaunchDaemons"), .systemDaemon),
        ]
    }

    /// `resolveBundle` maps a bundle ID to where that app is installed (for `BundleProgram`).
    static func load(from directories: [(URL, LaunchDomain)], resolveBundle: (String) -> URL?) -> [LaunchItem] {
        directories.flatMap { directory, domain -> [LaunchItem] in
            let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
            return names.filter { $0.hasSuffix(".plist") }.sorted().compactMap {
                parse(directory.appendingPathComponent($0), domain: domain, resolveBundle: resolveBundle)
            }
        }
    }

    static func parse(_ url: URL, domain: LaunchDomain, resolveBundle: (String) -> URL?) -> LaunchItem? {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        let label = plist["Label"] as? String ?? url.deletingPathExtension().lastPathComponent
        let programArguments = plist["ProgramArguments"] as? [String] ?? []
        let associated = (plist["AssociatedBundleIdentifiers"] as? [String])?.first
            ?? plist["AssociatedBundleIdentifiers"] as? String

        var program: String?
        var orphaned = false
        if let bundleProgram = plist["BundleProgram"] as? String {
            if let bundle = associated.flatMap(resolveBundle) {
                let path = bundle.appendingPathComponent(bundleProgram).path
                program = path
                orphaned = !DirectorySizer.exists(path)
            } else {
                orphaned = true
            }
        } else if let path = (plist["Program"] as? String) ?? programArguments.first {
            if path.hasPrefix("/") {
                program = path
                orphaned = !DirectorySizer.exists(path)
            } else {
                // launchd searches PATH for bare names like "sh"; not finding one isn't proof it's gone.
                program = Shell.locate(path)
            }
        }

        let keepAlive: Bool = switch plist["KeepAlive"] {
        case let flag as Bool: flag
        case is [String: Any]: true
        default: false
        }
        return LaunchItem(plist: url, label: label, domain: domain, program: program,
                          arguments: Array(programArguments.dropFirst()), associatedBundleID: associated,
                          runsAtLoad: (plist["RunAtLoad"] as? Bool ?? false) || keepAlive, isOrphaned: orphaned)
    }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `scripts/test.sh LaunchItemsTests`
Expected: 7 tests `✔`, `** TEST SUCCEEDED **`.

- [ ] **Step 8: Commit**

```bash
git add project.yml scripts/test.sh Tests Sources/Model/Apps/LaunchItems.swift
git commit -m "Add unit test target and launch agent/daemon parsing"
```

---

### Task 2: Code signature checks

**Files:**
- Create: `Sources/Model/Apps/CodeSignature.swift`
- Test: `Tests/CodeSignatureTests.swift`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `struct Signature: Hashable, Sendable { enum Kind { case apple, identified, adhoc, unidentified, unsigned, invalid }; let kind: Kind; let teamID: String?; var isTrusted: Bool; var summary: String }`
  - `enum CodeSignature { static func check(_ path: String) -> Signature }` — cached by path + modification date, thread-safe, offline.

- [ ] **Step 1: Write the failing tests `Tests/CodeSignatureTests.swift`**

```swift
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh CodeSignatureTests`
Expected: FAIL — `cannot find 'CodeSignature' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Apps/CodeSignature.swift`**

```swift
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh CodeSignatureTests`
Expected: 4 tests `✔`.

- [ ] **Step 5: Commit**

```bash
git add Sources/Model/Apps/CodeSignature.swift Tests/CodeSignatureTests.swift
git commit -m "Add offline code signature checks"
```

---

### Task 3: Installed-app inventory

**Files:**
- Create: `Sources/Model/Apps/AppInventory.swift`
- Test: `Tests/AppInventoryTests.swift`

**Interfaces:**
- Consumes: `DirectorySizer.allocatedSize(atPath:)`.
- Produces:
  - `struct InstalledApp: Hashable, Sendable { url: URL; bundleID: String; name: String; version: String?; nestedBundleIDs: [String]; size: Int64; lastUsed: Date?; dateAdded: Date?; var path: String }` (memberwise init in that order)
  - `enum AppInventory { static func standardLocations(home:) -> [URL]; static func bundles(in: [URL]) -> [URL]; static func read(_ url: URL, usage: (URL) -> (lastUsed: Date?, added: Date?)) -> InstalledApp?; static func load(locations: [URL], usage: ...) -> [InstalledApp]; static func nestedBundleIDs(in: URL) -> [String] }`
  - `enum Spotlight { static func usage(of url: URL) -> (lastUsed: Date?, added: Date?) }`

- [ ] **Step 1: Write the failing tests `Tests/AppInventoryTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct AppInventoryTests {
    let dir = TempDir()
    let noUsage: (URL) -> (lastUsed: Date?, added: Date?) = { _ in (nil, nil) }

    @Test func findsAppsInLocationsAndOneLevelOfSubfolders() {
        dir.app("Apps/One.app", id: "com.example.one")
        dir.app("Apps/Utilities/Two.app", id: "com.example.two")
        dir.app("Apps/Deep/Nested/Three.app", id: "com.example.three")
        dir.file("Apps/readme.txt")
        let names = AppInventory.bundles(in: [dir.url.appendingPathComponent("Apps")]).map(\.lastPathComponent)
        #expect(names == ["One.app", "Two.app"])
    }

    @Test func readsBundleDetailsAndNestedIDs() throws {
        let app = dir.app("One.app", id: "com.example.one")
        dir.app("One.app/Contents/Frameworks/One Helper.app", id: "com.example.one.helper")
        dir.app("One.app/Contents/Library/LoginItems/Launcher.app", id: "com.example.one.launcher")
        dir.plist("One.app/Contents/PlugIns/Share.appex/Contents/Info.plist", ["CFBundleIdentifier": "com.example.one.share"])
        dir.plist("One.app/Contents/Resources/Ignored.app/Contents/Info.plist", ["CFBundleIdentifier": "com.example.ignored"])
        let used = Date(timeIntervalSince1970: 1_000)

        let installed = try #require(AppInventory.read(app, usage: { _ in (used, nil) }))
        #expect(installed.bundleID == "com.example.one")
        #expect(installed.name == "One")
        #expect(installed.version == "1.0")
        #expect(installed.lastUsed == used)
        #expect(installed.dateAdded == nil)
        #expect(Set(installed.nestedBundleIDs) == ["com.example.one.helper", "com.example.one.launcher", "com.example.one.share"])
        #expect(installed.size > 0)
        #expect(installed.path == app.path)
    }

    @Test func skipsBundlesWithoutIdentifier() {
        dir.file("Broken.app/Contents/MacOS/x")
        #expect(AppInventory.read(dir.url.appendingPathComponent("Broken.app"), usage: noUsage) == nil)
    }

    @Test func loadReadsEveryBundle() {
        dir.app("A.app", id: "com.example.a")
        dir.app("B.app", id: "com.example.b")
        dir.file("C.app/Contents/MacOS/x")
        let apps = AppInventory.load(locations: [dir.url], usage: noUsage)
        #expect(apps.map(\.bundleID).sorted() == ["com.example.a", "com.example.b"])
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh AppInventoryTests`
Expected: FAIL — `cannot find 'AppInventory' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Apps/AppInventory.swift`**

```swift
import CoreServices
import Foundation

struct InstalledApp: Hashable, Sendable {
    let url: URL
    let bundleID: String
    let name: String
    let version: String?
    /// IDs of helpers, extensions and login items inside the bundle.
    let nestedBundleIDs: [String]
    let size: Int64
    let lastUsed: Date?
    let dateAdded: Date?

    var path: String { url.path }
}

enum AppInventory {
    static func standardLocations(home: String = NSHomeDirectory()) -> [URL] {
        [URL(fileURLWithPath: "/Applications"), URL(fileURLWithPath: home).appendingPathComponent("Applications")]
    }

    /// Apps directly in each location, plus one level of plain folders ("Utilities", vendor folders).
    static func bundles(in locations: [URL]) -> [URL] {
        let fm = FileManager.default
        var result: [URL] = []
        for location in locations {
            let names = (try? fm.contentsOfDirectory(atPath: location.path)) ?? []
            for name in names.sorted() where !name.hasPrefix(".") {
                let url = location.appendingPathComponent(name)
                if name.hasSuffix(".app") {
                    result.append(url)
                } else if (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                    let inner = (try? fm.contentsOfDirectory(atPath: url.path)) ?? []
                    result += inner.sorted().filter { $0.hasSuffix(".app") }.map { url.appendingPathComponent($0) }
                }
            }
        }
        return result
    }

    static func load(locations: [URL] = standardLocations(),
                     usage: @escaping (URL) -> (lastUsed: Date?, added: Date?) = Spotlight.usage) -> [InstalledApp] {
        let bundles = bundles(in: locations)
        var apps = [InstalledApp?](repeating: nil, count: bundles.count)
        // Sizing is IO-bound, so spread it across cores.
        apps.withUnsafeMutableBufferPointer { buffer in
            DispatchQueue.concurrentPerform(iterations: bundles.count) { buffer[$0] = read(bundles[$0], usage: usage) }
        }
        return apps.compactMap { $0 }
    }

    static func read(_ url: URL, usage: (URL) -> (lastUsed: Date?, added: Date?) = Spotlight.usage) -> InstalledApp? {
        guard let info = infoPlist(of: url), let id = info["CFBundleIdentifier"] as? String else { return nil }
        let dates = usage(url)
        return InstalledApp(url: url, bundleID: id, name: url.deletingPathExtension().lastPathComponent,
                            version: info["CFBundleShortVersionString"] as? String,
                            nestedBundleIDs: nestedBundleIDs(in: url),
                            size: DirectorySizer.allocatedSize(atPath: url.path),
                            lastUsed: dates.lastUsed, dateAdded: dates.added)
    }

    /// Bundle IDs of .app/.appex/.xpc bundles anywhere inside Contents, except under Resources.
    static func nestedBundleIDs(in app: URL) -> [String] {
        let contents = app.appendingPathComponent("Contents")
        guard let walker = FileManager.default.enumerator(at: contents, includingPropertiesForKeys: [.isDirectoryKey],
                                                          options: [.skipsHiddenFiles]) else { return [] }
        var ids: [String] = []
        for case let url as URL in walker {
            let name = url.lastPathComponent
            if name == "Resources" || name == "_CodeSignature" || walker.level > 8 {
                walker.skipDescendants()
                continue
            }
            guard ["app", "appex", "xpc"].contains(url.pathExtension),
                  let id = infoPlist(of: url)?["CFBundleIdentifier"] as? String else { continue }
            ids.append(id)
        }
        return ids
    }

    static func infoPlist(of bundle: URL) -> [String: Any]? {
        NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist")) as? [String: Any]
    }
}

enum Spotlight {
    static func usage(of url: URL) -> (lastUsed: Date?, added: Date?) {
        guard let item = MDItemCreate(nil, url.path as CFString) else { return (nil, nil) }
        return (MDItemCopyAttribute(item, kMDItemLastUsedDate) as? Date, MDItemCopyAttribute(item, kMDItemDateAdded) as? Date)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh AppInventoryTests`
Expected: 4 tests `✔`.

- [ ] **Step 5: Commit**

```bash
git add Sources/Model/Apps/AppInventory.swift Tests/AppInventoryTests.swift
git commit -m "Add installed app inventory with Spotlight usage dates"
```

---

### Task 4: Support files and leftovers

**Files:**
- Create: `Sources/Model/Apps/SupportFiles.swift`
- Create: `Sources/Model/Apps/Leftovers.swift`
- Test: `Tests/SupportFilesTests.swift`
- Test: `Tests/LeftoversTests.swift`

**Interfaces:**
- Consumes: `InstalledApp` (Task 3), `LaunchItem` (Task 1).
- Produces:
  - `struct SupportEntry: Hashable, Sendable { url: URL; bundleID: String?; var name: String }`
  - `enum SupportFiles { static let userFolders: [String]; static let systemFolders: [String]; static func standardFolders(home:) -> [URL]; static func index(_ folders: [URL]) -> [SupportEntry]; static func bundleID(fromName: String) -> String?; static func owner(of: SupportEntry, among: [InstalledApp]) -> InstalledApp? }`
  - `enum IDs { static func owns(_ owner: String, _ id: String) -> Bool; static func vendor(_ id: String) -> String; static func product(_ id: String) -> String }`
  - `struct LeftoverGroup: Hashable, Sendable { key: String; entries: [SupportEntry]; launchItems: [LaunchItem] }`
  - `enum Leftovers { static func find(entries: [SupportEntry], launchItems: [LaunchItem], installedIDs: [String], runningIDs: Set<String>, ownID: String) -> [LeftoverGroup] }`

- [ ] **Step 1: Write the failing tests `Tests/SupportFilesTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct SupportFilesTests {
    let dir = TempDir()

    @Test(arguments: zip(
        ["com.foo.Bar", "com.foo.Bar.plist", "com.foo.Bar.savedState", "com.foo.Bar.binarycookies",
         "ABCDE12345.com.foo.bar", "at.obdev.littlesnitch", "io.tailscale.ipn.macos"],
        ["com.foo.Bar", "com.foo.Bar", "com.foo.Bar", "com.foo.Bar",
         "com.foo.bar", "at.obdev.littlesnitch", "io.tailscale.ipn.macos"]))
    func parsesIDs(name: String, id: String) {
        #expect(SupportFiles.bundleID(fromName: name) == id)
    }

    @Test(arguments: ["Discord", "Google", "com.foo", "homebrew.mxcl.mysql", "foo..bar.baz", "com.foo bar.baz", "ByHost", "UBF8T346G9.Office"])
    func rejectsNonIDs(name: String) {
        #expect(SupportFiles.bundleID(fromName: name) == nil)
    }

    @Test func indexListsVisibleEntries() {
        dir.directory("Library/Caches/com.example.one")
        dir.file("Library/Caches/.hidden")
        dir.file("Library/Preferences/com.example.one.plist")
        let entries = SupportFiles.index([dir.url.appendingPathComponent("Library/Caches"),
                                          dir.url.appendingPathComponent("Library/Preferences")])
        #expect(entries.map(\.name) == ["com.example.one", "com.example.one.plist"])
        #expect(entries.map(\.bundleID) == ["com.example.one", "com.example.one"])
    }

    @Test func ownerMatchesByIDOrExactAppSupportName() {
        let app = InstalledApp(url: URL(fileURLWithPath: "/Applications/One.app"), bundleID: "com.example.one", name: "One",
                               version: nil, nestedBundleIDs: ["com.example.helperone"], size: 1, lastUsed: nil, dateAdded: nil)
        func entry(_ path: String) -> SupportEntry {
            SupportEntry(url: URL(fileURLWithPath: path), bundleID: SupportFiles.bundleID(fromName: (path as NSString).lastPathComponent))
        }
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.one"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Preferences/com.example.one.helper.plist"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.helperone"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Application Support/One"), among: [app]) == app)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/One"), among: [app]) == nil)
        #expect(SupportFiles.owner(of: entry("/u/Library/Caches/com.example.onething"), among: [app]) == nil)
    }
}
```

- [ ] **Step 2: Write the failing tests `Tests/LeftoversTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct LeftoversTests {
    func entry(_ path: String) -> SupportEntry {
        SupportEntry(url: URL(fileURLWithPath: path), bundleID: SupportFiles.bundleID(fromName: (path as NSString).lastPathComponent))
    }

    func item(_ label: String, orphaned: Bool) -> LaunchItem {
        LaunchItem(plist: URL(fileURLWithPath: "/L/\(label).plist"), label: label, domain: .userAgent, program: "/x",
                   arguments: [], associatedBundleID: nil, runsAtLoad: true, isOrphaned: orphaned)
    }

    func find(_ entries: [SupportEntry], items: [LaunchItem] = [], installed: [String] = [], running: Set<String> = []) -> [LeftoverGroup] {
        Leftovers.find(entries: entries, launchItems: items, installedIDs: installed, runningIDs: running, ownID: "com.lucascoupez.strata")
    }

    @Test func groupsEntriesOfAnUninstalledApp() {
        let groups = find([entry("/S/com.gone.app"), entry("/C/com.gone.app.cache"), entry("/P/com.gone.app.plist")])
        #expect(groups.map(\.key) == ["com.gone.app"])
        #expect(groups.first?.entries.count == 3)
    }

    @Test func skipsAppleOwnAndNonIDs() {
        #expect(find([entry("/S/com.apple.Safari"), entry("/S/com.lucascoupez.strata"), entry("/S/Discord")]).isEmpty)
    }

    @Test func skipsWhenVendorStillInstalled() {
        #expect(find([entry("/S/com.google.Keystone")], installed: ["com.google.Chrome"]).isEmpty)
        #expect(find([entry("/S/com.Google.Keystone")], installed: ["com.google.Chrome"]).isEmpty)
    }

    @Test func teamPrefixedEntriesMatchInstalledApps() {
        #expect(find([entry("/G/ABCDE12345.com.example.one")], installed: ["com.example.one"]).isEmpty)
    }

    @Test func skipsRunningAndLiveLaunchItemVendors() {
        #expect(find([entry("/S/com.cli.tool")], running: ["com.cli.tool"]).isEmpty)
        #expect(find([entry("/S/com.github.facebook.watchman")], items: [item("com.github.facebook.watchman", orphaned: false)]).isEmpty)
    }

    @Test func groupsOrphanedLaunchItemsWithTheirFiles() {
        let groups = find([entry("/S/com.gone.app")], items: [item("com.gone.app.updater", orphaned: true), item("com.apple.x", orphaned: true), item("Fing", orphaned: true)])
        #expect(groups.map(\.key) == ["Fing", "com.gone.app"])
        #expect(groups.last?.launchItems.map(\.label) == ["com.gone.app.updater"])
        #expect(groups.last?.entries.count == 1)
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `scripts/test.sh SupportFilesTests` then `scripts/test.sh LeftoversTests`
Expected: FAIL — `cannot find 'SupportFiles' in scope`, `cannot find 'Leftovers' in scope`.

- [ ] **Step 4: Implement `Sources/Model/Apps/SupportFiles.swift`**

```swift
import Foundation

struct SupportEntry: Hashable, Sendable {
    let url: URL
    /// The reverse-DNS ID this entry is named after, without extensions like .plist or .savedState.
    let bundleID: String?

    var name: String { url.lastPathComponent }
}

enum SupportFiles {
    static let userFolders = [
        "Library/Application Support", "Library/Caches", "Library/Containers", "Library/Preferences",
        "Library/Saved Application State", "Library/HTTPStorages", "Library/WebKit", "Library/Logs", "Library/Cookies",
    ]
    static let systemFolders = [
        "/Library/Application Support", "/Library/Caches", "/Library/Preferences", "/Library/PrivilegedHelperTools",
    ]

    static func standardFolders(home: String = NSHomeDirectory()) -> [URL] {
        userFolders.map { URL(fileURLWithPath: home).appendingPathComponent($0) } + systemFolders.map { URL(fileURLWithPath: $0) }
    }

    static func index(_ folders: [URL]) -> [SupportEntry] {
        folders.flatMap { folder in
            ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [])
                .filter { !$0.hasPrefix(".") }
                .sorted()
                .map { SupportEntry(url: folder.appendingPathComponent($0), bundleID: bundleID(fromName: $0)) }
        }
    }

    private static let strippedExtensions = ["plist", "savedState", "binarycookies"]
    private static let topLevelDomains: Set<String> = [
        "com", "org", "net", "io", "dev", "app", "co", "me", "info", "biz", "tv", "ai", "so", "sh", "xyz", "cc", "eu",
    ]

    /// "com.foo.Bar.plist" → "com.foo.Bar", "ABCDE12345.com.foo.bar" → "com.foo.bar", "Discord" → nil.
    static func bundleID(fromName name: String) -> String? {
        var id = name
        for suffix in strippedExtensions where id.hasSuffix("." + suffix) { id = String(id.dropLast(suffix.count + 1)) }
        var parts = id.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if let first = parts.first, first.count == 10, first.allSatisfy({ $0.isUppercase || $0.isNumber }) { parts.removeFirst() }
        guard parts.count >= 3, let tld = parts.first?.lowercased(), topLevelDomains.contains(tld) || tld.count == 2,
              parts.allSatisfy({ part in !part.isEmpty && part.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" } })
        else { return nil }
        return parts.joined(separator: ".")
    }

    /// The installed app an entry belongs to: by bundle ID (including helpers), or an
    /// Application Support folder named exactly like the app.
    static func owner(of entry: SupportEntry, among apps: [InstalledApp]) -> InstalledApp? {
        if let id = entry.bundleID {
            return apps.first { app in IDs.owns(app.bundleID, id) || app.nestedBundleIDs.contains { IDs.owns($0, id) } }
        }
        guard entry.url.deletingLastPathComponent().lastPathComponent == "Application Support" else { return nil }
        return apps.first { $0.name == entry.name }
    }
}

enum IDs {
    /// True when `id` is `owner` itself or a dotted child or parent of it ("com.foo.app" ~ "com.foo.app.helper").
    static func owns(_ owner: String, _ id: String) -> Bool {
        let owner = owner.lowercased(), id = id.lowercased()
        return owner == id || id.hasPrefix(owner + ".") || owner.hasPrefix(id + ".")
    }

    /// "com.microsoft.EdgeUpdater.update" → "com.microsoft"
    static func vendor(_ id: String) -> String { id.lowercased().split(separator: ".").prefix(2).joined(separator: ".") }

    /// "com.microsoft.EdgeUpdater.update" → "com.microsoft.EdgeUpdater"
    static func product(_ id: String) -> String { id.split(separator: ".").prefix(3).joined(separator: ".") }
}
```

- [ ] **Step 5: Implement `Sources/Model/Apps/Leftovers.swift`**

```swift
import Foundation

struct LeftoverGroup: Hashable, Sendable {
    let key: String
    var entries: [SupportEntry]
    var launchItems: [LaunchItem]
}

/// Files and launch items of apps that are gone. Deliberately conservative: anything from a
/// vendor that still has an installed app or a working launch item is left alone.
enum Leftovers {
    static func find(entries: [SupportEntry], launchItems: [LaunchItem], installedIDs: [String],
                     runningIDs: Set<String>, ownID: String) -> [LeftoverGroup] {
        let installedVendors = Set(installedIDs.map(IDs.vendor))
        let liveVendors = Set(launchItems.filter { !$0.isOrphaned }
            .flatMap { [$0.label] + ($0.associatedBundleID.map { [$0] } ?? []) }
            .map(IDs.vendor))

        var groups: [String: LeftoverGroup] = [:]
        func add(_ key: String, entry: SupportEntry? = nil, item: LaunchItem? = nil) {
            var group = groups[key] ?? LeftoverGroup(key: key, entries: [], launchItems: [])
            if let entry { group.entries.append(entry) }
            if let item { group.launchItems.append(item) }
            groups[key] = group
        }

        for entry in entries {
            guard let id = entry.bundleID, !id.lowercased().hasPrefix("com.apple."), !IDs.owns(ownID, id) else { continue }
            let vendor = IDs.vendor(id)
            guard !installedVendors.contains(vendor), !liveVendors.contains(vendor),
                  !runningIDs.contains(where: { IDs.owns($0, id) }) else { continue }
            add(IDs.product(id), entry: entry)
        }
        for item in launchItems where item.isOrphaned && !item.label.hasPrefix("com.apple.") {
            add(SupportFiles.bundleID(fromName: item.label).map(IDs.product) ?? item.label, item: item)
        }
        return groups.values.sorted { $0.key < $1.key }
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `scripts/test.sh SupportFilesTests` then `scripts/test.sh LeftoversTests`
Expected: all `✔` (parameterised cases count individually).

- [ ] **Step 7: Commit**

```bash
git add Sources/Model/Apps/SupportFiles.swift Sources/Model/Apps/Leftovers.swift Tests/SupportFilesTests.swift Tests/LeftoversTests.swift
git commit -m "Find app support files and leftovers of uninstalled apps"
```

---

### Task 5: Findings, bloatware and the classifier

**Files:**
- Create: `Sources/Model/Apps/Findings.swift`
- Create: `Sources/Model/Apps/Bloatware.swift`
- Create: `Sources/Model/Apps/Classifier.swift`
- Create: `Tests/Support/Fixtures.swift`
- Test: `Tests/ClassifierTests.swift`

**Interfaces:**
- Consumes: `Risk` (`Sources/Model/Cleanup.swift`), `InstalledApp`, `LaunchItem`, `SupportEntry`, `SupportFiles.owner`, `Leftovers.find`, `IDs`, `Signature`, `CodeSignature.check`.
- Produces:
  - `enum FindingGroup: String, CaseIterable, Identifiable, Sendable { case threat, unused, bloatware, leftover, background; title; caption; symbol; tint; order }`
  - `enum Verdict: Int, Comparable, Sendable { case suspicious, adware, malicious; label; color }`
  - `struct FindingPart: Identifiable, Hashable, Sendable { url: URL; size: Int64; kind: Kind; isLaunchItem }` with `enum Kind { case app, support, file, launchItem(label: String, domain: LaunchDomain) }`
  - `struct Finding: Identifiable, Hashable, Sendable { let id: String; var group: FindingGroup; var verdict: Verdict? = nil; let title: String; var reasons: [String]; let iconPath: String?; var parts: [FindingPart]; var risk: Risk; var lastUsed: Date? = nil; var isRunning = false; size; preselected; contains(_ path:) }`
  - `struct ThreatHit: Hashable, Sendable { paths: [String]; verdict: Verdict; reason: String; title: String; var primary: String }`
  - `struct AppScanInput: Sendable { apps; launchItems; support; running: Set<String>; ownID: String; now: Date; soundLibraries: [URL] }`
  - `enum Bloatware { garageBandID; logicID; apps: [String: String]; soundLibraryPaths; isBloatware(_:signature:); soundLibraries(existing:) -> [URL] }`
  - `enum Classifier { static func findings(_ input: AppScanInput, unusedAfter days: Int, hits: [ThreatHit] = [], signature: (String) -> Signature = CodeSignature.check, size: (URL) -> Int64 = …) -> [Finding]; static func owner(of: LaunchItem, among: [InstalledApp]) -> InstalledApp? }`
  - Test fixture: `func makeApp(_ path: String, id: String, lastUsed: Date? = nil, added: Date? = nil, nested: [String] = [], size: Int64 = 100) -> InstalledApp`

- [ ] **Step 1: Create `Tests/Support/Fixtures.swift`**

```swift
import Foundation
@testable import Strata

func makeApp(_ path: String, id: String, lastUsed: Date? = nil, added: Date? = nil, nested: [String] = [], size: Int64 = 100) -> InstalledApp {
    let url = URL(fileURLWithPath: path)
    return InstalledApp(url: url, bundleID: id, name: url.deletingPathExtension().lastPathComponent, version: nil,
                        nestedBundleIDs: nested, size: size, lastUsed: lastUsed, dateAdded: added)
}

func makeItem(_ label: String, program: String? = "/x", arguments: [String] = [], domain: LaunchDomain = .userAgent,
              associated: String? = nil, orphaned: Bool = false) -> LaunchItem {
    LaunchItem(plist: URL(fileURLWithPath: "/L/\(label).plist"), label: label, domain: domain, program: program,
               arguments: arguments, associatedBundleID: associated, runsAtLoad: true, isOrphaned: orphaned)
}
```

- [ ] **Step 2: Write the failing tests `Tests/ClassifierTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct ClassifierTests {
    let now = Date(timeIntervalSince1970: 2_000_000_000)
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let size: (URL) -> Int64 = { _ in 10 }

    func days(_ count: Double) -> Date { now.addingTimeInterval(-count * 86_400) }

    func input(apps: [InstalledApp] = [], items: [LaunchItem] = [], support: [SupportEntry] = [],
               running: Set<String> = [], sounds: [URL] = []) -> AppScanInput {
        AppScanInput(apps: apps, launchItems: items, support: support, running: running,
                     ownID: "com.lucascoupez.strata", now: now, soundLibraries: sounds)
    }

    func classify(_ input: AppScanInput, days: Int = 90, hits: [ThreatHit] = [],
                  signature: ((String) -> Signature)? = nil) -> [Finding] {
        Classifier.findings(input, unusedAfter: days, hits: hits, signature: signature ?? trusted, size: size)
    }

    @Test func unusedAppsRespectTheThreshold() {
        let apps = [
            makeApp("/Applications/A.app", id: "com.a", lastUsed: days(100)),
            makeApp("/Applications/B.app", id: "com.b", lastUsed: days(10)),
            makeApp("/Applications/C.app", id: "com.c", added: days(200)),
            makeApp("/Applications/D.app", id: "com.d"),
        ]
        #expect(Set(classify(input(apps: apps)).map(\.title)) == ["A", "C"])
        #expect(Set(classify(input(apps: apps), days: 5).map(\.title)) == ["A", "B", "C"])
        let a = classify(input(apps: apps)).first { $0.title == "A" }
        #expect(a?.group == .unused)
        #expect(a?.risk == .review)
        #expect(a?.preselected == false)
        #expect(a?.reasons.first?.hasPrefix("Last opened") == true)
    }

    @Test func runningAndOwnAppsAreNeverListed() {
        let apps = [makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400)),
                    makeApp("/Applications/Strata.app", id: "com.lucascoupez.strata", lastUsed: days(400))]
        #expect(classify(input(apps: apps, running: ["com.a"])).isEmpty)
    }

    @Test func unusedFindingIncludesSupportFilesAndLaunchItems() throws {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let support = [SupportEntry(url: URL(fileURLWithPath: "/S/com.a"), bundleID: "com.a")]
        let agent = makeItem("com.a.agent", program: "/Applications/A.app/Contents/MacOS/agent")
        let finding = try #require(classify(input(apps: [app], items: [agent], support: support)).first)
        #expect(finding.parts.map(\.kind) == [.app, .support, .launchItem(label: "com.a.agent", domain: .userAgent)])
        #expect(finding.size == 100 + 10 + 10)
        #expect(finding.id == "app:/Applications/A.app")
    }

    @Test func bloatwareNeedsTheAppleTeam() {
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let apple: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "F3LWYJ7GM7") }
        let found = classify(input(apps: [garageBand]), signature: apple)
        #expect(found.map(\.group) == [.bloatware])
        #expect(found.first?.risk == .caution)
        #expect(classify(input(apps: [garageBand]), signature: { _ in Signature(kind: .identified, teamID: "EVIL") }).isEmpty)
    }

    @Test func soundLibrariesFollowGarageBandUnlessLogicIsInstalled() {
        let sounds = [URL(fileURLWithPath: "/Library/Application Support/GarageBand")]
        let garageBand = makeApp("/Applications/GarageBand.app", id: Bloatware.garageBandID, lastUsed: days(1))
        let logic = makeApp("/Applications/Logic Pro.app", id: Bloatware.logicID, lastUsed: days(1))
        let apple: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "F3LWYJ7GM7") }

        let withGarageBand = classify(input(apps: [garageBand], sounds: sounds), signature: apple)
        #expect(withGarageBand.first?.parts.map(\.url) == [garageBand.url] + sounds)

        let withLogic = classify(input(apps: [garageBand, logic], sounds: sounds), signature: apple)
        #expect(withLogic.first?.parts.map(\.url) == [garageBand.url])

        let alone = classify(input(sounds: sounds))
        #expect(alone.map(\.id) == ["bloat:sounds"])
    }

    @Test func leftoversBecomeFindings() {
        let orphan = makeItem("com.gone.updater", orphaned: true)
        let onlyItem = classify(input(items: [orphan]))
        #expect(onlyItem.map(\.group) == [.leftover])
        #expect(onlyItem.first?.risk == .safe)
        #expect(onlyItem.first?.preselected == true)

        let onlyFiles = classify(input(support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.gone.app"), bundleID: "com.gone.app")]))
        #expect(onlyFiles.first?.risk == .review)
        #expect(onlyFiles.first?.preselected == false)
    }

    @Test func backgroundItemsSkipAppleAndClaimedItems() {
        let unused = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let items = [
            makeItem("com.apple.thing"),
            makeItem("com.vendor.agent", program: "/usr/local/bin/agent"),
            makeItem("com.a.agent", program: "/Applications/A.app/Contents/MacOS/agent"),
        ]
        let found = classify(input(apps: [unused], items: items))
        #expect(found.filter { $0.group == .background }.map(\.title) == ["com.vendor.agent"])
        #expect(found.filter { $0.group == .unused }.count == 1)
    }

    @Test func duplicateBundleIDsStaySeparate() {
        let apps = [makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400)),
                    makeApp("/Users/me/Applications/A.app", id: "com.a", lastUsed: days(400))]
        let found = classify(input(apps: apps, support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.a"), bundleID: "com.a")]))
        #expect(Set(found.map(\.id)).count == 2)
        let allPaths = found.flatMap { $0.parts.map(\.url.path) }
        #expect(allPaths.count == Set(allPaths).count)
    }

    @Test func threatHitConvertsTheAppsFinding() throws {
        let active = makeApp("/Applications/Evil.app", id: "com.evil", lastUsed: days(1))
        let hit = ThreatHit(paths: ["/Applications/Evil.app"], verdict: .malicious, reason: "Matches XProtect", title: "Evil")
        let finding = try #require(classify(input(apps: [active]), hits: [hit]).first)
        #expect(finding.group == .threat)
        #expect(finding.verdict == .malicious)
        #expect(finding.reasons.first == "Matches XProtect")
        #expect(finding.preselected)
    }

    @Test func threatHitElsewhereCreatesItsOwnFinding() {
        let hit = ThreatHit(paths: ["/Users/Shared/.x/agent", "/L/com.x.plist"], verdict: .suspicious, reason: "Hidden", title: "com.x")
        let found = classify(input(), hits: [hit])
        #expect(found.map(\.id) == ["threat:/Users/Shared/.x/agent"])
        #expect(found.first?.parts.count == 2)
        #expect(found.first?.preselected == false)
    }

    @Test func strongestVerdictWins() {
        let app = makeApp("/Applications/Keeper.app", id: "com.keeper", lastUsed: days(1))
        let hits = [ThreatHit(paths: [app.path], verdict: .suspicious, reason: "a", title: "Keeper"),
                    ThreatHit(paths: [app.path], verdict: .adware, reason: "b", title: "Keeper")]
        #expect(classify(input(apps: [app]), hits: hits).first?.verdict == .adware)
    }

    @Test func untrustedAppsSayWhy() {
        let app = makeApp("/Applications/A.app", id: "com.a", lastUsed: days(400))
        let found = classify(input(apps: [app]), signature: { _ in Signature(kind: .unsigned, teamID: nil) })
        #expect(found.first?.reasons.last == "Not signed")
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `scripts/test.sh ClassifierTests`
Expected: FAIL — `cannot find 'Classifier' in scope` (and `Finding`, `Bloatware`, `ThreatHit`, `AppScanInput`).

- [ ] **Step 4: Implement `Sources/Model/Apps/Findings.swift`**

```swift
import Foundation
import SwiftUI

enum FindingGroup: String, CaseIterable, Identifiable, Sendable {
    case threat, unused, bloatware, leftover, background

    var id: String { rawValue }
    var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }

    var title: String {
        switch self {
        case .threat: "Threats"
        case .unused: "Unused apps"
        case .bloatware: "Bloatware"
        case .leftover: "Leftovers"
        case .background: "Background items"
        }
    }

    var caption: String {
        switch self {
        case .threat: "Matches Apple's malware rules, known adware, or behaves like it."
        case .unused: "Apps you haven't opened in a while, with their support files."
        case .bloatware: "Optional apps and content that came with your Mac."
        case .leftover: "Files and launch items from apps that are already gone."
        case .background: "Everything else that starts on its own. Remove only what you recognize."
        }
    }

    var symbol: String {
        switch self {
        case .threat: "exclamationmark.shield.fill"
        case .unused: "moon.zzz.fill"
        case .bloatware: "shippingbox.fill"
        case .leftover: "tray.full.fill"
        case .background: "gearshape.2.fill"
        }
    }

    var tint: Color {
        switch self {
        case .threat: .red
        case .unused: .indigo
        case .bloatware: .orange
        case .leftover: .teal
        case .background: .gray
        }
    }
}

enum Verdict: Int, Comparable, Sendable {
    case suspicious, adware, malicious

    static func < (lhs: Verdict, rhs: Verdict) -> Bool { lhs.rawValue < rhs.rawValue }

    var label: String {
        switch self {
        case .suspicious: "Suspicious"
        case .adware: "Adware"
        case .malicious: "Malicious"
        }
    }

    var color: Color {
        switch self {
        case .suspicious: .yellow
        case .adware: .orange
        case .malicious: .red
        }
    }
}

struct FindingPart: Identifiable, Hashable, Sendable {
    enum Kind: Hashable, Sendable {
        case app, support, file
        case launchItem(label: String, domain: LaunchDomain)
    }

    let url: URL
    let size: Int64
    let kind: Kind

    var id: String { url.path }

    var isLaunchItem: Bool {
        guard case .launchItem = kind else { return false }
        return true
    }
}

struct Finding: Identifiable, Hashable, Sendable {
    let id: String
    var group: FindingGroup
    var verdict: Verdict? = nil
    let title: String
    var reasons: [String]
    /// A path whose Finder icon represents this finding.
    let iconPath: String?
    var parts: [FindingPart]
    var risk: Risk
    var lastUsed: Date? = nil
    var isRunning = false

    var size: Int64 { parts.reduce(0) { $0 + $1.size } }

    /// Only confirmed threats and launch items that can't run anyway start ticked.
    var preselected: Bool {
        if let verdict { return verdict >= .adware }
        return group == .leftover && parts.allSatisfy(\.isLaunchItem)
    }

    func contains(_ path: String) -> Bool {
        parts.contains { path == $0.url.path || path.hasPrefix($0.url.path + "/") }
    }
}

struct ThreatHit: Hashable, Sendable {
    /// What to remove; the first path is the thing the hit is about.
    let paths: [String]
    let verdict: Verdict
    let reason: String
    let title: String

    var primary: String { paths.first ?? "" }
}
```

- [ ] **Step 5: Implement `Sources/Model/Apps/Bloatware.swift`**

```swift
import Foundation

enum Bloatware {
    static let garageBandID = "com.apple.garageband10"
    static let logicID = "com.apple.logic10"

    /// Apple's optional App Store apps and the team IDs they're signed with. They aren't
    /// "anchor apple" signed, so the team ID is what proves they're Apple's.
    static let apps: [String: String] = [
        garageBandID: "F3LWYJ7GM7",
        "com.apple.iMovieApp": "PTN9T2S29T",
        "com.apple.iWork.Keynote": "74J34U3R6X",
        "com.apple.iWork.Pages": "74J34U3R6X",
        "com.apple.iWork.Numbers": "74J34U3R6X",
    ]

    static let soundLibraryPaths = [
        "/Library/Application Support/GarageBand", "/Library/Application Support/Logic",
        "/Library/Audio/Apple Loops", "/Library/Audio/Impulse Responses/Apple",
    ]

    static func isBloatware(_ app: InstalledApp, signature: (String) -> Signature) -> Bool {
        guard let team = apps[app.bundleID] else { return false }
        let actual = signature(app.path)
        return actual.kind == .apple || (actual.kind == .identified && actual.teamID == team)
    }

    static func soundLibraries(existing: (String) -> Bool = DirectorySizer.exists) -> [URL] {
        soundLibraryPaths.filter(existing).map { URL(fileURLWithPath: $0) }
    }
}
```

- [ ] **Step 6: Implement `Sources/Model/Apps/Classifier.swift`**

```swift
import Foundation

struct AppScanInput: Sendable {
    var apps: [InstalledApp]
    var launchItems: [LaunchItem]
    var support: [SupportEntry]
    /// Bundle IDs of running apps.
    var running: Set<String>
    var ownID: String
    var now: Date
    /// GarageBand/Logic content folders that exist on this Mac.
    var soundLibraries: [URL]
}

/// Turns a scan into findings. Every path lands in at most one finding.
enum Classifier {
    static func findings(_ input: AppScanInput, unusedAfter days: Int, hits: [ThreatHit] = [],
                         signature: (String) -> Signature = CodeSignature.check,
                         size: (URL) -> Int64 = { DirectorySizer.allocatedSize(atPath: $0.path) }) -> [Finding] {
        let cutoff = input.now.addingTimeInterval(-Double(days) * 86_400)
        let logicInstalled = input.apps.contains { $0.bundleID == Bloatware.logicID }
        let garageBandInstalled = input.apps.contains { $0.bundleID == Bloatware.garageBandID }

        var supportByApp: [String: [SupportEntry]] = [:]
        for entry in input.support {
            if let owner = SupportFiles.owner(of: entry, among: input.apps) { supportByApp[owner.path, default: []].append(entry) }
        }
        var launchByApp: [String: [LaunchItem]] = [:]
        for item in input.launchItems {
            if let owner = owner(of: item, among: input.apps) { launchByApp[owner.path, default: []].append(item) }
        }

        var findings: [Finding] = []
        for app in input.apps where app.bundleID != input.ownID {
            let threatened = hits.contains { $0.primary == app.path || $0.primary.hasPrefix(app.path + "/") }
            let bloat = Bloatware.isBloatware(app, signature: signature)
            let unused = !input.running.contains(app.bundleID) && isUnused(app, before: cutoff)
            guard threatened || bloat || unused else { continue }

            var parts = [FindingPart(url: app.url, size: app.size, kind: .app)]
            parts += (supportByApp[app.path] ?? []).map { FindingPart(url: $0.url, size: size($0.url), kind: .support) }
            parts += (launchByApp[app.path] ?? []).map { launchPart($0, size: size) }
            if bloat, app.bundleID == Bloatware.garageBandID, !logicInstalled {
                parts += input.soundLibraries.map { FindingPart(url: $0, size: size($0), kind: .file) }
            }

            var reasons = [usage(of: app, now: input.now)]
            if bloat { reasons.insert("Optional Apple app", at: 0) }
            let appSignature = signature(app.path)
            if !appSignature.isTrusted { reasons.append(appSignature.summary) }

            findings.append(Finding(id: "app:" + app.path, group: bloat ? .bloatware : (unused ? .unused : .threat),
                                    title: app.name, reasons: reasons, iconPath: app.path, parts: parts,
                                    risk: bloat ? .caution : .review, lastUsed: app.lastUsed,
                                    isRunning: input.running.contains(app.bundleID)))
        }

        if !garageBandInstalled, !logicInstalled, !input.soundLibraries.isEmpty {
            findings.append(Finding(id: "bloat:sounds", group: .bloatware, title: "GarageBand & Logic sound library",
                                    reasons: ["Loops and instruments only GarageBand and Logic use"], iconPath: nil,
                                    parts: input.soundLibraries.map { FindingPart(url: $0, size: size($0), kind: .file) },
                                    risk: .caution))
        }

        let installedIDs = input.apps.flatMap { [$0.bundleID] + $0.nestedBundleIDs }
        for group in Leftovers.find(entries: input.support, launchItems: input.launchItems, installedIDs: installedIDs,
                                    runningIDs: input.running, ownID: input.ownID) {
            let parts = group.entries.map { FindingPart(url: $0.url, size: size($0.url), kind: .support) }.filter { $0.size > 0 }
                + group.launchItems.map { launchPart($0, size: size) }
            guard !parts.isEmpty else { continue }
            var reasons: [String] = []
            if parts.contains(where: { !$0.isLaunchItem }) { reasons.append("Left behind by an app that's no longer installed") }
            if !group.launchItems.isEmpty { reasons.append("Starts a program that no longer exists") }
            findings.append(Finding(id: "leftover:" + group.key, group: .leftover, title: group.key, reasons: reasons,
                                    iconPath: nil, parts: parts, risk: parts.allSatisfy(\.isLaunchItem) ? .safe : .review))
        }

        let claimed = Set(findings.flatMap { $0.parts.map(\.url.path) })
        for item in input.launchItems where !claimed.contains(item.plist.path) && !item.label.hasPrefix("com.apple.") {
            let owner = owner(of: item, among: input.apps)
            var reasons = [item.domain.title]
            if let owner { reasons.append("Part of \(owner.name)") }
            if let program = item.program { reasons.append(signature(program).summary) }
            findings.append(Finding(id: "launch:" + item.plist.path, group: .background, title: item.label, reasons: reasons,
                                    iconPath: owner?.path, parts: [launchPart(item, size: size)], risk: .review))
        }

        merge(hits, into: &findings, size: size)
        return findings.sorted {
            if $0.group != $1.group { return $0.group.order < $1.group.order }
            if $0.verdict != $1.verdict { return ($0.verdict ?? .suspicious) > ($1.verdict ?? .suspicious) }
            return $0.size > $1.size
        }
    }

    /// The installed app a launch item belongs to: by program location, associated ID, or label.
    static func owner(of item: LaunchItem, among apps: [InstalledApp]) -> InstalledApp? {
        if let program = item.program, let app = apps.first(where: { program.hasPrefix($0.path + "/") }) { return app }
        if let id = item.associatedBundleID, let app = apps.first(where: { $0.bundleID == id }) { return app }
        return apps.first { app in IDs.owns(app.bundleID, item.label) || app.nestedBundleIDs.contains { IDs.owns($0, item.label) } }
    }

    static func isUnused(_ app: InstalledApp, before cutoff: Date) -> Bool {
        if let lastUsed = app.lastUsed { return lastUsed < cutoff }
        if let added = app.dateAdded { return added < cutoff }
        return false
    }

    static func usage(of app: InstalledApp, now: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        if let lastUsed = app.lastUsed { return "Last opened \(formatter.localizedString(for: lastUsed, relativeTo: now))" }
        if let added = app.dateAdded { return "Never opened · added \(formatter.localizedString(for: added, relativeTo: now))" }
        return "Never opened"
    }

    /// Folds threat hits into the finding that already owns the path, or adds a new finding.
    static func merge(_ hits: [ThreatHit], into findings: inout [Finding], size: (URL) -> Int64) {
        for hit in hits {
            if let index = findings.firstIndex(where: { $0.contains(hit.primary) }) {
                findings[index].group = .threat
                findings[index].verdict = max(findings[index].verdict ?? hit.verdict, hit.verdict)
                findings[index].risk = .review
                if !findings[index].reasons.contains(hit.reason) { findings[index].reasons.insert(hit.reason, at: 0) }
                for path in hit.paths.dropFirst() where !findings.contains(where: { $0.contains(path) }) {
                    let url = URL(fileURLWithPath: path)
                    findings[index].parts.append(FindingPart(url: url, size: size(url), kind: .file))
                }
            } else {
                let paths = hit.paths.filter { path in !findings.contains { $0.contains(path) } }
                findings.append(Finding(id: "threat:" + hit.primary, group: .threat, verdict: hit.verdict, title: hit.title,
                                        reasons: [hit.reason], iconPath: hit.primary.hasSuffix(".app") ? hit.primary : nil,
                                        parts: paths.map { FindingPart(url: URL(fileURLWithPath: $0), size: size(URL(fileURLWithPath: $0)), kind: .file) },
                                        risk: .review))
            }
        }
    }

    private static func launchPart(_ item: LaunchItem, size: (URL) -> Int64) -> FindingPart {
        FindingPart(url: item.plist, size: size(item.plist), kind: .launchItem(label: item.label, domain: item.domain))
    }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `scripts/test.sh ClassifierTests`
Expected: 12 tests `✔`.

- [ ] **Step 8: Commit**

```bash
git add Sources/Model/Apps/Findings.swift Sources/Model/Apps/Bloatware.swift Sources/Model/Apps/Classifier.swift Tests/Support/Fixtures.swift Tests/ClassifierTests.swift
git commit -m "Classify apps into unused, bloatware, leftovers, background items and threats"
```

---

### Task 6: Elevated removal in the deletion pipeline

**Files:**
- Create: `Sources/Model/Apps/PrivilegedRemover.swift`
- Modify: `Sources/Model/Deletion.swift` (`DeletionOperation.Kind`, `DeletionJob`, `DeletionResult`, `DeletionController.execute`, `Deleter.perform`, new `DeletionOperation.url`)
- Modify: `Sources/Model/Formatting.swift` (add `AppManagement`)
- Modify: `Sources/Views/Overlays.swift` (`ResultToast`)
- Test: `Tests/PrivilegedRemoverTests.swift`

**Interfaces:**
- Consumes: `SupportFiles.userFolders`, `DirectorySizer.exists`, `Shell.run`.
- Produces:
  - `DeletionOperation.Kind.unload(target: String)` — runs `launchctl bootout <target>`, always `.removed`.
  - `DeletionOperation.url: URL?` (for `.trash`/`.remove`).
  - `DeletionJob.allowsElevation: Bool` (default `false`), `DeletionResult.blockedByAppManagement: Bool` (default `false`).
  - `struct ElevatedOperation: Hashable, Sendable { url: URL; trash: Bool }`
  - `enum PrivilegedRemover { isAllowed(_:home:); quote(_:); script(for:owner:trashDirectory:stamp:); appleScript(for:); parse(_:count:); elevationCandidates(_:outcomes:home:) -> [(index: Int, operation: ElevatedOperation)]; run(_:) async -> [Bool]?; retry(_:outcomes:) async -> [DeletionOutcome] }`
  - `enum AppManagement { static func openSettings() }`

- [ ] **Step 1: Write the failing tests `Tests/PrivilegedRemoverTests.swift`**

```swift
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh PrivilegedRemoverTests`
Expected: FAIL — `cannot find 'PrivilegedRemover' in scope`, `type 'DeletionOperation.Kind' has no member 'unload'`.

- [ ] **Step 3: Extend `Sources/Model/Deletion.swift`**

In `struct DeletionOperation`, replace the `Kind` enum with:

```swift
    enum Kind {
        case trash(URL)
        case remove(URL)
        case command(executable: String, arguments: [String])
        /// `launchctl bootout <target>`; not being loaded counts as success.
        case unload(target: String)
    }
```

Directly after `struct DeletionOperation { … }` add:

```swift
extension DeletionOperation {
    var url: URL? {
        switch kind {
        case .trash(let url), .remove(let url): url
        case .command, .unload: nil
        }
    }
}
```

In `struct DeletionJob`, add after `let movesToTrash: Bool`:

```swift
    /// Retry items the user can't remove with one administrator prompt.
    var allowsElevation = false
```

In `struct DeletionResult`, add after `var movedToTrash: Bool`:

```swift
    /// An app bundle couldn't be moved even as admin: macOS's App Management protection.
    var blockedByAppManagement = false
```

In `DeletionController.execute()`, replace:

```swift
        let operations = job.operations
        let outcomes = await Task.detached(priority: .userInitiated) {
            await Deleter.performAll(operations, parallelism: Self.parallelism, progress: box)
        }.value
        ticker.cancel()
```

with:

```swift
        let operations = job.operations
        var outcomes = await Task.detached(priority: .userInitiated) {
            await Deleter.performAll(operations, parallelism: Self.parallelism, progress: box)
        }.value
        if job.allowsElevation {
            outcomes = await PrivilegedRemover.retry(operations, outcomes: outcomes)
        }
        ticker.cancel()
```

and replace:

```swift
        let result = DeletionResult(outcomes: outcomes, freedBytes: freed, failures: failures, movedToTrash: job.movesToTrash)
```

with:

```swift
        let blocked = zip(operations, outcomes).contains { operation, outcome in
            guard case .failed = outcome, let path = operation.url?.path else { return false }
            return path.hasPrefix("/Applications/") && path.hasSuffix(".app") && DirectorySizer.exists(path)
        }
        let result = DeletionResult(outcomes: outcomes, freedBytes: freed, failures: failures,
                                    movedToTrash: job.movesToTrash, blockedByAppManagement: blocked)
```

In `Deleter.perform(_:)`, add a case after `.command`:

```swift
        case .unload(let target):
            // Not being loaded is fine: its plist is removed by the next operation either way.
            _ = await Shell.run("/bin/launchctl", ["bootout", target], timeout: 30)
            return .removed
```

- [ ] **Step 4: Implement `Sources/Model/Apps/PrivilegedRemover.swift`**

```swift
import Foundation

struct ElevatedOperation: Hashable, Sendable {
    let url: URL
    let trash: Bool
}

/// Removes root-owned items with one administrator prompt per batch. Every path must pass
/// `isAllowed`, and every argument is single-quoted, so the elevated shell only ever sees
/// literal paths inside a handful of known locations.
enum PrivilegedRemover {
    static func allowedRoots(home: String) -> [String] {
        ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools",
         "/Library/Application Support", "/Library/Caches", "/Library/Preferences", "/Library/Audio/Apple Loops",
         "/Library/Audio/Impulse Responses", home]
    }

    static func protectedPaths(home: String) -> [String] {
        allowedRoots(home: home)
            + ["Library", "Applications", "Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Library/LaunchAgents"]
                .map { home + "/" + $0 }
            + SupportFiles.userFolders.map { home + "/" + $0 }
    }

    static func isAllowed(_ path: String, home: String = NSHomeDirectory()) -> Bool {
        guard path.hasPrefix("/"), !path.contains("\n"), !path.contains("\r"), !path.contains("\0") else { return false }
        let components = path.split(separator: "/")
        guard !components.contains(".."), !components.contains(".") else { return false }

        func resolved(_ path: String) -> String { URL(fileURLWithPath: path).resolvingSymlinksInPath().path }
        // Resolve the parent (not the item: removing a symlink only removes the link).
        let target = (resolved((path as NSString).deletingLastPathComponent) as NSString)
            .appendingPathComponent((path as NSString).lastPathComponent)
        let roots = allowedRoots(home: home).map(resolved)
        let protected = Set(protectedPaths(home: home).map(resolved))
        return roots.contains { target.hasPrefix($0 + "/") } && !protected.contains(target)
    }

    static func quote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }

    /// A /bin/sh script that prints "OK <index>" or "FAIL <index>" for each operation.
    static func script(for operations: [ElevatedOperation], owner: String, trashDirectory: String, stamp: String) -> String {
        var lines = ["cd /"]
        for (index, operation) in operations.enumerated() {
            let path = quote(operation.url.path)
            if operation.url.path.hasPrefix("/Library/LaunchDaemons/") {
                lines.append("/bin/launchctl bootout system \(path) 2>/dev/null")
            }
            if operation.trash {
                let base = operation.url.deletingPathExtension().lastPathComponent
                let ext = operation.url.pathExtension
                let destination = quote(trashDirectory + "/" + base + " \(stamp)-\(index)" + (ext.isEmpty ? "" : "." + ext))
                lines.append("if /bin/mv \(path) \(destination) && /usr/sbin/chown -R \(quote(owner)) \(destination); then echo OK \(index); else echo FAIL \(index); fi")
            } else {
                lines.append("if /bin/rm -rf \(path); then echo OK \(index); else echo FAIL \(index); fi")
            }
        }
        return lines.joined(separator: "\n")
    }

    static func appleScript(for script: String) -> String {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "do shell script \"\(escaped)\" with administrator privileges without altering line endings"
    }

    static func parse(_ output: String, count: Int) -> [Bool] {
        var succeeded = [Bool](repeating: false, count: count)
        for line in output.split(whereSeparator: \.isNewline) {
            let words = line.split(separator: " ")
            if words.count == 2, words[0] == "OK", let index = Int(words[1]), succeeded.indices.contains(index) {
                succeeded[index] = true
            }
        }
        return succeeded
    }

    /// Failed trash/remove operations whose item still exists and may be removed as admin.
    static func elevationCandidates(_ operations: [DeletionOperation], outcomes: [DeletionOutcome],
                                    home: String = NSHomeDirectory()) -> [(index: Int, operation: ElevatedOperation)] {
        zip(operations, outcomes).enumerated().compactMap { index, pair in
            let (operation, outcome) = pair
            guard case .failed = outcome, let url = operation.url, DirectorySizer.exists(url.path),
                  isAllowed(url.path, home: home) else { return nil }
            if case .trash = operation.kind { return (index, ElevatedOperation(url: url, trash: true)) }
            return (index, ElevatedOperation(url: url, trash: false))
        }
    }

    /// Runs the batch as admin. nil means the prompt was cancelled or something refused to run.
    static func run(_ operations: [ElevatedOperation]) async -> [Bool]? {
        guard !operations.isEmpty, operations.allSatisfy({ isAllowed($0.url.path) }) else { return nil }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH.mm.ss"
        let stamp = formatter.string(from: .now)
        let script = script(for: operations, owner: NSUserName(), trashDirectory: NSHomeDirectory() + "/.Trash", stamp: stamp)
        // osascript shows the password prompt itself, so the UI never blocks on it.
        let run = await Shell.run("/usr/bin/osascript", ["-e", appleScript(for: script)], timeout: 900)
        guard run.status == 0 else { return nil }
        return parse(run.output, count: operations.count)
    }

    static func retry(_ operations: [DeletionOperation], outcomes: [DeletionOutcome]) async -> [DeletionOutcome] {
        let candidates = elevationCandidates(operations, outcomes: outcomes)
        guard !candidates.isEmpty else { return outcomes }
        var outcomes = outcomes
        let results = await run(candidates.map(\.operation))
        for (position, candidate) in candidates.enumerated() {
            if let results {
                if results[position] { outcomes[candidate.index] = .removed }
            } else {
                outcomes[candidate.index] = .failed("Administrator access was cancelled")
            }
        }
        return outcomes
    }
}
```

- [ ] **Step 5: Add `AppManagement` to `Sources/Model/Formatting.swift`** (after `enum FullDiskAccess { … }`)

```swift
enum AppManagement {
    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AppBundles") {
            NSWorkspace.shared.open(url)
        }
    }
}
```

- [ ] **Step 6: Surface the App Management hint in `ResultToast` (`Sources/Views/Overlays.swift`)**

Inside `ResultToast`'s inner `VStack(alignment: .leading, spacing: 1)`, after the `if result.failures > 0 { … }` block, add:

```swift
                    if result.blockedByAppManagement {
                        Button("Allow Strata in App Management…") { AppManagement.openSettings() }
                            .buttonStyle(.link)
                            .font(.system(size: 11))
                    }
```

- [ ] **Step 7: Run the tests to verify they pass, and that the app still builds**

Run: `scripts/test.sh PrivilegedRemoverTests`
Expected: all `✔` (parameterised cases count individually).
Run: `scripts/test.sh`
Expected: every suite so far passes, `** TEST SUCCEEDED **`.

- [ ] **Step 8: Commit**

```bash
git add Sources/Model/Apps/PrivilegedRemover.swift Sources/Model/Deletion.swift Sources/Model/Formatting.swift Sources/Views/Overlays.swift Tests/PrivilegedRemoverTests.swift
git commit -m "Retry root-owned removals with one admin prompt per batch"
```

---

### Task 7: Apps & Threats tab

**Files:**
- Create: `Sources/Model/Apps/AppsModel.swift`
- Create: `Sources/Views/AppsView.swift`
- Create: `scripts/snapshot-apps.sh`
- Modify: `Sources/Model/AppModel.swift` (tab, `apps`, callbacks, `rescan`, `requestAppRemoval`)
- Modify: `Sources/StrataApp.swift` (detail switch, title, subtitle, toolbar, sidebar)
- Modify: `Sources/Views/Mascot.swift` (`tabChanged`)
- Modify: `Sources/Model/DevHooks.swift` (`STRATA_TAB=apps`)
- Test: `Tests/AppsModelTests.swift`

**Interfaces:**
- Consumes: everything from Tasks 1–6; `AppModel.DeleteMode`, `FullDiskAccessBanner`, `IconCache`, `Finder`.
- Produces:
  - `enum AppScan { static func gather(running:ownID:home:now:) -> AppScanInput }`
  - `@MainActor @Observable final class AppsModel` with `phase`, `status`, `fraction: Double?`, `findings`, `selected: Set<String>`, `expanded`, `unusedDays`, `threatCount`, `removableBytes`, `selectedBytes`, `summary`, `findings(in:)`, `setSelected(_:_:)`, `toggleExpanded(_:)`, `scan()`, `removalJob(trash:)`, `didRemove(_:result:)`, `onItemsRemoved`, `onScanFinished`, and `nonisolated static func removalJob(for:trash:uid:) -> DeletionJob`, `nonisolated static func selection(for:choices:) -> Set<String>`.
  - `AppModel.Tab.apps`, `AppModel.Tab.title`, `AppModel.apps`, `AppModel.requestAppRemoval()`.

- [ ] **Step 1: Write the failing tests `Tests/AppsModelTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct AppsModelTests {
    func part(_ path: String, _ size: Int64, _ kind: FindingPart.Kind) -> FindingPart {
        FindingPart(url: URL(fileURLWithPath: path), size: size, kind: kind)
    }

    func finding(_ id: String, parts: [FindingPart] = [], running: Bool = false, verdict: Verdict? = nil,
                 group: FindingGroup = .unused) -> Finding {
        Finding(id: id, group: group, verdict: verdict, title: id, reasons: [], iconPath: nil, parts: parts,
                risk: .review, isRunning: running)
    }

    @Test func removalJobSkipsRunningAppsAndUnloadsUserAgents() {
        let a = finding("app:A", parts: [
            part("/Applications/A.app", 100, .app),
            part("/u/Library/LaunchAgents/com.a.agent.plist", 1, .launchItem(label: "com.a.agent", domain: .userAgent)),
            part("/Library/LaunchDaemons/com.a.d.plist", 1, .launchItem(label: "com.a.d", domain: .systemDaemon)),
        ])
        let running = finding("app:B", parts: [part("/Applications/B.app", 5, .app)], running: true)
        let job = AppsModel.removalJob(for: [a, running], trash: true, uid: 501)
        #expect(job.allowsElevation)
        #expect(job.movesToTrash)
        #expect(job.operations.map(\.label) == ["A.app", "com.a.agent", "com.a.agent.plist", "com.a.d.plist"])
        if case .unload(let target) = job.operations[1].kind {
            #expect(target == "gui/501/com.a.agent")
        } else {
            Issue.record("Expected an unload operation before the agent's plist")
        }
        #expect(job.totalBytes == 102)
    }

    @Test func permanentModeRemoves() {
        let job = AppsModel.removalJob(for: [finding("x", parts: [part("/Applications/X.app", 1, .app)])], trash: false, uid: 501)
        #expect(!job.movesToTrash)
        if case .remove(let url) = job.operations[0].kind { #expect(url.path == "/Applications/X.app") } else { Issue.record("Expected .remove") }
    }

    @Test func selectionKeepsUserChoices() {
        let a = finding("a", verdict: .malicious, group: .threat)
        let b = finding("b")
        let c = finding("c", running: true, verdict: .malicious, group: .threat)
        #expect(AppsModel.selection(for: [a, b, c], choices: [:]) == ["a"])
        #expect(AppsModel.selection(for: [a, b, c], choices: ["a": false, "b": true, "c": true]) == ["b"])
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh AppsModelTests`
Expected: FAIL — `cannot find 'AppsModel' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Apps/AppsModel.swift`**

```swift
import AppKit
import SwiftUI

/// Gathers everything the Apps & Threats tab classifies. Runs off the main actor.
enum AppScan {
    static func gather(running: Set<String>, ownID: String, home: String = NSHomeDirectory(), now: Date = .now) -> AppScanInput {
        let apps = AppInventory.load(locations: AppInventory.standardLocations(home: home))
        var locations: [String: URL] = [:]
        for app in apps where locations[app.bundleID] == nil { locations[app.bundleID] = app.url }
        let launchItems = LaunchItems.load(from: LaunchItems.standardDirectories(home: home)) { id in
            locations[id] ?? NSWorkspace.shared.urlForApplication(withBundleIdentifier: id)
        }
        return AppScanInput(apps: apps, launchItems: launchItems,
                            support: SupportFiles.index(SupportFiles.standardFolders(home: home)),
                            running: running, ownID: ownID, now: now, soundLibraries: Bloatware.soundLibraries())
    }
}

@MainActor
@Observable
final class AppsModel {
    enum Phase: Equatable { case idle, scanning, ready }

    static let unusedChoices = [30, 90, 180, 365]
    private static let unusedKey = "AppsUnusedDays"

    private(set) var phase: Phase = .idle
    private(set) var status = ""
    /// 0…1 while a measurable step runs; nil means indeterminate.
    private(set) var fraction: Double?
    private(set) var findings: [Finding] = []
    private(set) var selected: Set<String> = []
    private(set) var expanded: Set<String> = []
    var unusedDays: Int = UserDefaults.standard.object(forKey: AppsModel.unusedKey) as? Int ?? 90 {
        didSet {
            guard unusedDays != oldValue else { return }
            UserDefaults.standard.set(unusedDays, forKey: Self.unusedKey)
            if phase == .ready { Task { await classify() } }
        }
    }

    @ObservationIgnored var onItemsRemoved: (([URL]) -> Void)?
    @ObservationIgnored var onScanFinished: (() -> Void)?
    @ObservationIgnored private var input: AppScanInput?
    @ObservationIgnored private var hits: [ThreatHit] = []
    /// Checkboxes the user touched; everything else follows `Finding.preselected`.
    @ObservationIgnored private var choices: [String: Bool] = [:]
    @ObservationIgnored private var scanID = 0

    func findings(in group: FindingGroup) -> [Finding] { findings.filter { $0.group == group } }
    var threatCount: Int { findings.filter { $0.group == .threat }.count }
    var removableBytes: Int64 { findings.filter { $0.group != .background }.reduce(0) { $0 + $1.size } }
    var selectedBytes: Int64 { findings.reduce(0) { selected.contains($1.id) ? $0 + $1.size : $0 } }

    var summary: String {
        switch phase {
        case .idle: "Finds unused apps, bloatware, leftovers and threats."
        case .scanning: status
        case .ready:
            threatCount > 0
                ? "\(threatCount) possible threat\(threatCount == 1 ? "" : "s") found. Review them first."
                : "No threats found. \(findings.count) thing\(findings.count == 1 ? "" : "s") you could remove."
        }
    }

    func setSelected(_ finding: Finding, _ isOn: Bool) {
        choices[finding.id] = isOn
        selected = Self.selection(for: findings, choices: choices)
    }

    func toggleExpanded(_ finding: Finding) {
        if expanded.contains(finding.id) { expanded.remove(finding.id) } else { expanded.insert(finding.id) }
    }

    func scan() {
        scanID += 1
        let id = scanID
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        let ownID = Bundle.main.bundleIdentifier ?? "com.lucascoupez.strata"
        choices = [:]
        hits = []
        fraction = nil
        status = "Reading your apps…"
        withAnimation(.smooth) { phase = .scanning }
        Task {
            let input = await Task.detached(priority: .utility) { AppScan.gather(running: running, ownID: ownID) }.value
            guard id == scanID else { return }
            self.input = input
            status = "Sorting things out…"
            await classify()
            guard id == scanID else { return }
            status = ""
            withAnimation(.smooth) { phase = .ready }
            onScanFinished?()
        }
    }

    private func classify() async {
        guard let input else { return }
        let days = unusedDays, hits = hits, id = scanID
        let result = await Task.detached(priority: .utility) { Classifier.findings(input, unusedAfter: days, hits: hits) }.value
        guard id == scanID else { return }
        withAnimation(.smooth) {
            findings = result
            selected = Self.selection(for: result, choices: choices)
        }
    }

    func removalJob(trash: Bool) -> DeletionJob {
        Self.removalJob(for: findings.filter { selected.contains($0.id) }, trash: trash, uid: getuid())
    }

    func didRemove(_ job: DeletionJob, result: DeletionResult) {
        var removed: [URL] = []
        for (operation, outcome) in zip(job.operations, result.outcomes) {
            guard let url = operation.url else { continue }
            if case .failed = outcome { continue }
            removed.append(url)
        }
        onItemsRemoved?(removed)
        let gone = Set(removed.map(\.path))
        // Keep the cached scan in step so re-classifying doesn't bring removed things back.
        input?.apps.removeAll { gone.contains($0.path) }
        input?.launchItems.removeAll { gone.contains($0.plist.path) }
        input?.support.removeAll { gone.contains($0.url.path) }
        hits.removeAll { gone.contains($0.primary) }
        withAnimation(.smooth) {
            findings.removeAll { finding in finding.parts.allSatisfy { gone.contains($0.url.path) } }
            selected = Self.selection(for: findings, choices: choices)
        }
    }

    nonisolated static func selection(for findings: [Finding], choices: [String: Bool]) -> Set<String> {
        Set(findings.filter { !$0.isRunning && (choices[$0.id] ?? $0.preselected) }.map(\.id))
    }

    nonisolated static func removalJob(for findings: [Finding], trash: Bool, uid: uid_t) -> DeletionJob {
        var operations: [DeletionOperation] = []
        for finding in findings where !finding.isRunning {
            for part in finding.parts {
                // System daemons are booted out by the elevated script, which runs as root.
                if case .launchItem(let label, let domain) = part.kind, domain != .systemDaemon {
                    operations.append(DeletionOperation(label: label, kind: .unload(target: "gui/\(uid)/\(label)"), estimatedBytes: 0))
                }
                operations.append(DeletionOperation(label: part.url.lastPathComponent,
                                                    kind: trash ? .trash(part.url) : .remove(part.url),
                                                    estimatedBytes: part.size))
            }
        }
        var job = DeletionJob(title: trash ? "Moving to Trash" : "Deleting permanently", operations: operations, movesToTrash: trash)
        job.allowsElevation = true
        return job
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh AppsModelTests`
Expected: 3 tests `✔`.

- [ ] **Step 5: Wire the model into `Sources/Model/AppModel.swift`**

Replace `enum Tab: Hashable { case explore, cleanup }` with:

```swift
    enum Tab: Hashable {
        case explore, cleanup, apps

        var title: String {
            switch self {
            case .explore: "Explore"
            case .cleanup: "Cleanup"
            case .apps: "Apps & Threats"
            }
        }
    }
```

Replace the `tab` property with:

```swift
    var tab: Tab = .explore {
        didSet {
            guard tab != oldValue else { return }
            mascot.tabChanged(to: tab, model: self)
            if tab == .apps, apps.phase == .idle { apps.scan() }
        }
    }
```

After `let cleanup = CleanupModel()` add `let apps = AppsModel()`.

In `init()`, after `cleanup.onItemsRemoved = …` add:

```swift
        apps.onItemsRemoved = { [weak self] urls in self?.removeFromTree(urls) }
        apps.onScanFinished = { [weak self] in
            guard let self, tab == .apps else { return }
            let count = apps.threatCount
            if count > 0 {
                mascot.say("Yikes! \(count) suspicious thing\(count == 1 ? "" : "s") moved in. Check the Threats list first.", mood: .excited, duration: 7)
            } else {
                mascot.say("No nasties found! \(apps.removableBytes.bytes) of old apps and leftovers you could let me eat.", mood: .happy, duration: 6)
            }
        }
```

Replace `rescan()` with:

```swift
    func rescan() {
        switch tab {
        case .cleanup: Task { await cleanup.measureAll() }
        case .apps: apps.scan()
        case .explore: if let target { startScan(target) }
        }
    }
```

After `requestCleanup(_:)` add:

```swift
    func requestAppRemoval() {
        guard !deletion.isBusy else { return }
        let job = apps.removalJob(trash: deleteMode == .trash)
        guard !job.operations.isEmpty else { return }
        deletion.schedule(job) { [weak self] result in self?.apps.didRemove(job, result: result) }
    }
```

- [ ] **Step 6: Teach Nibble about the tab (`Sources/Views/Mascot.swift`)**

Replace the body of `tabChanged(to:model:)` with:

```swift
        switch tab {
        case .cleanup:
            say("Snack menu! Caches grow back on their own. Read the Caution and Review tags before picking those.", mood: .curious, duration: 6)
        case .apps:
            say("Let's see which apps are gathering dust… and whether anything sneaky moved in.", mood: .curious, duration: 5)
        case .explore:
            if model.phase == .ready { say("Back to the rings! Click one to dive in.", mood: .happy, duration: 3) }
        }
```

- [ ] **Step 7: Create `Sources/Views/AppsView.swift`**

```swift
import SwiftUI

struct AppsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let apps = model.apps
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                AppsHeader()

                if !model.hasFullDiskAccess {
                    FullDiskAccessBanner().frame(maxWidth: .infinity)
                }

                ForEach(FindingGroup.allCases) { group in
                    let items = apps.findings(in: group)
                    if !items.isEmpty {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Label(group.title, systemImage: group.symbol)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundStyle(group == .threat ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                                Text(group.caption)
                                    .font(.system(size: 11.5))
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                            .padding(.leading, 6)
                            GlassEffectContainer(spacing: 10) {
                                VStack(spacing: 10) {
                                    ForEach(items) { FindingRow(finding: $0) }
                                }
                            }
                        }
                    }
                }

                if apps.phase == .ready, apps.findings.isEmpty {
                    Label("Nothing to remove. Your apps look tidy.", systemImage: "checkmark.seal")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(24)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity)
        }
        .scrollContentBackground(.hidden)
    }
}

struct AppsHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        @Bindable var apps = model.apps
        HStack(alignment: .center, spacing: 24) {
            ZStack {
                Circle()
                    .fill(AngularGradient(colors: [.green, .cyan, .purple, .pink, .green], center: .center))
                    .blur(radius: 16)
                    .opacity(0.55)
                Image(systemName: apps.threatCount > 0 ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                    .font(.system(size: 38, weight: .semibold))
                    .foregroundStyle(.white)
                    .symbolEffect(.pulse, isActive: apps.phase == .scanning)
            }
            .frame(width: 84, height: 84)

            VStack(alignment: .leading, spacing: 4) {
                Text(apps.threatCount > 0 ? "Threats found" : "Removable")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(apps.threatCount > 0 ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                Text(apps.removableBytes.bytes)
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                    .animation(.snappy, value: apps.removableBytes)
                Text(apps.summary)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                if apps.phase == .scanning {
                    ProgressView(value: apps.fraction)
                        .progressViewStyle(.linear)
                        .frame(maxWidth: 260)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 10) {
                Button { model.requestAppRemoval() } label: {
                    Label("Remove \(apps.selectedBytes.bytes)", systemImage: "trash.fill")
                        .fontWeight(.semibold)
                        .contentTransition(.numericText())
                }
                .buttonStyle(.glassProminent)
                .tint(.pink)
                .controlSize(.extraLarge)
                .disabled(apps.selected.isEmpty || model.deletion.isBusy || apps.phase == .scanning)

                HStack(spacing: 8) {
                    Picker("", selection: $model.deleteMode) {
                        ForEach(AppModel.DeleteMode.allCases) { mode in
                            Label(mode.title, systemImage: mode.symbol).tag(mode)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Picker("Unused after", selection: $apps.unusedDays) {
                        ForEach(AppsModel.unusedChoices, id: \.self) { Text("\($0) days").tag($0) }
                    }
                    .fixedSize()
                    .help("How long an app must go unopened to count as unused")
                }

                Button { apps.scan() } label: { Label("Re-scan", systemImage: "arrow.clockwise") }
                    .buttonStyle(.glass)
                    .disabled(apps.phase == .scanning)
            }
        }
        .padding(24)
        .glassEffect(.regular, in: .rect(cornerRadius: 30))
    }
}

struct FindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: Finding

    var body: some View {
        let apps = model.apps
        let isExpanded = apps.expanded.contains(finding.id)
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 14) {
                Toggle("", isOn: Binding(get: { apps.selected.contains(finding.id) }, set: { apps.setSelected(finding, $0) }))
                    .toggleStyle(.checkbox)
                    .labelsHidden()
                    .disabled(finding.isRunning)
                    .help(finding.isRunning ? "Quit it to remove" : "")

                icon.frame(width: 38, height: 38)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(finding.title)
                            .font(.system(size: 14, weight: .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        tag(finding.verdict?.label ?? finding.risk.label, color: finding.verdict?.color ?? finding.risk.color)
                            .help(finding.verdict == nil ? finding.risk.explanation : "")
                        if finding.isRunning { tag("Running", color: .gray) }
                    }
                    Text(finding.reasons.joined(separator: " · "))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 12)

                Text(finding.size.bytes)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .monospacedDigit()

                Button {
                    withAnimation(.smooth) { apps.toggleExpanded(finding) }
                } label: {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 12, weight: .semibold))
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        .frame(width: 24, height: 24)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .padding(16)

            if isExpanded {
                Divider().opacity(0.4).padding(.horizontal, 16)
                VStack(spacing: 2) {
                    ForEach(finding.parts) { part in
                        HStack(spacing: 10) {
                            Image(nsImage: IconCache.icon(for: part.url.path)).resizable().frame(width: 18, height: 18)
                            Text(part.url.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                                .font(.system(size: 12))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Text(part.size.bytes)
                                .font(.system(size: 11.5, weight: .medium, design: .rounded))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                            Button { Finder.reveal(part.url) } label: { Image(systemName: "magnifyingglass") }
                                .buttonStyle(.plain)
                                .foregroundStyle(.tertiary)
                                .help("Reveal in Finder")
                        }
                        .padding(.horizontal, 20)
                        .padding(.vertical, 4)
                    }
                }
                .padding(.vertical, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .glassEffect(.regular.tint(finding.group == .threat ? Color.red.opacity(0.08) : nil), in: .rect(cornerRadius: 22))
    }

    @ViewBuilder
    private var icon: some View {
        if let path = finding.iconPath {
            Image(nsImage: IconCache.icon(for: path)).resizable().interpolation(.high)
        } else {
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous).fill(finding.group.tint.gradient)
                Image(systemName: finding.group.symbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
    }

    private func tag(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .bold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.18)))
            .foregroundStyle(color)
    }
}
```

- [ ] **Step 8: Show the tab in `Sources/StrataApp.swift`**

In `ContentView.body`, replace the `switch model.tab { … }` with:

```swift
                switch model.tab {
                case .explore: ExploreView()
                case .cleanup: CleanupView()
                case .apps: AppsView()
                }
```

Replace `.navigationTitle(model.tab == .explore ? "Explore" : "Cleanup")` with `.navigationTitle(model.tab.title)`.

Replace the toolbar button's `.help(…)` and `.disabled(…)` with:

```swift
                    .help(model.tab == .explore ? "Scan again" : model.tab == .apps ? "Scan apps again" : "Re-check recommendations")
                    .disabled((model.tab == .explore && (model.target == nil || model.phase == .scanning))
                              || (model.tab == .apps && model.apps.phase == .scanning))
```

In `subtitle`, add a case:

```swift
        case .apps:
            return model.apps.phase == .ready ? "\(model.apps.removableBytes.bytes) removable" : ""
```

In `SidebarView`, after the `Section("Storage") { … }` block, add:

```swift
            Section("Health") {
                Label {
                    HStack {
                        Text("Apps & Threats")
                        Spacer()
                        if model.apps.threatCount > 0 {
                            Text("\(model.apps.threatCount)")
                                .font(.system(size: 11, weight: .bold))
                                .padding(.horizontal, 6)
                                .background(Capsule().fill(.red.opacity(0.2)))
                                .foregroundStyle(.red)
                        }
                    }
                } icon: {
                    Image(systemName: "shield.lefthalf.filled")
                }
                .tag(AppModel.Tab.apps)
            }
```

- [ ] **Step 9: Add the snapshot hook to `Sources/Model/DevHooks.swift`**

Document it in the header comment (`/// - STRATA_TAB=apps: open Apps & Threats; with STRATA_SNAPSHOT_DIR, snapshot it once scanned.`) and make these the first lines of `run(model:)`:

```swift
        let env = ProcessInfo.processInfo.environment
        if env["STRATA_TAB"] == "apps" {
            model.tab = .apps
            guard let directory = env["STRATA_SNAPSHOT_DIR"] else { return }
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                snapshot(directory, "apps-01-scanning")
                while model.apps.phase != .ready { try? await Task.sleep(for: .milliseconds(200)) }
                try? await Task.sleep(for: .seconds(1.5))
                snapshot(directory, "apps-02-ready")
            }
            return
        }
```

(Remove the now-duplicate `let env = …` line that followed.)

- [ ] **Step 10: Create `scripts/snapshot-apps.sh`**

```sh
#!/bin/zsh
# Launches the built app on the Apps & Threats tab and saves window snapshots to build/snapshots.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$PWD/build/snapshots"
rm -rf "$out" && mkdir -p "$out"
STRATA_TAB=apps STRATA_SNAPSHOT_DIR="$out" build/Strata.app/Contents/MacOS/Strata >/dev/null 2>&1 &
pid=$!
for _ in {1..240}; do
  [[ -f "$out/apps-02-ready.png" ]] && break
  sleep 1
done
sleep 1
kill $pid 2>/dev/null || true
ls "$out"
```

Run: `chmod +x scripts/snapshot-apps.sh`

- [ ] **Step 11: Run all tests, build, and look at the tab**

Run: `scripts/test.sh`
Expected: `** TEST SUCCEEDED **`.
Run: `scripts/build.sh && scripts/snapshot-apps.sh`
Expected: `Built build/Strata.app`, then `apps-01-scanning.png apps-02-ready.png`.
Open both PNGs (Read tool). Check: the sidebar shows **Health › Apps & Threats**; the header shows a size and summary; groups appear with rows, icons, badges and sizes; nothing is pre-ticked except orphaned launch items. On this Mac expect at least Bloatware (GarageBand/iMovie/iWork) and Background items.

- [ ] **Step 12: Commit**

```bash
git add Sources/Model/Apps/AppsModel.swift Sources/Views/AppsView.swift Sources/Model/AppModel.swift Sources/StrataApp.swift Sources/Views/Mascot.swift Sources/Model/DevHooks.swift scripts/snapshot-apps.sh Tests/AppsModelTests.swift
git commit -m "Add the Apps & Threats tab: unused apps, bloatware, leftovers and background items"
```

---

# Milestone 2 — Threats

### Task 8: Vendored libyara and the YARA engine

**Files:**
- Create: `scripts/vendor-yara.sh`
- Create: `Vendor/yara/` (generated by the script) and `Vendor/yara/module.modulemap`
- Modify: `project.yml` (new `yara` target; `Strata` and `StrataTests` settings)
- Create: `Sources/Model/Threats/YaraEngine.swift`
- Test: `Tests/YaraEngineTests.swift`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `struct YaraMatch: Hashable, Sendable { rule: String; description: String?; var displayName: String }`
  - `enum YaraError: Error, Equatable { case compile([String]); case initialization(Int32) }`
  - `final class YaraEngine: @unchecked Sendable { let ruleCount: Int; init(ruleFiles: [URL]) throws; convenience init(source: String) throws; func scan(file: URL, timeout: Int32 = 10) -> [YaraMatch]? }` — `nil` when the file couldn't be scanned; safe to call concurrently.

- [ ] **Step 1: Create `scripts/vendor-yara.sh`**

```sh
#!/bin/zsh
# Downloads a pinned libyara release and copies just what Strata compiles into Vendor/yara.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=4.5.8
SHA256=c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -o "$work/yara.tgz" "https://github.com/VirusTotal/yara/archive/refs/tags/v$VERSION.tar.gz"
echo "$SHA256  $work/yara.tgz" | shasum -a 256 -c --quiet
tar xzf "$work/yara.tgz" -C "$work"
src="$work/yara-$VERSION/libyara"
dst=Vendor/yara/libyara
rm -rf $dst
mkdir -p $dst/modules $dst/proc
cp "$src"/*.c "$src"/*.h $dst/
cp -R "$src/include" "$src/tlshc" $dst/
cp "$src/proc/none.c" $dst/proc/
cp "$src/modules/module_list" $dst/modules/
for module in tests elf math time console string hash; do cp -R "$src/modules/$module" $dst/modules/; done
mkdir -p $dst/modules/pe && cp "$src/modules/pe/pe.c" "$src/modules/pe/pe_utils.c" $dst/modules/pe/
cp "$work/yara-$VERSION/COPYING" Vendor/yara/COPYING
echo "$VERSION" > Vendor/yara/VERSION
echo "Vendored libyara $VERSION into Vendor/yara"
```

Run: `chmod +x scripts/vendor-yara.sh && scripts/vendor-yara.sh`
Expected: `Vendored libyara 4.5.8 into Vendor/yara`; `find Vendor/yara -name '*.c' | wc -l` prints `48`.

- [ ] **Step 2: Create `Vendor/yara/module.modulemap`**

```
module yara [system] {
    header "libyara/include/yara.h"
    link "yara"
    export *
}
```

- [ ] **Step 3: Add the library target to `project.yml`**

Under `targets:` add:

```yaml
  yara:
    type: library.static
    platform: macOS
    sources:
      - path: Vendor/yara/libyara
        excludes:
          - "include/**"
    settings:
      base:
        HEADER_SEARCH_PATHS: ["$(SRCROOT)/Vendor/yara/libyara", "$(SRCROOT)/Vendor/yara/libyara/include"]
        GCC_PREPROCESSOR_DEFINITIONS: ["USE_NO_PROC", "HAVE_SCAN_PROC_IMPL=0", "HASH_MODULE", "HAVE_COMMONCRYPTO_COMMONCRYPTO_H", "BUCKETS_128=1", "CHECKSUM_1B=1"]
        GCC_WARN_INHIBIT_ALL_WARNINGS: YES
        CLANG_ENABLE_MODULES: NO
```

In the `Strata` target add `dependencies:` (`- target: yara`) and these two keys under `settings.base`:

```yaml
        SWIFT_INCLUDE_PATHS: ["$(SRCROOT)/Vendor/yara"]
        HEADER_SEARCH_PATHS: ["$(SRCROOT)/Vendor/yara/libyara/include"]
```

Add the same two keys to `StrataTests.settings.base`.

- [ ] **Step 4: Write the failing tests `Tests/YaraEngineTests.swift`**

```swift
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
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `scripts/test.sh YaraEngineTests`
Expected: FAIL — `cannot find 'YaraEngine' in scope`. (If instead the build fails inside libyara, re-check Step 3's defines against the spec's Global Constraints.)

- [ ] **Step 6: Implement `Sources/Model/Threats/YaraEngine.swift`**

```swift
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
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `scripts/test.sh YaraEngineTests`
Expected: 4 tests `✔` (the live-rules test runs on any Mac with XProtect in `/var/protected`).

- [ ] **Step 8: Check the Release build still links**

Run: `scripts/build.sh`
Expected: `Built build/Strata.app`.

- [ ] **Step 9: Commit**

```bash
git add scripts/vendor-yara.sh Vendor/yara project.yml Sources/Model/Threats/YaraEngine.swift Tests/YaraEngineTests.swift
git commit -m "Vendor libyara 4.5.8 and add a Swift YARA engine"
```

---

### Task 9: XProtect rules locator

**Files:**
- Create: `Sources/Model/Threats/XProtectRules.swift`
- Test: `Tests/XProtectRulesTests.swift`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `struct XProtectInfo: Hashable, Sendable { bundle: URL; version: Int; updated: Date?; ruleFiles: [URL]; blockedExtensionIDs: Set<String> }`
  - `enum XProtectRules { static let candidates: [URL]; static func locate(_ candidates: [URL] = candidates) -> XProtectInfo?; static func read(_ bundle: URL) -> XProtectInfo? }`

- [ ] **Step 1: Write the failing tests `Tests/XProtectRulesTests.swift`**

```swift
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
            "ExtensionBlacklist": ["Extensions": [["CFBundleIdentifier": "com.bad.ext", "Developer Identifier": "X"]]],
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
        #expect(info.blockedExtensionIDs == ["com.bad.ext"])
        #expect(info.updated != nil)
    }

    @Test func nothingReadableMeansNil() {
        #expect(XProtectRules.locate([dir.url.appendingPathComponent("none")]) == nil)
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh XProtectRulesTests`
Expected: FAIL — `cannot find 'XProtectRules' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Threats/XProtectRules.swift`**

```swift
import Foundation

struct XProtectInfo: Hashable, Sendable {
    let bundle: URL
    let version: Int
    let updated: Date?
    let ruleFiles: [URL]
    /// Safari extensions Apple blocks.
    let blockedExtensionIDs: Set<String>
}

/// Apple's malware rules, read straight from the system. Newer macOS updates them in
/// /var/protected; the copy in /Library/Apple can lag a version behind.
enum XProtectRules {
    static let candidates = [
        URL(fileURLWithPath: "/var/protected/xprotect/XProtect.bundle"),
        URL(fileURLWithPath: "/Library/Apple/System/Library/CoreServices/XProtect.bundle"),
    ]

    static func locate(_ candidates: [URL] = candidates) -> XProtectInfo? {
        candidates.compactMap(read).max { $0.version < $1.version }
    }

    static func read(_ bundle: URL) -> XProtectInfo? {
        let contents = bundle.appendingPathComponent("Contents")
        let resources = contents.appendingPathComponent("Resources")
        let yara = resources.appendingPathComponent("XProtect.yara")
        guard FileManager.default.isReadableFile(atPath: yara.path),
              let info = NSDictionary(contentsOf: contents.appendingPathComponent("Info.plist")) as? [String: Any],
              let text = info["CFBundleShortVersionString"] as? String,
              let version = Int(text) ?? Double(text).map({ Int($0) }) else { return nil }
        let scripts = resources.appendingPathComponent("XPScripts.yr")
        let files = [yara] + (FileManager.default.isReadableFile(atPath: scripts.path) ? [scripts] : [])
        let updated = (try? FileManager.default.attributesOfItem(atPath: yara.path))?[.modificationDate] as? Date
        return XProtectInfo(bundle: bundle, version: version, updated: updated, ruleFiles: files,
                            blockedExtensionIDs: blockedExtensions(in: resources.appendingPathComponent("XProtect.meta.plist")))
    }

    static func blockedExtensions(in meta: URL) -> Set<String> {
        guard let plist = NSDictionary(contentsOf: meta) as? [String: Any],
              let blacklist = plist["ExtensionBlacklist"] as? [String: Any],
              let extensions = blacklist["Extensions"] as? [[String: Any]] else { return [] }
        return Set(extensions.compactMap { $0["CFBundleIdentifier"] as? String })
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh XProtectRulesTests`
Expected: 2 tests `✔`.

- [ ] **Step 5: Commit**

```bash
git add Sources/Model/Threats/XProtectRules.swift Tests/XProtectRulesTests.swift
git commit -m "Locate the newest XProtect rules and Apple's extension blocklist"
```

---

### Task 10: Known adware and suspicious-item heuristics

**Files:**
- Create: `Sources/Model/Threats/KnownThreats.swift`
- Create: `Sources/Model/Threats/Heuristics.swift`
- Test: `Tests/ThreatRulesTests.swift`

**Interfaces:**
- Consumes: `LaunchItem`, `Signature`, `AppScanInput`, `ThreatHit`, `Verdict`, `CodeSignature.check`, fixtures `makeApp`/`makeItem`.
- Produces:
  - `enum KnownThreats { struct Indicator { family: String; prefixes: [String] }; static let indicators; static func match(_ id: String) -> Indicator? }`
  - `enum Heuristics { trustedPrefixes; riskyLocations; systemPrefixes; interpreters; static func reasons(for: LaunchItem, signature: (String) -> Signature) -> [String]; static func removablePaths(of: LaunchItem) -> [String]; static func isRiskyLocation(_:) -> Bool }`
  - `enum StaticThreats { static func hits(_ input: AppScanInput, blockedExtensionIDs: Set<String>, signature: (String) -> Signature = CodeSignature.check) -> [ThreatHit] }`

- [ ] **Step 1: Write the failing tests `Tests/ThreatRulesTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct ThreatRulesTests {
    let unsigned: (String) -> Signature = { _ in Signature(kind: .unsigned, teamID: nil) }
    let trusted: (String) -> Signature = { _ in Signature(kind: .identified, teamID: "T") }
    let apple: (String) -> Signature = { _ in Signature(kind: .apple, teamID: nil) }

    @Test func knownAdwareMatchesByPrefix() {
        #expect(KnownThreats.match("com.mackeeper.MacKeeper")?.family == "MacKeeper")
        #expect(KnownThreats.match("COM.MACKEEPER.helper") != nil)
        #expect(KnownThreats.match("com.mackeeperish.app") == nil)
        #expect(KnownThreats.match("com.google.Chrome") == nil)
    }

    @Test func unsignedProgramInAHiddenFolderIsSuspicious() {
        let reasons = Heuristics.reasons(for: makeItem("com.x.agent", program: "/Users/me/.hidden/agent"), signature: unsigned)
        #expect(reasons == ["Runs from a hidden folder", "Program isn't signed"])
    }

    @Test func trustedPackageManagerAppleAndOrphanedItemsAreFine() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/Users/me/.hidden/agent"), signature: trusted).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("homebrew.mxcl.redis", program: "/opt/homebrew/opt/redis/bin/redis-server"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.apple.x", program: "/tmp/x"), signature: unsigned).isEmpty)
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/gone", orphaned: true), signature: unsigned).isEmpty)
    }

    @Test func interpreterRunningAScriptFromTempIsSuspicious() {
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"]), signature: apple)
            == ["Runs a bash script from a temporary folder"])
        #expect(Heuristics.reasons(for: makeItem("com.x", program: "/bin/bash", arguments: ["-c", "echo hi"]), signature: apple).isEmpty)
    }

    @Test func removablePathsSkipSystemAndAppPrograms() {
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/bin/bash", arguments: ["/tmp/run.sh"])) == ["/L/com.x.plist", "/tmp/run.sh"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Applications/X.app/Contents/MacOS/x")) == ["/L/com.x.plist"])
        #expect(Heuristics.removablePaths(of: makeItem("com.x", program: "/Users/me/.hidden/agent")) == ["/L/com.x.plist", "/Users/me/.hidden/agent"])
    }

    @Test func staticHitsCoverAdwareBlockedExtensionsAndSuspiciousItems() {
        let adware = makeApp("/Applications/MacKeeper.app", id: "com.mackeeper.MacKeeper")
        let blocked = makeApp("/Applications/Search.app", id: "com.example.search", nested: ["com.searchnt.safari"])
        let fine = makeApp("/Applications/Fine.app", id: "com.example.fine")
        let input = AppScanInput(apps: [adware, blocked, fine],
                                 launchItems: [makeItem("com.x.agent", program: "/Users/me/.hidden/agent")],
                                 support: [SupportEntry(url: URL(fileURLWithPath: "/S/com.zeobit.keeper"), bundleID: "com.zeobit.keeper")],
                                 running: [], ownID: "com.lucascoupez.strata", now: .now, soundLibraries: [])
        let hits = StaticThreats.hits(input, blockedExtensionIDs: ["com.searchnt.safari"], signature: unsigned)
        #expect(hits.map(\.verdict) == [.adware, .malicious, .suspicious, .adware])
        #expect(hits.map(\.primary) == ["/Applications/MacKeeper.app", "/Applications/Search.app", "/L/com.x.agent.plist", "/S/com.zeobit.keeper"])
        #expect(hits[2].paths == ["/L/com.x.agent.plist", "/Users/me/.hidden/agent"])
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh ThreatRulesTests`
Expected: FAIL — `cannot find 'KnownThreats' in scope` (and `Heuristics`, `StaticThreats`).

- [ ] **Step 3: Implement `Sources/Model/Threats/KnownThreats.swift`**

Each prefix below was checked against a public write-up while planning (cited inline). Only add a family later if you can cite where its bundle IDs or launch labels are documented — a wrong prefix flags someone's legitimate app as adware.

```swift
import Foundation

/// Well-documented adware and "cleaner" scareware, matched by bundle ID or launch label prefix.
/// Conservative on purpose: every entry cites a public write-up.
enum KnownThreats {
    struct Indicator: Sendable {
        let family: String
        /// Lower-case prefixes, each ending in ".".
        let prefixes: [String]
    }

    static let indicators: [Indicator] = [
        // com.mackeeper.MacKeeperAgent / com.zeobit.MacKeeper.Helper:
        // https://discussions.apple.com/docs/DOC-12761, https://discussions.apple.com/thread/6531782
        Indicator(family: "MacKeeper", prefixes: ["com.mackeeper.", "com.zeobit."]),
        // com.pcv.hlpramc, com.PCvark.AdvancedMacCleaner:
        // https://www.malwarebytes.com/blog/news/2016/08/pcvark-plays-dirty
        Indicator(family: "PCVARK cleaners", prefixes: ["com.pcv.", "com.pcvark."]),
        // com.genieo.engine, com.genieo.completer.update: https://www.malwarebytes.com/blog/detections/osx-genieo
        Indicator(family: "Genieo", prefixes: ["com.genieo."]),
        // com.vsearch.agent, com.vsearch.daemon: https://www.malwarebytes.com/blog/detections/osx-vsearch
        Indicator(family: "VSearch", prefixes: ["com.vsearch."]),
    ]

    static func match(_ id: String) -> Indicator? {
        let candidate = id.lowercased() + "."
        return indicators.first { $0.prefixes.contains { candidate.hasPrefix($0) } }
    }
}
```

- [ ] **Step 4: Implement `Sources/Model/Threats/Heuristics.swift`**

```swift
import Foundation

/// Signs that a launch item is up to no good. Signed-by-an-identified-developer programs and
/// package-manager installs (Homebrew bottles are ad-hoc signed by design) are left alone.
enum Heuristics {
    static let trustedPrefixes = ["/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/usr/local/Homebrew/", "/opt/local/", "/nix/store/"]
    static let riskyLocations = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/var/tmp/", "/Users/Shared/"]
    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"]
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "osascript", "node"]

    static func reasons(for item: LaunchItem, signature: (String) -> Signature) -> [String] {
        guard let program = item.program, !item.isOrphaned, !item.label.hasPrefix("com.apple.") else { return [] }
        let name = (program as NSString).lastPathComponent
        if interpreters.contains(name) {
            guard let script = item.arguments.first(where: { $0.hasPrefix("/") }), isRiskyLocation(script) else { return [] }
            return ["Runs a \(name) script from \(locationName(script))"]
        }
        if trustedPrefixes.contains(where: program.hasPrefix) { return [] }
        let programSignature = signature(program)
        if programSignature.isTrusted { return [] }

        var reasons: [String] = []
        if isRiskyLocation(program) { reasons.append("Runs from \(locationName(program))") }
        switch programSignature.kind {
        case .unsigned: reasons.append("Program isn't signed")
        case .adhoc: reasons.append("Program has no developer signature")
        case .invalid: reasons.append("Program's signature is broken")
        case .unidentified: reasons.append("Program is from an unidentified developer")
        case .apple, .identified: break
        }
        return reasons
    }

    /// The plist plus any program or script that isn't part of macOS or of an app bundle.
    static func removablePaths(of item: LaunchItem) -> [String] {
        var paths = [item.plist.path]
        guard let program = item.program else { return paths }
        if !systemPrefixes.contains(where: program.hasPrefix), !trustedPrefixes.contains(where: program.hasPrefix),
           !program.contains(".app/") {
            paths.append(program)
        }
        if interpreters.contains((program as NSString).lastPathComponent) {
            paths += item.arguments.filter { $0.hasPrefix("/") && isRiskyLocation($0) }
        }
        return paths
    }

    static func isRiskyLocation(_ path: String) -> Bool {
        riskyLocations.contains(where: path.hasPrefix) || path.split(separator: "/").dropLast().contains { $0.hasPrefix(".") }
    }

    private static func locationName(_ path: String) -> String {
        if path.hasPrefix("/Users/Shared/") { return "the shared Users folder" }
        if riskyLocations.contains(where: path.hasPrefix) { return "a temporary folder" }
        return "a hidden folder"
    }
}

/// Threats found without scanning file contents: known adware, Apple-blocked extensions and
/// suspicious launch items.
enum StaticThreats {
    static func hits(_ input: AppScanInput, blockedExtensionIDs: Set<String>,
                     signature: (String) -> Signature = CodeSignature.check) -> [ThreatHit] {
        var hits: [ThreatHit] = []
        for app in input.apps {
            let ids = [app.bundleID] + app.nestedBundleIDs
            if let blocked = ids.first(where: blockedExtensionIDs.contains) {
                hits.append(ThreatHit(paths: [app.path], verdict: .malicious, reason: "Contains an extension Apple blocks (\(blocked))", title: app.name))
            } else if let known = ids.lazy.compactMap(KnownThreats.match).first {
                hits.append(ThreatHit(paths: [app.path], verdict: .adware, reason: "Known adware: \(known.family)", title: app.name))
            }
        }
        for item in input.launchItems {
            if let known = KnownThreats.match(item.label) {
                hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item), verdict: .adware, reason: "Known adware: \(known.family)", title: item.label))
            } else {
                let reasons = Heuristics.reasons(for: item, signature: signature)
                if !reasons.isEmpty {
                    hits.append(ThreatHit(paths: Heuristics.removablePaths(of: item), verdict: .suspicious,
                                          reason: reasons.joined(separator: " · "), title: item.label))
                }
            }
        }
        for entry in input.support {
            if let id = entry.bundleID, let known = KnownThreats.match(id) {
                hits.append(ThreatHit(paths: [entry.url.path], verdict: .adware, reason: "Known adware: \(known.family)", title: id))
            }
        }
        return hits
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `scripts/test.sh ThreatRulesTests`
Expected: 6 tests `✔`.

- [ ] **Step 6: Commit**

```bash
git add Sources/Model/Threats/KnownThreats.swift Sources/Model/Threats/Heuristics.swift Tests/ThreatRulesTests.swift
git commit -m "Flag known adware, Apple-blocked extensions and suspicious launch items"
```

---

### Task 11: Privacy grants ("Can watch you")

**Files:**
- Create: `Sources/Model/Threats/PrivacyAccess.swift`
- Test: `Tests/PrivacyAccessTests.swift`

**Interfaces:**
- Consumes: `Signature`, `ThreatHit`, `DirectorySizer.exists`.
- Produces:
  - `struct PrivacyGrant: Hashable, Sendable, Identifiable { client: String; isPath: Bool; service: Service }` with `enum Service: String, CaseIterable, Identifiable, Sendable { case screen, keystrokes, accessibility, camera, microphone; title; symbol; settingsAnchor; canWatch }`
  - `enum PrivacyAccess { static func databases(home:) -> [URL]; static func load(from: [URL]) -> [PrivacyGrant]?; static func location(of: PrivacyGrant, resolve: (String) -> URL?) -> String?; static func resolveApp(_ id: String) -> URL?; static func hits(_ grants: [PrivacyGrant], resolve: (String) -> URL?, signature: (String) -> Signature) -> [ThreatHit]; static func openSettings(for: Service) }`

- [ ] **Step 1: Write the failing tests `Tests/PrivacyAccessTests.swift`**

```swift
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh PrivacyAccessTests`
Expected: FAIL — `cannot find 'PrivacyAccess' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Threats/PrivacyAccess.swift`**

```swift
import AppKit
import Foundation
import SQLite3

struct PrivacyGrant: Hashable, Sendable, Identifiable {
    enum Service: String, CaseIterable, Identifiable, Sendable {
        case screen = "kTCCServiceScreenCapture"
        case keystrokes = "kTCCServiceListenEvent"
        case accessibility = "kTCCServiceAccessibility"
        case camera = "kTCCServiceCamera"
        case microphone = "kTCCServiceMicrophone"

        var id: String { rawValue }

        var title: String {
            switch self {
            case .screen: "Screen Recording"
            case .keystrokes: "Input Monitoring"
            case .accessibility: "Accessibility"
            case .camera: "Camera"
            case .microphone: "Microphone"
            }
        }

        var symbol: String {
            switch self {
            case .screen: "rectangle.dashed.badge.record"
            case .keystrokes: "keyboard"
            case .accessibility: "accessibility"
            case .camera: "camera.fill"
            case .microphone: "mic.fill"
            }
        }

        var settingsAnchor: String {
            switch self {
            case .screen: "Privacy_ScreenCapture"
            case .keystrokes: "Privacy_ListenEvent"
            case .accessibility: "Privacy_Accessibility"
            case .camera: "Privacy_Camera"
            case .microphone: "Privacy_Microphone"
            }
        }

        /// Can see what you type or what's on screen, the permissions spyware needs.
        var canWatch: Bool { self == .screen || self == .keystrokes || self == .accessibility }
    }

    let client: String
    let isPath: Bool
    let service: Service

    var id: String { service.rawValue + client }
}

/// Reads macOS's privacy database. Needs Full Disk Access; returns nil without it.
enum PrivacyAccess {
    static func databases(home: String = NSHomeDirectory()) -> [URL] {
        [URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db"),
         URL(fileURLWithPath: "/Library/Application Support/com.apple.TCC/TCC.db")]
    }

    static func load(from databases: [URL]) -> [PrivacyGrant]? {
        var grants = Set<PrivacyGrant>()
        var readAny = false
        for url in databases {
            guard let rows = read(url) else { continue }
            readAny = true
            grants.formUnion(rows)
        }
        guard readAny else { return nil }
        return grants.sorted { ($0.client, $0.service.rawValue) < ($1.client, $1.service.rawValue) }
    }

    private static func read(_ url: URL) -> [PrivacyGrant]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            sqlite3_close(db)
            return nil
        }
        defer { sqlite3_close(db) }
        let services = PrivacyGrant.Service.allCases.map { "'\($0.rawValue)'" }.joined(separator: ",")
        let sql = "SELECT client, client_type, service FROM access WHERE auth_value = 2 AND service IN (\(services))"
        var statement: OpaquePointer?
        // A schema change or missing permission shows up here; treat it as unreadable.
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(statement) }
        var rows: [PrivacyGrant] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let client = sqlite3_column_text(statement, 0), let service = sqlite3_column_text(statement, 2),
                  let kind = PrivacyGrant.Service(rawValue: String(cString: service)) else { continue }
            rows.append(PrivacyGrant(client: String(cString: client), isPath: sqlite3_column_int(statement, 1) == 1, service: kind))
        }
        return rows
    }

    static func resolveApp(_ id: String) -> URL? { NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) }

    /// Where the client lives on disk, or nil if it's gone.
    static func location(of grant: PrivacyGrant, resolve: (String) -> URL?) -> String? {
        if grant.isPath { return DirectorySizer.exists(grant.client) ? grant.client : nil }
        return resolve(grant.client)?.path
    }

    /// Untrusted programs that can see your screen or keystrokes.
    static func hits(_ grants: [PrivacyGrant], resolve: (String) -> URL?, signature: (String) -> Signature) -> [ThreatHit] {
        let watching = Dictionary(grouping: grants.filter { $0.service.canWatch && !$0.client.hasPrefix("com.apple.") }, by: \.client)
        return watching.keys.sorted().compactMap { client in
            let clientGrants = watching[client] ?? []
            guard let first = clientGrants.first, let path = location(of: first, resolve: resolve) else { return nil }
            let clientSignature = signature(path)
            guard !clientSignature.isTrusted else { return nil }
            let services = clientGrants.map(\.service.title).sorted().joined(separator: ", ")
            return ThreatHit(paths: [path], verdict: .suspicious, reason: "\(clientSignature.summary) and allowed to use \(services)",
                             title: (path as NSString).lastPathComponent)
        }
    }

    static func openSettings(for service: PrivacyGrant.Service) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(service.settingsAnchor)") {
            NSWorkspace.shared.open(url)
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh PrivacyAccessTests`
Expected: 3 tests `✔`.

- [ ] **Step 5: Commit**

```bash
git add Sources/Model/Threats/PrivacyAccess.swift Tests/PrivacyAccessTests.swift
git commit -m "Read privacy grants and flag untrusted programs that can watch you"
```

---

### Task 12: Threat scanning in the tab

**Files:**
- Create: `Sources/Model/Threats/ThreatScanner.swift`
- Modify: `Sources/Model/Apps/AppsModel.swift` (threat pipeline, rules state, privacy grants)
- Modify: `Sources/Views/AppsView.swift` (rules footnote, `PrivacySection`)
- Test: `Tests/ThreatScannerTests.swift`

**Interfaces:**
- Consumes: `YaraEngine`, `YaraMatch`, `XProtectRules`, `XProtectInfo`, `StaticThreats`, `PrivacyAccess`, `InstalledApp`, `LaunchItem`, `ThreatHit`.
- Produces:
  - `final class ScanCounter: @unchecked Sendable { func claim(below: Int) -> Int?; func record(_ url: URL, _ matches: [YaraMatch]?); func snapshot() -> (done: Int, skipped: Int); var results: [(URL, [YaraMatch])] }`
  - `final class CancelFlag: @unchecked Sendable { func cancel(); var isCancelled: Bool }`
  - `enum ThreatScanner { maxFileSize; static func looseFolders(home:) -> [URL]; static func targets(apps:launchItems:looseFolders:) -> [URL]; static func isScannable(_:) -> Bool; static func scan(_:engine:counter:isCancelled:); static func hits(for:apps:launchItems:) -> [ThreatHit] }`
  - `AppsModel.RulesState`, `AppsModel.rules`, `AppsModel.skippedFiles`, `AppsModel.privacyGrants: [PrivacyGrant]?`, `AppsModel.rulesNote: String?`

- [ ] **Step 1: Write the failing tests `Tests/ThreatScannerTests.swift`**

```swift
import Foundation
import Testing
@testable import Strata

struct ThreatScannerTests {
    let dir = TempDir()

    @discardableResult
    func machO(_ relative: String) -> URL {
        let url = dir.url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! FileManager.default.copyItem(atPath: "/bin/ls", toPath: url.path)
        return url
    }

    func installed(_ url: URL) -> InstalledApp {
        InstalledApp(url: url, bundleID: "com.a", name: "A", version: nil, nestedBundleIDs: [], size: 1, lastUsed: nil, dateAdded: nil)
    }

    @Test func picksExecutablesAndScriptsOnly() {
        let app = dir.app("A.app", id: "com.a")
        machO("A.app/Contents/Library/LoginItems/L.app/Contents/MacOS/L")
        machO("A.app/Contents/Frameworks/F.framework/F")
        dir.file("A.app/Contents/Resources/data.bin", "plain")
        dir.file("Loose/notes.txt", "hello")
        machO("Loose/tool")
        let agent = LaunchItem(plist: dir.url.appendingPathComponent("x.plist"), label: "com.x", domain: .userAgent,
                               program: machO("bin/agent").path, arguments: [], associatedBundleID: nil, runsAtLoad: true, isOrphaned: false)
        let targets = ThreatScanner.targets(apps: [installed(app)], launchItems: [agent],
                                            looseFolders: [dir.url.appendingPathComponent("Loose")])
        #expect(Set(targets.map(\.lastPathComponent)) == ["main", "L", "tool", "agent"])
        #expect(targets.count == 4)
    }

    @Test func scansInParallelAndMapsHitsToTheirOwners() throws {
        let engine = try YaraEngine(source: #"rule Bad { meta: description = "TEST.BAD" strings: $a = "BAD_MARKER" condition: $a }"#)
        let app = dir.app("A.app", id: "com.a")
        let inApp = dir.file("A.app/Contents/MacOS/helper", "#!/bin/sh\n# BAD_MARKER\n")
        let loose = dir.file("Loose/run.sh", "#!/bin/sh\necho BAD_MARKER\n")
        let clean = dir.file("Loose/ok.sh", "#!/bin/sh\necho ok\n")
        let counter = ScanCounter()
        ThreatScanner.scan([inApp, loose, clean, dir.url.appendingPathComponent("missing")], engine: engine, counter: counter, isCancelled: { false })
        #expect(counter.snapshot().done == 4)
        #expect(counter.snapshot().skipped == 1)
        let hits = ThreatScanner.hits(for: counter.results, apps: [installed(app)], launchItems: [])
        #expect(Set(hits.map(\.primary)) == [app.path, loose.path])
        #expect(hits.allSatisfy { $0.verdict == .malicious && $0.reason == "Matches Apple's XProtect signature TEST.BAD" })
    }

    @Test func cancellationStopsEarly() throws {
        let engine = try YaraEngine(source: "rule A { condition: false }")
        let files = (0..<50).map { dir.file("f\($0).sh", "#!/bin/sh\n") }
        let counter = ScanCounter()
        ThreatScanner.scan(files, engine: engine, counter: counter, isCancelled: { true })
        #expect(counter.snapshot().done == 0)
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `scripts/test.sh ThreatScannerTests`
Expected: FAIL — `cannot find 'ThreatScanner' in scope`.

- [ ] **Step 3: Implement `Sources/Model/Threats/ThreatScanner.swift`**

```swift
import Foundation

final class ScanCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var next = 0
    private var done = 0
    private var skipped = 0
    private var found: [(URL, [YaraMatch])] = []

    func claim(below limit: Int) -> Int? {
        lock.withLock {
            guard next < limit else { return nil }
            defer { next += 1 }
            return next
        }
    }

    func record(_ url: URL, _ matches: [YaraMatch]?) {
        lock.withLock {
            done += 1
            if let matches {
                if !matches.isEmpty { found.append((url, matches)) }
            } else {
                skipped += 1
            }
        }
    }

    func snapshot() -> (done: Int, skipped: Int) { lock.withLock { (done, skipped) } }
    var results: [(URL, [YaraMatch])] { lock.withLock { found } }
}

final class CancelFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.withLock { cancelled = true } }
    var isCancelled: Bool { lock.withLock { cancelled } }
}

/// Runs XProtect's rules over the executables that matter: apps' own binaries and helpers,
/// everything launchd starts, and loose programs in the usual drop spots.
enum ThreatScanner {
    static let maxFileSize: Int64 = 256 * 1024 * 1024
    static let nestedFolders = ["Library/LoginItems", "Library/LaunchServices", "Helpers", "XPCServices", "PlugIns"]

    static func looseFolders(home: String = NSHomeDirectory()) -> [URL] {
        [URL(fileURLWithPath: home).appendingPathComponent("Downloads"), URL(fileURLWithPath: "/Users/Shared"),
         URL(fileURLWithPath: "/private/tmp"), URL(fileURLWithPath: "/private/var/tmp")]
    }

    static func targets(apps: [InstalledApp], launchItems: [LaunchItem], looseFolders: [URL]) -> [URL] {
        var seen = Set<String>()
        var result: [URL] = []
        func add(_ path: String) {
            guard !seen.contains(path) else { return }
            seen.insert(path)
            if isScannable(path) { result.append(URL(fileURLWithPath: path)) }
        }
        for app in apps { executables(in: app.url).forEach(add) }
        for item in launchItems where !item.isOrphaned {
            if let program = item.program { add(program) }
            item.arguments.filter { $0.hasPrefix("/") }.forEach(add)
        }
        for folder in looseFolders {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [] where !name.hasPrefix(".") {
                let url = folder.appendingPathComponent(name)
                if name.hasSuffix(".app") { executables(in: url).forEach(add) } else { add(url.path) }
            }
        }
        return result
    }

    static func executables(in bundle: URL) -> [String] {
        let contents = bundle.appendingPathComponent("Contents")
        var paths = files(in: contents.appendingPathComponent("MacOS"))
        for folder in nestedFolders {
            let directory = contents.appendingPathComponent(folder)
            for name in (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [] {
                let nested = directory.appendingPathComponent(name)
                paths += files(in: nested.appendingPathComponent("Contents/MacOS"))
                paths.append(nested.path) // Helpers can hold bare executables; isScannable filters directories.
            }
        }
        return paths
    }

    private static func files(in directory: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { !$0.hasPrefix(".") }
            .map { directory.appendingPathComponent($0).path }
    }

    /// Regular files under the size cap that are Mach-O binaries or scripts.
    static func isScannable(_ path: String) -> Bool {
        var info = stat()
        guard stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0, Int64(info.st_size) <= maxFileSize,
              let handle = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? handle.close() }
        let head = [UInt8](handle.readData(ofLength: 4))
        guard head.count == 4 else { return false }
        let magic = UInt32(head[0]) | UInt32(head[1]) << 8 | UInt32(head[2]) << 16 | UInt32(head[3]) << 24
        let machO: Set<UInt32> = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca]
        return machO.contains(magic) || head.starts(with: Array("#!".utf8))
            || head.starts(with: Array("Fasd".utf8)) || head.starts(with: Array("JsOs".utf8))
    }

    static func scan(_ targets: [URL], engine: YaraEngine, counter: ScanCounter, workers: Int = 4,
                     isCancelled: @escaping @Sendable () -> Bool) {
        DispatchQueue.concurrentPerform(iterations: workers) { _ in
            while !isCancelled(), let index = counter.claim(below: targets.count) {
                counter.record(targets[index], engine.scan(file: targets[index]))
            }
        }
    }

    static func hits(for matches: [(URL, [YaraMatch])], apps: [InstalledApp], launchItems: [LaunchItem]) -> [ThreatHit] {
        matches.map { url, found in
            let path = url.path
            let reason = "Matches Apple's XProtect signature \(found.map(\.displayName).joined(separator: ", "))"
            if let app = apps.first(where: { path.hasPrefix($0.path + "/") }) {
                return ThreatHit(paths: [app.path], verdict: .malicious, reason: reason, title: app.name)
            }
            if let item = launchItems.first(where: { $0.program == path || $0.arguments.contains(path) }) {
                return ThreatHit(paths: [item.plist.path, path], verdict: .malicious, reason: reason, title: item.label)
            }
            return ThreatHit(paths: [path], verdict: .malicious, reason: reason, title: url.lastPathComponent)
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/test.sh ThreatScannerTests`
Expected: 3 tests `✔`.

- [ ] **Step 5: Add the threat pipeline to `Sources/Model/Apps/AppsModel.swift`**

Add inside `AppsModel`, after `enum Phase …`:

```swift
    enum RulesState: Equatable {
        case unknown
        case loaded(version: Int, updated: Date?)
        case unavailable(String)
    }
```

Add stored properties after `private(set) var expanded …`:

```swift
    private(set) var rules: RulesState = .unknown
    private(set) var skippedFiles = 0
    /// nil without Full Disk Access.
    private(set) var privacyGrants: [PrivacyGrant]?
```

and after `@ObservationIgnored private var scanID = 0`:

```swift
    @ObservationIgnored private var cancelFlag: CancelFlag?
```

Add below `summary`:

```swift
    var rulesNote: String? {
        switch rules {
        case .unknown:
            return nil
        case .loaded(let version, let updated):
            var note = "Uses Apple's XProtect rules v\(version)"
            if let updated { note += ", updated \(updated.formatted(.dateTime.day().month()))" }
            note += ". No scanner catches everything."
            if skippedFiles > 0 { note += " \(skippedFiles) file\(skippedFiles == 1 ? "" : "s") couldn't be scanned." }
            return note
        case .unavailable(let reason):
            return "XProtect rules unavailable: \(reason)"
        }
    }
```

Replace `scan()` with:

```swift
    func scan() {
        scanID += 1
        let id = scanID
        cancelFlag?.cancel()
        let flag = CancelFlag()
        cancelFlag = flag
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        let ownID = Bundle.main.bundleIdentifier ?? "com.lucascoupez.strata"
        choices = [:]
        hits = []
        fraction = nil
        skippedFiles = 0
        status = "Reading your apps…"
        withAnimation(.smooth) { phase = .scanning }
        Task {
            let (input, xprotect, grants) = await Task.detached(priority: .utility) {
                (AppScan.gather(running: running, ownID: ownID), XProtectRules.locate(), PrivacyAccess.load(from: PrivacyAccess.databases()))
            }.value
            guard id == scanID else { return }
            self.input = input
            privacyGrants = grants
            status = "Checking signatures…"
            hits = await Task.detached(priority: .utility) {
                StaticThreats.hits(input, blockedExtensionIDs: xprotect?.blockedExtensionIDs ?? [])
                    + PrivacyAccess.hits(grants ?? [], resolve: PrivacyAccess.resolveApp, signature: CodeSignature.check)
            }.value
            guard id == scanID else { return }
            await classify()
            await scanWithXProtect(xprotect, input: input, id: id, flag: flag)
            guard id == scanID else { return }
            status = ""
            fraction = nil
            withAnimation(.smooth) { phase = .ready }
            onScanFinished?()
        }
    }

    private func scanWithXProtect(_ xprotect: XProtectInfo?, input: AppScanInput, id: Int, flag: CancelFlag) async {
        guard id == scanID else { return }
        guard let xprotect else {
            rules = .unavailable("XProtect isn't installed or readable")
            return
        }
        status = "Loading XProtect rules…"
        let loaded = await Task.detached(priority: .utility) { Result { try YaraEngine(ruleFiles: xprotect.ruleFiles) } }.value
        guard id == scanID else { return }
        let engine: YaraEngine
        switch loaded {
        case .success(let value):
            engine = value
            rules = .loaded(version: xprotect.version, updated: xprotect.updated)
        case .failure(let error):
            if let yaraError = error as? YaraError, case .compile(let messages) = yaraError {
                rules = .unavailable("they didn't compile (\(messages.first ?? "unknown error"))")
            } else {
                rules = .unavailable("the rule engine didn't start")
            }
            return
        }

        let targets = await Task.detached(priority: .utility) {
            ThreatScanner.targets(apps: input.apps, launchItems: input.launchItems, looseFolders: ThreatScanner.looseFolders())
        }.value
        let counter = ScanCounter()
        let poller = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(150))
                guard let self, id == self.scanID else { return }
                let done = counter.snapshot().done
                self.status = "Scanning \(done.formatted()) of \(targets.count.formatted()) files with XProtect…"
                self.fraction = targets.isEmpty ? nil : Double(done) / Double(targets.count)
            }
        }
        await Task.detached(priority: .utility) {
            ThreatScanner.scan(targets, engine: engine, counter: counter, isCancelled: { flag.isCancelled })
        }.value
        poller.cancel()
        guard id == scanID else { return }
        skippedFiles = counter.snapshot().skipped
        hits += ThreatScanner.hits(for: counter.results, apps: input.apps, launchItems: input.launchItems)
        await classify()
    }
```

- [ ] **Step 6: Show the footnote and the privacy list in `Sources/Views/AppsView.swift`**

In `AppsHeader`, directly after `Text(apps.summary)…` (before the `if apps.phase == .scanning` progress bar), add:

```swift
                if let note = apps.rulesNote {
                    Text(note)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.tertiary)
                }
```

In `AppsView`, after the `ForEach(FindingGroup.allCases) { … }` block, add:

```swift
                if let grants = apps.privacyGrants, !grants.isEmpty {
                    PrivacySection(grants: grants)
                }
```

At the end of the file, add:

```swift
struct PrivacySection: View {
    let grants: [PrivacyGrant]

    var body: some View {
        let clients = Dictionary(grouping: grants, by: \.client).sorted { $0.key < $1.key }
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Label("Can watch you", systemImage: "eye.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text("Apps allowed to see your screen, keystrokes, camera or microphone.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                Spacer()
                Menu("Open Settings") {
                    ForEach(PrivacyGrant.Service.allCases) { service in
                        Button(service.title, systemImage: service.symbol) { PrivacyAccess.openSettings(for: service) }
                    }
                }
                .fixedSize()
            }
            .padding(.leading, 6)

            VStack(spacing: 2) {
                ForEach(clients, id: \.key) { entry in
                    let location = entry.value.first.flatMap { PrivacyAccess.location(of: $0, resolve: PrivacyAccess.resolveApp) }
                    HStack(spacing: 10) {
                        Image(nsImage: IconCache.icon(for: location ?? "/")).resizable().frame(width: 20, height: 20)
                        Text(location.map { FileManager.default.displayName(atPath: $0) } ?? entry.key)
                            .font(.system(size: 12.5))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if location == nil {
                            Text("No longer installed").font(.system(size: 11)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        ForEach(entry.value.map(\.service).sorted { $0.rawValue < $1.rawValue }) { service in
                            Image(systemName: service.symbol)
                                .foregroundStyle(service.canWatch ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                                .help(service.title)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 5)
                }
            }
            .padding(.vertical, 10)
            .glassEffect(.regular, in: .rect(cornerRadius: 22))
        }
    }
}
```

- [ ] **Step 7: Run everything and look at the tab**

Run: `scripts/test.sh`
Expected: `** TEST SUCCEEDED **`, every suite `✔`.
Run: `scripts/build.sh && scripts/snapshot-apps.sh`
Expected: both PNGs written. In `apps-01-scanning.png` the header shows a progress bar with "Scanning N of M files with XProtect…" or an earlier stage; in `apps-02-ready.png` the header footnote reads "Uses Apple's XProtect rules v5363, updated … No scanner catches everything." (version may be newer), and — if Strata has Full Disk Access — the **Can watch you** list appears. Any Threats rows show a red/orange/yellow verdict badge and a reason.

- [ ] **Step 8: Commit**

```bash
git add Sources/Model/Threats/ThreatScanner.swift Sources/Model/Apps/AppsModel.swift Sources/Views/AppsView.swift Tests/ThreatScannerTests.swift
git commit -m "Scan apps and launch items with Apple's XProtect rules"
```

---

### Task 13: Docs and final verification

**Files:**
- Modify: `README.md`

**Interfaces:** none.

- [ ] **Step 1: Update `README.md`**

In **What it does**, after the "Recommends cleanups" bullet, add:

```markdown
- **Checks your apps.** A third tab lists apps you haven't opened in months, Apple's optional apps and sound libraries, files and launch items left behind by apps you already deleted, and everything that starts on its own. It also runs **Apple's own XProtect malware rules** (read from your Mac, never bundled) over app binaries and launch items, flags known adware, suspicious launch items and untrusted programs allowed to watch your screen or keystrokes. No scanner catches everything, so treat it as a second opinion.
```

In **How it works**, add rows:

```markdown
| Apps & Threats | [`Sources/Model/Apps`](Sources/Model/Apps), [`Sources/Model/Threats`](Sources/Model/Threats) | Pure scanners (apps, launch items, support files, signatures, XProtect, privacy grants) feed one `Classifier`. XProtect's YARA rules run through a vendored libyara on 4 threads. |
| Admin removals | [`PrivilegedRemover.swift`](Sources/Model/Apps/PrivilegedRemover.swift) | Root-owned items you can't remove are retried after one password prompt per batch: allowlisted locations only, every path single-quoted and re-validated (`cd -P`) inside the root script, no `chown`. |
```

In **Safety**, add:

```markdown
- Root-owned items (apps installed by a package, launch daemons) ask for your password once per batch. Only root-owned items in `/Applications`, `/Library/Launch*`, `/Library/PrivilegedHelperTools` and a few `/Library` support folders can be touched that way (never anything Apple's), each path is re-checked right before it's removed, and nothing is ever re-owned. Trashed root items land in a "Removed by Strata" folder in your Trash; emptying it asks for your password.
- In Apps & Threats only confirmed threats and dead launch items are pre-selected; running apps can't be selected.
```

In **Getting started**, after the build commands, add:

```markdown
Run the tests with `scripts/test.sh`. libyara is vendored in `Vendor/yara`; `scripts/vendor-yara.sh` re-fetches the pinned release.
```

Replace the **License** section body with:

```markdown
[MIT](LICENSE). Includes [libyara](https://github.com/VirusTotal/yara) 4.5.8, BSD-3-Clause — see [`Vendor/yara/COPYING`](Vendor/yara/COPYING).
```

- [ ] **Step 2: Full verification**

Run: `scripts/test.sh`
Expected: `** TEST SUCCEEDED **`; paste the `Test run with N tests … passed` line in the task report.
Run: `scripts/build.sh && scripts/snapshot-apps.sh`
Expected: `Built build/Strata.app`, both PNGs present; inspect `apps-02-ready.png` once more.
Run: `git status --short`
Expected: only `README.md` modified (nothing under `build/` or `Strata.xcodeproj/` is tracked).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document Apps & Threats"
```

- [ ] **Step 4: Hand the manual admin-prompt check to the user**

This needs a password, so ask the user to run it and report back. It plants a harmless root-owned "leftover" — a launch daemon pointing at a program that doesn't exist, plus a support folder:

```sh
sudo mkdir "/Library/Application Support/com.stratatest.gone"
sudo sh -c 'echo test > "/Library/Application Support/com.stratatest.gone/data"'
sudo defaults write /Library/LaunchDaemons/com.stratatest.gone.plist Label com.stratatest.gone
sudo defaults write /Library/LaunchDaemons/com.stratatest.gone.plist Program /nonexistent/stratatest
sudo chmod 644 /Library/LaunchDaemons/com.stratatest.gone.plist
```

Then in Strata: Apps & Threats → Re-scan. Expected: a **Leftovers** row `com.stratatest.gone` with 2 parts. Tick it, Remove (Move to Trash), wait out the countdown, enter the password once. Expected: both items leave `/Library`, and `ls -lR ~/.Trash/Removed\ by\ Strata.*` shows them (still owned by root, under their original names). Cancel the password prompt on a second attempt to confirm the toast reports the items as not removed.
