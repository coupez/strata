# Apps & Threats — design

**Date:** 2026-09-30
**Status:** Approved in conversation, awaiting spec review

## Goal

Add a third section to Strata that finds software the user can remove to reclaim space or
improve safety: malware, spyware, adware, bloatware, unused apps, and leftovers of apps that
are already gone. Every finding shows how much space it takes and can be removed through the
existing countdown-and-delete flow.

### Decisions made with the user

- It is a **new sidebar tab**, not extra Cleanup categories.
- Threat detection runs **Apple's XProtect YARA rules** through a bundled YARA engine, plus a
  curated adware list and heuristics.
- Root-owned items are removed after **one admin-password prompt per removal batch**.
- libyara is **vendored as C source** and built by XcodeGen as a static library.

### Non-goals (v1)

Chrome/Firefox extension scanning, configuration-profile checks, real-time protection,
a quarantine vault, automatic rule updates (Apple updates XProtect itself).

## User experience

- Sidebar gets a new section **Health** with one item, **Apps & Threats**
  (`shield.lefthalf.filled`). `AppModel.Tab` gains `.apps`.
- The first time the tab is opened the scan starts automatically. The toolbar *Rescan*
  button re-runs it while the tab is active (same as Cleanup's re-check).
- Header (glass card, same shape as `CleanupHeader`):
  - Summary: "2 threats · 41.3 GB removable" (or "No threats found" in green).
  - Progress while scanning: phase label ("Reading apps…", "Checking signatures…",
    "Scanning 312 of 1,480 files with XProtect…") and a progress bar.
  - Footnote: "Uses Apple's XProtect rules v5363, updated 29 Sep. No scanner catches
    everything." — or "XProtect rules unavailable: <reason>" when they can't be loaded.
  - Buttons: **Remove <selected bytes>** (prominent, pink) and an "Unused for" picker
    (30 / 90 / 180 / 365 days, default 90, stored in `@AppStorage`).
- Groups below, each hidden when empty, in this order:
  1. **Threats** — red. Each row: name, verdict badge (Malicious / Adware / Suspicious),
     the reason in one line ("Matches XProtect rule MACOS.ADLOAD.B", "Unsigned program
     launched at login from a hidden folder"), path, size.
  2. **Unused apps** — app icon, name, "Last opened 7 months ago", total size
     (bundle + support files), expandable to list the individual support folders.
  3. **Bloatware** — same row style, "Last opened …" or "Never opened".
  4. **Leftovers** — support folders and launch items of apps that are no longer installed,
     grouped by bundle ID ("com.microsoft.EdgeUpdater — 3 items, 412 MB").
  5. **Background items** — informational list of every non-Apple launch agent/daemon with
     its owner app, signer, and whether it runs at login. Items can be selected for removal
     but nothing is pre-selected.
  6. **Can watch you** (only with Full Disk Access) — apps granted Screen Recording, Input
     Monitoring, Accessibility, Camera or Microphone. Informational; a button opens the
     matching System Settings privacy pane. Suspicious ones are *also* listed under Threats.
- Every row has a checkbox, a Reveal-in-Finder button, and a risk badge reusing `Risk`
  (Safe / Caution / Review). Pre-selection rules are in the table below.
- A running app shows a "Running" badge; its checkbox is disabled with the help text
  "Quit it to remove".
- Without Full Disk Access, show the existing `FullDiskAccessBanner` style notice at the
  top: some leftovers and the privacy check are skipped.
- Nibble: "Sniffing through your apps…" on start; on finish either "All clear! …" or
  "Found N nasties hiding in …" (mood `.excited`), plus the usual eating animation on
  removal via `DeletionController`.

## What is detected

| Group | Rule | Risk | Pre-selected |
|---|---|---|---|
| Threat · Malicious | File matches an XProtect YARA rule; or a Safari extension is in XProtect's `ExtensionBlacklist` | review* | yes |
| Threat · Adware | App, launch item or support folder matches a `KnownThreats` indicator | caution | yes |
| Threat · Suspicious | See heuristics below | review | no |
| Unused app | Last used (Spotlight `kMDItemLastUsedDate`) older than the threshold; or never used and added (`kMDItemDateAdded`) before the threshold | review | no |
| Bloatware | App/content on the `Bloatware` list and present | caution | no |
| Leftover · support files | Folder/file named as a reverse-DNS bundle ID that no installed app owns | review | no |
| Leftover · launch item | Launch agent/daemon whose program does not exist | safe | yes |
| Background item | Any other non-Apple launch item | review | no |

\* Malicious items use the red "Malicious" verdict badge instead of the `Risk` badge.

Each app, launch item or folder appears in exactly one group, by priority:
Threat > Leftover > Bloatware > Unused > Background.

### Suspicious heuristics

A launch item or app is *Suspicious* when any of these holds (reasons are shown, several
can combine):

- Its program is **unsigned or ad-hoc signed** and it is persistent (launch item).
- Its program lives in a **hidden path component** (`/.foo/`), `/tmp`, `/private/tmp`,
  `/private/var/tmp` or `/Users/Shared`.
- The launch item's program is an **interpreter running a script from one of those
  locations** (`/bin/sh`, `bash`, `zsh`, `python3`, `osascript`, `node` with a script
  argument in a suspicious location).
- An app **fails Gatekeeper** (`SecAssessment`, same as `spctl --assess`) and is not
  signed by a Developer ID.
- A privacy grant (Screen Recording, Input Monitoring, Accessibility) belongs to a client
  that is **unsigned, ad-hoc signed, or no longer on disk**.

Apple-signed items (anchor apple) are never flagged.

## Architecture

```
Sources/Model/Apps/
  AppInventory.swift      installed apps: bundle, id, version, size, last used, support files
  SupportFiles.swift      maps bundle IDs ↔ ~/Library (and /Library) support locations
  LaunchItems.swift       parse LaunchAgents/LaunchDaemons plists, resolve program
  CodeSignature.swift     SecStaticCode: signed?, ad-hoc?, team ID, Apple?, notarized?, Gatekeeper
  Leftovers.swift         orphaned support files + orphaned launch items
  Bloatware.swift         curated optional Apple apps + content libraries
  PrivilegedRemover.swift allowlisted, quoted, one-prompt elevated trash/remove/bootout
  AppsModel.swift         @Observable state for the tab, scan orchestration, selection → DeletionJob
Sources/Model/Threats/
  XProtectRules.swift     find newest XProtect bundle, version, date, rule files, blocklists
  YaraEngine.swift        Swift wrapper around libyara (compile once, scan file, thread-safe)
  KnownThreats.swift      curated adware/PUP indicators
  PrivacyAccess.swift     read TCC.db (user + system) for surveillance-capable grants
  ThreatScanner.swift     gather targets, run YARA + indicators + heuristics → [Finding]
Sources/Views/AppsView.swift   header, groups, rows
Vendor/yara/                   libyara sources, module map, config
Tests/                         StrataTests (Swift Testing)
```

### Shared types

```swift
struct Finding: Identifiable {
    enum Group { case threat, unused, bloatware, leftover, background }
    enum Verdict { case malicious, adware, suspicious }   // threats only
    let id: String                 // stable: group + primary path
    let group: Group
    let verdict: Verdict?
    let title: String              // "Adload", "Keynote", "com.microsoft.EdgeUpdater"
    let reason: String             // one line shown under the title
    let icon: URL?                 // app bundle for IconCache, else nil
    let parts: [FindingPart]       // what gets removed
    let risk: Risk
    var isSelected: Bool
    var lastUsed: Date?            // unused/bloatware
    var isRunning: Bool
    var size: Int64 { parts.reduce(0) { $0 + $1.size } }
}

struct FindingPart: Identifiable, Hashable {
    enum Kind { case appBundle, supportFile, launchItem(domain: LaunchDomain, label: String), file }
    let url: URL
    let size: Int64
    let kind: Kind
}
```

`AppsModel` owns `findings: [Finding]`, the scan phase/progress, `xprotect: XProtectRules.Info?`,
`privacyGrants: [PrivacyGrant]`, and exposes `findings(in:)`, `selectedBytes`,
`removableBytes`, `threatCount`. It is created by `AppModel` next to `cleanup` and uses the
same `onItemsRemoved` callback so the Explore tree stays in sync.

### Scan pipeline (`AppsModel.scan()`)

Runs detached at `.utility` priority, reporting progress into a locked box that the UI
samples every 150 ms (same pattern as `DeletionProgressBox`).

1. **Inventory** — enumerate `.app` bundles in `/Applications` and `~/Applications`
   (plus one level of subfolders, e.g. `/Applications/Utilities`, vendor folders). For each:
   bundle ID, name, version, `DirectorySizer.allocatedSize`, Spotlight last-used and
   date-added via `MDItemCreate`/`MDItemCopyAttribute`, running state via
   `NSWorkspace.runningApplications`. Also collect bundle IDs of nested apps/helpers so
   helpers don't look like leftovers.
2. **Support files** — for each installed bundle ID, find its folders in the support
   locations (below). Attach them to the app as parts.
3. **Launch items** — parse every plist in `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
   `/Library/LaunchDaemons`. Resolve the program (`Program` or `ProgramArguments[0]`,
   following `BundleProgram` relative to its owning app). Owner app = the installed app whose
   bundle contains the program, or whose bundle ID is a prefix of the label.
4. **Signatures** — `CodeSignature.check` for every launch-item program and every app
   (static check, no network; cached by path + mtime for the session).
5. **Classify** — unused, bloatware, leftovers, background items, adware (known list),
   suspicious (heuristics).
6. **XProtect** — compile rules once, scan the YARA targets with 4 workers, add Malicious
   findings. Merge with an existing finding for the same app/launch item instead of
   duplicating (the app moves to Threats).
7. **Privacy** — when Full Disk Access is granted, read grants; flag suspicious ones.

Steps 1–5 are fast (seconds). Step 6 dominates; the UI shows findings from 1–5 as soon as
they're ready and adds threats as they arrive.

### Support locations

User: `~/Library/{Application Support, Caches, Containers, Preferences (<id>.plist and
<id>.*.plist), Saved Application State (<id>.savedState), HTTPStorages, WebKit, Logs,
Cookies (<id>.binarycookies), LaunchAgents}`. System (read-only discovery, elevated removal):
`/Library/{Application Support, Caches, Preferences, LaunchAgents, LaunchDaemons,
PrivilegedHelperTools}`.

Matching is by **bundle ID only** (exact, or the item name starts with `<id>.`), never by
display name — names collide too easily. `Application Support/<App Name>` folders are
attached to an installed app only when the app's name matches exactly, and are *never*
reported as leftovers.

### Leftover rules

An entry in a support location is a leftover when all hold:

- Its name parses as a reverse-DNS ID (≥ 3 dot-separated components, first component in
  a known TLD set or 2–3 letters: `com`, `org`, `net`, `io`, `dev`, `app`, `co`, country codes).
- Its ID is not `com.apple.*`, not Strata's own ID.
- No installed bundle ID (apps and nested bundles) equals it, is a prefix of it, or has it
  as a prefix. Team-ID-prefixed IDs (`ABCDE12345.com.foo`) strip the team prefix first.
- No running process has that bundle ID.
- It is not referenced by an existing launch item whose program exists.
- Its size is > 0.

Grouped by ID; one finding per ID.

### Bloatware list

Apple apps in `/Applications`, identified by bundle ID *and* Apple signature:
GarageBand (`com.apple.garageband10`), iMovie (`com.apple.iMovieApp`), Keynote
(`com.apple.iWork.Keynote`), Pages (`com.apple.iWork.Pages`), Numbers
(`com.apple.iWork.Numbers`). Content libraries (only when present):
`/Library/Application Support/GarageBand`, `/Library/Application Support/Logic`,
`/Library/Audio/Apple Loops`, `/Library/Audio/Impulse Responses/Apple` — attached to
GarageBand's finding when GarageBand is installed, otherwise their own finding
"GarageBand & Logic sound library". If Logic Pro is installed, the content libraries are
not offered (Logic needs them).

### Known threats list

`KnownThreats.indicators: [Indicator]`, each with a family name, kind (adware / PUP /
spyware) and matchers on bundle ID prefix, launch-item label prefix, or path glob. Seeded
conservatively with well-documented families (e.g. MacKeeper `com.mackeeper.`, `com.zeobit.`;
Advanced Mac Cleaner `com.pcv.`; Genieo `com.genieo.`; InstallMac `com.installmac.`;
VSearch `com.vsearch.`; Mughthesec/Adload/Pirrit label patterns). The list is plain data in
one file so it is easy to review and extend; each entry cites a public write-up in a comment.

### XProtect rules

`XProtectRules.locate()` checks `/var/protected/xprotect/XProtect.bundle` and
`/Library/Apple/System/Library/CoreServices/XProtect.bundle`, reads each `Info.plist`
version, and picks the higher. It returns the version, the rule files' modification date,
`XProtect.yara` and `XPScripts.yr` paths, and the parsed `ExtensionBlacklist` from
`XProtect.meta.plist`. Rules are read from disk at scan time and never bundled with Strata.

### YARA engine

- **Vendored libyara 4.5.x** (BSD-3-Clause) in `Vendor/yara/`: `libyara/` core, the `hash`
  module only (built with CommonCrypto; `HASH_MODULE`, `HAVE_COMMONCRYPTO_COMMONCRYPTO_H`),
  no OpenSSL, no magic/cuckoo/dotnet/dex modules. A `module.modulemap` exposes it as a
  Clang module `yara`. `Vendor/yara/LICENSE` and `Vendor/yara/VERSION` record provenance.
- **XcodeGen:** new `yara` target (`type: library.static`, `platform: macOS`, C sources,
  header search paths, preprocessor defines). `Strata` depends on it and sets
  `SWIFT_INCLUDE_PATHS` to the module map directory.
- **`YaraEngine`** (Swift, `final class`, `@unchecked Sendable`):
  - `static func initialize()` — `yr_initialize` once per process.
  - `init(ruleFiles: [URL]) throws` — `yr_compiler_create`, add each file with its own
    namespace, collect compiler errors, `yr_compiler_get_rules`. Throws
    `YaraError.compile([String])`.
  - `func scan(file: URL, timeout: Int = 10) -> [YaraMatch]` — `yr_rules_scan_file` with
    `SCAN_FLAGS_FAST_MODE`, collecting matched rule identifiers and the `description` meta.
    Safe to call from several threads (libyara allows concurrent scans on shared rules;
    at most 4 concurrent calls, below `YR_MAX_THREADS`).
  - `deinit` destroys rules.
- **Targets:** Mach-O files (checked by magic bytes) in each app's `Contents/MacOS`, and in
  nested bundles under `Contents/{Library/LoginItems, Library/LaunchServices, Helpers,
  XPCServices, PlugIns}` (not `Frameworks`); every launch-item program and script argument;
  executable files in `~/Downloads` (top level and `.app` bundles there), `/Users/Shared`,
  `/tmp`, `/private/var/tmp`. Skip files > 256 MB. Scripts (shebang) are scanned too since
  `XPScripts.yr` targets them.
- A match's family name is the rule's `description` meta (e.g. `MACOS.ADLOAD.B`), shown
  as "Adload (XProtect: MACOS.ADLOAD.B)".

### Privacy grants

`PrivacyAccess.load()` opens `~/Library/Application Support/com.apple.TCC/TCC.db` and
`/Library/Application Support/com.apple.TCC/TCC.db` read-only with SQLite3 (requires Full
Disk Access; otherwise returns `nil`), selects `client, client_type, service, auth_value`
for services `kTCCServiceScreenCapture`, `kTCCServiceListenEvent`,
`kTCCServiceAccessibility`, `kTCCServiceCamera`, `kTCCServiceMicrophone` where
`auth_value = 2` (allowed). Clients are bundle IDs (resolved via
`NSWorkspace.urlForApplication(withBundleIdentifier:)`) or paths. Query failures (schema
changes) degrade to "unavailable", never crash.

### Removal

`AppsModel.job(for:)` turns selected findings into a `DeletionJob`:

- Launch items first: a new `DeletionOperation.Kind.bootout(domain:, plist: URL)` runs
  `launchctl bootout gui/<uid> <plist>` (user agents) — failures are ignored because the
  item may not be loaded — then the plist is trashed/removed like any other part.
- Every part becomes `.trash(url)` or `.remove(url)` according to the Explore delete mode
  (Trash by default).
- `Deleter.performAll` is unchanged for normal items. After the pool finishes, operations
  that failed with a permission error (`EACCES`, `EPERM`, `NSFileWriteNoPermissionError`)
  or that target system domains (`/Library/LaunchDaemons`, `/Library/LaunchAgents`,
  `PrivilegedHelperTools`) are retried in **one** `PrivilegedRemover.run` call.
- **`PrivilegedRemover`**:
  - `static func isAllowed(_ path: String) -> Bool` — standardized path must be inside
    `/Applications/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`,
    `/Library/PrivilegedHelperTools/`, `/Library/Application Support/`, `/Library/Caches/`,
    `/Library/Preferences/`, `/Library/Audio/Apple Loops/`,
    `/Library/Audio/Impulse Responses/`, or the user's home; must not equal any of those
    roots; must not contain `..` after standardization; must not be a symlink escaping them.
  - `static func script(for operations: [ElevatedOperation], user: String, uid: uid_t) -> String`
    — builds a `/bin/sh` script: `launchctl bootout system <plist>` for daemons (ignoring
    errors), then per item either `mv <path> /Users/<user>/.Trash/<unique name>` followed
    by `chown -R <user>` (trash mode) or `rm -rf <path>` (permanent). Every argument is
    single-quoted with `'` → `'\''`. Pure function, unit tested.
  - `static func run(...) async -> [DeletionOutcome]` — executes via `NSAppleScript`
    `do shell script "<script>" with administrator privileges`, where the whole script is
    passed as one AppleScript string (escape `\` and `"`). The script prints one status
    line per item so outcomes map back. User cancel → those items `.failed("Cancelled")`.
  - Refuses (without prompting) if any path fails `isAllowed`.
- **App Management:** if a move out of `/Applications` fails with `EPERM` both normally and
  elevated, the result toast says "macOS blocked removing apps. Allow Strata in Privacy &
  Security → App Management" with a button that opens that pane.
- After removal the affected findings are removed or re-measured, `onItemsRemoved` updates
  the Explore tree, and the volume info refreshes (existing `onFinished` path).

## Error handling

| Situation | Behaviour |
|---|---|
| No Full Disk Access | Banner; skip privacy grants and unreadable support folders; everything else runs |
| XProtect bundle missing / rules fail to compile | Header footnote shows the reason; YARA step skipped; other checks run |
| One file can't be read or times out | Skipped silently, counted in "N files couldn't be scanned" footnote |
| Spotlight has no data for an app | Not listed as unused |
| Admin prompt cancelled | Those items fail with "Cancelled"; others already done stay done |
| Scan started while another is running | The old one is cancelled (same as disk scans) |

## Testing

New `StrataTests` unit-test target (Swift Testing, `@testable import Strata`), run with
`xcodebuild test`. Tests use temporary directories as fake homes, so all path-based units
take their root directories as parameters (defaulting to the real ones).

- `LaunchItemsTests` — parses `Program`, `ProgramArguments`, `BundleProgram`, `RunAtLoad`,
  `KeepAlive`; missing program detection.
- `LeftoversTests` — reverse-DNS parsing, prefix ownership, team-ID stripping, Apple and
  self exclusion, running-process exclusion.
- `KnownThreatsTests` — indicators match/don't match sample IDs, labels and paths.
- `SuspiciousTests` — hidden-path / tmp / interpreter-script heuristics on sample launch items.
- `PrivilegedRemoverTests` — allowlist accepts/rejects (roots, `..`, `/System`, `/usr`,
  symlink escape), shell quoting of paths with spaces, quotes, `$`, backticks, newlines;
  generated script shape.
- `YaraEngineTests` — compile a tiny rule, match a fixture file, no match on another,
  compile error surfaces messages; compile the **real** XProtect rules when present
  (guards libyara compatibility with Apple's rule syntax).
- `XProtectRulesTests` — picks the higher version given two fake bundles.

Manual verification (documented in the plan): build with `scripts/build.sh`, open the tab,
check findings against this Mac; use `STRATA_SNAPSHOT_DIR` snapshots for the tab; run one
elevated removal on a harmless fixture (a copy of a small app placed in `/Applications`
with `sudo chown root`) — done by the user, since it needs a password.

## Milestones

1. **Apps** — tab, inventory, support files, launch items, signatures, unused, bloatware,
   leftovers, background items, removal including elevated removal, tests for those units.
2. **Threats** — vendored libyara + `YaraEngine`, XProtect rules, known threats,
   suspicious heuristics, privacy grants, Threats and Can-watch-you groups, their tests.

Each milestone ends with a green build, passing tests, and a snapshot of the tab.

## Open risks

- **libyara vs. Apple's rule syntax** — Apple may use syntax newer than libyara 4.5.
  Mitigated by the real-rules test, which is the first task of milestone 2; if it fails we
  revisit YARA-X before building on it.
- **App Management TCC** may block removing app bundles even with admin rights; handled by
  the guidance toast, verified manually.
- **Leftover false positives** — mitigated by bundle-ID-only matching, Review risk, and no
  pre-selection.
