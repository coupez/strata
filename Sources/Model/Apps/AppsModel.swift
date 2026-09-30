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

    enum RulesState: Equatable {
        case unknown
        case loaded(version: Int, updated: Date?)
        case unavailable(String)
    }

    static let unusedChoices = [30, 90, 180, 365]
    private static let unusedKey = "AppsUnusedDays"

    private(set) var phase: Phase = .idle
    private(set) var status = ""
    /// 0…1 while a measurable step runs; nil means indeterminate.
    private(set) var fraction: Double?
    private(set) var findings: [Finding] = []
    private(set) var selected: Set<String> = []
    private(set) var expanded: Set<String> = []
    private(set) var rules: RulesState = .unknown
    private(set) var skippedFiles = 0
    /// nil without Full Disk Access.
    private(set) var privacyGrants: [PrivacyGrant]?
    var unusedDays: Int = {
        let stored = UserDefaults.standard.object(forKey: AppsModel.unusedKey) as? Int
        return stored.flatMap { AppsModel.unusedChoices.contains($0) ? $0 : nil } ?? 90
    }() {
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
    /// Classification runs can overlap (a threshold change, a removal, hits arriving mid-scan); only the latest may land.
    @ObservationIgnored private var classifyID = 0
    @ObservationIgnored private var cancelFlag: CancelFlag?

    func findings(in group: FindingGroup) -> [Finding] { findings.filter { $0.group == group } }
    var threatCount: Int { findings.filter { $0.group == .threat }.count }
    /// Background items are listed but never counted as reclaimable.
    private var removable: [Finding] { findings.filter { $0.group != .background } }
    var removableBytes: Int64 { removable.reduce(0) { $0 + $1.size } }
    var selectedBytes: Int64 { findings.reduce(0) { selected.contains($1.id) ? $0 + $1.size : $0 } }

    var summary: String {
        switch phase {
        case .idle: "Finds unused apps, bloatware, leftovers and threats."
        case .scanning: status
        case .ready: Self.readySummary(threats: threatCount, removable: removable.count, rulesLoaded: rulesLoaded)
        }
    }

    /// Whether XProtect's rules compiled, so a clean result means something.
    var rulesLoaded: Bool {
        if case .loaded = rules { true } else { false }
    }

    nonisolated static func readySummary(threats: Int, removable: Int, rulesLoaded: Bool) -> String {
        let things = "\(removable) thing\(removable == 1 ? "" : "s") you could remove."
        if threats > 0 { return "\(threats) possible threat\(threats == 1 ? "" : "s") found. Review them first." }
        // Without the malware rules an empty Threats list proves nothing.
        return rulesLoaded ? "No threats found. \(things)" : "Threat check unavailable. \(things)"
    }

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
        cancelFlag?.cancel()
        let flag = CancelFlag()
        cancelFlag = flag
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        let ownID = Bundle.main.bundleIdentifier ?? "com.lucascoupez.strata"
        choices = [:]
        hits = []
        fraction = nil
        skippedFiles = 0
        rules = .unknown
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
                StaticThreats.hits(input, blockedExtensions: xprotect?.blockedExtensions ?? [:])
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

    private func classify() async {
        guard let input else { return }
        classifyID += 1
        let days = unusedDays, hits = hits, id = scanID, call = classifyID
        let result = await Task.detached(priority: .utility) { Classifier.findings(input, unusedAfter: days, hits: hits) }.value
        guard id == scanID, call == classifyID else { return }
        withAnimation(.smooth) {
            findings = result
            selected = Self.selection(for: result, choices: choices)
        }
    }

    func removalJob(trash: Bool) -> DeletionJob {
        // The scan's running flags go stale; check again so a freshly launched app is never removed.
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        let runningPaths = Set((input?.apps ?? []).filter { Classifier.isRunning($0, among: running) }.map(\.path))
        if input != nil, input?.running != running {
            input?.running = running
            Task { await classify() }
        }
        return Self.removalJob(for: findings.filter { selected.contains($0.id) }, trash: trash, uid: getuid(),
                               runningAppPaths: runningPaths)
    }

    func didRemove(_ job: DeletionJob, result: DeletionResult) {
        // A partial or failed removal may still have deleted things, so trust the disk, not the outcome.
        let removed = job.operations.compactMap(\.url).filter { !DirectorySizer.exists($0.path) }
        onItemsRemoved?(removed)
        let gone = Set(removed.map(\.path))
        // Keep the cached scan in step so re-classifying doesn't bring removed things back.
        input?.apps.removeAll { gone.contains($0.path) }
        input?.launchItems.removeAll { gone.contains($0.plist.path) }
        input?.support.removeAll { gone.contains($0.url.path) }
        hits.removeAll { gone.contains($0.primary) }
        Task { await classify() }
    }

    nonisolated static func selection(for findings: [Finding], choices: [String: Bool]) -> Set<String> {
        Set(findings.filter { !$0.isRunning && (choices[$0.id] ?? $0.preselected) }.map(\.id))
    }

    nonisolated static func removalJob(for findings: [Finding], trash: Bool, uid: uid_t,
                                       runningAppPaths: Set<String> = []) -> DeletionJob {
        var operations: [DeletionOperation] = []
        for finding in findings where !finding.isRunning {
            let appIsRunning = finding.parts.contains { $0.kind == .app && runningAppPaths.contains($0.url.path) }
            if appIsRunning { continue }
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
