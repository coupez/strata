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
        case .ready:
            threatCount > 0
                ? "\(threatCount) possible threat\(threatCount == 1 ? "" : "s") found. Review them first."
                : "No threats found. \(removable.count) thing\(removable.count == 1 ? "" : "s") you could remove."
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
