import AppKit
import SwiftUI

@MainActor
@Observable
final class AppModel {
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
    enum Phase: Equatable { case idle, scanning, ready }
    enum DeleteMode: String, CaseIterable, Identifiable {
        case trash, permanent
        var id: Self { self }
        var title: String { self == .trash ? "Move to Trash" : "Delete Permanently" }
        var symbol: String { self == .trash ? "trash" : "xmark.bin" }
    }
    enum SelectionState { case none, direct, inherited }

    var tab: Tab = .explore {
        didSet {
            guard tab != oldValue else { return }
            mascot.tabChanged(to: tab, model: self)
            if tab == .apps, apps.phase == .idle { apps.scan() }
        }
    }
    private(set) var phase: Phase = .idle
    private(set) var target: ScanTarget?
    private(set) var progress = ScanSnapshot()
    private(set) var scanStarted = Date()

    private(set) var root: FileNode?
    private(set) var focus: FileNode?
    private(set) var layout: [SunburstSegment] = []
    private(set) var layoutAngles: [ObjectIdentifier: Double] = [:]
    private(set) var transition = SunburstTransition.identity
    private(set) var transitionID = 0
    private(set) var treeVersion = 0

    private(set) var hovered: FileNode?
    private(set) var selection: [FileNode] = []
    private(set) var selectedIDs: Set<ObjectIdentifier> = []
    var deleteMode: DeleteMode = .trash

    var hasFullDiskAccess = FullDiskAccess.isGranted
    private(set) var volume = VolumeInfo.load()
    var showsMascot = true

    let deletion = DeletionController()
    let cleanup = CleanupModel()
    let apps = AppsModel()
    let mascot = MascotController()

    /// Where the sunburst sits in window coordinates, so the mascot knows where food comes from.
    @ObservationIgnored var sunburstFrame: CGRect = .zero
    @ObservationIgnored private var scanner: DiskScanner?
    @ObservationIgnored private var progressTask: Task<Void, Never>?

    init() {
        cleanup.onItemsRemoved = { [weak self] urls in self?.removeFromTree(urls) }
        apps.onItemsRemoved = { [weak self] urls in self?.removeFromTree(urls) }
        apps.onScanFinished = { [weak self] in
            guard let self, tab == .apps else { return }
            let count = apps.threatCount
            if count > 0 {
                mascot.say("Yikes! \(count) suspicious thing\(count == 1 ? "" : "s") moved in. Check the Threats list first.", mood: .excited, duration: 7)
            } else if apps.rulesLoaded {
                mascot.say("No nasties found! \(apps.removableBytes.bytes) of old apps and leftovers you could let me eat.", mood: .happy, duration: 6)
            } else {
                mascot.say("Couldn't run the malware check, but here's what you could remove: \(apps.removableBytes.bytes).", mood: .neutral, duration: 6)
            }
        }
        deletion.onCountdownStarted = { [weak self] job in
            self?.mascot.say("Deleting \(job.totalBytes.bytes) in 5 seconds… press Esc if you change your mind!", mood: .excited, duration: 5)
        }
        deletion.onCancelled = { [weak self] in
            self?.mascot.say("Phew! Nothing was eaten.", mood: .sad, duration: 3)
        }
        deletion.onExecute = { [weak self] job in self?.feedMascot(job) }
        deletion.onTick = { [weak self] in
            guard let self else { return }
            mascot.nibble(progress: deletion.workProgress, freed: deletion.bytesFreedSoFar)
        }
        deletion.onFinished = { [weak self] result in
            guard let self else { return }
            let verb = result.movedToTrash ? "moved to the Trash" : "gone for good"
            var line = "Burp! \(result.freedBytes.bytes) \(verb)."
            if result.failures > 0 { line += " \(result.failures) bit\(result.failures == 1 ? " was" : "s were") too crunchy." }
            mascot.finishMeal(line)
            volume = VolumeInfo.load()
        }
        Task { await cleanup.measureAll() }
        mascot.say("Hi, I'm Nibble! Pick a disk to scan and I'll help you find things to clean up.", mood: .happy, duration: 7)

        // Development hook: STRATA_AUTOSCAN=disk|home|/some/path starts a scan on launch.
        if let auto = ProcessInfo.processInfo.environment["STRATA_AUTOSCAN"] {
            let target: ScanTarget = switch auto {
            case "disk": .disk
            case "home": .home
            default: .folder(URL(fileURLWithPath: auto))
            }
            Task { startScan(target) }
        }
        DevHooks.run(model: self)
    }

    // MARK: Scanning

    func startScan(_ target: ScanTarget) {
        scanner?.cancel()
        progressTask?.cancel()
        self.target = target
        tab = .explore
        progress = ScanSnapshot()
        scanStarted = .now
        clearSelection()
        hovered = nil
        withAnimation(.smooth) { phase = .scanning }
        hasFullDiskAccess = FullDiskAccess.isGranted
        mascot.say(hasFullDiskAccess
            ? "Sniffing through \(target.title)…"
            : "Sniffing through \(target.title)… Psst, grant Full Disk Access so I can see everything.",
            mood: .curious, duration: 6)

        let scanner = DiskScanner(rootPath: target.path)
        self.scanner = scanner
        progressTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(120))
                guard let self, self.scanner === scanner else { return }
                self.progress = scanner.progress.snapshot()
            }
        }
        Task.detached(priority: .userInitiated) { [weak self] in
            let root = await scanner.run()
            guard !scanner.isCancelled else { return }
            await self?.finishScan(root: root, scanner: scanner)
        }
    }

    func rescan() {
        switch tab {
        case .cleanup: Task { await cleanup.measureAll() }
        case .apps: apps.scan()
        case .explore: if let target { startScan(target) }
        }
    }

    func cancelScan() {
        scanner?.cancel()
        scanner = nil
        progressTask?.cancel()
        withAnimation(.smooth) { phase = root == nil ? .idle : .ready }
        mascot.say("Okay, stopping.", mood: .neutral, duration: 2.5)
    }

    private func finishScan(root: FileNode, scanner: DiskScanner) {
        guard self.scanner === scanner else { return }
        progressTask?.cancel()
        progress = scanner.progress.snapshot()
        self.scanner = nil
        volume = VolumeInfo.load()

        root.customTitle = target?.title
        if target == .disk, let volume, volume.used > root.size {
            root.adopt(FileNode(name: "System, snapshots & other volumes", kind: .hidden, size: volume.used - root.size))
            root.finalize()
        }
        self.root = root
        focus = root
        layout = SunburstLayout.build(focus: root)
        layoutAngles = SunburstLayout.midAngles(layout)
        transition = .sweepIn
        transitionID += 1
        treeVersion += 1
        withAnimation(.smooth) { phase = .ready }
        cleanup.updateDerived(from: root)
        mascot.say("Found \(root.size.bytes)! Click a ring to dive in. Tick boxes or ⌘-click to choose what to delete.", mood: .happy, duration: 8)
    }

    // MARK: Navigation

    func zoom(into node: FileNode) {
        guard node.isDirectory, let focus, node !== focus, node.size > 0 else { return }
        setFocus(node, from: focus)
    }

    func zoomOut() {
        guard let focus, let parent = focus.parent else { return }
        setFocus(parent, from: focus)
    }

    func jump(to node: FileNode) {
        guard let focus, node !== focus else { return }
        setFocus(node, from: focus)
    }

    private func setFocus(_ new: FileNode, from old: FileNode) {
        let previous = layout
        if new.isDescendant(of: old) {
            let range = SunburstLayout.angleRange(of: new, within: old)
            transition = SunburstTransition(zoomingInto: range, depth: new.depth(below: old), previous: previous)
        } else if old.isDescendant(of: new) {
            let range = SunburstLayout.angleRange(of: old, within: new)
            transition = SunburstTransition(zoomingOutOf: range, depth: old.depth(below: new), previous: previous)
        } else {
            transition = SunburstTransition(crossfadeFrom: previous)
        }
        focus = new
        hovered = nil
        layout = SunburstLayout.build(focus: new)
        layoutAngles = SunburstLayout.midAngles(layout)
        transitionID += 1
        mascot.hop()
    }

    private func relayout() {
        guard let focus else { return }
        transition = SunburstTransition(crossfadeFrom: layout)
        layout = SunburstLayout.build(focus: focus)
        layoutAngles = SunburstLayout.midAngles(layout)
        transitionID += 1
        treeVersion += 1
    }

    func setHovered(_ node: FileNode?) {
        guard node !== hovered else { return }
        hovered = node
        if let node, let focus { mascot.noticeHover(node, in: focus) }
    }

    // MARK: Selection

    func selectionState(of node: FileNode) -> SelectionState {
        if selectedIDs.contains(node.id) { return .direct }
        var current = node.parent
        while let ancestor = current {
            if selectedIDs.contains(ancestor.id) { return .inherited }
            current = ancestor.parent
        }
        return .none
    }

    func toggleSelection(_ node: FileNode) {
        switch selectionState(of: node) {
        case .direct:
            withAnimation(.snappy) { selection.removeAll { $0 === node } }
            selectedIDs.remove(node.id)
        case .inherited:
            return
        case .none:
            guard node.canDelete else {
                mascot.say("I'm not allowed to eat \(node.displayName), it's important to macOS.", mood: .sad, duration: 4)
                return
            }
            withAnimation(.snappy) {
                selection.removeAll { $0.isDescendant(of: node) }
                selection.append(node)
            }
            selectedIDs = Set(selection.map(\.id))
            mascot.say("Mmm, \(selectedBytes.bytes) of snacks queued up.", mood: .happy, duration: 3.5)
        }
    }

    func clearSelection() {
        withAnimation(.snappy) { selection.removeAll() }
        selectedIDs.removeAll()
    }

    var selectedBytes: Int64 { selection.reduce(0) { $0 + $1.size } }

    // MARK: Deletion

    func requestDeletion() {
        let nodes = selection.filter(\.canDelete)
        guard !nodes.isEmpty, !deletion.isBusy else { return }
        let trash = deleteMode == .trash
        let operations = nodes.map {
            DeletionOperation(label: $0.displayName, kind: trash ? .trash($0.url) : .remove($0.url), estimatedBytes: $0.size)
        }
        let job = DeletionJob(title: trash ? "Moving to Trash" : "Deleting permanently", operations: operations, movesToTrash: trash)
        deletion.schedule(job) { [weak self] result in self?.applyDeletion(nodes: nodes, result: result) }
    }

    func requestCleanup(_ recommendations: [Recommendation]) {
        guard !deletion.isBusy else { return }
        let job = cleanup.job(for: recommendations)
        guard !job.operations.isEmpty else { return }
        deletion.schedule(job) { [weak self] result in
            self?.cleanup.didClean(recommendations, job: job, result: result)
        }
    }

    func requestAppRemoval() {
        guard !deletion.isBusy else { return }
        let job = apps.removalJob(trash: deleteMode == .trash)
        guard !job.operations.isEmpty else { return }
        deletion.schedule(job) { [weak self] result in self?.apps.didRemove(job, result: result) }
    }

    private func applyDeletion(nodes: [FileNode], result: DeletionResult) {
        for (node, outcome) in zip(nodes, result.outcomes) {
            guard let parent = node.parent else { continue }
            let focusAffected = focus === node || (focus?.isDescendant(of: node) ?? false)
            switch outcome {
            case .removed:
                node.detach()
            case .partial:
                let rescanned = DiskScanner(rootPath: node.path).scanSubtree(name: node.name)
                parent.replace(node, with: rescanned)
            case .failed:
                continue
            }
            if focusAffected { focus = parent }
        }
        clearSelection()
        relayout()
        if let root { cleanup.updateDerived(from: root) }
    }

    private func removeFromTree(_ urls: [URL]) {
        guard let root, !urls.isEmpty else { return }
        var changed = false
        for url in urls {
            guard let node = root.descendant(atPath: url.path), node !== root, let parent = node.parent else { continue }
            if focus === node || (focus?.isDescendant(of: node) ?? false) { focus = parent }
            selection.removeAll { $0 === node || $0.isDescendant(of: node) }
            node.detach()
            changed = true
        }
        selectedIDs = Set(selection.map(\.id))
        if changed { relayout() }
    }

    // MARK: Mascot

    /// Sends one morsel per deleted item, flying from where it sits in the chart.
    private func feedMascot(_ job: DeletionJob) {
        var origins: [(CGPoint, Color)] = []
        let frame = sunburstFrame
        if tab == .explore, frame.width > 0 {
            let geometry = SunburstGeometry(size: frame.size, rings: SunburstLayout.rings)
            for node in selection {
                if let segment = layout.first(where: { $0.node === node && !$0.isRemainder }) {
                    let mid = (segment.start + segment.end) / 2
                    let radius = geometry.innerRadius + (CGFloat(segment.depth) + 0.5) * geometry.ringThickness
                    let point = CGPoint(x: frame.minX + geometry.center.x + radius * sin(mid),
                                        y: frame.minY + geometry.center.y - radius * cos(mid))
                    origins.append((point, SunburstPalette.color(mid: mid, ring: Double(segment.depth), kind: node.kind)))
                } else {
                    origins.append((CGPoint(x: frame.midX, y: frame.maxY - 40), .white))
                }
            }
        }
        mascot.feed(origins: origins, count: max(8, min(36, job.operations.count * 4)))
    }
}
