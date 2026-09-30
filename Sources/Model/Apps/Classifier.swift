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
        let garageBandInstalled = input.apps.contains { $0.bundleID == Bloatware.garageBandID }
        // Logic and MainStage install the same content, so it's only bloat once neither is left.
        let contentConsumerInstalled = input.apps.contains { Bloatware.soundLibraryConsumerIDs.contains($0.bundleID) }
        var soundsAttached = false

        var supportByApp: [String: [SupportEntry]] = [:]
        for entry in input.support {
            if let owner = SupportFiles.owner(of: entry, among: input.apps) { supportByApp[owner.path, default: []].append(entry) }
        }
        // Orphaned items are leftovers even when their app is installed; each path belongs to one finding.
        var launchByApp: [String: [LaunchItem]] = [:]
        for item in input.launchItems where !item.isOrphaned {
            if let owner = owner(of: item, among: input.apps) { launchByApp[owner.path, default: []].append(item) }
        }

        var findings: [Finding] = []
        for app in input.apps where app.bundleID != input.ownID {
            let threatened = hits.contains { $0.primary == app.path || $0.primary.hasPrefix(app.path + "/") }
            let bloat = Bloatware.isBloatware(app, signature: signature)
            let running = isRunning(app, among: input.running)
            let unused = !running && isUnused(app, before: cutoff)
            guard threatened || bloat || unused else { continue }
            let appSignature = signature(app.path)
            // Apple-signed system apps are never flagged, except the optional ones we list as bloatware.
            if appSignature.kind == .apple, !bloat { continue }

            var parts = [FindingPart(url: app.url, size: app.size, kind: .app)]
            parts += (supportByApp[app.path] ?? []).map { FindingPart(url: $0.url, size: size($0.url), kind: .support) }
            parts += (launchByApp[app.path] ?? []).map { launchPart($0, size: size) }
            if bloat, app.bundleID == Bloatware.garageBandID, !contentConsumerInstalled, !soundsAttached {
                soundsAttached = true
                parts += input.soundLibraries.map { FindingPart(url: $0, size: size($0), kind: .file) }
            }

            var reasons = [usage(of: app, now: input.now)]
            if bloat { reasons.insert("Optional Apple app", at: 0) }
            if !appSignature.isTrusted { reasons.append(appSignature.summary) }

            findings.append(Finding(id: "app:" + app.path, group: bloat ? .bloatware : (unused ? .unused : .threat),
                                    title: app.name, reasons: reasons, iconPath: app.path, parts: parts,
                                    risk: bloat ? .caution : .review, lastUsed: app.lastUsed, isRunning: running))
        }

        if !garageBandInstalled, !contentConsumerInstalled, !input.soundLibraries.isEmpty {
            findings.append(Finding(id: "bloat:sounds", group: .bloatware, title: "GarageBand & Logic sound library",
                                    reasons: ["Loops and instruments used by GarageBand, Logic and MainStage"], iconPath: nil,
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
            // The key is lowercased for grouping; show the name as the app wrote it.
            let title = group.entries.first?.bundleID ?? group.launchItems.first?.label ?? group.key
            findings.append(Finding(id: "leftover:" + group.key, group: .leftover, title: title, reasons: reasons,
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
        if let id = item.associatedBundleID, let app = IDs.bestOwner(of: id, among: apps) { return app }
        return IDs.bestOwner(of: item.label, among: apps)
    }

    /// An app counts as running when it or one of its helpers is.
    static func isRunning(_ app: InstalledApp, among running: Set<String>) -> Bool {
        running.contains(app.bundleID) || app.nestedBundleIDs.contains { running.contains($0) }
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

    /// Folds threat hits into one finding per hit: the one that owns the primary path, or a new one.
    /// The hit's other paths move out of whatever lower-priority finding held them.
    static func merge(_ hits: [ThreatHit], into findings: inout [Finding], size: (URL) -> Int64) {
        for hit in hits where !hit.paths.isEmpty {
            let target: Int
            if let index = findings.firstIndex(where: { $0.contains(hit.primary) }) {
                target = index
                findings[target].group = .threat
                findings[target].verdict = max(findings[target].verdict ?? hit.verdict, hit.verdict)
                if !findings[target].reasons.contains(hit.reason) { findings[target].reasons.insert(hit.reason, at: 0) }
            } else {
                findings.append(Finding(id: "threat:" + hit.primary, group: .threat, verdict: hit.verdict, title: hit.title,
                                        reasons: [hit.reason], iconPath: hit.primary.hasSuffix(".app") ? hit.primary : nil,
                                        parts: [], risk: .review))
                target = findings.count - 1
            }
            findings[target].risk = findings[target].verdict == .adware ? .caution : .review

            for path in hit.paths where !findings[target].contains(path) {
                var moved: FindingPart?
                for index in findings.indices where index != target {
                    guard let part = findings[index].parts.first(where: { path == $0.url.path || path.hasPrefix($0.url.path + "/") }) else { continue }
                    findings[index].parts.removeAll { $0.url == part.url }
                    moved = part
                    break
                }
                let url = URL(fileURLWithPath: path)
                findings[target].parts.append(moved ?? FindingPart(url: url, size: size(url), kind: .file))
            }
            findings.removeAll { $0.parts.isEmpty }
        }
    }

    private static func launchPart(_ item: LaunchItem, size: (URL) -> Int64) -> FindingPart {
        FindingPart(url: item.plist, size: size(item.plist), kind: .launchItem(label: item.label, domain: item.domain))
    }
}
