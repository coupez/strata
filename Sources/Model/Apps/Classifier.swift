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
