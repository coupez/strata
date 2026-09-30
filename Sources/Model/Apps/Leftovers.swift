import Foundation

struct LeftoverGroup: Hashable, Sendable {
    let key: String
    var entries: [SupportEntry]
    var launchItems: [LaunchItem]
}

/// Files and launch items of apps that are gone. Deliberately conservative: anything from a
/// vendor that still has an installed app or a working launch item is left alone.
enum Leftovers {
    private static func isApple(_ id: String) -> Bool { id.lowercased().hasPrefix("com.apple.") }

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
            guard let id = entry.bundleID, !isApple(id), !IDs.owns(ownID, id) else { continue }
            let vendor = IDs.vendor(id)
            guard !installedVendors.contains(vendor), !liveVendors.contains(vendor),
                  !runningIDs.contains(where: { IDs.owns($0, id) }) else { continue }
            add(IDs.product(id).lowercased(), entry: entry)
        }
        for item in launchItems where item.isOrphaned && !isApple(item.label) {
            add(SupportFiles.bundleID(fromName: item.label).map { IDs.product($0).lowercased() } ?? item.label, item: item)
        }
        return groups.values.sorted { $0.key < $1.key }
    }
}
