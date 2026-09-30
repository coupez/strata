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
