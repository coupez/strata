import AppKit
import Foundation

extension Int64 {
    var bytes: String { ByteCountFormatter.string(fromByteCount: self, countStyle: .file) }
}

func percentString(_ part: Int64, of whole: Int64) -> String {
    guard whole > 0 else { return "—" }
    let fraction = Double(part) / Double(whole)
    if fraction > 0, fraction < 0.001 { return "<0.1%" }
    return fraction.formatted(.percent.precision(.fractionLength(fraction < 0.1 ? 1 : 0)))
}

enum Finder {
    static func reveal(_ url: URL) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    static func open(_ url: URL) { NSWorkspace.shared.open(url) }
    static func copyPath(_ path: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(path, forType: .string)
    }
}

enum FullDiskAccess {
    /// The TCC folder is only listable with Full Disk Access.
    static var isGranted: Bool {
        let probes = ["Library/Application Support/com.apple.TCC", "Library/Safari", "Library/Mail"]
            .map { (NSHomeDirectory() as NSString).appendingPathComponent($0) }
        for probe in probes where FileManager.default.fileExists(atPath: probe) {
            return (try? FileManager.default.contentsOfDirectory(atPath: probe)) != nil
        }
        return false
    }

    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}

struct VolumeInfo: Equatable {
    var name: String
    var total: Int64
    var available: Int64
    var used: Int64 { max(0, total - available) }
    var usedFraction: Double { total > 0 ? Double(used) / Double(total) : 0 }

    static func load(path: String = "/") -> VolumeInfo? {
        let keys: Set<URLResourceKey> = [.volumeNameKey, .volumeTotalCapacityKey, .volumeAvailableCapacityKey]
        guard let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: keys),
              let total = values.volumeTotalCapacity else { return nil }
        return VolumeInfo(
            name: values.volumeName ?? "Macintosh HD",
            total: Int64(total),
            available: Int64(values.volumeAvailableCapacity ?? 0)
        )
    }
}

enum ScanTarget: Hashable {
    case disk
    case home
    case folder(URL)

    var path: String {
        switch self {
        case .disk: "/"
        case .home: NSHomeDirectory()
        case .folder(let url): url.path
        }
    }

    var title: String {
        switch self {
        case .disk: VolumeInfo.load()?.name ?? "Macintosh HD"
        case .home: "Home"
        case .folder(let url): url.lastPathComponent
        }
    }

    var symbol: String {
        switch self {
        case .disk: "internaldrive.fill"
        case .home: "house.fill"
        case .folder: "folder.fill"
        }
    }
}
