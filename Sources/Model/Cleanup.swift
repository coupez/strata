import Foundation
import SwiftUI

enum Risk {
    case safe, caution, review

    var label: String {
        switch self {
        case .safe: "Safe"
        case .caution: "Caution"
        case .review: "Review"
        }
    }

    var color: Color {
        switch self {
        case .safe: .green
        case .caution: .orange
        case .review: .pink
        }
    }

    var explanation: String {
        switch self {
        case .safe: "Regenerated automatically when needed."
        case .caution: "Re-downloaded or rebuilt on next use; may take a while."
        case .review: "Could contain things you want to keep. Check before deleting."
        }
    }
}

enum CleanupCategory: String, CaseIterable, Identifiable {
    case system = "System & Apps"
    case developer = "Developer Tools"
    case packages = "Package Managers"
    case containers = "Containers"
    case files = "Large & Forgotten"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .system: "macwindow.on.rectangle"
        case .developer: "hammer.fill"
        case .packages: "shippingbox.fill"
        case .containers: "cube.transparent.fill"
        case .files: "doc.viewfinder.fill"
        }
    }
}

struct CleanupItem: Identifiable {
    let url: URL
    let size: Int64
    var isSelected: Bool
    var id: String { url.path }
    var name: String { url.lastPathComponent }
}

enum MeasureResult {
    case bytes(Int64)
    case notFound
    case unavailable(String)
}

@MainActor
@Observable
final class Recommendation: Identifiable {
    enum Source {
        /// Delete these files/folders.
        case items(@Sendable () -> [URL])
        /// Run a tool that knows how to clean up after itself.
        case command(tool: String, arguments: [String], measure: @Sendable (String) async -> MeasureResult)
        /// Filled in from the latest disk scan.
        case derived
    }

    enum State: Equatable { case measuring, ready, empty, notFound, unavailable(String) }

    let id: String
    let title: String
    let detail: String
    let symbol: String
    let tint: Color
    let category: CleanupCategory
    let risk: Risk
    @ObservationIgnored let source: Source

    var state: State = .measuring
    var items: [CleanupItem] = []
    var commandBytes: Int64 = 0
    var commandPath: String?
    var commandSelected = false
    var isExpanded = false

    init(_ id: String, _ title: String, _ detail: String, symbol: String, tint: Color, category: CleanupCategory, risk: Risk, source: Source) {
        self.id = id
        self.title = title
        self.detail = detail
        self.symbol = symbol
        self.tint = tint
        self.category = category
        self.risk = risk
        self.source = source
        if case .derived = source { state = .empty }
    }

    var isCommand: Bool {
        if case .command = source { return true }
        return false
    }

    var totalBytes: Int64 { isCommand ? commandBytes : items.reduce(0) { $0 + $1.size } }

    var selectedBytes: Int64 {
        guard state == .ready else { return 0 }
        if isCommand { return commandSelected ? commandBytes : 0 }
        return items.reduce(0) { $0 + ($1.isSelected ? $1.size : 0) }
    }

    var selectedCount: Int { items.filter(\.isSelected).count }

    var isSelected: Bool {
        get { isCommand ? commandSelected : (!items.isEmpty && items.allSatisfy(\.isSelected)) }
        set {
            if isCommand {
                commandSelected = newValue
            } else {
                for index in items.indices { items[index].isSelected = newValue }
            }
        }
    }

    var isVisible: Bool {
        switch state {
        case .notFound, .empty: false
        default: true
        }
    }
}

@MainActor
@Observable
final class CleanupModel {
    let recommendations: [Recommendation] = CleanupCatalog.make()
    private(set) var isMeasuring = false
    /// Called with every URL that was removed so the explorer tree can be updated.
    @ObservationIgnored var onItemsRemoved: (([URL]) -> Void)?

    var visible: [Recommendation] { recommendations.filter(\.isVisible) }
    var totalReclaimable: Int64 { visible.reduce(0) { $0 + ($1.state == .ready ? $1.totalBytes : 0) } }
    var selectedBytes: Int64 { visible.reduce(0) { $0 + $1.selectedBytes } }
    var hiddenCount: Int { recommendations.count - visible.count }

    func recommendations(in category: CleanupCategory) -> [Recommendation] {
        visible.filter { $0.category == category }.sorted { $0.totalBytes > $1.totalBytes }
    }

    func measureAll() async {
        guard !isMeasuring else { return }
        isMeasuring = true
        await withTaskGroup(of: Void.self) { group in
            for recommendation in recommendations {
                if case .derived = recommendation.source { continue }
                group.addTask { await self.measure(recommendation) }
            }
        }
        isMeasuring = false
    }

    func measure(_ recommendation: Recommendation) async {
        switch recommendation.source {
        case .items(let resolve):
            recommendation.state = .measuring
            let preselect = recommendation.risk == .safe
            let items = await Task.detached(priority: .utility) {
                resolve()
                    .map { CleanupItem(url: $0, size: DirectorySizer.allocatedSize(atPath: $0.path), isSelected: preselect) }
                    .filter { $0.size > 0 }
                    .sorted { $0.size > $1.size }
            }.value
            withAnimation(.smooth) {
                recommendation.items = items
                recommendation.state = items.isEmpty ? .empty : .ready
            }

        case .command(let tool, _, let measure):
            guard let path = Shell.locate(tool) else {
                recommendation.state = .notFound
                return
            }
            recommendation.state = .measuring
            recommendation.commandPath = path
            let result = await measure(path)
            withAnimation(.smooth) {
                switch result {
                case .bytes(let bytes):
                    recommendation.commandBytes = bytes
                    recommendation.commandSelected = recommendation.risk == .safe
                    recommendation.state = bytes > 0 ? .ready : .empty
                case .notFound:
                    recommendation.state = .notFound
                case .unavailable(let reason):
                    recommendation.state = .unavailable(reason)
                }
            }

        case .derived:
            break
        }
    }

    /// Builds the node_modules and large-file suggestions from a finished scan.
    func updateDerived(from root: FileNode) {
        Task {
            let found = await Task.detached(priority: .utility) { CleanupCatalog.derive(from: root) }.value
            for recommendation in recommendations {
                guard case .derived = recommendation.source else { continue }
                let urls = recommendation.id == "node_modules" ? found.nodeModules : found.largeFiles
                withAnimation(.smooth) {
                    recommendation.items = urls.map { CleanupItem(url: $0.0, size: $0.1, isSelected: false) }
                    recommendation.state = urls.isEmpty ? .empty : .ready
                }
            }
        }
    }

    func job(for selection: [Recommendation]) -> DeletionJob {
        var operations: [DeletionOperation] = []
        for recommendation in selection where recommendation.state == .ready {
            if case .command(_, let arguments, _) = recommendation.source {
                if recommendation.commandSelected, let path = recommendation.commandPath {
                    operations.append(DeletionOperation(label: recommendation.title, kind: .command(executable: path, arguments: arguments), estimatedBytes: recommendation.commandBytes))
                }
            } else {
                for item in recommendation.items where item.isSelected {
                    operations.append(DeletionOperation(label: item.name, kind: .remove(item.url), estimatedBytes: item.size))
                }
            }
        }
        return DeletionJob(title: "Cleaning up", operations: operations, movesToTrash: false)
    }

    func didClean(_ selection: [Recommendation], job: DeletionJob, result: DeletionResult) {
        var removed: [URL] = []
        for (operation, outcome) in zip(job.operations, result.outcomes) {
            guard case .remove(let url) = operation.kind else { continue }
            if case .failed = outcome { continue }
            removed.append(url)
        }
        onItemsRemoved?(removed)
        let removedPaths = Set(removed.map(\.path))
        for recommendation in selection {
            if case .derived = recommendation.source {
                withAnimation(.smooth) {
                    recommendation.items.removeAll { removedPaths.contains($0.url.path) }
                    if recommendation.items.isEmpty { recommendation.state = .empty }
                }
            } else {
                Task { await measure(recommendation) }
            }
        }
    }
}

// MARK: - Catalog

enum CleanupCatalog {
    static let home = NSHomeDirectory()

    static func path(_ relative: String) -> String { (home as NSString).appendingPathComponent(relative) }

    /// Everything inside a folder (the folder itself stays).
    static func contents(_ relative: String, excluding: Set<String> = []) -> @Sendable () -> [URL] {
        let directory = path(relative)
        return {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return [] }
            return names
                .filter { !excluding.contains($0) && $0 != ".DS_Store" }
                .map { URL(fileURLWithPath: directory).appendingPathComponent($0) }
        }
    }

    static func contents(ofEach relatives: [String]) -> @Sendable () -> [URL] {
        let resolvers = relatives.map { contents($0) }
        return { resolvers.flatMap { $0() } }
    }

    /// Whole folders, if they exist.
    static func folders(_ relatives: [String]) -> @Sendable () -> [URL] {
        let paths = relatives.map(path)
        return { paths.filter(DirectorySizer.exists).map { URL(fileURLWithPath: $0) } }
    }

    static func files(in relative: String, extensions: Set<String>) -> @Sendable () -> [URL] {
        let directory = path(relative)
        return {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return [] }
            return names
                .filter { extensions.contains(($0 as NSString).pathExtension.lowercased()) }
                .map { URL(fileURLWithPath: directory).appendingPathComponent($0) }
        }
    }

    static func sizeOf(_ relative: String) -> @Sendable (String) async -> MeasureResult {
        let full = path(relative)
        return { _ in DirectorySizer.exists(full) ? .bytes(DirectorySizer.allocatedSize(atPath: full)) : .notFound }
    }

    static func dockerReclaimable(_ types: Set<String>) -> @Sendable (String) async -> MeasureResult {
        { tool in
            let run = await Shell.run(tool, ["system", "df", "--format", "{{json .}}"], timeout: 25)
            guard run.status == 0 else { return .unavailable("Start Docker to measure") }
            var total: Int64 = 0
            for line in run.output.split(separator: "\n") {
                guard let data = String(line).data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let type = object["Type"] as? String, types.contains(type),
                      let reclaimable = object["Reclaimable"] as? String else { continue }
                total += parseBytes(reclaimable.split(separator: " ").first.map(String.init) ?? "")
            }
            return .bytes(total)
        }
    }

    static func unavailableSimulators() -> @Sendable (String) async -> MeasureResult {
        { tool in
            // Avoid triggering the "install developer tools" prompt on Macs without Xcode.
            guard DirectorySizer.exists(path("Library/Developer/CoreSimulator/Devices")) else { return .notFound }
            let run = await Shell.run(tool, ["simctl", "list", "devices", "unavailable", "-j"], timeout: 30)
            guard run.status == 0,
                  let data = run.output.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let devices = object["devices"] as? [String: [[String: Any]]] else { return .notFound }
            var total: Int64 = 0
            for list in devices.values {
                for device in list {
                    if let dataPath = device["dataPath"] as? String {
                        total += DirectorySizer.allocatedSize(atPath: (dataPath as NSString).deletingLastPathComponent)
                    }
                }
            }
            return .bytes(total)
        }
    }

    static func parseBytes(_ text: String) -> Int64 {
        let number = text.prefix { "0123456789.".contains($0) }
        guard let value = Double(number) else { return 0 }
        let multiplier: Double = switch text.dropFirst(number.count).lowercased() {
        case "kb": 1e3
        case "mb": 1e6
        case "gb": 1e9
        case "tb": 1e12
        default: 1
        }
        return Int64(value * multiplier)
    }

    static func derive(from root: FileNode) -> (nodeModules: [(URL, Int64)], largeFiles: [(URL, Int64)]) {
        var nodeModules: [(URL, Int64)] = []
        var largeFiles: [(URL, Int64)] = []
        var stack = [root]
        while let node = stack.popLast() {
            for child in node.children {
                switch child.kind {
                case .directory:
                    if child.name == "node_modules" {
                        if child.size > 0, child.canDelete { nodeModules.append((child.url, child.size)) }
                    } else {
                        stack.append(child)
                    }
                case .file:
                    if child.size >= 1_000_000_000, child.canDelete { largeFiles.append((child.url, child.size)) }
                default:
                    break
                }
            }
        }
        return (nodeModules.sorted { $0.1 > $1.1 }, largeFiles.sorted { $0.1 > $1.1 })
    }

    @MainActor
    static func make() -> [Recommendation] {
        let coveredCaches: Set<String> = [
            "Homebrew", "pip", "Yarn", "CocoaPods", "go-build", "ms-playwright", "pnpm",
            Bundle.main.bundleIdentifier ?? "com.lucascoupez.strata",
        ]
        let appSupport = "Library/Application Support/"
        return [
            // System & Apps
            Recommendation("caches", "App caches", "Temporary data apps keep in ~/Library/Caches. Quit apps first for best results.",
                           symbol: "internaldrive.fill", tint: .blue, category: .system, risk: .safe,
                           source: .items(contents("Library/Caches", excluding: coveredCaches))),
            Recommendation("logs", "Logs", "Diagnostic logs written by apps and crash reporters.",
                           symbol: "doc.text.fill", tint: .gray, category: .system, risk: .safe,
                           source: .items(contents("Library/Logs"))),
            Recommendation("trash", "Trash", "Items you've already moved to the Trash.",
                           symbol: "trash.fill", tint: .red, category: .system, risk: .safe,
                           source: .items(contents(".Trash"))),
            Recommendation("electron", "Chat, editor & browser caches", "Cache folders from Slack, Discord, VS Code, Spotify, Chrome and friends.",
                           symbol: "bubble.left.and.bubble.right.fill", tint: .purple, category: .system, risk: .safe,
                           source: .items(folders([
                               appSupport + "Slack/Cache", appSupport + "Slack/Service Worker/CacheStorage", appSupport + "Slack/Code Cache",
                               appSupport + "discord/Cache", appSupport + "discord/Code Cache",
                               appSupport + "Code/Cache", appSupport + "Code/CachedData", appSupport + "Code/CachedExtensionVSIXs",
                               appSupport + "Code/Service Worker/CacheStorage",
                               appSupport + "Cursor/Cache", appSupport + "Cursor/CachedData",
                               appSupport + "Spotify/PersistentCache",
                               appSupport + "Google/Chrome/Default/Service Worker/CacheStorage",
                               appSupport + "Microsoft/Teams/Cache",
                           ]))),
            Recommendation("mail", "Mail downloads", "Attachments Mail saved when you opened them.",
                           symbol: "envelope.fill", tint: .cyan, category: .system, risk: .safe,
                           source: .items(contents("Library/Containers/com.apple.mail/Data/Library/Mail Downloads"))),
            Recommendation("backups", "iPhone & iPad backups", "Local device backups. Delete old ones you no longer need.",
                           symbol: "iphone", tint: .indigo, category: .system, risk: .review,
                           source: .items(contents(appSupport + "MobileSync/Backup"))),

            // Developer
            Recommendation("deriveddata", "Xcode DerivedData", "Build products and indexes. Xcode rebuilds them on the next build.",
                           symbol: "hammer.fill", tint: .blue, category: .developer, risk: .safe,
                           source: .items(contents("Library/Developer/Xcode/DerivedData"))),
            Recommendation("simcaches", "Simulator caches", "Dyld and runtime caches for iOS simulators.",
                           symbol: "ipad.and.iphone", tint: .teal, category: .developer, risk: .safe,
                           source: .items(contents("Library/Developer/CoreSimulator/Caches"))),
            Recommendation("simunavailable", "Unavailable simulators", "Simulators for runtimes that are no longer installed.",
                           symbol: "iphone.slash", tint: .orange, category: .developer, risk: .safe,
                           source: .command(tool: "/usr/bin/xcrun", arguments: ["simctl", "delete", "unavailable"], measure: unavailableSimulators())),
            Recommendation("previews", "SwiftUI preview data", "Cached SwiftUI preview simulators.",
                           symbol: "eye.fill", tint: .mint, category: .developer, risk: .safe,
                           source: .items(contents("Library/Developer/Xcode/UserData/Previews"))),
            Recommendation("devicesupport", "Device support files", "Symbols copied from devices you've connected. Re-copied on next connect.",
                           symbol: "cable.connector", tint: .gray, category: .developer, risk: .caution,
                           source: .items(contents(ofEach: [
                               "Library/Developer/Xcode/iOS DeviceSupport", "Library/Developer/Xcode/watchOS DeviceSupport",
                               "Library/Developer/Xcode/tvOS DeviceSupport", "Library/Developer/Xcode/visionOS DeviceSupport",
                           ]))),
            Recommendation("archives", "Xcode archives", "App archives from past releases. Keep ones you may need to re-symbolicate.",
                           symbol: "archivebox.fill", tint: .brown, category: .developer, risk: .review,
                           source: .items(contents("Library/Developer/Xcode/Archives"))),
            Recommendation("playwright", "Playwright browsers", "Browser builds downloaded by Playwright.",
                           symbol: "theatermasks.fill", tint: .green, category: .developer, risk: .caution,
                           source: .items(contents("Library/Caches/ms-playwright"))),
            Recommendation("node_modules", "node_modules folders", "Dependencies of JavaScript projects. Reinstall with npm/pnpm/yarn install.",
                           symbol: "square.stack.3d.up.fill", tint: .green, category: .developer, risk: .caution,
                           source: .derived),

            // Package managers
            Recommendation("brew", "Homebrew", "Old versions and downloads (brew cleanup --prune=all).",
                           symbol: "mug.fill", tint: .orange, category: .packages, risk: .safe,
                           source: .command(tool: "brew", arguments: ["cleanup", "--prune=all", "-s"], measure: sizeOf("Library/Caches/Homebrew"))),
            Recommendation("npm", "npm cache", "Downloaded package tarballs.",
                           symbol: "shippingbox.fill", tint: .red, category: .packages, risk: .safe,
                           source: .items(folders([".npm/_cacache"]))),
            Recommendation("yarn", "Yarn cache", "Yarn's global package cache.",
                           symbol: "shippingbox.fill", tint: .blue, category: .packages, risk: .safe,
                           source: .items(contents("Library/Caches/Yarn"))),
            Recommendation("pnpm", "pnpm store", "Content-addressable package store. Projects re-link on install.",
                           symbol: "shippingbox.fill", tint: .yellow, category: .packages, risk: .caution,
                           source: .items(contents(ofEach: ["Library/pnpm/store", "Library/Caches/pnpm"]))),
            Recommendation("bun", "Bun cache", "Bun's global install cache.",
                           symbol: "shippingbox.fill", tint: .pink, category: .packages, risk: .safe,
                           source: .items(contents(".bun/install/cache"))),
            Recommendation("pip", "pip cache", "Downloaded Python wheels.",
                           symbol: "shippingbox.fill", tint: .yellow, category: .packages, risk: .safe,
                           source: .items(contents("Library/Caches/pip"))),
            Recommendation("uv", "uv cache", "Astral uv's package cache.",
                           symbol: "shippingbox.fill", tint: .purple, category: .packages, risk: .safe,
                           source: .items(contents(".cache/uv"))),
            Recommendation("cocoapods", "CocoaPods cache", "Downloaded pod specs and sources.",
                           symbol: "shippingbox.fill", tint: .red, category: .packages, risk: .safe,
                           source: .items(contents("Library/Caches/CocoaPods"))),
            Recommendation("cargo", "Cargo registry", "Downloaded Rust crates and git checkouts.",
                           symbol: "shippingbox.fill", tint: .orange, category: .packages, risk: .safe,
                           source: .items(folders([".cargo/registry/cache", ".cargo/registry/src", ".cargo/git/checkouts"]))),
            Recommendation("gomod", "Go module cache", "Downloaded Go modules (go clean -modcache).",
                           symbol: "shippingbox.fill", tint: .cyan, category: .packages, risk: .caution,
                           source: .command(tool: "go", arguments: ["clean", "-modcache"], measure: sizeOf("go/pkg/mod"))),
            Recommendation("gobuild", "Go build cache", "Compiled Go packages.",
                           symbol: "shippingbox.fill", tint: .cyan, category: .packages, risk: .safe,
                           source: .items(contents("Library/Caches/go-build"))),
            Recommendation("gradle", "Gradle caches", "Dependencies and build caches for Gradle projects.",
                           symbol: "shippingbox.fill", tint: .green, category: .packages, risk: .caution,
                           source: .items(contents(".gradle/caches"))),
            Recommendation("maven", "Maven repository", "Local Maven artifacts. Re-downloaded on next build.",
                           symbol: "shippingbox.fill", tint: .brown, category: .packages, risk: .caution,
                           source: .items(contents(".m2/repository"))),

            // Containers
            Recommendation("docker", "Docker images, containers & build cache", "Unused images, stopped containers and build cache (docker system prune -a).",
                           symbol: "cube.box.fill", tint: .blue, category: .containers, risk: .caution,
                           source: .command(tool: "docker", arguments: ["system", "prune", "-a", "-f"], measure: dockerReclaimable(["Images", "Containers", "Build Cache"]))),
            Recommendation("dockervolumes", "Docker volumes", "Volumes not used by any container. May hold database data!",
                           symbol: "externaldrive.fill", tint: .indigo, category: .containers, risk: .review,
                           source: .command(tool: "docker", arguments: ["volume", "prune", "-a", "-f"], measure: dockerReclaimable(["Local Volumes"]))),

            // Files
            Recommendation("installers", "Installers in Downloads", "Disk images and packages you probably already installed.",
                           symbol: "arrow.down.app.fill", tint: .teal, category: .files, risk: .review,
                           source: .items(files(in: "Downloads", extensions: ["dmg", "pkg", "mpkg", "xip", "iso"]))),
            Recommendation("largefiles", "Files over 1 GB", "The biggest single files found in your last scan.",
                           symbol: "doc.fill", tint: .pink, category: .files, risk: .review,
                           source: .derived),
        ]
    }
}
