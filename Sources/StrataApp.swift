import AppKit
import SwiftUI

@main
struct StrataApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup("Strata") {
            ContentView()
                .environment(model)
                .frame(minWidth: 1100, minHeight: 720)
        }
        .defaultSize(width: 1380, height: 880)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Scan Startup Disk") { model.startScan(.disk) }
                    .keyboardShortcut("1")
                Button("Scan Home Folder") { model.startScan(.home) }
                    .keyboardShortcut("2")
                Button("Scan Folder…") { if let url = chooseFolder() { model.startScan(.folder(url)) } }
                    .keyboardShortcut("o")
                Divider()
                Button("Rescan") { model.rescan() }
                    .keyboardShortcut("r")
            }
            CommandGroup(after: .toolbar) {
                Toggle("Show Nibble", isOn: $model.showsMascot)
                    .keyboardShortcut("m", modifiers: [.command, .shift])
            }
        }
    }
}

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 220, ideal: 240, max: 300)
        } detail: {
            ZStack {
                AmbientBackground()
                switch model.tab {
                case .explore: ExploreView()
                case .cleanup: CleanupView()
                case .apps: AppsView()
                }
            }
            .overlay(alignment: .top) { ResultToast() }
            .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
            .navigationTitle(model.tab.title)
            .navigationSubtitle(subtitle)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { model.rescan() } label: {
                        Label("Rescan", systemImage: "arrow.clockwise")
                    }
                    .help(model.tab == .explore ? "Scan again" : model.tab == .apps ? "Scan apps again" : "Re-check recommendations")
                    .disabled((model.tab == .explore && (model.target == nil || model.phase == .scanning))
                              || (model.tab == .apps && model.apps.phase == .scanning))
                }
            }
        }
        .overlay { CountdownOverlay() }
        .overlay {
            if model.showsMascot { MascotOverlay() }
        }
        .onAppear { model.mascot.startTracking() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.hasFullDiskAccess = FullDiskAccess.isGranted
        }
    }

    private var subtitle: String {
        switch model.tab {
        case .explore:
            let _ = model.treeVersion
            guard let root = model.root, model.phase == .ready else { return "" }
            return "\(root.displayName) · \(root.size.bytes)"
        case .cleanup:
            return "\(model.cleanup.totalReclaimable.bytes) reclaimable"
        case .apps:
            return model.apps.phase == .ready ? "\(model.apps.removableBytes.bytes) removable" : ""
        }
    }
}

struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let selection = Binding<AppModel.Tab?>(get: { model.tab }, set: { if let tab = $0 { model.tab = tab } })
        List(selection: selection) {
            Section("Storage") {
                Label("Explore", systemImage: "circle.circle.fill")
                    .tag(AppModel.Tab.explore)
                Label {
                    HStack {
                        Text("Cleanup")
                        Spacer()
                        if model.cleanup.totalReclaimable > 0 {
                            Text(model.cleanup.totalReclaimable.bytes)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                } icon: {
                    Image(systemName: "sparkles")
                }
                .tag(AppModel.Tab.cleanup)
            }

            Section("Health") {
                Label {
                    HStack {
                        Text("Apps & Threats")
                        Spacer()
                        if model.apps.threatCount > 0 {
                            Text("\(model.apps.threatCount)")
                                .font(.system(size: 11, weight: .bold))
                                .padding(.horizontal, 6)
                                .background(Capsule().fill(.red.opacity(0.2)))
                                .foregroundStyle(.red)
                        }
                    }
                } icon: {
                    Image(systemName: "shield.lefthalf.filled")
                }
                .tag(AppModel.Tab.apps)
            }

            Section("Scan") {
                LocationButton(title: ScanTarget.disk.title, symbol: ScanTarget.disk.symbol, isCurrent: model.target == .disk) {
                    model.startScan(.disk)
                }
                LocationButton(title: "Home", symbol: ScanTarget.home.symbol, isCurrent: model.target == .home) {
                    model.startScan(.home)
                }
                if case .folder(let url) = model.target {
                    LocationButton(title: url.lastPathComponent, symbol: "folder.fill", isCurrent: true) {
                        model.startScan(.folder(url))
                    }
                }
                LocationButton(title: "Choose Folder…", symbol: "folder.badge.plus", isCurrent: false) {
                    if let url = chooseFolder() { model.startScan(.folder(url)) }
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 10) {
                if !model.hasFullDiskAccess {
                    Button { FullDiskAccess.openSettings() } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "lock.shield.fill").foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 1) {
                                Text("Grant Full Disk Access").font(.system(size: 11.5, weight: .semibold))
                                Text("To scan protected folders").font(.system(size: 10.5)).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        .padding(10)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 14))
                }
                if let volume = model.volume {
                    DiskUsageCard(volume: volume)
                }
            }
            .padding(12)
        }
    }
}

struct LocationButton: View {
    let title: String
    let symbol: String
    let isCurrent: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                if isCurrent {
                    Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

struct DiskUsageCard: View {
    let volume: VolumeInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Image(systemName: "internaldrive.fill").foregroundStyle(.secondary)
                Text(volume.name).font(.system(size: 12, weight: .semibold))
                Spacer()
            }
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(.primary.opacity(0.1))
                    Capsule()
                        .fill(LinearGradient(colors: [.cyan, .purple, .pink], startPoint: .leading, endPoint: .trailing))
                        .frame(width: proxy.size.width * volume.usedFraction)
                }
            }
            .frame(height: 6)
            Text("\(volume.available.bytes) available of \(volume.total.bytes)")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .padding(12)
        .glassEffect(.regular, in: .rect(cornerRadius: 14))
    }
}
