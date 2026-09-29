import AppKit
import SwiftUI

struct ExploreView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        switch model.phase {
        case .idle: WelcomeView()
        case .scanning: ScanningView()
        case .ready: ExplorerContent()
        }
    }
}

struct ExplorerContent: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(spacing: 14) {
                BreadcrumbBar()
                SunburstView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.bottom, model.selection.isEmpty ? 0 : 64)
            }
            .overlay(alignment: .bottom) {
                if !model.selection.isEmpty {
                    SelectionTray()
                        .transition(.move(edge: .bottom).combined(with: .opacity).combined(with: .scale(scale: 0.9)))
                }
            }
            ItemListPanel()
                .frame(width: 350)
        }
        .padding(18)
        .animation(.spring(duration: 0.45, bounce: 0.2), value: model.selection.isEmpty)
    }
}

// MARK: - Header

struct BreadcrumbBar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let _ = model.treeVersion
        HStack(spacing: 12) {
            Button { model.zoomOut() } label: {
                Image(systemName: "chevron.left").font(.system(size: 13, weight: .semibold)).frame(width: 18, height: 18)
            }
            .buttonStyle(.glass)
            .buttonBorderShape(.circle)
            .disabled(model.focus?.parent == nil)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    let chain = model.focus?.ancestry ?? []
                    ForEach(Array(chain.enumerated()), id: \.element.id) { index, node in
                        if index > 0 {
                            Image(systemName: "chevron.compact.right").foregroundStyle(.tertiary)
                        }
                        Button { model.jump(to: node) } label: {
                            HStack(spacing: 5) {
                                if index == 0 { Image(systemName: model.target?.symbol ?? "internaldrive.fill") }
                                Text(node.displayName).lineLimit(1)
                            }
                            .font(.system(size: 12.5, weight: index == chain.count - 1 ? .semibold : .regular))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .contentShape(Capsule())
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(index == chain.count - 1 ? .primary : .secondary)
                    }
                }
                .padding(.horizontal, 10)
            }
            .frame(height: 36)
            .glassEffect(.regular, in: .capsule)

            if let volume = model.volume, model.target == .disk {
                VolumeCapsule(volume: volume)
            }
        }
    }
}

struct VolumeCapsule: View {
    let volume: VolumeInfo

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "internaldrive").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text("\(volume.available.bytes) free of \(volume.total.bytes)")
                    .font(.system(size: 11, weight: .medium))
                    .monospacedDigit()
                GeometryReader { proxy in
                    ZStack(alignment: .leading) {
                        Capsule().fill(.quaternary)
                        Capsule()
                            .fill(LinearGradient(colors: [.cyan, .purple, .pink], startPoint: .leading, endPoint: .trailing))
                            .frame(width: proxy.size.width * volume.usedFraction)
                    }
                }
                .frame(height: 5)
            }
            .frame(width: 150)
        }
        .padding(.horizontal, 14)
        .frame(height: 36)
        .glassEffect(.regular, in: .capsule)
    }
}

// MARK: - List

struct ItemListPanel: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let _ = model.treeVersion
        VStack(alignment: .leading, spacing: 0) {
            if let focus = model.focus {
                VStack(alignment: .leading, spacing: 4) {
                    Text(focus.displayName)
                        .font(.system(size: 17, weight: .semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    HStack(spacing: 6) {
                        Text(focus.size.bytes).monospacedDigit()
                        Text("·")
                        Text("\(focus.itemCount.formatted()) files")
                        if focus.isInaccessible {
                            Label("No access", systemImage: "lock.fill").foregroundStyle(.orange)
                        }
                    }
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 18)
                .padding(.top, 16)
                .padding(.bottom, 12)

                Divider().opacity(0.5)

                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(focus.children) { child in
                            ItemRow(node: child, parentSize: focus.size, color: rowColor(for: child))
                        }
                        if focus.children.isEmpty {
                            ContentUnavailableView("Empty", systemImage: "tray", description: Text(focus.isInaccessible ? "Strata couldn't read this folder." : "Nothing in here."))
                                .padding(.top, 40)
                        }
                    }
                    .padding(8)
                }
                .scrollContentBackground(.hidden)
            }
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .glassEffect(.regular, in: .rect(cornerRadius: 26))
    }

    private func rowColor(for node: FileNode) -> Color {
        guard let angle = model.layoutAngles[node.id] else { return SunburstPalette.color(mid: 0, ring: 0, kind: .aggregate) }
        return SunburstPalette.color(mid: angle, ring: 0, kind: node.kind)
    }
}

struct ItemRow: View {
    @Environment(AppModel.self) private var model
    let node: FileNode
    let parentSize: Int64
    let color: Color

    var body: some View {
        let state = model.selectionState(of: node)
        let isHovered = model.hovered === node
        let fraction = parentSize > 0 ? Double(node.size) / Double(parentSize) : 0

        HStack(spacing: 10) {
            Toggle("", isOn: Binding(get: { state != .none }, set: { _ in model.toggleSelection(node) }))
                .toggleStyle(.checkbox)
                .labelsHidden()
                .disabled(!node.canDelete || state == .inherited)
                .opacity(node.isRealItem ? 1 : 0)

            NodeIcon(node: node)
                .frame(width: 24, height: 24)

            VStack(alignment: .leading, spacing: 4) {
                Text(node.displayName)
                    .font(.system(size: 12.5, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                GeometryReader { proxy in
                    ZStack(alignment: .leading) {
                        Capsule().fill(.primary.opacity(0.06))
                        Capsule()
                            .fill(color.gradient)
                            .frame(width: max(3, proxy.size.width * fraction))
                    }
                }
                .frame(height: 4)
            }

            VStack(alignment: .trailing, spacing: 2) {
                Text(node.size.bytes)
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                Text(percentString(node.size, of: parentSize))
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
            .frame(width: 70, alignment: .trailing)

            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(.tertiary)
                .opacity(node.isDirectory ? 1 : 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(background(state: state, hovered: isHovered))
        }
        .contentShape(Rectangle())
        .onHover { inside in
            if inside { model.setHovered(node) } else if model.hovered === node { model.setHovered(nil) }
        }
        .onTapGesture {
            if node.isDirectory { model.zoom(into: node) }
        }
        .contextMenu { NodeMenu(node: node) }
    }

    private func background(state: AppModel.SelectionState, hovered: Bool) -> Color {
        switch state {
        case .direct: return Color.red.opacity(hovered ? 0.26 : 0.18)
        case .inherited: return Color.red.opacity(0.1)
        case .none: return hovered ? Color.primary.opacity(0.08) : .clear
        }
    }
}

struct NodeIcon: View {
    let node: FileNode

    var body: some View {
        switch node.kind {
        case .aggregate:
            Image(systemName: "square.stack.3d.up.fill").font(.system(size: 15)).foregroundStyle(.secondary)
        case .hidden:
            Image(systemName: "lock.fill").font(.system(size: 15)).foregroundStyle(.secondary)
        default:
            Image(nsImage: IconCache.icon(for: node.path)).resizable().interpolation(.high)
        }
    }
}

@MainActor
enum IconCache {
    private static let cache = NSCache<NSString, NSImage>()

    static func icon(for path: String) -> NSImage {
        if let cached = cache.object(forKey: path as NSString) { return cached }
        let image = NSWorkspace.shared.icon(forFile: path)
        cache.setObject(image, forKey: path as NSString)
        return image
    }
}

struct NodeMenu: View {
    @Environment(AppModel.self) private var model
    let node: FileNode

    var body: some View {
        if node.isRealItem {
            Button("Reveal in Finder", systemImage: "folder") { Finder.reveal(node.url) }
            Button("Open", systemImage: "arrow.up.forward.app") { Finder.open(node.url) }
            Button("Copy Path", systemImage: "doc.on.doc") { Finder.copyPath(node.path) }
            Divider()
            if node.isDirectory {
                Button("Zoom In", systemImage: "plus.magnifyingglass") { model.zoom(into: node) }
            }
            switch model.selectionState(of: node) {
            case .direct:
                Button("Deselect", systemImage: "minus.circle") { model.toggleSelection(node) }
            case .none:
                Button("Select for Deletion", systemImage: "checkmark.circle") { model.toggleSelection(node) }
                    .disabled(!node.canDelete)
            case .inherited:
                EmptyView()
            }
        }
    }
}

// MARK: - Selection tray

struct SelectionTray: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(.red.gradient).frame(width: 34, height: 34)
                Text("\(model.selection.count)")
                    .font(.system(size: 14, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(model.selectedBytes.bytes)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                Text(model.selection.count == 1 ? "1 item selected" : "\(model.selection.count) items selected")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(model.selection.prefix(12)) { node in
                        HStack(spacing: 5) {
                            NodeIcon(node: node).frame(width: 14, height: 14)
                            Text(node.displayName).lineLimit(1).frame(maxWidth: 140)
                            Button { model.toggleSelection(node) } label: {
                                Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                        }
                        .font(.system(size: 11.5))
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(Capsule().fill(.primary.opacity(0.07)))
                    }
                    if model.selection.count > 12 {
                        Text("+\((model.selection.count - 12).formatted()) more")
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 6)
                    }
                }
            }
            .frame(maxWidth: 320)

            Picker("", selection: $model.deleteMode) {
                ForEach(AppModel.DeleteMode.allCases) { mode in
                    Label(mode.title, systemImage: mode.symbol).tag(mode)
                }
            }
            .labelsHidden()
            .fixedSize()

            Button("Clear") { model.clearSelection() }
                .buttonStyle(.glass)

            Button { model.requestDeletion() } label: {
                Label("Delete", systemImage: "trash.fill").fontWeight(.semibold)
            }
            .buttonStyle(.glassProminent)
            .tint(.red)
            .keyboardShortcut(.delete, modifiers: .command)
            .disabled(model.deletion.isBusy)
        }
        .controlSize(.large)
        .padding(.leading, 12)
        .padding(.trailing, 14)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: .capsule)
    }
}

// MARK: - Welcome & scanning

struct WelcomeView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 30) {
            StrataGlyph().frame(width: 150, height: 150)
            VStack(spacing: 8) {
                Text("Strata")
                    .font(.system(size: 46, weight: .bold, design: .rounded))
                Text("See what's filling your disk, layer by layer.")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
            GlassEffectContainer(spacing: 18) {
                HStack(spacing: 18) {
                    TargetCard(target: .disk, subtitle: model.volume.map { "\($0.used.bytes) used of \($0.total.bytes)" } ?? "Entire startup disk")
                    TargetCard(target: .home, subtitle: "Your user folder")
                    ChooseFolderCard()
                }
            }
            if !model.hasFullDiskAccess {
                FullDiskAccessBanner()
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct TargetCard: View {
    @Environment(AppModel.self) private var model
    let target: ScanTarget
    let subtitle: String

    var body: some View {
        Button { model.startScan(target) } label: {
            CardLabel(symbol: target.symbol, title: target == .disk ? "Scan \(target.title)" : "Scan \(target.title)", subtitle: subtitle)
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 28))
    }
}

struct ChooseFolderCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Button {
            if let url = chooseFolder() { model.startScan(.folder(url)) }
        } label: {
            CardLabel(symbol: "folder.badge.gearshape", title: "Choose Folder…", subtitle: "Any folder or drive")
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 28))
    }
}

@MainActor
func chooseFolder() -> URL? {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = false
    panel.prompt = "Scan"
    return panel.runModal() == .OK ? panel.url : nil
}

struct CardLabel: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 38, weight: .regular))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(height: 46)
            Text(title).font(.system(size: 15, weight: .semibold))
            Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(width: 200, height: 170)
        .contentShape(Rectangle())
    }
}

struct FullDiskAccessBanner: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 24))
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Full Disk Access recommended").font(.system(size: 13, weight: .semibold))
                Text("Without it, protected folders like Mail, Safari and other apps' containers are skipped.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Button("Open Settings") { FullDiskAccess.openSettings() }
                .buttonStyle(.glass)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .glassEffect(.regular.tint(.orange.opacity(0.15)), in: .rect(cornerRadius: 20))
        .frame(maxWidth: 640)
    }
}

struct ScanningView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let progress = model.progress
        let estimate: Double? = {
            guard model.target == .disk, let used = model.volume?.used, used > 0 else { return nil }
            return min(0.99, Double(progress.bytes) / Double(used))
        }()

        VStack(spacing: 26) {
            ScanRing(fraction: estimate).frame(width: 170, height: 170)

            VStack(spacing: 6) {
                Text("Scanning \(model.target?.title ?? "")…")
                    .font(.system(size: 22, weight: .semibold, design: .rounded))
                Text(progress.currentPath)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 440)
            }

            HStack(spacing: 34) {
                StatView(value: progress.files.formatted(), label: "Files")
                StatView(value: progress.directories.formatted(), label: "Folders")
                StatView(value: progress.bytes.bytes, label: "Found")
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    StatView(value: Duration.seconds(context.date.timeIntervalSince(model.scanStarted)).formatted(.time(pattern: .minuteSecond)), label: "Elapsed")
                }
            }

            Button("Cancel Scan") { model.cancelScan() }
                .buttonStyle(.glass)
                .controlSize(.large)
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 44)
        .padding(.vertical, 36)
        .glassEffect(.regular, in: .rect(cornerRadius: 36))
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct StatView: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 3) {
            Text(value)
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .monospacedDigit()
                .contentTransition(.numericText())
                .animation(.snappy, value: value)
            Text(label.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
                .tracking(0.8)
        }
        .frame(minWidth: 80)
    }
}

struct ScanRing: View {
    let fraction: Double?

    var body: some View {
        TimelineView(.animation) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            ZStack {
                ForEach(0 ..< 3) { index in
                    let inset = CGFloat(index) * 22
                    Circle()
                        .trim(from: 0, to: 0.3 + 0.12 * Double(index))
                        .stroke(
                            AngularGradient(colors: [.cyan, .purple, .pink, .orange, .cyan], center: .center),
                            style: StrokeStyle(lineWidth: 12, lineCap: .round)
                        )
                        .rotationEffect(.radians(t * (1.1 - Double(index) * 0.3) * (index.isMultiple(of: 2) ? 1 : -1)))
                        .padding(inset)
                        .opacity(1 - Double(index) * 0.2)
                }
                if let fraction {
                    Text(fraction.formatted(.percent.precision(.fractionLength(0))))
                        .font(.system(size: 26, weight: .bold, design: .rounded))
                        .monospacedDigit()
                }
            }
        }
    }
}
