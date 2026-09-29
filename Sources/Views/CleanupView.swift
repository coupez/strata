import SwiftUI

struct CleanupView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let cleanup = model.cleanup
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                CleanupHeader()

                ForEach(CleanupCategory.allCases) { category in
                    let items = cleanup.recommendations(in: category)
                    if !items.isEmpty {
                        VStack(alignment: .leading, spacing: 10) {
                            Label(category.rawValue, systemImage: category.symbol)
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(.secondary)
                                .padding(.leading, 6)
                            GlassEffectContainer(spacing: 10) {
                                VStack(spacing: 10) {
                                    ForEach(items) { RecommendationCard(recommendation: $0) }
                                }
                            }
                        }
                    }
                }

                if cleanup.hiddenCount > 0 && !cleanup.isMeasuring {
                    Label("\(cleanup.hiddenCount) other checks came back clean or don't apply to this Mac.", systemImage: "checkmark.seal")
                        .font(.system(size: 12))
                        .foregroundStyle(.tertiary)
                        .frame(maxWidth: .infinity)
                }
                if model.root == nil {
                    Label("Run a scan in Explore to also find node_modules folders and huge files.", systemImage: "lightbulb")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(24)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity)
        }
        .scrollContentBackground(.hidden)
    }
}

struct CleanupHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let cleanup = model.cleanup
        HStack(alignment: .center, spacing: 24) {
            ZStack {
                Circle()
                    .fill(AngularGradient(colors: [.cyan, .purple, .pink, .orange, .cyan], center: .center))
                    .blur(radius: 16)
                    .opacity(0.55)
                Image(systemName: "sparkles")
                    .font(.system(size: 38, weight: .semibold))
                    .foregroundStyle(.white)
                    .symbolEffect(.pulse, isActive: cleanup.isMeasuring)
            }
            .frame(width: 84, height: 84)

            VStack(alignment: .leading, spacing: 4) {
                Text("Reclaim up to")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.secondary)
                Text(cleanup.totalReclaimable.bytes)
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                    .animation(.snappy, value: cleanup.totalReclaimable)
                Text(cleanup.isMeasuring ? "Measuring caches and tools…" : "Caches, build products, and other things your Mac can live without.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 10) {
                Button {
                    model.requestCleanup(cleanup.visible.filter { $0.selectedBytes > 0 })
                } label: {
                    Label("Clean \(cleanup.selectedBytes.bytes)", systemImage: "wand.and.stars")
                        .fontWeight(.semibold)
                        .contentTransition(.numericText())
                }
                .buttonStyle(.glassProminent)
                .tint(.pink)
                .controlSize(.extraLarge)
                .disabled(cleanup.selectedBytes == 0 || model.deletion.isBusy)

                Button {
                    Task { await cleanup.measureAll() }
                } label: {
                    Label("Re-check", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.glass)
                .disabled(cleanup.isMeasuring)
            }
        }
        .padding(24)
        .glassEffect(.regular, in: .rect(cornerRadius: 30))
    }
}

struct RecommendationCard: View {
    @Environment(AppModel.self) private var model
    @Bindable var recommendation: Recommendation

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 14) {
                Toggle("", isOn: $recommendation.isSelected)
                    .toggleStyle(.checkbox)
                    .labelsHidden()
                    .disabled(recommendation.state != .ready)

                ZStack {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .fill(recommendation.tint.gradient)
                    Image(systemName: recommendation.symbol)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.white)
                }
                .frame(width: 38, height: 38)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(recommendation.title).font(.system(size: 14, weight: .semibold))
                        Text(recommendation.risk.label)
                            .font(.system(size: 10, weight: .bold))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(recommendation.risk.color.opacity(0.18)))
                            .foregroundStyle(recommendation.risk.color)
                            .help(recommendation.risk.explanation)
                    }
                    Text(recommendation.detail)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 12)

                trailing

                if !recommendation.items.isEmpty {
                    Button {
                        withAnimation(.smooth) { recommendation.isExpanded.toggle() }
                    } label: {
                        Image(systemName: "chevron.down")
                            .font(.system(size: 12, weight: .semibold))
                            .rotationEffect(.degrees(recommendation.isExpanded ? 180 : 0))
                            .frame(width: 24, height: 24)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(16)

            if recommendation.isExpanded {
                Divider().opacity(0.4).padding(.horizontal, 16)
                LazyVStack(spacing: 2) {
                    ForEach($recommendation.items.prefix(80)) { $item in
                        HStack(spacing: 10) {
                            Toggle("", isOn: $item.isSelected).toggleStyle(.checkbox).labelsHidden()
                            Image(nsImage: IconCache.icon(for: item.url.path)).resizable().frame(width: 18, height: 18)
                            Text(item.name).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(item.size.bytes)
                                .font(.system(size: 11.5, weight: .medium, design: .rounded))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                            Button { Finder.reveal(item.url) } label: { Image(systemName: "magnifyingglass") }
                                .buttonStyle(.plain)
                                .foregroundStyle(.tertiary)
                                .help("Reveal in Finder")
                        }
                        .padding(.horizontal, 20)
                        .padding(.vertical, 4)
                    }
                    if recommendation.items.count > 80 {
                        Text("and \(recommendation.items.count - 80) more")
                            .font(.system(size: 11))
                            .foregroundStyle(.tertiary)
                            .padding(6)
                    }
                }
                .padding(.vertical, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .glassEffect(.regular, in: .rect(cornerRadius: 22))
    }

    @ViewBuilder
    private var trailing: some View {
        switch recommendation.state {
        case .measuring:
            ProgressView().controlSize(.small)
        case .unavailable(let reason):
            Text(reason).font(.system(size: 12)).foregroundStyle(.secondary)
        case .ready:
            VStack(alignment: .trailing, spacing: 2) {
                Text(recommendation.totalBytes.bytes)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .monospacedDigit()
                if !recommendation.isCommand, recommendation.items.count > 1 {
                    Text("\(recommendation.selectedCount) of \(recommendation.items.count) selected")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                }
            }
            Button("Clean") {
                if !recommendation.isCommand, recommendation.selectedCount == 0 { recommendation.isSelected = true }
                if recommendation.isCommand { recommendation.commandSelected = true }
                model.requestCleanup([recommendation])
            }
            .buttonStyle(.glass)
            .disabled(model.deletion.isBusy)
        case .empty, .notFound:
            EmptyView()
        }
    }
}
