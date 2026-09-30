import SwiftUI

struct AppsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let apps = model.apps
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                AppsHeader()

                if !model.hasFullDiskAccess {
                    FullDiskAccessBanner(message: "Without Full Disk Access, some leftovers and the privacy check are skipped.")
                        .frame(maxWidth: .infinity)
                }

                ForEach(FindingGroup.allCases) { group in
                    let items = apps.findings(in: group)
                    if !items.isEmpty {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Label(group.title, systemImage: group.symbol)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundStyle(group == .threat ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                                Text(group.caption)
                                    .font(.system(size: 11.5))
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                            .padding(.leading, 6)
                            GlassEffectContainer(spacing: 10) {
                                VStack(spacing: 10) {
                                    ForEach(items) { FindingRow(finding: $0) }
                                }
                            }
                        }
                    }
                }

                if let grants = apps.privacyGrants, !grants.isEmpty {
                    PrivacySection(grants: grants)
                }

                if apps.phase == .ready, apps.findings.isEmpty {
                    Label("Nothing to remove. Your apps look tidy.", systemImage: "checkmark.seal")
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

struct AppsHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        @Bindable var apps = model.apps
        HStack(alignment: .center, spacing: 24) {
            ZStack {
                Circle()
                    .fill(AngularGradient(colors: [.green, .cyan, .purple, .pink, .green], center: .center))
                    .blur(radius: 16)
                    .opacity(0.55)
                Image(systemName: apps.threatCount > 0 ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                    .font(.system(size: 38, weight: .semibold))
                    .foregroundStyle(.white)
                    .symbolEffect(.pulse, isActive: apps.phase == .scanning)
            }
            .frame(width: 84, height: 84)

            VStack(alignment: .leading, spacing: 4) {
                Text(apps.threatCount > 0 ? "Threats found" : "Removable")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(apps.threatCount > 0 ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                Text(apps.removableBytes.bytes)
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                    .animation(.snappy, value: apps.removableBytes)
                Text(apps.summary)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                if let note = apps.rulesNote {
                    Text(note)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.tertiary)
                }
                if apps.phase == .scanning {
                    ProgressView(value: apps.fraction)
                        .progressViewStyle(.linear)
                        .frame(maxWidth: 260)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 10) {
                Button { model.requestAppRemoval() } label: {
                    Label(apps.selected.isEmpty ? "Remove" : "Remove \(apps.selectedBytes.bytes)", systemImage: "trash.fill")
                        .fontWeight(.semibold)
                        .contentTransition(.numericText())
                }
                .buttonStyle(.glassProminent)
                .tint(.pink)
                .controlSize(.extraLarge)
                .disabled(apps.selected.isEmpty || model.deletion.isBusy || apps.phase == .scanning)

                HStack(spacing: 8) {
                    Picker("", selection: $model.deleteMode) {
                        ForEach(AppModel.DeleteMode.allCases) { mode in
                            Label(mode.title, systemImage: mode.symbol).tag(mode)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Picker("Unused after", selection: $apps.unusedDays) {
                        ForEach(AppsModel.unusedChoices, id: \.self) { Text("\($0) days").tag($0) }
                    }
                    .fixedSize()
                    .disabled(apps.phase == .scanning)
                    .help("How long an app must go unopened to count as unused")
                }

                // A scan mid-removal would replace the findings the removal is about to report back on.
                Button { apps.scan() } label: { Label("Re-scan", systemImage: "arrow.clockwise") }
                    .buttonStyle(.glass)
                    .disabled(apps.phase == .scanning || model.deletion.isBusy)
            }
        }
        .padding(24)
        .glassEffect(.regular, in: .rect(cornerRadius: 30))
    }
}

struct FindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: Finding

    var body: some View {
        let apps = model.apps
        let isExpanded = apps.expanded.contains(finding.id)
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 14) {
                Toggle("", isOn: Binding(get: { apps.selected.contains(finding.id) }, set: { apps.setSelected(finding, $0) }))
                    .toggleStyle(.checkbox)
                    .labelsHidden()
                    .disabled(finding.isRunning)
                    .help(finding.isRunning ? "Quit it to remove" : "")

                icon.frame(width: 38, height: 38)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(finding.title)
                            .font(.system(size: 14, weight: .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        tag(finding.verdict?.label ?? finding.risk.label, color: finding.verdict?.color ?? finding.risk.color)
                            .help(finding.verdict == nil ? finding.risk.explanation : "")
                        if finding.isRunning { tag("Running", color: .gray) }
                    }
                    Text(finding.reasons.joined(separator: " · "))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 12)

                Text(finding.size.bytes)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .monospacedDigit()

                Button {
                    withAnimation(.smooth) { apps.toggleExpanded(finding) }
                } label: {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 12, weight: .semibold))
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        .frame(width: 24, height: 24)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .padding(16)

            if isExpanded {
                Divider().opacity(0.4).padding(.horizontal, 16)
                VStack(spacing: 2) {
                    ForEach(finding.parts) { part in
                        HStack(spacing: 10) {
                            Image(nsImage: IconCache.icon(for: part.url.path)).resizable().frame(width: 18, height: 18)
                            Text(part.url.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                                .font(.system(size: 12))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Text(part.size.bytes)
                                .font(.system(size: 11.5, weight: .medium, design: .rounded))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                            Button { Finder.reveal(part.url) } label: { Image(systemName: "magnifyingglass") }
                                .buttonStyle(.plain)
                                .foregroundStyle(.tertiary)
                                .help("Reveal in Finder")
                        }
                        .padding(.horizontal, 20)
                        .padding(.vertical, 4)
                    }
                }
                .padding(.vertical, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .glassEffect(.regular.tint(finding.group == .threat ? Color.red.opacity(0.08) : nil), in: .rect(cornerRadius: 22))
    }

    @ViewBuilder
    private var icon: some View {
        if let path = finding.iconPath {
            Image(nsImage: IconCache.icon(for: path)).resizable().interpolation(.high)
        } else {
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous).fill(finding.group.tint.gradient)
                Image(systemName: finding.group.symbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
    }

    private func tag(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .bold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.18)))
            .foregroundStyle(color)
    }
}

struct PrivacySection: View {
    let grants: [PrivacyGrant]

    var body: some View {
        let clients = Dictionary(grouping: grants, by: \.client).sorted { $0.key < $1.key }
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Label("Can watch you", systemImage: "eye.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text("Apps allowed to see your screen, keystrokes, camera or microphone.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                Spacer()
                Menu("Open Settings") {
                    ForEach(PrivacyGrant.Service.allCases) { service in
                        Button(service.title, systemImage: service.symbol) { PrivacyAccess.openSettings(for: service) }
                    }
                }
                .fixedSize()
            }
            .padding(.leading, 6)

            VStack(spacing: 2) {
                ForEach(clients, id: \.key) { entry in
                    let location = entry.value.first.flatMap { PrivacyAccess.location(of: $0, resolve: PrivacyAccess.resolveApp) }
                    HStack(spacing: 10) {
                        Image(nsImage: IconCache.icon(for: location ?? "/")).resizable().frame(width: 20, height: 20)
                        Text(location.map { FileManager.default.displayName(atPath: $0) } ?? entry.key)
                            .font(.system(size: 12.5))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if location == nil {
                            Text("No longer installed").font(.system(size: 11)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        ForEach(entry.value.map(\.service).sorted { $0.rawValue < $1.rawValue }) { service in
                            Image(systemName: service.symbol)
                                .foregroundStyle(service.canWatch ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                                .help(service.title)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 5)
                }
            }
            .padding(.vertical, 10)
            .glassEffect(.regular, in: .rect(cornerRadius: 22))
        }
    }
}
