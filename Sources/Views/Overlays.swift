import SwiftUI

struct CountdownOverlay: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let deletion = model.deletion
        if let job = deletion.job, deletion.phase == .countdown || deletion.phase == .working {
            ZStack {
                Color.black.opacity(0.28)
                    .ignoresSafeArea()
                    .contentShape(Rectangle())
                    .onTapGesture {}
                    .transition(.opacity)

                VStack(spacing: 20) {
                    if deletion.phase == .countdown {
                        CountdownRing(deadline: deletion.deadline)
                            .frame(width: 150, height: 150)
                    } else {
                        ZStack {
                            Circle().stroke(.primary.opacity(0.08), lineWidth: 10)
                            Circle()
                                .trim(from: 0, to: deletion.workProgress)
                                .stroke(Color.green.gradient, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                                .rotationEffect(.degrees(-90))
                            VStack(spacing: 2) {
                                Image(systemName: "fork.knife")
                                    .font(.system(size: 26, weight: .semibold))
                                    .symbolEffect(.bounce, options: .repeating)
                                Text(deletion.workProgress.formatted(.percent.precision(.fractionLength(0))))
                                    .font(.system(size: 22, weight: .bold, design: .rounded))
                                    .monospacedDigit()
                                    .contentTransition(.numericText())
                            }
                        }
                        .frame(width: 150, height: 150)
                    }

                    VStack(spacing: 6) {
                        Text(deletion.phase == .countdown ? job.title : "Nom nom…")
                            .font(.system(size: 20, weight: .semibold, design: .rounded))
                        if deletion.phase == .working {
                            Text("\(deletion.bytesFreedSoFar.bytes) of \(job.totalBytes.bytes) · \(deletion.completed.formatted()) of \(job.operations.count.formatted()) items")
                                .font(.system(size: 13))
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                                .contentTransition(.numericText())
                            TimelineView(.periodic(from: .now, by: 1)) { context in
                                Text("Elapsed \(Duration.seconds(context.date.timeIntervalSince(deletion.workStarted)).formatted(.time(pattern: .minuteSecond)))")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.tertiary)
                                    .monospacedDigit()
                            }
                        } else {
                            Text("\(job.totalBytes.bytes) · \(job.operations.count) item\(job.operations.count == 1 ? "" : "s")")
                                .font(.system(size: 13))
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }

                    if deletion.phase == .working {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("EATING NOW").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary).tracking(0.8)
                            ForEach(Array(deletion.inFlight.prefix(4).enumerated()), id: \.offset) { _, label in
                                HStack(spacing: 6) {
                                    ProgressView().controlSize(.mini)
                                    Text(label).lineLimit(1).truncationMode(.middle)
                                }
                            }
                        }
                        .font(.system(size: 12))
                        .frame(width: 290, alignment: .leading)
                    } else {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(job.operations.prefix(4).enumerated()), id: \.offset) { _, operation in
                            HStack {
                                Image(systemName: "circle.fill").font(.system(size: 4)).foregroundStyle(.secondary)
                                Text(operation.label).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Text(operation.estimatedBytes.bytes).foregroundStyle(.secondary).monospacedDigit()
                            }
                        }
                        if job.operations.count > 4 {
                            Text("and \(job.operations.count - 4) more…").foregroundStyle(.tertiary)
                        }
                    }
                    .font(.system(size: 12))
                    .frame(width: 290)
                    }

                    if deletion.phase == .countdown {
                        Button { deletion.cancel() } label: {
                            Label("Cancel", systemImage: "xmark").frame(width: 140)
                        }
                        .buttonStyle(.glass)
                        .controlSize(.extraLarge)
                        .keyboardShortcut(.cancelAction)
                        Text("Press Esc to cancel")
                            .font(.system(size: 11))
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(34)
                .frame(width: 380)
                .glassEffect(.regular, in: .rect(cornerRadius: 36))
                .transition(.scale(scale: 0.85).combined(with: .opacity))
            }
        }
    }
}

struct CountdownRing: View {
    let deadline: Date

    var body: some View {
        TimelineView(.animation) { context in
            let remaining = max(0, deadline.timeIntervalSince(context.date))
            let seconds = Int(remaining.rounded(.up))
            ZStack {
                Circle().stroke(.primary.opacity(0.08), lineWidth: 10)
                Circle()
                    .trim(from: 0, to: remaining / DeletionController.countdown)
                    .stroke(
                        AngularGradient(colors: [.orange, .red, .pink, .orange], center: .center),
                        style: StrokeStyle(lineWidth: 10, lineCap: .round)
                    )
                    .rotationEffect(.degrees(-90))
                    .shadow(color: .red.opacity(0.5), radius: 8)
                Text("\(seconds)")
                    .font(.system(size: 68, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText(countsDown: true))
                    .animation(.snappy, value: seconds)
            }
        }
    }
}

struct ResultToast: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.deletion.phase == .finished, let result = model.deletion.result {
            HStack(spacing: 12) {
                Image(systemName: result.failures == 0 ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 20))
                    .foregroundStyle(result.failures == 0 ? .green : .orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text(result.movedToTrash ? "Moved \(result.freedBytes.bytes) to the Trash" : "Freed \(result.freedBytes.bytes)")
                        .font(.system(size: 14, weight: .semibold))
                    if result.failures > 0 {
                        Text("\(result.failures) item\(result.failures == 1 ? "" : "s") couldn't be removed")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
                Button { model.deletion.dismissResult() } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 12)
            .glassEffect(.regular.tint(.green.opacity(0.12)), in: .capsule)
            .padding(.top, 14)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }
}
