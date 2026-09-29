import Foundation
import SwiftUI

struct DeletionOperation {
    enum Kind {
        case trash(URL)
        case remove(URL)
        case command(executable: String, arguments: [String])
    }

    let label: String
    let kind: Kind
    let estimatedBytes: Int64
}

struct DeletionJob {
    let title: String
    let operations: [DeletionOperation]
    let movesToTrash: Bool
    var totalBytes: Int64 { operations.reduce(0) { $0 + $1.estimatedBytes } }
}

enum DeletionOutcome {
    case removed
    case partial(freed: Int64)
    case failed(String)
}

struct DeletionResult {
    var outcomes: [DeletionOutcome]
    var freedBytes: Int64
    var failures: Int
    var movedToTrash: Bool
}

/// Owns the 5-second grace period before anything is touched, then performs the work.
@MainActor
@Observable
final class DeletionController {
    enum Phase { case idle, countdown, working, finished }

    static let countdown: TimeInterval = 5

    private(set) var phase: Phase = .idle
    private(set) var job: DeletionJob?
    private(set) var deadline = Date()
    private(set) var completed = 0
    private(set) var result: DeletionResult?
    /// Estimated bytes of the operations that have finished.
    private(set) var bytesDone: Int64 = 0
    /// Growth in the volume's free space since work began (permanent deletes only).
    private(set) var volumeFreed: Int64 = 0
    private(set) var inFlight: [String] = []
    private(set) var workStarted = Date()

    /// How many items are removed at once; unlinking is metadata-bound and parallelizes well.
    static let parallelism = 6

    /// 0…1, by bytes rather than item count so a few huge folders don't look stuck.
    var workProgress: Double {
        guard let job, job.totalBytes > 0 else { return 0 }
        return min(1, Double(max(bytesDone, volumeFreed)) / Double(job.totalBytes))
    }

    var bytesFreedSoFar: Int64 { min(job?.totalBytes ?? 0, max(bytesDone, volumeFreed)) }

    /// Fires every few hundred milliseconds while work is in progress.
    @ObservationIgnored var onTick: (() -> Void)?
    @ObservationIgnored var onCountdownStarted: ((DeletionJob) -> Void)?
    @ObservationIgnored var onCancelled: (() -> Void)?
    @ObservationIgnored var onExecute: ((DeletionJob) -> Void)?
    @ObservationIgnored var onFinished: ((DeletionResult) -> Void)?
    @ObservationIgnored private var timer: Task<Void, Never>?
    @ObservationIgnored private var completion: ((DeletionResult) -> Void)?

    var isBusy: Bool { phase == .countdown || phase == .working }

    func schedule(_ job: DeletionJob, completion: @escaping (DeletionResult) -> Void) {
        guard !isBusy, !job.operations.isEmpty else { return }
        self.job = job
        self.completion = completion
        result = nil
        completed = 0
        deadline = Date().addingTimeInterval(Self.countdown)
        withAnimation(.spring(duration: 0.45, bounce: 0.25)) { phase = .countdown }
        onCountdownStarted?(job)
        timer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.countdown))
            guard !Task.isCancelled else { return }
            await self?.execute()
        }
    }

    func cancel() {
        guard phase == .countdown else { return }
        timer?.cancel()
        withAnimation(.spring(duration: 0.35)) { phase = .idle }
        job = nil
        completion = nil
        onCancelled?()
    }

    func dismissResult() {
        guard phase == .finished else { return }
        withAnimation(.smooth) { phase = .idle }
    }

    private func execute() async {
        guard let job, phase == .countdown else { return }
        withAnimation(.smooth) { phase = .working }
        onExecute?(job)

        workStarted = .now
        bytesDone = 0
        volumeFreed = 0
        inFlight = []

        // The worker pool runs entirely off the main actor and reports into a locked box;
        // the UI samples it a few times a second. Publishing per item re-rendered the
        // overlay thousands of times a second and froze the main thread.
        let box = DeletionProgressBox()

        // For permanent deletes the volume's free space is the most honest live progress
        // signal: it moves even while one huge folder is still being removed.
        let startFree = VolumeInfo.load()?.available ?? 0
        let movesToTrash = job.movesToTrash
        let ticker = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(300))
                guard let self, !Task.isCancelled else { return }
                tick += 1
                let snapshot = box.snapshot()
                let freedOnDisk: Int64? = (!movesToTrash && tick % 3 == 0) ? VolumeInfo.load().map { max(0, $0.available - startFree) } : nil
                withAnimation(.smooth(duration: 0.3)) {
                    self.completed = snapshot.completed
                    self.bytesDone = snapshot.bytes
                    if let freedOnDisk { self.volumeFreed = freedOnDisk }
                    let visible = Array(snapshot.inFlight.prefix(4))
                    if visible != self.inFlight { self.inFlight = visible }
                }
                self.onTick?()
            }
        }

        let operations = job.operations
        let outcomes = await Task.detached(priority: .userInitiated) {
            await Deleter.performAll(operations, parallelism: Self.parallelism, progress: box)
        }.value
        ticker.cancel()

        var freed: Int64 = 0
        var failures = 0
        for (operation, outcome) in zip(operations, outcomes) {
            switch outcome {
            case .removed: freed += operation.estimatedBytes
            case .partial(let bytes): freed += bytes
            case .failed: failures += 1
            }
        }
        completed = operations.count
        bytesDone = job.totalBytes
        inFlight = []

        let result = DeletionResult(outcomes: outcomes, freedBytes: freed, failures: failures, movedToTrash: job.movesToTrash)
        self.result = result
        withAnimation(.spring(duration: 0.4)) { phase = .finished }
        completion?(result)
        completion = nil
        onFinished?(result)

        try? await Task.sleep(for: .seconds(5))
        if phase == .finished, self.result.map({ $0.freedBytes == result.freedBytes }) == true {
            dismissResult()
        }
    }
}

final class DeletionProgressBox: @unchecked Sendable {
    struct Snapshot {
        var completed = 0
        var bytes: Int64 = 0
        var inFlight: [String] = []
    }

    private let lock = NSLock()
    private var state = Snapshot()

    func started(_ label: String) {
        lock.lock()
        state.inFlight.append(label)
        lock.unlock()
    }

    func finished(_ label: String, bytes: Int64) {
        lock.lock()
        if let index = state.inFlight.firstIndex(of: label) { state.inFlight.remove(at: index) }
        state.completed += 1
        state.bytes += bytes
        lock.unlock()
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return state
    }
}

enum Deleter {
    /// Runs every operation with bounded parallelism, off the main actor.
    static func performAll(_ operations: [DeletionOperation], parallelism: Int, progress: DeletionProgressBox) async -> [DeletionOutcome] {
        var outcomes = [DeletionOutcome](repeating: .failed("Not run"), count: operations.count)
        await withTaskGroup(of: (Int, DeletionOutcome).self) { group in
            var next = 0
            func launch(_ group: inout TaskGroup<(Int, DeletionOutcome)>) {
                let index = next
                let operation = operations[index]
                progress.started(operation.label)
                group.addTask { (index, await perform(operation)) }
                next += 1
            }
            while next < min(parallelism, operations.count) { launch(&group) }
            for await (index, outcome) in group {
                outcomes[index] = outcome
                progress.finished(operations[index].label, bytes: operations[index].estimatedBytes)
                if next < operations.count { launch(&group) }
            }
        }
        return outcomes
    }

    static func perform(_ operation: DeletionOperation) async -> DeletionOutcome {
        let fm = FileManager.default
        switch operation.kind {
        case .trash(let url):
            do {
                try fm.trashItem(at: url, resultingItemURL: nil)
                return .removed
            } catch {
                return .failed(error.localizedDescription)
            }

        case .remove(let url):
            do {
                try fm.removeItem(at: url)
                return .removed
            } catch {
                sweep(url)
                guard DirectorySizer.exists(url.path) else { return .removed }
                let remaining = DirectorySizer.allocatedSize(atPath: url.path)
                let freed = max(0, operation.estimatedBytes - remaining)
                return freed > 0 ? .partial(freed: freed) : .failed(error.localizedDescription)
            }

        case .command(let executable, let arguments):
            let run = await Shell.run(executable, arguments, timeout: 900)
            if run.status == 0 { return .removed }
            return .failed(String(run.output.trimmingCharacters(in: .whitespacesAndNewlines).suffix(240)))
        }
    }

    /// Best-effort removal when a folder contains a few items we are not allowed to delete.
    private static func sweep(_ url: URL) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.isDirectoryKey], options: [], errorHandler: { _, _ in true }) else { return }
        var directories: [URL] = []
        for case let item as URL in enumerator {
            if (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                directories.append(item)
            } else {
                try? fm.removeItem(at: item)
            }
        }
        for directory in directories.reversed() { try? fm.removeItem(at: directory) }
        try? fm.removeItem(at: url)
    }
}

enum Shell {
    static let searchPaths: [String] = {
        let home = NSHomeDirectory()
        return [
            "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
            home + "/.docker/bin", "/Applications/Docker.app/Contents/Resources/bin", home + "/.orbstack/bin",
            "/usr/local/go/bin", "/opt/homebrew/opt/go/bin", home + "/go/bin",
        ]
    }()

    static func locate(_ tool: String) -> String? {
        if tool.hasPrefix("/") { return FileManager.default.isExecutableFile(atPath: tool) ? tool : nil }
        return searchPaths.map { $0 + "/" + tool }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 60) async -> (status: Int32, output: String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
                var environment = ProcessInfo.processInfo.environment
                environment["PATH"] = (searchPaths + [environment["PATH"] ?? ""]).joined(separator: ":")
                process.environment = environment
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                process.standardInput = FileHandle.nullDevice
                do {
                    try process.run()
                } catch {
                    continuation.resume(returning: (-1, error.localizedDescription))
                    return
                }
                let killer = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                killer.cancel()
                continuation.resume(returning: (process.terminationStatus, String(decoding: data, as: UTF8.self)))
            }
        }
    }
}
