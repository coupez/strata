import Darwin
import Foundation

struct ScanSnapshot: Equatable {
    var files = 0
    var directories = 0
    var bytes: Int64 = 0
    var errors = 0
    var currentPath = ""
}

final class ScanProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var state = ScanSnapshot()

    func record(files: Int, bytes: Int64, errors: Int, path: String) {
        lock.lock()
        state.files += files
        state.directories += 1
        state.bytes += bytes
        state.errors += errors
        state.currentPath = path
        lock.unlock()
    }

    func snapshot() -> ScanSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return state
    }
}

private let direntNameOffset = MemoryLayout<dirent>.offset(of: \dirent.d_name) ?? 21

/// Walks a directory tree with raw `readdir`/`fstatat` calls, fanning out across
/// the first few levels in parallel. Sizes are allocated bytes (`st_blocks * 512`)
/// and hard-linked files are only counted once.
final class DiskScanner: @unchecked Sendable {
    static let individualFileThreshold: Int64 = 256 * 1024
    static let maxLooseFiles = 4

    let rootPath: String
    let progress = ScanProgress()

    private let skipPaths: Set<String>
    private let allowedDevices: Set<dev_t>
    private let lock = NSLock()
    private var cancelled = false
    private var seenInodes = Set<InodeKey>()

    private struct InodeKey: Hashable {
        let device: dev_t
        let inode: ino_t
    }

    private struct Listing {
        var subdirectories: [(name: String, path: String)] = []
        var files: [FileNode] = []
        var loose: [(name: String, bytes: Int64)] = []
        var smallCount = 0
        var smallBytes: Int64 = 0
        var totalFiles = 0
        var totalBytes: Int64 = 0
        var errors = 0
        var accessible = true
    }

    init(rootPath: String) {
        self.rootPath = rootPath
        var skip: Set<String> = ["/dev", "/Volumes", "/net", "/home", "/.vol", "/.nofollow", "/.resolve", "/private/var/vm"]
        // The data volume is reachable through firmlinks from "/", so avoid counting it twice.
        if !rootPath.hasPrefix("/System/Volumes") { skip.insert("/System/Volumes") }
        skipPaths = skip

        var devices = Set<dev_t>()
        var info = stat()
        if lstat(rootPath, &info) == 0 { devices.insert(info.st_dev) }
        if stat("/System/Volumes/Data", &info) == 0, rootPath == "/" { devices.insert(info.st_dev) }
        allowedDevices = devices
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func run() async -> FileNode {
        let root = FileNode(name: rootPath, kind: .directory, rootPath: rootPath)
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            scanInParallel(root) { continuation.resume() }
        }
        return root
    }

    /// Scans a single directory synchronously into a detached node named `name`.
    func scanSubtree(name: String) -> FileNode {
        let node = FileNode(name: name, kind: .directory)
        scanSequential(path: rootPath, node: node)
        return node
    }

    // MARK: Work-stealing parallel scan
    //
    // Every directory is a job on a shared LIFO queue, so a single enormous subtree is
    // still spread across all workers. A directory is finalized once its last
    // subdirectory finishes; the scan ends when the queue is empty and nobody is working.

    private let queue = NSCondition()
    private var jobs: [(node: FileNode, path: String)] = []
    private var activeWorkers = 0
    private var queueFinished = false
    private let pendingLock = NSLock()

    private func scanInParallel(_ root: FileNode, completion: @escaping () -> Void) {
        jobs = [(root, rootPath)]
        let workerCount = max(4, min(24, ProcessInfo.processInfo.activeProcessorCount * 2))
        let group = DispatchGroup()
        for index in 0 ..< workerCount {
            group.enter()
            let thread = Thread { [self] in
                workerLoop()
                group.leave()
            }
            thread.name = "Strata scanner \(index)"
            thread.qualityOfService = .userInitiated
            thread.start()
        }
        group.notify(queue: .global(qos: .userInitiated), execute: completion)
    }

    private func workerLoop() {
        while true {
            queue.lock()
            while jobs.isEmpty && !queueFinished {
                if activeWorkers == 0 {
                    queueFinished = true
                    queue.broadcast()
                    break
                }
                queue.wait()
            }
            if queueFinished {
                queue.unlock()
                return
            }
            let job = jobs.removeLast()
            activeWorkers += 1
            queue.unlock()

            process(job.node, path: job.path)

            queue.lock()
            activeWorkers -= 1
            if jobs.isEmpty && activeWorkers == 0 {
                queueFinished = true
                queue.broadcast()
            }
            queue.unlock()
        }
    }

    private func process(_ node: FileNode, path: String) {
        guard !isCancelled else { return }
        let listing = list(path)
        populate(node, with: listing, path: path)
        guard !listing.subdirectories.isEmpty else {
            complete(node)
            return
        }
        var children: [(node: FileNode, path: String)] = []
        children.reserveCapacity(listing.subdirectories.count)
        for sub in listing.subdirectories {
            let child = FileNode(name: sub.name, kind: .directory)
            node.adopt(child)
            children.append((child, sub.path))
        }
        pendingLock.lock()
        node.pendingChildren = Int32(children.count)
        pendingLock.unlock()

        queue.lock()
        jobs.append(contentsOf: children)
        queue.broadcast()
        queue.unlock()
    }

    /// Finalizes `node`, then any ancestors whose last pending subdirectory it was.
    private func complete(_ node: FileNode) {
        var current = node
        while true {
            current.finalize()
            guard let parent = current.parent else { return }
            pendingLock.lock()
            parent.pendingChildren -= 1
            let done = parent.pendingChildren == 0
            pendingLock.unlock()
            guard done else { return }
            current = parent
        }
    }

    /// Iterative depth-first walk; deeply nested trees (node_modules…) never blow the stack.
    private func scanSequential(path: String, node: FileNode) {
        struct Frame {
            let node: FileNode
            let pending: [(name: String, path: String)]
            var index = 0
        }
        let listing = list(path)
        populate(node, with: listing, path: path)
        var stack = [Frame(node: node, pending: listing.subdirectories)]

        while let top = stack.last {
            if top.index < top.pending.count {
                if isCancelled {
                    for frame in stack.reversed() { frame.node.finalize() }
                    return
                }
                let sub = top.pending[top.index]
                stack[stack.count - 1].index += 1
                let child = FileNode(name: sub.name, kind: .directory)
                top.node.adopt(child)
                let childListing = list(sub.path)
                populate(child, with: childListing, path: sub.path)
                stack.append(Frame(node: child, pending: childListing.subdirectories))
            } else {
                top.node.finalize()
                stack.removeLast()
            }
        }
    }

    private func populate(_ node: FileNode, with listing: Listing, path: String) {
        node.isInaccessible = !listing.accessible
        for file in listing.files { node.adopt(file) }
        if listing.smallCount > 0 {
            if listing.smallCount <= Self.maxLooseFiles {
                for file in listing.loose {
                    node.adopt(FileNode(name: file.name, kind: .file, size: file.bytes, itemCount: 1))
                }
            } else {
                node.adopt(FileNode(
                    name: "\(listing.smallCount.formatted()) smaller files",
                    kind: .aggregate,
                    size: listing.smallBytes,
                    itemCount: listing.smallCount
                ))
            }
        }
        progress.record(files: listing.totalFiles, bytes: listing.totalBytes, errors: listing.errors, path: path)
    }

    private func firstSighting(device: dev_t, inode: ino_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return seenInodes.insert(InodeKey(device: device, inode: inode)).inserted
    }

    private func list(_ path: String) -> Listing {
        var listing = Listing()
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            listing.accessible = false
            listing.errors = 1
            return listing
        }
        guard let dir = fdopendir(fd) else {
            close(fd)
            listing.accessible = false
            listing.errors = 1
            return listing
        }
        defer { closedir(dir) }

        let prefix = path.hasSuffix("/") ? path : path + "/"
        var info = stat()
        while let entry = readdir(dir) {
            let namePtr = (UnsafeRawPointer(entry) + direntNameOffset).assumingMemoryBound(to: CChar.self)
            if namePtr[0] == 46 && (namePtr[1] == 0 || (namePtr[1] == 46 && namePtr[2] == 0)) { continue }
            guard fstatat(fd, namePtr, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                listing.errors += 1
                continue
            }
            let name = String(cString: namePtr)
            let type = info.st_mode & S_IFMT
            if type == S_IFDIR {
                let childPath = prefix + name
                if skipPaths.contains(childPath) || !allowedDevices.contains(info.st_dev) { continue }
                listing.subdirectories.append((name, childPath))
            } else {
                var bytes = Int64(info.st_blocks) * 512
                if type == S_IFREG, info.st_nlink > 1, !firstSighting(device: info.st_dev, inode: info.st_ino) {
                    bytes = 0
                }
                listing.totalFiles += 1
                listing.totalBytes += bytes
                if bytes >= Self.individualFileThreshold {
                    listing.files.append(FileNode(name: name, kind: .file, size: bytes, itemCount: 1))
                } else {
                    listing.smallCount += 1
                    listing.smallBytes += bytes
                    if listing.loose.count <= Self.maxLooseFiles { listing.loose.append((name, bytes)) }
                }
            }
        }
        return listing
    }
}

/// Lightweight `du` for measuring cleanup candidates.
enum DirectorySizer {
    static func allocatedSize(atPath path: String) -> Int64 {
        var info = stat()
        guard lstat(path, &info) == 0 else { return 0 }
        guard info.st_mode & S_IFMT == S_IFDIR else { return Int64(info.st_blocks) * 512 }

        let device = info.st_dev
        var total: Int64 = 0
        var pending = [path]
        while let current = pending.popLast() {
            let fd = open(current, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { continue }
            guard let dir = fdopendir(fd) else {
                close(fd)
                continue
            }
            let prefix = current.hasSuffix("/") ? current : current + "/"
            while let entry = readdir(dir) {
                let namePtr = (UnsafeRawPointer(entry) + direntNameOffset).assumingMemoryBound(to: CChar.self)
                if namePtr[0] == 46 && (namePtr[1] == 0 || (namePtr[1] == 46 && namePtr[2] == 0)) { continue }
                guard fstatat(fd, namePtr, &info, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
                if info.st_mode & S_IFMT == S_IFDIR {
                    if info.st_dev == device { pending.append(prefix + String(cString: namePtr)) }
                } else {
                    total += Int64(info.st_blocks) * 512
                }
            }
            closedir(dir)
        }
        return total
    }

    static func exists(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0
    }
}
