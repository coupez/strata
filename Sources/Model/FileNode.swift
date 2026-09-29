import Foundation

/// One entry in the scanned tree. Directories keep every subdirectory; files below
/// `DiskScanner.individualFileThreshold` are folded into a single aggregate node per folder
/// so that a full-disk scan stays within a reasonable memory budget.
final class FileNode: Identifiable, Hashable {
    enum Kind: UInt8 {
        case directory
        case file
        case aggregate   // "1,234 smaller files"
        case hidden      // space the scan could not attribute (system, snapshots, other volumes)
    }

    let name: String
    let kind: Kind
    var size: Int64
    var itemCount: Int
    var children: [FileNode] = []
    unowned(unsafe) var parent: FileNode?
    var isInaccessible = false
    /// Subdirectories still being scanned; only used by `DiskScanner`.
    var pendingChildren: Int32 = 0
    var customTitle: String?
    private let rootPath: String?

    init(name: String, kind: Kind, size: Int64 = 0, itemCount: Int = 0, rootPath: String? = nil) {
        self.name = name
        self.kind = kind
        self.size = size
        self.itemCount = itemCount
        self.rootPath = rootPath
    }

    var id: ObjectIdentifier { ObjectIdentifier(self) }
    static func == (lhs: FileNode, rhs: FileNode) -> Bool { lhs === rhs }
    func hash(into hasher: inout Hasher) { hasher.combine(ObjectIdentifier(self)) }

    var path: String {
        if let rootPath { return rootPath }
        guard let parent else { return name }
        let base = parent.path
        return base.hasSuffix("/") ? base + name : base + "/" + name
    }

    var url: URL { URL(fileURLWithPath: path, isDirectory: kind == .directory) }
    var displayName: String { customTitle ?? name }
    var isDirectory: Bool { kind == .directory }
    var isRealItem: Bool { kind == .directory || kind == .file }
    var canDelete: Bool { isRealItem && parent != nil && !Protection.isProtected(path) }

    /// Root first, self last.
    var ancestry: [FileNode] {
        var chain = [self]
        var node = parent
        while let current = node {
            chain.append(current)
            node = current.parent
        }
        return chain.reversed()
    }

    func isDescendant(of other: FileNode) -> Bool {
        var node = parent
        while let current = node {
            if current === other { return true }
            node = current.parent
        }
        return false
    }

    /// Number of levels between `ancestor` and self (1 for a direct child).
    func depth(below ancestor: FileNode) -> Int {
        var depth = 0
        var node: FileNode? = self
        while let current = node, current !== ancestor {
            depth += 1
            node = current.parent
        }
        return depth
    }

    func adopt(_ child: FileNode) {
        child.parent = self
        children.append(child)
    }

    func finalize() {
        var total: Int64 = 0
        var count = 0
        for child in children {
            total += child.size
            count += child.itemCount
        }
        size = total
        itemCount = count
        children.sort { $0.size > $1.size }
    }

    /// Removes this node from the tree and subtracts its size from every ancestor.
    func detach() {
        guard let parent else { return }
        parent.children.removeAll { $0 === self }
        var node: FileNode? = parent
        while let current = node {
            current.size -= size
            current.itemCount -= itemCount
            current.children.sort { $0.size > $1.size }
            node = current.parent
        }
        self.parent = nil
    }

    func replace(_ old: FileNode, with new: FileNode) {
        guard let index = children.firstIndex(where: { $0 === old }) else { return }
        let sizeDelta = new.size - old.size
        let countDelta = new.itemCount - old.itemCount
        new.parent = self
        children[index] = new
        old.parent = nil
        var node: FileNode? = self
        while let current = node {
            current.size += sizeDelta
            current.itemCount += countDelta
            current.children.sort { $0.size > $1.size }
            node = current.parent
        }
    }

    func descendant(atPath target: String) -> FileNode? {
        let base = path
        if target == base { return self }
        let prefix = base.hasSuffix("/") ? base : base + "/"
        guard target.hasPrefix(prefix) else { return nil }
        var node = self
        for component in target.dropFirst(prefix.count).split(separator: "/") {
            guard let next = node.children.first(where: { $0.name == component }) else { return nil }
            node = next
        }
        return node
    }
}

/// Paths the app refuses to delete no matter what the user selects.
enum Protection {
    static let home = NSHomeDirectory()

    private static let exact: Set<String> = [
        "/", "/Applications", "/Library", "/System", "/Users", "/Users/Shared", "/private",
        "/private/var", "/private/tmp", "/private/etc", "/var", "/etc", "/tmp", "/usr", "/usr/local",
        "/bin", "/sbin", "/opt", "/opt/homebrew", "/cores", "/Volumes",
        home, home + "/Library", home + "/Documents", home + "/Desktop", home + "/Downloads",
        home + "/Pictures", home + "/Movies", home + "/Music", home + "/Applications", home + "/Public",
        home + "/Library/Application Support", home + "/Library/Containers",
        home + "/Library/Group Containers", home + "/Library/Caches", home + "/Library/Mobile Documents",
        home + "/Library/CloudStorage", home + "/.Trash",
    ]

    private static let subtrees: [String] = [
        "/System", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/share",
        "/usr/standalone", "/private/etc", "/private/var/db", "/private/var/vm", "/dev", "/Library/Apple",
        home + "/Library/Keychains", home + "/Library/Preferences",
    ]

    static func isProtected(_ path: String) -> Bool {
        if exact.contains(path) { return true }
        return subtrees.contains { path == $0 || path.hasPrefix($0 + "/") }
    }
}
