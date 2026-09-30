import Foundation

enum PathProbe {
    /// Only a path the system says isn't there. One we merely can't reach (a root-only or
    /// privacy-protected folder) may well exist, so it never counts as gone.
    static func isGone(_ path: String) -> Bool {
        var info = stat()
        guard lstat(path, &info) != 0 else { return false }
        return errno == ENOENT || errno == ENOTDIR
    }
}
