import Foundation

/// A scratch directory that disappears with the test. Paths are symlink-resolved so they
/// compare equal to what the code under test computes.
final class TempDir {
    let url: URL
    var path: String { url.path }

    init() {
        let raw = FileManager.default.temporaryDirectory.appendingPathComponent("StrataTests-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        url = raw.resolvingSymlinksInPath()
    }

    deinit { try? FileManager.default.removeItem(at: url) }

    @discardableResult
    func file(_ relative: String, _ contents: String = "x") -> URL {
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! Data(contents.utf8).write(to: target)
        return target
    }

    @discardableResult
    func directory(_ relative: String) -> URL {
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        return target
    }

    @discardableResult
    func plist(_ relative: String, _ object: [String: Any]) -> URL {
        let data = try! PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        let target = url.appendingPathComponent(relative)
        try! FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! data.write(to: target)
        return target
    }

    /// A minimal .app bundle: Info.plist plus a shell-script executable.
    @discardableResult
    func app(_ relative: String, id: String, executable: String = "main") -> URL {
        plist(relative + "/Contents/Info.plist", [
            "CFBundleIdentifier": id, "CFBundleExecutable": executable, "CFBundleShortVersionString": "1.0",
        ])
        file(relative + "/Contents/MacOS/" + executable, "#!/bin/sh\n")
        return url.appendingPathComponent(relative)
    }
}

struct ShellError: Error { let status: Int32 }

func shell(_ tool: String, _ arguments: String...) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: tool)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw ShellError(status: process.terminationStatus) }
}
