import AppKit

/// Development-only automation, driven by environment variables:
/// - STRATA_SNAPSHOT_DIR: write PNG snapshots of the window there.
/// - STRATA_DEMO=1: after a scan, zoom into the largest folder, select items and start a deletion.
/// - STRATA_TAB=apps: open Apps & Threats; with STRATA_SNAPSHOT_DIR, snapshot it once scanned.
/// Point STRATA_AUTOSCAN at a throwaway folder when using STRATA_DEMO.
@MainActor
enum DevHooks {
    static func run(model: AppModel) {
        let env = ProcessInfo.processInfo.environment
        if env["STRATA_TAB"] == "apps" {
            model.tab = .apps
            guard let directory = env["STRATA_SNAPSHOT_DIR"] else { return }
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                snapshot(directory, "apps-01-scanning")
                while model.apps.phase != .ready { try? await Task.sleep(for: .milliseconds(200)) }
                try? await Task.sleep(for: .seconds(1.5))
                snapshot(directory, "apps-02-ready")
            }
            return
        }
        guard let directory = env["STRATA_SNAPSHOT_DIR"] else { return }
        let demo = env["STRATA_DEMO"] == "1"
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            snapshot(directory, "01-start")
            while model.phase != .ready { try? await Task.sleep(for: .milliseconds(200)) }
            try? await Task.sleep(for: .seconds(1.5))
            snapshot(directory, "02-ready")
            guard demo, let root = model.root else { return }

            if let big = root.children.first(where: \.isDirectory) {
                model.zoom(into: big)
                try? await Task.sleep(for: .milliseconds(300))
                snapshot(directory, "03-zooming")
                try? await Task.sleep(for: .seconds(1))
                let count = Int(env["STRATA_DEMO_SELECT"] ?? "") ?? 3
                for child in big.children.prefix(count) where child.canDelete { model.toggleSelection(child) }
                model.setHovered(big.children.dropFirst(3).first)
                try? await Task.sleep(for: .seconds(0.8))
                snapshot(directory, "04-selected")
                model.setHovered(nil)
            }
            model.deleteMode = .permanent
            model.requestDeletion()
            if ProcessInfo.processInfo.environment["STRATA_DEMO_CANCEL"] == "1" {
                try? await Task.sleep(for: .seconds(1))
                model.deletion.cancel()
                try? await Task.sleep(for: .seconds(1.5))
                snapshot(directory, "05b-cancelled")
                return
            }
            try? await Task.sleep(for: .seconds(2))
            snapshot(directory, "05-countdown")
            try? await Task.sleep(for: .seconds(3.4))
            snapshot(directory, "06-eating")
            try? await Task.sleep(for: .seconds(1.6))
            snapshot(directory, "07-after")
            model.tab = .cleanup
            try? await Task.sleep(for: .seconds(3))
            snapshot(directory, "08-cleanup")
            try? await Task.sleep(for: .seconds(4))
            snapshot(directory, "09-cleanup-later")
            model.tab = .explore
            try? await Task.sleep(for: .seconds(1.5))
            snapshot(directory, "10-explore-later")
        }
    }

    static func snapshot(_ directory: String, _ name: String) {
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil }),
              let view = window.contentView?.superview ?? window.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        let url = URL(fileURLWithPath: directory).appendingPathComponent(name + ".png")
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }
}
