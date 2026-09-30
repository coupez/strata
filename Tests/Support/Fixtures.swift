import Foundation
@testable import Strata

func makeApp(_ path: String, id: String, lastUsed: Date? = nil, added: Date? = nil, nested: [String] = [], size: Int64 = 100) -> InstalledApp {
    let url = URL(fileURLWithPath: path)
    return InstalledApp(url: url, bundleID: id, name: url.deletingPathExtension().lastPathComponent, version: nil,
                        nestedBundleIDs: nested, size: size, lastUsed: lastUsed, dateAdded: added)
}

func makeItem(_ label: String, program: String? = "/x", arguments: [String] = [], domain: LaunchDomain = .userAgent,
              associated: String? = nil, orphaned: Bool = false) -> LaunchItem {
    LaunchItem(plist: URL(fileURLWithPath: "/L/\(label).plist"), label: label, domain: domain, program: program,
               arguments: arguments, associatedBundleID: associated, runsAtLoad: true, isOrphaned: orphaned)
}
