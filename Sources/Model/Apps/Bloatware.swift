import Foundation

enum Bloatware {
    static let garageBandID = "com.apple.garageband10"
    static let logicID = "com.apple.logic10"
    static let mainStageID = "com.apple.mainstage3"
    /// Apps that use the GarageBand/Logic content folders.
    static let soundLibraryConsumerIDs: Set<String> = [logicID, mainStageID]

    /// Apple's optional App Store apps and the team IDs they're signed with. They aren't
    /// "anchor apple" signed, so the team ID is what proves they're Apple's.
    static let apps: [String: String] = [
        garageBandID: "F3LWYJ7GM7",
        "com.apple.iMovieApp": "PTN9T2S29T",
        "com.apple.iWork.Keynote": "74J34U3R6X",
        "com.apple.iWork.Pages": "74J34U3R6X",
        "com.apple.iWork.Numbers": "74J34U3R6X",
    ]

    /// Each one must pass `PrivilegedRemover.isAllowed`: "Apple Loops" itself is an allowed root, so its "Apple" folder is listed.
    static let soundLibraryPaths = [
        "/Library/Application Support/GarageBand", "/Library/Application Support/Logic",
        "/Library/Audio/Apple Loops/Apple", "/Library/Audio/Impulse Responses/Apple",
    ]

    static func isBloatware(_ app: InstalledApp, signature: (String) -> Signature) -> Bool {
        guard let team = apps[app.bundleID] else { return false }
        let actual = signature(app.path)
        return actual.kind == .apple || (actual.kind == .identified && actual.teamID == team)
    }

    static func soundLibraries(existing: (String) -> Bool = DirectorySizer.exists) -> [URL] {
        soundLibraryPaths.filter(existing).map { URL(fileURLWithPath: $0) }
    }
}
