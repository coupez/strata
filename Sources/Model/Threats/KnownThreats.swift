import Foundation

/// Well-documented adware and "cleaner" scareware, matched by bundle ID or launch label prefix.
/// Conservative on purpose: every entry cites a public write-up.
enum KnownThreats {
    struct Indicator: Sendable {
        let family: String
        /// Lower-case prefixes, each ending in ".".
        let prefixes: [String]
    }

    static let indicators: [Indicator] = [
        // com.mackeeper.MacKeeperAgent / com.zeobit.MacKeeper.Helper:
        // https://discussions.apple.com/docs/DOC-12761, https://discussions.apple.com/thread/6531782
        Indicator(family: "MacKeeper", prefixes: ["com.mackeeper.", "com.zeobit."]),
        // com.pcv.hlpramc, com.PCvark.AdvancedMacCleaner:
        // https://www.malwarebytes.com/blog/news/2016/08/pcvark-plays-dirty
        Indicator(family: "PCVARK cleaners", prefixes: ["com.pcv.", "com.pcvark."]),
        // com.genieo.engine, com.genieo.completer.update: https://www.malwarebytes.com/blog/detections/osx-genieo
        Indicator(family: "Genieo", prefixes: ["com.genieo."]),
        // com.vsearch.agent, com.vsearch.daemon: https://www.malwarebytes.com/blog/detections/osx-vsearch
        Indicator(family: "VSearch", prefixes: ["com.vsearch."]),
    ]

    static func match(_ id: String) -> Indicator? {
        let candidate = id.lowercased() + "."
        return indicators.first { $0.prefixes.contains { candidate.hasPrefix($0) } }
    }
}
