import Foundation
import Testing
@testable import Strata

struct AppsModelTests {
    func part(_ path: String, _ size: Int64, _ kind: FindingPart.Kind) -> FindingPart {
        FindingPart(url: URL(fileURLWithPath: path), size: size, kind: kind)
    }

    func finding(_ id: String, parts: [FindingPart] = [], running: Bool = false, verdict: Verdict? = nil,
                 group: FindingGroup = .unused) -> Finding {
        Finding(id: id, group: group, verdict: verdict, title: id, reasons: [], iconPath: nil, parts: parts,
                risk: .review, isRunning: running)
    }

    @Test func removalJobSkipsRunningAppsAndUnloadsUserAgents() {
        let a = finding("app:A", parts: [
            part("/Applications/A.app", 100, .app),
            part("/u/Library/LaunchAgents/com.a.agent.plist", 1, .launchItem(label: "com.a.agent", domain: .userAgent)),
            part("/Library/LaunchDaemons/com.a.d.plist", 1, .launchItem(label: "com.a.d", domain: .systemDaemon)),
        ])
        let running = finding("app:B", parts: [part("/Applications/B.app", 5, .app)], running: true)
        let job = AppsModel.removalJob(for: [a, running], trash: true, uid: 501)
        #expect(job.allowsElevation)
        #expect(job.movesToTrash)
        #expect(job.operations.map(\.label) == ["A.app", "com.a.agent", "com.a.agent.plist", "com.a.d.plist"])
        if case .unload(let target) = job.operations[1].kind {
            #expect(target == "gui/501/com.a.agent")
        } else {
            Issue.record("Expected an unload operation before the agent's plist")
        }
        #expect(job.totalBytes == 102)
    }

    @Test func permanentModeRemoves() {
        let job = AppsModel.removalJob(for: [finding("x", parts: [part("/Applications/X.app", 1, .app)])], trash: false, uid: 501)
        #expect(!job.movesToTrash)
        if case .remove(let url) = job.operations[0].kind { #expect(url.path == "/Applications/X.app") } else { Issue.record("Expected .remove") }
    }

    @Test func removalJobSkipsAppsRunningAtRemovalTime() {
        let stale = finding("app:C", parts: [part("/Applications/C.app", 7, .app), part("/u/Library/Caches/com.c", 1, .support)])
        let other = finding("app:D", parts: [part("/Applications/D.app", 3, .app)])
        let job = AppsModel.removalJob(for: [stale, other], trash: true, uid: 501, runningAppPaths: ["/Applications/C.app"])
        #expect(job.operations.map(\.label) == ["D.app"])
    }

    @Test func summaryOnlyClaimsNoThreatsWhenTheRulesRan() {
        #expect(AppsModel.readySummary(threats: 0, removable: 3, rulesLoaded: true) == "No threats found. 3 things you could remove.")
        #expect(AppsModel.readySummary(threats: 0, removable: 1, rulesLoaded: false) == "Threat check unavailable. 1 thing you could remove.")
        #expect(AppsModel.readySummary(threats: 2, removable: 5, rulesLoaded: false) == "2 possible threats found. Review them first.")
    }

    @Test func selectionKeepsUserChoices() {
        let a = finding("a", verdict: .malicious, group: .threat)
        let b = finding("b")
        let c = finding("c", running: true, verdict: .malicious, group: .threat)
        #expect(AppsModel.selection(for: [a, b, c], choices: [:]) == ["a"])
        #expect(AppsModel.selection(for: [a, b, c], choices: ["a": false, "b": true, "c": true]) == ["b"])
    }
}
