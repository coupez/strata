import AppKit
import SwiftUI

// MARK: - Controller

/// Nibble: a small glowing pixel cat that trails the cursor, narrates what's going on,
/// and eats whatever gets deleted.
@MainActor
@Observable
final class MascotController {
    enum Mood { case neutral, happy, excited, curious, sad, eating }

    struct Bubble: Equatable {
        let id: Int
        let text: String
    }

    private(set) var bubble: Bubble?
    private(set) var mood: Mood = .happy

    @ObservationIgnored let physics = MascotPhysics()
    @ObservationIgnored private var bubbleTask: Task<Void, Never>?
    @ObservationIgnored private var bubbleCounter = 0
    @ObservationIgnored private var monitor: Any?
    @ObservationIgnored private var lastHoverRemark = Date.distantPast
    @ObservationIgnored private var lastMunchRemark = Date()
    @ObservationIgnored private var mealStarted = Date()

    func say(_ text: String, mood: Mood = .neutral, duration: TimeInterval = 4) {
        bubbleCounter += 1
        let id = bubbleCounter
        withAnimation(.spring(duration: 0.35, bounce: 0.3)) {
            bubble = Bubble(id: id, text: text)
            self.mood = mood
        }
        bubbleTask?.cancel()
        bubbleTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(duration))
            guard !Task.isCancelled, let self, self.bubble?.id == id else { return }
            withAnimation(.smooth(duration: 0.3)) {
                self.bubble = nil
                if self.mood != .eating { self.mood = .neutral }
            }
        }
    }

    func hop() { physics.hop(strength: 1) }

    func noticeHover(_ node: FileNode, in focus: FileNode) {
        guard node !== focus, node.isRealItem, focus.size > 0, bubble == nil,
              Double(node.size) / Double(focus.size) >= 0.25,
              Date().timeIntervalSince(lastHoverRemark) > 14 else { return }
        lastHoverRemark = .now
        say("Whoa, \(node.displayName) is \(percentString(node.size, of: focus.size)) of this folder!", mood: .curious, duration: 3.5)
    }

    func tabChanged(to tab: AppModel.Tab, model: AppModel) {
        if tab == .cleanup {
            say("Snack menu! Caches grow back on their own. Read the Caution and Review tags before picking those.", mood: .curious, duration: 6)
        } else if model.phase == .ready {
            say("Back to the rings! Click one to dive in.", mood: .happy, duration: 3)
        }
    }

    /// Launches one morsel per origin (cycling) toward Nibble's mouth.
    func feed(origins: [(CGPoint, Color)], count: Int) {
        let now = Date()
        mealStarted = now
        let size = physics.bounds
        let palette: [Color] = [.cyan, .purple, .pink, .orange, .mint, .yellow]
        for index in 0 ..< count {
            let origin: (CGPoint, Color)
            if origins.isEmpty {
                let angle = Double.random(in: 0 ..< 2 * .pi)
                let radius = CGFloat.random(in: 40 ... 170)
                origin = (CGPoint(x: size.width / 2 + radius * cos(angle), y: size.height / 2 + radius * sin(angle)), palette[index % palette.count])
            } else {
                origin = origins[index % origins.count]
            }
            let jitter = CGPoint(x: .random(in: -14 ... 14), y: .random(in: -14 ... 14))
            physics.particles.append(MascotPhysics.Morsel(
                start: CGPoint(x: origin.0.x + jitter.x, y: origin.0.y + jitter.y),
                color: origin.1,
                born: now.addingTimeInterval(Double(index) * 0.07),
                duration: .random(in: 0.65 ... 1.0),
                lift: .random(in: 60 ... 180),
                spin: .random(in: -6 ... 6)
            ))
        }
        physics.eatingUntil = now.addingTimeInterval(Double(count) * 0.07 + 1.2)
        say("Nom nom nom!", mood: .eating, duration: Double(count) * 0.07 + 1.2)
    }

    /// Called as each item of a long deletion finishes, so Nibble keeps munching throughout.
    /// Called on every progress tick of a deletion: Nibble munches in bursts of a few
    /// seconds with short breathers in between, for as long as the work continues.
    func nibble(progress: Double, freed: Int64) {
        let now = Date()
        let cycle = now.timeIntervalSince(mealStarted).truncatingRemainder(dividingBy: 7)
        let munching = cycle < 4.5
        if munching, physics.particles.count < 8 {
            let size = physics.bounds
            let angle = Double.random(in: 0 ..< 2 * .pi)
            let radius = CGFloat.random(in: 60 ... 190)
            let palette: [Color] = [.cyan, .purple, .pink, .orange, .mint, .yellow]
            physics.particles.append(MascotPhysics.Morsel(
                start: CGPoint(x: size.width / 2 + radius * cos(angle), y: size.height / 2 + radius * sin(angle)),
                color: palette.randomElement() ?? .pink,
                born: now,
                duration: .random(in: 0.6 ... 0.9),
                lift: .random(in: 60 ... 160),
                spin: .random(in: -6 ... 6)
            ))
        }
        if munching { physics.eatingUntil = max(physics.eatingUntil, now.addingTimeInterval(0.8)) }
        if now.timeIntervalSince(lastMunchRemark) > 20 {
            lastMunchRemark = now
            let lines = ["Still munching… \(freed.bytes) down!", "\(progress.formatted(.percent.precision(.fractionLength(0)))) eaten. So many crunchy little files.",
                         "node_modules are like popcorn: tiny, endless.", "Chomp chomp… \(freed.bytes) and counting."]
            say(lines.randomElement() ?? "", mood: .eating, duration: 5)
        }
    }

    func finishMeal(_ line: String) {
        let delay = max(0, physics.eatingUntil.timeIntervalSinceNow)
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay + 0.2))
            guard let self else { return }
            self.physics.hop(strength: 1.4)
            self.say(line, mood: .happy, duration: 5)
        }
    }

    func startTracking() {
        guard monitor == nil else { return }
        let enableMouseMoved = { for window in NSApp.windows { window.acceptsMouseMovedEvents = true } }
        enableMouseMoved()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: enableMouseMoved)

        monitor = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .leftMouseDragged, .leftMouseDown, .rightMouseDown]) { [weak self] event in
            guard let self, let content = event.window?.contentView else { return event }
            let point = CGPoint(x: event.locationInWindow.x, y: content.bounds.height - event.locationInWindow.y)
            switch event.type {
            case .leftMouseDown, .rightMouseDown:
                self.physics.cursorMoved(to: point)
                self.physics.hop(strength: 0.8)
            default:
                self.physics.cursorMoved(to: point)
            }
            return event
        }
    }
}

// MARK: - Physics (mutated every frame, deliberately not observed)

final class MascotPhysics {
    struct Morsel {
        let start: CGPoint
        let color: Color
        let born: Date
        let duration: Double
        let lift: CGFloat
        let spin: Double
    }

    struct Sparkle {
        let origin: CGPoint
        let velocity: CGVector
        let born: Date
    }

    var position = CGPoint(x: 90, y: 600)
    var velocity = CGVector.zero
    var target: CGPoint?
    var bounds = CGSize(width: 1200, height: 800)
    var hopHeight: CGFloat = 0
    var hopVelocity: CGFloat = 0
    var lastStep: Date?
    var lastActivity = Date()
    var mouthOpenUntil = Date.distantPast
    var eatingUntil = Date.distantPast
    var fullness: Double = 0
    var nextBlink = Date().addingTimeInterval(3)
    var blinkUntil = Date.distantPast
    var particles: [Morsel] = []
    var sparkles: [Sparkle] = []
    private var placed = false

    static let pixel: CGFloat = 4
    var spriteSize: CGSize { CGSize(width: 16 * Self.pixel, height: 14 * Self.pixel) }
    /// Point the food flies into.
    var mouth: CGPoint { CGPoint(x: position.x, y: position.y - hopHeight + 2) }

    // Follow-from-a-distance behavior: Nibble picks a spot on a ring around the cursor
    // and only relocates when that spot drifts too far, the cursor comes too close,
    // or it simply feels like wandering somewhere else.
    private var cursor: CGPoint?
    private var perch: CGVector?
    private var nextWander = Date()
    private let comfortZone: ClosedRange<CGFloat> = 150 ... 330
    private let personalSpace: CGFloat = 120

    func cursorMoved(to point: CGPoint) {
        cursor = point
        lastActivity = .now
    }

    private func pickPerch(avoiding point: CGPoint?, in size: CGSize) -> CGVector {
        // Prefer spots beside or below the cursor, where they cover the least text.
        for _ in 0 ..< 12 {
            let angle = Double.random(in: -0.35 * .pi ... 1.35 * .pi)   // skips the arc straight above
            let radius = CGFloat.random(in: 170 ... 250)
            let offset = CGVector(dx: radius * cos(angle), dy: radius * sin(angle))
            guard let point else { return offset }
            let spot = CGPoint(x: point.x + offset.dx, y: point.y + offset.dy)
            if spot.x > 50, spot.x < size.width - 50, spot.y > 60, spot.y < size.height - 40 { return offset }
        }
        return CGVector(dx: 190, dy: 150)
    }

    private func updateTarget(now: Date, size: CGSize) {
        guard let cursor else { return }
        let distance = hypot(position.x - cursor.x, position.y - cursor.y)
        var needsNewPerch = perch == nil || now >= nextWander

        if distance < personalSpace {
            // Too close: step away on the opposite side from where the cursor approached.
            let away = atan2(position.y - cursor.y, position.x - cursor.x) + .random(in: -0.6 ... 0.6)
            let radius = CGFloat.random(in: 180 ... 230)
            perch = CGVector(dx: radius * cos(away), dy: radius * sin(away))
            nextWander = now.addingTimeInterval(.random(in: 4 ... 8))
            needsNewPerch = false
        } else if !comfortZone.contains(distance) {
            needsNewPerch = true
        }
        if needsNewPerch {
            perch = pickPerch(avoiding: cursor, in: size)
            nextWander = now.addingTimeInterval(.random(in: 4 ... 9))
        }

        guard let perch else { return }
        let desired = CGPoint(x: cursor.x + perch.dx, y: cursor.y + perch.dy)
        // Lazy follow: only commit to a new target once the old one is clearly stale.
        if let current = target, hypot(current.x - desired.x, current.y - desired.y) < 70 { return }
        target = desired
    }

    func hop(strength: CGFloat) {
        if hopHeight < 4 { hopVelocity = 260 * strength }
        let now = Date()
        for index in 0 ..< 6 {
            let angle = Double(index) / 6 * 2 * .pi + .random(in: -0.3 ... 0.3)
            sparkles.append(Sparkle(origin: position, velocity: CGVector(dx: cos(angle) * 70, dy: sin(angle) * 70 - 30), born: now))
        }
        lastActivity = now
    }

    func step(now: Date, bounds size: CGSize) {
        bounds = size
        if !placed, size.width > 0 {
            position = CGPoint(x: 90, y: size.height - 60)
            placed = true
        }
        let dt = min(1 / 30, max(0, now.timeIntervalSince(lastStep ?? now)))
        lastStep = now

        updateTarget(now: now, size: size)

        let margin: CGFloat = 36
        var goal = target ?? position
        // A slow, meandering drift so it never sits perfectly still.
        let t = now.timeIntervalSinceReferenceDate
        goal.x += CGFloat(sin(t * 0.7) * 14 + sin(t * 1.9) * 5)
        goal.y += CGFloat(cos(t * 0.5) * 9)
        goal.x = min(max(goal.x, margin), size.width - margin)
        goal.y = min(max(goal.y, margin + 20), size.height - margin)

        // A soft, slightly underdamped spring: it trails behind and ambles over.
        let stiffness = 9.0, damping = 5.2
        let ax = stiffness * (goal.x - position.x) - damping * velocity.dx
        let ay = stiffness * (goal.y - position.y) - damping * velocity.dy
        velocity.dx += ax * dt
        velocity.dy += ay * dt
        position.x += velocity.dx * dt
        position.y += velocity.dy * dt

        hopVelocity -= 900 * dt
        hopHeight = max(0, hopHeight + hopVelocity * dt)
        if hopHeight == 0, hopVelocity < 0 { hopVelocity = 0 }

        if now >= nextBlink {
            blinkUntil = now.addingTimeInterval(0.14)
            nextBlink = now.addingTimeInterval(.random(in: 2.5 ... 5.5))
        }

        // Morsels that reached the mouth get eaten.
        particles.removeAll { morsel in
            let t = now.timeIntervalSince(morsel.born) / morsel.duration
            if t >= 1 {
                mouthOpenUntil = now.addingTimeInterval(0.16)
                fullness = min(1, fullness + 0.035)
                lastActivity = now
                return true
            }
            return false
        }
        if now > eatingUntil.addingTimeInterval(2.5) { fullness = max(0, fullness - dt * 0.12) }
        sparkles.removeAll { now.timeIntervalSince($0.born) > 0.6 }
    }

    var speed: CGFloat { hypot(velocity.dx, velocity.dy) }
    func isEating(_ now: Date) -> Bool { now < eatingUntil || !particles.isEmpty }
    func isAsleep(_ now: Date) -> Bool { now.timeIntervalSince(lastActivity) > 30 && !isEating(now) }
}

// MARK: - Sprite

enum MascotSprite {
    enum Pose: Hashable { case idle, blink, happy, chomp, sad, sleep }

    struct Frame {
        let pixels: [(x: Int, y: Int, color: Color)]
        let outline: [(x: Int, y: Int)]
    }

    private static let base: [String] = [
        "................",
        "..WW........WW..",
        "..WPW......WPW..",
        "..WWWWWWWWWWWW..",
        ".WWWWWWWWWWWWWW.",
        ".WWWHEWWWWHEWWW.",
        ".WWWEEWWWWEEWWW.",
        ".WPPWWWKKWWWPPW.",
        ".WWWWWMWWMWWWWW.",
        ".WWWWWWMMWWWWWW.",
        "..WWWWWWWWWWWW..",
        "..WWWWWWWWWWWW..",
        "..SWWWWWWWWWWS..",
        "...WWW....WWW...",
    ]

    private static let overrides: [Pose: [Int: String]] = [
        .idle: [:],
        .blink: [5: ".WWWWWWWWWWWWWW.", 6: ".WWWMMWWWWMMWWW."],
        .happy: [5: ".WWWWEWWWWEWWWW.", 6: ".WWWEWEWWEWEWWW."],
        .chomp: [5: ".WWWWEWWWWEWWWW.", 6: ".WWWEWEWWEWEWWW.",
                 8: ".WWWWMMMMMMWWWW.", 9: ".WWWWMKKKKMWWWW.", 10: "..WWWMMMMMMWWW.."],
        .sad: [5: ".WWWWWWWWWWWWWW.", 8: ".WWWWWWMMWWWWWW.", 9: ".WWWWWMWWMWWWWW."],
        .sleep: [5: ".WWWWWWWWWWWWWW.", 6: ".WWWMMWWWWMMWWW.", 8: ".WWWWWWWWWWWWWW.", 9: ".WWWWWWMMWWWWWW."],
    ]

    private static let walkFeet = "..WWW......WWW.."

    private static let palette: [Character: Color] = [
        "W": Color(red: 0.97, green: 0.97, blue: 1.0),
        "S": Color(red: 0.80, green: 0.84, blue: 0.96),
        "E": Color(red: 0.13, green: 0.14, blue: 0.27),
        "H": .white,
        "P": Color(red: 1.0, green: 0.73, blue: 0.83),
        "K": Color(red: 1.0, green: 0.52, blue: 0.67),
        "M": Color(red: 0.32, green: 0.17, blue: 0.30),
    ]

    private struct Key: Hashable {
        let pose: Pose
        let stride: Bool
    }

    @MainActor private static var cache: [Key: Frame] = [:]

    @MainActor
    static func frame(_ pose: Pose, stride: Bool) -> Frame {
        let key = Key(pose: pose, stride: stride)
        if let cached = cache[key] { return cached }
        var rows = base
        for (index, row) in overrides[pose] ?? [:] { rows[index] = row }
        if stride { rows[13] = walkFeet }

        let grid = rows.map(Array.init)
        var pixels: [(Int, Int, Color)] = []
        var outline: [(Int, Int)] = []
        for y in grid.indices {
            for x in grid[y].indices {
                if let color = palette[grid[y][x]] {
                    pixels.append((x, y, color))
                } else {
                    let neighbours = [(x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)]
                    let touches = neighbours.contains { nx, ny in
                        ny >= 0 && ny < grid.count && nx >= 0 && nx < grid[ny].count && grid[ny][nx] != "."
                    }
                    if touches { outline.append((x, y)) }
                }
            }
        }
        let frame = Frame(pixels: pixels.map { (x: $0.0, y: $0.1, color: $0.2) }, outline: outline.map { (x: $0.0, y: $0.1) })
        cache[key] = frame
        return frame
    }
}

// MARK: - Overlay

struct MascotOverlay: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let mascot = model.mascot
        GeometryReader { proxy in
            TimelineView(.animation) { context in
                let now = context.date
                let physics = mascot.physics
                let _ = physics.step(now: now, bounds: proxy.size)
                let pose = currentPose(physics: physics, mood: mascot.mood, now: now)
                let stride = physics.speed > 40 && Int(now.timeIntervalSinceReferenceDate * 8) % 2 == 0
                let frame = MascotSprite.frame(pose, stride: stride)

                ZStack(alignment: .topLeading) {
                    Canvas { ctx, _ in
                        drawMorsels(&ctx, physics: physics, now: now)
                        drawSparkles(&ctx, physics: physics, now: now)
                        drawMascot(&ctx, frame: frame, physics: physics, now: now, asleep: pose == .sleep)
                    }

                    if let bubble = mascot.bubble {
                        SpeechBubble(text: bubble.text)
                            .id(bubble.id)
                            .position(bubblePosition(physics: physics, in: proxy.size))
                            .transition(.scale(scale: 0.6, anchor: .bottom).combined(with: .opacity))
                    }
                }
            }
        }
        .allowsHitTesting(false)
        .ignoresSafeArea()
    }

    private func currentPose(physics: MascotPhysics, mood: MascotController.Mood, now: Date) -> MascotSprite.Pose {
        if physics.isEating(now) || mood == .eating {
            return now < physics.mouthOpenUntil ? .chomp : .happy
        }
        if physics.isAsleep(now) { return .sleep }
        if now < physics.blinkUntil { return .blink }
        switch mood {
        case .happy, .excited: return .happy
        case .sad: return .sad
        default: return .idle
        }
    }

    private func bubblePosition(physics: MascotPhysics, in size: CGSize) -> CGPoint {
        let halfWidth: CGFloat = 130
        let x = min(max(physics.position.x, halfWidth + 12), size.width - halfWidth - 12)
        let above = physics.position.y - physics.hopHeight - 78
        let y = above < 60 ? physics.position.y + 80 : above
        return CGPoint(x: x, y: y)
    }

    private func drawMascot(_ ctx: inout GraphicsContext, frame: MascotSprite.Frame, physics: MascotPhysics, now: Date, asleep: Bool) {
        let t = now.timeIntervalSinceReferenceDate
        let px = MascotPhysics.pixel
        let bob = asleep ? CGFloat(sin(t * 1.6)) * 1.5 : (physics.speed < 20 ? CGFloat(sin(t * 3)) * 2 : 0)
        let center = CGPoint(x: physics.position.x, y: physics.position.y - physics.hopHeight + bob)

        // Ground shadow and halo.
        let shadowWidth = 46 - min(20, physics.hopHeight * 0.2)
        ctx.fill(Path(ellipseIn: CGRect(x: physics.position.x - shadowWidth / 2, y: physics.position.y + 26, width: shadowWidth, height: 8)),
                 with: .color(.black.opacity(0.18)))
        let glow = 58 + 6 * sin(t * 2.2)
        ctx.fill(Path(ellipseIn: CGRect(x: center.x - glow, y: center.y - glow, width: glow * 2, height: glow * 2)),
                 with: .radialGradient(Gradient(colors: [.white.opacity(0.35), .white.opacity(0)]), center: center, startRadius: 4, endRadius: glow))

        let tilt = Angle.radians(Double(max(-0.25, min(0.25, physics.velocity.dx / 1600))))
        let squash = 1 + physics.fullness * 0.18

        ctx.drawLayer { layer in
            layer.translateBy(x: center.x, y: center.y)
            layer.rotate(by: tilt)
            layer.scaleBy(x: squash, y: 1 + physics.fullness * 0.05)
            layer.translateBy(x: -8 * px, y: -7 * px)
            layer.addFilter(.shadow(color: .white.opacity(0.9), radius: 7))

            let outlineColor = Color(red: 0.55, green: 0.6, blue: 0.9).opacity(0.5)
            for cell in frame.outline {
                layer.fill(Path(CGRect(x: CGFloat(cell.x) * px, y: CGFloat(cell.y) * px, width: px, height: px)), with: .color(outlineColor))
            }
            for cell in frame.pixels {
                layer.fill(Path(CGRect(x: CGFloat(cell.x) * px, y: CGFloat(cell.y) * px, width: px + 0.3, height: px + 0.3)), with: .color(cell.color))
            }
        }

        if asleep {
            for index in 0 ..< 3 {
                let phase = (t * 0.6 + Double(index) / 3).truncatingRemainder(dividingBy: 1)
                let point = CGPoint(x: center.x + 30 + CGFloat(phase) * 16, y: center.y - 30 - CGFloat(phase) * 34)
                ctx.draw(Text("z").font(.system(size: 10 + CGFloat(phase) * 8, weight: .bold, design: .monospaced))
                            .foregroundStyle(.white.opacity(1 - phase)), at: point)
            }
        }
    }

    private func drawMorsels(_ ctx: inout GraphicsContext, physics: MascotPhysics, now: Date) {
        let mouth = physics.mouth
        for morsel in physics.particles {
            let raw = now.timeIntervalSince(morsel.born) / morsel.duration
            guard raw >= 0 else { continue }
            let t = CGFloat(raw * raw * (3 - 2 * raw))   // smoothstep
            let control = CGPoint(x: (morsel.start.x + mouth.x) / 2, y: min(morsel.start.y, mouth.y) - morsel.lift)
            let x = (1 - t) * (1 - t) * morsel.start.x + 2 * (1 - t) * t * control.x + t * t * mouth.x
            let y = (1 - t) * (1 - t) * morsel.start.y + 2 * (1 - t) * t * control.y + t * t * mouth.y
            let scale = 1 - t * 0.6

            ctx.drawLayer { layer in
                layer.translateBy(x: x, y: y)
                layer.rotate(by: .radians(morsel.spin * Double(t)))
                layer.scaleBy(x: scale, y: scale)
                layer.addFilter(.shadow(color: morsel.color.opacity(0.8), radius: 4))
                // A tiny pixel document with a folded corner.
                let p: CGFloat = 3
                for row in 0 ..< 5 {
                    for column in 0 ..< 4 {
                        if row == 0 && column == 3 { continue }
                        let fold = row == 1 && column == 3
                        layer.fill(Path(CGRect(x: CGFloat(column) * p - 6, y: CGFloat(row) * p - 7.5, width: p, height: p)),
                                   with: .color(fold ? .white : morsel.color))
                    }
                }
            }
        }
    }

    private func drawSparkles(_ ctx: inout GraphicsContext, physics: MascotPhysics, now: Date) {
        for sparkle in physics.sparkles {
            let age = now.timeIntervalSince(sparkle.born)
            let progress = age / 0.6
            let point = CGPoint(x: sparkle.origin.x + sparkle.velocity.dx * age, y: sparkle.origin.y + sparkle.velocity.dy * age)
            ctx.fill(Path(CGRect(x: point.x - 2, y: point.y - 2, width: 4, height: 4)), with: .color(.white.opacity(1 - progress)))
        }
    }
}

struct SpeechBubble: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 12.5, weight: .medium, design: .rounded))
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .frame(maxWidth: 260)
            .glassEffect(.regular, in: .rect(cornerRadius: 16))
            .shadow(color: .white.opacity(0.25), radius: 10)
    }
}
