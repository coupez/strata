import SwiftUI

// MARK: - Layout

struct SunburstSegment {
    let node: FileNode
    let depth: Int
    let start: Double   // radians, clockwise from 12 o'clock
    let end: Double
    let isRemainder: Bool
}

enum SunburstLayout {
    static let rings = 5
    static let minAngle = 0.005
    static let maxSegments = 5000

    static func build(focus: FileNode) -> [SunburstSegment] {
        var segments: [SunburstSegment] = []
        segments.reserveCapacity(1024)

        func place(_ node: FileNode, from start: Double, to end: Double, depth: Int) {
            guard depth < rings, node.size > 0, segments.count < maxSegments else { return }
            let span = end - start
            var cursor = start
            for child in node.children {
                let width = span * Double(child.size) / Double(node.size)
                if width < minAngle { break }   // children are sorted, the rest are smaller
                segments.append(SunburstSegment(node: child, depth: depth, start: cursor, end: cursor + width, isRemainder: false))
                if child.isDirectory { place(child, from: cursor, to: cursor + width, depth: depth + 1) }
                cursor += width
            }
            if end - cursor > minAngle * 0.5 {
                segments.append(SunburstSegment(node: node, depth: depth, start: cursor, end: end, isRemainder: true))
            }
        }

        place(focus, from: 0, to: 2 * .pi, depth: 0)
        return segments
    }

    static func midAngles(_ segments: [SunburstSegment]) -> [ObjectIdentifier: Double] {
        var angles: [ObjectIdentifier: Double] = [:]
        for segment in segments where segment.depth == 0 && !segment.isRemainder {
            angles[segment.node.id] = (segment.start + segment.end) / 2
        }
        return angles
    }

    /// Exact angular range of `node` when `ancestor` fills the full circle.
    static func angleRange(of node: FileNode, within ancestor: FileNode) -> (Double, Double) {
        var start = 0.0
        var span = 2 * Double.pi
        let chain = node.ancestry
        guard let top = chain.firstIndex(where: { $0 === ancestor }) else { return (0, span) }
        for index in top ..< chain.count - 1 {
            let parent = chain[index]
            let child = chain[index + 1]
            guard parent.size > 0 else { break }
            var preceding: Int64 = 0
            for sibling in parent.children {
                if sibling === child { break }
                preceding += sibling.size
            }
            start += span * Double(preceding) / Double(parent.size)
            span *= Double(child.size) / Double(parent.size)
        }
        return (start, start + span)
    }
}

/// Maps the previous picture onto the new one so zooming feels continuous.
/// Screen angle = alpha * worldAngle + beta, screen ring = depth + delta,
/// with (alpha, beta, delta) interpolated to identity as the animation runs.
struct SunburstTransition {
    var alpha0 = 1.0
    var beta0 = 0.0
    var delta0 = 0.0
    // Previous layout expressed in the new layout's world: angle = s * old + o, ring = old + dr.
    var s = 1.0
    var o = 0.0
    var dr = 0.0
    var previous: [SunburstSegment] = []
    var crossfade = false

    static let identity = SunburstTransition()
    static let sweepIn = SunburstTransition(alpha0: 0.001, beta0: 0, delta0: -1.2)

    init(alpha0: Double = 1, beta0: Double = 0, delta0: Double = 0) {
        self.alpha0 = alpha0
        self.beta0 = beta0
        self.delta0 = delta0
    }

    init(zoomingInto range: (Double, Double), depth: Int, previous: [SunburstSegment]) {
        let width = max(range.1 - range.0, 1e-9)
        s = 2 * .pi / width
        o = -range.0 * s
        dr = -Double(depth)
        alpha0 = 1 / s
        beta0 = -o / s
        delta0 = -dr
        self.previous = previous
    }

    init(zoomingOutOf range: (Double, Double), depth: Int, previous: [SunburstSegment]) {
        let width = max(range.1 - range.0, 1e-9)
        s = width / (2 * .pi)
        o = range.0
        dr = Double(depth)
        alpha0 = 1 / s
        beta0 = -o / s
        delta0 = -dr
        self.previous = previous
    }

    init(crossfadeFrom previous: [SunburstSegment]) {
        self.previous = previous
        crossfade = true
    }
}

struct SunburstGeometry {
    let center: CGPoint
    let outerRadius: CGFloat
    let innerRadius: CGFloat
    let rings: Int

    init(size: CGSize, rings: Int) {
        center = CGPoint(x: size.width / 2, y: size.height / 2)
        outerRadius = max(60, min(size.width, size.height) / 2 - 8)
        innerRadius = outerRadius * 0.3
        self.rings = rings
    }

    var ringThickness: CGFloat { (outerRadius - innerRadius) / CGFloat(rings) }

    func hit(_ point: CGPoint) -> (ring: Int, angle: Double)? {
        let dx = Double(point.x - center.x)
        let dy = Double(point.y - center.y)
        let radius = CGFloat(hypot(dx, dy))
        guard radius >= innerRadius, radius <= outerRadius else { return nil }
        var angle = atan2(dx, -dy)
        if angle < 0 { angle += 2 * .pi }
        return (Int((radius - innerRadius) / ringThickness), angle)
    }
}

enum SunburstPalette {
    /// Hue follows the on-screen angle, so colors stay continuous while zooming.
    static func color(mid: Double, ring: Double, kind: FileNode.Kind) -> Color {
        switch kind {
        case .aggregate: return Color(white: 0.62)
        case .hidden: return Color(white: 0.4)
        default: break
        }
        var hue = (mid / (2 * .pi)) * 0.92 + 0.56
        hue -= hue.rounded(.down)
        var saturation = 0.66 - ring * 0.07
        var brightness = 0.97 - ring * 0.055
        if kind == .file {
            saturation *= 0.5
            brightness = min(1, brightness + 0.02)
        }
        return Color(hue: hue, saturation: max(0.12, saturation), brightness: brightness)
    }
}

// MARK: - Canvas

struct SunburstCanvas: View, Animatable {
    var step: Double
    let targetStep: Double
    let segments: [SunburstSegment]
    let transition: SunburstTransition
    let hovered: FileNode?
    let selectedIDs: Set<ObjectIdentifier>
    let geometry: SunburstGeometry

    var animatableData: Double {
        get { step }
        set { step = newValue }
    }

    var body: some View {
        Canvas { context, _ in
            let t = min(1, max(0, step - (targetStep - 1)))
            let tr = transition
            let alpha = tr.alpha0 + (1 - tr.alpha0) * t
            let beta = tr.beta0 * (1 - t)
            let delta = tr.delta0 * (1 - t)
            var selectedPath = Path()
            var hoveredPath: Path?

            if t < 1 {
                for segment in tr.previous {
                    let a0 = alpha * (tr.s * segment.start + tr.o) + beta
                    let a1 = alpha * (tr.s * segment.end + tr.o) + beta
                    _ = draw(segment, a0, a1, ring: Double(segment.depth) + tr.dr + delta, opacity: 1 - t, in: &context)
                }
            }

            let opacity = tr.crossfade ? t : 1
            for segment in segments {
                guard let path = draw(segment, alpha * segment.start + beta, alpha * segment.end + beta,
                                      ring: Double(segment.depth) + delta, opacity: opacity, in: &context) else { continue }
                if !segment.isRemainder {
                    if isSelected(segment.node) { selectedPath.addPath(path) }
                    if t >= 1, segment.node === hovered { hoveredPath = path }
                }
            }

            if !selectedPath.isEmpty {
                context.fill(selectedPath, with: .color(Color(hue: 0.99, saturation: 0.72, brightness: 0.95).opacity(0.78 * opacity)))
                context.drawLayer { layer in
                    layer.clip(to: selectedPath)
                    var stripes = Path()
                    let r = geometry.outerRadius
                    var x = -r * 2
                    while x < r * 2 {
                        stripes.move(to: CGPoint(x: geometry.center.x + x, y: geometry.center.y - r))
                        stripes.addLine(to: CGPoint(x: geometry.center.x + x + 2 * r, y: geometry.center.y + r))
                        x += 9
                    }
                    layer.stroke(stripes, with: .color(.white.opacity(0.22)), lineWidth: 3)
                }
                context.stroke(selectedPath, with: .color(.white.opacity(0.85)), lineWidth: 1)
            }
            if let hoveredPath {
                context.fill(hoveredPath, with: .color(.white.opacity(0.22)))
                context.stroke(hoveredPath, with: .color(.white), lineWidth: 2)
            }
        }
    }

    private func isSelected(_ node: FileNode) -> Bool {
        guard !selectedIDs.isEmpty else { return false }
        var current: FileNode? = node
        while let item = current {
            if selectedIDs.contains(item.id) { return true }
            current = item.parent
        }
        return false
    }

    private func draw(_ segment: SunburstSegment, _ rawStart: Double, _ rawEnd: Double, ring: Double, opacity: Double, in context: inout GraphicsContext) -> Path? {
        var start = max(0, rawStart)
        var end = min(2 * .pi, rawEnd)
        guard end - start > 0.0006, ring > -1 else { return nil }

        let lastRing = Double(geometry.rings - 1)
        var ringAlpha = 1.0
        if ring > lastRing { ringAlpha = max(0, 1 - (ring - lastRing)) }
        if ring < 0 { ringAlpha = max(0, 1 + ring) }
        let alpha = opacity * ringAlpha
        guard alpha > 0.01 else { return nil }

        let thickness = geometry.ringThickness
        let inner = max(2, geometry.innerRadius + CGFloat(ring) * thickness + 1.5)
        let outer = geometry.innerRadius + CGFloat(ring + 1) * thickness - 1.5
        guard outer > inner else { return nil }

        let gap = min((end - start) * 0.2, Double(1.1 / outer))
        start += gap
        end -= gap

        var path = Path()
        path.addRelativeArc(center: geometry.center, radius: outer, startAngle: .radians(start - .pi / 2), delta: .radians(end - start))
        path.addRelativeArc(center: geometry.center, radius: inner, startAngle: .radians(end - .pi / 2), delta: .radians(start - end))
        path.closeSubpath()

        let mid = (start + end) / 2
        if segment.isRemainder {
            context.fill(path, with: .color(Color(white: 0.55).opacity(0.28 * alpha)))
        } else {
            let base = SunburstPalette.color(mid: mid, ring: ring, kind: segment.node.kind)
            let light = base.mix(with: .white, by: 0.28)
            context.fill(path, with: .radialGradient(
                Gradient(colors: [light.opacity(alpha), base.opacity(alpha)]),
                center: geometry.center, startRadius: inner, endRadius: outer
            ))
        }
        return path
    }
}

// MARK: - View

struct SunburstView: View {
    @Environment(AppModel.self) private var model
    @State private var animatedStep: Double = 0

    var body: some View {
        GeometryReader { proxy in
            let geometry = SunburstGeometry(size: proxy.size, rings: SunburstLayout.rings)
            ZStack {
                // A soft glow behind the rings.
                Circle()
                    .fill(RadialGradient(colors: [.white.opacity(0.18), .clear], center: .center,
                                         startRadius: geometry.innerRadius, endRadius: geometry.outerRadius * 1.1))
                    .frame(width: geometry.outerRadius * 2.2, height: geometry.outerRadius * 2.2)
                    .position(geometry.center)
                    .blur(radius: 20)

                SunburstCanvas(
                    step: animatedStep,
                    targetStep: Double(model.transitionID),
                    segments: model.layout,
                    transition: model.transition,
                    hovered: model.hovered,
                    selectedIDs: model.selectedIDs,
                    geometry: geometry
                )

                CenterDisc(diameter: geometry.innerRadius * 2 - 12)
                    .position(geometry.center)
            }
            .contentShape(Rectangle())
            .onContinuousHover { phase in
                switch phase {
                case .active(let point): model.setHovered(node(at: point, geometry: geometry))
                case .ended: model.setHovered(nil)
                }
            }
            .onTapGesture { point in
                guard let node = node(at: point, geometry: geometry) else { return }
                if NSEvent.modifierFlags.contains(.command) {
                    model.toggleSelection(node)
                } else if node.isDirectory {
                    model.zoom(into: node)
                } else {
                    model.toggleSelection(node)
                }
            }
            .contextMenu {
                if let node = model.hovered { NodeMenu(node: node) }
            }
            .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { model.sunburstFrame = $0 }
        }
        .onChange(of: model.transitionID, initial: true) {
            withAnimation(.smooth(duration: 0.75)) { animatedStep = Double(model.transitionID) }
        }
    }

    private func node(at point: CGPoint, geometry: SunburstGeometry) -> FileNode? {
        guard let hit = geometry.hit(point) else { return nil }
        let segment = model.layout.first {
            $0.depth == hit.ring && $0.start <= hit.angle && hit.angle < $0.end
        }
        guard let segment, !segment.isRemainder else { return nil }
        return segment.node
    }
}

struct CenterDisc: View {
    @Environment(AppModel.self) private var model
    let diameter: CGFloat

    var body: some View {
        let node = model.hovered ?? model.focus
        Button { model.zoomOut() } label: {
            VStack(spacing: diameter * 0.025) {
                if let node {
                    Image(systemName: symbol(for: node))
                        .font(.system(size: diameter * 0.1, weight: .semibold))
                        .foregroundStyle(.secondary)
                    Text(node.displayName)
                        .font(.system(size: max(11, diameter * 0.075), weight: .semibold))
                        .lineLimit(2)
                        .multilineTextAlignment(.center)
                        .truncationMode(.middle)
                    Text(node.size.bytes)
                        .font(.system(size: diameter * 0.13, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .contentTransition(.numericText())
                    Text(subtitle(for: node))
                        .font(.system(size: max(10, diameter * 0.055)))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if model.hovered == nil, model.focus?.parent != nil {
                        Label("Back", systemImage: "arrow.up.left")
                            .font(.system(size: max(9, diameter * 0.05), weight: .medium))
                            .foregroundStyle(.tertiary)
                            .padding(.top, 2)
                    }
                }
            }
            .padding(diameter * 0.13)
            .frame(width: diameter, height: diameter)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.interactive(), in: .circle)
        .animation(.snappy(duration: 0.2), value: model.hovered?.id)
    }

    private func symbol(for node: FileNode) -> String {
        switch node.kind {
        case .directory: node.parent == nil ? (model.target?.symbol ?? "internaldrive.fill") : "folder.fill"
        case .file: "doc.fill"
        case .aggregate: "square.stack.3d.up.fill"
        case .hidden: "lock.fill"
        }
    }

    private func subtitle(for node: FileNode) -> String {
        if let focus = model.focus, node !== focus {
            return "\(percentString(node.size, of: focus.size)) of \(focus.displayName)"
        }
        return "\(node.itemCount.formatted()) files"
    }
}
