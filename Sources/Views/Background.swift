import SwiftUI

/// Slowly drifting mesh gradient that gives the glass something to refract.
struct AmbientBackground: View {
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 20)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            MeshGradient(
                width: 3,
                height: 3,
                points: [
                    [0, 0], [Float(0.5 + 0.12 * sin(t * 0.21)), 0], [1, 0],
                    [0, Float(0.5 + 0.14 * sin(t * 0.17))],
                    [Float(0.5 + 0.18 * sin(t * 0.23)), Float(0.5 + 0.16 * cos(t * 0.19))],
                    [1, Float(0.5 + 0.14 * cos(t * 0.25))],
                    [0, 1], [Float(0.5 + 0.12 * cos(t * 0.15)), 1], [1, 1],
                ],
                colors: colorScheme == .dark ? Self.dark : Self.light
            )
        }
        .ignoresSafeArea()
    }

    private static let dark: [Color] = [
        Color(red: 0.05, green: 0.06, blue: 0.16), Color(red: 0.13, green: 0.07, blue: 0.27), Color(red: 0.04, green: 0.12, blue: 0.22),
        Color(red: 0.10, green: 0.05, blue: 0.22), Color(red: 0.20, green: 0.10, blue: 0.34), Color(red: 0.03, green: 0.18, blue: 0.26),
        Color(red: 0.03, green: 0.05, blue: 0.13), Color(red: 0.16, green: 0.06, blue: 0.20), Color(red: 0.06, green: 0.08, blue: 0.18),
    ]

    private static let light: [Color] = [
        Color(red: 0.86, green: 0.90, blue: 1.00), Color(red: 0.93, green: 0.86, blue: 1.00), Color(red: 0.84, green: 0.95, blue: 0.98),
        Color(red: 0.97, green: 0.88, blue: 0.95), Color(red: 0.90, green: 0.87, blue: 1.00), Color(red: 0.85, green: 0.93, blue: 1.00),
        Color(red: 0.99, green: 0.92, blue: 0.88), Color(red: 0.92, green: 0.88, blue: 0.99), Color(red: 0.87, green: 0.92, blue: 0.99),
    ]
}

/// Decorative mini sunburst used on the welcome screen.
struct StrataGlyph: View {
    var body: some View {
        TimelineView(.animation) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                let center = CGPoint(x: size.width / 2, y: size.height / 2)
                let outer = min(size.width, size.height) / 2
                let inner = outer * 0.32
                let rings = 3
                let thickness = (outer - inner) / CGFloat(rings)
                for ring in 0 ..< rings {
                    let count = 3 + ring * 3
                    let rotation = t * (0.25 - Double(ring) * 0.08)
                    for index in 0 ..< count {
                        let start = Double(index) / Double(count) * 2 * .pi + rotation
                        let span = 2 * .pi / Double(count) * (0.55 + 0.4 * abs(sin(Double(index * 7 + ring * 3))))
                        var path = Path()
                        let r0 = inner + CGFloat(ring) * thickness + 2
                        let r1 = r0 + thickness - 4
                        path.addRelativeArc(center: center, radius: r1, startAngle: .radians(start), delta: .radians(span))
                        path.addRelativeArc(center: center, radius: r0, startAngle: .radians(start + span), delta: .radians(-span))
                        path.closeSubpath()
                        let mid = start + span / 2
                        ctx.fill(path, with: .color(SunburstPalette.color(mid: mid.truncatingRemainder(dividingBy: 2 * .pi) + (mid < 0 ? 2 * .pi : 0), ring: Double(ring), kind: .directory)))
                    }
                }
            }
        }
        .shadow(color: .purple.opacity(0.4), radius: 24)
    }
}
