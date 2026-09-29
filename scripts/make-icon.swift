// Renders the Strata app icon: a glowing sunburst with Nibble peeking out.
import AppKit

let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext
let s = CGFloat(size)

// Squircle background
let inset: CGFloat = 100
let rect = CGRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
let bg = CGPath(roundedRect: rect, cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.saveGState()
ctx.addPath(bg); ctx.clip()
let colors = [NSColor(red: 0.08, green: 0.07, blue: 0.22, alpha: 1).cgColor, NSColor(red: 0.25, green: 0.10, blue: 0.40, alpha: 1).cgColor] as CFArray
let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])!
ctx.drawLinearGradient(gradient, start: CGPoint(x: 0, y: s), end: CGPoint(x: s, y: 0), options: [])

// Sunburst rings
let center = CGPoint(x: s / 2, y: s / 2 + 20)
let inner: CGFloat = 115, thickness: CGFloat = 78
let rings: [[Double]] = [[0.34, 0.22, 0.18, 0.14, 0.12], [0.2, 0.1, 0.08, 0.12, 0.1, 0.07, 0.09, 0.06], [0.1, 0.06, 0.05, 0.08, 0.04, 0.06, 0.07, 0.05, 0.09]]
for (r, weights) in rings.enumerated() {
    var angle = -Double.pi / 2
    let total = weights.reduce(0, +)
    for w in weights {
        let span = w / total * 2 * .pi * (r == 0 ? 1 : 0.92 - Double(r) * 0.12)
        let mid = angle + span / 2 + .pi / 2
        let hue = (mid / (2 * .pi) * 0.92 + 0.56).truncatingRemainder(dividingBy: 1)
        let color = NSColor(hue: hue, saturation: 0.62 - Double(r) * 0.07, brightness: 0.97 - Double(r) * 0.05, alpha: 1)
        let r0 = inner + CGFloat(r) * thickness + 5, r1 = r0 + thickness - 10
        let gap = 0.018
        let path = CGMutablePath()
        path.addArc(center: center, radius: r1, startAngle: -(angle + gap), endAngle: -(angle + span - gap), clockwise: true)
        path.addArc(center: center, radius: r0, startAngle: -(angle + span - gap), endAngle: -(angle + gap), clockwise: false)
        path.closeSubpath()
        ctx.addPath(path); ctx.setFillColor(color.cgColor); ctx.fillPath()
        angle += span
    }
}
// Glass center
ctx.setFillColor(NSColor(white: 1, alpha: 0.18).cgColor)
ctx.fillEllipse(in: CGRect(x: center.x - inner + 8, y: center.y - inner + 8, width: (inner - 8) * 2, height: (inner - 8) * 2))

// Nibble, pixel cat, bottom right
let sprite = ["..WW........WW..", "..WPW......WPW..", "..WWWWWWWWWWWW..", ".WWWWWWWWWWWWWW.", ".WWWHEWWWWHEWWW.", ".WWWEEWWWWEEWWW.", ".WPPWWWKKWWWPPW.", ".WWWWWMWWMWWWWW.", ".WWWWWWMMWWWWWW.", "..WWWWWWWWWWWW.."]
let px: CGFloat = 17
let origin = CGPoint(x: s - inset - 16 * px - 40, y: inset - 10)
ctx.setShadow(offset: .zero, blur: 40, color: NSColor.white.withAlphaComponent(0.9).cgColor)
for (y, row) in sprite.enumerated() {
    for (x, ch) in row.enumerated() {
        let c: NSColor? = switch ch {
        case "W", "H": NSColor(red: 0.97, green: 0.97, blue: 1, alpha: 1)
        case "E": NSColor(red: 0.13, green: 0.14, blue: 0.27, alpha: 1)
        case "P": NSColor(red: 1, green: 0.73, blue: 0.83, alpha: 1)
        case "K": NSColor(red: 1, green: 0.52, blue: 0.67, alpha: 1)
        case "M": NSColor(red: 0.32, green: 0.17, blue: 0.3, alpha: 1)
        default: nil
        }
        guard let c else { continue }
        ctx.setFillColor(c.cgColor)
        ctx.fill(CGRect(x: origin.x + CGFloat(x) * px, y: origin.y + CGFloat(sprite.count - 1 - y) * px, width: px + 0.5, height: px + 0.5))
    }
}
ctx.restoreGState()
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
