// Renders Nibble as an animated GIF (idle, blink, chomp) for the README.
import AppKit
import ImageIO
import UniformTypeIdentifiers

let base = [
    "................", "..WW........WW..", "..WPW......WPW..", "..WWWWWWWWWWWW..", ".WWWWWWWWWWWWWW.",
    ".WWWHEWWWWHEWWW.", ".WWWEEWWWWEEWWW.", ".WPPWWWKKWWWPPW.", ".WWWWWMWWMWWWWW.", ".WWWWWWMMWWWWWW.",
    "..WWWWWWWWWWWW..", "..WWWWWWWWWWWW..", "..SWWWWWWWWWWS..", "...WWW....WWW...",
]
func pose(_ overrides: [Int: String]) -> [String] {
    var rows = base
    for (i, r) in overrides { rows[i] = r }
    return rows
}
let idle = base
let blink = pose([5: ".WWWWWWWWWWWWWW.", 6: ".WWWMMWWWWMMWWW."])
let happy = pose([5: ".WWWWEWWWWEWWWW.", 6: ".WWWEWEWWEWEWWW."])
let chomp = pose([5: ".WWWWEWWWWEWWWW.", 6: ".WWWEWEWWEWEWWW.", 8: ".WWWWMMMMMMWWWW.", 9: ".WWWWMKKKKMWWWW.", 10: "..WWWMMMMMMWWW.."])

let colors: [Character: NSColor] = [
    "W": NSColor(red: 0.97, green: 0.97, blue: 1, alpha: 1), "H": .white,
    "S": NSColor(red: 0.80, green: 0.84, blue: 0.96, alpha: 1), "E": NSColor(red: 0.13, green: 0.14, blue: 0.27, alpha: 1),
    "P": NSColor(red: 1, green: 0.73, blue: 0.83, alpha: 1), "K": NSColor(red: 1, green: 0.52, blue: 0.67, alpha: 1),
    "M": NSColor(red: 0.32, green: 0.17, blue: 0.30, alpha: 1),
]
let outline = NSColor(red: 0.55, green: 0.6, blue: 0.9, alpha: 0.55)
let px = 12, pad = 24, bob = [0, 0, 1, 1, 0, 0, -1, -1]
let width = 16 * px + pad * 2, height = 14 * px + pad * 2

func render(_ rows: [String], dy: Int, morsel: CGFloat?) -> CGImage {
    let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let grid = rows.map(Array.init)
    func cell(_ x: Int, _ y: Int, _ c: NSColor) {
        ctx.setFillColor(c.cgColor)
        ctx.fill(CGRect(x: pad + x * px, y: height - pad - (y + 1) * px + dy * 2, width: px, height: px))
    }
    for y in grid.indices { for x in grid[y].indices where grid[y][x] == "." {
        let n = [(x-1,y),(x+1,y),(x,y-1),(x,y+1)].contains { nx, ny in ny >= 0 && ny < grid.count && nx >= 0 && nx < 16 && grid[ny][nx] != "." }
        if n { cell(x, y, outline) }
    } }
    for y in grid.indices { for x in grid[y].indices { if let c = colors[grid[y][x]] { cell(x, y, c) } } }
    if let m = morsel {   // a tiny pixel file flying into the mouth
        let mx = CGFloat(width) - 20 - m * CGFloat(width / 2 - 10), my = CGFloat(height) * 0.62 + sin(m * .pi) * 30
        ctx.setFillColor(NSColor.systemPink.cgColor)
        ctx.fill(CGRect(x: mx, y: my, width: 12, height: 15))
        ctx.setFillColor(NSColor.white.cgColor)
        ctx.fill(CGRect(x: mx + 8, y: my + 11, width: 4, height: 4))
    }
    return ctx.makeImage()!
}

var frames: [(CGImage, Double)] = []
for i in 0 ..< 8 { frames.append((render(idle, dy: bob[i], morsel: nil), 0.12)) }
frames.append((render(blink, dy: 0, morsel: nil), 0.12))
for i in 0 ..< 6 { frames.append((render(idle, dy: bob[i], morsel: nil), 0.12)) }
for round in 0 ..< 3 {
    for s in 0 ..< 5 { frames.append((render(happy, dy: 0, morsel: CGFloat(s) / 5), 0.06)) }
    frames.append((render(chomp, dy: 0, morsel: nil), 0.14))
    frames.append((render(happy, dy: round == 2 ? 2 : 0, morsel: nil), 0.14))
}
frames.append((render(happy, dy: 4, morsel: nil), 0.5))

let out = URL(fileURLWithPath: CommandLine.arguments[1])
let dest = CGImageDestinationCreateWithURL(out as CFURL, UTType.gif.identifier as CFString, frames.count, nil)!
CGImageDestinationSetProperties(dest, [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFLoopCount: 0]] as CFDictionary)
for (image, delay) in frames {
    CGImageDestinationAddImage(dest, image, [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFDelayTime: delay]] as CFDictionary)
}
CGImageDestinationFinalize(dest)
