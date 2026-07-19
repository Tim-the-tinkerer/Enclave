import AppKit

let size: CGFloat = 1024
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

let backgroundTop = NSColor(calibratedRed: 0.12, green: 0.14, blue: 0.20, alpha: 1)
let backgroundBottom = NSColor(calibratedRed: 0.07, green: 0.08, blue: 0.12, alpha: 1)
let accent = NSColor(calibratedRed: 0.35, green: 0.62, blue: 0.98, alpha: 1)
let accentLight = NSColor(calibratedRed: 0.58, green: 0.78, blue: 1.00, alpha: 1)
let panel = NSColor(calibratedRed: 0.16, green: 0.19, blue: 0.27, alpha: 1)
let innerGlow = NSColor(calibratedRed: 0.22, green: 0.36, blue: 0.58, alpha: 1)
let dark = NSColor(calibratedRed: 0.08, green: 0.10, blue: 0.15, alpha: 1)

if let gradient = NSGradient(colors: [backgroundTop, backgroundBottom]) {
    gradient.draw(in: NSRect(x: 0, y: 0, width: size, height: size), angle: 90)
}

let shellRect = NSRect(x: 96, y: 96, width: 832, height: 832)
let shell = NSBezierPath(roundedRect: shellRect, xRadius: 196, yRadius: 196)
panel.setFill()
shell.fill()

accent.withAlphaComponent(0.22).setStroke()
shell.lineWidth = 12
shell.stroke()

let outerRing = NSBezierPath(ovalIn: NSRect(x: 172, y: 172, width: 680, height: 680))
accent.withAlphaComponent(0.28).setStroke()
outerRing.lineWidth = 18
outerRing.stroke()

let chamber = NSBezierPath(ovalIn: NSRect(x: 252, y: 252, width: 520, height: 520))
innerGlow.setFill()
chamber.fill()

accent.withAlphaComponent(0.45).setStroke()
chamber.lineWidth = 10
chamber.stroke()

let sanctum = NSBezierPath(ovalIn: NSRect(x: 332, y: 332, width: 360, height: 360))
dark.setFill()
sanctum.fill()

accent.withAlphaComponent(0.18).setFill()
sanctum.fill()

let core = NSBezierPath(ovalIn: NSRect(x: 412, y: 412, width: 200, height: 200))
accent.setFill()
core.fill()

accentLight.withAlphaComponent(0.35).setFill()
NSBezierPath(ovalIn: NSRect(x: 432, y: 452, width: 120, height: 80)).fill()

let lockBody = NSBezierPath(roundedRect: NSRect(x: 472, y: 448, width: 80, height: 72), xRadius: 14, yRadius: 14)
dark.setFill()
lockBody.fill()

let shackle = NSBezierPath()
shackle.appendArc(
    withCenter: NSPoint(x: 512, y: 530),
    radius: 28,
    startAngle: 0,
    endAngle: 180,
    clockwise: false
)
shackle.lineWidth = 16
shackle.lineCapStyle = .round
accentLight.setStroke()
shackle.stroke()

let label = "E" as NSString
let attributes: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 430, weight: .heavy),
    .foregroundColor: accentLight
]
let textSize = label.size(withAttributes: attributes)
label.draw(
    at: NSPoint(x: (size - textSize.width) / 2 - 8, y: (size - textSize.height) / 2 - 24),
    withAttributes: attributes
)

let name = "enclave" as NSString
let nameAttributes: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 92, weight: .semibold),
    .foregroundColor: accentLight.withAlphaComponent(0.92),
    .kern: 10.0
]
let nameSize = name.size(withAttributes: nameAttributes)
name.draw(
    at: NSPoint(x: (size - nameSize.width) / 2, y: 148),
    withAttributes: nameAttributes
)

for index in 0..<12 {
    let angle = CGFloat(index) * (.pi * 2 / 12) - .pi / 2
    let cx: CGFloat = 512
    let cy: CGFloat = 512
    let inner: CGFloat = 318
    let outer: CGFloat = 338
    let tick = NSBezierPath()
    tick.move(to: NSPoint(x: cx + cos(angle) * inner, y: cy + sin(angle) * inner))
    tick.line(to: NSPoint(x: cx + cos(angle) * outer, y: cy + sin(angle) * outer))
    tick.lineWidth = 10
    tick.lineCapStyle = .round
    accent.withAlphaComponent(0.55).setStroke()
    tick.stroke()
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("Failed to create icon\n", stderr)
    exit(1)
}

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.png"
try png.write(to: URL(fileURLWithPath: output))
print("Wrote \(output)")