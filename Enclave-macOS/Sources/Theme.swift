import AppKit

enum Theme {
    static let background = NSColor(calibratedRed: 0.11, green: 0.12, blue: 0.16, alpha: 1.0)
    static let panel = NSColor(calibratedRed: 0.16, green: 0.18, blue: 0.24, alpha: 1.0)
    static let accent = NSColor(calibratedRed: 0.35, green: 0.62, blue: 0.98, alpha: 1.0)
    static let text = NSColor(calibratedRed: 0.92, green: 0.93, blue: 0.95, alpha: 1.0)
    static let muted = NSColor(calibratedRed: 0.58, green: 0.62, blue: 0.70, alpha: 1.0)
    static let border = NSColor(calibratedRed: 0.28, green: 0.32, blue: 0.40, alpha: 1.0)

    static let title = NSFont.systemFont(ofSize: 24, weight: .bold)
    static let body = NSFont.systemFont(ofSize: 13, weight: .regular)
    static let monospaced = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
}

extension NSView {
    func applyPanelStyle() {
        wantsLayer = true
        layer?.backgroundColor = Theme.panel.cgColor
        layer?.cornerRadius = 10
        layer?.borderWidth = 1
        layer?.borderColor = Theme.border.cgColor
    }
}

extension NSTextField {
    static func makeLabel(_ text: String, muted: Bool = false) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.textColor = muted ? Theme.muted : Theme.text
        field.font = Theme.body
        return field
    }

    static func makeInput(placeholder: String = "") -> NSTextField {
        let field = NSTextField(string: "")
        field.placeholderString = placeholder
        field.isBordered = true
        field.isBezeled = true
        field.bezelStyle = .roundedBezel
        field.font = Theme.monospaced
        field.textColor = Theme.text
        field.backgroundColor = NSColor(calibratedWhite: 0.14, alpha: 1.0)
        field.focusRingType = .none
        return field
    }
}

extension NSButton {
    static func makePrimary(_ title: String) -> NSButton {
        let button = NSButton(title: title, target: nil, action: nil)
        button.bezelStyle = .rounded
        button.font = Theme.body
        button.contentTintColor = Theme.accent
        return button
    }

    static func makeSecondary(_ title: String) -> NSButton {
        let button = NSButton(title: title, target: nil, action: nil)
        button.bezelStyle = .rounded
        button.font = Theme.body
        return button
    }
}