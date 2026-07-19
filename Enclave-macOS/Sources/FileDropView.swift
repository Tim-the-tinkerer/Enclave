import AppKit

enum FileDropLogic {
    static func dragOperation(for sender: NSDraggingInfo) -> NSDragOperation {
        fileURLs(from: sender).isEmpty ? [] : .copy
    }

    static func setDropHighlight(on view: NSView?, active: Bool) {
        view?.wantsLayer = true
        view?.layer?.borderWidth = active ? 2 : 0
        view?.layer?.borderColor = active ? Theme.accent.cgColor : nil
        view?.layer?.cornerRadius = active ? 10 : 0
    }

    static func performDrop(_ sender: NSDraggingInfo, handler: ([URL]) -> Void) -> Bool {
        let urls = fileURLs(from: sender)
        guard !urls.isEmpty else { return false }
        handler(urls)
        return true
    }

    static func fileURLs(from sender: NSDraggingInfo) -> [URL] {
        let options: [NSPasteboard.ReadingOptionKey: Any] = [
            .urlReadingFileURLsOnly: true
        ]
        guard let items = sender.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: options
        ) as? [URL], !items.isEmpty else {
            return []
        }
        return items
    }
}

final class FileDropView: NSView {
    var onFilesDropped: (([URL]) -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        registerForDraggedTypes([.fileURL])
        wantsLayer = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        let operation = FileDropLogic.dragOperation(for: sender)
        FileDropLogic.setDropHighlight(on: self, active: operation != [])
        return operation
    }

    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation {
        FileDropLogic.dragOperation(for: sender)
    }

    override func draggingExited(_ sender: NSDraggingInfo?) {
        FileDropLogic.setDropHighlight(on: self, active: false)
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        FileDropLogic.setDropHighlight(on: self, active: false)
        guard let onFilesDropped else { return false }
        return FileDropLogic.performDrop(sender, handler: onFilesDropped)
    }
}