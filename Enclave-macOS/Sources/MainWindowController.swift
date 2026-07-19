import AppKit
import UniformTypeIdentifiers

final class MainWindowController: NSWindowController {
    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 460),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Enclave"
        window.center()
        window.backgroundColor = Theme.background
        window.minSize = NSSize(width: 480, height: 400)
        window.isReleasedWhenClosed = false

        super.init(window: window)
        window.contentViewController = MainViewController()
    }

    var mainViewController: MainViewController? {
        contentViewController as? MainViewController
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

final class MainViewController: NSViewController {
    private var selectedURL: URL?
    private var isBusy = false

    private let statusLabel = NSTextField.makeLabel("Ready.")
    private let passwordField = NSSecureTextField(string: "")
    private let chooseButton = NSButton.makeSecondary("Choose…")
    private let clearButton = NSButton.makeSecondary("Clear")
    private let inputPathField = NSTextField.makeInput(placeholder: "No file or folder selected")
    private let encryptFilenameSwitch = NSSwitch()
    private let encryptButton = NSButton.makePrimary("Encrypt")
    private let decryptButton = NSButton.makePrimary("Decrypt")

    override func loadView() {
        let dropView = FileDropView(frame: NSRect(x: 0, y: 0, width: 520, height: 460))
        dropView.layer?.backgroundColor = Theme.background.cgColor
        dropView.onFilesDropped = { [weak self] urls in
            self?.openFiles(urls)
        }
        view = dropView

        let root = NSStackView()
        root.translatesAutoresizingMaskIntoConstraints = false
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 16
        view.addSubview(root)

        root.addArrangedSubview(makeHeader())
        root.addArrangedSubview(makePasswordPanel())
        root.addArrangedSubview(makeOptionsPanel())
        root.addArrangedSubview(makeFilePanel())
        root.addArrangedSubview(makeActionPanel())
        root.addArrangedSubview(makeStatusPanel())

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            root.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            root.topAnchor.constraint(equalTo: view.topAnchor, constant: 24),
            root.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -24)
        ])
    }

    private func makeHeader() -> NSView {
        let title = NSTextField(labelWithString: "Enclave")
        title.font = Theme.title
        title.textColor = Theme.accent

        let subtitle = NSTextField(labelWithString: "AES-256-GCM · Argon2id keys · filename privacy optional")
        subtitle.font = Theme.body
        subtitle.textColor = Theme.muted

        let stack = NSStackView(views: [title, subtitle])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        return stack
    }

    private func makePasswordPanel() -> NSView {
        let panel = NSStackView()
        panel.orientation = .vertical
        panel.alignment = .leading
        panel.spacing = 8
        panel.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        panel.applyPanelStyle()

        panel.addArrangedSubview(sectionTitle("PASSWORD"))

        passwordField.placeholderString = "Enter password"
        passwordField.isBordered = true
        passwordField.isBezeled = true
        passwordField.bezelStyle = .roundedBezel
        passwordField.font = Theme.body
        passwordField.translatesAutoresizingMaskIntoConstraints = false
        passwordField.widthAnchor.constraint(equalToConstant: 440).isActive = true
        panel.addArrangedSubview(passwordField)

        return panel
    }

    private func makeOptionsPanel() -> NSView {
        let panel = NSStackView()
        panel.orientation = .vertical
        panel.alignment = .leading
        panel.spacing = 8
        panel.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        panel.applyPanelStyle()

        panel.addArrangedSubview(sectionTitle("OPTIONS"))

        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 10
        row.alignment = .centerY

        let label = NSTextField(labelWithString: "Encrypt filename")
        label.font = Theme.body
        label.textColor = Theme.text
        row.addArrangedSubview(label)

        encryptFilenameSwitch.state = .on
        row.addArrangedSubview(encryptFilenameSwitch)

        panel.addArrangedSubview(row)

        let hint = NSTextField(labelWithString: "Off keeps the original name in the archive and as the saved .enclave filename.")
        hint.font = NSFont.systemFont(ofSize: 11)
        hint.textColor = Theme.muted
        hint.lineBreakMode = .byWordWrapping
        hint.maximumNumberOfLines = 0
        hint.preferredMaxLayoutWidth = 440
        panel.addArrangedSubview(hint)

        return panel
    }

    private func makeFilePanel() -> NSView {
        let panel = NSStackView()
        panel.orientation = .vertical
        panel.alignment = .leading
        panel.spacing = 8
        panel.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        panel.applyPanelStyle()

        panel.addArrangedSubview(sectionTitle("FILE OR FOLDER"))

        let hint = NSTextField(labelWithString: "Drag a file or folder to encrypt, or a .enclave archive to decrypt.")
        hint.font = NSFont.systemFont(ofSize: 11)
        hint.textColor = Theme.muted
        hint.lineBreakMode = .byWordWrapping
        hint.maximumNumberOfLines = 0
        hint.preferredMaxLayoutWidth = 440
        panel.addArrangedSubview(hint)

        inputPathField.isEditable = false
        inputPathField.translatesAutoresizingMaskIntoConstraints = false
        inputPathField.widthAnchor.constraint(equalToConstant: 440).isActive = true
        panel.addArrangedSubview(inputPathField)

        let buttonRow = NSStackView()
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 10

        chooseButton.target = self
        chooseButton.action = #selector(chooseFile)
        buttonRow.addArrangedSubview(chooseButton)

        clearButton.target = self
        clearButton.action = #selector(clearSelection)
        buttonRow.addArrangedSubview(clearButton)

        panel.addArrangedSubview(buttonRow)
        return panel
    }

    private func makeActionPanel() -> NSView {
        let panel = NSStackView()
        panel.orientation = .horizontal
        panel.spacing = 12

        encryptButton.target = self
        encryptButton.action = #selector(encryptFile)
        panel.addArrangedSubview(encryptButton)

        decryptButton.target = self
        decryptButton.action = #selector(decryptFile)
        panel.addArrangedSubview(decryptButton)

        return panel
    }

    private func makeStatusPanel() -> NSView {
        let panel = NSStackView()
        panel.orientation = .vertical
        panel.alignment = .leading
        panel.spacing = 6
        panel.edgeInsets = NSEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
        panel.applyPanelStyle()

        panel.addArrangedSubview(sectionTitle("STATUS"))
        statusLabel.lineBreakMode = .byWordWrapping
        statusLabel.maximumNumberOfLines = 0
        statusLabel.preferredMaxLayoutWidth = 440
        panel.addArrangedSubview(statusLabel)
        return panel
    }

    private func sectionTitle(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        label.textColor = Theme.muted
        return label
    }

    private func setStatus(_ text: String, isError: Bool = false) {
        statusLabel.stringValue = text
        statusLabel.textColor = isError ? .systemRed : Theme.text
    }

    private func setBusy(_ busy: Bool) {
        isBusy = busy
        encryptButton.isEnabled = !busy
        decryptButton.isEnabled = !busy
        passwordField.isEnabled = !busy
        chooseButton.isEnabled = !busy
        clearButton.isEnabled = !busy
        encryptFilenameSwitch.isEnabled = !busy
    }

    private func encryptFilenameEnabled() -> Bool {
        encryptFilenameSwitch.state == .on
    }

    private func archiveContentTypes() -> [UTType] {
        // Accept Enclave's own .enclave and EnigmaVault's .enigma — the two apps
        // share the same secure archive format, so either opens here.
        return [
            UTType(filenameExtension: EnclaveCrypto.fileExtension),
            UTType(filenameExtension: "enigma")
        ].compactMap { $0 }
    }

    private func password() throws -> String {
        let value = passwordField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw EnclaveError.emptyPassword
        }
        return value
    }

    private func clearPassword() {
        passwordField.stringValue = ""
    }

    private func showError(_ error: Error) {
        if let enclaveError = error as? EnclaveError {
            switch enclaveError {
            case .emptyInput:
                setStatus("Select a file or folder first.", isError: true)
            case .emptyFolder:
                setStatus("The folder is empty or contains no encryptable files.", isError: true)
            case .destinationExists:
                setStatus("That folder already exists. Choose a different location.", isError: true)
            case .emptyPassword:
                setStatus("Enter a password.", isError: true)
            case .cannotEncryptArchive:
                setStatus("Cannot encrypt an existing .enclave archive.", isError: true)
            default:
                setStatus(enclaveError.localizedDescription, isError: true)
            }
        } else {
            setStatus(error.localizedDescription, isError: true)
        }
    }

    func openFiles(_ urls: [URL]) {
        guard !isBusy else { return }
        guard let url = urls.first else { return }
        if urls.count > 1 {
            setStatus("Using first of \(urls.count) dropped files.")
        }
        guard selectFile(at: url) else { return }
        if EnclaveCrypto.isArchiveFilename(url.lastPathComponent) {
            decryptFile()
        }
    }

    @discardableResult
    func selectFile(at url: URL) -> Bool {
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            setStatus("Cannot read: \(url.lastPathComponent).", isError: true)
            return false
        }

        if EnclaveCrypto.isArchiveFilename(url.lastPathComponent) {
            do {
                try EnclaveIO.validateArchiveInput(url)
            } catch {
                selectedURL = nil
                inputPathField.stringValue = ""
                showError(error)
                return false
            }
        }

        selectedURL = url
        inputPathField.stringValue = url.path
        if EnclaveFolder.isDirectory(url) {
            setStatus("Selected folder \(url.lastPathComponent).")
        } else if EnclaveCrypto.isArchiveFilename(url.lastPathComponent) {
            setStatus("Selected archive \(url.lastPathComponent).")
        } else {
            setStatus("Selected \(url.lastPathComponent).")
        }
        return true
    }

    @objc func chooseFile() {
        guard !isBusy else { return }

        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Select"
        panel.message = "Choose a file or folder to encrypt, or a .enclave archive to decrypt."

        if panel.runModal() == .OK, let url = panel.url {
            selectFile(at: url)
        }
    }

    @objc private func clearSelection() {
        guard !isBusy else { return }

        selectedURL = nil
        inputPathField.stringValue = ""
        setStatus("Selection cleared.")
    }

    @objc func encryptFile() {
        guard !isBusy else { return }

        do {
            guard let inputURL = selectedURL else {
                throw EnclaveError.emptyInput
            }
            if EnclaveCrypto.isArchiveFilename(inputURL.lastPathComponent) {
                throw EnclaveError.cannotEncryptArchive
            }
            let pass = try password()
            let encryptFilename = encryptFilenameEnabled()

            setBusy(true)
            setStatus(EnclaveFolder.isDirectory(inputURL) ? "Encrypting folder…" : "Encrypting…")

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let prepared = try EnclaveIO.prepareEncryptionPayload(from: inputURL)
                    let result = try EnclaveCrypto.encrypt(
                        data: prepared.data,
                        originalFilename: prepared.filename,
                        password: pass,
                        encryptFilename: encryptFilename
                    )

                    DispatchQueue.main.async {
                        self.presentEncryptSavePanel(
                            inputURL: inputURL,
                            encryptedData: result.data,
                            suggestedFilename: result.diskFilename,
                            encryptFilename: encryptFilename
                        )
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.setBusy(false)
                        self.showError(error)
                    }
                }
            }
        } catch {
            showError(error)
        }
    }

    private func presentEncryptSavePanel(
        inputURL: URL,
        encryptedData: Data,
        suggestedFilename: String,
        encryptFilename: Bool
    ) {
        defer { setBusy(false) }

        let savePanel = NSSavePanel()
        if let archiveType = UTType(filenameExtension: EnclaveCrypto.fileExtension) {
            savePanel.allowedContentTypes = [archiveType]
        }
        savePanel.directoryURL = inputURL.deletingLastPathComponent()
        savePanel.nameFieldStringValue = suggestedFilename
        savePanel.prompt = "Encrypt"
        if encryptFilename {
            savePanel.message = "Save the encrypted file. The on-disk name is a SHA-512 hash of the salt and encrypted filename (not your password)."
        } else {
            savePanel.message = "Save the encrypted file. The original filename is stored in plaintext in the archive and used as the on-disk name."
        }
        savePanel.canCreateDirectories = true

        guard savePanel.runModal() == .OK, let outputURL = savePanel.url else { return }

        let finalURL = EnclaveIO.normalizedArchiveURL(outputURL)

        do {
            try encryptedData.write(to: finalURL, options: .atomic)
            clearPassword()
            let itemLabel = EnclaveFolder.isDirectory(inputURL) ? "folder \(inputURL.lastPathComponent)" : inputURL.lastPathComponent
            setStatus("Encrypted \(itemLabel) → \(finalURL.lastPathComponent)")
        } catch {
            showError(error)
        }
    }

    @objc func decryptFile() {
        guard !isBusy else { return }

        do {
            let pass = try password()
            let inputURL = try resolveDecryptInputURL()

            setBusy(true)
            setStatus("Decrypting…")

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let encryptedData = try EnclaveIO.readArchive(from: inputURL)
                    let result = try EnclaveCrypto.decrypt(data: encryptedData, password: pass)

                    DispatchQueue.main.async {
                        self.presentDecryptSavePanel(inputURL: inputURL, payload: result.payload, filename: result.filename)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.setBusy(false)
                        self.showError(error)
                    }
                }
            }
        } catch {
            showError(error)
        }
    }

    private func resolveDecryptInputURL() throws -> URL {
        if let selectedURL, EnclaveCrypto.isArchiveFilename(selectedURL.lastPathComponent) {
            try EnclaveIO.validateArchiveInput(selectedURL)
            return selectedURL
        }

        let openPanel = NSOpenPanel()
        openPanel.canChooseFiles = true
        openPanel.canChooseDirectories = false
        openPanel.allowsMultipleSelection = false
        openPanel.allowedContentTypes = archiveContentTypes()
        openPanel.prompt = "Decrypt"
        openPanel.message = "Choose a .enclave file to decrypt."

        guard openPanel.runModal() == .OK, let url = openPanel.url else {
            throw EnclaveError.emptyInput
        }

        selectFile(at: url)
        try EnclaveIO.validateArchiveInput(url)
        return url
    }

    private func presentDecryptSavePanel(inputURL: URL, payload: Data, filename: String) {
        defer { setBusy(false) }

        if EnclaveFolder.isFolderPayload(payload) {
            presentFolderDecryptSavePanel(inputURL: inputURL, payload: payload, filename: filename)
            return
        }

        let savePanel = NSSavePanel()
        savePanel.directoryURL = inputURL.deletingLastPathComponent()
        savePanel.nameFieldStringValue = filename
        savePanel.prompt = "Save"
        savePanel.message = "Save the decrypted original file."
        savePanel.canCreateDirectories = true

        guard savePanel.runModal() == .OK, let outputURL = savePanel.url else { return }

        do {
            try EnclaveIO.writeDecryptedPayload(payload, filename: filename, to: outputURL)
            clearPassword()
            setStatus("Decrypted \(inputURL.lastPathComponent) → \(outputURL.lastPathComponent)")
        } catch {
            showError(error)
        }
    }

    private func presentFolderDecryptSavePanel(inputURL: URL, payload: Data, filename: String) {
        let folderName = EnclaveFolder.displayFolderName(from: filename)
        let openPanel = NSOpenPanel()
        openPanel.canChooseFiles = false
        openPanel.canChooseDirectories = true
        openPanel.allowsMultipleSelection = false
        openPanel.canCreateDirectories = true
        openPanel.prompt = "Create Folder"
        openPanel.message = "Choose where to create the decrypted folder “\(folderName)”."
        openPanel.directoryURL = inputURL.deletingLastPathComponent()

        guard openPanel.runModal() == .OK, let parentURL = openPanel.url else { return }

        do {
            try EnclaveIO.writeDecryptedPayload(payload, filename: filename, to: parentURL)
            clearPassword()
            let restored = parentURL.appendingPathComponent(folderName, isDirectory: true)
            setStatus("Decrypted \(inputURL.lastPathComponent) → \(restored.path)")
        } catch {
            showError(error)
        }
    }
}