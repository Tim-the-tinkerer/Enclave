import AppKit
import WebKit

final class HelpWindowController: NSWindowController {
    static let shared = HelpWindowController()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Enclave Help"
        window.center()
        window.backgroundColor = Theme.background
        window.isReleasedWhenClosed = false

        super.init(window: window)
        window.contentViewController = HelpViewController()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        (window?.contentViewController as? HelpViewController)?.reloadHelp()
        window?.title = "Enclave Help (\(AppInfo.version))"
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

final class HelpViewController: NSViewController {
    private let webView: WKWebView = {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        if #available(macOS 12.0, *) {
            configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        }
        return WKWebView(frame: .zero, configuration: configuration)
    }()

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 640, height: 560))
        view.wantsLayer = true
        view.layer?.backgroundColor = Theme.background.cgColor

        webView.translatesAutoresizingMaskIntoConstraints = false
        if #available(macOS 13.0, *) {
            webView.underPageBackgroundColor = .clear
        }

        view.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webView.topAnchor.constraint(equalTo: view.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])

        reloadHelp()
    }

    func reloadHelp() {
        guard let (helpURL, readAccessURL) = helpLocations() else {
            showFallbackText()
            return
        }

        guard var html = try? String(contentsOf: helpURL, encoding: .utf8) else {
            webView.loadFileURL(helpURL, allowingReadAccessTo: readAccessURL)
            return
        }

        html = html
            .replacingOccurrences(of: "{{VERSION}}", with: AppInfo.version)
            .replacingOccurrences(of: "{{BUILD}}", with: AppInfo.build)
        let baseURL = readAccessURL.appendingPathComponent("Contents/Resources/en.lproj", isDirectory: true)
        webView.loadHTMLString(html, baseURL: baseURL)
    }

    private func helpLocations() -> (URL, URL)? {
        if let indexURL = Bundle.main.url(
            forResource: "index",
            withExtension: "html",
            subdirectory: "Enclave.help/Contents/Resources/en.lproj"
        ) {
            let helpRoot = indexURL
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
            return (indexURL, helpRoot)
        }

        let resources = Bundle.main.resourceURL
        let helpRoot = resources?.appendingPathComponent("Enclave.help", isDirectory: true)
        let indexURL = helpRoot?
            .appendingPathComponent("Contents/Resources/en.lproj/index.html", isDirectory: false)

        if let indexURL, let helpRoot, FileManager.default.fileExists(atPath: indexURL.path) {
            return (indexURL, helpRoot)
        }

        return nil
    }

    private func showFallbackText() {
        let html = """
        <html><body style="font-family:-apple-system,sans-serif;padding:24px;background:#12141c;color:#e8ecf2;line-height:1.5;">
        <h1>Enclave Help</h1>
        <p style="color:#8b93a3;">Version \(AppInfo.version) (build \(AppInfo.build))</p>
        <p>Enter a password, choose a file or folder, then click <strong>Encrypt</strong> or <strong>Decrypt</strong>.</p>
        <p><strong>AES-256-GCM</strong> encrypts file contents. Toggle <strong>Encrypt filename</strong> to hide the original name.</p>
        <p><strong>Argon2id</strong> (BLAKE2b) derives keys — 65,536 KiB, 3 iterations, 1 lane by default.</p>
        <p><strong>SHA-512</strong> hashes the on-disk filename when filename encryption is on.</p>
        <p>Enclave also opens <strong>.enigma</strong> files from EnigmaVault made in its Secure mode — the two apps share the same archive format.</p>
        <p>Older PBKDF2-HMAC-SHA256 v3 and HKDF-SHA512 v2 archives still decrypt.</p>
        </body></html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }
}