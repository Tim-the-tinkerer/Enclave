import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var mainWindowController: MainWindowController?
    private var pendingOpenFiles: [String] = []

    func applicationWillFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        collectCommandLineFiles()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            mainWindowController?.showWindow(nil)
            mainWindowController?.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        return true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMainMenu()

        mainWindowController = MainWindowController()
        wireMenuTargets()

        guard let window = mainWindowController?.window else {
            fputs("Enclave: failed to create main window\n", stderr)
            return
        }

        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)

        if !pendingOpenFiles.isEmpty {
            let files = pendingOpenFiles
            pendingOpenFiles.removeAll()
            processOpenFiles(files)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        if mainWindowController?.mainViewController != nil {
            processOpenFiles(filenames)
        } else {
            pendingOpenFiles.append(contentsOf: filenames)
        }
    }

    private func collectCommandLineFiles() {
        let paths = CommandLine.arguments.dropFirst()
            .filter { !$0.hasPrefix("-") }
            .map { ($0 as NSString).expandingTildeInPath }
            .filter { FileManager.default.isReadableFile(atPath: $0) }

        guard !paths.isEmpty else { return }
        pendingOpenFiles.append(contentsOf: paths)
    }

    private func processOpenFiles(_ filenames: [String]) {
        guard let mainView = mainWindowController?.mainViewController else { return }

        NSApp.activate(ignoringOtherApps: true)
        mainWindowController?.showWindow(nil)
        mainWindowController?.window?.makeKeyAndOrderFront(nil)
        mainView.openFiles(filenames.map { URL(fileURLWithPath: $0) })
    }

    private func buildMainMenu() {
        let mainMenu = NSMenu()

        let appMenuItem = NSMenuItem()
        appMenuItem.title = "Enclave"
        mainMenu.addItem(appMenuItem)

        let appMenu = NSMenu(title: "Enclave")
        appMenu.addItem(menuItem(title: "About Enclave", action: #selector(showAbout)))
        appMenu.addItem(.separator())
        appMenu.addItem(
            withTitle: "Quit Enclave",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appMenuItem.submenu = appMenu

        let fileMenuItem = NSMenuItem()
        fileMenuItem.title = "File"
        mainMenu.addItem(fileMenuItem)

        let fileMenu = NSMenu(title: "File")
        fileMenu.addItem(menuItem(title: "Choose…", action: #selector(MainViewController.chooseFile), key: "o"))
        fileMenu.addItem(menuItem(title: "Encrypt…", action: #selector(MainViewController.encryptFile), key: "e"))
        fileMenu.addItem(menuItem(title: "Decrypt…", action: #selector(MainViewController.decryptFile), key: "d"))
        fileMenu.addItem(.separator())
        fileMenu.addItem(
            withTitle: "Close Window",
            action: #selector(NSWindow.performClose(_:)),
            keyEquivalent: "w"
        )
        fileMenuItem.submenu = fileMenu

        let helpMenuItem = NSMenuItem()
        helpMenuItem.title = "Help"
        mainMenu.addItem(helpMenuItem)

        let helpMenu = NSMenu(title: "Help")
        helpMenu.addItem(menuItem(title: "Enclave Help", action: #selector(showHelp), key: "?"))
        helpMenuItem.submenu = helpMenu

        NSApp.mainMenu = mainMenu
    }

    private func wireMenuTargets() {
        guard let mainView = mainWindowController?.mainViewController,
              let fileMenu = NSApp.mainMenu?.item(withTitle: "File")?.submenu else {
            return
        }

        let actions: [Selector] = [
            #selector(MainViewController.chooseFile),
            #selector(MainViewController.encryptFile),
            #selector(MainViewController.decryptFile)
        ]

        for item in fileMenu.items {
            guard let action = item.action, actions.contains(action) else { continue }
            item.target = mainView
        }
    }

    private func menuItem(title: String, action: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        if action == #selector(showAbout) || action == #selector(showHelp) {
            item.target = self
        }
        return item
    }

    @objc func showHelp() {
        HelpWindowController.shared.show()
    }

    @objc func showAbout() {
        let alert = NSAlert()
        alert.messageText = "Enclave"
        alert.informativeText = """
        Simple file encryption for macOS.

        AES-256-GCM encrypts file contents.
        Argon2id (BLAKE2b) derives keys from your password.
        Filename encryption is optional; SHA-512 hashes the on-disk name when enabled.

        Version \(AppInfo.version) (build \(AppInfo.build))
        """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}