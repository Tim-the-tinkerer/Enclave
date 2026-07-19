import AppKit

@main
enum EnclaveApp {
    static func main() {
        autoreleasepool {
            let app = NSApplication.shared
            let delegate = AppDelegate()
            app.delegate = delegate
            app.setActivationPolicy(.regular)
            let exitCode = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
            exit(exitCode)
        }
    }
}