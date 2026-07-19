import Darwin
import Foundation

@main
enum EnclaveCLI {
    static func main() {
        exit(CLI.run())
    }
}

enum CLI {
    static func run() -> Int32 {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let command = args.first else {
            printUsage()
            return 1
        }

        if ["help", "-h", "--help"].contains(command) {
            printUsage()
            return 0
        }

        let options: Options
        do {
            options = try parseOptions(Array(args.dropFirst()))
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            printUsage()
            return 1
        }

        guard let input = options.input else {
            fputs("Error: missing input file or folder.\n", stderr)
            printUsage()
            return 1
        }

        let inputURL = URL(fileURLWithPath: EnclaveIO.expandedPath(input))
        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            fputs("Error: path not found: \(input)\n", stderr)
            return 1
        }

        guard let password = options.password ?? promptPassword() else {
            fputs("Error: password is required.\n", stderr)
            return 1
        }

        do {
            switch command {
            case "encrypt", "enc", "e":
                try encrypt(
                    inputURL: inputURL,
                    password: password,
                    output: options.output,
                    encryptFilename: options.encryptFilename
                )
            case "decrypt", "dec", "d":
                try decrypt(inputURL: inputURL, password: password, output: options.output)
            default:
                fputs("Error: unknown command '\(command)'.\n", stderr)
                printUsage()
                return 1
            }
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            return 1
        }

        return 0
    }

    private static func encrypt(
        inputURL: URL,
        password: String,
        output: String?,
        encryptFilename: Bool
    ) throws {
        if EnclaveCrypto.isArchiveFilename(inputURL.lastPathComponent) {
            throw EnclaveError.cannotEncryptArchive
        }
        let prepared = try EnclaveIO.prepareEncryptionPayload(from: inputURL)
        let result = try EnclaveCrypto.encrypt(
            data: prepared.data,
            originalFilename: prepared.filename,
            password: password,
            encryptFilename: encryptFilename
        )

        let outputURL = try EnclaveIO.resolveOutputURL(
            output: output,
            defaultName: result.diskFilename,
            relativeTo: inputURL
        )
        try result.data.write(to: outputURL, options: .atomic)
        print("Encrypted: \(outputURL.path)")
    }

    private static func decrypt(inputURL: URL, password: String, output: String?) throws {
        let inputData = try EnclaveIO.readArchive(from: inputURL)
        let (payload, filename) = try EnclaveCrypto.decrypt(data: inputData, password: password)

        if EnclaveFolder.isFolderPayload(payload) {
            let parentURL = try EnclaveIO.resolveFolderDecryptParent(output: output, relativeTo: inputURL)
            try EnclaveIO.writeDecryptedPayload(payload, filename: filename, to: parentURL)
            let folderName = EnclaveFolder.displayFolderName(from: filename)
            print("Decrypted folder: \(parentURL.appendingPathComponent(folderName).path)")
            return
        }

        let outputURL = try EnclaveIO.resolveOutputURL(
            output: output,
            defaultName: filename,
            relativeTo: inputURL,
            appendedFilename: filename
        )
        try EnclaveIO.writeDecryptedPayload(payload, filename: filename, to: outputURL)
        print("Decrypted: \(outputURL.path)")
    }

    private static func promptPassword() -> String? {
        guard isatty(STDIN_FILENO) != 0 else { return nil }
        guard let cString = getpass("Password: ") else { return nil }
        let password = String(cString: cString)
        guard !password.isEmpty else { return nil }
        return password
    }

    private struct Options {
        var input: String?
        var output: String?
        var password: String?
        var encryptFilename = true
    }

    private enum ParseError: LocalizedError {
        case missingValue(String)

        var errorDescription: String? {
            switch self {
            case .missingValue(let flag):
                return "Missing value for \(flag)."
            }
        }
    }

    private static func parseOptions(_ args: [String]) throws -> Options {
        var options = Options()
        var index = 0

        while index < args.count {
            let arg = args[index]
            switch arg {
            case "-o", "--output":
                index += 1
                guard index < args.count else { throw ParseError.missingValue(arg) }
                options.output = EnclaveIO.expandedPath(args[index])
            case "-p", "--password":
                index += 1
                guard index < args.count else { throw ParseError.missingValue(arg) }
                options.password = args[index]
            case "--plaintext-filename", "--no-encrypt-filename":
                options.encryptFilename = false
            default:
                if !arg.hasPrefix("-"), options.input == nil {
                    options.input = EnclaveIO.expandedPath(arg)
                }
            }
            index += 1
        }

        return options
    }

    private static func printUsage() {
        let text = """
        Enclave — simple AES-256-GCM file encryption for macOS

        Usage:
          enclave-cli encrypt <file-or-folder> [-p password] [-o output]
          enclave-cli decrypt <file> [-p password] [-o output]

        Options:
          -p, --password   Password (prompted securely if omitted in a terminal)
          -o, --output     Output file or directory
          --plaintext-filename
                           Store the original filename in plaintext (encrypt only)

        Notes:
          - Files and folders are encrypted with AES-256-GCM (folders are packed first).
          - Keys are derived with Argon2id (BLAKE2b; 64 MiB, 3 iterations, 1 lane)
            from your password and a random salt.
          - Older v3 PBKDF2-HMAC-SHA256 and v2 HKDF-SHA512 archives still decrypt.
          - By default, on-disk names use SHA-512 filename hashing; use --plaintext-filename
            to keep the original name in the archive and on disk.
          - Avoid -p on shared systems; passwords may be visible in process lists.
        """
        fputs(text + "\n", stdout)
        fflush(stdout)
    }
}