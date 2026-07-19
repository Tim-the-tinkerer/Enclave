import Foundation

enum EnclaveIO {
    static func expandedPath(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    static func validatePlaintextInput(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }
        guard !EnclaveCrypto.isArchiveFilename(url.lastPathComponent) else {
            throw EnclaveError.cannotEncryptArchive
        }
        if isDirectory.boolValue {
            guard directoryContainsRegularFile(url) else {
                throw EnclaveError.emptyFolder
            }
        } else {
            try validateFileSize(url)
        }
    }

    static func prepareEncryptionPayload(from url: URL) throws -> (data: Data, filename: String) {
        try validatePlaintextInput(url)
        if EnclaveFolder.isDirectory(url) {
            let data = try EnclaveFolder.pack(directory: url)
            return (data, EnclaveFolder.storedFilename(forDirectory: url))
        }
        let data = try Data(contentsOf: url)
        guard data.count <= EnclaveCrypto.maxPlaintextSize else {
            throw EnclaveError.payloadTooLarge
        }
        return (data, url.lastPathComponent)
    }

    static func resolveFolderDecryptParent(output: String?, relativeTo inputURL: URL) throws -> URL {
        guard let output else {
            return inputURL.deletingLastPathComponent()
        }

        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: output, isDirectory: &isDirectory)
        if exists && isDirectory.boolValue {
            return URL(fileURLWithPath: output, isDirectory: true)
        }

        let parent = URL(fileURLWithPath: output).deletingLastPathComponent()
        if !parent.path.isEmpty, parent.path != "/" {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        return parent.path.isEmpty ? inputURL.deletingLastPathComponent() : parent
    }

    static func writeDecryptedPayload(_ payload: Data, filename: String, to outputURL: URL) throws {
        if EnclaveFolder.isFolderPayload(payload) {
            let folderName = EnclaveFolder.displayFolderName(from: filename)
            try EnclaveFolder.unpack(payload: payload, to: outputURL, folderName: folderName)
            return
        }
        try payload.write(to: outputURL, options: .atomic)
    }

    static func validateArchiveInput(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw EnclaveError.invalidFormat
        }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }

        try validateArchiveSize(url)

        let headerSize = EnclaveCrypto.magic.count
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        guard let header = try handle.read(upToCount: headerSize), EnclaveCrypto.isArchiveData(header) else {
            throw EnclaveError.invalidFormat
        }
    }

    static func readArchive(from url: URL) throws -> Data {
        try validateArchiveInput(url)
        let data = try Data(contentsOf: url)
        guard data.count <= EnclaveCrypto.maxArchiveSize else {
            throw EnclaveError.payloadTooLarge
        }
        return data
    }

    static func resolveOutputURL(
        output: String?,
        defaultName: String,
        relativeTo inputURL: URL,
        appendedFilename: String? = nil
    ) throws -> URL {
        guard let output else {
            return inputURL.deletingLastPathComponent().appendingPathComponent(defaultName)
        }

        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: output, isDirectory: &isDirectory)
        if exists && isDirectory.boolValue {
            let name = appendedFilename ?? defaultName
            return URL(fileURLWithPath: output, isDirectory: true).appendingPathComponent(name)
        }

        let outputURL = URL(fileURLWithPath: output)
        let parent = outputURL.deletingLastPathComponent()
        if !parent.path.isEmpty, parent.path != "/" {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        return outputURL
    }

    static func normalizedArchiveURL(_ url: URL) -> URL {
        guard EnclaveCrypto.isArchiveFilename(url.lastPathComponent) else {
            return url.deletingPathExtension().appendingPathExtension(EnclaveCrypto.fileExtension)
        }
        return url
    }

    private static func validateArchiveSize(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw EnclaveError.invalidFormat
        }
        if values.isRegularFile == false {
            throw EnclaveError.invalidFormat
        }

        var fileSize = values.fileSize
        if fileSize == nil {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            fileSize = attributes[.size] as? Int
        }
        guard let fileSize else {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }
        if fileSize > EnclaveCrypto.maxArchiveSize {
            throw EnclaveError.payloadTooLarge
        }
    }

    private static func validateFileSize(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }
        if values.isRegularFile == false {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }

        var fileSize = values.fileSize
        if fileSize == nil {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            fileSize = attributes[.size] as? Int
        }
        guard let fileSize else {
            throw EnclaveError.unreadableFile(url.lastPathComponent)
        }
        if fileSize > EnclaveCrypto.maxPlaintextSize {
            throw EnclaveError.payloadTooLarge
        }
    }

    private static func directoryContainsRegularFile(_ url: URL) -> Bool {
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsPackageDescendants, .skipsHiddenFiles]
        ) else {
            return false
        }

        for case let item as URL in enumerator {
            guard let values = try? item.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else {
                continue
            }
            if values.isSymbolicLink == true {
                continue
            }
            if values.isRegularFile == true {
                return true
            }
        }
        return false
    }
}