import Foundation

enum EnclaveFolder {
    static let magic = Data("ENCLPKG1".utf8)
    static let version: UInt8 = 1
    static let filenameSuffix = ".enclavefolder"
    static let maxEntries = 100_000
    static let maxPathLength = 4_096
    static let maxEntrySize = EnclaveCrypto.maxPlaintextSize

    static func isDirectory(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    static func isFolderPayload(_ data: Data) -> Bool {
        data.starts(with: magic)
    }

    static func storedFilename(forDirectory url: URL) -> String {
        url.lastPathComponent + filenameSuffix
    }

    static func isFolderStoredName(_ filename: String) -> Bool {
        let base = (filename as NSString).lastPathComponent
        return base.hasSuffix(filenameSuffix)
    }

    static func displayFolderName(from storedFilename: String) -> String {
        let base = (storedFilename as NSString).lastPathComponent
        if base.hasSuffix(filenameSuffix) {
            return String(base.dropLast(filenameSuffix.count))
        }
        return base
    }

    /// Visible archive filename when filename encryption is off (no internal suffix).
    static func plaintextArchiveName(from storedFilename: String) -> String {
        if isFolderStoredName(storedFilename) {
            return displayFolderName(from: storedFilename)
        }
        return (storedFilename as NSString).lastPathComponent
    }

    static func pack(directory url: URL) throws -> Data {
        let root = url.standardizedFileURL
        guard isDirectory(root) else {
            throw EnclaveError.invalidFormat
        }

        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
            options: [.skipsPackageDescendants, .skipsHiddenFiles]
        ) else {
            throw EnclaveError.unreadableFile(root.lastPathComponent)
        }

        var entries: [(path: String, data: Data)] = []
        var payloadSize = magic.count + 1 + 4

        while let item = enumerator.nextObject() as? URL {
            let values = try item.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            if values.isSymbolicLink == true {
                continue
            }
            guard values.isRegularFile == true else {
                continue
            }

            if let fileSize = values.fileSize, fileSize > maxEntrySize {
                throw EnclaveError.payloadTooLarge
            }

            let relativePath = try relativePath(from: root, to: item)
            let fileData = try Data(contentsOf: item)
            guard fileData.count <= maxEntrySize else {
                throw EnclaveError.payloadTooLarge
            }

            let entrySize = 4 + relativePath.utf8.count + 8 + fileData.count
            guard payloadSize + entrySize <= EnclaveCrypto.maxPlaintextSize else {
                throw EnclaveError.payloadTooLarge
            }
            payloadSize += entrySize
            entries.append((relativePath, fileData))

            guard entries.count <= maxEntries else {
                throw EnclaveError.payloadTooLarge
            }
        }

        guard !entries.isEmpty else {
            throw EnclaveError.emptyFolder
        }

        entries.sort { $0.path < $1.path }

        var archive = Data()
        archive.append(magic)
        archive.append(version)
        appendUInt32(UInt32(entries.count), to: &archive)

        for entry in entries {
            appendBlob(entry.path, data: entry.data, to: &archive)
        }

        return archive
    }

    static func unpack(payload: Data, to parentDirectory: URL, folderName: String) throws {
        var offset = 0
        guard payload.starts(with: magic) else {
            throw EnclaveError.invalidFormat
        }
        offset = magic.count

        guard offset + 1 + 4 <= payload.count else {
            throw EnclaveError.invalidFormat
        }
        let fileVersion = payload[offset]
        offset += 1
        guard fileVersion == version else {
            throw EnclaveError.invalidFormat
        }

        let entryCount = Int(try readUInt32(payload, offset: &offset))
        guard entryCount >= 1, entryCount <= maxEntries else {
            throw EnclaveError.invalidFormat
        }

        let safeFolderName = try sanitizeFolderName(folderName)
        let destination = parentDirectory.standardizedFileURL
            .appendingPathComponent(safeFolderName, isDirectory: true)
        try ensureDestinationAvailable(destination)

        for _ in 0..<entryCount {
            let remaining = payload.count - offset
            let (relativePath, fileData) = try readBlob(payload, offset: &offset, remaining: remaining)
            let safePath = try sanitizeRelativePath(relativePath)
            let fileURL = destination.appendingPathComponent(safePath)
            guard isContainedInDirectory(fileURL, directory: destination) else {
                throw EnclaveError.invalidFormat
            }

            let parent = fileURL.deletingLastPathComponent()
            if !parent.path.isEmpty {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            }
            try fileData.write(to: fileURL, options: .atomic)
        }

        guard offset == payload.count else {
            throw EnclaveError.invalidFormat
        }
    }

    private static func ensureDestinationAvailable(_ destination: URL) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDirectory) else {
            try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
            return
        }

        guard isDirectory.boolValue else {
            throw EnclaveError.destinationExists
        }

        let contents = try FileManager.default.contentsOfDirectory(atPath: destination.path)
        guard contents.isEmpty else {
            throw EnclaveError.destinationExists
        }
    }

    private static func sanitizeFolderName(_ name: String) throws -> String {
        guard !name.isEmpty, !name.contains("/"), !name.contains("\\") else {
            throw EnclaveError.invalidFormat
        }
        let base = (name as NSString).lastPathComponent
        guard !base.isEmpty, base != ".", base != ".." else {
            throw EnclaveError.invalidFormat
        }
        guard !base.contains("..") else {
            throw EnclaveError.invalidFormat
        }
        return base
    }

    private static func relativePath(from root: URL, to file: URL) throws -> String {
        let rootPath = root.standardizedFileURL.path
        let filePath = file.standardizedFileURL.path
        let prefix = rootPath + "/"
        guard filePath.hasPrefix(prefix) else {
            throw EnclaveError.invalidFormat
        }
        return try sanitizeRelativePath(String(filePath.dropFirst(prefix.count)))
    }

    private static func sanitizeRelativePath(_ path: String) throws -> String {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\\") else {
            throw EnclaveError.invalidFormat
        }
        guard path.utf8.count <= maxPathLength else {
            throw EnclaveError.invalidFormat
        }

        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty,
              !parts.contains(".."),
              !parts.contains("."),
              !parts.contains(where: { $0.isEmpty }) else {
            throw EnclaveError.invalidFormat
        }
        return parts.joined(separator: "/")
    }

    private static func isContainedInDirectory(_ fileURL: URL, directory: URL) -> Bool {
        let fileComponents = fileURL.standardizedFileURL.pathComponents
        let directoryComponents = directory.standardizedFileURL.pathComponents
        guard fileComponents.count >= directoryComponents.count else {
            return false
        }
        return Array(fileComponents.prefix(directoryComponents.count)) == directoryComponents
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
    }

    private static func readUInt32(_ data: Data, offset: inout Int) throws -> UInt32 {
        guard offset + 4 <= data.count else {
            throw EnclaveError.invalidFormat
        }
        let bytes = [UInt8](data[offset..<(offset + 4)])
        offset += 4
        return (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
    }

    private static func appendBlob(_ path: String, data fileData: Data, to archive: inout Data) {
        let pathData = Data(path.utf8)
        precondition(pathData.count <= UInt32.max)
        appendUInt32(UInt32(pathData.count), to: &archive)
        archive.append(pathData)
        var size = UInt64(fileData.count).bigEndian
        withUnsafeBytes(of: &size) { archive.append(contentsOf: $0) }
        archive.append(fileData)
    }

    private static func readBlob(_ data: Data, offset: inout Int, remaining: Int) throws -> (String, Data) {
        guard remaining >= 4 else {
            throw EnclaveError.invalidFormat
        }

        let pathLength = Int(try readUInt32(data, offset: &offset))
        guard pathLength > 0,
              pathLength <= maxPathLength,
              offset + pathLength + 8 <= data.count else {
            throw EnclaveError.invalidFormat
        }

        let pathData = data[offset..<(offset + pathLength)]
        offset += pathLength
        guard let path = String(data: pathData, encoding: .utf8) else {
            throw EnclaveError.invalidFormat
        }

        let sizeBytes = [UInt8](data[offset..<(offset + 8)])
        offset += 8
        var fileLength64: UInt64 = 0
        for b in sizeBytes { fileLength64 = (fileLength64 << 8) | UInt64(b) }
        // Zero-length entries are valid — empty files must round-trip faithfully.
        // Validate as UInt64 before narrowing to Int so a corrupt size field
        // throws cleanly instead of trapping the Int conversion.
        guard fileLength64 <= UInt64(maxEntrySize) else {
            throw EnclaveError.invalidFormat
        }
        let fileLength = Int(fileLength64)
        guard offset + fileLength <= data.count else {
            throw EnclaveError.invalidFormat
        }

        let fileData = Data(data[offset..<(offset + fileLength)])
        offset += fileLength
        return (path, fileData)
    }
}