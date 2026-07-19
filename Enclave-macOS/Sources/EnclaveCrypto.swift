import CArgon2
import CommonCrypto
import CryptoKit
import Foundation
import Security

enum EnclaveError: LocalizedError {
    case invalidFormat
    case unsupportedVersion(UInt8)
    case unsupportedKDF(UInt8)
    case wrongPassword
    case emptyInput
    case emptyPassword
    case unreadableFile(String)
    case cannotEncryptArchive
    case payloadTooLarge
    case randomGenerationFailed
    case keyDerivationFailed
    case emptyFolder
    case destinationExists

    var errorDescription: String? {
        switch self {
        case .invalidFormat:
            return "Not a valid Enclave archive."
        case .unsupportedVersion(let version):
            return "Unsupported format version: \(version)."
        case .unsupportedKDF(let id):
            return "Unsupported key-derivation algorithm: \(id)."
        case .wrongPassword:
            return "Decryption failed. Check the password."
        case .emptyInput:
            return "No input file or folder was provided."
        case .emptyPassword:
            return "A password is required."
        case .unreadableFile(let path):
            return "Cannot read file: \(path)."
        case .cannotEncryptArchive:
            return "Cannot encrypt an existing .enclave archive."
        case .payloadTooLarge:
            return "The file exceeds the maximum supported size."
        case .randomGenerationFailed:
            return "Secure random number generation failed."
        case .keyDerivationFailed:
            return "Key derivation failed."
        case .emptyFolder:
            return "The folder is empty or contains no encryptable files."
        case .destinationExists:
            return "The destination folder already exists and is not empty."
        }
    }
}

struct EnclaveEncryptResult {
    let data: Data
    let diskFilename: String
}

// MARK: - Key-derivation parameters

/// Identifies the password-hashing function used for an archive.
/// The numeric raw value is what gets written into the file header.
enum KDFAlgorithm: UInt8 {
    case pbkdf2SHA256 = 1
    case argon2id = 2
}

/// Self-describing KDF parameters, serialized into the v3 header so that the
/// work factor can be raised over time and new algorithms added without a
/// new format version.
enum KDFParams {
    case pbkdf2(iterations: UInt32)
    case argon2id(memoryKiB: UInt32, iterations: UInt32, parallelism: UInt8)

    var algorithm: KDFAlgorithm {
        switch self {
        case .pbkdf2: return .pbkdf2SHA256
        case .argon2id: return .argon2id
        }
    }

    /// (kdfID, body) for the header. Body excludes the id and the outer length;
    /// the archive writer prepends those.
    func encode() -> (id: UInt8, body: Data) {
        switch self {
        case .pbkdf2(let iterations):
            return (KDFAlgorithm.pbkdf2SHA256.rawValue, EnclaveCrypto.uint32BE(iterations))
        case .argon2id(let memoryKiB, let iterations, let parallelism):
            var body = Data()
            body.append(EnclaveCrypto.uint32BE(memoryKiB))
            body.append(EnclaveCrypto.uint32BE(iterations))
            body.append(parallelism)
            return (KDFAlgorithm.argon2id.rawValue, body)
        }
    }

    /// Parse a KDF block read from a header. `body` is a fresh, zero-based copy.
    /// Bounds are enforced so a hostile archive cannot force unbounded CPU/RAM.
    static func decode(id: UInt8, body: Data) throws -> KDFParams {
        guard let algorithm = KDFAlgorithm(rawValue: id) else {
            throw EnclaveError.unsupportedKDF(id)
        }
        let bytes = [UInt8](body)
        switch algorithm {
        case .pbkdf2SHA256:
            guard bytes.count == 4 else { throw EnclaveError.invalidFormat }
            let iterations = EnclaveCrypto.readUInt32BE(bytes, at: 0)
            guard iterations >= 1, iterations <= EnclaveCrypto.maxPBKDF2Iterations else {
                throw EnclaveError.invalidFormat
            }
            return .pbkdf2(iterations: iterations)
        case .argon2id:
            guard bytes.count == 9 else { throw EnclaveError.invalidFormat }
            let memoryKiB = EnclaveCrypto.readUInt32BE(bytes, at: 0)
            let iterations = EnclaveCrypto.readUInt32BE(bytes, at: 4)
            let parallelism = bytes[8]
            guard iterations >= 1,
                  iterations <= EnclaveCrypto.maxArgon2Iterations,
                  memoryKiB >= 8,
                  memoryKiB <= EnclaveCrypto.maxArgon2MemoryKiB,
                  parallelism >= 1,
                  parallelism <= EnclaveCrypto.maxArgon2Parallelism else {
                throw EnclaveError.invalidFormat
            }
            return .argon2id(memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism)
        }
    }
}

enum EnclaveCrypto {
    static let magic = Data("ENCLAVE1".utf8)
    static let currentVersion: UInt8 = 5
    static let legacyVersionV4: UInt8 = 4
    static let legacyVersionV3: UInt8 = 3
    static let legacyVersionV2: UInt8 = 2
    static let flagEncryptFilename: UInt8 = 1
    static let fileExtension = "enclave"
    static let saltLength = 32
    static let nonceLength = 12
    static let diskNameHexLength = 32
    static let maxFilenameBlobSize = 1_048_576
    static let maxContentBlobSize = 4_294_967_224
    static let minSealedBlobSize = nonceLength + 16
    static let maxPlaintextSize = maxContentBlobSize - minSealedBlobSize
    /// Worst-case v4 header: magic + version + flags + kdf id + param length + max param block + salt.
    static let maxArchiveHeaderSize = magic.count + 1 + 1 + 1 + 1 + 255 + saltLength
    static let maxArchiveSize = maxArchiveHeaderSize + 4 + maxFilenameBlobSize + 4 + maxContentBlobSize

    // PBKDF2-HMAC-SHA256 work factor (OWASP floor, ~600k). Still available by
    // passing `kdf: .pbkdf2(...)`; kept as a lighter-weight alternative for
    // environments where Argon2id's memory use is undesirable. Because the value
    // is stored per-archive you can raise it freely and old files still decrypt.
    static let pbkdf2DefaultIterations: UInt32 = 600_000

    // Decode-time safety caps (a crafted header must not be able to hang the app).
    static let maxPBKDF2Iterations: UInt32 = 100_000_000
    static let maxArgon2Iterations: UInt32 = 64
    static let maxArgon2MemoryKiB: UInt32 = 4_194_304 // 4 GiB
    static let maxArgon2Parallelism: UInt8 = 8

    // Default KDF for new archives: Argon2id, memory-hard and the stronger choice
    // against GPU/ASIC guessing. ~64 MiB of RAM per derivation. OWASP's minimum is
    // m=19456 KiB, t=2, p=1; this is a little stronger.
    static let argon2idDefault = KDFParams.argon2id(memoryKiB: 65_536, iterations: 3, parallelism: 1)

    static func isArchiveFilename(_ filename: String) -> Bool {
        // Accept Enclave's own .enclave and EnigmaVault's .enigma — same secure format.
        let ext = (filename as NSString).pathExtension.lowercased()
        return ext == fileExtension || ext == "enigma"
    }

    static func isArchiveData(_ data: Data) -> Bool {
        data.starts(with: magic)
    }

    // MARK: Encrypt / Decrypt

    static func encrypt(
        data: Data,
        originalFilename: String,
        password: String,
        encryptFilename: Bool = true,
        kdf: KDFParams = argon2idDefault
    ) throws -> EnclaveEncryptResult {
        try validatePassword(password)
        guard data.count <= maxPlaintextSize else {
            throw EnclaveError.payloadTooLarge
        }

        let salt = try randomBytes(count: saltLength)
        let key = try deriveKey(password: password, salt: salt, params: kdf)

        let sanitizedName = sanitizedFilename(originalFilename)
        let archiveFilename = encryptFilename
            ? sanitizedName
            : filesystemSafeFilename(EnclaveFolder.plaintextArchiveName(from: sanitizedName))
        let filenameData = Data(archiveFilename.utf8)
        guard filenameData.count <= maxFilenameBlobSize else {
            throw EnclaveError.payloadTooLarge
        }

        // Build the header up front so it can be bound as additional authenticated
        // data (AAD) on every sealed box. Any later tampering with the version,
        // flags, KDF id/parameters, or salt then fails authentication instead of
        // silently deriving a different key. The header is exactly the bytes
        // preceding the first blob, so the decryptor reconstructs the same AAD
        // by slicing.
        let (kdfID, kdfBody) = kdf.encode()
        precondition(kdfBody.count <= 255, "KDF param block must fit a UInt8 length")

        var header = Data()
        header.append(magic)
        header.append(currentVersion)
        header.append(encryptFilename ? flagEncryptFilename : 0)
        header.append(kdfID)
        header.append(UInt8(kdfBody.count))
        header.append(kdfBody)
        header.append(salt)

        let filenameBlob: Data
        if encryptFilename {
            let filenameNonce = try AES.GCM.Nonce(data: randomBytes(count: nonceLength))
            let encryptedFilename = try AES.GCM.seal(
                filenameData, using: key, nonce: filenameNonce, authenticating: header
            )
            filenameBlob = combined(encryptedFilename)
        } else {
            filenameBlob = filenameData
        }

        // Content is sealed with the header AAD plus the filename blob. Binding
        // the filename (whether it is the sealed blob or a plaintext name) means
        // tampering with the stored filename is detected even when filename
        // encryption is disabled. This is the v5 rule; v3/v4 bound only the header.
        let contentAAD = header + filenameBlob
        let contentNonce = try AES.GCM.Nonce(data: randomBytes(count: nonceLength))
        let encryptedContent = try AES.GCM.seal(
            data, using: key, nonce: contentNonce, authenticating: contentAAD
        )
        let contentBlob = combined(encryptedContent)

        var archive = header
        try appendBlob(&archive, filenameBlob, encrypted: encryptFilename)
        try appendBlob(&archive, contentBlob)

        let diskName = encryptFilename
            ? diskFilename(for: salt, sealedFilename: filenameBlob)
            : archiveFilename
        return EnclaveEncryptResult(data: archive, diskFilename: "\(diskName).\(fileExtension)")
    }

    static func decrypt(data: Data, password: String) throws -> (payload: Data, filename: String) {
        try validatePassword(password)

        var offset = 0
        let parsed = try parseHeader(data: data, offset: &offset)

        // The header (every byte up to the first blob) is bound as AAD for v3+.
        // v2 archives were sealed without AAD, so they verify with empty AAD —
        // which in GCM is identical to having sealed with no AAD at all.
        let headerAAD: Data = usesHeaderAAD(parsed.version) ? Data(data[0..<offset]) : Data()

        let key: SymmetricKey
        switch parsed.version {
        case currentVersion, legacyVersionV4, legacyVersionV3:
            guard let params = parsed.kdf else { throw EnclaveError.invalidFormat }
            key = try deriveKey(password: password, salt: parsed.salt, params: params)
        case legacyVersionV2:
            // Backward compatibility: v2 used SHA-512 -> HKDF-SHA512 (fast, not
            // password-hardened). Kept readable so users can migrate; re-encrypt
            // to upgrade to the v3 PBKDF2/Argon2id work factor.
            key = deriveKeyLegacyV2(password: password, salt: parsed.salt)
        default:
            throw EnclaveError.unsupportedVersion(parsed.version)
        }

        let filenameBlob = try readBlob(
            &offset,
            from: data,
            maxSize: maxFilenameBlobSize,
            encrypted: parsed.encryptFilename
        )
        let filename: String
        if parsed.encryptFilename {
            filename = try openString(blob: filenameBlob, using: key, aad: headerAAD)
        } else {
            filename = try parsePlaintextFilename(blob: filenameBlob)
        }

        // v5 binds the filename blob into the content AAD; v3/v4 bound only the
        // header; v2 used no AAD. Reconstruct the same value the sealer used.
        let contentAAD = bindsFilenameInContentAAD(parsed.version)
            ? headerAAD + filenameBlob
            : headerAAD

        let contentBlob = try readBlob(&offset, from: data, maxSize: maxContentBlobSize)
        let payload = try openData(blob: contentBlob, using: key, aad: contentAAD)

        guard offset == data.count else {
            throw EnclaveError.invalidFormat
        }

        return (payload, sanitizedFilename(filename))
    }

    // MARK: Header

    private struct Header {
        let version: UInt8
        let encryptFilename: Bool
        let kdf: KDFParams?   // nil for legacy v2
        let salt: Data
    }

    private static func usesHeaderAAD(_ version: UInt8) -> Bool {
        version >= legacyVersionV3
    }

    /// v5+ binds the filename blob into the content blob's AAD so the stored
    /// filename is authenticated even when filename encryption is disabled.
    private static func bindsFilenameInContentAAD(_ version: UInt8) -> Bool {
        version >= currentVersion
    }

    private static func parseHeader(data: Data, offset: inout Int) throws -> Header {
        let prefixSize = magic.count + 1
        guard data.count >= prefixSize else {
            throw EnclaveError.invalidFormat
        }
        guard data.starts(with: magic) else {
            throw EnclaveError.invalidFormat
        }

        offset = magic.count
        let version = data[offset]
        offset += 1

        switch version {
        case currentVersion, legacyVersionV4:
            guard offset + 1 <= data.count else { throw EnclaveError.invalidFormat }
            let flags = data[offset]
            offset += 1
            guard flags & ~flagEncryptFilename == 0 else {
                throw EnclaveError.invalidFormat
            }
            let encryptFilename = (flags & flagEncryptFilename) != 0
            let (kdf, salt) = try parseKDFHeader(data: data, offset: &offset)
            return Header(version: version, encryptFilename: encryptFilename, kdf: kdf, salt: salt)

        case legacyVersionV3:
            let (kdf, salt) = try parseKDFHeader(data: data, offset: &offset)
            return Header(version: version, encryptFilename: true, kdf: kdf, salt: salt)

        case legacyVersionV2:
            guard offset + saltLength <= data.count else { throw EnclaveError.invalidFormat }
            let salt = Data(data[offset..<(offset + saltLength)]); offset += saltLength
            return Header(version: version, encryptFilename: true, kdf: nil, salt: salt)

        default:
            if version > currentVersion {
                throw EnclaveError.unsupportedVersion(version)
            }
            throw EnclaveError.invalidFormat
        }
    }

    private static func parseKDFHeader(data: Data, offset: inout Int) throws -> (KDFParams, Data) {
        guard offset + 2 <= data.count else { throw EnclaveError.invalidFormat }
        let kdfID = data[offset]; offset += 1
        let bodyLen = Int(data[offset]); offset += 1

        guard offset + bodyLen + saltLength <= data.count else {
            throw EnclaveError.invalidFormat
        }
        let body = Data(data[offset..<(offset + bodyLen)]); offset += bodyLen
        let kdf = try KDFParams.decode(id: kdfID, body: body)
        let salt = Data(data[offset..<(offset + saltLength)]); offset += saltLength
        return (kdf, salt)
    }

    private static func parsePlaintextFilename(blob: Data) throws -> String {
        guard let text = String(data: blob, encoding: .utf8), !text.isEmpty else {
            throw EnclaveError.invalidFormat
        }
        return sanitizedFilename(text)
    }

    private static func validatePassword(_ password: String) throws {
        guard !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw EnclaveError.emptyPassword
        }
    }

    // MARK: Key derivation

    static func deriveKey(password: String, salt: Data, params: KDFParams) throws -> SymmetricKey {
        switch params {
        case .pbkdf2(let iterations):
            let keyData = try pbkdf2SHA256(
                password: password, salt: salt, iterations: iterations, keyLength: 32
            )
            return SymmetricKey(data: keyData)
        case .argon2id(let memoryKiB, let iterations, let parallelism):
            let keyData = try argon2id(
                password: password, salt: salt,
                memoryKiB: memoryKiB, iterations: iterations,
                parallelism: parallelism, keyLength: 32
            )
            return SymmetricKey(data: keyData)
        }
    }

    /// PBKDF2-HMAC-SHA256 via CommonCrypto (part of the SDK; no extra linker flags,
    /// no third-party dependency). This is a real password-hardening KDF: the
    /// iteration count makes offline guessing expensive.
    private static func pbkdf2SHA256(
        password: String, salt: Data, iterations: UInt32, keyLength: Int
    ) throws -> Data {
        let passwordData = Data(password.utf8) // non-empty: validated by caller
        var derived = Data(repeating: 0, count: keyLength)

        let status: Int32 = derived.withUnsafeMutableBytes { derivedBuf in
            salt.withUnsafeBytes { saltBuf in
                passwordData.withUnsafeBytes { passwordBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuf.baseAddress!.assumingMemoryBound(to: CChar.self),
                        passwordData.count,
                        saltBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        guard Int(status) == kCCSuccess else {
            throw EnclaveError.keyDerivationFailed
        }
        return derived
    }

    /// Argon2id via the bundled, RFC 9106-validated C backend (`Sources/CArgon2`).
    /// The v3 header already carries these parameters, so this is a pure
    /// implementation detail — no format change. To swap in a third-party library
    /// later, only the call below changes; the signature mirrors the conventional
    /// Argon2 API.
    private static func argon2id(
        password: String, salt: Data,
        memoryKiB: UInt32, iterations: UInt32, parallelism: UInt8, keyLength: Int
    ) throws -> Data {
        let passwordData = Data(password.utf8) // non-empty: validated by caller
        var out = Data(repeating: 0, count: keyLength)

        let rc: Int32 = out.withUnsafeMutableBytes { outBuf in
            passwordData.withUnsafeBytes { pwBuf in
                salt.withUnsafeBytes { saltBuf in
                    enclave_argon2id_raw(
                        pwBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        passwordData.count,
                        saltBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        iterations,
                        memoryKiB,
                        UInt32(parallelism),
                        outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        guard rc == 0 else {
            throw EnclaveError.keyDerivationFailed
        }
        return out
    }

    /// Legacy v2 derivation (SHA-512 -> HKDF-SHA512). Decrypt-only.
    private static func deriveKeyLegacyV2(password: String, salt: Data) -> SymmetricKey {
        var material = Data(password.utf8)
        material.append(salt)
        let digest = SHA512.hash(data: material)
        let inputKey = SymmetricKey(data: Data(digest))
        return HKDF<SHA512>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: Data("Enclave-v2".utf8),
            outputByteCount: 32
        )
    }

    // MARK: Helpers

    private static func diskFilename(for salt: Data, sealedFilename: Data) -> String {
        var material = salt
        material.append(sealedFilename)
        let digest = SHA512.hash(data: material)
        return Data(digest).map { String(format: "%02x", $0) }.joined().prefix(diskNameHexLength).lowercased()
    }

    private static func sanitizedFilename(_ name: String) -> String {
        let base = (name as NSString).lastPathComponent
        guard !base.isEmpty, base != ".", base != ".." else {
            return "file"
        }
        return base
    }

    private static func filesystemSafeFilename(_ name: String) -> String {
        var safe = sanitizedFilename(name)
        safe = safe.replacingOccurrences(of: "/", with: "_")
        safe = safe.replacingOccurrences(of: ":", with: "_")
        safe = safe.replacingOccurrences(of: "\0", with: "")
        guard !safe.isEmpty, safe != ".", safe != ".." else {
            return "file"
        }
        return safe
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw EnclaveError.randomGenerationFailed
        }
        return Data(bytes)
    }

    static func uint32BE(_ value: UInt32) -> Data {
        var be = value.bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }

    static func readUInt32BE(_ bytes: [UInt8], at index: Int) -> UInt32 {
        (UInt32(bytes[index]) << 24)
            | (UInt32(bytes[index + 1]) << 16)
            | (UInt32(bytes[index + 2]) << 8)
            | UInt32(bytes[index + 3])
    }

    private static func appendBlob(
        _ data: inout Data,
        _ blob: Data,
        encrypted: Bool = true
    ) throws {
        guard blob.count <= UInt32.max else {
            throw EnclaveError.payloadTooLarge
        }
        if encrypted {
            guard blob.count >= minSealedBlobSize else {
                throw EnclaveError.invalidFormat
            }
        } else {
            guard !blob.isEmpty else {
                throw EnclaveError.invalidFormat
            }
        }
        var length = UInt32(blob.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(blob)
    }

    private static func readBlob(
        _ offset: inout Int,
        from data: Data,
        maxSize: Int,
        encrypted: Bool = true
    ) throws -> Data {
        guard offset + 4 <= data.count else {
            throw EnclaveError.invalidFormat
        }

        let lengthBytes = [UInt8](data[offset..<(offset + 4)])
        let length = (UInt32(lengthBytes[0]) << 24) | (UInt32(lengthBytes[1]) << 16)
            | (UInt32(lengthBytes[2]) << 8) | UInt32(lengthBytes[3])
        offset += 4

        if encrypted {
            guard length > 0, Int(length) >= minSealedBlobSize, Int(length) <= maxSize else {
                throw EnclaveError.invalidFormat
            }
        } else {
            guard length > 0, Int(length) <= maxSize else {
                throw EnclaveError.invalidFormat
            }
        }
        guard offset + Int(length) <= data.count else {
            throw EnclaveError.invalidFormat
        }

        let blob = data[offset..<(offset + Int(length))]
        offset += Int(length)
        return Data(blob)
    }

    private static func combined(_ sealed: AES.GCM.SealedBox) -> Data {
        if let value = sealed.combined {
            return value
        }
        return Data(sealed.nonce) + sealed.ciphertext + sealed.tag
    }

    private static func openString(blob: Data, using key: SymmetricKey, aad: Data) throws -> String {
        let opened = try openData(blob: blob, using: key, aad: aad)
        guard let text = String(data: opened, encoding: .utf8), !text.isEmpty else {
            throw EnclaveError.wrongPassword
        }
        return text
    }

    private static func openData(blob: Data, using key: SymmetricKey, aad: Data) throws -> Data {
        do {
            let sealed = try AES.GCM.SealedBox(combined: blob)
            return try AES.GCM.open(sealed, using: key, authenticating: aad)
        } catch {
            throw EnclaveError.wrongPassword
        }
    }
}
