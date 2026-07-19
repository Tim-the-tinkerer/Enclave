import CryptoKit
import Foundation
import Security

@main
enum EnclaveTests {
    static func main() {
        func assert(_ condition: Bool, _ message: String) {
            if !condition {
                fputs("FAIL: \(message)\n", stderr)
                exit(1)
            }
        }

        let payload = Data("Hello, Enclave!".utf8)
        let password = "test-password-123"
        let originalName = "secret-notes.txt"
        let testKDF = KDFParams.pbkdf2(iterations: 1)

        do {
            assert(EnclaveCrypto.isArchiveFilename("file.enclave"), "enclave extension detection")
            assert(!EnclaveCrypto.isArchiveFilename("file.vault"), "legacy vault extension rejected")
            assert(!EnclaveCrypto.isArchiveFilename("file.txt"), "plaintext extension detection")

            let encrypted = try EnclaveCrypto.encrypt(
                data: payload,
                originalFilename: originalName,
                password: password,
                kdf: testKDF
            )

            assert(encrypted.data.starts(with: EnclaveCrypto.magic), "new archives use ENCLAVE1 magic")
            assert(
                encrypted.data[EnclaveCrypto.magic.count] == EnclaveCrypto.currentVersion,
                "new archives use current format version"
            )
            assert(EnclaveCrypto.isArchiveData(encrypted.data), "archive data detection")
            assert(!EnclaveCrypto.isArchiveData(Data("VAULTENC".utf8)), "legacy magic rejected")
            assert(encrypted.diskFilename.hasSuffix(".enclave"), "disk filename should use .enclave extension")
            assert(encrypted.diskFilename.count == 32 + 1 + EnclaveCrypto.fileExtension.count, "disk filename length")

            let decrypted = try EnclaveCrypto.decrypt(data: encrypted.data, password: password)
            assert(decrypted.payload == payload, "payload round-trip")
            assert(decrypted.filename == originalName, "filename round-trip")

            let v2 = try makeV2Archive(
                payload: payload,
                filename: originalName,
                password: password
            )
            let v2Decrypted = try EnclaveCrypto.decrypt(data: v2, password: password)
            assert(v2Decrypted.payload == payload, "v2 payload round-trip")
            assert(v2Decrypted.filename == originalName, "v2 filename round-trip")

            // Argon2id end-to-end round-trip (v3 header with kdfID = 2).
            let argonEncrypted = try EnclaveCrypto.encrypt(
                data: payload,
                originalFilename: originalName,
                password: password,
                kdf: .argon2id(memoryKiB: 64, iterations: 3, parallelism: 1)
            )
            let argonDecrypted = try EnclaveCrypto.decrypt(data: argonEncrypted.data, password: password)
            assert(argonDecrypted.payload == payload, "argon2id payload round-trip")
            assert(argonDecrypted.filename == originalName, "argon2id filename round-trip")

            // Argon2id known-answer test. The expected value was produced by the
            // C backend after it reproduced the official RFC 9106 Argon2id vector,
            // so this pins the whole BLAKE2b + Argon2id chain as compiled here.
            let katSalt = Data(repeating: 0x02, count: 16)
            let katKey = try EnclaveCrypto.deriveKey(
                password: "enclave-kat",
                salt: katSalt,
                params: .argon2id(memoryKiB: 64, iterations: 3, parallelism: 1)
            )
            let katActual = katKey.withUnsafeBytes { Array($0) }
            let katExpected: [UInt8] = [
                0x28, 0x23, 0x5d, 0x98, 0xf7, 0x8a, 0x35, 0x63,
                0x1f, 0x74, 0x0d, 0xe2, 0x47, 0xe3, 0xcf, 0xae,
                0x5c, 0x87, 0x1d, 0x2e, 0x1d, 0x9a, 0xcf, 0x83,
                0x65, 0x6e, 0x05, 0x91, 0xdc, 0x99, 0x58, 0x2c
            ]
            assert(katActual == katExpected, "Argon2id known-answer test")

            // New archives default to Argon2id (kdfID byte == 2, after magic,
            // version, and flags). Guards against an accidental revert of the
            // default KDF.
            let defaultEncrypted = try EnclaveCrypto.encrypt(
                data: payload, originalFilename: originalName, password: password
            )
            assert(
                defaultEncrypted.data[EnclaveCrypto.magic.count + 2] == KDFAlgorithm.argon2id.rawValue,
                "new archives default to Argon2id"
            )
            let defaultDecrypted = try EnclaveCrypto.decrypt(data: defaultEncrypted.data, password: password)
            assert(defaultDecrypted.payload == payload, "default-KDF payload round-trip")

            let visibleEncrypted = try EnclaveCrypto.encrypt(
                data: payload,
                originalFilename: originalName,
                password: password,
                encryptFilename: false,
                kdf: testKDF
            )
            assert(
                visibleEncrypted.data[EnclaveCrypto.magic.count] == EnclaveCrypto.currentVersion,
                "plaintext filename archives use current format version"
            )
            assert(
                visibleEncrypted.data[EnclaveCrypto.magic.count + 1] == 0,
                "plaintext filename flag is clear"
            )
            assert(
                visibleEncrypted.diskFilename == "\(originalName).\(EnclaveCrypto.fileExtension)",
                "plaintext filename disk name preserves original name"
            )
            let visibleDecrypted = try EnclaveCrypto.decrypt(data: visibleEncrypted.data, password: password)
            assert(visibleDecrypted.payload == payload, "plaintext filename payload round-trip")
            assert(visibleDecrypted.filename == originalName, "plaintext filename round-trip")

            // v5 binds the filename into the content AAD, so tampering with the
            // visible (plaintext) filename is now detected. Before v5 the content
            // would still decrypt and the restored name would silently differ.
            var fnTampered = visibleEncrypted.data
            if let range = fnTampered.range(of: Data(originalName.utf8)) {
                fnTampered[range.lowerBound] ^= 0x01
            } else {
                fputs("FAIL: could not locate plaintext filename to tamper\n", stderr)
                exit(1)
            }
            do {
                _ = try EnclaveCrypto.decrypt(data: fnTampered, password: password)
                fputs("FAIL: v5 plaintext filename tampering should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected — content AAD no longer matches
            }

            let v3 = try makeV3Archive(
                payload: payload,
                filename: originalName,
                password: password
            )
            let v3Decrypted = try EnclaveCrypto.decrypt(data: v3, password: password)
            assert(v3Decrypted.payload == payload, "v3 payload round-trip")
            assert(v3Decrypted.filename == originalName, "v3 filename round-trip")

            // v4 archives (header-only content AAD) must still decrypt under the
            // v5 code, both with encrypted and plaintext filenames.
            let v4 = try makeV4Archive(
                payload: payload, filename: originalName, password: password, encryptFilename: true
            )
            let v4Decrypted = try EnclaveCrypto.decrypt(data: v4, password: password)
            assert(v4Decrypted.payload == payload, "v4 payload round-trip")
            assert(v4Decrypted.filename == originalName, "v4 filename round-trip")

            let v4Plain = try makeV4Archive(
                payload: payload, filename: originalName, password: password, encryptFilename: false
            )
            let v4PlainDecrypted = try EnclaveCrypto.decrypt(data: v4Plain, password: password)
            assert(v4PlainDecrypted.payload == payload, "v4 plaintext-filename payload round-trip")
            assert(v4PlainDecrypted.filename == originalName, "v4 plaintext-filename round-trip")

            var tampered = encrypted.data
            tampered.append(0xFF)
            do {
                _ = try EnclaveCrypto.decrypt(data: tampered, password: password)
                fputs("FAIL: trailing bytes should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            var headerTampered = encrypted.data
            headerTampered[EnclaveCrypto.magic.count] = EnclaveCrypto.legacyVersionV2
            do {
                _ = try EnclaveCrypto.decrypt(data: headerTampered, password: password)
                fputs("FAIL: header tampering should be rejected via AAD\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            var flagsTampered = encrypted.data
            flagsTampered[EnclaveCrypto.magic.count + 1] = 0
            do {
                _ = try EnclaveCrypto.decrypt(data: flagsTampered, password: password)
                fputs("FAIL: v4 flags tampering should be rejected via AAD\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let unsafeVisible = try EnclaveCrypto.encrypt(
                data: payload,
                originalFilename: "bad:name.txt",
                password: password,
                encryptFilename: false,
                kdf: testKDF
            )
            assert(
                unsafeVisible.diskFilename == "bad_name.txt.\(EnclaveCrypto.fileExtension)",
                "plaintext disk name strips path separators"
            )

            do {
                _ = try EnclaveCrypto.encrypt(data: payload, originalFilename: originalName, password: "")
                fputs("FAIL: empty password should fail on encrypt\n", stderr)
                exit(1)
            } catch EnclaveError.emptyPassword {
                // expected
            }

            do {
                _ = try EnclaveCrypto.decrypt(data: encrypted.data, password: "wrong-password")
                fputs("FAIL: wrong password should fail\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let legacy = try makeLegacyV1Archive(
                payload: payload,
                filename: originalName,
                password: password
            )
            do {
                _ = try EnclaveCrypto.decrypt(data: legacy, password: password)
                fputs("FAIL: legacy VAULTENC archives should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            var mismatched = encrypted.data
            mismatched[EnclaveCrypto.magic.count] = 1
            do {
                _ = try EnclaveCrypto.decrypt(data: mismatched, password: password)
                fputs("FAIL: unsupported version should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let normalized = EnclaveIO.normalizedArchiveURL(URL(fileURLWithPath: "/tmp/output.txt"))
            assert(normalized.pathExtension == EnclaveCrypto.fileExtension, "normalized archive extension")

            let plainURL = URL(fileURLWithPath: "/tmp/enclave-plain.txt")
            try payload.write(to: plainURL)
            defer { try? FileManager.default.removeItem(at: plainURL) }
            try EnclaveIO.validatePlaintextInput(plainURL)

            let archiveURL = URL(fileURLWithPath: "/tmp/test.enclave")
            try encrypted.data.write(to: archiveURL)
            defer { try? FileManager.default.removeItem(at: archiveURL) }
            do {
                try EnclaveIO.validatePlaintextInput(archiveURL)
                fputs("FAIL: archive should not be accepted for encryption\n", stderr)
                exit(1)
            } catch EnclaveError.cannotEncryptArchive {
                // expected
            }

            let fakeArchiveURL = URL(fileURLWithPath: "/tmp/fake.enclave")
            try Data("not an archive".utf8).write(to: fakeArchiveURL)
            defer { try? FileManager.default.removeItem(at: fakeArchiveURL) }
            do {
                try EnclaveIO.validateArchiveInput(fakeArchiveURL)
                fputs("FAIL: fake .enclave without magic should be rejected\n", stderr)
                exit(1)
            } catch EnclaveError.invalidFormat {
                // expected
            }

            let folderRoot = URL(fileURLWithPath: "/tmp/enclave-folder-src")
            let nested = folderRoot.appendingPathComponent("nested", isDirectory: true)
            try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
            try payload.write(to: folderRoot.appendingPathComponent("readme.txt"))
            try Data("nested-data".utf8).write(to: nested.appendingPathComponent("child.txt"))
            // Empty file: must survive the pack/encrypt/decrypt/unpack round-trip
            // (regression test — empty entries previously failed to decrypt).
            // Non-hidden so pack's skipsHiddenFiles doesn't exclude it.
            try Data().write(to: folderRoot.appendingPathComponent("empty.txt"))
            defer { try? FileManager.default.removeItem(at: folderRoot) }

            let preparedFolder = try EnclaveIO.prepareEncryptionPayload(from: folderRoot)
            assert(preparedFolder.filename == "enclave-folder-src.enclavefolder", "folder stored filename")
            let encryptedFolder = try EnclaveCrypto.encrypt(
                data: preparedFolder.data,
                originalFilename: preparedFolder.filename,
                password: password,
                kdf: testKDF
            )
            let decryptedFolder = try EnclaveCrypto.decrypt(data: encryptedFolder.data, password: password)
            assert(EnclaveFolder.isFolderPayload(decryptedFolder.payload), "folder payload marker")

            let restoreParent = URL(fileURLWithPath: "/tmp/enclave-folder-out")
            try? FileManager.default.removeItem(at: restoreParent)
            try FileManager.default.createDirectory(at: restoreParent, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: restoreParent) }
            try EnclaveIO.writeDecryptedPayload(
                decryptedFolder.payload,
                filename: decryptedFolder.filename,
                to: restoreParent
            )
            let restored = restoreParent.appendingPathComponent("enclave-folder-src", isDirectory: true)
            let restoredNested = restored.appendingPathComponent("nested/child.txt")
            assert(FileManager.default.fileExists(atPath: restored.appendingPathComponent("readme.txt").path), "folder file restored")
            assert(try Data(contentsOf: restoredNested) == Data("nested-data".utf8), "nested folder file restored")
            let restoredEmpty = restored.appendingPathComponent("empty.txt")
            assert(FileManager.default.fileExists(atPath: restoredEmpty.path), "empty file restored")
            assert(try Data(contentsOf: restoredEmpty).isEmpty, "empty file is zero-length after round-trip")

            let visibleFolderEncrypted = try EnclaveCrypto.encrypt(
                data: preparedFolder.data,
                originalFilename: preparedFolder.filename,
                password: password,
                encryptFilename: false,
                kdf: testKDF
            )
            assert(
                visibleFolderEncrypted.diskFilename == "enclave-folder-src.\(EnclaveCrypto.fileExtension)",
                "plaintext folder disk name uses folder title not .enclavefolder suffix"
            )
            let visibleFolderDecrypted = try EnclaveCrypto.decrypt(
                data: visibleFolderEncrypted.data,
                password: password
            )
            assert(visibleFolderDecrypted.filename == "enclave-folder-src", "plaintext folder stored name")
            assert(EnclaveFolder.isFolderPayload(visibleFolderDecrypted.payload), "plaintext folder payload marker")

            do {
                try EnclaveFolder.unpack(
                    payload: decryptedFolder.payload,
                    to: restoreParent,
                    folderName: "enclave-folder-src"
                )
                fputs("FAIL: unpack should reject existing non-empty folder\n", stderr)
                exit(1)
            } catch EnclaveError.destinationExists {
                // expected
            }

            let maliciousFolder = try makeFolderPayload(entries: [
                ("../../../tmp/pwned.txt", Data("bad".utf8))
            ])
            do {
                let scratch = URL(fileURLWithPath: "/tmp/enclave-folder-scratch")
                try? FileManager.default.removeItem(at: scratch)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: scratch) }
                try EnclaveFolder.unpack(payload: maliciousFolder, to: scratch, folderName: "safe")
                fputs("FAIL: path traversal should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            do {
                _ = try KDFParams.decode(
                    id: KDFAlgorithm.argon2id.rawValue,
                    body: Data([0, 0, 0, 64, 0, 0, 0, 3, 32])
                )
                fputs("FAIL: excessive Argon2 parallelism should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let expanded = EnclaveIO.expandedPath("~/enclave-test.txt")
            assert(expanded == "\(home)/enclave-test.txt", "tilde path expansion")

            let slashFolder = try makeFolderPayload(entries: [
                ("nested//child.txt", Data("bad".utf8))
            ])
            do {
                let scratch = URL(fileURLWithPath: "/tmp/enclave-folder-slash")
                try? FileManager.default.removeItem(at: scratch)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: scratch) }
                try EnclaveFolder.unpack(payload: slashFolder, to: scratch, folderName: "safe")
                fputs("FAIL: empty path components should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let backslashFolder = try makeFolderPayload(entries: [
                ("nested\\child.txt", Data("bad".utf8))
            ])
            do {
                let scratch = URL(fileURLWithPath: "/tmp/enclave-folder-backslash")
                try? FileManager.default.removeItem(at: scratch)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: scratch) }
                try EnclaveFolder.unpack(payload: backslashFolder, to: scratch, folderName: "safe")
                fputs("FAIL: backslash paths should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            do {
                let scratch = URL(fileURLWithPath: "/tmp/enclave-folder-evil-name")
                try? FileManager.default.removeItem(at: scratch)
                try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: scratch) }
                try EnclaveFolder.unpack(
                    payload: decryptedFolder.payload,
                    to: scratch,
                    folderName: "../evil"
                )
                fputs("FAIL: malicious folder names should be rejected\n", stderr)
                exit(1)
            } catch {
                // expected
            }

            let oversizedArchiveURL = URL(fileURLWithPath: "/tmp/enclave-oversized.enclave")
            FileManager.default.createFile(atPath: oversizedArchiveURL.path, contents: EnclaveCrypto.magic)
            let sparseHandle = try FileHandle(forWritingTo: oversizedArchiveURL)
            try sparseHandle.truncate(atOffset: UInt64(EnclaveCrypto.maxArchiveSize + 1))
            try sparseHandle.close()
            defer { try? FileManager.default.removeItem(at: oversizedArchiveURL) }
            do {
                _ = try EnclaveIO.readArchive(from: oversizedArchiveURL)
                fputs("FAIL: archive larger than max should be rejected before full load\n", stderr)
                exit(1)
            } catch EnclaveError.payloadTooLarge {
                // expected
            }

            print("All tests passed.")
        } catch {
            fputs("FAIL: \(error)\n", stderr)
            exit(1)
        }
    }

    private static func makeFolderPayload(entries: [(String, Data)]) throws -> Data {
        var archive = Data("ENCLPKG1".utf8)
        archive.append(UInt8(1))
        var count = UInt32(entries.count).bigEndian
        withUnsafeBytes(of: &count) { archive.append(contentsOf: $0) }
        for (path, data) in entries {
            let pathData = Data(path.utf8)
            var pathLen = UInt32(pathData.count).bigEndian
            withUnsafeBytes(of: &pathLen) { archive.append(contentsOf: $0) }
            archive.append(pathData)
            var dataLen = UInt64(data.count).bigEndian
            withUnsafeBytes(of: &dataLen) { archive.append(contentsOf: $0) }
            archive.append(data)
        }
        return archive
    }

    private static func makeV4Archive(
        payload: Data,
        filename: String,
        password: String,
        encryptFilename: Bool
    ) throws -> Data {
        let salt = try randomBytes(count: EnclaveCrypto.saltLength)
        let key = try EnclaveCrypto.deriveKey(
            password: password,
            salt: salt,
            params: .pbkdf2(iterations: 1)
        )

        var header = Data()
        header.append(EnclaveCrypto.magic)
        header.append(EnclaveCrypto.legacyVersionV4)
        header.append(encryptFilename ? EnclaveCrypto.flagEncryptFilename : 0)
        header.append(KDFAlgorithm.pbkdf2SHA256.rawValue)
        header.append(UInt8(4))
        header.append(EnclaveCrypto.uint32BE(1))
        header.append(salt)

        let filenameData = Data(filename.utf8)
        let filenameBlob: Data
        if encryptFilename {
            let filenameNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
            let encryptedFilename = try AES.GCM.seal(filenameData, using: key, nonce: filenameNonce, authenticating: header)
            filenameBlob = combined(encryptedFilename)
        } else {
            filenameBlob = filenameData
        }

        // v4 sealed content with AAD = header only (no filename binding).
        let contentNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedContent = try AES.GCM.seal(payload, using: key, nonce: contentNonce, authenticating: header)
        let contentBlob = combined(encryptedContent)

        var archive = header
        try appendBlob(&archive, filenameBlob)
        try appendBlob(&archive, contentBlob)
        return archive
    }

    private static func makeV3Archive(
        payload: Data,
        filename: String,
        password: String
    ) throws -> Data {
        let salt = try randomBytes(count: EnclaveCrypto.saltLength)
        let key = try EnclaveCrypto.deriveKey(
            password: password,
            salt: salt,
            params: .pbkdf2(iterations: 1)
        )

        var header = Data()
        header.append(EnclaveCrypto.magic)
        header.append(EnclaveCrypto.legacyVersionV3)
        header.append(KDFAlgorithm.pbkdf2SHA256.rawValue)
        header.append(UInt8(4))
        header.append(EnclaveCrypto.uint32BE(1))
        header.append(salt)

        let filenameData = Data(filename.utf8)
        let filenameNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedFilename = try AES.GCM.seal(filenameData, using: key, nonce: filenameNonce, authenticating: header)
        let filenameBlob = combined(encryptedFilename)

        let contentNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedContent = try AES.GCM.seal(payload, using: key, nonce: contentNonce, authenticating: header)
        let contentBlob = combined(encryptedContent)

        var archive = header
        try appendBlob(&archive, filenameBlob)
        try appendBlob(&archive, contentBlob)
        return archive
    }

    private static func makeV2Archive(
        payload: Data,
        filename: String,
        password: String
    ) throws -> Data {
        let salt = try randomBytes(count: EnclaveCrypto.saltLength)
        let key = v2Key(password: password, salt: salt)

        let filenameData = Data(filename.utf8)
        let filenameNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedFilename = try AES.GCM.seal(filenameData, using: key, nonce: filenameNonce)
        let filenameBlob = combined(encryptedFilename)

        let contentNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedContent = try AES.GCM.seal(payload, using: key, nonce: contentNonce)
        let contentBlob = combined(encryptedContent)

        var archive = Data()
        archive.append(EnclaveCrypto.magic)
        archive.append(EnclaveCrypto.legacyVersionV2)
        archive.append(salt)
        try appendBlob(&archive, filenameBlob)
        try appendBlob(&archive, contentBlob)
        return archive
    }

    private static func makeLegacyV1Archive(
        payload: Data,
        filename: String,
        password: String
    ) throws -> Data {
        let salt = try randomBytes(count: EnclaveCrypto.saltLength)
        let key = v1Key(password: password, salt: salt)

        let filenameData = Data(filename.utf8)
        let filenameNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedFilename = try AES.GCM.seal(filenameData, using: key, nonce: filenameNonce)
        let filenameBlob = combined(encryptedFilename)

        let contentNonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let encryptedContent = try AES.GCM.seal(payload, using: key, nonce: contentNonce)
        let contentBlob = combined(encryptedContent)

        var archive = Data()
        archive.append(Data("VAULTENC".utf8))
        archive.append(UInt8(1))
        archive.append(salt)
        try appendBlob(&archive, filenameBlob)
        try appendBlob(&archive, contentBlob)
        return archive
    }

    private static func appendBlob(_ data: inout Data, _ blob: Data) throws {
        guard blob.count <= UInt32.max else {
            throw EnclaveError.payloadTooLarge
        }
        var length = UInt32(blob.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(blob)
    }

    private static func v2Key(password: String, salt: Data) -> SymmetricKey {
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

    private static func v1Key(password: String, salt: Data) -> SymmetricKey {
        var material = Data(password.utf8)
        material.append(salt)
        let digest = SHA512.hash(data: material)
        return SymmetricKey(data: Data(digest.prefix(32)))
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw EnclaveError.invalidFormat
        }
        return Data(bytes)
    }

    private static func combined(_ sealed: AES.GCM.SealedBox) -> Data {
        if let value = sealed.combined {
            return value
        }
        return Data(sealed.nonce) + sealed.ciphertext + sealed.tag
    }
}