# Enclave

**Enclave** is a password-based file and folder encryption app for **macOS** and **Windows**. Both platforms write and read the same **`.enclave`** archive format, so a file encrypted on one machine decrypts on the other with the same password.

| | |
|---|---|
| **Version** | 1.7.1 (build 20) |
| **Encryption** | AES-256-GCM |
| **Key derivation (new files)** | Argon2id (64 MiB, 3 iterations, 1 lane) |
| **Archive format** | `ENCLAVE1` v5 (reads v5 / v4 / v3 / v2) |
| **Interop** | Opens EnigmaVault Secure-mode **`.enigma`** archives (same wire format) |

Security design, threat model, and format details: **[SECURITY.md](SECURITY.md)**.  
History of changes: [Enclave-macOS/CHANGELOG.md](Enclave-macOS/CHANGELOG.md).

---

## What it does

- Encrypts a **file** or an entire **folder** into a single `.enclave` archive
- Optionally encrypts the **original filename** (on by default); otherwise the name stays readable on disk
- Derives a 256-bit key from your password with a memory-hard KDF and a random salt
- Authenticates the archive header (and, in v5, the stored filename) so tampering fails decryption
- Never stores your password; if you lose it, the data cannot be recovered

It is built for **data at rest** (USB drives, cloud sync folders, backups). It is not a full-disk encryptor, a messaging app, or an online vault service.

---

## Repository layout

```
Enclave/
├── README.md                 ← this file
├── SECURITY.md               ← threat model, crypto, safe use
├── .gitignore
├── Enclave-macOS/            ← Swift GUI + CLI, bundled Argon2 C
│   ├── Sources/
│   ├── Resources/
│   ├── build.sh
│   ├── test_enclave.swift
│   └── CHANGELOG.md
└── Enclave For Windows/      ← .NET 8 WPF GUI + CLI
    ├── Enclave.sln
    ├── README.md             ← Windows-specific build notes
    ├── src/
    │   ├── EnclaveCore/      ← shared crypto & I/O
    │   ├── EnclaveCli/
    │   └── EnclaveApp/
    └── BUILD INSTALLER.bat
```

Both trees implement the same format. Prefer changing crypto in both ports when you change the wire format.

---

## Quick start

### macOS

```bash
cd Enclave-macOS
./build.sh
```

See `Enclave-macOS/build.sh` for targets (app bundle, CLI, tests). Run the regression suite with `test_enclave.swift` as wired by the build script.

### Windows

Requires the **.NET 8 SDK** (x64).

```bat
cd "Enclave For Windows"
dotnet build -c Release
dotnet run --project src\EnclaveCli -c Release -- selftest
```

GUI:

```bat
dotnet run --project src\EnclaveApp -c Release
```

Installer (on a Windows machine with the SDK and Inno Setup):

```bat
BUILD INSTALLER.bat
```

More detail: [Enclave For Windows/README.md](Enclave%20For%20Windows/README.md).

---

## CLI overview

Commands are available on both platforms (`enclave` / `enclave-cli`).

```text
encrypt <file-or-folder> [-p password] [-o output] [--plaintext-filename]
decrypt <archive>        [-p password] [-o output]
selftest                 # Windows CLI; macOS has a separate test binary
help
```

Examples:

```bash
# Encrypt (prompts for password if -p is omitted)
enclave-cli encrypt report.pdf
enclave-cli encrypt ~/Projects --plaintext-filename -o ~/out

# Decrypt
enclave-cli decrypt a3f8b2c1d4e5f678....enclave
```

Avoid `-p` / `--password` on shared machines: the password can appear in process lists. Prefer the interactive prompt.

---

## Cryptography (summary)

| Role | Algorithm |
|------|-----------|
| Content encryption | AES-256-GCM (12-byte nonce, 16-byte tag) |
| Filename encryption (default) | AES-256-GCM, same key, header as AAD |
| Key derivation (new archives) | Argon2id, m=65536 KiB, t=3, p=1 → 32-byte key |
| Key derivation (legacy v3) | PBKDF2-HMAC-SHA256 (iterations in header; default was 600 000) |
| Key derivation (legacy v2) | SHA-512 then HKDF-SHA512 (decrypt only; not password-hard) |
| On-disk name (encrypted-filename mode) | First 32 hex chars of SHA-512(salt ‖ sealed filename) |
| Randomness | OS CSPRNG (`SecRandomCopyBytes` / `RandomNumberGenerator`) |

New archives are **format v5**:

1. Header (`ENCLAVE1` + version + flags + KDF block + salt) is authenticated as GCM AAD on the filename seal (when used) and is part of content AAD.
2. The **filename blob** is also bound into the content blob’s AAD, so renaming or rewriting a plaintext filename is detected.
3. Folders are packed as an `ENCLPKG1` payload, then encrypted as one archive.

Full discussion: [SECURITY.md](SECURITY.md).

---

## Cross-platform interop

| Primitive | macOS | Windows |
|-----------|-------|---------|
| AES-256-GCM | CryptoKit | `AesGcm` |
| SHA-512 / HKDF | CryptoKit | `SHA512` / `HKDF` |
| PBKDF2 | CommonCrypto | `Rfc2898DeriveBytes` |
| Argon2id | Bundled `argon2.c` (RFC 9106) | Konscious.Security.Cryptography |

Multi-byte integers on the wire are **big-endian**. Argon2id is deterministic across correct implementations; the Windows `selftest` includes a known-answer test so both ports produce the same key bytes.

**EnigmaVault:** from 1.7.1, Enclave opens `.enigma` files created in EnigmaVault’s Secure mode (same `ENCLAVE1` magic and crypto stack).

---

## Limits and practical notes

- Payloads are processed **in memory** (no streaming). Practical ceilings are on the order of a few GiB per file; Windows .NET arrays are tighter (~2 GiB) than the format’s ~4 GiB design cap.
- Folder pack skips **symlinks** / reparse points and (on macOS) **hidden** files; path traversal is rejected on unpack.
- Decrypt will not overwrite a non-empty destination folder for folder archives.
- You cannot encrypt an existing `.enclave` / `.enigma` archive again by design.

---

## Contributing / changing crypto

1. Update the format or KDF in **both** `Enclave-macOS` and `Enclave For Windows` so archives stay interoperable.
2. Bump version/build in `AppInfo` on both platforms.
3. Extend macOS `test_enclave.swift` and Windows `SelfTest.cs`.
4. Document security-relevant changes in [SECURITY.md](SECURITY.md) and the changelog.
5. Prefer a new format version or header-carried KDF parameters over breaking old archives.

---

## License

No license file is present in this repository yet. Add one before publishing or distributing if you intend third-party use.
