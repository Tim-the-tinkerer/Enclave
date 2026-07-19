# Changelog

All notable changes to Enclave are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.1] - 2026-07-18

### Added

- Opens **`.enigma`** archives created by EnigmaVault's Secure mode. The two apps share the same `ENCLAVE1` format (Argon2id + AES-256-GCM), so secure archives made in one now open directly in the other — both the file picker and the drag-and-drop / decrypt path accept `.enigma` alongside `.enclave`.

## [1.7.0] - 2026-06-29

### Security

- Format **v5**: the stored filename is now bound into the file blob's authentication (AAD), so tampering with the filename is detected even when filename encryption is disabled. Previously a plaintext filename could be altered without detection. New archives use v5; v4/v3/v2 still decrypt unchanged.

### Changed

- New archives use format v5 (default). v4 and v3 archives decrypt with their original header-only content authentication.
- Folder archive integer fields are assembled byte-by-byte (big-endian) instead of via unaligned `load(as:)`, avoiding a technically-undefined unaligned read; same change applied to the archive blob length reader

## [1.6.3] - 2026-06-29

### Fixed

- Folders containing empty (zero-byte) files now encrypt and decrypt correctly. Empty entries previously packed fine but failed to unpack with an "invalid format" error, aborting the whole folder restore. Regression test added covering an empty file in a folder round-trip.
- Folder unpack validates a corrupt entry-size field as `UInt64` before narrowing to `Int`, throwing a clean error instead of risking a trap on an out-of-range value

## [1.6.2] - 2026-06-29

### Security

- Plaintext on-disk filenames sanitize `/`, `:`, and null bytes for macOS safety
- Single-file encrypt rejects symlinks and checks size via file attributes when metadata is missing

### Fixed

- GUI blocks encrypting a selected `.enclave` archive with a clear error
- Choose/Clear/File menu actions ignored while an operation is in progress
- CLI rejects encrypt on `.enclave` inputs before loading payload
- About dialog, subtitle, and help fallback describe optional filename encryption

### Changed

- v4 archives reject flags-byte tampering via header AAD (test coverage added)

## [1.6.1] - 2026-06-29

### Fixed

- Plaintext folder archives use the folder title on disk (not `.enclavefolder`)

## [1.6.0] - 2026-06-29

### Added

- **Encrypt filename** toggle in the app (on by default) and `--plaintext-filename` CLI flag
- Format **v4** with a flags byte; filename encryption can be disabled while content stays encrypted

### Changed

- New archives use format v4; v3 archives still decrypt

## [1.5.3] - 2026-06-28

### Security

- Folder unpack uses path-component containment checks instead of string prefix matching (more robust on all volumes)
- Folder and file paths reject backslashes; folder names reject path separators and `..` sequences
- Archive size validation rejects symbolic links and falls back to file attributes when resource metadata is missing

### Fixed

- CLI expands `~` in input and output paths (consistent with the GUI)
- GUI validates `.enclave` magic bytes when selecting or dropping archives (no auto-decrypt on fake archives)
- Choose/Clear buttons disable while an operation is in progress

### Changed

- Password and file-selection placeholders clarified for encrypt and decrypt
- Help keyboard shortcut documents folder selection

## [1.5.2] - 2026-06-28

### Security

- Archive decrypt checks on-disk size before loading the full file into memory (CLI and GUI)
- Folder unpack rejects relative paths with empty components (e.g. `nested//file`)

### Fixed

- Password field clears after successful decrypt (matching encrypt behavior)
- Oversized-archive error message applies to both encrypt and decrypt

### Changed

- Help book adds a **Folder Encryption** section (pack format, skipped items, destination rules)

## [1.5.1] - 2026-06-27

### Security

- Folder unpack rejects path traversal (`..`, absolute paths) and verifies extracted files stay inside the destination directory
- Folder format enforces entry count, path length, and per-file size limits when packing and unpacking
- Argon2id decode caps parallelism at 8 lanes (prevents hostile headers from requesting excessive memory)
- Archive decrypt rejects directories passed as `.enclave` inputs

### Fixed

- Single-file encrypt checks file size before loading into memory (avoids reading oversized files)
- Folder decrypt refuses to overwrite an existing non-empty destination folder
- File menu label updated to **Choose…** (supports folders)

## [1.5.0] - 2026-06-27

### Added

- **Folder encryption** in the app and CLI: directories are packed into an `ENCLPKG1` bundle, then encrypted as a single `.enclave` archive
- Folder decrypt restores the original directory tree; GUI prompts for a destination parent folder
- `EnclaveFolder` module and `emptyFolder` error for folders with no encryptable files

### Changed

- File picker and drag-and-drop accept folders for encryption
- CLI usage documents `encrypt <file-or-folder>`

## [1.4.1] - 2026-06-27

### Changed

- Help book adds an **Algorithms** section documenting which hash/KDF is used for each purpose:
  - **Argon2id** (BLAKE2b internally) — default key derivation for new archives
  - **PBKDF2-HMAC-SHA256** — older v3 archives (still decryptable)
  - **HKDF-SHA512** — v2 legacy archives (decrypt-only)
  - **SHA-512** — on-disk filename hashing only (not password stretching)
  - **AES-256-GCM** — file and filename encryption
- CLI `help`, About dialog, main-window subtitle, and encrypt save-panel message updated to match
- `build.sh` fills `{{VERSION}}`/`{{BUILD}}` help placeholders from `Info.plist` during bundle assembly

### Fixed

- Help window no longer displayed literal `{{VERSION}}`/`{{BUILD}}` tokens in the subtitle
- Stale references to SHA-512 as the key-derivation algorithm removed from user-facing text (SHA-512 is filename hashing only for new files)
- Help fallback text (shown if the help bundle fails to load) now describes the correct algorithms
- Password field clears automatically after each successful encryption (not on cancel or failure)

## [1.4.0] - 2026-06-27

### Security

- **New archives now use Argon2id by default** (memory-hard: 64 MiB, 3 passes, 1 lane). This is stronger than PBKDF2 against GPU and custom-hardware password guessing. Existing PBKDF2 and v2 archives remain fully decryptable.

### Added

- **Argon2id key derivation** is now functional, backed by a self-contained C implementation (`Sources/CArgon2`) with no third-party dependencies. v3 archives carry the parameters needed to decrypt.
- Known-answer test pinning the Argon2id backend, derived after the implementation reproduced the official RFC 9106 Argon2id test vector
- Argon2id end-to-end encrypt/decrypt round-trip test

### Changed

- `encrypt()` defaults to Argon2id; pass `kdf: .pbkdf2(iterations:)` to select PBKDF2-HMAC-SHA256 instead
- `build.sh` compiles the Argon2 C backend with `clang` and links it into the CLI, app, and self-test builds
- Help book and CLI `--help` now describe Argon2id key derivation
- Help book rewritten from source: Argon2id defaults (65,536 KiB / 3 / 1), v3 header layout, KDF ids, AAD, v2/v1 compatibility, and CLI `help` command

## [1.3.1] - 2026-06-27

### Security

- v3 archives bind the file header as **AES-GCM additional authenticated data (AAD)**. Tampering with the version byte, KDF algorithm, work-factor parameters, or salt is detected during decryption instead of silently deriving a different key.

### Added

- Test that header tampering is rejected on v3 archives

### Fixed

- Help window reloads from disk on every open and disables web-view caching, so updated help content is always shown

## [1.3.0] - 2026-06-27

### Security

- New archives use format v3 with **PBKDF2-HMAC-SHA256** key derivation (600,000 iterations by default)
- KDF algorithm and work factor are stored in each archive header, so defaults can be raised over time without breaking older files
- Decode-time caps on PBKDF2/Argon2 parameters prevent hostile archives from forcing unbounded CPU or memory use

### Added

- `KDFAlgorithm` and `KDFParams` types for self-describing key-derivation metadata in v3 headers
- Argon2id format support (parameters encoded in header; implementation hook reserved for a future backend)
- `unsupportedKDF` and `keyDerivationFailed` error cases
- Tests for v3 round-trip and continued v2 decrypt compatibility

### Changed

- `encrypt()` accepts an optional `kdf` parameter (defaults to PBKDF2 at the current OWASP floor)
- v2 archives (`ENCLAVE1` + HKDF-SHA512) remain decryptable; re-encrypt to upgrade to v3

## [1.2.0] - 2026-06-27

### Removed

- **Breaking:** Legacy v1 format (`VAULTENC` magic, `.vault` extension) is no longer supported
- Removed `.vault` document type registration from the app bundle

### Changed

- Key derivation uses HKDF-SHA512 only (v2 `ENCLAVE1` format)
- Tests verify that legacy archives are rejected

## [1.1.3] - 2026-06-27

### Security

- Archive validation now checks file magic bytes, not just the `.enclave` extension

### Fixed

- Help HTML loads reliably from the bundled `Enclave.help` folder
- Help window loads HTML from the correct bundle path
- Removed duplicate ⌘? shortcut from the app menu (kept under **Help**)
- File drops ignored while encrypt/decrypt is in progress
- Build fails early if the help bundle is missing

## [1.1.2] - 2026-06-27

### Added

- Built-in help book (`Enclave.help`) with usage, CLI commands, and security notes
- Help window (⌘?) and **Help** menu

## [1.1.1] - 2026-06-27

### Security

- Bind archive magic to format version (`VAULTENC` ↔ v1, `ENCLAVE1` ↔ v2); reject mismatched headers
- Cap plaintext size before encryption to prevent oversized payloads
- Guard blob length encoding against `UInt32` overflow

### Fixed

- Header parser now validates minimum archive size correctly
- Random generation failures report a dedicated error instead of "invalid format"
- GUI stays in busy state until the save dialog completes (prevents double-submit)
- Save panel normalizes extension even when user omits `.enclave`
- CLI creates missing parent directories for explicit output paths
- Multi-file drops show which file is being used

### Added

- Tests for magic/version mismatch and archive URL normalization

## [1.1.0] - 2026-06-27

### Security

- New archives use format v2 (`ENCLAVE1` magic) with HKDF-SHA512 key derivation
- Legacy v1 archives (`VAULTENC` magic) remain decryptable for backward compatibility
- Reject empty passwords during encrypt and decrypt
- Check `SecRandomCopyBytes` for failure instead of silently using zero bytes
- Enforce blob size limits and minimum sealed-box sizes when parsing archives
- Reject archives with trailing garbage bytes after the payload

### Fixed

- CLI binary no longer collides with the GUI app on case-insensitive macOS volumes (`enclave-cli` vs `Enclave`)
- CLI `help` works without requiring a file argument
- CLI password prompt uses `getpass()` instead of `readLine()` (no hang, reads from `/dev/tty`)
- CLI `-p` and `-o` flags now error when missing their value
- CLI output path correctly detects directories via `FileManager`
- CLI and GUI block encrypting existing `.enclave` / `.vault` archives
- GUI encrypt/decrypt no longer blocks the main thread on large files
- GUI shows a proper message for empty passwords (was conflated with missing file)
- GUI save dialog normalizes output to the `.enclave` extension
- GUI buttons disable while an operation is in progress
- App no longer treats command-line flags as file paths on launch

### Added

- `EnclaveIO` module for shared file validation and output path resolution
- Expanded test suite: v2 round-trip, v1 legacy compat, tamper detection, input validation
- CLI usage note warning that `-p` exposes passwords in process lists

## [1.0.0] - 2026-06-27

### Added

- **Enclave** — simple macOS file encryption tool (renamed from VaultEnc)
- AES-256-GCM encryption for file contents and original filenames
- SHA-512-based key derivation and hashed on-disk filenames
- `.enclave` file extension (legacy `.vault` files still supported for decrypt)
- Command-line tool: `enclave-cli encrypt` / `decrypt`
- GUI app with drag-and-drop, password field, and encrypt/decrypt actions
- App icon with vault/lock motif and **E** branding
- macOS app bundle (`Enclave.app`) with `.enclave` document type registration

