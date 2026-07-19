# Security

This document describes what Enclave is designed to protect, how the cryptography works, what is **out of scope**, and how to use the app safely. It matches the implementation in **Enclave 1.7.1** (format **v5**).

If you find a vulnerability in Enclave itself, see [Reporting issues](#reporting-issues) at the end.

---

## 1. Threat model

### What Enclave is for

Enclave protects **files and folders at rest** when an attacker has a copy of the `.enclave` archive but **not** the password. Typical cases:

- Lost or stolen USB drive or laptop disk image that contains only the archive
- Cloud sync / backup of encrypted blobs without the password
- Casual snooping of filenames when **Encrypt filename** is enabled

Confidentiality of file **contents** depends on a strong password and correct crypto. Integrity of the archive (detecting modification) is provided by AES-GCM authentication tags and header/filename binding (v3+ / v5).

### What Enclave is *not*

Enclave does **not** claim to protect against:

| Threat | Why |
|--------|-----|
| **Weak or reused passwords** | Offline guessing is always possible; Argon2id only slows it |
| **Malware / keyloggers on a machine you trust** | Password entry and plaintext live in process memory |
| **Cold-boot / RAM dumps / debugger attachment while encrypting or decrypting** | Keys and plaintext are held in memory during the operation |
| **Compromised OS or false app binaries** | No remote attestation; trust the install source |
| **Traffic analysis or metadata of *when* you encrypt** | Local app only; no network protocol |
| **Secure deletion of the original plaintext file** | Encrypting creates a new archive; you must securely erase originals yourself if required |
| **Full-disk encryption or OS login** | Use FileVault, BitLocker, etc. for volume-level protection |
| **Multi-user secret sharing, recovery, or escrow** | Single password; no recovery path |
| **Side-channel resistance against local high-privilege attackers** | Not a constant-time / HSM-backed design |

**Bottom line:** Treat Enclave as strong **password-sealed containers** for offline data, not as a substitute for endpoint security or volume encryption.

---

## 2. Security goals (properties)

Assuming a correct implementation and a high-entropy password:

1. **Confidentiality of payload** — Without the password, recovering file bytes from a v3+ archive should require offline work proportional to Argon2id (or PBKDF2 for older files) times the password search space.
2. **Confidentiality of original filename (default mode)** — The on-disk name is a non-reversible fingerprint; the real name is inside an AES-GCM sealed blob.
3. **Integrity / authenticity of sealed blobs** — AES-GCM tags reject bit flips in ciphertext; wrong password also fails open (cannot distinguish “wrong password” from “corrupt ciphertext” by design of password AE — users see a generic decryption failure).
4. **Header binding (v3+)** — Version, flags, KDF parameters, and salt are included as GCM additional authenticated data (AAD). Changing them without the key fails authentication rather than silently deriving a different key.
5. **Filename binding (v5)** — The stored filename blob is bound into the *content* blob’s AAD. Even with **Encrypt filename** off, rewriting the plaintext name is detected.
6. **No plaintext password storage** — The password is only used to derive a key; nothing in the archive is a password verifier beyond “GCM open succeeds.”

---

## 3. Cryptographic design

### 3.1 Algorithms by role

| Purpose | Algorithm | Notes |
|---------|-----------|--------|
| Content encryption | **AES-256-GCM** | 12-byte random nonce, 16-byte tag; layout `nonce ‖ ciphertext ‖ tag` |
| Filename encryption (optional, default on) | **AES-256-GCM** | Same 32-byte key; AAD = archive header |
| Password → key (new files) | **Argon2id** | Default: memory **65536 KiB** (~64 MiB), **t=3**, **p=1**, output 32 bytes |
| Password → key (legacy) | **PBKDF2-HMAC-SHA256** | v3+; iterations stored in header (historical default 600 000) |
| Password → key (legacy v2 only) | **SHA-512(password‖salt)** then **HKDF-SHA512** | **Not** memory-hard; decrypt-only; re-encrypt to upgrade |
| On-disk archive basename (encrypted-name mode) | **SHA-512(salt ‖ sealed filename)** | First **32 hex** characters + `.enclave`; **not** a KDF |
| Salt / nonces | OS CSPRNG | 32-byte salt; independent 12-byte nonces per sealed box |

SHA-512 is **never** used as the password-stretching function for new archives. Help text and older UI copy that suggested otherwise were corrected in 1.4.x.

### 3.2 Default Argon2id parameters

```
type        = Argon2id (RFC 9106)
memory      = 65536 KiB  (64 MiB)
iterations  = 3
parallelism = 1
hash length = 32 bytes
salt length = 32 bytes
```

These sit above OWASP’s minimum recommendation for Argon2id (e.g. m≈19 MiB, t=2, p=1) and intentionally cost CPU and RAM on each encrypt/decrypt to raise offline guessing cost.

Parameters for each archive are **stored in the header**, so future builds can raise defaults without breaking old files. Decode-time **caps** reject hostile headers that would request absurd work factors (e.g. Argon2 memory up to 4 GiB, iterations ≤ 64, parallelism ≤ 8; PBKDF2 iterations ≤ 100 000 000).

### 3.3 Randomness

| Platform | API |
|----------|-----|
| macOS | `SecRandomCopyBytes` |
| Windows | `RandomNumberGenerator` (.NET) |

Used for salts and AES-GCM nonces. Nonce reuse under the same key would be catastrophic for GCM; Enclave generates a fresh random nonce per seal operation.

### 3.4 Cross-implementation consistency

macOS uses a **bundled Argon2 C** implementation; Windows uses **Konscious** (Argon2 1.3 / version 0x13). The Windows CLI `selftest` includes an Argon2id **known-answer test** so both stacks produce identical key bytes for the same password and salt. Wire integers are **big-endian** on both platforms.

---

## 4. Archive format (security-relevant)

Magic: ASCII `ENCLAVE1` (8 bytes). Extension: `.enclave` (also accepts `.enigma` for EnigmaVault Secure-mode files — same format).

### 4.1 Version matrix

| Version | Written by current apps? | KDF | Filename encryption | Authenticated data |
|---------|--------------------------|-----|---------------------|--------------------|
| **v5** | **Yes (default)** | Self-describing (Argon2id / PBKDF2) | Flag bit 0 | Header AAD on filename seal; **header ‖ filename blob** as content AAD |
| **v4** | No (decrypt only) | Same | Flag bit 0 | Header AAD only on content |
| **v3** | No (decrypt only) | Same | Always on | Header AAD only |
| **v2** | No (decrypt only) | Fixed HKDF-SHA512 path | Always on | **No** header AAD |

**Upgrade path:** decrypt a legacy archive and re-encrypt with a current build to move to v5 + Argon2id.

### 4.2 Logical layout (v5)

```
header:
  magic[8] = "ENCLAVE1"
  version  = 5
  flags    = bit0: encrypt filename
  kdf_id, kdf_len, kdf_params
  salt[32]

blob1: length_be32 ‖ filename_blob
  - if encrypt filename: AES-GCM(nonce‖ct‖tag), AAD = header
  - else: UTF-8 plaintext name (filesystem-sanitized)

blob2: length_be32 ‖ content_blob
  - always AES-GCM, AAD = header ‖ filename_blob   (v5)
```

Any trailing bytes after the second blob are rejected (`invalid format`).

### 4.3 On-disk names

| Mode | On-disk name |
|------|----------------|
| Encrypt filename **on** | `hex32(SHA-512(salt ‖ sealed_filename)).enclave` |
| Encrypt filename **off** | Sanitized original base name + `.enclave` (folder → folder title) |

Plaintext mode intentionally leaks the name for usability. Content remains encrypted. On Windows, illegal path characters (`\ : * ? " < > |`) are neutralized for *new* plaintext names only.

### 4.4 Folder packages

Folders are not encrypted file-by-file. They are packed into an inner format:

```
ENCLPKG1 ‖ version ‖ entry_count ‖ { path_len ‖ path ‖ size ‖ bytes }…
```

then that payload is encrypted as a normal Enclave content blob (stored name often ends with `.enclavefolder` when filename encryption is on).

**Security controls on pack/unpack:**

- Skip symbolic links / reparse points (and hidden files on macOS pack)
- Reject path traversal (`..`, absolute paths, empty components, backslashes)
- Verify extracted paths stay under the destination directory
- Caps on entry count, path length, and per-entry / total size
- Refuse to unpack into an existing non-empty destination folder

---

## 5. Application-level hardening

Implemented in GUI and CLI paths (see changelog 1.5.x–1.7.x):

- Reject encrypting an input that is already an Enclave/Enigma archive
- Reject decrypt of directories passed as archives; validate magic / size before full load where possible
- Size checks before loading large files into memory (DoS / OOM mitigation)
- GUI: ignore Choose/Clear/menu actions while an operation is in progress
- GUI: validate archive magic on select/drop before auto-decrypt flows
- Empty password rejected
- Filename sanitization for extraction (`lastPathComponent`, reject `.` / `..`)

These reduce foot-guns and some classes of path-abuse; they do not replace OS ACLs or AV.

---

## 6. Password guidance

Enclave’s security is **dominated by password strength**.

### Do

- Use a **long, unique** passphrase (diceware-style or password manager)
- Prefer the interactive password prompt over `-p` / `--password` on multi-user systems
- Keep an offline backup of anything you cannot afford to lose **and** of the password (or manager vault)
- Re-encrypt old **v2** archives after you can decrypt them (weak KDF)

### Don’t

- Reuse your email/login password
- Expect recovery: **there is no backdoor or reset**
- Pass passwords on the command line on shared hosts (argv visibility, shell history)
- Assume cloud providers cannot see **metadata** (file size, mtime, and plaintext names if filename encryption is off)

### Offline attack cost (intuition)

An attacker with your `.enclave` file can try passwords offline. Each guess costs roughly one Argon2id evaluation (~64 MiB RAM and hundreds of ms on typical hardware). That is intentional. Short passwords (dictionary words, short PINs) remain breakable; long random passphrases are not practical to brute-force with current parameters.

---

## 7. Memory and residual data

Honest limitations of this class of app:

1. **Plaintext and keys exist in RAM** during encrypt/decrypt. After the operation, managed runtimes (Swift/ARC, .NET GC) do not guarantee immediate zeroization of all buffers.
2. **Original files are not shredded** when you encrypt. Delete or securely wipe the plaintext yourself if the threat model requires it.
3. **Swap / hibernation / crash dumps** may capture secrets if the OS writes process memory to disk.
4. **Clipboard / UI** may retain filenames or paths; password fields are standard secure fields but are not a hardened PIN pad.

For higher assurance, combine Enclave with full-disk encryption and good operational hygiene.

---

## 8. Size and availability limits

| Constraint | Value / behavior |
|------------|------------------|
| Content blob design cap | ~4 GiB sealed blob class |
| Practical Windows limit | ~2 GiB per `byte[]` payload |
| Processing model | Whole file in memory (no streaming AEAD) |
| Hostile KDF params | Rejected above hard-coded caps |

A huge or malicious archive can still stress memory; size checks reduce but do not eliminate resource exhaustion.

---

## 9. Third-party and supply chain

| Component | Role | Trust note |
|-----------|------|------------|
| Apple CryptoKit / CommonCrypto | AES-GCM, SHA-512, HKDF, PBKDF2 (macOS) | Platform crypto |
| .NET `System.Security.Cryptography` | AES-GCM, SHA-512, HKDF, PBKDF2, RNG (Windows) | Platform crypto |
| Bundled `argon2.c` | Argon2id (macOS) | Vendored in-tree |
| Konscious.Security.Cryptography | Argon2id (Windows) | NuGet dependency; first build needs network |

There is **no network protocol** in Enclave itself. GUI help loads local HTML only.

---

## 10. Compatibility notes (security)

- **EnigmaVault Secure mode (`.enigma`)** — Same `ENCLAVE1` stack; opening is intentional interoperability, not a second weaker mode inside Enclave.
- **Plaintext filename mode** — Content is still encrypted; name and approximate size/metadata remain visible. Prefer default encrypted-filename mode for sensitive titles.
- **Legacy v2** — Decrypt supported for migration only; KDF is not suitable for new secrets.

---

## 11. Verification

Before trusting a build on a given machine:

1. **Windows:** `enclave-cli selftest` — Argon2 KAT, v5 round-trips, plaintext-filename tamper check, wrong-password rejection, folder (incl. empty file) round-trip.
2. **macOS:** run `test_enclave.swift` / the suite invoked by `build.sh`.
3. **Interop:** encrypt on one OS, decrypt on the other; compare plaintext byte-for-byte.

Passing self-tests increases confidence in the port; it is not a formal proof or external audit.

---

## 12. Reporting issues

There is no dedicated bug-bounty program or private security mailbox configured in this repository yet.

Until one is published:

1. Prefer **private** disclosure to the project maintainer (do not open a public issue with a working exploit for a live product if users are at risk).
2. Include: Enclave version/build, platform, steps to reproduce, impact (confidentiality / integrity / availability), and whether a fix idea exists.
3. Avoid attaching real user archives that contain sensitive plaintext.

If you maintain a public fork, add a contact address here when you publish.

---

## 13. Document history

| Date | Notes |
|------|--------|
| 2026-07-19 | Initial SECURITY.md for repo root; describes 1.7.1 / format v5 behavior from macOS and Windows sources |

When you change crypto, authentication binding, KDF defaults, or the threat model, update this file in the same change set.
