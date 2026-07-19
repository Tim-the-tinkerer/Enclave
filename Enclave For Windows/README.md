# Enclave for Windows (x64)

A Windows port of the macOS **Enclave** file-encryption app, written in C#/.NET 8
(WPF GUI + console CLI). It produces and reads the **same `.enclave` archive format**
as the macOS build, so files encrypted on one platform decrypt on the other.

- **Content & filename:** AES-256-GCM (filename encryption optional).
- **Key derivation:** Argon2id by default — 64 MiB, 3 iterations, 1 lane.
  Reads legacy PBKDF2-HMAC-SHA256 (v3) and HKDF-SHA512 (v2) archives too.
- **On-disk name (encrypted-filename mode):** first 32 hex chars of SHA-512(salt‖sealed-name).
- **Folders:** packed into an `ENCLPKG1` bundle, then encrypted as one archive.
- **Format version:** writes v5 (filename authenticated via content AAD); decrypts v5/v4/v3/v2.
- **EnigmaVault compatibility (1.7.1):** also opens `.enigma` archives from EnigmaVault's Secure mode — same `ENCLAVE1` format, so secure files made in either app open in the other.

64-bit only, by design: the ~4 GiB size caps assume a 64-bit target.

## Build — one tool, one command

You only need the **.NET 8 SDK** (or newer). No C compiler, no native build step.

If you installed Visual Studio with the ".NET desktop development" workload, you already
have it. Otherwise grab the SDK from https://dotnet.microsoft.com/download.

```
cd EnclaveWin
dotnet build -c Release
```

The first build downloads one NuGet package (the Argon2 implementation) automatically,
so it needs an internet connection once.

> If `dotnet build` reports it can't find the **.NET 8** targeting pack (e.g. you only
> have a newer SDK), install it once with `winget install Microsoft.DotNet.SDK.8`, or
> just open `Enclave.sln` in Visual Studio and accept its prompt to install the missing
> component.

## Run

Confirm it works first:
```
dotnet run --project src\EnclaveCli -c Release -- selftest
```
Every line should say `PASS`. The first one — the Argon2id KAT — is the important one:
it proves the C# Argon2 produces the **same key bytes** as your macOS build, which is
what makes archives interoperate.

CLI:
```
dotnet run --project src\EnclaveCli -c Release -- encrypt "C:\path\to\file.txt"
dotnet run --project src\EnclaveCli -c Release -- decrypt "C:\path\to\xxxx.enclave"
dotnet run --project src\EnclaveCli -c Release -- encrypt "C:\folder" --plaintext-filename -o "C:\out"
```

GUI:
```
dotnet run --project src\EnclaveApp -c Release
```
or double-click `src\EnclaveApp\bin\Release\net8.0-windows\Enclave.exe` after building.

## Cross-platform interop

Every primitive is standardized, so a faithful reimplementation interoperates:

| Piece            | macOS (Swift)        | Windows (.NET)                          |
|------------------|----------------------|-----------------------------------------|
| AES-256-GCM      | CryptoKit            | `System.Security.Cryptography.AesGcm`   |
| SHA-512          | CryptoKit            | `SHA512`                                |
| HKDF-SHA512 (v2) | CryptoKit            | `HKDF`                                  |
| PBKDF2 (v3)      | CommonCrypto         | `Rfc2898DeriveBytes.Pbkdf2`             |
| Argon2id         | bundled `argon2.c`   | Konscious (Argon2 1.3 spec, version 0x13) |

Argon2id is deterministic: given the same version, parameters, password, and salt (and
no associated data or secret), every correct implementation yields identical bytes. The
self-test's KAT verifies that the Konscious output matches the value your validated C
backend produces. All multi-byte integers are big-endian in the format and are read/written
explicitly, so the little-endian Windows build reads macOS archives (and vice versa).

**One intentional platform difference:** when storing a *plaintext* filename, the Windows
build also neutralises Windows-illegal characters (`\ : * ? " < > |`) so the name is
writable on disk. This only affects names chosen for newly created archives; it does not
affect reading archives from either platform.

## Limitations

Like the macOS app, files are processed whole-in-memory (no streaming). On .NET a single
`byte[]` is capped near 2 GiB, so the practical per-file ceiling on Windows is ~2 GiB
rather than the format's ~4 GiB. Archives within that range interoperate fully.

## Verification status

This C# was ported by inspection from the validated Swift sources. The byte layout
(header fields, blob framing, the `nonce‖ciphertext‖tag` AES-GCM layout, the v5
filename-in-content-AAD binding, the empty-file case) was modelled in a reference
implementation and round-trips correctly, with filename tampering rejected.

**The real gates on your machine are:**

1. `enclave-cli selftest` — the Argon2 KAT (proves the C# Argon2 matches macOS),
   v5 round-trips, the plaintext-filename tamper check, wrong-password rejection, and a
   folder round-trip including an empty file.
2. A true interop test: encrypt a file on macOS, copy the `.enclave` to Windows, and
   confirm `enclave-cli decrypt` restores it bit-for-bit — and the reverse.

If the self-test passes and an archive made on each platform decrypts on the other,
the port is sound.
