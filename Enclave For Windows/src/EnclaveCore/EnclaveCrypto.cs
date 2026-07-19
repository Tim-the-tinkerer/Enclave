using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace EnclaveCore;

public readonly record struct EncryptResult(byte[] Data, string DiskFilename);

public readonly record struct DecryptResult(byte[] Payload, string Filename);

/// <summary>
/// Core Enclave cryptography. Wire format is byte-for-byte compatible with the
/// macOS build: AES-256-GCM content/filename sealing, a self-describing KDF
/// header, header-as-AAD authentication (v3+), and filename-in-content-AAD
/// binding (v5). New archives are v5; v4/v3/v2 decrypt unchanged.
/// </summary>
public static class EnclaveCrypto
{
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("ENCLAVE1");
    public const byte CurrentVersion = 5;
    public const byte LegacyVersionV4 = 4;
    public const byte LegacyVersionV3 = 3;
    public const byte LegacyVersionV2 = 2;
    public const byte FlagEncryptFilename = 1;
    public const string FileExtension = "enclave";
    public const int SaltLength = 32;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int DiskNameHexLength = 32;
    public const int MaxFilenameBlobSize = 1_048_576;
    public const long MaxContentBlobSize = 4_294_967_224;
    public const int MinSealedBlobSize = NonceLength + TagLength;
    public const long MaxPlaintextSize = MaxContentBlobSize - MinSealedBlobSize;
    public static readonly long MaxArchiveHeaderSize = Magic.Length + 1 + 1 + 1 + 1 + 255 + SaltLength;
    public static readonly long MaxArchiveSize = MaxArchiveHeaderSize + 4 + MaxFilenameBlobSize + 4 + MaxContentBlobSize;

    public const uint Pbkdf2DefaultIterations = 600_000;

    // Decode-time safety caps (a crafted header must not be able to hang the app).
    public const uint MaxPbkdf2Iterations = 100_000_000;
    public const uint MaxArgon2Iterations = 64;
    public const uint MaxArgon2MemoryKiB = 4_194_304; // 4 GiB
    public const byte MaxArgon2Parallelism = 8;

    // Default KDF for new archives: Argon2id, ~64 MiB / 3 passes / 1 lane.
    public static KdfParams Argon2idDefault => new KdfParams.Argon2id(65_536, 3, 1);

    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    public static bool IsArchiveFilename(string filename)
    {
        // Accept Enclave's own .enclave and EnigmaVault's .enigma — same secure format.
        var ext = Path.GetExtension(filename);
        return ext.Equals("." + FileExtension, StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".enigma", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsArchiveData(ReadOnlySpan<byte> data) => data.StartsWith(Magic);

    // ===================== Encrypt / Decrypt =====================

    public static EncryptResult Encrypt(
        byte[] data,
        string originalFilename,
        string password,
        bool encryptFilename = true,
        KdfParams? kdf = null)
    {
        ValidatePassword(password);
        kdf ??= Argon2idDefault;

        if (data.LongLength > MaxPlaintextSize)
            throw EnclaveException.PayloadTooLarge();

        byte[] salt = RandomBytes(SaltLength);
        byte[] key = DeriveKey(password, salt, kdf);

        string sanitizedName = SanitizedFilename(originalFilename);
        string archiveFilename = encryptFilename
            ? sanitizedName
            : FilesystemSafeFilename(EnclaveFolder.PlaintextArchiveName(sanitizedName));
        byte[] filenameData = Encoding.UTF8.GetBytes(archiveFilename);
        if (filenameData.Length > MaxFilenameBlobSize)
            throw EnclaveException.PayloadTooLarge();

        // Header = exactly the bytes preceding the first blob; bound as AAD so any
        // later tampering with version/flags/KDF/salt fails authentication.
        var (kdfId, kdfBody) = kdf.Encode();
        if (kdfBody.Length > 255)
            throw EnclaveException.InvalidFormat();

        var header = new MemoryStream();
        header.Write(Magic);
        header.WriteByte(CurrentVersion);
        header.WriteByte(encryptFilename ? FlagEncryptFilename : (byte)0);
        header.WriteByte(kdfId);
        header.WriteByte((byte)kdfBody.Length);
        header.Write(kdfBody);
        header.Write(salt);
        byte[] headerBytes = header.ToArray();

        byte[] filenameBlob = encryptFilename
            ? Seal(filenameData, key, headerBytes)
            : filenameData;

        // v5: content AAD = header || filename blob, so the stored filename is
        // authenticated even when filename encryption is off.
        byte[] contentAad = Concat(headerBytes, filenameBlob);
        byte[] contentBlob = Seal(data, key, contentAad);

        var archive = new MemoryStream();
        archive.Write(headerBytes);
        AppendBlob(archive, filenameBlob, encrypted: encryptFilename);
        AppendBlob(archive, contentBlob, encrypted: true);

        string diskName = encryptFilename
            ? DiskFilename(salt, filenameBlob)
            : archiveFilename;

        return new EncryptResult(archive.ToArray(), $"{diskName}.{FileExtension}");
    }

    public static DecryptResult Decrypt(byte[] data, string password)
    {
        ValidatePassword(password);

        int offset = 0;
        Header parsed = ParseHeader(data, ref offset);

        // Header (every byte up to the first blob) is the AAD for v3+. v2 used no
        // AAD, which in GCM is identical to empty AAD.
        byte[] headerAad = UsesHeaderAad(parsed.Version) ? data[..offset] : Array.Empty<byte>();

        byte[] key;
        switch (parsed.Version)
        {
            case CurrentVersion:
            case LegacyVersionV4:
            case LegacyVersionV3:
                if (parsed.Kdf is null) throw EnclaveException.InvalidFormat();
                key = DeriveKey(password, parsed.Salt, parsed.Kdf);
                break;
            case LegacyVersionV2:
                key = DeriveKeyLegacyV2(password, parsed.Salt);
                break;
            default:
                throw EnclaveException.UnsupportedVersion(parsed.Version);
        }

        byte[] filenameBlob = ReadBlob(data, ref offset, MaxFilenameBlobSize, encrypted: parsed.EncryptFilename);
        string filename = parsed.EncryptFilename
            ? OpenString(filenameBlob, key, headerAad)
            : ParsePlaintextFilename(filenameBlob);

        // v5 binds the filename blob into the content AAD; v3/v4 bound only the
        // header; v2 used no AAD.
        byte[] contentAad = BindsFilenameInContentAad(parsed.Version)
            ? Concat(headerAad, filenameBlob)
            : headerAad;

        byte[] contentBlob = ReadBlob(data, ref offset, (int)Math.Min(MaxContentBlobSize, int.MaxValue), encrypted: true);
        byte[] payload = OpenData(contentBlob, key, contentAad);

        if (offset != data.Length)
            throw EnclaveException.InvalidFormat();

        return new DecryptResult(payload, SanitizedFilename(filename));
    }

    // ===================== Header =====================

    private readonly record struct Header(byte Version, bool EncryptFilename, KdfParams? Kdf, byte[] Salt);

    private static bool UsesHeaderAad(byte version) => version >= LegacyVersionV3;

    /// <summary>v5+ binds the filename blob into the content blob's AAD.</summary>
    private static bool BindsFilenameInContentAad(byte version) => version >= CurrentVersion;

    private static Header ParseHeader(byte[] data, ref int offset)
    {
        int prefixSize = Magic.Length + 1;
        if (data.Length < prefixSize) throw EnclaveException.InvalidFormat();
        if (!IsArchiveData(data)) throw EnclaveException.InvalidFormat();

        offset = Magic.Length;
        byte version = data[offset];
        offset += 1;

        switch (version)
        {
            case CurrentVersion:
            case LegacyVersionV4:
            {
                if (offset + 1 > data.Length) throw EnclaveException.InvalidFormat();
                byte flags = data[offset];
                offset += 1;
                if ((flags & ~FlagEncryptFilename) != 0) throw EnclaveException.InvalidFormat();
                bool encryptFilename = (flags & FlagEncryptFilename) != 0;
                var (kdf, salt) = ParseKdfHeader(data, ref offset);
                return new Header(version, encryptFilename, kdf, salt);
            }
            case LegacyVersionV3:
            {
                var (kdf, salt) = ParseKdfHeader(data, ref offset);
                return new Header(version, true, kdf, salt);
            }
            case LegacyVersionV2:
            {
                if (offset + SaltLength > data.Length) throw EnclaveException.InvalidFormat();
                byte[] salt = data[offset..(offset + SaltLength)];
                offset += SaltLength;
                return new Header(version, true, null, salt);
            }
            default:
                if (version > CurrentVersion) throw EnclaveException.UnsupportedVersion(version);
                throw EnclaveException.InvalidFormat();
        }
    }

    private static (KdfParams, byte[]) ParseKdfHeader(byte[] data, ref int offset)
    {
        if (offset + 2 > data.Length) throw EnclaveException.InvalidFormat();
        byte kdfId = data[offset]; offset += 1;
        int bodyLen = data[offset]; offset += 1;

        if (offset + bodyLen + SaltLength > data.Length) throw EnclaveException.InvalidFormat();
        byte[] body = data[offset..(offset + bodyLen)]; offset += bodyLen;
        KdfParams kdf = KdfParams.Decode(kdfId, body);
        byte[] salt = data[offset..(offset + SaltLength)]; offset += SaltLength;
        return (kdf, salt);
    }

    private static string ParsePlaintextFilename(byte[] blob)
    {
        string? text = TryUtf8(blob);
        if (string.IsNullOrEmpty(text)) throw EnclaveException.InvalidFormat();
        return SanitizedFilename(text);
    }

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Trim().Length == 0)
            throw EnclaveException.EmptyPassword();
    }

    // ===================== Key derivation =====================

    public static byte[] DeriveKey(string password, byte[] salt, KdfParams kdf)
    {
        byte[] pwd = Encoding.UTF8.GetBytes(password);
        switch (kdf)
        {
            case KdfParams.Pbkdf2 p:
                return Rfc2898DeriveBytes.Pbkdf2(pwd, salt, (int)p.Iterations, HashAlgorithmName.SHA256, 32);
            case KdfParams.Argon2id a:
                return Argon2Backend.DeriveRaw(pwd, salt, a.MemoryKiB, a.Iterations, a.Parallelism, 32);
            default:
                throw EnclaveException.KeyDerivationFailed();
        }
    }

    /// <summary>Legacy v2 derivation (SHA-512 -> HKDF-SHA512). Decrypt-only.</summary>
    private static byte[] DeriveKeyLegacyV2(string password, byte[] salt)
    {
        byte[] material = Concat(Encoding.UTF8.GetBytes(password), salt);
        byte[] digest = SHA512.HashData(material);
        return HKDF.DeriveKey(HashAlgorithmName.SHA512, digest, 32, salt, Encoding.UTF8.GetBytes("Enclave-v2"));
    }

    // ===================== AES-GCM helpers =====================

    /// <summary>Seal to the "combined" layout: nonce(12) || ciphertext || tag(16).</summary>
    private static byte[] Seal(byte[] plaintext, byte[] key, byte[] aad)
    {
        byte[] nonce = RandomBytes(NonceLength);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagLength];
        using var gcm = new AesGcm(key, TagLength);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] combined = new byte[NonceLength + ciphertext.Length + TagLength];
        Buffer.BlockCopy(nonce, 0, combined, 0, NonceLength);
        Buffer.BlockCopy(ciphertext, 0, combined, NonceLength, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, combined, NonceLength + ciphertext.Length, TagLength);
        return combined;
    }

    private static byte[] OpenData(byte[] blob, byte[] key, byte[] aad)
    {
        if (blob.Length < MinSealedBlobSize) throw EnclaveException.WrongPassword();
        byte[] nonce = blob[..NonceLength];
        byte[] tag = blob[^TagLength..];
        byte[] ciphertext = blob[NonceLength..^TagLength];
        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            using var gcm = new AesGcm(key, TagLength);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch
        {
            throw EnclaveException.WrongPassword();
        }
        return plaintext;
    }

    private static string OpenString(byte[] blob, byte[] key, byte[] aad)
    {
        byte[] opened = OpenData(blob, key, aad);
        string? text = TryUtf8(opened);
        if (string.IsNullOrEmpty(text)) throw EnclaveException.WrongPassword();
        return text;
    }

    // ===================== Blobs / helpers =====================

    private static string DiskFilename(byte[] salt, byte[] sealedFilename)
    {
        byte[] material = Concat(salt, sealedFilename);
        byte[] digest = SHA512.HashData(material);
        string hex = Convert.ToHexString(digest).ToLowerInvariant();
        return hex[..DiskNameHexLength];
    }

    /// <summary>Last path component (handles both '/' and '\\' separators); rejects ".", "..".</summary>
    public static string SanitizedFilename(string name)
    {
        int slash = name.LastIndexOfAny(new[] { '/', '\\' });
        string baseName = slash >= 0 ? name[(slash + 1)..] : name;
        if (string.IsNullOrEmpty(baseName) || baseName == "." || baseName == "..")
            return "file";
        return baseName;
    }

    /// <summary>Filesystem-safe name for plaintext archives. Superset of the macOS
    /// rules: also neutralises Windows-illegal characters so the name is writable
    /// on disk. (The encrypted-filename path is unaffected — that name is a hash.)</summary>
    public static string FilesystemSafeFilename(string name)
    {
        string safe = SanitizedFilename(name);
        var sb = new StringBuilder(safe.Length);
        foreach (char c in safe)
        {
            if (c == '\0') continue;
            if (c is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' || c < 0x20)
                sb.Append('_');
            else
                sb.Append(c);
        }
        string result = sb.ToString();
        if (string.IsNullOrEmpty(result) || result == "." || result == "..")
            return "file";
        return result;
    }

    public static byte[] RandomBytes(int count)
    {
        try
        {
            return RandomNumberGenerator.GetBytes(count);
        }
        catch
        {
            throw EnclaveException.RandomGenerationFailed();
        }
    }

    private static void AppendBlob(Stream stream, byte[] blob, bool encrypted)
    {
        if ((uint)blob.Length > uint.MaxValue) throw EnclaveException.PayloadTooLarge();
        if (encrypted)
        {
            if (blob.Length < MinSealedBlobSize) throw EnclaveException.InvalidFormat();
        }
        else
        {
            if (blob.Length == 0) throw EnclaveException.InvalidFormat();
        }
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)blob.Length);
        stream.Write(len);
        stream.Write(blob);
    }

    private static byte[] ReadBlob(byte[] data, ref int offset, int maxSize, bool encrypted)
    {
        if (offset + 4 > data.Length) throw EnclaveException.InvalidFormat();
        uint length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
        offset += 4;

        if (encrypted)
        {
            if (length == 0 || length < MinSealedBlobSize || length > (uint)maxSize)
                throw EnclaveException.InvalidFormat();
        }
        else
        {
            if (length == 0 || length > (uint)maxSize)
                throw EnclaveException.InvalidFormat();
        }
        if (offset + (long)length > data.Length) throw EnclaveException.InvalidFormat();

        byte[] blob = data[offset..(offset + (int)length)];
        offset += (int)length;
        return blob;
    }

    internal static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static string? TryUtf8(byte[] bytes)
    {
        try { return StrictUtf8.GetString(bytes); }
        catch { return null; }
    }
}
