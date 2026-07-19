namespace EnclaveCore;

/// <summary>
/// Kinds of failures the Enclave core can raise. Mirrors the Swift EnclaveError
/// cases so behaviour (and messages) match the macOS build.
/// </summary>
public enum EnclaveErrorKind
{
    InvalidFormat,
    UnsupportedVersion,
    UnsupportedKdf,
    WrongPassword,
    EmptyInput,
    EmptyPassword,
    UnreadableFile,
    CannotEncryptArchive,
    PayloadTooLarge,
    RandomGenerationFailed,
    KeyDerivationFailed,
    EmptyFolder,
    DestinationExists
}

/// <summary>Domain error for all Enclave operations.</summary>
public sealed class EnclaveException : Exception
{
    public EnclaveErrorKind Kind { get; }

    private EnclaveException(EnclaveErrorKind kind, string message) : base(message)
    {
        Kind = kind;
    }

    public static EnclaveException InvalidFormat() =>
        new(EnclaveErrorKind.InvalidFormat, "Not a valid Enclave archive.");

    public static EnclaveException UnsupportedVersion(byte version) =>
        new(EnclaveErrorKind.UnsupportedVersion, $"Unsupported format version: {version}.");

    public static EnclaveException UnsupportedKdf(byte id) =>
        new(EnclaveErrorKind.UnsupportedKdf, $"Unsupported key-derivation algorithm: {id}.");

    public static EnclaveException WrongPassword() =>
        new(EnclaveErrorKind.WrongPassword, "Decryption failed. Check the password.");

    public static EnclaveException EmptyInput() =>
        new(EnclaveErrorKind.EmptyInput, "No input file or folder was provided.");

    public static EnclaveException EmptyPassword() =>
        new(EnclaveErrorKind.EmptyPassword, "A password is required.");

    public static EnclaveException UnreadableFile(string path) =>
        new(EnclaveErrorKind.UnreadableFile, $"Cannot read file: {path}.");

    public static EnclaveException CannotEncryptArchive() =>
        new(EnclaveErrorKind.CannotEncryptArchive, "Cannot encrypt an existing .enclave archive.");

    public static EnclaveException PayloadTooLarge() =>
        new(EnclaveErrorKind.PayloadTooLarge, "The file exceeds the maximum supported size.");

    public static EnclaveException RandomGenerationFailed() =>
        new(EnclaveErrorKind.RandomGenerationFailed, "Secure random number generation failed.");

    public static EnclaveException KeyDerivationFailed() =>
        new(EnclaveErrorKind.KeyDerivationFailed, "Key derivation failed.");

    public static EnclaveException EmptyFolder() =>
        new(EnclaveErrorKind.EmptyFolder, "The folder is empty or contains no encryptable files.");

    public static EnclaveException DestinationExists() =>
        new(EnclaveErrorKind.DestinationExists, "The destination folder already exists and is not empty.");
}
