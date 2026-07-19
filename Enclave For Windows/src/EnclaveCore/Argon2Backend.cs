using Konscious.Security.Cryptography;

namespace EnclaveCore;

/// <summary>
/// Argon2id key derivation via the Konscious pure-C# implementation (Argon2 1.3
/// spec, version 0x13 — the same version as the validated macOS C backend). With
/// identical parameters and no associated data or secret, Argon2id is
/// deterministic, so this produces byte-for-byte the same key as the macOS build.
/// The self-test's known-answer test (28235d98…582c) confirms that parity at runtime.
/// </summary>
internal static class Argon2Backend
{
    public static byte[] DeriveRaw(
        byte[] password, byte[] salt,
        uint memoryKiB, uint iterations, byte parallelism, int keyLength)
    {
        try
        {
            using var argon2 = new Argon2id(password)
            {
                Salt = salt,
                DegreeOfParallelism = parallelism,
                MemorySize = checked((int)memoryKiB), // KiB, same unit as the C backend
                Iterations = checked((int)iterations)
                // No AssociatedData / KnownSecret — matches the raw C derivation.
            };
            return argon2.GetBytes(keyLength);
        }
        catch
        {
            throw EnclaveException.KeyDerivationFailed();
        }
    }
}
