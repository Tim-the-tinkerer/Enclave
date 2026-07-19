using System.Text;
using EnclaveCore;

namespace EnclaveCli;

/// <summary>
/// Runtime self-checks. The Argon2id KAT is the important one: it proves the
/// pure-C# Argon2 backend produces the same bytes as the macOS build (the value
/// was derived from the RFC 9106-validated C). The round-trips and the
/// plaintext-filename tamper check mirror the Swift suite.
/// </summary>
internal static class SelfTest
{
    public static int Run()
    {
        int passed = 0;
        int failed = 0;

        void Check(string name, Func<bool> test)
        {
            try
            {
                if (test())
                {
                    passed++;
                    Console.WriteLine($"  PASS  {name}");
                }
                else
                {
                    failed++;
                    Console.WriteLine($"  FAIL  {name}");
                }
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine($"  FAIL  {name} ({ex.GetType().Name}: {ex.Message})");
            }
        }

        const string password = "correct horse battery staple";
        byte[] payload = Encoding.UTF8.GetBytes("the quick brown fox jumps over the lazy dog, twice for good measure.");
        const string originalName = "secret-notes.txt";

        // 1. Argon2id known-answer test (derived from the RFC 9106-validated C backend).
        Check("Argon2id KAT (native backend)", () =>
        {
            byte[] salt = Enumerable.Repeat((byte)0x02, 16).ToArray();
            byte[] key = EnclaveCrypto.DeriveKey("enclave-kat", salt, new KdfParams.Argon2id(64, 3, 1));
            byte[] expected = Convert.FromHexString("28235d98f78a35631f740de247e3cfae5c871d2e1d9acf83656e0591dc99582c");
            return key.AsSpan().SequenceEqual(expected);
        });

        // 2. v5 round-trip (default = encrypted filename).
        Check("v5 file round-trip", () =>
        {
            var enc = EnclaveCrypto.Encrypt(payload, originalName, password);
            if (enc.Data[EnclaveCrypto.Magic.Length] != EnclaveCrypto.CurrentVersion) return false;
            var dec = EnclaveCrypto.Decrypt(enc.Data, password);
            return dec.Payload.AsSpan().SequenceEqual(payload) && dec.Filename == originalName;
        });

        // 3. Plaintext-filename round-trip.
        Check("plaintext-filename round-trip", () =>
        {
            var enc = EnclaveCrypto.Encrypt(payload, originalName, password, encryptFilename: false);
            var dec = EnclaveCrypto.Decrypt(enc.Data, password);
            return dec.Payload.AsSpan().SequenceEqual(payload) && dec.Filename == originalName;
        });

        // 4. v5 binds the plaintext filename into the content AAD: tampering is detected.
        Check("plaintext-filename tamper rejected", () =>
        {
            var enc = EnclaveCrypto.Encrypt(payload, originalName, password, encryptFilename: false);
            byte[] tampered = (byte[])enc.Data.Clone();
            byte[] needle = Encoding.UTF8.GetBytes(originalName);
            int idx = IndexOf(tampered, needle);
            if (idx < 0) throw new Exception("could not locate plaintext filename");
            tampered[idx] ^= 0x01;
            try
            {
                EnclaveCrypto.Decrypt(tampered, password);
                return false; // should have thrown
            }
            catch (EnclaveException)
            {
                return true;
            }
        });

        // 5. Wrong password rejected.
        Check("wrong password rejected", () =>
        {
            var enc = EnclaveCrypto.Encrypt(payload, originalName, password);
            try { EnclaveCrypto.Decrypt(enc.Data, "not the password"); return false; }
            catch (EnclaveException) { return true; }
        });

        // 6. Folder round-trip including an empty file.
        Check("folder round-trip (incl. empty file)", () =>
        {
            string work = Path.Combine(Path.GetTempPath(), "enclave-selftest-" + Guid.NewGuid().ToString("N"));
            string src = Path.Combine(work, "MyFolder");
            string outParent = Path.Combine(work, "out");
            try
            {
                Directory.CreateDirectory(Path.Combine(src, "nested"));
                File.WriteAllText(Path.Combine(src, "readme.txt"), "hello");
                File.WriteAllText(Path.Combine(src, "nested", "child.txt"), "nested-data");
                File.WriteAllBytes(Path.Combine(src, "empty.txt"), Array.Empty<byte>());

                var prepared = EnclaveIo.PrepareEncryptionPayload(src);
                var enc = EnclaveCrypto.Encrypt(prepared.Data, prepared.Filename, password);
                var dec = EnclaveCrypto.Decrypt(enc.Data, password);
                if (!EnclaveFolder.IsFolderPayload(dec.Payload)) return false;

                Directory.CreateDirectory(outParent);
                EnclaveIo.WriteDecryptedPayload(dec.Payload, dec.Filename, outParent);

                string restored = Path.Combine(outParent, "MyFolder");
                bool ok =
                    File.ReadAllText(Path.Combine(restored, "readme.txt")) == "hello" &&
                    File.ReadAllText(Path.Combine(restored, "nested", "child.txt")) == "nested-data" &&
                    File.Exists(Path.Combine(restored, "empty.txt")) &&
                    new FileInfo(Path.Combine(restored, "empty.txt")).Length == 0;
                return ok;
            }
            finally
            {
                try { Directory.Delete(work, recursive: true); } catch { /* best effort */ }
            }
        });

        Console.WriteLine();
        Console.WriteLine($"{passed} passed, {failed} failed.");
        return failed == 0 ? 0 : 1;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}
