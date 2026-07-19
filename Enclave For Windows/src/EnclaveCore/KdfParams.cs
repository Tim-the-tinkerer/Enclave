using System.Buffers.Binary;

namespace EnclaveCore;

/// <summary>Identifies the password-hashing function used for an archive.
/// The numeric value is written into the file header.</summary>
public enum KdfAlgorithm : byte
{
    Pbkdf2Sha256 = 1,
    Argon2id = 2
}

/// <summary>
/// Self-describing KDF parameters, serialized into the v3+ header so the work
/// factor can be raised over time and new algorithms added without a new format
/// version. Byte layout matches the macOS build exactly.
/// </summary>
public abstract class KdfParams
{
    public abstract KdfAlgorithm Algorithm { get; }

    /// <summary>(id, body) for the header. Body excludes the id and outer length.</summary>
    public abstract (byte Id, byte[] Body) Encode();

    public sealed class Pbkdf2 : KdfParams
    {
        public uint Iterations { get; }
        public Pbkdf2(uint iterations) => Iterations = iterations;
        public override KdfAlgorithm Algorithm => KdfAlgorithm.Pbkdf2Sha256;

        public override (byte Id, byte[] Body) Encode()
        {
            var body = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(body, Iterations);
            return ((byte)KdfAlgorithm.Pbkdf2Sha256, body);
        }
    }

    public sealed class Argon2id : KdfParams
    {
        public uint MemoryKiB { get; }
        public uint Iterations { get; }
        public byte Parallelism { get; }

        public Argon2id(uint memoryKiB, uint iterations, byte parallelism)
        {
            MemoryKiB = memoryKiB;
            Iterations = iterations;
            Parallelism = parallelism;
        }

        public override KdfAlgorithm Algorithm => KdfAlgorithm.Argon2id;

        public override (byte Id, byte[] Body) Encode()
        {
            var body = new byte[9];
            BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(0, 4), MemoryKiB);
            BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(4, 4), Iterations);
            body[8] = Parallelism;
            return ((byte)KdfAlgorithm.Argon2id, body);
        }
    }

    /// <summary>Parse a KDF block read from a header. Bounds are enforced so a
    /// hostile archive cannot force unbounded CPU/RAM.</summary>
    public static KdfParams Decode(byte id, byte[] body)
    {
        if (!Enum.IsDefined(typeof(KdfAlgorithm), id))
            throw EnclaveException.UnsupportedKdf(id);

        switch ((KdfAlgorithm)id)
        {
            case KdfAlgorithm.Pbkdf2Sha256:
            {
                if (body.Length != 4) throw EnclaveException.InvalidFormat();
                uint iterations = BinaryPrimitives.ReadUInt32BigEndian(body);
                if (iterations < 1 || iterations > EnclaveCrypto.MaxPbkdf2Iterations)
                    throw EnclaveException.InvalidFormat();
                return new Pbkdf2(iterations);
            }
            case KdfAlgorithm.Argon2id:
            {
                if (body.Length != 9) throw EnclaveException.InvalidFormat();
                uint memoryKiB = BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(0, 4));
                uint iterations = BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(4, 4));
                byte parallelism = body[8];
                if (iterations < 1 ||
                    iterations > EnclaveCrypto.MaxArgon2Iterations ||
                    memoryKiB < 8 ||
                    memoryKiB > EnclaveCrypto.MaxArgon2MemoryKiB ||
                    parallelism < 1 ||
                    parallelism > EnclaveCrypto.MaxArgon2Parallelism)
                    throw EnclaveException.InvalidFormat();
                return new Argon2id(memoryKiB, iterations, parallelism);
            }
            default:
                throw EnclaveException.UnsupportedKdf(id);
        }
    }
}
