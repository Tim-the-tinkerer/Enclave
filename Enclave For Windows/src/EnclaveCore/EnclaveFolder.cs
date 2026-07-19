using System.Buffers.Binary;
using System.Text;

namespace EnclaveCore;

/// <summary>
/// Folder packing/unpacking. A directory tree is serialized into an ENCLPKG1
/// bundle (paths stored '/'-separated, platform-neutral) which is then encrypted
/// as a single archive. Byte-compatible with the macOS build, so a folder packed
/// on one platform unpacks on the other.
/// </summary>
public static class EnclaveFolder
{
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("ENCLPKG1");
    public const byte Version = 1;
    public const string FilenameSuffix = ".enclavefolder";
    public const int MaxEntries = 100_000;
    public const int MaxPathLength = 4_096;
    public static long MaxEntrySize => EnclaveCrypto.MaxPlaintextSize;

    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    public static bool IsDirectory(string path) => Directory.Exists(path);

    public static bool IsFolderPayload(ReadOnlySpan<byte> data) => data.StartsWith(Magic);

    public static string StoredFilename(string directoryPath) =>
        new DirectoryInfo(directoryPath).Name + FilenameSuffix;

    public static bool IsFolderStoredName(string filename)
    {
        string baseName = LastComponent(filename);
        return baseName.EndsWith(FilenameSuffix, StringComparison.Ordinal);
    }

    public static string DisplayFolderName(string storedFilename)
    {
        string baseName = LastComponent(storedFilename);
        if (baseName.EndsWith(FilenameSuffix, StringComparison.Ordinal))
            return baseName[..^FilenameSuffix.Length];
        return baseName;
    }

    /// <summary>Visible archive name when filename encryption is off (no internal suffix).</summary>
    public static string PlaintextArchiveName(string storedFilename)
    {
        if (IsFolderStoredName(storedFilename))
            return DisplayFolderName(storedFilename);
        return LastComponent(storedFilename);
    }

    // ===================== Pack =====================

    public static byte[] Pack(string directoryPath)
    {
        string root = Path.GetFullPath(directoryPath);
        if (!IsDirectory(root)) throw EnclaveException.InvalidFormat();

        var entries = new List<(string Path, byte[] Data)>();
        long payloadSize = Magic.Length + 1 + 4;

        foreach (string file in EnumerateRegularFiles(root))
        {
            long size;
            try { size = new FileInfo(file).Length; }
            catch { throw EnclaveException.UnreadableFile(Path.GetFileName(file)); }
            if (size > MaxEntrySize) throw EnclaveException.PayloadTooLarge();

            string relativePath = RelativePath(root, file);
            byte[] fileData = File.ReadAllBytes(file);
            if (fileData.LongLength > MaxEntrySize) throw EnclaveException.PayloadTooLarge();

            long entrySize = 4 + Encoding.UTF8.GetByteCount(relativePath) + 8 + fileData.Length;
            if (payloadSize + entrySize > EnclaveCrypto.MaxPlaintextSize)
                throw EnclaveException.PayloadTooLarge();
            payloadSize += entrySize;
            entries.Add((relativePath, fileData));

            if (entries.Count > MaxEntries) throw EnclaveException.PayloadTooLarge();
        }

        if (entries.Count == 0) throw EnclaveException.EmptyFolder();

        entries.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));

        var archive = new MemoryStream();
        archive.Write(Magic);
        archive.WriteByte(Version);
        WriteUInt32(archive, (uint)entries.Count);
        foreach (var entry in entries)
            AppendEntry(archive, entry.Path, entry.Data);

        return archive.ToArray();
    }

    // ===================== Unpack =====================

    public static void Unpack(byte[] payload, string parentDirectory, string folderName)
    {
        int offset = 0;
        if (!IsFolderPayload(payload)) throw EnclaveException.InvalidFormat();
        offset = Magic.Length;

        if (offset + 1 + 4 > payload.Length) throw EnclaveException.InvalidFormat();
        byte fileVersion = payload[offset];
        offset += 1;
        if (fileVersion != Version) throw EnclaveException.InvalidFormat();

        long entryCount = ReadUInt32(payload, ref offset);
        if (entryCount < 1 || entryCount > MaxEntries) throw EnclaveException.InvalidFormat();

        string safeFolderName = SanitizeFolderName(folderName);
        string destination = Path.GetFullPath(Path.Combine(Path.GetFullPath(parentDirectory), safeFolderName));
        EnsureDestinationAvailable(destination);

        for (long i = 0; i < entryCount; i++)
        {
            var (relativePath, fileData) = ReadEntry(payload, ref offset);
            string safePath = SanitizeRelativePath(relativePath);

            string[] parts = safePath.Split('/');
            var combineArgs = new string[parts.Length + 1];
            combineArgs[0] = destination;
            Array.Copy(parts, 0, combineArgs, 1, parts.Length);
            string fileFull = Path.GetFullPath(Path.Combine(combineArgs));

            if (!IsContainedInDirectory(fileFull, destination))
                throw EnclaveException.InvalidFormat();

            string? parent = Path.GetDirectoryName(fileFull);
            if (!string.IsNullOrEmpty(parent))
                Directory.CreateDirectory(parent);
            File.WriteAllBytes(fileFull, fileData);
        }

        if (offset != payload.Length) throw EnclaveException.InvalidFormat();
    }

    private static void EnsureDestinationAvailable(string destination)
    {
        if (Directory.Exists(destination))
        {
            if (Directory.EnumerateFileSystemEntries(destination).Any())
                throw EnclaveException.DestinationExists();
            return;
        }
        if (File.Exists(destination))
            throw EnclaveException.DestinationExists();
        Directory.CreateDirectory(destination);
    }

    // ===================== Path safety =====================

    private static string SanitizeFolderName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Contains('/') || name.Contains('\\'))
            throw EnclaveException.InvalidFormat();
        string baseName = LastComponent(name);
        if (string.IsNullOrEmpty(baseName) || baseName == "." || baseName == "..")
            throw EnclaveException.InvalidFormat();
        if (baseName.Contains(".."))
            throw EnclaveException.InvalidFormat();
        return baseName;
    }

    private static string RelativePath(string root, string file)
    {
        string rel = Path.GetRelativePath(root, file).Replace('\\', '/');
        return SanitizeRelativePath(rel);
    }

    private static string SanitizeRelativePath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.StartsWith('/') || path.Contains('\\'))
            throw EnclaveException.InvalidFormat();
        if (Encoding.UTF8.GetByteCount(path) > MaxPathLength)
            throw EnclaveException.InvalidFormat();

        string[] parts = path.Split('/');
        foreach (string part in parts)
        {
            if (part.Length == 0 || part == "." || part == "..")
                throw EnclaveException.InvalidFormat();
        }
        return string.Join('/', parts);
    }

    private static bool IsContainedInDirectory(string fileFullPath, string directoryFullPath)
    {
        string normalizedDir = directoryFullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string rel = Path.GetRelativePath(normalizedDir, fileFullPath);
        if (rel == "." || rel == "..") return false;
        if (rel.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)) return false;
        if (rel.StartsWith("../", StringComparison.Ordinal)) return false;
        if (Path.IsPathRooted(rel)) return false;
        return true;
    }

    private static string LastComponent(string name)
    {
        int slash = name.LastIndexOfAny(new[] { '/', '\\' });
        return slash >= 0 ? name[(slash + 1)..] : name;
    }

    /// <summary>Recursive walk that skips symlinks/junctions (reparse points),
    /// hidden files, and dotfiles — mirroring the macOS enumerator options and
    /// avoiding traversal out of the tree via a junction.</summary>
    private static IEnumerable<string> EnumerateRegularFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            string[] children;
            try { children = Directory.GetFileSystemEntries(dir); }
            catch { continue; }

            foreach (string entry in children)
            {
                FileAttributes attr;
                try { attr = File.GetAttributes(entry); }
                catch { continue; }

                string name = Path.GetFileName(entry);
                if (name.StartsWith('.')) continue;
                if ((attr & FileAttributes.Hidden) != 0) continue;
                if ((attr & FileAttributes.ReparsePoint) != 0) continue;

                if ((attr & FileAttributes.Directory) != 0)
                {
                    stack.Push(entry);
                    continue;
                }
                yield return entry;
            }
        }
    }

    // ===================== Wire helpers =====================

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        stream.Write(buf);
    }

    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length) throw EnclaveException.InvalidFormat();
        uint value = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    private static void AppendEntry(Stream stream, string path, byte[] fileData)
    {
        byte[] pathData = Encoding.UTF8.GetBytes(path);
        WriteUInt32(stream, (uint)pathData.Length);
        stream.Write(pathData);
        Span<byte> size = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(size, (ulong)fileData.LongLength);
        stream.Write(size);
        stream.Write(fileData);
    }

    private static (string, byte[]) ReadEntry(byte[] data, ref int offset)
    {
        if (data.Length - offset < 4) throw EnclaveException.InvalidFormat();

        long pathLength = ReadUInt32(data, ref offset);
        if (pathLength == 0 || pathLength > MaxPathLength || offset + pathLength + 8 > data.Length)
            throw EnclaveException.InvalidFormat();

        byte[] pathData = data[offset..(offset + (int)pathLength)];
        offset += (int)pathLength;
        string? path = TryUtf8(pathData);
        if (path is null) throw EnclaveException.InvalidFormat();

        ulong fileLength = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
        offset += 8;
        // Zero-length entries are valid — empty files round-trip faithfully.
        if (fileLength > (ulong)MaxEntrySize) throw EnclaveException.InvalidFormat();
        int len = (int)fileLength;
        if (offset + len > data.Length) throw EnclaveException.InvalidFormat();

        byte[] fileData = data[offset..(offset + len)];
        offset += len;
        return (path, fileData);
    }

    private static string? TryUtf8(byte[] bytes)
    {
        try { return StrictUtf8.GetString(bytes); }
        catch { return null; }
    }
}
