using System.Text;

namespace EnclaveCore;

/// <summary>File IO, validation, and output-path resolution. Adapted from the
/// macOS URL-based version to Windows paths.</summary>
public static class EnclaveIo
{
    public static string ExpandedPath(string path)
    {
        if (path == "~")
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[2..]);
        return path;
    }

    public static void ValidatePlaintextInput(string path)
    {
        bool isDir = Directory.Exists(path);
        if (!isDir && !File.Exists(path))
            throw EnclaveException.UnreadableFile(Name(path));
        if (!IsReadable(path, isDir))
            throw EnclaveException.UnreadableFile(Name(path));
        if (EnclaveCrypto.IsArchiveFilename(Name(path)))
            throw EnclaveException.CannotEncryptArchive();

        if (isDir)
        {
            if (!DirectoryContainsRegularFile(path))
                throw EnclaveException.EmptyFolder();
        }
        else
        {
            ValidateFileSize(path);
        }
    }

    public static (byte[] Data, string Filename) PrepareEncryptionPayload(string path)
    {
        ValidatePlaintextInput(path);
        if (EnclaveFolder.IsDirectory(path))
        {
            byte[] packed = EnclaveFolder.Pack(path);
            return (packed, EnclaveFolder.StoredFilename(path));
        }

        byte[] data = File.ReadAllBytes(path);
        if (data.LongLength > EnclaveCrypto.MaxPlaintextSize)
            throw EnclaveException.PayloadTooLarge();
        return (data, Name(path));
    }

    public static string ResolveFolderDecryptParent(string? output, string inputPath)
    {
        if (output is null)
            return Path.GetDirectoryName(Path.GetFullPath(inputPath)) ?? Directory.GetCurrentDirectory();

        if (Directory.Exists(output))
            return Path.GetFullPath(output);

        string parent = Path.GetDirectoryName(Path.GetFullPath(output)) ?? "";
        if (!string.IsNullOrEmpty(parent))
            Directory.CreateDirectory(parent);
        return string.IsNullOrEmpty(parent)
            ? Path.GetDirectoryName(Path.GetFullPath(inputPath)) ?? Directory.GetCurrentDirectory()
            : parent;
    }

    public static void WriteDecryptedPayload(byte[] payload, string filename, string outputPath)
    {
        if (EnclaveFolder.IsFolderPayload(payload))
        {
            string folderName = EnclaveFolder.DisplayFolderName(filename);
            EnclaveFolder.Unpack(payload, outputPath, folderName);
            return;
        }
        File.WriteAllBytes(outputPath, payload);
    }

    public static void ValidateArchiveInput(string path)
    {
        if (!File.Exists(path))
            throw EnclaveException.InvalidFormat();
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw EnclaveException.InvalidFormat();
        if (!IsReadable(path, isDirectory: false))
            throw EnclaveException.UnreadableFile(Name(path));

        long size = new FileInfo(path).Length;
        if (size > EnclaveCrypto.MaxArchiveSize)
            throw EnclaveException.PayloadTooLarge();

        Span<byte> header = stackalloc byte[EnclaveCrypto.Magic.Length];
        using var stream = File.OpenRead(path);
        int read = stream.Read(header);
        if (read < header.Length || !EnclaveCrypto.IsArchiveData(header))
            throw EnclaveException.InvalidFormat();
    }

    public static byte[] ReadArchive(string path)
    {
        ValidateArchiveInput(path);
        byte[] data = File.ReadAllBytes(path);
        if (data.LongLength > EnclaveCrypto.MaxArchiveSize)
            throw EnclaveException.PayloadTooLarge();
        return data;
    }

    public static string ResolveOutputPath(
        string? output,
        string defaultName,
        string inputPath,
        string? appendedFilename = null)
    {
        if (output is null)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(inputPath)) ?? Directory.GetCurrentDirectory();
            return Path.Combine(dir, defaultName);
        }

        if (Directory.Exists(output))
            return Path.Combine(Path.GetFullPath(output), appendedFilename ?? defaultName);

        string parent = Path.GetDirectoryName(Path.GetFullPath(output)) ?? "";
        if (!string.IsNullOrEmpty(parent))
            Directory.CreateDirectory(parent);
        return Path.GetFullPath(output);
    }

    public static string NormalizedArchivePath(string path)
    {
        if (!EnclaveCrypto.IsArchiveFilename(Name(path)))
            return Path.ChangeExtension(path, "." + EnclaveCrypto.FileExtension);
        return path;
    }

    // ===================== helpers =====================

    private static string Name(string path)
    {
        string trimmed = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string name = Path.GetFileName(trimmed);
        return string.IsNullOrEmpty(name) ? path : name;
    }

    private static bool IsReadable(string path, bool isDirectory)
    {
        try
        {
            if (isDirectory)
            {
                _ = Directory.EnumerateFileSystemEntries(path).Any();
                return true;
            }
            using var s = File.OpenRead(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ValidateFileSize(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw EnclaveException.UnreadableFile(Name(path));
        long size = new FileInfo(path).Length;
        if (size > EnclaveCrypto.MaxPlaintextSize)
            throw EnclaveException.PayloadTooLarge();
    }

    private static bool DirectoryContainsRegularFile(string path)
    {
        var stack = new Stack<string>();
        stack.Push(path);
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir); }
            catch { continue; }
            foreach (string entry in entries)
            {
                FileAttributes attr;
                try { attr = File.GetAttributes(entry); }
                catch { continue; }
                string name = Path.GetFileName(entry);
                if (name.StartsWith('.')) continue;
                if ((attr & FileAttributes.Hidden) != 0) continue;
                if ((attr & FileAttributes.ReparsePoint) != 0) continue;
                if ((attr & FileAttributes.Directory) != 0) { stack.Push(entry); continue; }
                return true;
            }
        }
        return false;
    }
}
