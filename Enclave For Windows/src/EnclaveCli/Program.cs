using System.Text;
using EnclaveCore;

namespace EnclaveCli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        string command = args[0];

        if (command is "help" or "-h" or "--help")
        {
            PrintUsage();
            return 0;
        }

        if (command is "selftest")
            return SelfTest.Run();

        Options options;
        try
        {
            options = ParseOptions(args.Skip(1).ToArray());
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            PrintUsage();
            return 1;
        }

        if (options.Input is null)
        {
            Console.Error.WriteLine("Error: missing input file or folder.");
            PrintUsage();
            return 1;
        }

        string input = options.Input;
        if (!File.Exists(input) && !Directory.Exists(input))
        {
            Console.Error.WriteLine($"Error: path not found: {input}");
            return 1;
        }

        string? password = options.Password ?? PromptPassword();
        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Error: password is required.");
            return 1;
        }

        try
        {
            switch (command)
            {
                case "encrypt" or "enc" or "e":
                    Encrypt(input, password, options.Output, options.EncryptFilename);
                    break;
                case "decrypt" or "dec" or "d":
                    Decrypt(input, password, options.Output);
                    break;
                default:
                    Console.Error.WriteLine($"Error: unknown command '{command}'.");
                    PrintUsage();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static void Encrypt(string input, string password, string? output, bool encryptFilename)
    {
        if (EnclaveCrypto.IsArchiveFilename(input))
            throw EnclaveException.CannotEncryptArchive();

        var prepared = EnclaveIo.PrepareEncryptionPayload(input);
        var result = EnclaveCrypto.Encrypt(prepared.Data, prepared.Filename, password, encryptFilename);

        string outputPath = EnclaveIo.ResolveOutputPath(output, result.DiskFilename, input);
        File.WriteAllBytes(outputPath, result.Data);
        Console.WriteLine($"Encrypted: {outputPath}");
    }

    private static void Decrypt(string input, string password, string? output)
    {
        byte[] data = EnclaveIo.ReadArchive(input);
        var (payload, filename) = EnclaveCrypto.Decrypt(data, password);

        if (EnclaveFolder.IsFolderPayload(payload))
        {
            string parent = EnclaveIo.ResolveFolderDecryptParent(output, input);
            EnclaveIo.WriteDecryptedPayload(payload, filename, parent);
            string folderName = EnclaveFolder.DisplayFolderName(filename);
            Console.WriteLine($"Decrypted folder: {Path.Combine(parent, folderName)}");
            return;
        }

        string outputPath = EnclaveIo.ResolveOutputPath(output, filename, input, filename);
        EnclaveIo.WriteDecryptedPayload(payload, filename, outputPath);
        Console.WriteLine($"Decrypted: {outputPath}");
    }

    private static string? PromptPassword()
    {
        if (Console.IsInputRedirected) return null;
        Console.Error.Write("Password: ");
        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);
            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }
            if (keyInfo.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) sb.Length--;
                continue;
            }
            if (!char.IsControl(keyInfo.KeyChar))
                sb.Append(keyInfo.KeyChar);
        }
        string password = sb.ToString();
        return password.Length == 0 ? null : password;
    }

    private sealed class Options
    {
        public string? Input;
        public string? Output;
        public string? Password;
        public bool EncryptFilename = true;
    }

    private static Options ParseOptions(string[] args)
    {
        var options = new Options();
        int index = 0;
        while (index < args.Length)
        {
            string arg = args[index];
            switch (arg)
            {
                case "-o" or "--output":
                    index++;
                    if (index >= args.Length) throw new ArgumentException($"Missing value for {arg}.");
                    options.Output = EnclaveIo.ExpandedPath(args[index]);
                    break;
                case "-p" or "--password":
                    index++;
                    if (index >= args.Length) throw new ArgumentException($"Missing value for {arg}.");
                    options.Password = args[index];
                    break;
                case "--plaintext-filename" or "--no-encrypt-filename":
                    options.EncryptFilename = false;
                    break;
                default:
                    if (!arg.StartsWith('-') && options.Input is null)
                        options.Input = EnclaveIo.ExpandedPath(arg);
                    break;
            }
            index++;
        }
        return options;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            Enclave — simple AES-256-GCM file encryption for Windows

            Usage:
              enclave-cli encrypt <file-or-folder> [-p password] [-o output]
              enclave-cli decrypt <file> [-p password] [-o output]
              enclave-cli selftest

            Options:
              -p, --password   Password (prompted securely if omitted in a terminal)
              -o, --output     Output file or directory
              --plaintext-filename
                               Store the original filename in plaintext (encrypt only)

            Notes:
              - Files and folders are encrypted with AES-256-GCM (folders are packed first).
              - Keys are derived with Argon2id (BLAKE2b; 64 MiB, 3 iterations, 1 lane)
                from your password and a random salt.
              - Older v3 PBKDF2-HMAC-SHA256 and v2 HKDF-SHA512 archives still decrypt.
              - Archives are byte-compatible with the macOS Enclave build.
              - Avoid -p on shared systems; passwords may be visible in process lists.
            """);
    }
}
