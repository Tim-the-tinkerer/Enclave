using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using EnclaveCore;

namespace EnclaveApp;

public partial class MainWindow : Window
{
    private string? _selectedPath;

    public MainWindow()
    {
        InitializeComponent();
        LoadStartupFile();
    }

    /// <summary>
    /// When Enclave is launched by opening a file (double-click or "Open with"),
    /// Windows passes that file's path as a command-line argument. Pre-select it
    /// so the user can decrypt straight away instead of dragging it in.
    /// </summary>
    private void LoadStartupFile()
    {
        string[] args = Environment.GetCommandLineArgs();
        // args[0] is Enclave's own path; a file passed by Windows is args[1+].
        for (int i = 1; i < args.Length; i++)
        {
            string candidate = args[i];
            if (File.Exists(candidate) || Directory.Exists(candidate))
            {
                SetSelectedPath(Path.GetFullPath(candidate));
                // If it's an archive, focus the password box — it's ready to decrypt.
                if (File.Exists(candidate) && EnclaveCrypto.IsArchiveFilename(candidate))
                    PasswordBox.Focus();
                break;
            }
        }
    }

    // ===================== Selection =====================

    private void SetSelectedPath(string? path)
    {
        _selectedPath = path;
        if (string.IsNullOrEmpty(path))
        {
            SelectedPathText.Text = "";
            DropHint.Text = "Drag a file or folder here";
            return;
        }
        SelectedPathText.Text = path;
        bool isFolder = Directory.Exists(path);
        bool isArchive = File.Exists(path) && EnclaveCrypto.IsArchiveFilename(path);
        DropHint.Text = isFolder ? "Folder selected" : isArchive ? "Encrypted archive selected" : "File selected";
        StatusText.Text = "";
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a file", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true)
            SetSelectedPath(dialog.FileName);
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder" };
        if (dialog.ShowDialog(this) == true)
            SetSelectedPath(dialog.FolderName);
    }

    private void DropArea_DragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            DropArea.Background = new SolidColorBrush(Color.FromRgb(0x33, 0x39, 0x4B));
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void DropArea_DragLeave(object sender, DragEventArgs e)
    {
        DropArea.Background = (Brush)Application.Current.Resources["PanelBrush"];
    }

    private void DropArea_Drop(object sender, DragEventArgs e)
    {
        DropArea.Background = (Brush)Application.Current.Resources["PanelBrush"];
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
            SetSelectedPath(paths[0]);
    }

    // ===================== Encrypt =====================

    private async void Encrypt_Click(object sender, RoutedEventArgs e)
    {
        if (!ValidateSelectionAndPassword(out string input, out string password)) return;

        if (EnclaveCrypto.IsArchiveFilename(input))
        {
            Fail("That file is already an Enclave archive.");
            return;
        }

        bool encryptFilename = EncryptFilenameCheck.IsChecked == true;
        SetBusy(true, "Encrypting…");
        try
        {
            EncryptResult result = await Task.Run(() =>
            {
                var prepared = EnclaveIo.PrepareEncryptionPayload(input);
                return EnclaveCrypto.Encrypt(prepared.Data, prepared.Filename, password, encryptFilename);
            });

            var save = new SaveFileDialog
            {
                Title = "Save encrypted archive",
                FileName = result.DiskFilename,
                Filter = "Encrypted archive (*.enclave;*.enigma)|*.enclave;*.enigma|All files (*.*)|*.*",
                InitialDirectory = SafeDirectoryOf(input)
            };
            if (save.ShowDialog(this) != true) { SetBusy(false, "Cancelled."); return; }

            string outputPath = save.FileName;
            await Task.Run(() => File.WriteAllBytes(outputPath, result.Data));
            SetBusy(false, $"Encrypted → {outputPath}");
        }
        catch (Exception ex)
        {
            SetBusy(false, "");
            Fail(Describe(ex));
        }
    }

    // ===================== Decrypt =====================

    private async void Decrypt_Click(object sender, RoutedEventArgs e)
    {
        if (!ValidateSelectionAndPassword(out string input, out string password)) return;

        SetBusy(true, "Decrypting…");
        try
        {
            DecryptResult result = await Task.Run(() =>
            {
                byte[] data = EnclaveIo.ReadArchive(input);
                return EnclaveCrypto.Decrypt(data, password);
            });

            if (EnclaveFolder.IsFolderPayload(result.Payload))
            {
                var dialog = new OpenFolderDialog
                {
                    Title = "Choose where to restore the folder",
                    InitialDirectory = SafeDirectoryOf(input)
                };
                if (dialog.ShowDialog(this) != true) { SetBusy(false, "Cancelled."); return; }

                string parent = dialog.FolderName;
                string filename = result.Filename;
                byte[] payload = result.Payload;
                await Task.Run(() => EnclaveIo.WriteDecryptedPayload(payload, filename, parent));
                string folderName = EnclaveFolder.DisplayFolderName(result.Filename);
                SetBusy(false, $"Restored folder → {Path.Combine(parent, folderName)}");
            }
            else
            {
                var save = new SaveFileDialog
                {
                    Title = "Save decrypted file",
                    FileName = result.Filename,
                    InitialDirectory = SafeDirectoryOf(input)
                };
                if (save.ShowDialog(this) != true) { SetBusy(false, "Cancelled."); return; }

                string outputPath = save.FileName;
                byte[] payload = result.Payload;
                string filename = result.Filename;
                await Task.Run(() => EnclaveIo.WriteDecryptedPayload(payload, filename, outputPath));
                SetBusy(false, $"Decrypted → {outputPath}");
            }
        }
        catch (Exception ex)
        {
            SetBusy(false, "");
            Fail(Describe(ex));
        }
    }

    // ===================== About =====================

    private void Help_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string path = Path.Combine(AppContext.BaseDirectory, "help.html");
            if (!File.Exists(path))
            {
                Fail("Help file not found next to the app.");
                return;
            }
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Fail(Describe(ex));
        }
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            $"Enclave {AppInfo.Version} (build {AppInfo.Build})\n\n" +
            "AES-256-GCM encrypts file contents and (optionally) the filename.\n" +
            "Argon2id (BLAKE2b) derives keys from your password — 64 MiB, 3 iterations, 1 lane.\n" +
            "SHA-512 hashes the on-disk filename only.\n" +
            "Older PBKDF2-HMAC-SHA256 (v3) and HKDF-SHA512 (v2) archives still decrypt.\n\n" +
            "Archives are byte-compatible with the macOS Enclave build.\n\n" +
            "Click Help for full documentation.",
            "About Enclave", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ===================== Helpers =====================

    private bool ValidateSelectionAndPassword(out string input, out string password)
    {
        input = _selectedPath ?? "";
        password = PasswordBox.Password;

        if (string.IsNullOrEmpty(input) || (!File.Exists(input) && !Directory.Exists(input)))
        {
            Fail("Choose a file or folder first.");
            return false;
        }
        if (string.IsNullOrWhiteSpace(password))
        {
            Fail("Enter a password.");
            return false;
        }
        return true;
    }

    private void SetBusy(bool busy, string status)
    {
        EncryptButton.IsEnabled = !busy;
        DecryptButton.IsEnabled = !busy;
        Cursor = busy ? Cursors.Wait : Cursors.Arrow;
        StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0x9E, 0xB3));
        StatusText.Text = status;
    }

    private void Fail(string message)
    {
        StatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x6B, 0x6B));
        StatusText.Text = message;
    }

    private static string Describe(Exception ex) =>
        ex is EnclaveException ee ? ee.Message : ex.Message;

    private static string SafeDirectoryOf(string path)
    {
        try
        {
            string? dir = Directory.Exists(path) ? Path.GetDirectoryName(path.TrimEnd(Path.DirectorySeparatorChar))
                                                  : Path.GetDirectoryName(path);
            return string.IsNullOrEmpty(dir) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : dir;
        }
        catch
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }
    }
}
