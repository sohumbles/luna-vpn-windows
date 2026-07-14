using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("Luna Setup")]
[assembly: AssemblyDescription("Luna VPN offline installer for Windows 10 and Windows 11 x64")]
[assembly: AssemblyCompany("Luna")]
[assembly: AssemblyProduct("Luna")]
[assembly: AssemblyCopyright("Copyright © 2026")]
[assembly: AssemblyVersion("1.3.5.0")]
[assembly: AssemblyFileVersion("1.3.5.0")]
[assembly: AssemblyInformationalVersion("1.3.5-release")]

internal static class LunaInstaller
{
    private const string Version = "1.3.5-release";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\LunaVPN";

    private static readonly string DefaultInstallDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs",
        "Luna");

    [STAThread]
    private static int Main(string[] args)
    {
        bool silent = args.Any(a =>
            a.Equals("/silent", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/verysilent", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/quiet", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/q", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/s", StringComparison.OrdinalIgnoreCase));
        bool uninstall = args.Any(a => a.Equals("/uninstall", StringComparison.OrdinalIgnoreCase));
        string installDirectory = args
            .FirstOrDefault(a => a.StartsWith("/installpath=", StringComparison.OrdinalIgnoreCase));
        installDirectory = installDirectory == null
            ? DefaultInstallDirectory
            : installDirectory.Substring("/installpath=".Length).Trim('"');

        try
        {
            if (uninstall)
            {
                Uninstall(installDirectory, silent);
                return 0;
            }

            if (silent)
            {
                Install(installDirectory, false, false);
                return 0;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm(installDirectory));
            return InstallerForm.ResultCode;
        }
        catch (Exception error)
        {
            if (!silent)
            {
                MessageBox.Show(
                    error.Message,
                    "Luna — ошибка установки",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1603;
        }
    }

    private static void EnsureLunaIsClosed()
    {
        Process current = Process.GetCurrentProcess();
        if (Process.GetProcessesByName("Luna").Any(p => p.Id != current.Id))
            throw new InvalidOperationException(
                "Закройте Luna перед установкой обновления и повторите попытку.");
    }

    internal static void Install(string installDirectory, bool desktopShortcut, bool launchAfterInstall)
    {
        EnsureLunaIsClosed();
        installDirectory = Path.GetFullPath(installDirectory);
        Directory.CreateDirectory(installDirectory);

        using (Stream payload = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("Luna.Payload"))
        {
            if (payload == null)
                throw new InvalidOperationException("В установщике отсутствует пакет Luna.");

            using (ZipArchive archive = new ZipArchive(payload, ZipArchiveMode.Read))
            {
                string root = installDirectory.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destination = Path.GetFullPath(
                        Path.Combine(installDirectory, entry.FullName));
                    if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Пакет содержит небезопасный путь.");

                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(destination);
                        continue;
                    }

                    Directory.CreateDirectory(Path.GetDirectoryName(destination));
                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(
                        destination, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        input.CopyTo(output);
                    }
                }
            }
        }

        string currentInstaller = Assembly.GetExecutingAssembly().Location;
        string uninstaller = Path.Combine(installDirectory, "Uninstall Luna.exe");
        File.Copy(currentInstaller, uninstaller, true);

        string lunaExe = Path.Combine(installDirectory, "Luna.exe");
        string programs = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            "Programs",
            "Luna");
        Directory.CreateDirectory(programs);
        CreateShortcut(Path.Combine(programs, "Luna.lnk"), lunaExe, installDirectory);
        CreateShortcut(Path.Combine(programs, "Удалить Luna.lnk"), uninstaller, installDirectory, "/uninstall");

        string desktopLink = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "Luna.lnk");
        if (desktopShortcut)
            CreateShortcut(desktopLink, lunaExe, installDirectory);

        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(UninstallKey))
        {
            key.SetValue("DisplayName", "Luna VPN");
            key.SetValue("DisplayVersion", Version);
            key.SetValue("Publisher", "Luna");
            key.SetValue("DisplayIcon", lunaExe);
            key.SetValue("InstallLocation", installDirectory);
            key.SetValue("UninstallString", "\"" + uninstaller + "\" /uninstall");
            key.SetValue("QuietUninstallString", "\"" + uninstaller + "\" /uninstall /quiet");
            key.SetValue("NoModify", 1, RegistryValueKind.DWord);
            key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            key.SetValue("EstimatedSize",
                (int)(Directory.GetFiles(installDirectory, "*", SearchOption.AllDirectories)
                    .Sum(f => new FileInfo(f).Length) / 1024),
                RegistryValueKind.DWord);
        }

        if (launchAfterInstall)
            Process.Start(new ProcessStartInfo(lunaExe) { WorkingDirectory = installDirectory });
    }

    private static void Uninstall(string installDirectory, bool silent)
    {
        EnsureLunaIsClosed();
        installDirectory = Path.GetFullPath(installDirectory);

        if (!silent)
        {
            DialogResult answer = MessageBox.Show(
                "Удалить Luna с этого компьютера?\r\n\r\n" +
                "Пользовательские настройки в %LOCALAPPDATA%\\Luna будут сохранены.",
                "Удаление Luna",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (answer != DialogResult.Yes)
                return;
        }

        string programs = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            "Programs",
            "Luna");
        string desktopLink = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "Luna.lnk");
        if (Directory.Exists(programs))
            Directory.Delete(programs, true);
        if (File.Exists(desktopLink))
            File.Delete(desktopLink);
        Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);

        string helper = Path.Combine(Path.GetTempPath(), "luna-remove-" + Guid.NewGuid().ToString("N") + ".cmd");
        File.WriteAllText(
            helper,
            "@echo off\r\n" +
            "ping 127.0.0.1 -n 3 >nul\r\n" +
            "rmdir /s /q \"" + installDirectory + "\"\r\n" +
            "del /q \"%~f0\"\r\n");
        Process.Start(new ProcessStartInfo("cmd.exe", "/c \"" + helper + "\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }

    private static void CreateShortcut(
        string shortcutPath,
        string targetPath,
        string workingDirectory,
        string arguments = "")
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        dynamic shell = Activator.CreateInstance(shellType);
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workingDirectory;
        shortcut.Arguments = arguments;
        shortcut.IconLocation = targetPath + ",0";
        shortcut.Description = "Luna VPN";
        shortcut.Save();
    }

    private sealed class InstallerForm : Form
    {
        internal static int ResultCode = 1602;

        private readonly string installDirectory;
        private readonly CheckBox desktopShortcut;
        private readonly CheckBox launchAfterInstall;
        private readonly Button installButton;
        private readonly Label status;
        private readonly ProgressBar progress;

        internal InstallerForm(string directory)
        {
            installDirectory = directory;
            Text = "Установка Luna VPN";
            Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ClientSize = new Size(560, 390);
            BackColor = Color.FromArgb(8, 10, 35);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10F);

            Label brand = new Label
            {
                Text = "Luna",
                Font = new Font("Segoe UI Semibold", 30F),
                ForeColor = Color.FromArgb(181, 168, 255),
                AutoSize = true,
                Location = new Point(34, 28)
            };
            Label title = new Label
            {
                Text = "Установка Luna VPN",
                Font = new Font("Segoe UI Semibold", 19F),
                AutoSize = true,
                Location = new Point(36, 100)
            };
            Label details = new Label
            {
                Text = "Версия 1.3.5-release\r\n" +
                       "Автономная установка для Windows 10 и Windows 11 x64.\r\n\r\n" +
                       "Папка: " + installDirectory,
                ForeColor = Color.FromArgb(196, 202, 226),
                AutoSize = false,
                Size = new Size(490, 83),
                Location = new Point(39, 145)
            };

            desktopShortcut = new CheckBox
            {
                Text = "Создать ярлык на рабочем столе",
                Checked = true,
                AutoSize = true,
                Location = new Point(40, 238)
            };
            launchAfterInstall = new CheckBox
            {
                Text = "Запустить Luna после установки",
                Checked = true,
                AutoSize = true,
                Location = new Point(40, 270)
            };
            progress = new ProgressBar
            {
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 25,
                Visible = false,
                Location = new Point(40, 309),
                Size = new Size(480, 6)
            };
            status = new Label
            {
                Text = "",
                ForeColor = Color.FromArgb(116, 229, 178),
                AutoSize = true,
                Location = new Point(40, 324)
            };
            installButton = new Button
            {
                Text = "Установить Luna",
                BackColor = Color.FromArgb(71, 58, 157),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(165, 42),
                Location = new Point(355, 334)
            };
            installButton.FlatAppearance.BorderColor = Color.FromArgb(145, 127, 255);
            installButton.Click += async (sender, eventArgs) => await InstallAsync();

            Controls.AddRange(new Control[] {
                brand, title, details, desktopShortcut, launchAfterInstall,
                progress, status, installButton
            });
        }

        private async Task InstallAsync()
        {
            installButton.Enabled = false;
            desktopShortcut.Enabled = false;
            launchAfterInstall.Enabled = false;
            progress.Visible = true;
            status.Text = "Устанавливаем Luna…";

            try
            {
                await Task.Run(() => Install(
                    installDirectory,
                    desktopShortcut.Checked,
                    launchAfterInstall.Checked));
                ResultCode = 0;
                status.Text = "Luna установлена.";
                MessageBox.Show(
                    "Установка Luna 1.3.5-release завершена.",
                    "Luna",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                Close();
            }
            catch (Exception error)
            {
                ResultCode = 1603;
                progress.Visible = false;
                status.Text = "Установка не выполнена.";
                installButton.Enabled = true;
                desktopShortcut.Enabled = true;
                launchAfterInstall.Enabled = true;
                MessageBox.Show(
                    error.Message,
                    "Luna — ошибка установки",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
    }
}
