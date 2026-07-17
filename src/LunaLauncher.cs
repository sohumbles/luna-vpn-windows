using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

[assembly: AssemblyTitle("Luna")]
[assembly: AssemblyDescription("Luna VPN client for Windows 10 and Windows 11")]
[assembly: AssemblyCompany("Luna")]
[assembly: AssemblyProduct("Luna")]
[assembly: AssemblyCopyright("Copyright © 2026")]
[assembly: AssemblyVersion("1.5.3.0")]
[assembly: AssemblyFileVersion("1.5.3.0")]
[assembly: AssemblyInformationalVersion("1.5.3-release")]

internal static class LunaLauncher
{
    private const int AppModelErrorNoPackage = 15700;
    private const string InstanceMutexName = @"Local\Luna.VPN.Desktop.SingleInstance";

    [DllImport("shell32.dll")]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(
        ref uint packageFullNameLength,
        StringBuilder packageFullName);

    private static bool IsPackaged()
    {
        uint length = 0;
        return GetCurrentPackageFullName(ref length, null) != AppModelErrorNoPackage;
    }

    private static void Extract(string resourceName, string destination)
    {
        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
        {
            if (input == null)
                throw new InvalidOperationException("Missing resource: " + resourceName);

            using (FileStream output = new FileStream(
                destination,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read))
            {
                input.CopyTo(output);
            }
        }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        bool createdNew;
        using (Mutex instanceMutex = new Mutex(true, InstanceMutexName, out createdNew))
        {
            bool elevationHandoff = args.Any(arg => string.Equals(arg, "--elevated-tun", StringComparison.OrdinalIgnoreCase));
            if (!createdNew)
            {
                if (elevationHandoff)
                {
                    bool acquired = false;
                    try { acquired = instanceMutex.WaitOne(TimeSpan.FromSeconds(15)); }
                    catch (AbandonedMutexException) { acquired = true; }
                    if (acquired)
                        return Run(args);
                }

                System.Windows.Forms.MessageBox.Show(
                    "Luna уже запущена.\r\n\r\nОткройте существующее окно через панель задач или значок Luna в системном трее.",
                    "Luna уже работает",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Information);
                return 0;
            }

            return Run(args);
        }
    }

    private static int Run(string[] args)
    {
        try
        {
            SetCurrentProcessExplicitAppUserModelID("Luna.VPN.Desktop");

            string runtime = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Luna",
                "runtime",
                "1.5.3-release");
            Directory.CreateDirectory(runtime);

            string script = Path.Combine(runtime, "Luna.ps1");
            string icon = Path.Combine(runtime, "luna-icon.png");
            Extract("Luna.Script", script);
            Extract("Luna.Icon", icon);

            Environment.SetEnvironmentVariable(
                "LUNA_RUNTIME_DIR",
                runtime,
                EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable(
                "LUNA_EXECUTABLE_PATH",
                Assembly.GetExecutingAssembly().Location,
                EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable(
                "LUNA_APP_DIR",
                AppDomain.CurrentDomain.BaseDirectory,
                EnvironmentVariableTarget.Process);

            if (IsPackaged())
            {
                Environment.SetEnvironmentVariable(
                    "LUNA_PACKAGED",
                    "1",
                    EnvironmentVariableTarget.Process);
            }

            if (args.Any(arg => string.Equals(
                arg,
                "--tray",
                StringComparison.OrdinalIgnoreCase)))
            {
                Environment.SetEnvironmentVariable(
                    "LUNA_START_IN_TRAY",
                    "1",
                    EnvironmentVariableTarget.Process);
            }

            if (args.Any(arg => string.Equals(
                arg,
                "--elevated-tun",
                StringComparison.OrdinalIgnoreCase)))
            {
                Environment.SetEnvironmentVariable(
                    "LUNA_TUN_AUTOCONNECT",
                    "1",
                    EnvironmentVariableTarget.Process);
            }

            InitialSessionState session = InitialSessionState.CreateDefault();
            using (Runspace runspace = RunspaceFactory.CreateRunspace(session))
            {
                runspace.ApartmentState = System.Threading.ApartmentState.STA;
                runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
                runspace.Open();

                using (PowerShell shell = PowerShell.Create())
                {
                    shell.Runspace = runspace;
                    shell.AddScript(File.ReadAllText(script));
                    shell.Invoke();

                    if (shell.Streams.Error.Count > 0)
                    {
                        string message = shell.Streams.Error[0].ToString();
                        throw new InvalidOperationException(message);
                    }
                }
            }

            return 0;
        }
        catch (Exception error)
        {
            System.Windows.Forms.MessageBox.Show(
                error.Message,
                "Luna",
                System.Windows.Forms.MessageBoxButtons.OK,
                System.Windows.Forms.MessageBoxIcon.Error);
            return 1;
        }
    }
}
