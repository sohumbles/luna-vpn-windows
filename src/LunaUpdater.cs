using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

internal static class LunaUpdater
{
    private static readonly string[] StateFiles =
    {
        "state.json",
        "client-api.json",
        "luna-auto-state.json",
        "backend-servers-cache.json",
        "backend-metadata-cache.json"
    };

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            var options = Parse(args);
            string installer = Required(options, "installer");
            string dataRoot = Required(options, "data-root");
            string launch = Required(options, "launch");
            string fallback = options.ContainsKey("fallback") ? options["fallback"] : launch;
            string version = options.ContainsKey("version") ? options["version"] : "unknown";
            int pid = options.ContainsKey("pid") ? Int32.Parse(options["pid"]) : 0;

            installer = Path.GetFullPath(installer);
            dataRoot = Path.GetFullPath(dataRoot);
            launch = Path.GetFullPath(launch);
            fallback = Path.GetFullPath(fallback);
            if (!File.Exists(installer))
                throw new FileNotFoundException("Downloaded Luna installer was not found.", installer);

            Directory.CreateDirectory(dataRoot);
            WaitForProcess(pid, TimeSpan.FromSeconds(45));
            string backupRoot = BackupState(dataRoot, version);

            var start = new ProcessStartInfo
            {
                FileName = installer,
                Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS",
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(installer)
            };
            using (Process process = Process.Start(start))
            {
                if (process == null)
                    throw new InvalidOperationException("The Luna installer could not be started.");
                process.WaitForExit();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException("The Luna installer returned code " + process.ExitCode + ".");
            }

            RestoreMissingState(dataRoot, backupRoot);
            WriteResult(dataRoot, true, version, backupRoot, null);
            StartApplication(launch, fallback);
            return 0;
        }
        catch (Exception error)
        {
            try
            {
                var options = Parse(args);
                string dataRoot = options.ContainsKey("data-root")
                    ? Path.GetFullPath(options["data-root"])
                    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Luna");
                string version = options.ContainsKey("version") ? options["version"] : "unknown";
                string fallback = options.ContainsKey("fallback") ? options["fallback"] : null;
                Directory.CreateDirectory(dataRoot);
                WriteResult(dataRoot, false, version, null, error.Message);
                if (!String.IsNullOrWhiteSpace(fallback) && File.Exists(fallback))
                    Process.Start(new ProcessStartInfo { FileName = fallback, UseShellExecute = true });
            }
            catch { }
            return 1;
        }
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                continue;
            string key = args[i].Substring(2);
            string value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[++i]
                : "true";
            result[key] = value;
        }
        return result;
    }

    private static string Required(IDictionary<string, string> options, string key)
    {
        string value;
        if (!options.TryGetValue(key, out value) || String.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Missing required argument --" + key + ".");
        return value;
    }

    private static string BackupState(string dataRoot, string version)
    {
        string safeVersion = new string(version.Select(c => Char.IsLetterOrDigit(c) || c == '.' || c == '-' ? c : '_').ToArray());
        string backupRoot = Path.Combine(
            dataRoot,
            "backups",
            "before-" + safeVersion + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
        Directory.CreateDirectory(backupRoot);
        foreach (string name in StateFiles)
        {
            string source = Path.Combine(dataRoot, name);
            if (File.Exists(source))
                File.Copy(source, Path.Combine(backupRoot, name), true);
        }
        return backupRoot;
    }

    private static void RestoreMissingState(string dataRoot, string backupRoot)
    {
        foreach (string name in StateFiles)
        {
            string destination = Path.Combine(dataRoot, name);
            string backup = Path.Combine(backupRoot, name);
            if (!File.Exists(destination) && File.Exists(backup))
                File.Copy(backup, destination, false);
        }
    }

    private static void WaitForProcess(int pid, TimeSpan timeout)
    {
        if (pid <= 0)
            return;
        try
        {
            using (Process process = Process.GetProcessById(pid))
                process.WaitForExit((int)timeout.TotalMilliseconds);
        }
        catch (ArgumentException) { }
    }

    private static void StartApplication(string launch, string fallback)
    {
        string target = File.Exists(launch) ? launch : fallback;
        if (!String.IsNullOrWhiteSpace(target) && File.Exists(target))
            Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
    }

    private static void WriteResult(string dataRoot, bool success, string version, string backup, string error)
    {
        string path = Path.Combine(dataRoot, "pending-update-result.json");
        string json = "{"
            + "\"success\":" + (success ? "true" : "false") + ","
            + "\"version\":\"" + Escape(version) + "\","
            + "\"completedAt\":\"" + DateTime.UtcNow.ToString("O") + "\","
            + "\"backup\":\"" + Escape(backup ?? String.Empty) + "\","
            + "\"error\":\"" + Escape(error ?? String.Empty) + "\""
            + "}";
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, json, new UTF8Encoding(false));
        if (File.Exists(path))
            File.Delete(path);
        File.Move(temporary, path);
    }

    private static string Escape(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\r", "\\r")
            .Replace("\n", "\\n");
    }
}
