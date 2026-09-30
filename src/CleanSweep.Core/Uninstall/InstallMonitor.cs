using System.ServiceProcess;
using System.Text.Json;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.Uninstall;

/// <summary>安装监控快照：已安装应用、关键目录的一级子目录、服务、Run 启动项。</summary>
public sealed class MonitorSnapshot
{
    public DateTime TakenUtc { get; set; }
    public string Label { get; set; } = "";
    public Dictionary<string, string> Apps { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, DateTime> Directories { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Services { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> RunEntries { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record MonitorDiff(
    IReadOnlyList<string> NewApps,
    IReadOnlyList<string> RemovedApps,
    IReadOnlyList<string> NewDirectories,
    IReadOnlyList<string> ModifiedDirectories,
    IReadOnlyList<string> NewServices,
    IReadOnlyList<(string Name, string Command)> NewRunEntries)
{
    public bool IsEmpty => NewApps.Count == 0 && RemovedApps.Count == 0 && NewDirectories.Count == 0 && NewServices.Count == 0 && NewRunEntries.Count == 0;
}

/// <summary>
/// 安装监控（设计文档 5.1）：安装前拍快照，安装后比对，列出新增的应用、目录、服务与启动项。
/// 本阶段只做"识别"，回滚交给残留清理与开机加速分别处理（新增目录移入隔离区、新增启动项禁用）。
/// </summary>
public sealed class InstallMonitor
{
    private readonly AppInventory _inventory;
    private readonly IEnvironmentResolver _env;
    private readonly string _storeDir;

    public InstallMonitor(AppInventory inventory, IEnvironmentResolver env, string storeDir)
    {
        _inventory = inventory;
        _env = env;
        _storeDir = storeDir;
    }

    public MonitorSnapshot Take(string label, CancellationToken ct = default)
    {
        var snap = new MonitorSnapshot { TakenUtc = DateTime.UtcNow, Label = label };

        foreach (var a in _inventory.Scan(ct).Apps) snap.Apps[a.Id] = a.Name;

        foreach (var var in new[] { "ProgramFiles", "ProgramFilesX86", "ProgramData", "LocalAppData", "AppData", "LocalAppDataLow" })
        {
            if (!_env.Variables.TryGetValue(var, out var root) || !Directory.Exists(root)) continue;
            AddDirs(snap, root);
        }
        if (_env.Variables.TryGetValue("LocalAppData", out var local))
        {
            AddDirs(snap, Path.Combine(local, "Programs"));
            AddDirs(snap, Path.Combine(local, "Packages"));
        }

        try { foreach (var s in ServiceController.GetServices()) { snap.Services.Add(s.ServiceName); s.Dispose(); } }
        catch { }

        foreach (var (key, view) in new[]
                 {
                     (@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64),
                     (@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64),
                     (@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry32),
                 })
        {
            try
            {
                using var k = RegistryPath.Open(key, view, writable: false);
                if (k is null) continue;
                foreach (var name in k.GetValueNames())
                {
                    if (k.GetValue(name) is string cmd) snap.RunEntries[$"{key}|{view}|{name}"] = cmd;
                }
            }
            catch { }
        }
        return snap;
    }

    private static void AddDirs(MonitorSnapshot snap, string root)
    {
        if (!Directory.Exists(root)) return;
        try
        {
            foreach (var d in new DirectoryInfo(root).EnumerateDirectories("*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
            {
                try { snap.Directories[d.FullName] = d.LastWriteTimeUtc; } catch { }
            }
        }
        catch { }
    }

    public static MonitorDiff Diff(MonitorSnapshot before, MonitorSnapshot after)
    {
        var newApps = after.Apps.Where(kv => !before.Apps.ContainsKey(kv.Key)).Select(kv => kv.Value).OrderBy(n => n).ToList();
        var removed = before.Apps.Where(kv => !after.Apps.ContainsKey(kv.Key)).Select(kv => kv.Value).OrderBy(n => n).ToList();
        var newDirs = after.Directories.Keys.Where(d => !before.Directories.ContainsKey(d)).OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        var modified = after.Directories.Where(kv => before.Directories.TryGetValue(kv.Key, out var t) && t != kv.Value).Select(kv => kv.Key)
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        var newServices = after.Services.Where(s => !before.Services.Contains(s)).OrderBy(s => s).ToList();
        var newRun = after.RunEntries.Where(kv => !before.RunEntries.ContainsKey(kv.Key)).Select(kv => (kv.Key.Split('|')[^1], kv.Value)).ToList();
        return new MonitorDiff(newApps, removed, newDirs, modified, newServices, newRun);
    }

    // ---------- 持久化 ----------

    public string Save(MonitorSnapshot snap)
    {
        Directory.CreateDirectory(_storeDir);
        var file = Path.Combine(_storeDir, $"snapshot-{snap.TakenUtc:yyyyMMdd-HHmmss}.json");
        File.WriteAllText(file, JsonSerializer.Serialize(snap));
        return file;
    }

    public MonitorSnapshot? LoadLatest()
    {
        if (!Directory.Exists(_storeDir)) return null;
        var latest = Directory.EnumerateFiles(_storeDir, "snapshot-*.json").OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
        if (latest is null) return null;
        try { return JsonSerializer.Deserialize<MonitorSnapshot>(File.ReadAllText(latest)); }
        catch { return null; }
    }

    public void DeleteAll()
    {
        if (!Directory.Exists(_storeDir)) return;
        foreach (var f in Directory.EnumerateFiles(_storeDir, "snapshot-*.json"))
        {
            try { File.Delete(f); } catch { }
        }
    }
}
