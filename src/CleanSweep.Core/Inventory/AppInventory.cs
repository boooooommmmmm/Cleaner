using System.Diagnostics;
using System.Globalization;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.Inventory;

/// <summary>一次清单扫描的结果，附带各来源的可靠性信息。</summary>
public sealed class InventorySnapshot
{
    public required IReadOnlyList<InstalledApp> Apps { get; init; }
    public required DateTime TakenUtc { get; init; }

    /// <summary>注册表来源读到的条目数。极少（&lt; 5）说明读取失败或环境异常，"未找到卸载项"不能作为已卸载的证据。</summary>
    public int RegistryCount { get; init; }

    /// <summary>UWP 来源读到的包家族数。为 0 时不能据此判定 Packages 目录下的包已卸载。</summary>
    public int UwpCount { get; init; }

    /// <summary>正在运行的进程可执行文件路径（能读到的部分）。</summary>
    public required IReadOnlySet<string> RunningExecutables { get; init; }

    public bool RegistryReliable => RegistryCount >= 5;
    public bool UwpReliable => UwpCount > 0;

    private HashSet<string>? _familyNames;
    private HashSet<string>? _nameKeys;
    private HashSet<string>? _publisherKeys;

    public bool IsPackageFamilyInstalled(string familyName)
    {
        _familyNames ??= Apps.Where(a => a.PackageFamilyName is not null).Select(a => a.PackageFamilyName!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return _familyNames.Contains(familyName);
    }

    /// <summary>有已安装应用的名字与给定名字匹配（归一化前缀匹配）。</summary>
    public InstalledApp? FindByName(string? name)
    {
        var key = NameKey.Normalize(name);
        if (key.Length == 0) return null;
        _nameKeys ??= Apps.Select(a => a.NameKeyValue).Where(k => k.Length > 0).ToHashSet(StringComparer.Ordinal);
        if (_nameKeys.Contains(key)) return Apps.First(a => a.NameKeyValue == key);
        return Apps.FirstOrDefault(a => NameKey.Matches(a.Name, name));
    }

    /// <summary>
    /// 名字是否与某个已安装应用的发布者匹配（厂商目录：Google、JetBrains、Adobe）。
    /// 只接受"目录名等于发布者"或"发布者以目录名开头"（JetBrains ↔ JetBrains s.r.o.），不接受反向前缀：
    /// "UnityHubWebGLHost" 不是厂商 "Unity Technologies" 的目录。
    /// </summary>
    public bool IsPublisher(string? name)
    {
        var key = NameKey.Normalize(name);
        if (key.Length < 4) return false;
        _publisherKeys ??= Apps.Select(a => NameKey.Normalize(a.Publisher)).Where(k => k.Length > 0).ToHashSet(StringComparer.Ordinal);
        return _publisherKeys.Contains(key) || _publisherKeys.Any(p => p.StartsWith(key, StringComparison.Ordinal));
    }

    /// <summary>目录是否位于某个已安装应用的安装位置之内（或包含它）。</summary>
    public InstalledApp? FindByInstallLocation(string directory)
    {
        string full;
        try { full = PathGuard.Normalize(directory); } catch { return null; }
        foreach (var a in Apps)
        {
            if (string.IsNullOrWhiteSpace(a.InstallLocation)) continue;
            string loc;
            try { loc = PathGuard.Normalize(a.InstallLocation.Trim('"')); } catch { continue; }
            if (loc.Length <= 3) continue; // 卷根之类的垃圾值
            if (PathGuard.IsSameOrUnder(full, loc) || PathGuard.IsSameOrUnder(loc, full)) return a;
        }
        return null;
    }

    /// <summary>目录下是否有正在运行的可执行文件。</summary>
    public bool HasRunningProcessUnder(string directory)
    {
        string full;
        try { full = PathGuard.Normalize(directory); } catch { return false; }
        return RunningExecutables.Any(p => PathGuard.IsSameOrUnder(p, full));
    }
}

/// <summary>
/// App Inventory（设计文档 7.2）：维护已安装软件清单。来源：注册表 Uninstall 键（HKLM 64 / 32 位、HKCU）、
/// 应用商店包仓库、便携软件目录、正在运行的进程。只读，不修改任何东西。
/// </summary>
public sealed class AppInventory
{
    private static readonly string[] UninstallKeys =
    {
        @"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    };

    private const string UwpRepository = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    private const string UwpAllUsers = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications";

    private readonly IEnvironmentResolver _env;
    private InventorySnapshot? _last;

    public AppInventory(IEnvironmentResolver env)
    {
        _env = env;
    }

    /// <summary>最近一次扫描结果；从未扫描时为 null。</summary>
    public InventorySnapshot? Last => _last;

    /// <summary>注入一份快照（测试，或提权服务从客户端接收的清单）。</summary>
    public void UseSnapshot(InventorySnapshot snapshot) => _last = snapshot;

    /// <summary>扫描时可选回调，用于记录单个来源的失败（不中断扫描）。</summary>
    public Action<string, Exception>? OnSourceError { get; set; }

    public InventorySnapshot Scan(CancellationToken ct = default)
    {
        var apps = new List<InstalledApp>();
        int registryCount = 0;

        foreach (var key in UninstallKeys)
        {
            foreach (var view in key.StartsWith("HKLM") ? new[] { RegistryView.Registry64, RegistryView.Registry32 } : new[] { RegistryView.Registry64 })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var list = ScanUninstallKey(key, view).ToList();
                    registryCount += list.Count;
                    apps.AddRange(list);
                }
                catch (Exception ex)
                {
                    OnSourceError?.Invoke($"{key} ({view})", ex);
                }
            }
        }

        var uwp = new List<InstalledApp>();
        try { uwp.AddRange(ScanUwp()); }
        catch (Exception ex) { OnSourceError?.Invoke("uwp", ex); }
        apps.AddRange(uwp);

        try { apps.AddRange(ScanPortable(apps, ct)); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { OnSourceError?.Invoke("portable", ex); }

        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { foreach (var p in RunningExecutables()) running.Add(p); }
        catch (Exception ex) { OnSourceError?.Invoke("processes", ex); }

        // 同一应用可能在 64 位与 32 位视图各有一条（同一子键名）：按 Id 去重
        var distinct = apps.GroupBy(a => a.Id, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();

        _last = new InventorySnapshot
        {
            Apps = distinct,
            TakenUtc = DateTime.UtcNow,
            RegistryCount = registryCount,
            UwpCount = uwp.Select(u => u.PackageFamilyName).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            RunningExecutables = running,
        };
        return _last;
    }

    // ---------- 注册表 ----------

    private static IEnumerable<InstalledApp> ScanUninstallKey(string keyPath, RegistryView view)
    {
        using var root = RegistryPath.Open(keyPath, view, writable: false);
        if (root is null) yield break;

        foreach (var sub in root.GetSubKeyNames())
        {
            InstalledApp? app = null;
            try
            {
                using var k = root.OpenSubKey(sub);
                if (k is null) continue;
                var name = (k.GetValue("DisplayName") as string)?.Trim();
                if (string.IsNullOrEmpty(name)) continue;
                // 补丁 / 更新条目
                if (k.GetValue("ParentKeyName") is string parent && parent.Length > 0) continue;
                if (k.GetValue("ReleaseType") is string rt && (rt.Contains("Update", StringComparison.OrdinalIgnoreCase) || rt.Contains("Hotfix", StringComparison.OrdinalIgnoreCase))) continue;

                var publisher = (k.GetValue("Publisher") as string)?.Trim();
                var fullKey = RegistryPath.Combine(keyPath, sub);
                app = new InstalledApp
                {
                    Id = "reg:" + (view == RegistryView.Registry32 ? "32:" : "") + fullKey.ToLowerInvariant(),
                    Name = name,
                    Publisher = publisher,
                    Version = (k.GetValue("DisplayVersion") as string)?.Trim(),
                    InstallLocation = (k.GetValue("InstallLocation") as string)?.Trim(),
                    UninstallString = (k.GetValue("UninstallString", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string)?.Trim(),
                    QuietUninstallString = (k.GetValue("QuietUninstallString", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string)?.Trim(),
                    Source = AppSource.Registry,
                    RegistryKey = fullKey,
                    View = view,
                    IsSystemComponent = k.GetValue("SystemComponent") is int sc && sc == 1,
                    IsWindowsInstaller = k.GetValue("WindowsInstaller") is int wi && wi == 1,
                    InstallDate = ParseInstallDate(k.GetValue("InstallDate") as string),
                    EstimatedSizeBytes = k.GetValue("EstimatedSize") is int kb && kb > 0 ? (long)kb * 1024 : 0,
                    DisplayIcon = (k.GetValue("DisplayIcon") as string)?.Trim(),
                    IsMicrosoft = publisher is not null && publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase),
                };
            }
            catch
            {
                // 单个子键读不了（权限、损坏）跳过
            }
            if (app is not null) yield return app;
        }
    }

    internal static DateTime? ParseInstallDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (DateTime.TryParseExact(s, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var d)) return d;
        if (DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out d)) return d;
        return null;
    }

    // ---------- UWP ----------

    private static IEnumerable<InstalledApp> ScanUwp()
    {
        var results = new List<InstalledApp>();
        foreach (var (keyPath, scopeAll) in new[] { (UwpRepository, false), (UwpAllUsers, true) })
        {
            RegistryKey? root;
            try { root = RegistryPath.Open(keyPath, RegistryView.Registry64, writable: false); }
            catch { continue; }
            if (root is null) continue;
            using (root)
            {
                foreach (var full in root.GetSubKeyNames())
                {
                    try
                    {
                        var family = ToFamilyName(full);
                        if (family is null) continue;
                        string? display = null;
                        if (!scopeAll)
                        {
                            using var sub = root.OpenSubKey(full);
                            display = sub?.GetValue("DisplayName") as string;
                        }
                        var parts = full.Split('_');
                        var packageName = parts[0];
                        if (string.IsNullOrEmpty(display) || display.StartsWith('@')) display = packageName;
                        var publisherId = parts[^1];
                        var isMs = packageName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
                                   || packageName.StartsWith("MicrosoftWindows.", StringComparison.OrdinalIgnoreCase)
                                   || publisherId.Equals("8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase)
                                   || publisherId.Equals("cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase);
                        results.Add(new InstalledApp
                        {
                            Id = "uwp:" + family.ToLowerInvariant(),
                            Name = display,
                            Publisher = isMs ? "Microsoft Corporation" : PublisherFromPackageName(packageName),
                            Version = parts.Length >= 2 ? parts[1] : null,
                            Source = AppSource.Uwp,
                            PackageFullName = full,
                            PackageFamilyName = family,
                            IsMicrosoft = isMs,
                            // 系统自带包（Windows 组件）不可卸载；cw5n1h2txyewy 是系统应用的发布者 ID（含以 GUID 命名的内置包）
                            IsSystemComponent = publisherId.Equals("cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.Windows.", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("MicrosoftWindows.", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.UI.", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.NET.", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.VCLibs", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.WindowsAppRuntime", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.DirectX", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.Services.Store", StringComparison.OrdinalIgnoreCase)
                                                || packageName.StartsWith("Microsoft.Advertising", StringComparison.OrdinalIgnoreCase)
                                                || packageName.Equals("Microsoft.WindowsStore", StringComparison.OrdinalIgnoreCase),
                        });
                    }
                    catch
                    {
                    }
                }
            }
        }
        // 同一家族多个版本 / 架构：保留一条
        return results.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).Select(g => g.First());
    }

    /// <summary>Name_Version_Arch_ResourceId_PublisherId → Name_PublisherId。</summary>
    internal static string? ToFamilyName(string packageFullName)
    {
        var parts = packageFullName.Split('_');
        return parts.Length >= 2 ? parts[0] + "_" + parts[^1] : null;
    }

    /// <summary>"SpotifyAB.SpotifyMusic" → "SpotifyAB"。</summary>
    internal static string? PublisherFromPackageName(string packageName)
    {
        var idx = packageName.IndexOf('.');
        return idx > 0 ? packageName[..idx] : null;
    }

    // ---------- 便携软件 ----------

    private IEnumerable<InstalledApp> ScanPortable(IReadOnlyList<InstalledApp> known, CancellationToken ct)
    {
        var roots = new List<string>();
        if (_env.Variables.TryGetValue("LocalAppData", out var local)) roots.Add(Path.Combine(local, "Programs"));
        if (_env.Variables.TryGetValue("UserProfile", out var profile))
        {
            roots.Add(Path.Combine(profile, "scoop", "apps"));
            roots.Add(Path.Combine(profile, "AppData", "Local", "Microsoft", "WinGet", "Packages"));
        }

        var results = new List<InstalledApp>();
        foreach (var root in roots.Where(Directory.Exists))
        {
            IEnumerable<string> dirs;
            try { dirs = Directory.EnumerateDirectories(root); } catch { continue; }
            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (PathGuard.IsReparsePoint(dir)) continue;
                    // 已有注册表卸载项指向这里的不重复登记
                    if (known.Any(a => !string.IsNullOrEmpty(a.InstallLocation) && SafeSameOrUnder(dir, a.InstallLocation))) continue;

                    var exe = FindMainExecutable(dir);
                    if (exe is null) continue;
                    var info = ReadVersionInfo(exe);
                    var name = info.Product ?? Path.GetFileName(dir);
                    results.Add(new InstalledApp
                    {
                        Id = "portable:" + PathGuard.Normalize(dir).ToLowerInvariant(),
                        Name = name,
                        Publisher = info.Company,
                        Version = info.Version,
                        InstallLocation = dir,
                        Source = AppSource.Portable,
                        IsMicrosoft = info.Company?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) == true,
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
        return results;
    }

    private static bool SafeSameOrUnder(string child, string parent)
    {
        try { return PathGuard.IsSameOrUnder(PathGuard.Normalize(child), PathGuard.Normalize(parent.Trim('"'))); }
        catch { return false; }
    }

    /// <summary>目录（最多两层）里最大的 exe。</summary>
    internal static string? FindMainExecutable(string dir)
    {
        var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false };
        string? best = null;
        long bestLen = -1;
        void Look(string d)
        {
            IEnumerable<FileInfo> files;
            try { files = new DirectoryInfo(d).EnumerateFiles("*.exe", opts); } catch { return; }
            foreach (var f in files)
            {
                var n = f.Name.ToLowerInvariant();
                if (n.Contains("unins") || n.Contains("setup") || n.Contains("update") || n.Contains("crash")) continue;
                long len;
                try { len = f.Length; } catch { continue; }
                if (len > bestLen) { bestLen = len; best = f.FullName; }
            }
        }
        Look(dir);
        if (best is null)
        {
            IEnumerable<string> subs;
            try { subs = Directory.EnumerateDirectories(dir).Take(20); } catch { return null; }
            foreach (var s in subs)
            {
                if (PathGuard.IsReparsePoint(s)) continue;
                Look(s);
            }
        }
        return best;
    }

    internal static (string? Product, string? Company, string? Version) ReadVersionInfo(string exe)
    {
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(exe);
            static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
            return (Clean(vi.ProductName), Clean(vi.CompanyName), Clean(vi.ProductVersion) ?? Clean(vi.FileVersion));
        }
        catch
        {
            return (null, null, null);
        }
    }

    // ---------- 进程 ----------

    private static IEnumerable<string> RunningExecutables()
    {
        Process[] processes;
        try { processes = Process.GetProcesses(); } catch { yield break; }
        foreach (var p in processes)
        {
            string? path = null;
            try { path = p.MainModule?.FileName; }
            catch { /* 其他用户 / 受保护进程读不到 */ }
            finally { p.Dispose(); }
            if (!string.IsNullOrEmpty(path)) yield return path;
        }
    }
}
