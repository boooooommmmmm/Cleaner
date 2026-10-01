using CleanSweep.Core.Backup;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Uninstall;
using Microsoft.Win32;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>扫描范围，可被测试替换成 HKCU\Software\CleanSweepTests 下的假键。</summary>
public sealed class RegistryCleanerOptions
{
    public List<(string Key, RegistryView View)> UninstallKeys { get; set; } = new()
    {
        (@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Registry64),
        (@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Registry32),
        (@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Registry64),
    };

    public List<(string Key, RegistryView View)> MuiCacheKeys { get; set; } = new()
    {
        (@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", RegistryView.Registry64),
    };

    public List<(string Key, RegistryView View)> AppPathsKeys { get; set; } = new()
    {
        (@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths", RegistryView.Registry64),
        (@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths", RegistryView.Registry32),
        (@"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths", RegistryView.Registry64),
    };

    public List<(string Key, RegistryView View)> SoftwareRoots { get; set; } = new()
    {
        (@"HKCU\Software", RegistryView.Registry64),
        (@"HKLM\Software", RegistryView.Registry64),
        (@"HKLM\Software", RegistryView.Registry32),
    };

    public List<(string Key, RegistryView View)> ClassesRoots { get; set; } = new()
    {
        (@"HKCU\Software\Classes", RegistryView.Registry64),
        (@"HKLM\Software\Classes", RegistryView.Registry64),
        (@"HKLM\Software\Classes", RegistryView.Registry32),
    };

    public (string Key, RegistryView View) SharedDllsKey { get; set; } = (@"HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs", RegistryView.Registry64);

    public string ServicesKey { get; set; } = @"HKLM\SYSTEM\CurrentControlSet\Services";

    public bool IncludeServices { get; set; } = true;
    public bool IncludeTasks { get; set; } = true;
    public bool IncludeShortcuts { get; set; } = true;
    public bool IncludeCom { get; set; } = true;
    public bool IncludeSharedDlls { get; set; } = true;

    /// <summary>快捷方式目录；null 表示按环境变量取开始菜单与桌面。</summary>
    public List<string>? ShortcutFolders { get; set; }
}

/// <summary>
/// 注册表与僵尸配置清理（设计文档 3.4）。定位是移除已卸载软件的残留配置，不是提速。
/// 安全级：无效卸载项、失效快捷方式、MUI 缓存孤儿；建议确认：已卸载软件的 Software 键、失效文件关联与 App Paths、
/// 指向不存在文件的服务与计划任务；高风险：失效 COM 注册、失效共享 DLL 计数。
/// 文件是否存在一律经 <see cref="RegistryProbe"/>（Unknown 放过），Windows 目录下缺文件不算垃圾。
/// </summary>
public sealed class RegistryCleanerScanner : IScanner
{
    public const string ModuleId = "registry";

    private static readonly HashSet<string> SystemProgIdPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.", "Windows.", "AppX", "ms-", "MSEdge", "IE.", "Excel.", "Word.", "PowerPoint.", "Outlook.", "Access.", "Visio.", "Publisher.", "OneNote.",
        "WMP", "CLSID", "Interface", "TypeLib", "Wow6432Node", "Local Settings", "Applications", "SystemFileAssociations", "Directory", "Drive", "Folder",
        "AllFilesystemObjects", "Unknown", "exefile", "lnkfile", "batfile", "cmdfile", "dllfile", "regfile", "txtfile", "inffile", "htmlfile", "xmlfile",
        "PROTOCOLS", "MIME", "Installer", "AppID", "Record", "Extensions", "AppUserModelId", "ActivatableClasses", "PackagedCom", "DesktopBackground",
        "LibraryFolder", "Network", "Printers", "UserLibraryFolder", "VirtualStore", "WOW6432Node", "*", "Software",
    };

    private static readonly HashSet<string> ProtectedVendorKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Classes", "Policies", "Clients", "RegisteredApplications", "WOW6432Node", "Wow6432Node", "ODBC", "Intel", "AMD", "NVIDIA Corporation",
        "Realtek", "Khronos", "Google", "Mozilla", "JavaSoft", "Oracle", "Dell", "HP", "Lenovo", "ASUS", "Synaptics", "ELAN", "Conexant", "Macromedia",
        "Adobe", "Apple Inc.", "Apple Computer, Inc.", "DefaultUserEnvironment", "Description", "Setup", "7-Zip", "SimonTatham", "Valve", "Chromium",
        "Cygwin", "Python", "PythonCore", "Docker Inc.", "GitForWindows", "Kitware", "OpenSSH", "Npcap", "WinPcap", "Wireshark", "VMware, Inc.", "Oracle",
    };

    private static readonly string[] PathValueHints = { "path", "dir", "location", "folder", "exe", "install", "home", "root" };

    private readonly AppInventory _inventory;
    private readonly UninstallHistory? _history;
    private readonly RegistryCleanerOptions _options;
    private readonly Action<string, string>? _log;

    public RegistryCleanerScanner(AppInventory inventory, UninstallHistory? history, RegistryCleanerOptions? options = null, Action<string, string>? log = null)
    {
        _inventory = inventory;
        _history = history;
        _options = options ?? new RegistryCleanerOptions();
        _log = log;
    }

    public string Id => ModuleId;
    public string DisplayName => "注册表清理";

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run(() => Scan(ctx, progress, ct), ct);

    private IReadOnlyList<ScanItem> Scan(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var inv = _inventory.Last is { } last && (DateTime.UtcNow - last.TakenUtc) < TimeSpan.FromMinutes(2) ? last : _inventory.Scan(ct);
        var history = _history?.List(500) ?? Array.Empty<UninstallRecord>();
        var items = new List<ScanItem>();

        void Run(string source, Action scan)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgress(Id, source, items.Count, 0));
            try { scan(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { _log?.Invoke(source, ex.Message); }
        }

        Run("uninstall", () => ScanUninstallEntries(items, ct));
        Run("muicache", () => ScanMuiCache(items, ct));
        Run("apppaths", () => ScanAppPaths(items, ct));
        Run("software", () => ScanOrphanSoftwareKeys(items, inv, history, ct));
        Run("classes", () => ScanFileAssociations(items, ct));
        if (_options.IncludeServices) Run("services", () => ScanServices(items, ct));
        if (_options.IncludeTasks) Run("tasks", () => ScanTasks(items, ct));
        if (_options.IncludeCom) Run("com", () => ScanCom(items, ct));
        if (_options.IncludeSharedDlls) Run("shareddlls", () => ScanSharedDlls(items, ct));
        if (_options.IncludeShortcuts) Run("shortcuts", () => ScanShortcuts(ctx, items, ct));

        var unique = items.DistinctBy(RegistryScanIdentity.ForItem).ToArray();
        progress?.Report(new ScanProgress(Id, null, unique.Length, 0));
        return unique;
    }

    private static string MakeId(params string[] parts) => RuleScanner.MakeId(new[] { ModuleId }.Concat(parts).ToArray());

    private static ScanItem KeyItem(string group, string display, string description, RiskLevel risk, string keyPath, RegistryView view, string? missing = null) => new()
    {
        Id = MakeId("key", view.ToString(), keyPath),
        ModuleId = ModuleId,
        Group = group,
        DisplayName = display,
        Kind = ItemKind.RegistryKey,
        Path = keyPath + (view == RegistryView.Registry32 ? "（32 位视图）" : ""),
        Registry = new RegistryTarget(keyPath, view, null),
        TargetSnapshot = RegistrySnapshot.OfKey(keyPath, view),
        MissingPath = missing,
        Risk = risk,
        Description = description,
    };

    private static ScanItem ValueItem(string group, string display, string description, RiskLevel risk, string keyPath, RegistryView view, string valueName, string? missing = null) => new()
    {
        Id = MakeId("value", view.ToString(), keyPath, valueName),
        ModuleId = ModuleId,
        Group = group,
        DisplayName = display,
        Kind = ItemKind.RegistryValue,
        Path = keyPath + "\\" + valueName,
        Registry = new RegistryTarget(keyPath, view, valueName),
        TargetSnapshot = RegistrySnapshot.OfValue(keyPath, view, valueName),
        MissingPath = missing,
        Risk = risk,
        Description = description,
    };

    // ---------- 无效卸载项（安全） ----------

    private void ScanUninstallEntries(List<ScanItem> items, CancellationToken ct)
    {
        foreach (var (key, view) in _options.UninstallKeys)
        {
            using var root = RegistryPath.Open(key, view, writable: false);
            if (root is null) continue;
            foreach (var sub in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var k = root.OpenSubKey(sub);
                    if (k is null) continue;
                    var name = (k.GetValue("DisplayName") as string)?.Trim();
                    if (string.IsNullOrEmpty(name)) continue;
                    if (k.GetValue("WindowsInstaller") is int wi && wi == 1) continue; // MSI 由 Windows Installer 管理
                    if (k.GetValue("ParentKeyName") is string) continue;
                    var uninstall = k.GetValue("UninstallString", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    if (string.IsNullOrWhiteSpace(uninstall)) continue;
                    if (uninstall.Contains("msiexec", StringComparison.OrdinalIgnoreCase)) continue;

                    var exe = RegistryProbe.ExtractPath(uninstall);
                    if (exe is null || RegistryProbe.ProbePath(exe) != FileProbe.Missing) continue;

                    var location = k.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrWhiteSpace(location))
                    {
                        var loc = RegistryProbe.ExtractPath(location, isCommandLine: false);
                        if (loc is not null && RegistryProbe.ProbePath(loc) == FileProbe.Exists) continue; // 安装目录还在：可能只是卸载程序被删，保守放过
                    }

                    var keyPath = RegistryPath.Combine(key, sub);
                    items.Add(KeyItem("无效的卸载项", name,
                        $"卸载程序 {exe} 已不存在，“应用和功能”里这一项无法卸载也无法修复。删除前会导出该键为 .reg 备份", RiskLevel.Safe, keyPath, view, exe));
                }
                catch (Exception ex)
                {
                    _log?.Invoke("uninstall " + sub, ex.Message);
                }
            }
        }
    }

    // ---------- MUI 缓存（安全） ----------

    private void ScanMuiCache(List<ScanItem> items, CancellationToken ct)
    {
        foreach (var (key, view) in _options.MuiCacheKeys)
        {
            using var k = RegistryPath.Open(key, view, writable: false);
            if (k is null) continue;
            foreach (var valueName in k.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(valueName) || valueName.Equals("LangID", StringComparison.OrdinalIgnoreCase)) continue;
                // "C:\x\app.exe.FriendlyAppName" / ".ApplicationCompany"
                var dot = valueName.LastIndexOf('.');
                if (dot <= 0) continue;
                var path = valueName[..dot];
                if (!Path.IsPathRooted(path)) continue;
                if (RegistryProbe.IsUnderWindows(path)) continue;
                if (RegistryProbe.ProbePath(path) != FileProbe.Missing) continue;
                items.Add(ValueItem("MUI 缓存中不存在的程序", Path.GetFileName(path),
                    $"{path} 已不存在，这是资源管理器缓存的它的显示名称 / 公司名。删除前做值级备份", RiskLevel.Safe, key, view, valueName, path));
            }
        }
    }

    // ---------- App Paths（建议确认） ----------

    private void ScanAppPaths(List<ScanItem> items, CancellationToken ct)
    {
        foreach (var (key, view) in _options.AppPathsKeys)
        {
            using var root = RegistryPath.Open(key, view, writable: false);
            if (root is null) continue;
            foreach (var sub in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var k = root.OpenSubKey(sub);
                    var target = k?.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    var exe = RegistryProbe.ExtractPath(target, isCommandLine: false);
                    if (exe is null || RegistryProbe.IsUnderWindows(exe) || RegistryProbe.ProbePath(exe) != FileProbe.Missing) continue;
                    items.Add(KeyItem("失效的应用路径（App Paths）", sub, $"“运行”对话框与 ShellExecute 用它把 {sub} 解析到 {exe}，该文件已不存在", RiskLevel.Confirm,
                        RegistryPath.Combine(key, sub), view, exe));
                }
                catch (Exception ex)
                {
                    _log?.Invoke("apppaths " + sub, ex.Message);
                }
            }
        }
    }

    // ---------- 已卸载软件遗留的 Software 键（建议确认） ----------

    private void ScanOrphanSoftwareKeys(List<ScanItem> items, InventorySnapshot inv, IReadOnlyList<UninstallRecord> history, CancellationToken ct)
    {
        foreach (var (rootPath, view) in _options.SoftwareRoots)
        {
            using var root = RegistryPath.Open(rootPath, view, writable: false);
            if (root is null) continue;
            foreach (var vendor in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (ProtectedVendorKeys.Contains(vendor)) continue;
                var vendorPath = RegistryPath.Combine(rootPath, vendor);
                if (RegistryGuard.CheckDeleteKey(vendorPath, view) is not null) continue;

                try
                {
                    using var vk = root.OpenSubKey(vendor);
                    if (vk is null) continue;
                    // 目录名对得上已安装应用或其发布者：活跃
                    if (inv.FindByName(vendor) is not null || inv.IsPublisher(vendor)) continue;
                    var children = vk.GetSubKeyNames();
                    if (children.Any(c => inv.FindByName(c) is not null)) continue;

                    // 证据 1：卸载记录
                    var rec = _history?.FindByName(vendor, history) ?? children.Select(c => _history?.FindByName(c, history)).FirstOrDefault(r => r is not null);
                    if (rec is not null)
                    {
                        items.Add(KeyItem("已卸载软件遗留的注册表键", vendor,
                            $"“{rec.Name}”已于 {rec.TsUtc.ToLocalTime():yyyy-MM-dd} 卸载（卸载记录），这是它在 {rootPath} 下遗留的配置。删除前导出整键备份", RiskLevel.Confirm, vendorPath, view));
                        continue;
                    }

                    // 证据 2：键里记录的安装路径已不存在。证据来自某个产品子键时只针对该子键（厂商键下可能还有别的产品）
                    var missing = FindMissingPathValue(vk, depth: 2);
                    if (missing is not null)
                    {
                        var targetPath = vendorPath;
                        var display = vendor;
                        var firstSeg = missing.Value.ValueName.Split('\\')[0];
                        if (missing.Value.ValueName.Contains('\\') && children.Length > 1 && children.Contains(firstSeg, StringComparer.OrdinalIgnoreCase))
                        {
                            targetPath = RegistryPath.Combine(vendorPath, firstSeg);
                            display = vendor + "\\" + firstSeg;
                            if (RegistryGuard.CheckDeleteKey(targetPath, view) is not null) continue;
                        }
                        items.Add(KeyItem("已卸载软件遗留的注册表键", display,
                            $"键中的 {missing.Value.ValueName} 指向 {missing.Value.Path}，该位置已不存在，且系统中没有对应的已安装应用。删除前导出整键备份", RiskLevel.Confirm, targetPath, view, missing.Value.Path));
                    }
                }
                catch (Exception ex)
                {
                    _log?.Invoke("software " + vendor, ex.Message);
                }
            }
        }
    }

    private static (string ValueName, string Path)? FindMissingPathValue(RegistryKey key, int depth)
    {
        foreach (var name in key.GetValueNames())
        {
            var lower = name.ToLowerInvariant();
            if (!PathValueHints.Any(lower.Contains)) continue;
            if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string s) continue;
            // 值名含 cmd / command / exe 的是命令行，其余（Path、Dir、Location…）是纯路径
            var isCommand = lower.Contains("cmd") || lower.Contains("command") || lower.Contains("exe");
            var path = RegistryProbe.ExtractPath(s, isCommandLine: isCommand);
            if (path is null || RegistryProbe.IsUnderWindows(path)) continue;
            // 卷根、只有一层的路径（D:\Games）不算证据：太容易被用户自己移动
            if (path.Count(c => c == '\\') < 2) continue;
            if (RegistryProbe.ProbePath(path) == FileProbe.Missing) return (name, path);
        }
        if (depth <= 0) return null;
        foreach (var sub in key.GetSubKeyNames().Take(30))
        {
            try
            {
                using var k = key.OpenSubKey(sub);
                if (k is null) continue;
                var r = FindMissingPathValue(k, depth - 1);
                if (r is not null) return (sub + "\\" + r.Value.ValueName, r.Value.Path);
            }
            catch { }
        }
        return null;
    }

    // ---------- 文件关联（建议确认） ----------

    private void ScanFileAssociations(List<ScanItem> items, CancellationToken ct)
    {
        foreach (var (rootPath, view) in _options.ClassesRoots)
        {
            using var root = RegistryPath.Open(rootPath, view, writable: false);
            if (root is null) continue;
            foreach (var sub in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (sub.StartsWith('.'))
                    {
                        // .ext → ProgID 不存在
                        using var ek = root.OpenSubKey(sub);
                        var progId = ek?.GetValue(null) as string;
                        if (string.IsNullOrWhiteSpace(progId) || progId.Contains('\\')) continue;
                        if (RegistryDetect.KeyExists(@"HKCR\" + progId) || RegistryDetect.KeyExists(@"HKCU\Software\Classes\" + progId) || RegistryDetect.KeyExists(@"HKLM\Software\Classes\" + progId)) continue;
                        // 扩展名键自身还带 OpenWithProgids / ShellNew 等子键时只提示不删
                        if (ek!.SubKeyCount > 0 || ek.ValueCount > 1) continue;
                        items.Add(KeyItem("失效的文件关联", sub, $"扩展名 {sub} 关联到不存在的类型 {progId}。删除后该扩展名退回系统默认处理", RiskLevel.Confirm, RegistryPath.Combine(rootPath, sub), view));
                        continue;
                    }

                    if (SystemProgIdPrefixes.Any(p => sub.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                    var command = ReadDefault(root, sub + @"\shell\open\command");
                    if (command is null) continue;
                    var exe = RegistryProbe.ExtractPath(command);
                    if (exe is null || RegistryProbe.IsUnderWindows(exe) || RegistryProbe.ProbePath(exe) != FileProbe.Missing) continue;
                    items.Add(KeyItem("失效的文件关联", sub, $"文件类型 {sub} 的打开命令指向 {exe}，该程序已不存在", RiskLevel.Confirm, RegistryPath.Combine(rootPath, sub), view, exe));
                }
                catch (Exception ex)
                {
                    _log?.Invoke("classes " + sub, ex.Message);
                }
            }

            // Applications\foo.exe（"打开方式"列表）
            try
            {
                using var apps = root.OpenSubKey("Applications");
                if (apps is not null)
                {
                    foreach (var app in apps.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var command = ReadDefault(apps, app + @"\shell\open\command");
                        if (command is null) continue;
                        var exe = RegistryProbe.ExtractPath(command);
                        if (exe is null || RegistryProbe.IsUnderWindows(exe) || RegistryProbe.ProbePath(exe) != FileProbe.Missing) continue;
                        items.Add(KeyItem("失效的“打开方式”程序", app, $"“打开方式”列表里的 {app} 指向 {exe}，该程序已不存在", RiskLevel.Confirm,
                            RegistryPath.Combine(rootPath, "Applications\\" + app), view, exe));
                    }
                }
            }
            catch (Exception ex)
            {
                _log?.Invoke("classes Applications", ex.Message);
            }
        }
    }

    private static string? ReadDefault(RegistryKey root, string relative)
    {
        try
        {
            using var k = root.OpenSubKey(relative);
            return k?.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }
        catch
        {
            return null;
        }
    }

    // ---------- 服务（建议确认） ----------

    private void ScanServices(List<ScanItem> items, CancellationToken ct)
    {
        using var root = RegistryPath.Open(_options.ServicesKey, RegistryView.Registry64, writable: false);
        if (root is null) return;
        foreach (var name in root.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var k = root.OpenSubKey(name);
                if (k is null) continue;
                var type = k.GetValue("Type") as int? ?? 0;
                if ((type & 0x30) == 0) continue; // 只看用户态服务
                var start = k.GetValue("Start") as int? ?? 0;
                if (start is 0 or 1) continue;
                var image = k.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if (string.IsNullOrWhiteSpace(image)) continue;

                var normalized = CommandLine.NormalizeNtPrefix(System.Environment.ExpandEnvironmentVariables(image), null);
                var (exe, args) = CommandLine.Split(normalized);
                if (exe is null) continue;
                string? missing = null;
                if (Path.GetFileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    using var pk = k.OpenSubKey("Parameters");
                    var dll = pk?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    var dllPath = RegistryProbe.ExtractPath(dll);
                    if (dllPath is not null && !RegistryProbe.IsUnderWindows(dllPath) && RegistryProbe.ProbePath(dllPath) == FileProbe.Missing) missing = dllPath;
                }
                else
                {
                    var exePath = RegistryProbe.ExtractPath(exe, isCommandLine: false);
                    if (exePath is not null && !RegistryProbe.IsUnderWindows(exePath) && RegistryProbe.ProbePath(exePath) == FileProbe.Missing) missing = exePath;
                }
                if (missing is null) continue;

                var display = k.GetValue("DisplayName") as string;
                if (display is null || display.StartsWith('@')) display = name;
                items.Add(new ScanItem
                {
                    Id = MakeId("service", name),
                    ModuleId = ModuleId,
                    Group = "指向不存在程序的服务",
                    DisplayName = display,
                    Kind = ItemKind.Service,
                    Path = RegistryPath.Combine(_options.ServicesKey, name),
                    ServiceName = name,
                    MissingPath = missing,
                    TargetSnapshot = RegistrySnapshot.OfServiceKey(RegistryPath.Combine(_options.ServicesKey, name)),
                    Risk = RiskLevel.Confirm,
                    Description = $"服务 {name} 的程序 {missing} 已不存在，它永远无法启动。删除前导出服务键备份；驱动与 Boot / System 级服务不在此列",
                });
            }
            catch (Exception ex)
            {
                _log?.Invoke("service " + name, ex.Message);
            }
        }
    }

    private static string Quote(string s) => s.Contains(' ') && !s.StartsWith('"') ? "\"" + s + "\"" : s;

    private static string? SnapshotOfTask(dynamic task)
    {
        try
        {
            string xml = task.Xml;
            return RegistrySnapshot.OfTaskXml(xml);
        }
        catch
        {
            return null;
        }
    }

    // ---------- 计划任务（建议确认） ----------

    private void ScanTasks(List<ScanItem> items, CancellationToken ct)
    {
        var t = Type.GetTypeFromProgID("Schedule.Service");
        if (t is null) return;
        dynamic svc = Activator.CreateInstance(t)!;
        svc.Connect();
        var folders = new Stack<dynamic>();
        folders.Push(svc.GetFolder("\\"));
        while (folders.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            dynamic folder = folders.Pop();
            string folderPath = folder.Path;
            if (folderPath.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase)) continue;

            dynamic subs = folder.GetFolders(0);
            for (int i = 1; i <= (int)subs.Count; i++) folders.Push(subs.Item(i));

            dynamic tasks = folder.GetTasks(1);
            for (int i = 1; i <= (int)tasks.Count; i++)
            {
                dynamic task = tasks.Item(i);
                string path;
                try { path = task.Path; } catch { continue; }
                if (path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    dynamic actions = task.Definition.Actions;
                    // 只有任务的每一个可执行动作都指向不存在的程序、且没有其他类型的动作（COM、邮件、消息）时才建议整项删除：
                    // 一个动作失效而其他动作仍有效的任务，删除整项会丢掉仍在工作的部分
                    string? missing = null;
                    int execCount = 0, missingCount = 0;
                    bool otherActions = false;
                    for (int a = 1; a <= (int)actions.Count; a++)
                    {
                        dynamic action = actions.Item(a);
                        if ((int)action.Type != 0) { otherActions = true; continue; }
                        execCount++;
                        string exe = action.Path;
                        var exePath = RegistryProbe.ExtractPath(exe, isCommandLine: false);
                        if (exePath is not null && !RegistryProbe.IsUnderWindows(exePath) && RegistryProbe.ProbePath(exePath) == FileProbe.Missing)
                        {
                            missingCount++;
                            missing ??= exePath;
                        }
                    }
                    if (missing is null || execCount == 0 || missingCount != execCount || otherActions) continue;
                    string name = task.Name;
                    items.Add(new ScanItem
                    {
                        Id = MakeId("task", path),
                        ModuleId = ModuleId,
                        Group = "指向不存在程序的计划任务",
                        DisplayName = name,
                        Kind = ItemKind.ScheduledTask,
                        Path = path,
                        TaskPath = path,
                        MissingPath = missing,
                        TargetSnapshot = SnapshotOfTask(task),
                        Risk = RiskLevel.Confirm,
                        Description = $"任务 {path} 要运行的 {missing} 已不存在。删除前把任务定义 XML 存到备份目录",
                    });
                }
                catch (Exception ex)
                {
                    _log?.Invoke("task " + path, ex.Message);
                }
            }
        }
    }

    // ---------- COM（高风险） ----------

    private void ScanCom(List<ScanItem> items, CancellationToken ct)
    {
        foreach (var (rootPath, view) in _options.ClassesRoots)
        {
            using var clsid = RegistryPath.Open(RegistryPath.Combine(rootPath, "CLSID"), view, writable: false);
            if (clsid is null) continue;
            foreach (var guid in clsid.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var inproc = ReadDefault(clsid, guid + @"\InprocServer32");
                    var server = inproc ?? ReadDefault(clsid, guid + @"\LocalServer32");
                    if (server is null) continue;
                    var path = RegistryProbe.ExtractPath(server, isCommandLine: inproc is null);
                    if (path is null || RegistryProbe.IsUnderWindows(path) || RegistryProbe.ProbePath(path) != FileProbe.Missing) continue;
                    var name = ReadDefault(clsid, guid) ?? guid;
                    items.Add(KeyItem("失效的 COM / ActiveX 注册", name,
                        $"CLSID {guid} 的服务器 {path} 已不存在。误删仍在使用的注册会让依赖它的程序报错，删除前导出整键备份", RiskLevel.High,
                        RegistryPath.Combine(rootPath, "CLSID\\" + guid), view, path));
                }
                catch (Exception ex)
                {
                    _log?.Invoke("clsid " + guid, ex.Message);
                }
            }
        }
    }

    // ---------- 共享 DLL（高风险） ----------

    private void ScanSharedDlls(List<ScanItem> items, CancellationToken ct)
    {
        var (key, view) = _options.SharedDllsKey;
        using var k = RegistryPath.Open(key, view, writable: false);
        if (k is null) return;
        foreach (var valueName in k.GetValueNames())
        {
            ct.ThrowIfCancellationRequested();
            if (!Path.IsPathRooted(valueName) || RegistryProbe.IsUnderWindows(valueName)) continue;
            if (RegistryProbe.ProbePath(valueName) != FileProbe.Missing) continue;
            items.Add(ValueItem("失效的共享 DLL 计数", Path.GetFileName(valueName),
                $"{valueName} 已不存在。此计数供 MSI 卸载时判断能否删除共享文件，删除可能影响其他程序的修复 / 卸载流程", RiskLevel.High, key, view, valueName, valueName));
        }
    }

    // ---------- 失效快捷方式（安全，走隔离区） ----------

    private void ScanShortcuts(ScanContext ctx, List<ScanItem> items, CancellationToken ct)
    {
        var folders = _options.ShortcutFolders ?? DefaultShortcutFolders(ctx);
        foreach (var folder in folders)
        {
            if (!Directory.Exists(folder)) continue;
            var broken = new List<FileEntry>();
            foreach (var f in ctx.Guard.EnumerateFiles(folder, "*.lnk", recurse: true, ct))
            {
                if (!ctx.Guard.Check(f.Path).Allowed) continue;
                var (target, _) = StartupManager.ResolveShortcut(f.Path);
                if (string.IsNullOrWhiteSpace(target) || !Path.IsPathRooted(target)) continue; // shell 命名空间、URL、空目标
                if (RegistryProbe.ProbePath(target) != FileProbe.Missing) continue;
                broken.Add(f);
            }
            if (broken.Count == 0) continue;
            items.Add(new ScanItem
            {
                Id = MakeId("lnk", folder),
                ModuleId = ModuleId,
                Group = "失效的快捷方式",
                DisplayName = folder,
                Kind = ItemKind.FileSet,
                Path = folder,
                Files = broken,
                SizeBytes = broken.Sum(b => b.Size),
                Risk = RiskLevel.Safe,
                Description = $"{broken.Count} 个快捷方式指向已不存在的文件。移入隔离区，可恢复",
                LastWriteUtc = broken.Max(b => b.LastWriteUtc),
            });
        }
    }

    private static List<string> DefaultShortcutFolders(ScanContext ctx)
    {
        var v = ctx.Env.Variables;
        var list = new List<string>();
        if (v.TryGetValue("AppData", out var appData)) list.Add(Path.Combine(appData, @"Microsoft\Windows\Start Menu"));
        if (v.TryGetValue("ProgramData", out var pd)) list.Add(Path.Combine(pd, @"Microsoft\Windows\Start Menu"));
        if (v.TryGetValue("UserProfile", out var up)) list.Add(Path.Combine(up, "Desktop"));
        if (v.TryGetValue("Public", out var pub)) list.Add(Path.Combine(pub, "Desktop"));
        return list;
    }
}
