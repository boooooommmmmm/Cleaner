using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Privacy;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Uninstall;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

public sealed class RegistryGuardTests
{
    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "x")]
    [InlineData(@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell")]
    [InlineData(@"HKLM\Software\Policies\Microsoft\Windows", "x")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\Foo", "ImagePath")]
    [InlineData(@"HKLM\Software\Microsoft\Cryptography", "MachineGuid")]
    [InlineData(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "x")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "x")]
    [InlineData(@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages", "x")]
    public void Never_touch_values_are_refused(string key, string value) =>
        Assert.NotNull(RegistryGuard.CheckDeleteValue(key, RegistryView.Registry64, value));

    [Theory]
    [InlineData(@"HKCU\Software")]
    [InlineData(@"HKLM\Software")]
    [InlineData(@"HKCU\Software\Microsoft")]
    [InlineData(@"HKLM\Software\Microsoft\Windows")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion")]
    [InlineData(@"HKLM\Software\Classes")]
    [InlineData(@"HKLM\Software\Intel")]
    [InlineData(@"HKLM\Software\WOW6432Node\Microsoft")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Control")]
    [InlineData(@"HKLM\SAM")]
    [InlineData(@"HKCR\CLSID")]
    [InlineData(@"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID")]
    public void Dangerous_key_deletes_are_refused(string key) =>
        Assert.NotNull(RegistryGuard.CheckDeleteKey(key, RegistryView.Registry64));

    [Theory]
    [InlineData(@"HKCU\Software\GoneVendor")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\GoneApp_is1")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\gone.exe")]
    [InlineData(@"HKCU\Software\Classes\GoneProg")]
    [InlineData(@"HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000001}")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")]
    [InlineData(@"HKU\S-1-5-21-1-2-3-1001\Software\GoneVendor")]
    public void Legitimate_key_deletes_are_allowed(string key) =>
        Assert.Null(RegistryGuard.CheckDeleteKey(key, RegistryView.Registry64));

    [Fact]
    public void Value_delete_in_shared_dlls_and_muicache_allowed()
    {
        Assert.Null(RegistryGuard.CheckDeleteValue(@"HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs", RegistryView.Registry64, @"C:\x.dll"));
        Assert.Null(RegistryGuard.CheckDeleteValue(@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", RegistryView.Registry64, "x"));
    }
}

public sealed class RegistryProbeTests : IDisposable
{
    private readonly TestEnv _t = new();
    public void Dispose() => _t.Dispose();

    [Fact]
    public void Extracts_paths_from_command_lines()
    {
        var exe = _t.File(Path.Combine("bin", "app.exe"));
        Assert.Equal(exe, RegistryProbe.ExtractPath($"\"{exe}\" /uninstall"), ignoreCase: true);
        Assert.Equal(exe, RegistryProbe.ExtractPath($"{exe},0"), ignoreCase: true);
        Assert.Equal(exe, RegistryProbe.ExtractPath($"{exe} -x -y"), ignoreCase: true);
        Assert.Null(RegistryProbe.ExtractPath("http://example.com"));
        Assert.Null(RegistryProbe.ExtractPath("%UNKNOWN_VAR_XYZ%\\a.exe"));
        Assert.Null(RegistryProbe.ExtractPath(null));
        // rundll32 载荷
        var dll = _t.File(Path.Combine("bin", "payload.dll"));
        Assert.Equal(dll, RegistryProbe.ExtractPath($"rundll32.exe \"{dll}\",Entry"), ignoreCase: true);

        // 无引号带空格的路径：不能截成 "C:\Program"
        var spaced = Path.Combine(_t.Root, "Program Files", "Vendor App", "lib.dll");
        Assert.Equal(spaced, RegistryProbe.ExtractPath(spaced), ignoreCase: true);
        Assert.Equal(spaced, RegistryProbe.ExtractPath(spaced + " /regserver"), ignoreCase: true);
        Assert.Null(RegistryProbe.ExtractPath(Path.Combine(_t.Root, "Program Files", "Vendor App") + " -x"));
        // 纯路径模式：整个值就是路径
        var loc = Path.Combine(_t.Root, "Program Files", "Vendor App");
        Assert.Equal(loc, RegistryProbe.ExtractPath("\"" + loc + "\\\"", isCommandLine: false), ignoreCase: true);
        Assert.Equal(loc, RegistryProbe.ExtractPath(loc.Replace('\\', '/'), isCommandLine: false), ignoreCase: true);
        Assert.Null(RegistryProbe.ExtractPath("relative\\dir", isCommandLine: false));
        // shell 占位符不是环境变量
        Assert.Equal(exe, RegistryProbe.ExtractPath($"\"{exe}\" \"%1\" %*"), ignoreCase: true);
    }

    [Fact]
    public void Probe_distinguishes_exists_missing_unknown()
    {
        var exe = _t.File(Path.Combine("bin", "app.exe"));
        Assert.Equal(FileProbe.Exists, RegistryProbe.ProbePath(exe));
        Assert.Equal(FileProbe.Missing, RegistryProbe.ProbePath(Path.Combine(_t.Root, "nope", "gone.exe")));
        Assert.Equal(FileProbe.Unknown, RegistryProbe.ProbePath(@"\\server\share\x.exe"));
        Assert.Equal(FileProbe.Unknown, RegistryProbe.ProbePath("relative\\x.exe"));
        // 不存在的驱动器：不可判定，不能当作缺失
        Assert.Equal(FileProbe.Unknown, RegistryProbe.ProbePath(@"Q:\gone\x.exe"));
    }

    [Fact]
    public void Redirection_alternatives_cover_system32_and_program_files()
    {
        var windir = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);
        var alts = RegistryProbe.RedirectionAlternatives(Path.Combine(windir, "System32", "foo.dll")).ToList();
        Assert.Contains(Path.Combine(windir, "SysWOW64", "foo.dll"), alts);
        Assert.Equal(FileProbe.Exists, RegistryProbe.ProbePath(Path.Combine(windir, "System32", "kernel32.dll")));
        Assert.True(RegistryProbe.IsUnderWindows(Path.Combine(windir, "x.dll")));
    }
}

/// <summary>用 HKCU\Software\CleanSweepTests 下的假键模拟各类注册表垃圾。</summary>
public sealed class RegistryCleanerScannerTests : IDisposable
{
    private const string TestRoot = @"Software\CleanSweepTests";
    private readonly string _name = "regclean-" + Guid.NewGuid().ToString("N")[..8];
    private readonly string _base;
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly string _missingExe;
    private readonly string _existingExe;

    public RegistryCleanerScannerTests()
    {
        _base = $@"HKCU\{TestRoot}\{_name}";
        _missingExe = Path.Combine(_t.Root, "gone", "app.exe");
        _existingExe = _t.File("live/app.exe");
        using var root = Microsoft.Win32.Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}");

        using (var bad = root.CreateSubKey(@"Uninstall\BadApp_is1"))
        {
            bad.SetValue("DisplayName", "Bad App");
            bad.SetValue("UninstallString", $"\"{_missingExe}\" /uninstall");
        }
        using (var good = root.CreateSubKey(@"Uninstall\GoodApp"))
        {
            good.SetValue("DisplayName", "Good App");
            good.SetValue("UninstallString", $"\"{_existingExe}\"");
        }
        using (var msi = root.CreateSubKey(@"Uninstall\{11111111-2222-3333-4444-555555555555}"))
        {
            msi.SetValue("DisplayName", "Msi App");
            msi.SetValue("WindowsInstaller", 1);
            msi.SetValue("UninstallString", "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}");
        }
        using (var mui = root.CreateSubKey("MuiCache"))
        {
            mui.SetValue(_missingExe + ".FriendlyAppName", "Gone");
            mui.SetValue(_existingExe + ".FriendlyAppName", "Live");
        }
        using (var ap = root.CreateSubKey(@"App Paths\gone.exe")) ap.SetValue("", _missingExe);
        using (var ap = root.CreateSubKey(@"App Paths\live.exe")) ap.SetValue("", _existingExe);

        using (var v = root.CreateSubKey(@"Software\GoneVendor\Product")) v.SetValue("InstallPath", Path.Combine(_t.Root, "gone", "vendor"));
        using (var v = root.CreateSubKey(@"Software\LiveVendor")) v.SetValue("InstallPath", _t.Dir("live"));
        using (var v = root.CreateSubKey(@"Software\UninstalledByHistory")) v.SetValue("Setting", 1);
        using (var v = root.CreateSubKey(@"Software\NoEvidence")) v.SetValue("Setting", 1);
        using (var v = root.CreateSubKey(@"Software\Microsoft\Foo")) v.SetValue("Path", _missingExe);

        using (var c = root.CreateSubKey(@"Classes\.gone")) c.SetValue("", "CleanSweepTests.NoSuchProgId");
        using (var c = root.CreateSubKey(@"Classes\GoneProg\shell\open\command")) c.SetValue("", $"\"{_missingExe}\" \"%1\"");
        using (var c = root.CreateSubKey(@"Classes\LiveProg\shell\open\command")) c.SetValue("", $"\"{_existingExe}\" \"%1\"");
        using (var c = root.CreateSubKey(@"Classes\Applications\gone.exe\shell\open\command")) c.SetValue("", $"\"{_missingExe}\" \"%1\"");
        using (var c = root.CreateSubKey(@"Classes\CLSID\{00000000-0000-0000-0000-00000000C0DE}\InprocServer32")) c.SetValue("", Path.Combine(_t.Root, "gone", "com.dll"));
        using (var c = root.CreateSubKey(@"Classes\CLSID\{00000000-0000-0000-0000-00000000C0DE}")) c.SetValue("", "Gone COM Server");

        using (var s = root.CreateSubKey("SharedDLLs"))
        {
            s.SetValue(Path.Combine(_t.Root, "gone", "shared.dll"), 1);
            s.SetValue(_existingExe, 1);
        }
    }

    public void Dispose()
    {
        try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_name}", false); } catch { }
        _db.Dispose();
        _t.Dispose();
    }

    private RegistryCleanerOptions Options(bool shortcuts = false) => new()
    {
        UninstallKeys = new() { ($@"{_base}\Uninstall", RegistryView.Registry64) },
        MuiCacheKeys = new() { ($@"{_base}\MuiCache", RegistryView.Registry64) },
        AppPathsKeys = new() { ($@"{_base}\App Paths", RegistryView.Registry64) },
        SoftwareRoots = new() { ($@"{_base}\Software", RegistryView.Registry64) },
        ClassesRoots = new() { ($@"{_base}\Classes", RegistryView.Registry64) },
        SharedDllsKey = ($@"{_base}\SharedDLLs", RegistryView.Registry64),
        IncludeServices = false,
        IncludeTasks = false,
        IncludeShortcuts = shortcuts,
        ShortcutFolders = shortcuts ? new() { _t.Dir("Shortcuts") } : null,
    };

    private async Task<IReadOnlyList<ScanItem>> Scan(RegistryCleanerOptions opts, UninstallHistory? history = null)
    {
        var inventory = new AppInventory(_t.Env);
        inventory.UseSnapshot(FingerprintTests.Snapshot(new InstalledApp { Id = "1", Name = "Live Product", Publisher = "LiveVendor", Source = AppSource.Registry }));
        var scanner = new RegistryCleanerScanner(inventory, history, opts);
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist() };
        return await scanner.ScanAsync(ctx, null, default);
    }

    [Fact]
    public async Task Finds_each_kind_and_leaves_live_entries_alone()
    {
        var history = new UninstallHistory(_db);
        history.Record(new InstalledApp { Id = "h", Name = "UninstalledByHistory", Source = AppSource.Registry }, "test");

        var items = await Scan(Options(), history);

        var uninstall = Assert.Single(items, i => i.Group == "无效的卸载项");
        Assert.Equal("Bad App", uninstall.DisplayName);
        Assert.Equal(ItemKind.RegistryKey, uninstall.Kind);
        Assert.Equal(RiskLevel.Safe, uninstall.Risk);
        Assert.EndsWith(@"\Uninstall\BadApp_is1", uninstall.Registry!.KeyPath);

        var mui = Assert.Single(items, i => i.Group.StartsWith("MUI"));
        Assert.Equal(ItemKind.RegistryValue, mui.Kind);
        Assert.Equal(_missingExe + ".FriendlyAppName", mui.Registry!.ValueName);
        // 注册表类条目都带扫描时快照，清理前比对
        Assert.NotNull(uninstall.TargetSnapshot);
        Assert.NotNull(mui.TargetSnapshot);
        Assert.All(items.Where(i => i.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue), i => Assert.NotNull(i.TargetSnapshot));

        var appPath = Assert.Single(items, i => i.Group.Contains("App Paths"));
        Assert.Equal("gone.exe", appPath.DisplayName);
        Assert.Equal(RiskLevel.Confirm, appPath.Risk);

        var software = items.Where(i => i.Group == "已卸载软件遗留的注册表键").Select(i => i.DisplayName).OrderBy(x => x).ToList();
        Assert.Equal(new[] { "GoneVendor", "UninstalledByHistory" }, software);

        var assoc = items.Where(i => i.Group == "失效的文件关联").Select(i => i.DisplayName).OrderBy(x => x).ToList();
        Assert.Equal(new[] { ".gone", "GoneProg" }, assoc);
        Assert.Single(items, i => i.Group.Contains("打开方式") && i.DisplayName == "gone.exe");

        var com = Assert.Single(items, i => i.Group.StartsWith("失效的 COM"));
        Assert.Equal(RiskLevel.High, com.Risk);
        Assert.Equal("Gone COM Server", com.DisplayName);

        var shared = Assert.Single(items, i => i.Group.StartsWith("失效的共享 DLL"));
        Assert.Equal(RiskLevel.High, shared.Risk);
        Assert.Equal(ItemKind.RegistryValue, shared.Kind);

        Assert.DoesNotContain(items, i => i.DisplayName is "Good App" or "Msi App" or "live.exe" or "LiveVendor" or "LiveProg" or "NoEvidence" or "Microsoft");
        Assert.All(items, i => Assert.True(i.Path is not null));
    }

    [Fact]
    public async Task Broken_shortcuts_are_file_items_for_quarantine()
    {
        var dir = _t.Dir("Shortcuts");
        var broken = Path.Combine(dir, "Gone App.lnk");
        var live = Path.Combine(dir, "Live App.lnk");
        if (!CreateShortcut(broken, _missingExe) || !CreateShortcut(live, _existingExe)) return; // 没有 WScript.Shell 的环境跳过

        var items = await Scan(Options(shortcuts: true));
        var lnk = Assert.Single(items, i => i.Group == "失效的快捷方式");
        Assert.Equal(ItemKind.FileSet, lnk.Kind);
        Assert.Single(lnk.Files);
        Assert.Equal(broken, lnk.Files[0].Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Safe, lnk.Risk);
    }

    private static bool CreateShortcut(string lnk, string target)
    {
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell");
            if (t is null) return false;
            dynamic shell = Activator.CreateInstance(t)!;
            dynamic sc = shell.CreateShortcut(lnk);
            sc.TargetPath = target;
            sc.Save();
            return File.Exists(lnk);
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public async Task Scanner_merges_shared_targets_from_both_views()
    {
        var baseline = await Scan(Options());
        var opts = Options();
        opts.AppPathsKeys.Add((opts.AppPathsKeys[0].Key, RegistryView.Registry32));
        opts.ClassesRoots.Add((opts.ClassesRoots[0].Key, RegistryView.Registry32));
        var items = await Scan(opts);
        Assert.Equal(baseline.Select(i => i.Id).Order(), items.Select(i => i.Id).Order());
        Assert.Single(items, i => i.Registry?.KeyPath == $@"{_base}\Classes\.gone");
        Assert.Single(items, i => i.Registry?.KeyPath == $@"{_base}\App Paths\gone.exe");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Already_missing_targets_leave_list_without_counting_as_deleted_or_failed(bool wholeKeyForValue)
    {
        var items = await Scan(Options());
        var value = items.Single(i => i.Group.StartsWith("MUI"));
        var key = items.Single(i => i.Group == "无效的卸载项");
        Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_name}\Uninstall\BadApp_is1");
        if (wholeKeyForValue) Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_name}\MuiCache");
        else
        {
            using var mui = RegistryPath.Open(value.Registry!.KeyPath, value.Registry.View, writable: true)!;
            mui.DeleteValue(value.Registry.ValueName!);
        }
        var backup = new RegistryBackup(_db, Path.Combine(_t.Root, "Backups"));
        var log = new OperationLog(_db);
        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), log, new NullPreActionRunner(), null, new RegistryOps(backup));
        var report = await engine.CleanAsync(new[] { value, key }, null, default);
        Assert.Empty(report.Failures);
        Assert.Empty(report.IncompleteItemIds);
        Assert.Equal(2, report.RegistryEntriesAlreadyAbsent);
        Assert.Equal(0, report.RegistryEntriesRemoved);
        Assert.Equal(0, report.Skipped);
        Assert.All(report.Outcomes.Values, outcome => Assert.Equal(0, outcome.Succeeded));
        Assert.Empty(backup.List());
        Assert.Equal(2, log.GetOperations(report.BatchId).Count(o => o.Action == "already-absent"));
    }

    [Fact]
    public async Task Duplicate_shared_key_from_old_scan_is_deleted_and_backed_up_only_once()
    {
        var key = (await Scan(Options())).Single(i => i.Group == "无效的卸载项");
        var duplicate = key with { Id = key.Id + "-32", Registry = key.Registry! with { View = RegistryView.Registry32 } };
        var backup = new RegistryBackup(_db, Path.Combine(_t.Root, "Backups"));
        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), new OperationLog(_db), new NullPreActionRunner(), null, new RegistryOps(backup));
        var report = await engine.CleanAsync(new[] { key, duplicate }, null, default);
        Assert.Empty(report.Failures);
        Assert.Empty(report.IncompleteItemIds);
        Assert.Equal(1, report.RegistryEntriesRemoved);
        Assert.Equal(1, report.RegistryEntriesAlreadyAbsent);
        var saved = Assert.Single(backup.List());
        backup.Restore(saved.Id);
        Assert.Equal(key.TargetSnapshot, RegistrySnapshot.OfKey(key.Registry!.KeyPath, key.Registry.View));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Backup_failure_keeps_target_and_reports_stage_and_view(bool valueTarget)
    {
        var items = await Scan(Options());
        var item = valueTarget ? items.Single(i => i.Group.StartsWith("MUI")) : items.Single(i => i.Group == "无效的卸载项");
        var backupDir = Path.Combine(_t.Root, "Backups");
        var backup = new RegistryBackup(_db, backupDir);
        // 用普通文件阻挡测试目录中的备份输出，模拟真实写入失败。
        Directory.Delete(backupDir);
        File.WriteAllText(backupDir, "blocked");
        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), new OperationLog(_db), new NullPreActionRunner(), null, new RegistryOps(backup));
        var report = await engine.CleanAsync(new[] { item }, null, default);
        var failure = Assert.Single(report.Failures);
        Assert.Contains("备份阶段失败，未执行删除", failure.Reason);
        Assert.Contains("64 位视图", failure.Path);
        Assert.Contains(item.Id, report.IncompleteItemIds);
        Assert.Equal(0, report.RegistryEntriesRemoved);
        Assert.Equal(0, report.RegistryEntriesAlreadyAbsent);
        var target = item.Registry!;
        var current = valueTarget ? RegistrySnapshot.OfValue(target.KeyPath, target.View, target.ValueName!) : RegistrySnapshot.OfKey(target.KeyPath, target.View);
        Assert.Equal(item.TargetSnapshot, current);
    }

    [Fact]
    public async Task Engine_deletes_registry_items_with_backup_and_restore_brings_them_back()
    {
        var items = await Scan(Options());
        var backupDir = Path.Combine(_t.Root, "Backups");
        var backup = new RegistryBackup(_db, backupDir);
        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), new OperationLog(_db), new NullPreActionRunner(), null, new RegistryOps(backup));

        var value = items.Single(i => i.Group.StartsWith("MUI"));
        var key = items.Single(i => i.Group == "无效的卸载项");
        var report = await engine.CleanAsync(new[] { value, key }, null, default);

        Assert.Empty(report.Failures);
        Assert.Equal(2, report.RegistryEntriesRemoved);
        Assert.False(RegistryPath.Exists($@"{_base}\Uninstall\BadApp_is1", RegistryView.Registry64));
        using (var mui = RegistryPath.Open($@"{_base}\MuiCache", RegistryView.Registry64, false)!)
            Assert.Null(mui.GetValue(_missingExe + ".FriendlyAppName"));

        var backups = backup.List();
        Assert.Equal(2, backups.Count);
        foreach (var b in backups) backup.Restore(b.Id);

        Assert.True(RegistryPath.Exists($@"{_base}\Uninstall\BadApp_is1", RegistryView.Registry64));
        using (var mui = RegistryPath.Open($@"{_base}\MuiCache", RegistryView.Registry64, false)!)
            Assert.Equal("Gone", mui.GetValue(_missingExe + ".FriendlyAppName"));
    }

    [Fact]
    public async Task Engine_refuses_items_whose_target_changed_after_scan()
    {
        var items = await Scan(Options());
        var value = items.Single(i => i.Group.StartsWith("MUI"));
        var key = items.Single(i => i.Group == "无效的卸载项");

        // 扫描后：MUI 值被改写、软件被"重新安装"（卸载键多了一个值）
        using (var mui = RegistryPath.Open($@"{_base}\MuiCache", RegistryView.Registry64, writable: true)!) mui.SetValue(_missingExe + ".FriendlyAppName", "Back");
        using (var u = RegistryPath.Open($@"{_base}\Uninstall\BadApp_is1", RegistryView.Registry64, writable: true)!) u.SetValue("DisplayVersion", "2.0");

        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), new OperationLog(_db), new NullPreActionRunner(), null, new RegistryOps(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups"))));
        var report = await engine.CleanAsync(new[] { value, key }, null, default);

        Assert.Equal(2, report.Failures.Count);
        Assert.All(report.Failures, f => Assert.Contains("扫描后发生变化", f.Reason));
        Assert.Equal(0, report.RegistryEntriesRemoved);
        Assert.True(RegistryPath.Exists($@"{_base}\Uninstall\BadApp_is1", RegistryView.Registry64));
        using (var mui = RegistryPath.Open($@"{_base}\MuiCache", RegistryView.Registry64, false)!)
            Assert.Equal("Back", mui.GetValue(_missingExe + ".FriendlyAppName"));
    }

    [Fact]
    public async Task Engine_refuses_registry_items_outside_guard_and_without_backup()
    {
        var backup = new RegistryBackup(_db, Path.Combine(_t.Root, "Backups"));
        var log = new OperationLog(_db);
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);

        var forged = new ScanItem
        {
            Id = "forged", ModuleId = "registry", Group = "g", DisplayName = "Run", Kind = ItemKind.RegistryValue,
            Registry = new RegistryTarget(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64, "CleanSweepTestsNoSuchValue"),
        };
        var withOps = new CleanEngine(_t.Guard, q, log, new NullPreActionRunner(), null, new RegistryOps(backup));
        var report = await withOps.CleanAsync(new[] { forged }, null, default);
        var f = Assert.Single(report.Failures);
        Assert.Contains("护栏拒绝", f.Reason);

        var withoutOps = new CleanEngine(_t.Guard, q, log, new NullPreActionRunner());
        var items = await Scan(Options());
        var report2 = await withoutOps.CleanAsync(new[] { items.First(i => i.Kind == ItemKind.RegistryValue) }, null, default);
        Assert.Contains(report2.Failures, x => x.Reason.Contains("未配置注册表备份"));
        using var mui = RegistryPath.Open($@"{_base}\MuiCache", RegistryView.Registry64, false)!;
        Assert.Equal("Gone", mui.GetValue(_missingExe + ".FriendlyAppName"));
    }

    [Fact]
    public async Task Privacy_scanner_lists_mru_keys_and_recent_files()
    {
        using (var mru = Microsoft.Win32.Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Explorer\RunMRU"))
        {
            mru.SetValue("a", "cmd\\1");
            mru.SetValue("MRUList", "a");
        }
        Microsoft.Win32.Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Explorer\TypedPaths").Dispose(); // 空键不列出
        var recent = _t.Dir(Path.Combine(_t.Vars["AppData"], @"Microsoft\Windows\Recent"));
        _t.File(Path.Combine(recent, "doc.lnk"), "x");
        _t.File(Path.Combine(recent, "AutomaticDestinations", "abc.automaticDestinations-ms"), "x");

        var scanner = new PrivacyScanner(new PrivacyOptions { ExplorerKey = $@"{_base}\Explorer" });
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist() };
        var items = await scanner.ScanAsync(ctx, null, default);

        var run = Assert.Single(items, i => i.DisplayName.Contains("运行"));
        Assert.Equal(ItemKind.RegistryKey, run.Kind);
        Assert.EndsWith("RunMRU", run.Registry!.KeyPath);
        Assert.DoesNotContain(items, i => i.DisplayName.Contains("地址栏"));
        Assert.Single(items, i => i.DisplayName == "最近使用的文件记录" && i.Files.Count == 1);
        Assert.Single(items, i => i.DisplayName.StartsWith("跳转列表（自动）"));
    }
}

public sealed class ShredderTests : IDisposable
{
    private readonly TestEnv _t = new();
    public void Dispose() => _t.Dispose();

    [Fact]
    public void Shreds_file_and_refuses_directories_and_protected_paths()
    {
        var file = _t.RandomFile(Path.Combine(_t.Vars["LocalAppData"], "secret.bin"), 300_000, 7);
        var r = FileShredder.Shred(file, 3, _t.Guard);
        Assert.True(r.Success, r.Message);
        Assert.False(File.Exists(file));
        Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(file)!)); // 改名后的临时名也不留下

        var dir = _t.Dir("somedir");
        Assert.False(FileShredder.Shred(dir, 1, _t.Guard).Success);
        var sys = Path.Combine(_t.Vars["Windir"], "System32", "x.dll");
        _t.File(sys);
        var denied = FileShredder.Shred(sys, 1, _t.Guard);
        Assert.False(denied.Success);
        Assert.Contains("护栏", denied.Message);
        Assert.True(File.Exists(sys));
        Assert.False(FileShredder.Shred(file, 0, _t.Guard).Success);
    }

    [Fact]
    public void Pattern_passes()
    {
        var buf = new byte[16];
        FileShredder.FillPattern(buf, 0);
        Assert.All(buf, b => Assert.Equal(0, b));
        FileShredder.FillPattern(buf, 1);
        Assert.All(buf, b => Assert.Equal(0xFF, b));
        FileShredder.FillPattern(buf, 2);
        Assert.Contains(buf, b => b != 0);
    }

    [Fact]
    public void Free_space_wipe_refuses_ssd_and_unknown_media()
    {
        var original = Disk.DiskMedia.SolidStateProbe;
        try
        {
            var root = Path.GetPathRoot(Path.GetTempPath())!;
            Disk.DiskMedia.SolidStateProbe = _ => true;
            Assert.Contains("固态", FreeSpaceWiper.CheckVolume(root));
            Disk.DiskMedia.SolidStateProbe = _ => null;
            Assert.Contains("无法判定", FreeSpaceWiper.CheckVolume(root));
            Disk.DiskMedia.SolidStateProbe = _ => false;
            Assert.Null(FreeSpaceWiper.CheckVolume(root));
        }
        finally
        {
            Disk.DiskMedia.SolidStateProbe = original;
        }
    }

    [Fact]
    public void Real_volume_media_query_does_not_throw()
    {
        var result = Disk.DiskMedia.IsSolidState(Path.GetTempPath());
        _ = result; // 只要求不抛异常；结果取决于本机介质
    }

    [Fact]
    public void Start_menu_single_shortcut_is_allowed_but_directory_is_not()
    {
        var startMenu = Path.Combine(_t.Vars["AppData"], @"Microsoft\Windows\Start Menu\Programs");
        var lnk = _t.File(Path.Combine(startMenu, "Gone.lnk"), "x");
        Assert.True(_t.Guard.Check(lnk).Allowed);
        Assert.False(_t.Guard.Check(startMenu).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(startMenu, "notalink.txt")).Allowed);
        var lnkDir = _t.Dir(Path.Combine(startMenu, "Folder.lnk"));
        Assert.False(_t.Guard.Check(lnkDir).Allowed);
    }
}
