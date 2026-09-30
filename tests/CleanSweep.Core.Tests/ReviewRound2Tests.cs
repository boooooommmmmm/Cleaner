using System.ServiceProcess;
using System.Xml;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Optimize;
using CleanSweep.Core.Popup;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Repair;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 2026-09-29 全量审查报告的第二轮复查（"对同类边界覆盖所有模块"）：M3–M6 新模块里重现的同类问题的回归基线。
/// R01 注册表类条目扫描后变化、R02 服务恢复方向、R03 弹窗 IFEO 恢复、R05 hosts 原子写入、R06 计划任务备份可恢复、R07 取消后仍受超时约束。
/// </summary>
public sealed class ReviewRound2Tests : IDisposable
{
    private const string TestRoot = @"Software\CleanSweepTests";
    private readonly string _name = "round2-" + Guid.NewGuid().ToString("N")[..8];
    private readonly string _base;
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public ReviewRound2Tests()
    {
        _base = $@"HKCU\{TestRoot}\{_name}";
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_name}", throwOnMissingSubKey: false); } catch { }
        _db.Dispose();
        _t.Dispose();
    }

    private RegistryOps Ops() => new(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")));

    // ---------- R01：注册表类条目的扫描时快照 ----------

    [Fact]
    public void Value_snapshot_changes_with_data_and_reports_missing()
    {
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Snap")) k.SetValue("v", "one");
        var a = RegistrySnapshot.OfValue($@"{_base}\Snap", RegistryView.Registry64, "v");
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Snap")) k.SetValue("v", "two");
        var b = RegistrySnapshot.OfValue($@"{_base}\Snap", RegistryView.Registry64, "v");
        Assert.NotNull(a);
        Assert.NotEqual(a, b);
        // 同样的数据但类型不同也算变化
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Snap")) k.SetValue("v", "two", RegistryValueKind.ExpandString);
        Assert.NotEqual(b, RegistrySnapshot.OfValue($@"{_base}\Snap", RegistryView.Registry64, "v"));
        Assert.Equal(RegistrySnapshot.Missing, RegistrySnapshot.OfValue($@"{_base}\Snap", RegistryView.Registry64, "nope"));
        Assert.Equal(RegistrySnapshot.Missing, RegistrySnapshot.OfValue($@"{_base}\NoKey", RegistryView.Registry64, "v"));
    }

    [Fact]
    public void Key_snapshot_covers_subkeys_and_values()
    {
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Tree\Sub")) k.SetValue("x", 1);
        var a = RegistrySnapshot.OfKey($@"{_base}\Tree", RegistryView.Registry64);
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Tree\Sub")) k.SetValue("x", 2);
        var b = RegistrySnapshot.OfKey($@"{_base}\Tree", RegistryView.Registry64);
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Tree\Sub\Deeper")) { }
        var c = RegistrySnapshot.OfKey($@"{_base}\Tree", RegistryView.Registry64);
        Assert.NotNull(a);
        Assert.NotEqual(a, b);
        Assert.NotEqual(b, c);
        Assert.Equal(c, RegistrySnapshot.OfKey($@"{_base}\Tree", RegistryView.Registry64));
    }

    [Fact]
    public void Delete_refuses_when_value_changed_after_scan_and_proceeds_when_unchanged()
    {
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Del")) k.SetValue("orphan", @"C:\gone\app.exe");
        var target = new RegistryTarget($@"{_base}\Del", RegistryView.Registry64, "orphan");
        var snapshot = RegistrySnapshot.OfValue(target.KeyPath, target.View, target.ValueName!);

        // 扫描后软件"重新安装"，值被改写
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Del")) k.SetValue("orphan", @"C:\back\app.exe");
        var ex = Assert.Throws<InvalidOperationException>(() => Ops().DeleteValue(target, "test", snapshot));
        Assert.Contains("扫描后发生变化", ex.Message);
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_name}\Del")!) Assert.Equal(@"C:\back\app.exe", k.GetValue("orphan"));

        // 重新扫描后快照一致才删
        var fresh = RegistrySnapshot.OfValue(target.KeyPath, target.View, target.ValueName!);
        Ops().DeleteValue(target, "test", fresh);
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_name}\Del")!) Assert.Null(k.GetValue("orphan"));
    }

    [Fact]
    public async Task Engine_reports_changed_registry_item_as_failure_and_keeps_key()
    {
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Vendor\Product")) k.SetValue("InstallLocation", @"C:\gone");
        var keyPath = $@"{_base}\Vendor\Product";
        var item = new ScanItem
        {
            Id = "k", ModuleId = "registry", Group = "g", DisplayName = "Product", Kind = ItemKind.RegistryKey,
            Registry = new RegistryTarget(keyPath, RegistryView.Registry64, null),
            TargetSnapshot = RegistrySnapshot.OfKey(keyPath, RegistryView.Registry64),
        };
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Vendor\Product")) k.SetValue("Version", "2.0");

        var engine = new CleanEngine(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard), new OperationLog(_db), new NullPreActionRunner(), null, Ops());
        var report = await engine.CleanAsync(new[] { item }, null, default);

        var f = Assert.Single(report.Failures);
        Assert.Contains("扫描后发生变化", f.Reason);
        Assert.Equal(0, report.RegistryEntriesRemoved);
        Assert.True(RegistryPath.Exists(keyPath, RegistryView.Registry64));
        Assert.Contains("k", report.IncompleteItemIds);
    }

    [Fact]
    public void Snapshot_must_exist_on_both_sides_and_be_complete()
    {
        // 第三轮复审 N05：没有快照、读不到、超出预算都不能当作"未变化"
        Assert.False(RegistrySnapshot.Matches(null, null));
        Assert.False(RegistrySnapshot.Matches(null, "x"));
        Assert.False(RegistrySnapshot.Matches("x", null));
        Assert.False(RegistrySnapshot.Matches("x", "y"));
        Assert.False(RegistrySnapshot.Matches(RegistrySnapshot.Truncated, RegistrySnapshot.Truncated));
        Assert.True(RegistrySnapshot.Matches("ab", "AB"));
        Assert.Contains("缺少扫描时的快照", RegistrySnapshot.Check(null, "x"));
        Assert.Contains("无法完整核对", RegistrySnapshot.Check(RegistrySnapshot.Truncated, "x"));
    }

    // ---------- R02：服务"恢复"只针对本程序改过的服务 ----------

    [Fact]
    public void Restore_refuses_services_this_program_never_changed()
    {
        var tweaks = new ServiceTweaks(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new RestorePointService(), new OperationLog(_db), Path.Combine(_t.Root, "svc.json"))
        { CreateRestorePoint = false };
        // 目录里在 Windows 上默认为手动 / 已禁用的服务：以前的界面会对它们显示"恢复自动"
        var candidate = ServiceTweaks.Query().FirstOrDefault(s => s.Installed && s.StartMode != ServiceStartMode.Automatic);
        if (candidate is null) return;
        var (ok, msg) = tweaks.SetManual(candidate.Tweak.ServiceName, manual: false);
        Assert.False(ok);
        Assert.Contains("没有修改过", msg);
        using var sc = new ServiceController(candidate.Tweak.ServiceName);
        Assert.Equal(candidate.StartMode, sc.StartType);
    }

    [Fact]
    public void Optimize_refuses_services_that_are_not_automatic()
    {
        var tweaks = new ServiceTweaks(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new RestorePointService(), new OperationLog(_db), Path.Combine(_t.Root, "svc.json"))
        { CreateRestorePoint = false };
        var candidate = ServiceTweaks.Query().FirstOrDefault(s => s.Installed && s.StartMode != ServiceStartMode.Automatic);
        if (candidate is null) return;
        var (ok, msg) = tweaks.SetManual(candidate.Tweak.ServiceName, manual: true);
        Assert.False(ok);
        Assert.Contains("不是自动启动", msg);
    }

    [Fact]
    public void Query_attaches_recorded_original_only_to_recorded_services()
    {
        var records = Path.Combine(_t.Root, "svc.json");
        File.WriteAllText(records, """{ "Fax": { "OriginalStartMode": 2, "TsUtc": "2026-09-29T00:00:00Z" } }""");
        var tweaks = new ServiceTweaks(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new RestorePointService(), new OperationLog(_db), records);
        Assert.Equal(ServiceStartMode.Automatic, tweaks.Records["Fax"]);
        var states = tweaks.QueryStates();
        Assert.All(states.Where(s => s.Tweak.ServiceName != "Fax"), s => Assert.False(s.CanRestore));
        var fax = states.Single(s => s.Tweak.ServiceName == "Fax");
        Assert.Equal(ServiceStartMode.Automatic, fax.RecordedOriginal);
        Assert.Equal(fax.Installed, fax.CanRestore);

        // 没有记录文件：永远不提供恢复
        var none = new ServiceTweaks(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new RestorePointService(), new OperationLog(_db));
        Assert.All(none.QueryStates(), s => Assert.False(s.CanRestore));
    }

    // ---------- R03：弹窗 IFEO 阻止 ----------

    [Fact]
    public void Ifeo_marker_is_recognized_only_for_our_value()
    {
        Assert.True(PopupBlocker.IsOurDebugger($"\"C:\\Windows\\System32\\systray.exe\" {PopupBlocker.BlockMarker}"));
        Assert.False(PopupBlocker.IsOurDebugger(@"C:\Windows\System32\systray.exe"));
        Assert.False(PopupBlocker.IsOurDebugger(@"C:\Tools\windbg.exe"));
        Assert.False(PopupBlocker.IsOurDebugger(null));
    }

    [Fact]
    public void Unblock_does_not_require_rule_listing_and_is_a_no_op_when_not_blocked()
    {
        var blocker = new PopupBlocker(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new OperationLog(_db));
        blocker.LoadJson("""{ "rules": [], "blockableProcesses": [ "AdThing.exe" ] }""", "t.json");
        // 规则库里已经没有这个名字，但恢复仍然允许；当前没被阻止时什么都不写
        var (ok, msg) = blocker.SetBlocked("OldPopup-" + _name + ".exe", false);
        Assert.True(ok);
        Assert.Contains("没有被阻止", msg);
        Assert.False(blocker.SetBlocked(@"..\x.exe", false).Success);
        Assert.False(blocker.SetBlocked("explorer.exe", false).Success);
        Assert.False(blocker.SetBlocked("NotListed-" + _name + ".exe", true).Success);
    }

    // ---------- R05：hosts 原子写入与备份命名 ----------

    [Fact]
    public void Hosts_write_is_atomic_and_backups_never_collide()
    {
        var hosts = Path.Combine(_t.Dir("etc"), "hosts");
        File.WriteAllText(hosts, "127.0.0.1 localhost\r\n");
        var repair = new SystemRepair(new OperationLog(_db), Path.Combine(_t.Root, "hosts-backups"));

        var (ok1, _) = repair.WriteHostsFile(hosts, "127.0.0.1 a.local\n");
        var (ok2, _) = repair.WriteHostsFile(hosts, "127.0.0.1 b.local\n");
        Assert.True(ok1);
        Assert.True(ok2);
        Assert.Equal("127.0.0.1 b.local\r\n", File.ReadAllText(hosts));
        Assert.Equal(2, repair.ListHostsBackups().Count);
        Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(hosts)!, "*.tmp"));

        var (bad, msg) = repair.WriteHostsFile(hosts, "not an ip host\n");
        Assert.False(bad);
        Assert.Contains("不是合法 IP", msg);
        Assert.Equal("127.0.0.1 b.local\r\n", File.ReadAllText(hosts));
    }

    // ---------- R06：计划任务备份可恢复且受同样的完整性校验 ----------

    private const string SampleTaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
          <Actions Context="Author"><Exec><Command>C:\gone\app.exe</Command></Exec></Actions>
        </Task>
        """;

    [Fact]
    public void Task_backup_lists_with_hash_and_restore_rejects_tampering_and_bad_names()
    {
        var ops = Ops();
        var file = ops.WriteTaskBackup(@"\CleanSweepTests\Sample", SampleTaskXml, "test");
        var rec = Assert.Single(ops.ListTaskBackups());
        Assert.Equal(Path.GetFileName(file), rec.FileName);
        Assert.Equal(@"\CleanSweepTests\Sample", rec.TaskPath);
        Assert.Equal(RegistrySnapshot.OfTaskXml(SampleTaskXml), rec.Sha256);

        Assert.Throws<ArgumentException>(() => ops.RestoreScheduledTask(Path.Combine("..", rec.FileName)));
        Assert.Throws<ArgumentException>(() => ops.RestoreScheduledTask(file));
        Assert.Throws<FileNotFoundException>(() => ops.RestoreScheduledTask("nope.xml"));

        File.WriteAllText(file, SampleTaskXml.Replace(@"C:\gone\app.exe", @"C:\evil\app.exe"));
        var ex = Assert.Throws<InvalidOperationException>(() => ops.RestoreScheduledTask(rec.FileName));
        Assert.Contains("哈希不一致", ex.Message);

        // sidecar 指向 Microsoft 的任务：拒绝
        var ms = ops.WriteTaskBackup(@"\Microsoft\Windows\X", SampleTaskXml, "test");
        Assert.Contains("Microsoft", Assert.Throws<InvalidOperationException>(() => ops.RestoreScheduledTask(Path.GetFileName(ms))).Message);
    }

    [Fact]
    public void Task_logon_type_maps_from_xml_and_password_tasks_are_not_auto_restored()
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(SampleTaskXml);
        Assert.Equal(3, RegistryOps.TaskLogonType(doc));
        doc.LoadXml(SampleTaskXml.Replace("InteractiveToken", "S4U"));
        Assert.Equal(2, RegistryOps.TaskLogonType(doc));
        doc.LoadXml(SampleTaskXml.Replace("InteractiveToken", "Password"));
        Assert.Null(RegistryOps.TaskLogonType(doc));
        doc.LoadXml(SampleTaskXml.Replace("<LogonType>InteractiveToken</LogonType>", ""));
        Assert.Equal(3, RegistryOps.TaskLogonType(doc));
    }

    // ---------- R07：用户取消后系统命令仍受总时限约束 ----------

    [Fact]
    public async Task System_command_still_times_out_after_user_cancel()
    {
        using var cts = new CancellationTokenSource(200);
        var r = await SystemCommand.RunAsync("ping.exe", "-n 30 127.0.0.1", TimeSpan.FromSeconds(3), cts.Token);
        Assert.True(r.TimedOut);
        Assert.False(r.Success);
        Assert.True(r.Elapsed < TimeSpan.FromSeconds(20));
    }

    // ---------- R04：不提权启动的令牌获取 ----------

    [Fact]
    public void Can_duplicate_primary_token_of_own_process()
    {
        var token = UnelevatedProcess.DuplicatePrimaryTokenOf(System.Diagnostics.Process.GetCurrentProcess());
        Assert.NotEqual(IntPtr.Zero, token);
        UnelevatedProcess.CloseToken(token);
        Assert.Equal("没有可用的令牌", UnelevatedProcess.TryStart(IntPtr.Zero, @"C:\Windows\explorer.exe", null));
    }
}
