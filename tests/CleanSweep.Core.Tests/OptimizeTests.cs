using CleanSweep.Core.Backup;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Memory;
using CleanSweep.Core.Optimize;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class DiskHealthTests
{
    [Fact]
    public void Defragment_is_refused_on_ssd_and_unknown_media()
    {
        Assert.Null(DiskHealth.BuildCommand(DiskHealth.DiskOperation.Defragment, "C:", MediaKind.Ssd, out var e1));
        Assert.Contains("硬性约束", e1);
        Assert.Null(DiskHealth.BuildCommand(DiskHealth.DiskOperation.Defragment, "C:", MediaKind.Unknown, out _));
        var hdd = DiskHealth.BuildCommand(DiskHealth.DiskOperation.Defragment, "d", MediaKind.Hdd, out _);
        Assert.Equal(("defrag.exe", "D: /D /U"), hdd);
    }

    [Fact]
    public void Retrim_only_on_solid_state()
    {
        Assert.Null(DiskHealth.BuildCommand(DiskHealth.DiskOperation.Retrim, "C:", MediaKind.Hdd, out var err));
        Assert.Contains("固态", err);
        Assert.Equal(("defrag.exe", "C: /L /U"), DiskHealth.BuildCommand(DiskHealth.DiskOperation.Retrim, "C:", MediaKind.Ssd, out _));
    }

    [Fact]
    public void Optimize_analyze_and_chkdsk_commands_are_fixed()
    {
        Assert.Equal(("defrag.exe", "C: /O /U"), DiskHealth.BuildCommand(DiskHealth.DiskOperation.Optimize, "c:", MediaKind.Ssd, out _));
        Assert.Equal(("defrag.exe", "C: /A /U"), DiskHealth.BuildCommand(DiskHealth.DiskOperation.Analyze, "C:", MediaKind.Unknown, out _));
        Assert.Equal(("chkntfs.exe", "/C C:"), DiskHealth.BuildCommand(DiskHealth.DiskOperation.ScheduleCheckDisk, "C:", MediaKind.Hdd, out _));
        Assert.Equal(("chkntfs.exe", "C:"), DiskHealth.BuildCommand(DiskHealth.DiskOperation.QueryCheckDisk, "C:", MediaKind.Hdd, out _));
    }

    [Theory]
    [InlineData("C:\\")]
    [InlineData("CC:")]
    [InlineData("1:")]
    [InlineData("C: /X")]
    [InlineData("")]
    public void Invalid_drive_letters_are_refused(string letter)
    {
        Assert.Null(DiskHealth.BuildCommand(DiskHealth.DiskOperation.Analyze, letter, MediaKind.Hdd, out var err));
        Assert.Contains("驱动器号", err);
    }

    [Fact]
    public void Real_machine_inventory_is_read_only_and_consistent()
    {
        var disks = DiskHealth.GetPhysicalDisks();
        var volumes = DiskHealth.GetVolumes(disks);
        Assert.NotEmpty(volumes);
        Assert.All(volumes, v => Assert.Matches("^[A-Z]:$", v.Letter));
        Assert.Contains(volumes, v => v.Type == DriveType.Fixed);
        var smart = DiskHealth.GetSmart(disks);
        Assert.Equal(disks.Count, smart.Count);
        var schedule = DiskHealth.GetOptimizeSchedule();
        Assert.NotNull(schedule);
    }

    [Fact]
    public void System_command_only_accepts_bare_names()
    {
        Assert.Throws<ArgumentException>(() => SystemCommand.System32(@"C:\evil\defrag.exe"));
        Assert.Throws<ArgumentException>(() => SystemCommand.System32("defrag.exe /X"));
        Assert.EndsWith(@"\defrag.exe", SystemCommand.System32("defrag.exe"));
    }
}

public sealed class SystemTweaksTests
{
    [Fact]
    public void Parses_powercfg_list_output()
    {
        const string output = """
            现有电源使用方案 (* Active)
            -----------------------------------
            电源方案 GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (平衡) *
            电源方案 GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (高性能)
            Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)
            """;
        var plans = SystemTweaks.ParsePowerPlans(output);
        Assert.Equal(3, plans.Count);
        Assert.Single(plans, p => p.Active);
        Assert.Equal("平衡", plans[0].Name);
        Assert.Equal(Guid.Parse("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"), plans[1].Id);
        Assert.Equal("Power saver", plans[2].Name);
    }

    [Fact]
    public void Network_fixes_are_fixed_commands()
    {
        var (exe, args, _, reboot) = SystemTweaks.Describe(SystemTweaks.NetworkFix.ResetWinsock);
        Assert.Equal("netsh.exe", exe);
        Assert.Equal("winsock reset", args);
        Assert.True(reboot);
        Assert.False(SystemTweaks.Describe(SystemTweaks.NetworkFix.FlushDns).NeedsReboot);
    }

    [Fact]
    public void Visual_effects_setting_range()
    {
        using var db = CleanSweepDb.InMemory();
        var tweaks = new SystemTweaks(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "vfx-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
        Assert.False(tweaks.SetVisualEffects(7).Success);
        Assert.True(SystemTweaks.GetVisualEffectsSetting() is >= 0 and <= 3);
    }

    [Fact]
    public void Read_only_probes_do_not_throw()
    {
        _ = SystemTweaks.IsHibernateEnabled();
        _ = SystemTweaks.HiberfilBytes();
        var pf = SystemTweaks.GetPageFileInfo();
        Assert.NotNull(pf.Files);
    }
}

public sealed class ServiceTweaksTests
{
    [Fact]
    public void Catalog_is_well_formed()
    {
        Assert.Equal(ServiceTweaks.Catalog.Count, ServiceTweaks.Catalog.Select(c => c.ServiceName).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(ServiceTweaks.Catalog, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Description));
            Assert.False(string.IsNullOrWhiteSpace(c.RestoreHint));
        });
        // 绝不把安全相关服务列进去
        Assert.DoesNotContain(ServiceTweaks.Catalog, c => c.ServiceName is "WinDefend" or "wscsvc" or "EventLog" or "wuauserv" or "BITS" or "Dhcp" or "Dnscache");
    }

    [Fact]
    public void Refuses_services_outside_catalog()
    {
        using var db = CleanSweepDb.InMemory();
        var tweaks = new ServiceTweaks(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "svc-" + Guid.NewGuid().ToString("N")[..6])), new RestorePointService(), new OperationLog(db))
        { CreateRestorePoint = false };
        var (ok, msg) = tweaks.SetManual("wuauserv", true);
        Assert.False(ok);
        Assert.Contains("目录", msg);
    }

    [Fact]
    public void Query_reads_real_services_read_only()
    {
        var states = ServiceTweaks.Query();
        Assert.Equal(ServiceTweaks.Catalog.Count, states.Count);
        Assert.Contains(states, s => s.Installed);
    }
}

public sealed class MemoryManagerTests
{
    [Fact]
    public void Status_has_physical_memory()
    {
        var s = MemoryManager.GetStatus();
        Assert.True(s.TotalBytes > 0);
        Assert.True(s.AvailableBytes > 0 && s.AvailableBytes <= s.TotalBytes);
        Assert.True(s.UsedFraction is > 0 and < 1);
    }

    [Fact]
    public async Task Processes_mark_system_and_self_as_protected()
    {
        var rows = await MemoryManager.ListProcessesAsync(200);
        Assert.NotEmpty(rows);
        var me = rows.Single(r => r.Pid == System.Environment.ProcessId);
        Assert.True(me.IsProtected);
        Assert.Contains(rows, r => r.Pid == 4 && r.IsProtected);
        Assert.All(rows.Where(r => r.Name.Equals("csrss.exe", StringComparison.OrdinalIgnoreCase)), r => Assert.True(r.IsProtected));
    }

    [Fact]
    public void Kill_refuses_protected_rows_without_touching_processes()
    {
        using var db = CleanSweepDb.InMemory();
        var mm = new MemoryManager(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "mm-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
        var row = new ProcessInfoRow(4, "System", null, 0, 0, 0, true, "系统进程", null);
        Assert.Contains("拒绝", mm.Kill(row));
        var self = new ProcessInfoRow(System.Environment.ProcessId, "testhost.exe", null, 0, 0, 0, false, null, null);
        // 即使调用方伪造 IsProtected=false，Kill 也会重新判定并拒绝结束自身
        Assert.NotNull(mm.Kill(self));
    }

    [Fact]
    public void Background_apps_list_from_inventory()
    {
        var inv = FingerprintTests.Snapshot(
            new Inventory.InstalledApp { Id = "uwp:a", Name = "A", Source = Inventory.AppSource.Uwp, PackageFamilyName = "A_x" },
            new Inventory.InstalledApp { Id = "uwp:s", Name = "S", Source = Inventory.AppSource.Uwp, PackageFamilyName = "S_x", IsSystemComponent = true });
        var apps = MemoryManager.ListBackgroundApps(inv);
        Assert.Single(apps);
        Assert.Equal("A_x", apps[0].PackageFamilyName);
    }
}

public sealed class ContextMenuManagerTests
{
    [Fact]
    public void Lists_real_handlers_read_only()
    {
        var handlers = ContextMenuManager.List();
        Assert.All(handlers, h => Assert.True(Guid.TryParse(h.Clsid, out _)));
        Assert.All(handlers, h => Assert.False(string.IsNullOrWhiteSpace(h.Scope)));
    }

    [Fact]
    public void Refuses_invalid_clsid()
    {
        using var db = CleanSweepDb.InMemory();
        var cm = new ContextMenuManager(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "cm-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
        var bad = new ContextMenuHandler("not-a-guid", "x", "s", null, null, Startup.SignatureState.Unknown, false, false, "k", Microsoft.Win32.RegistryView.Registry64, false);
        Assert.False(cm.SetBlocked(bad, true).Success);
    }
}
