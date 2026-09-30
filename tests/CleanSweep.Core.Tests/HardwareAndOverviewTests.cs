using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.SysInfo;
using Xunit;

namespace CleanSweep.Core.Tests;

/// <summary>v0.19：硬件状态、系统工具入口、隔离区概览、清理项说明。</summary>
public class HardwareAndOverviewTests
{
    // ---------------- 硬件状态 ----------------

    [Fact]
    public void NvidiaSmi_csv_output_is_parsed_and_na_fields_are_null()
    {
        var text = "NVIDIA GeForce RTX 4070, 45, 3, 1234, 12282, [N/A], 28.50\r\n" +
                   "NVIDIA T400, 38, 0, 100, 2048, 30, [Not Supported]\r\n";
        var gpus = HardwareStatus.ParseNvidiaSmi(text);
        Assert.Equal(2, gpus.Count);
        Assert.Equal("NVIDIA GeForce RTX 4070", gpus[0].Name);
        Assert.Equal(45, gpus[0].TemperatureC);
        Assert.Equal(3, gpus[0].Utilization);
        Assert.Equal(1234, gpus[0].MemoryUsedMb);
        Assert.Equal(12282, gpus[0].MemoryTotalMb);
        Assert.Null(gpus[0].FanPercent);
        Assert.Equal(28.5, gpus[0].PowerW);
        Assert.Equal(30, gpus[1].FanPercent);
        Assert.Null(gpus[1].PowerW);
    }

    [Fact]
    public void NvidiaSmi_garbage_lines_are_ignored()
    {
        Assert.Empty(HardwareStatus.ParseNvidiaSmi(""));
        Assert.Empty(HardwareStatus.ParseNvidiaSmi("NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver."));
        var one = HardwareStatus.ParseNvidiaSmi("GPU X, 50\n\n   \n");
        Assert.Single(one);
        Assert.Null(one[0].Utilization);
    }

    [Theory]
    [InlineData(@"ACPI\ThermalZone\TZ00_0", "TZ00")]
    [InlineData(@"ACPI\ThermalZone\CPUZ_1", "CPUZ")]
    [InlineData("TZ01", "TZ01")]
    [InlineData("", "?")]
    [InlineData(null, "?")]
    public void Thermal_zone_name_keeps_last_segment_without_index(string? instance, string expected)
        => Assert.Equal(expected, HardwareStatus.ZoneName(instance));

    [Fact]
    public void Hardware_snapshot_can_be_collected_read_only_on_this_machine()
    {
        HardwareStatus.ResetCpuSample();
        var first = HardwareStatus.Collect(includeStorage: false);
        Thread.Sleep(300);
        var snap = HardwareStatus.Collect(includeStorage: false);
        Assert.Contains(snap.Readings, r => r.Group == HardwareStatus.GroupMemory && r.Name == "物理内存" && r.Percent is > 0 and <= 100);
        // 第二次采样有 CPU 基线，占用率应是数字
        var cpu = Assert.Single(snap.Readings, r => r.Group == HardwareStatus.GroupCpu && r.Name == "占用率");
        Assert.NotNull(cpu.Percent);
        Assert.Contains(snap.Readings, r => r.Group == HardwareStatus.GroupThermal);
        Assert.Contains(snap.Readings, r => r.Group == HardwareStatus.GroupPower);
        Assert.DoesNotContain(snap.Readings, r => r.Group == HardwareStatus.GroupStorage);
        Assert.True(first.TakenUtc <= snap.TakenUtc);
    }

    // ---------------- 系统工具 ----------------

    [Fact]
    public void System_tools_table_is_well_formed()
    {
        Assert.Equal(SystemTools.All.Count, SystemTools.All.Select(t => t.Id).Distinct().Count());
        foreach (var t in SystemTools.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Title));
            Assert.False(string.IsNullOrWhiteSpace(t.Description));
            switch (t.Launch)
            {
                case ToolLaunch.Exe:
                    Assert.EndsWith(".exe", t.Target, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain('\\', t.Target);
                    break;
                case ToolLaunch.Msc:
                    Assert.EndsWith(".msc", t.Target, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain('\\', t.Target);
                    Assert.Equal("", t.Args);
                    break;
                case ToolLaunch.SettingsUri:
                    Assert.True(SystemTools.IsAllowedUri(t.Target), t.Target);
                    break;
            }
            // 参数不得含 shell 元字符
            Assert.DoesNotContain(t.Args, ch => ch is '&' or '|' or '>' or '<' or '"');
        }
    }

    [Fact]
    public void System_tools_build_absolute_system32_paths_and_reject_unknown_uris()
    {
        var resmon = SystemTools.Find("resmon")!;
        var psi = SystemTools.Build(resmon, out var err);
        Assert.Null(err);
        Assert.NotNull(psi);
        Assert.Equal(Path.Combine(System.Environment.SystemDirectory, "resmon.exe"), psi!.FileName, ignoreCase: true);
        Assert.True(psi.UseShellExecute);

        var ev = SystemTools.Find("eventvwr")!;
        var mmc = SystemTools.Build(ev, out err);
        Assert.Null(err);
        Assert.Equal(Path.Combine(System.Environment.SystemDirectory, "mmc.exe"), mmc!.FileName, ignoreCase: true);
        Assert.Contains("eventvwr.msc", mmc.Arguments);

        var missing = new SystemTool("x", "x", "x", ToolLaunch.Exe, "definitely-not-here-12345.exe");
        Assert.Null(SystemTools.Build(missing, out err));
        Assert.NotNull(err);

        var web = new SystemTool("w", "w", "w", ToolLaunch.SettingsUri, "https://example.com");
        Assert.Null(SystemTools.Build(web, out err));
        Assert.False(SystemTools.IsAllowedUri("http://ms-settings:storagesense"));
        Assert.True(SystemTools.IsAllowedUri("ms-settings:storagesense"));
        Assert.True(SystemTools.IsAllowedUri("windowsdefender:"));
    }

    // ---------------- 隔离区概览 ----------------

    private static QuarantineEntry Entry(long id, string batch, string original, string quarantinePath, long size, DateTime quarantined, DateTime expires, string module = "system")
        => new(id, batch, module, module + "-item", original, quarantinePath, false, size, quarantined, expires);

    [Fact]
    public void Overview_groups_by_volume_with_expiry_and_expired_counts()
    {
        var now = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        var entries = new[]
        {
            Entry(1, "b1", @"C:\Users\a\x.tmp", @"C:\$CleanSweep.Quarantine\b1\1", 100, now.AddDays(-40), now.AddDays(-10)),
            Entry(2, "b1", @"C:\Users\a\y.tmp", @"C:\$CleanSweep.Quarantine\b1\2", 200, now.AddDays(-5), now.AddDays(25)),
            Entry(3, "b2", @"D:\proj\z.log", @"D:\$CleanSweep.Quarantine\b2\3", 300, now.AddDays(-1), now.AddDays(29), "dev"),
            Entry(4, "b2", @"c:\lower\w.log", @"c:\$CleanSweep.Quarantine\b2\4", 50, now.AddDays(-1), now.AddDays(2), "dev"),
        };
        var vols = QuarantineOverview.ByVolume(entries, now, p => Path.Combine(Path.GetPathRoot(p)!, "$CleanSweep.Quarantine"));
        Assert.Equal(2, vols.Count);
        var c = vols[0];
        Assert.Equal(@"C:\", c.Root, ignoreCase: true);
        Assert.Equal(3, c.Count);
        Assert.Equal(350, c.Bytes);
        Assert.Equal(1, c.ExpiredCount);
        Assert.Equal(100, c.ExpiredBytes);
        Assert.Equal(now.AddDays(2), c.NextExpiryUtc);
        var d = vols[1];
        Assert.Equal(@"D:\", d.Root);
        Assert.Equal(0, d.ExpiredCount);
        Assert.Equal(now.AddDays(29), d.NextExpiryUtc);
        Assert.True(QuarantineOverview.OnVolume(entries[3], @"C:\"));
        Assert.False(QuarantineOverview.OnVolume(entries[2], @"C:\"));
    }

    [Fact]
    public void Overview_groups_by_batch_newest_first_and_keyword_matches_path_or_source()
    {
        var now = DateTime.UtcNow;
        var entries = new[]
        {
            Entry(1, "old", @"C:\a\x.tmp", @"C:\$Q\old\1", 1, now.AddDays(-2), now),
            Entry(2, "new", @"C:\a\y.tmp", @"C:\$Q\new\2", 2, now.AddDays(-1), now, "apps"),
            Entry(3, "new", @"C:\a\z.tmp", @"C:\$Q\new\3", 3, now, now, "system"),
        };
        var batches = QuarantineOverview.ByBatch(entries);
        Assert.Equal(new[] { "new", "old" }, batches.Select(b => b.BatchId));
        Assert.Equal(2, batches[0].Count);
        Assert.Equal(5, batches[0].Bytes);
        Assert.Equal(new[] { "apps", "system" }, batches[0].ModuleIds);
        Assert.Equal(now.AddDays(-1), batches[0].QuarantinedUtc);

        Assert.True(QuarantineOverview.Matches(entries[0], null));
        Assert.True(QuarantineOverview.Matches(entries[0], "  "));
        Assert.True(QuarantineOverview.Matches(entries[0], "X.TMP"));
        Assert.True(QuarantineOverview.Matches(entries[1], "apps-item"));
        Assert.False(QuarantineOverview.Matches(entries[1], "nope"));
    }

    [Fact]
    public void Overview_of_empty_quarantine_is_empty()
    {
        Assert.Empty(QuarantineOverview.ByVolume(Array.Empty<QuarantineEntry>(), DateTime.UtcNow, p => p));
        Assert.Empty(QuarantineOverview.ByBatch(Array.Empty<QuarantineEntry>()));
    }

    // ---------------- 清理项说明 ----------------

    [Fact]
    public void Explanation_for_rule_file_set_mentions_rule_quarantine_and_checks()
    {
        var item = new ScanItem
        {
            Id = "i", ModuleId = "system", Group = "临时文件", DisplayName = "用户临时文件", Kind = ItemKind.FileSet, Path = @"C:\Users\a\AppData\Local\Temp",
            Files = new[] { new FileEntry(@"C:\Users\a\AppData\Local\Temp\a.tmp", 10, DateTime.UtcNow) }, SizeBytes = 10, RuleId = "system.temp",
            PreActions = new[] { "stopService:wuauserv" }, LastWriteUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
        };
        var t = ItemExplanation.For(item, 14, p => @"C:\$CleanSweep.Quarantine");
        Assert.Contains("system.temp", t.Basis);
        Assert.Contains("1 个文件", t.Basis);
        Assert.Contains("2026-01-02", t.Basis);
        Assert.StartsWith("删除这些文件", t.Effect);
        Assert.Contains("重新生成", t.Effect);
        Assert.Contains(@"C:\$CleanSweep.Quarantine", t.Recovery);
        Assert.Contains("14 天", t.Recovery);
        Assert.NotNull(t.Preconditions);
        Assert.Contains("wuauserv", t.Preconditions);
        Assert.Contains("逐个文件核对", t.Preconditions);
    }

    [Fact]
    public void Explanation_for_registry_item_uses_backup_wording_and_missing_path()
    {
        var item = new ScanItem
        {
            Id = "r", ModuleId = "registry", Group = "无效卸载项", DisplayName = "Foo", Kind = ItemKind.RegistryKey, Path = @"HKLM\Software\Foo", Risk = RiskLevel.Confirm,
            MissingPath = @"C:\Program Files\Foo\foo.exe", TargetSnapshot = "abc",
        };
        var t = ItemExplanation.For(item, 30);
        Assert.Contains("注册表清理", t.Basis);
        Assert.Contains(@"C:\Program Files\Foo\foo.exe", t.Basis);
        Assert.Contains("请确认", t.Effect);
        Assert.Contains(".reg", t.Recovery);
        Assert.Contains("备份与还原", t.Recovery);
        Assert.Contains("重新出现则拒绝", t.Preconditions);
        Assert.Contains("被改写则拒绝", t.Preconditions);
    }

    [Fact]
    public void Explanation_for_recycle_bin_and_command_is_not_recoverable_and_has_no_preconditions()
    {
        var rb = new ScanItem { Id = "rb", ModuleId = "system", Group = "g", DisplayName = "回收站", Kind = ItemKind.RecycleBin };
        var t = ItemExplanation.For(rb, 30);
        Assert.Contains("不可恢复", t.Recovery);
        Assert.Null(t.Preconditions);

        var cmd = new ScanItem { Id = "c", ModuleId = "system", Group = "g", DisplayName = "组件清理", Kind = ItemKind.Command, Command = "dism.exe", Risk = RiskLevel.High };
        var tc = ItemExplanation.For(cmd, 30);
        Assert.Contains("不可撤销", tc.Recovery);
        Assert.Contains("只有确定不再需要", tc.Effect);

        // 目录条目：指纹核对
        var dir = new ScanItem { Id = "d", ModuleId = "residue", Group = "g", DisplayName = "Foo 残留", Kind = ItemKind.Directory, Path = @"C:\x", DirectoryFingerprint = "f", DirectoryFileCount = 7 };
        var td = ItemExplanation.For(dir, 30);
        Assert.Contains("残留清理", td.Basis);
        Assert.Contains("7 个文件", td.Basis);
        Assert.Contains("重新核对目录内容", td.Preconditions);
        Assert.Contains("同一磁盘的隔离区", td.Recovery);
    }
}
