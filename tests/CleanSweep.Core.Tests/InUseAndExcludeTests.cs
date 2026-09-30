using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 2026-09-30 真机反馈：显卡着色器缓存与开始菜单磁贴缓存被进程独占，清理结果弹出一整屏"失败"；
/// 磁盘页在普通权限下点"碎片整理"看起来没反应（defrag 打印权限不足但退出码 0，被当成完成）。
/// </summary>
public sealed class InUseAndExcludeTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly CleanEngine _engine;
    private readonly OperationLog _log;

    public InUseAndExcludeTests()
    {
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"));
        _log = new OperationLog(_db);
        _engine = new CleanEngine(_t.Guard, q, _log, new NullPreActionRunner());
    }

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private static FileEntry Snapshot(string path)
    {
        var fi = new FileInfo(path);
        return new FileEntry(fi.FullName, fi.Length, fi.LastWriteTimeUtc);
    }

    [Fact]
    public async Task Locked_file_counts_as_in_use_skip_not_failure_and_item_stays_incomplete()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "NVIDIA", "DXCache");
        var locked = _t.File(Path.Combine(root, "a.nvph"), "aaaa");
        var free = _t.File(Path.Combine(root, "b.nvph"), "bb");
        var item = new ScanItem
        {
            Id = "dx", ModuleId = "test", Group = "g", DisplayName = "着色器缓存", Kind = ItemKind.FileSet,
            Path = root, Files = new[] { Snapshot(locked), Snapshot(free) }, SizeBytes = 6,
        };

        CleanReport report;
        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            report = await _engine.CleanAsync(new[] { item }, null, default);
        }

        Assert.Empty(report.Failures);
        Assert.Equal(1, report.InUse);
        var inUse = Assert.Single(report.InUseFiles);
        Assert.Equal(locked, inUse.Path, ignoreCase: true);
        Assert.Contains("正在被其他程序使用", inUse.Reason);
        Assert.Equal(1, report.FilesQuarantined);
        Assert.Equal(0, report.Skipped);
        Assert.True(File.Exists(locked));
        Assert.False(File.Exists(free));
        Assert.Contains("dx", report.IncompleteItemIds);
        Assert.Empty(report.FailedItemIds);
        var rec = _log.GetOperations().Single(e => e.Target is not null && e.Target.EndsWith("a.nvph", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("skip", rec.Action);
        Assert.True(rec.Success);
    }

    [Fact]
    public void FileInUse_recognises_both_win32_and_hresult_forms_but_not_access_denied()
    {
        Assert.True(FileInUse.Is(new IOException("x", 32)));
        Assert.True(FileInUse.Is(new IOException("x", 33)));
        Assert.True(FileInUse.Is(new IOException("x", unchecked((int)0x80070020))));
        Assert.True(FileInUse.Is(new InvalidOperationException("outer", new IOException("x", 32))));
        Assert.False(FileInUse.Is(new IOException("x", 5)));
        Assert.False(FileInUse.Is(new UnauthorizedAccessException()));
        Assert.False(FileInUse.Is(new IOException("x", 2)));
        Assert.False(FileInUse.Is(null));
    }

    [Theory]
    [InlineData(@"无法打开源对象：另一个程序正在使用此文件，进程无法访问。（C:\x\a.bin）", @"C:\x\a.bin", "无法打开源对象：另一个程序正在使用此文件，进程无法访问")]
    [InlineData(@"Access to the path 'C:\x\a.bin' is denied.", @"C:\x\a.bin", @"Access to the path 'C:\x\a.bin' is denied.")]
    [InlineData(@"护栏拒绝：受保护目录", @"C:\x\a.bin", @"护栏拒绝：受保护目录")]
    [InlineData(@"移动失败：xx（C:\x\a.bin → D:\q\a.bin）", @"C:\x\a.bin", @"移动失败：xx（C:\x\a.bin → D:\q\a.bin）")]
    public void Fail_reason_drops_duplicated_trailing_path(string reason, string path, string expected)
    {
        Assert.Equal(expected, CleanEngine.StripPathSuffix(reason, path));
        Assert.Equal(reason, CleanEngine.StripPathSuffix(reason, null));
    }

    private static string Wrap(string rulesJson) => $$"""{ "version": 1, "rules": [ {{rulesJson}} ] }""";

    [Fact]
    public async Task Exclude_patterns_drop_matching_file_names_at_scan_time()
    {
        var local = _t.Vars["LocalAppData"];
        var pkg = Path.Combine(local, "Packages", "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy", "TempState");
        var old = DateTime.UtcNow.AddDays(-3);
        foreach (var name in new[] { "TileCache_200_4_PNGEncoded_Data.bin", "TileCache_200_4_PNGEncoded_Header.bin", "other.tmp", "sub\\TileCache_1.bin", "sub\\keep.log" })
        {
            var f = _t.File(Path.Combine(pkg, name), "1234");
            File.SetLastWriteTimeUtc(f, old);
        }

        var rules = new RuleLoader(_t.Guard).LoadJson(Wrap("""
            { "id": "uwp", "app": "UWP", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\Packages\\*\\TempState", "pattern": "*", "recurse": true, "risk": "safe", "when": "always", "description": "临时", "minAgeDays": 1, "exclude": ["TileCache_*"] } ] }
            """), "uwp.json");
        Assert.Empty(rules.Rejected);
        Assert.Equal(new[] { "TileCache_*" }, Assert.Single(Assert.Single(rules.Rules).Targets).Exclude);

        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);
        var item = Assert.Single(items);
        Assert.Equal(2, item.Files!.Count);
        Assert.All(item.Files, f => Assert.DoesNotContain("TileCache", f.Path));
        Assert.Equal(8, item.SizeBytes);
    }

    [Theory]
    [InlineData("""{ "path": "%LocalAppData%\\Foo\\Cache", "pattern": "*", "risk": "safe", "when": "always", "description": "d", "exclude": ["sub\\a.bin"] }""", "路径分隔符")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo\\Cache", "pattern": "*", "risk": "safe", "when": "always", "description": "d", "exclude": ["*"] }""", "不得为 *")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo\\Cache", "pattern": "*", "risk": "safe", "when": "always", "description": "d", "exclude": [" "] }""", "空模式")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo\\Cache", "kind": "directory", "risk": "confirm", "when": "always", "description": "d", "exclude": ["x"] }""", "只对 files")]
    public void Invalid_exclude_rejects_rule(string target, string reason)
    {
        var r = new RuleLoader(_t.Guard).LoadJson(Wrap($$"""{ "id": "e", "app": "E", "category": "system", "targets": [ {{target}} ] }"""), "e.json");
        Assert.Empty(r.Rules);
        Assert.Contains(r.Rejected, x => x.Reason.Contains(reason));
    }

    [Fact]
    public void Bundled_uwp_tempstate_rule_excludes_tile_cache()
    {
        var rules = new RuleLoader(_t.Guard).LoadDirectory(Path.Combine(AppContext.BaseDirectory, "rules"));
        Assert.Empty(rules.Rejected);
        var uwp = Assert.Single(rules.Rules, r => r.Id == "windows.uwp-temp");
        var temp = Assert.Single(uwp.Targets, t => t.RawPath!.EndsWith("\\TempState", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("TileCache_*", temp.Exclude);
    }

    [Fact]
    public void Defrag_error_in_output_turns_zero_exit_into_failure()
    {
        var unprivileged = new CommandResult(0, "The storage optimizer cannot start because you have insufficient privileges to perform this operation. (0x89000024)", TimeSpan.FromSeconds(1), false);
        var fixedUp = DiskHealth.Normalize(unprivileged);
        Assert.False(fixedUp.Success);
        Assert.Equal(unchecked((int)0x89000024), fixedUp.ExitCode);
        Assert.Contains("管理员", DiskHealth.DescribeExitCode(fixedUp.ExitCode));

        Assert.Equal(unchecked((int)0x89000001), DiskHealth.ParseDefragError("The given volume path is invalid. (0x89000001)"));
        Assert.Null(DiskHealth.ParseDefragError("Pre-Optimization Report:\n  Volume Information:\n  Total = 476.31 GB"));
        Assert.Null(DiskHealth.ParseDefragError(null));

        var ok = new CommandResult(0, "The operation completed successfully.", TimeSpan.FromSeconds(1), false);
        Assert.Same(ok, DiskHealth.Normalize(ok));
        var already = new CommandResult(1, "(0x89000024)", TimeSpan.Zero, false);
        Assert.Equal(1, DiskHealth.Normalize(already).ExitCode);
        Assert.Null(DiskHealth.DescribeExitCode(1));

        Assert.True(DiskHealth.RequiresElevation(DiskHealth.DiskOperation.Defragment));
        Assert.True(DiskHealth.RequiresElevation(DiskHealth.DiskOperation.Analyze));
        Assert.True(DiskHealth.RequiresElevation(DiskHealth.DiskOperation.ScheduleCheckDisk));
        Assert.False(DiskHealth.RequiresElevation(DiskHealth.DiskOperation.QueryCheckDisk));
    }
}
