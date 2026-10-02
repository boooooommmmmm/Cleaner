using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class BaiduNetdiskTempTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly Whitelist _whitelist = new();
    private string Root => Path.Combine(_t.Vars["UserProfile"], "Documents", "BaiduNetdiskTmp");

    private ScanContext Context()
    {
        var loaded = new RuleLoader(_t.Guard).LoadDirectory(Path.Combine(AppContext.BaseDirectory, "rules"));
        Assert.Empty(loaded.Rejected);
        var rule = Assert.Single(loaded.Rules, r => r.Id == "baidu.netdisk-temp-nodes");
        return new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist, Rules = [rule] };
    }

    private Task<IReadOnlyList<ScanItem>> Scan() => new ScanScheduler().RunAsync([RuleScanner.AppCache()], Context(), null, default);

    private string Old(string path)
    {
        var file = _t.File(path);
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddDays(-10));
        return file;
    }

    [Fact]
    public async Task Only_old_top_level_tmp_node_files_are_offered_without_installation_detection()
    {
        var expected = Old(Path.Combine(Root, "70fbcc6a-1ea8-4918-b8fb-a6c34e87de59.tmp.node"));
        _t.File(Path.Combine(Root, "recent.tmp.node"));
        Old(Path.Combine(Root, "download.baiduyun.p.downloading"));
        Old(Path.Combine(Root, "report.docx"));
        Old(Path.Combine(Root, "component.node"));
        Old(Path.Combine(Root, "component.tmp.node.bak"));
        Old(Path.Combine(Root, "Subfolder", "old.tmp.node"));
        Old(Path.Combine(_t.Vars["UserProfile"], "Documents", "personal.tmp.node"));
        Old(Path.Combine(_t.Vars["UserProfile"], "Documents", "BaiduNetdiskTmp-other", "old.tmp.node"));
        var item = Assert.Single(await Scan());
        Assert.Equal(expected, Assert.Single(item.Files).Path);
        Assert.Equal(ItemKind.FileSet, item.Kind);
        Assert.Equal(RiskLevel.Confirm, item.Risk);
        Assert.False(item.DefaultSelected);
        Assert.Equal("百度网盘", item.Group);
        Assert.Contains("退出网盘", item.Description);
    }

    [Fact]
    public async Task Empty_or_missing_directory_is_not_offered()
    {
        Assert.Empty(await Scan());
        _t.Dir(Root);
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Same_named_plain_file_is_preserved_and_rule_detection_also_protects_old_clients()
    {
        var file = Old(Root);
        var ctx = Context();
        var rule = Assert.Single(ctx.Rules);
        // 旧客户端只要应用 installed 检测，也会拒绝目录位置的普通文件。
        Assert.NotNull(rule.Detect);
        Assert.Equal(RuleWhen.Installed, Assert.Single(rule.Targets).When);
        Assert.False(RegistryDetect.IsInstalled(rule.Detect, _t.Env));
        var items = await Scan();
        Assert.Empty(items);
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new NullPreActionRunner(), _whitelist);
        Assert.Equal(0, (await engine.CleanAsync(items, null, default)).FilesQuarantined);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task Whitelisted_files_and_rules_are_excluded()
    {
        var file = Old(Path.Combine(Root, "old.tmp.node"));
        _whitelist.AddPath(file);
        Assert.Empty(await Scan());
        _whitelist.RemovePath(file);
        _whitelist.AddRule("baidu.netdisk-temp-nodes");
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Junction_to_other_data_is_not_scanned()
    {
        var outside = _t.Dir("Outside");
        var file = Old(Path.Combine(outside, "personal.tmp.node"));
        _t.Dir(Path.GetDirectoryName(Root)!);
        Assert.True(TestEnv.TryCreateJunction(Root, outside));
        Assert.Empty(await Scan());
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task Cleanup_moves_only_selected_snapshot_and_preserves_changed_files()
    {
        var eligible = Old(Path.Combine(Root, "old.tmp.node"));
        var changed = Old(Path.Combine(Root, "changed.tmp.node"));
        var document = Old(Path.Combine(Root, "document.txt"));
        var items = await Scan();
        File.AppendAllText(changed, "new content");
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new NullPreActionRunner(), _whitelist);
        var result = await engine.CleanAsync(items, null, default);
        Assert.Equal(1, result.FilesQuarantined);
        Assert.False(File.Exists(eligible));
        Assert.True(File.Exists(changed));
        Assert.True(File.Exists(document));
        Assert.True(Directory.Exists(Root));
        Assert.Equal(CleanIssueKind.Changed, Assert.Single(result.SkippedDetails).Kind);
    }

    public void Dispose() => _t.Dispose();
}
