using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class QuickOptimizeTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly Whitelist _white = new();
    private string Cache => Path.Combine(_t.Vars["LocalAppData"], @"Microsoft\Windows\INetCache");
    private string Logs => Path.Combine(_t.Vars["LocalAppData"], @"Microsoft\CLR_v4.0\UsageLogs");
    private IReadOnlyList<CleanRule> Rules => new RuleLoader(_t.Guard).LoadDirectory(Path.Combine(AppContext.BaseDirectory, "rules")).Rules;
    private ScanContext Context(IReadOnlyList<CleanRule>? rules = null) => new()
    { Env = _t.Env, Guard = _t.Guard, Whitelist = _white, Rules = rules ?? Rules, AdvancedMode = true };
    private Task<IReadOnlyList<ScanItem>> Scan(QuickOptimizeScope? scope = null, IReadOnlyList<CleanRule>? rules = null) =>
        new ScanScheduler().RunAsync([new QuickOptimizeScanner(scope ?? new())], Context(rules), null, default);
    private string Old(string root, string name = "old.tmp", int days = 40)
    {
        var path = _t.File(Path.Combine(root, name));
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-days));
        return path;
    }

    [Fact]
    public async Task Default_scope_only_includes_old_files_in_the_three_allowed_locations()
    {
        var expected = new[] { Old(_t.Vars["Temp"]), Old(Cache), Old(Logs) };
        Old(_t.Vars["Temp"], "recent.tmp", 6);
        Old(Cache, "recent.tmp", 6);
        Old(Logs, "recent.log", 29);
        Old(Path.Combine(_t.Vars["Windir"], "Temp"));
        Old(Path.Combine(_t.Vars["LocalAppData"], "D3DSCache"));
        Old(Path.Combine(_t.Vars["UserProfile"], "Documents", "BaiduNetdiskTmp"), "old.tmp.node");
        var items = await Scan();
        Assert.Equal(expected.Order(), items.SelectMany(i => i.Files).Select(f => f.Path).Order());
        Assert.All(items, i => { Assert.Equal(RiskLevel.Safe, i.Risk); Assert.Equal(ItemKind.FileSet, i.Kind); Assert.Empty(i.PreActions); });
    }

    [Theory]
    [InlineData(true, false, false, "windows.temp")]
    [InlineData(false, true, false, "windows.inetcache")]
    [InlineData(false, false, true, "windows.clr-usage-logs")]
    [InlineData(false, false, false, null)]
    public async Task Only_checked_scopes_are_returned(bool temp, bool cache, bool logs, string? id)
    {
        Old(_t.Vars["Temp"]); Old(Cache); Old(Logs);
        var result = await Scan(new(temp, cache, logs));
        if (id is null) Assert.Empty(result);
        else Assert.Equal(id, Assert.Single(result).RuleId);
    }

    [Fact]
    public async Task Future_rule_changes_cannot_add_commands_risky_targets_preactions_or_other_paths()
    {
        Old(_t.Vars["Temp"]);
        var rule = Rules.Single(r => r.Id == "windows.temp");
        var target = rule.Targets[0];
        var other = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "Personal"));
        Old(other);
        var altered = rule with { Targets = [
            target with { Risk = RiskLevel.Confirm },
            target with { Kind = TargetKind.Directory },
            target with { Kind = TargetKind.Command, Command = "dism.exe" },
            target with { PreActions = ["stopService:wuauserv"] },
            target with { ExpandedPath = other },
            target with { When = RuleWhen.Installed },
        ] };
        Assert.Empty(await Scan(rules: [altered]));
        Assert.Empty(await Scan(rules: [rule with { Id = "new.safe.rule", Targets = [target] }]));
    }

    [Fact]
    public async Task Rule_age_constraints_can_be_stricter_than_home_defaults()
    {
        Old(_t.Vars["Temp"], days: 40);
        var rule = Rules.Single(r => r.Id == "windows.temp");
        Assert.Empty(await Scan(rules: [rule with { Targets = [rule.Targets[0] with { MinAgeDays = 60 }] }]));
    }

    [Fact]
    public async Task A_plain_file_in_place_of_the_cache_directory_is_not_offered()
    {
        Old(Path.GetDirectoryName(Cache)!, Path.GetFileName(Cache));
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task A_junction_in_place_of_the_cache_directory_is_not_followed()
    {
        var outside = _t.Dir("Outside");
        Old(outside);
        _t.Dir(Path.GetDirectoryName(Cache)!);
        Assert.True(TestEnv.TryCreateJunction(Cache, outside));
        Assert.Empty(await Scan());
    }

    [Theory]
    [InlineData("item")]
    [InlineData("rule")]
    [InlineData("path")]
    public async Task Existing_system_cleaner_whitelist_is_respected(string kind)
    {
        var file = Old(_t.Vars["Temp"]);
        var normal = Assert.Single(await new ScanScheduler().RunAsync([RuleScanner.SystemJunk()], Context(Rules.Where(r => r.Id == "windows.temp").ToArray()), null, default));
        if (kind == "item") _white.AddItem(normal.Id);
        if (kind == "rule") _white.AddRule(normal.RuleId!);
        if (kind == "path") _white.AddPath(file);
        Assert.Empty(await Scan());
    }

    [Theory]
    [InlineData("item")]
    [InlineData("rule")]
    [InlineData("path")]
    public async Task Whitelist_added_after_scan_prevents_cleanup_and_preactions(string kind)
    {
        var file = Old(_t.Vars["Temp"]);
        var item = Assert.Single(await Scan()) with { PreActions = ["stopService:wuauserv"] };
        if (kind == "item") _white.AddItem(item.Id);
        if (kind == "rule") _white.AddRule(item.RuleId!);
        if (kind == "path") _white.AddPath(item.Path!);
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new RejectPreActions(), _white);
        var result = await engine.CleanAsync([item], null, default);
        Assert.True(File.Exists(file));
        Assert.Equal(0, result.FilesQuarantined);
        Assert.Contains("白名单", Assert.Single(result.SkippedDetails).Reason);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public async Task End_to_end_quarantine_counts_bytes_without_claiming_freed_space_and_keeps_changed_files()
    {
        var old = Old(_t.Vars["Temp"]);
        var changed = Old(_t.Vars["Temp"], "changed.tmp");
        var items = await Scan();
        var expectedBytes = new FileInfo(old).Length;
        File.AppendAllText(changed, "changed since scan");
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new RejectPreActions(), _white);
        var result = await engine.CleanAsync(items, null, default);
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(changed));
        Assert.Equal(1, result.FilesQuarantined);
        Assert.Equal(expectedBytes, result.QuarantinedBytes);
        Assert.Equal(0, result.FreedBytes);
        Assert.Equal(CleanIssueKind.Changed, Assert.Single(result.SkippedDetails).Kind);
    }

    private sealed class RejectPreActions : IPreActionRunner
    {
        public IDisposable? Run(string action, out string? error) => throw new InvalidOperationException("Must not run preactions");
    }
    public void Dispose() => _t.Dispose();
}
