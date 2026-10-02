using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Uninstall;

namespace CleanSweep.Core.Tests;

public sealed class OrphanDirectoryTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly Whitelist _whitelist = new();
    private InventorySnapshot _inventory = FingerprintTests.Snapshot();
    private string Owner => Path.Combine(_t.Vars["LocalAppData"], "Gone Tool");
    private string Cache => Path.Combine(Owner, "Cache");
    private readonly List<CleanRule> _rules = [];

    private AppFingerprintDb Fingerprints => AppFingerprintDb.FromJson("""
        { "fingerprints": [
          { "id": "gone", "app": "Gone Tool", "paths": ["%LocalAppData%\\Gone Tool", "%AppData%\\Missing Root"],
            "detect": { "anyOf": [{ "installedName": "Gone Tool" }] },
            "cachePaths": ["%LocalAppData%\\Gone Tool\\Cache"] }
        ] }
        """, "test.json", _t.Guard);

    private ScanContext Context => new() { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist, Rules = _rules };
    private void Record(string name = "Gone Tool 2.0", string? path = null) => new UninstallHistory(_db).Record(
        new InstalledApp { Id = "gone", Name = name, Source = AppSource.Registry, InstallLocation = path }, "test");
    private Task<IReadOnlyList<ScanItem>> Scan(CancellationToken ct = default) =>
        new OrphanDirectoryScanner(_ => _inventory, Fingerprints, new UninstallHistory(_db)).ScanAsync(Context, null, ct);

    [Theory]
    [InlineData("Gone Tool 9.0", 1)]
    [InlineData("Gone Tool Companion", 0)]
    [InlineData("", 0)]
    public async Task Targeted_scan_limits_both_cache_and_recorded_directory_candidates(string name, int expected)
    {
        Record();
        _t.File(Path.Combine(Cache, "cached.bin"));
        var other = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "Other Tool"));
        Record("Other Tool", other);
        Assert.Equal(2, (await Scan()).Count);
        var scanner = new OrphanDirectoryScanner(_ => _inventory, Fingerprints, new UninstallHistory(_db), [name]);
        var items = await scanner.ScanAsync(Context, null, default);
        Assert.Equal(expected, items.Count);
        Assert.DoesNotContain(items, i => i.Path == other);
    }

    [Fact]
    public async Task Targeted_batch_includes_all_requested_apps_and_snapshots_scope()
    {
        Record();
        _t.File(Path.Combine(Cache, "cached.bin"));
        var other = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "Other Tool"));
        Record("Other Tool", other);
        var names = new List<string> { "Gone Tool", "Other Tool" };
        var scanner = new OrphanDirectoryScanner(_ => _inventory, Fingerprints, new UninstallHistory(_db), names);
        names.Clear();
        var items = await scanner.ScanAsync(Context, null, default);
        Assert.Equal(2, items.Count);
        Assert.Contains(items, i => i.Path == other);
    }

    private CleanEngine Engine(Func<CancellationToken, Task<IReadOnlyList<ScanItem>>>? recheck = null) =>
        new(_t.Guard, new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q")), new OperationLog(_db),
            new NullPreActionRunner(), _whitelist, orphanRecheck: recheck);

    [Fact]
    public async Task Known_cache_only_is_quarantined_and_user_data_is_preserved()
    {
        Record();
        var cache = _t.File(Path.Combine(Cache, "cached.bin"));
        var settings = _t.File(Path.Combine(Owner, "settings.json"));
        var save = _t.File(Path.Combine(Owner, "Saves", "game.dat"));
        var login = _t.File(Path.Combine(Owner, "Login Data"));
        var items = await Scan();
        var item = Assert.Single(items);
        Assert.Equal(ItemKind.FileSet, item.Kind);
        Assert.Equal(RiskLevel.Confirm, item.Risk);
        Assert.False(item.DefaultSelected);
        Assert.Contains("卸载记录", item.Description);
        Assert.Equal(cache, Assert.Single(item.Files).Path);
        var report = await Engine(Scan).CleanAsync(items, null, default);
        Assert.Equal(1, report.FilesQuarantined);
        Assert.False(File.Exists(cache));
        Assert.True(File.Exists(settings));
        Assert.True(File.Exists(save));
        Assert.True(File.Exists(login));
        Assert.True(Directory.Exists(Owner));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Gone Tool Companion")]
    public async Task No_history_or_prefix_only_history_is_not_evidence(string? name)
    {
        if (name is not null) Record(name);
        _t.File(Path.Combine(Cache, "cached.bin"));
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Unreliable_inventory_does_not_produce_candidates()
    {
        Record();
        _t.Dir(Owner);
        _inventory = new InventorySnapshot { Apps = [], TakenUtc = DateTime.UtcNow, RegistryCount = 4, RunningExecutables = new HashSet<string>() };
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Installed_application_or_shared_install_location_is_protected()
    {
        Record();
        _t.File(Path.Combine(Cache, "cached.bin"));
        _inventory = FingerprintTests.Snapshot(new InstalledApp { Id = "new", Name = "Gone Tool 3.0", Source = AppSource.Registry });
        Assert.Empty(await Scan());
        _inventory = FingerprintTests.Snapshot(new InstalledApp { Id = "other", Name = "Other App", Source = AppSource.Registry, InstallLocation = Owner });
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Running_portable_application_is_protected()
    {
        Record();
        _t.File(Path.Combine(Cache, "cached.bin"));
        _inventory = new InventorySnapshot { Apps = [], TakenUtc = DateTime.UtcNow, RegistryCount = 50,
            RunningExecutables = new HashSet<string> { Path.Combine(Owner, "tool.exe") } };
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Literal_empty_owner_is_quarantined()
    {
        Record();
        _t.Dir(Owner);
        var items = await Scan();
        Assert.Equal(ItemKind.Directory, Assert.Single(items).Kind);
        var report = await Engine(Scan).CleanAsync(items, null, default);
        Assert.Equal(1, report.DirectoriesQuarantined);
        Assert.False(Directory.Exists(Owner));
    }

    [Fact]
    public async Task Directory_with_even_empty_child_is_not_empty()
    {
        Record();
        _t.Dir(Path.Combine(Owner, "Saves"));
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Junction_cache_and_junction_children_are_never_moved()
    {
        Record();
        _t.Dir(Owner);
        var outside = _t.Dir("Outside");
        var data = _t.File(Path.Combine(outside, "user.dat"));
        Assert.True(TestEnv.TryCreateJunction(Cache, outside));
        Assert.Empty(await Scan());
        Assert.True(File.Exists(data));
    }

    [Fact]
    public async Task Only_exact_recorded_empty_install_location_is_eligible()
    {
        var exact = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "Programs", "Recorded"));
        _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "Programs", "Unknown"));
        Record(path: exact);
        Assert.Equal(exact, Assert.Single(await Scan()).Path);
    }

    [Theory]
    [InlineData("UserProfile", "Documents\\Gone Tool")]
    [InlineData("ProgramData", "Gone Tool")]
    [InlineData("ProgramFiles", "Gone Tool")]
    [InlineData("LocalAppData", "Microsoft\\Gone Tool")]
    [InlineData("LocalAppData", "Packages\\Gone Tool")]
    [InlineData("LocalAppData", "OneDrive\\Gone Tool")]
    [InlineData("LocalAppData", "Programs")]
    public async Task Protected_or_out_of_scope_install_locations_are_not_candidates(string root, string relative)
    {
        var path = _t.Dir(Path.Combine(_t.Vars[root], relative));
        Record(path: path);
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Path_and_item_whitelists_are_respected()
    {
        Record();
        var file = _t.File(Path.Combine(Cache, "cached.bin"));
        var item = Assert.Single(await Scan());
        _whitelist.AddItem(item.Id);
        Assert.Empty(await Scan());
        _whitelist.RemoveItem(item.Id);
        _whitelist.AddPath(file);
        Assert.Empty(await Scan());
    }

    [Fact]
    public async Task Reinstalled_after_scan_is_skipped_before_cleanup()
    {
        Record();
        var file = _t.File(Path.Combine(Cache, "cached.bin"));
        var items = await Scan();
        _inventory = FingerprintTests.Snapshot(new InstalledApp { Id = "new", Name = "Gone Tool", Source = AppSource.Registry });
        var report = await Engine(Scan).CleanAsync(items, null, default);
        Assert.Equal(CleanIssueKind.Changed, Assert.Single(report.SkippedDetails).Kind);
        Assert.Equal(0, report.FilesQuarantined);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task No_verifier_or_failed_verifier_does_not_clean()
    {
        Record();
        var file = _t.File(Path.Combine(Cache, "cached.bin"));
        var items = await Scan();
        foreach (var engine in new[] { Engine(), Engine(_ => throw new IOException("inventory unavailable")) })
        {
            var report = await engine.CleanAsync(items, null, default);
            Assert.Equal(1, report.Skipped);
            Assert.True(File.Exists(file));
        }
    }

    [Fact]
    public async Task Empty_directory_gaining_child_after_recheck_is_preserved()
    {
        Record();
        _t.Dir(Owner);
        var items = await Scan();
        var report = await Engine(async ct =>
        {
            var fresh = await Scan(ct);
            _t.Dir(Path.Combine(Owner, "NewEmptyChild"));
            return fresh;
        }).CleanAsync(items, null, default);
        Assert.Equal(CleanIssueKind.Changed, Assert.Single(report.SkippedDetails).Kind);
        Assert.True(Directory.Exists(Owner));
    }

    [Fact]
    public async Task Cancellation_during_recheck_retains_partial_report_without_cleaning()
    {
        Record();
        var file = _t.File(Path.Combine(Cache, "cached.bin"));
        var items = await Scan();
        var ex = await Assert.ThrowsAsync<CleanCancelledException>(() => Engine(_ => throw new OperationCanceledException()).CleanAsync(items, null, default));
        Assert.True(ex.Report.Cancelled);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task Rules_keep_pattern_age_exclusions_and_rule_whitelist()
    {
        Record("Rule Tool");
        var path = _t.Dir(Path.Combine(_t.Vars["AppData"], "Rule Tool", "Logs"));
        var old = _t.File(Path.Combine(path, "old.log"));
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-10));
        var other = _t.File(Path.Combine(path, "other.log"));
        File.SetLastWriteTimeUtc(other, DateTime.UtcNow.AddDays(-10));
        var excluded = _t.File(Path.Combine(path, "keep.log"));
        File.SetLastWriteTimeUtc(excluded, DateTime.UtcNow.AddDays(-10));
        _t.File(Path.Combine(path, "new.log"));
        _t.File(Path.Combine(path, "settings.json"));
        var target = new RuleTarget(path, path, "*.log", true, RiskLevel.Safe, RuleWhen.Installed, TargetKind.Files,
            "logs", [], null, null, 7, ["keep.log"]);
        _rules.Add(new CleanRule("logs", "Rule Tool", null, "app", new RuleDetect { AnyOf = [new DetectCondition { File = Path.Combine(_t.Root, "absent.exe") }] }, [target], "test"));
        var items = await Scan();
        Assert.Equal(new[] { old, other }.Order(), Assert.Single(items).Files.Select(f => f.Path).Order());
        _rules[0] = _rules[0] with { Targets = [target with { Exclude = ["keep.log", "old.log"] }] };
        var report = await Engine(Scan).CleanAsync(items, null, default);
        Assert.Equal(1, report.Skipped);
        Assert.True(File.Exists(old));
        Assert.True(File.Exists(other));
        _rules[0] = _rules[0] with { Targets = [target] };
        _whitelist.AddRule("logs");
        Assert.Empty(await Scan());
    }

    public void Dispose() { _db.Dispose(); _t.Dispose(); }
}
