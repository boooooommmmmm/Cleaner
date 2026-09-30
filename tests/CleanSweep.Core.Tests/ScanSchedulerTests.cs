using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;

namespace CleanSweep.Core.Tests;

public sealed class ScanSchedulerTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    private sealed class FakeScanner : IScanner
    {
        private readonly IReadOnlyList<ScanItem> _items;
        public FakeScanner(params ScanItem[] items) => _items = items;
        public string Id => "fake";
        public string DisplayName => "Fake";
        public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) => Task.FromResult(_items);
    }

    private ScanContext Ctx(Whitelist wl, bool advanced = false) => new()
    {
        Env = _t.Env, Guard = _t.Guard, Whitelist = wl, AdvancedMode = advanced,
    };

    [Fact]
    public async Task NotRecommended_HiddenUnlessAdvanced()
    {
        var item = new ScanItem { Id = "a", ModuleId = "m", Group = "g", DisplayName = "x", Kind = ItemKind.Command, Command = "dism.exe", Risk = RiskLevel.NotRecommended };
        var s = new ScanScheduler();

        var normal = await s.RunAsync(new[] { new FakeScanner(item) }, Ctx(new Whitelist()), null, default);
        var advanced = await s.RunAsync(new[] { new FakeScanner(item) }, Ctx(new Whitelist(), advanced: true), null, default);

        Assert.Empty(normal);
        Assert.Single(advanced);
    }

    [Fact]
    public async Task Whitelist_RemovesFilesUnderExcludedPath()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "App");
        var keep = new FileEntry(Path.Combine(root, "Cache", "a.bin"), 10, DateTime.UtcNow);
        var excluded = new FileEntry(Path.Combine(root, "Important", "b.bin"), 20, DateTime.UtcNow);
        var item = new ScanItem { Id = "a", ModuleId = "m", Group = "g", DisplayName = "x", Path = root, Files = new[] { keep, excluded }, SizeBytes = 30 };

        var wl = new Whitelist();
        wl.AddPath(Path.Combine(root, "Important"));

        var result = await new ScanScheduler().RunAsync(new[] { new FakeScanner(item) }, Ctx(wl), null, default);

        var only = Assert.Single(result);
        Assert.Single(only.Files);
        Assert.Equal(10, only.SizeBytes);
    }

    [Fact]
    public async Task Whitelist_ByItemId_RemovesItem()
    {
        var item = new ScanItem { Id = "abc", ModuleId = "m", Group = "g", DisplayName = "x", Kind = ItemKind.RecycleBin, SizeBytes = 1 };
        var wl = new Whitelist();
        wl.AddItem("abc");

        var result = await new ScanScheduler().RunAsync(new[] { new FakeScanner(item) }, Ctx(wl), null, default);

        Assert.Empty(result);
    }

    [Fact]
    public async Task RuleScanner_SystemJunk_FindsFilesInTemp()
    {
        var temp = _t.Vars["Temp"];
        _t.File(Path.Combine(temp, "a.tmp"), "1234");
        _t.File(Path.Combine(temp, "deep", "b.tmp"), "12");

        var rules = new RuleLoader(_t.Guard).LoadJson("""
            { "rules": [ { "id": "sys.temp", "app": "Temp", "category": "system",
              "targets": [ { "path": "%Temp%", "pattern": "*", "recurse": true, "risk": "safe", "when": "always", "description": "temp" } ] } ] }
            """, "t.json");
        Assert.Empty(rules.Rejected);

        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await new ScanScheduler().RunAsync(new[] { RuleScanner.SystemJunk() }, ctx, null, default);

        var item = Assert.Single(items);
        Assert.Equal(2, item.FileCount);
        Assert.Equal(6, item.SizeBytes);
        Assert.True(item.DefaultSelected);
    }

    [Fact]
    public async Task RuleScanner_AppCache_SkipsUninstalledApp()
    {
        var cache = Path.Combine(_t.Vars["LocalAppData"], "Ghost", "Cache");
        _t.File(Path.Combine(cache, "x.bin"));

        var rules = new RuleLoader(_t.Guard).LoadJson("""
            { "rules": [ { "id": "ghost", "app": "Ghost", "category": "app",
              "detect": { "anyOf": [ { "file": "%LocalAppData%\\Ghost\\ghost.exe" } ] },
              "targets": [
                { "path": "%LocalAppData%\\Ghost\\Cache", "pattern": "*", "risk": "safe", "when": "installed" },
                { "path": "%LocalAppData%\\Ghost", "kind": "directory", "risk": "high", "when": "uninstalled" } ] } ] }
            """, "g.json");
        Assert.Empty(rules.Rejected);

        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await new ScanScheduler().RunAsync(new[] { RuleScanner.AppCache() }, ctx, null, default);

        // 应用未安装：installed 目标不生效；uninstalled 目标属于 M3 残留模块，AppCache 扫描器不产出
        Assert.Empty(items);

        _t.File(Path.Combine(_t.Vars["LocalAppData"], "Ghost", "ghost.exe"));
        items = await new ScanScheduler().RunAsync(new[] { RuleScanner.AppCache() }, ctx, null, default);
        Assert.Single(items);
    }
}
