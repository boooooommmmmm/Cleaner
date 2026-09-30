using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;

namespace CleanSweep.Core.Tests;

/// <summary>规则路径的通配目录段（"Profile *"、"Packages\*\TempState"）：加载校验、扫描展开、重解析点、条目 ID 与命名。</summary>
public sealed class RuleWildcardTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    private static string Wrap(string rulesJson) => $$"""{ "version": 1, "rules": [ {{rulesJson}} ] }""";

    private RuleLoadResult Load(string path, string kind = "") => new RuleLoader(_t.Guard).LoadJson(Wrap($$"""
        { "id": "w", "app": "W", "category": "system",
          "targets": [ { "path": "{{path.Replace("\\", "\\\\")}}", {{kind}} "risk": "safe", "when": "always", "description": "d" } ] }
        """), "w.json");

    [Theory]
    [InlineData(@"%LocalAppData%\Google\Chrome\User Data\Profile *\Cache")]
    [InlineData(@"%LocalAppData%\Packages\*\TempState")]
    [InlineData(@"%LocalAppData%\Microsoft\VisualStudio\*\ComponentModelCache")]
    [InlineData(@"%LocalAppData%\JetBrains\*\caches")]
    [InlineData(@"%LocalAppData%\Google\AndroidStudio*\log")]
    [InlineData(@"%UserProfile%\Documents\WeChat Files\*\FileStorage\Cache")]
    public void Valid_templates_load_with_wildcard_kept_in_expanded_path(string path)
    {
        var r = Load(path);
        Assert.Empty(r.Rejected);
        var t = Assert.Single(Assert.Single(r.Rules).Targets);
        Assert.True(t.HasWildcard);
        Assert.Contains("*", t.ExpandedPath);
        Assert.DoesNotContain("%", t.ExpandedPath);
    }

    [Theory]
    [InlineData(@"%LocalAppData%\Foo\*", "最后一段")]
    [InlineData(@"%LocalAppData%\*\Cache", "紧跟环境变量")]
    [InlineData(@"%Local*%\Foo\Cache", "环境变量段")]
    [InlineData(@"%LocalAppData%\Foo\*\..\Cache", "..")]
    [InlineData(@"%LocalAppData%\Foo\a?*\Cache", "不允许的字符")]
    [InlineData(@"%Windir%\System32\*\Cache", "Windows 系统目录")]
    [InlineData(@"%ProgramFiles%\Foo\*\Cache", "Program Files")]
    [InlineData(@"%UserProfile%\*\Credentials", "紧跟环境变量")]
    public void Invalid_templates_reject_whole_rule(string path, string reason)
    {
        var r = Load(path);
        Assert.Empty(r.Rules);
        Assert.Contains(r.Rejected, x => x.Reason.Contains(reason));
    }

    [Fact]
    public async Task Scanner_expands_each_matching_directory_skipping_junctions_and_names_items_by_match()
    {
        var local = _t.Vars["LocalAppData"];
        var userData = Path.Combine(local, "Google", "Chrome", "User Data");
        _t.File(Path.Combine(userData, "Default", "Cache", "a.bin"), "aaaa");
        _t.File(Path.Combine(userData, "Profile 1", "Cache", "b.bin"), "bb");
        _t.File(Path.Combine(userData, "Profile 2", "Cache", "c.bin"), "c");
        _t.File(Path.Combine(userData, "Profile 2", "Cache", "sub", "d.bin"), "dd");
        _t.File(Path.Combine(userData, "Profiler", "Cache", "x.bin"), "x"); // 不匹配 "Profile *"
        var external = _t.Dir("external");
        _t.File(Path.Combine(external, "Cache", "outside.bin"), "outside");
        var junction = Path.Combine(userData, "Profile 9");
        var hasJunction = TestEnv.TryCreateJunction(junction, external);

        var rules = new RuleLoader(_t.Guard).LoadJson(Wrap("""
            { "id": "chrome", "app": "Chrome", "category": "browser",
              "detect": { "anyOf": [ { "directory": "%LocalAppData%\\Google\\Chrome\\User Data" } ] },
              "targets": [
                { "path": "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Cache", "pattern": "*", "recurse": true, "risk": "safe", "when": "installed", "description": "网页缓存" },
                { "path": "%LocalAppData%\\Google\\Chrome\\User Data\\Profile *\\Cache", "pattern": "*", "recurse": true, "risk": "safe", "when": "installed", "description": "网页缓存" }
              ] }
            """), "chrome.json");
        Assert.Empty(rules.Rejected);

        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await RuleScanner.AppCache().ScanAsync(ctx, null, default);

        Assert.Equal(3, items.Count);
        Assert.Contains(items, i => i.DisplayName == "网页缓存" && i.Path!.EndsWith(@"\Default\Cache"));
        var p1 = Assert.Single(items, i => i.DisplayName == "网页缓存（Profile 1）");
        var p2 = Assert.Single(items, i => i.DisplayName == "网页缓存（Profile 2）");
        Assert.Equal(2, p2.Files!.Count);
        Assert.Equal(3, p2.SizeBytes);
        Assert.Equal(2, p1.SizeBytes);
        Assert.DoesNotContain(items, i => i.Path!.Contains("Profiler"));
        Assert.Equal(items.Count, items.Select(i => i.Id).Distinct().Count());
        if (hasJunction)
        {
            Assert.DoesNotContain(items, i => i.DisplayName.Contains("Profile 9"));
            Assert.DoesNotContain(items, i => i.Files is { } fs && fs.Any(f => f.Path.Contains("outside")));
        }

        // 同一路径再扫一次 ID 稳定（服务端重扫按 ID 匹配）
        var again = await RuleScanner.AppCache().ScanAsync(ctx, null, default);
        Assert.Equal(items.Select(i => i.Id).OrderBy(x => x), again.Select(i => i.Id).OrderBy(x => x));
    }

    [Fact]
    public async Task Directory_kind_targets_expand_too_and_missing_parents_yield_nothing()
    {
        var local = _t.Vars["LocalAppData"];
        _t.File(Path.Combine(local, "JetBrains", "IntelliJIdea2024.1", "caches", "x"), "1234");
        _t.File(Path.Combine(local, "JetBrains", "PyCharm2024.2", "caches", "y"), "12");
        Directory.CreateDirectory(Path.Combine(local, "JetBrains", "Toolbox"));

        var rules = new RuleLoader(_t.Guard).LoadJson(Wrap("""
            { "id": "jb", "app": "JetBrains", "category": "system",
              "targets": [
                { "path": "%LocalAppData%\\JetBrains\\*\\caches", "kind": "directory", "risk": "confirm", "when": "always", "description": "索引缓存" },
                { "path": "%LocalAppData%\\Nope\\*\\caches", "kind": "directory", "risk": "confirm", "when": "always", "description": "不存在" }
              ] }
            """), "jb.json");
        Assert.Empty(rules.Rejected);
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);

        Assert.Equal(2, items.Count);
        Assert.All(items, i => Assert.Equal(ItemKind.Directory, i.Kind));
        Assert.Contains(items, i => i.DisplayName == "索引缓存（IntelliJIdea2024.1）" && i.SizeBytes == 4);
        Assert.Contains(items, i => i.DisplayName == "索引缓存（PyCharm2024.2）" && i.SizeBytes == 2);
    }

    [Fact]
    public void Expand_wildcards_caps_matches_and_handles_multiple_segments()
    {
        var root = _t.Dir("multi");
        for (var i = 0; i < 5; i++)
            for (var j = 0; j < 2; j++)
                Directory.CreateDirectory(Path.Combine(root, $"pkg{i}", $"ver{j}", "cache"));
        var all = PathGuard.ExpandWildcards(Path.Combine(root, "pkg*", "ver*", "cache"));
        Assert.Equal(10, all.Count);
        Assert.All(all, m => Assert.Matches(@"^pkg\d\\ver\d$", m.Match));
        Assert.All(all, m => Assert.EndsWith(@"\cache", m.Path));
        var capped = PathGuard.ExpandWildcards(Path.Combine(root, "pkg*", "ver*", "cache"), maxMatches: 3);
        Assert.Equal(3, capped.Count);
        Assert.Empty(PathGuard.ExpandWildcards(Path.Combine(root, "zzz*", "cache")));
    }
}
