using CleanSweep.Core.Inventory;
using CleanSweep.Core.Popup;
using CleanSweep.Core.Rules;

namespace CleanSweep.Core.Tests;

/// <summary>内置数据集的覆盖面与一致性：2026-09-30 扩展后的规模下限、类别分布、新增规则的路径边界。</summary>
public sealed class DataCoverageTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    private static string BundledDir(string kind) => Path.Combine(AppContext.BaseDirectory, kind);

    [Fact]
    public void Bundled_rules_cover_all_four_categories_with_expected_scale()
    {
        var r = new RuleLoader(_t.Guard).LoadDirectory(BundledDir("rules"));
        Assert.Empty(r.Rejected);
        Assert.True(r.Rules.Count >= 60, $"规则数 {r.Rules.Count}");
        var byCategory = r.Rules.GroupBy(x => x.Category).ToDictionary(g => g.Key, g => g.Count());
        Assert.True(byCategory["browser"] >= 10, "浏览器规则应覆盖 Chromium 系主流分支与国内浏览器");
        Assert.True(byCategory["app"] >= 18);
        Assert.True(byCategory["dev"] >= 18);
        Assert.True(byCategory["system"] >= 13);
        Assert.Contains(r.Rules, x => x.Id == "tencent.qqbrowser");
        Assert.Contains(r.Rules, x => x.Id == "gpu.shader-cache");
        Assert.Contains(r.Rules, x => x.Id == "dev.uv");
        Assert.Contains(r.Rules, x => x.Id == "cursor");
    }

    [Fact]
    public void New_installed_only_app_rules_do_not_duplicate_fingerprint_residue_paths()
    {
        // 已有指纹的应用，其规则只含"已安装"缓存目标：残留由指纹库负责，避免残留页同一目录列两次
        var rules = new RuleLoader(_t.Guard).LoadDirectory(BundledDir("rules")).Rules;
        var fps = AppFingerprintDb.LoadDirectory(BundledDir("fingerprints"), _t.Guard);
        Assert.Empty(fps.Rejected);
        Assert.True(fps.Fingerprints.Count >= 65, $"指纹数 {fps.Fingerprints.Count}");

        var fpPaths = new HashSet<string>(fps.Fingerprints.SelectMany(f => f.RawPaths), StringComparer.OrdinalIgnoreCase);
        var newRuleIds = new[] { "slack", "zoom", "telegram.desktop", "notion", "obsidian", "postman", "figma", "cursor", "epic.games-launcher", "obs.studio", "netease.cloudmusic",
            "opera.browser", "opera.gx", "vivaldi.browser", "chromium.browser", "qihoo.360chrome", "qihoo.360se", "tencent.qqbrowser" };
        foreach (var id in newRuleIds)
        {
            var rule = Assert.Single(rules, x => x.Id == id);
            Assert.All(rule.Targets, t => Assert.Equal(RuleWhen.Installed, t.When));
            Assert.All(rule.Targets, t => Assert.DoesNotContain(t.RawPath!, fpPaths));
        }
    }

    [Fact]
    public void System_rules_without_detect_only_target_local_caches()
    {
        var rules = new RuleLoader(_t.Guard).LoadDirectory(BundledDir("rules")).Rules;
        foreach (var rule in rules.Where(x => x.Category == "system" && x.Detect is null))
        {
            foreach (var t in rule.Targets.Where(t => t.RawPath is not null))
            {
                Assert.Equal(RuleWhen.Always, t.When);
                Assert.True(t.RawPath!.StartsWith("%LocalAppData%\\", StringComparison.OrdinalIgnoreCase)
                            || t.RawPath.StartsWith("%Windir%\\", StringComparison.OrdinalIgnoreCase)
                            || t.RawPath.StartsWith("%ProgramData%\\", StringComparison.OrdinalIgnoreCase)
                            || t.RawPath.StartsWith("%SystemDrive%\\", StringComparison.OrdinalIgnoreCase)
                            || t.RawPath.StartsWith("%Temp%", StringComparison.OrdinalIgnoreCase),
                    $"{rule.Id}: {t.RawPath}");
                // 不带检测条件的系统规则不得把 Roaming 配置当缓存
                Assert.DoesNotContain("%AppData%", t.RawPath, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void Popup_rules_stay_generic_and_each_has_class_or_title()
    {
        using var db = Storage.CleanSweepDb.InMemory();
        var blocker = new PopupBlocker(new Backup.RegistryBackup(db, Path.Combine(_t.Root, "popup-backups")), new Storage.OperationLog(db));
        blocker.LoadDirectory(BundledDir("popups"));
        Assert.Empty(blocker.Rejected);
        Assert.True(blocker.Rules.Count >= 3);
        Assert.All(blocker.Rules, r => Assert.True(r.WindowClass is not null || r.WindowTitle is not null));
        Assert.True(blocker.BlockableProcesses.Count >= 8);
        Assert.All(blocker.BlockableProcesses, p => Assert.EndsWith(".exe", p, StringComparison.OrdinalIgnoreCase));
    }
}
