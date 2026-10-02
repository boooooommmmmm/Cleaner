using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;

namespace CleanSweep.Core.Tests;

public sealed class SingleFileRuleTests : IDisposable
{
    private readonly TestEnv _t = new();

    [Theory]
    [InlineData("BaiduNetdiskTmp", "*.tmp.node", false, false)]
    [InlineData("old.tmp.node", "*.tmp.node", false, true)]
    [InlineData("old.tmp.node", "*.tmp.node", true, false)]
    [InlineData("MEMORY.DMP", null, false, true)]
    [InlineData("MEMORY.DMP", "*.log;*.DMP", false, true)]
    public async Task Single_file_targets_obey_pattern_and_exclusion_without_breaking_explicit_files(string name, string? pattern, bool exclude, bool expected)
    {
        var file = _t.File(Path.Combine(_t.Vars["Temp"], name));
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddDays(-10));
        var target = new RuleTarget(file, file, pattern, false, RiskLevel.Safe, RuleWhen.Always,
            TargetKind.Files, "test", [], null, null, 7, exclude ? ["old.*"] : []);
        var rule = new CleanRule("single", "test", null, "system", null, [target], "test");
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = [rule] };
        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);
        Assert.Equal(expected ? 1 : 0, items.Count);
        Assert.True(File.Exists(file));
    }

    public void Dispose() => _t.Dispose();
}
