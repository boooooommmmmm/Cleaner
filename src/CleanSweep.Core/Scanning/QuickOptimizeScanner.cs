using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Scanning;

public sealed record QuickOptimizeScope(bool Temp = true, bool WebCache = true, bool Logs = true);

/// <summary>首页的固定保守范围；不会仅凭规则标记 safe 自动扩大清理范围。</summary>
public sealed class QuickOptimizeScanner(QuickOptimizeScope scope) : IScanner
{
    public string Id => "quick-optimize";
    public string DisplayName => "一键优化";

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        if (!ctx.Env.Variables.TryGetValue("LocalAppData", out var local))
            return Task.FromResult<IReadOnlyList<ScanItem>>([]);
        var allowed = new Dictionary<string, (string Rule, int Days)>(StringComparer.OrdinalIgnoreCase);
        if (scope.Temp && ctx.Env.Variables.TryGetValue("Temp", out var temp)
            && PathGuard.IsSameOrUnder(temp, local) && !string.Equals(PathGuard.Normalize(temp), PathGuard.Normalize(local), StringComparison.OrdinalIgnoreCase))
            allowed[PathGuard.Normalize(temp)] = ("windows.temp", 7);
        if (scope.WebCache) allowed[Path.Combine(local, @"Microsoft\Windows\INetCache")] = ("windows.inetcache", 7);
        if (scope.Logs)
        {
            allowed[Path.Combine(local, @"Microsoft\CLR_v4.0\UsageLogs")] = ("windows.clr-usage-logs", 30);
            allowed[Path.Combine(local, @"Microsoft\CLR_v4.0_32\UsageLogs")] = ("windows.clr-usage-logs", 30);
        }

        var rules = ctx.Rules.Where(r => r.Category == "system").Select(r => r with
        {
            Targets = r.Targets.Where(t => t.Kind == TargetKind.Files && t.Risk == RiskLevel.Safe
                && t.When == RuleWhen.Always && t.PreActions.Count == 0 && !t.HasWildcard
                && t.ExpandedPath is { } p && allowed.TryGetValue(PathGuard.Normalize(p), out var entry)
                && entry.Rule == r.Id && Directory.Exists(p) && ctx.Guard.VerifyPhysical(p).Allowed)
                .Select(t => t with { MinAgeDays = Math.Max(t.MinAgeDays, allowed[PathGuard.Normalize(t.ExpandedPath!)].Days) }).ToArray(),
        }).Where(r => r.Targets.Count > 0).ToArray();
        var narrowed = new ScanContext { Env = ctx.Env, Guard = ctx.Guard, Whitelist = ctx.Whitelist, Rules = rules, AdvancedMode = false };
        // 复用系统清理条目身份，尊重用户此前加入白名单的项目。
        return RuleScanner.SystemJunk().ScanAsync(narrowed, progress, ct);
    }
}
