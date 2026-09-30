using CleanSweep.Core.Environment;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Settings;

namespace CleanSweep.Core.Scanning;

/// <summary>扫描器共享的上下文。</summary>
public sealed class ScanContext
{
    public required IEnvironmentResolver Env { get; init; }
    public required PathGuard Guard { get; init; }
    public required Whitelist Whitelist { get; init; }
    public IReadOnlyList<CleanRule> Rules { get; init; } = Array.Empty<CleanRule>();

    /// <summary>高级模式：显示"不建议"级项目。</summary>
    public bool AdvancedMode { get; init; }
}

public interface IScanner
{
    string Id { get; }
    string DisplayName { get; }
    Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct);
}
