using CleanSweep.Core.Model;

namespace CleanSweep.Core.Scanning;

/// <summary>按条件过滤另一个扫描器的结果（例如"只看某个应用"的定向残留扫描要同时约束规则库扫描器与启发式扫描器）。</summary>
public sealed class FilteredScanner : IScanner
{
    private readonly IScanner _inner;
    private readonly Func<ScanItem, bool> _keep;

    public FilteredScanner(IScanner inner, Func<ScanItem, bool> keep)
    {
        _inner = inner;
        _keep = keep;
    }

    public string Id => _inner.Id;
    public string DisplayName => _inner.DisplayName;

    public async Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var items = await _inner.ScanAsync(ctx, progress, ct).ConfigureAwait(false);
        return items.Where(_keep).ToList();
    }
}
