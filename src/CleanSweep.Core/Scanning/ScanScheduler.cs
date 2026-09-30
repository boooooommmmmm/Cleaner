using CleanSweep.Core.Model;

namespace CleanSweep.Core.Scanning;

/// <summary>并行运行多个扫描器，汇总结果，并应用白名单与高级模式过滤。</summary>
public sealed class ScanScheduler
{
    public async Task<IReadOnlyList<ScanItem>> RunAsync(
        IEnumerable<IScanner> scanners,
        ScanContext ctx,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        var tasks = scanners.Select(s => Task.Run(() => s.ScanAsync(ctx, progress, ct), ct)).ToList();
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        var items = new List<ScanItem>();
        foreach (var list in results)
        {
            foreach (var item in list)
            {
                var filtered = ApplyFilters(item, ctx);
                if (filtered is not null) items.Add(filtered);
            }
        }

        return items
            .OrderBy(i => i.Group, StringComparer.CurrentCultureIgnoreCase)
            .ThenByDescending(i => i.SizeBytes)
            .ToList();
    }

    private static ScanItem? ApplyFilters(ScanItem item, ScanContext ctx)
    {
        if (item.Risk == RiskLevel.NotRecommended && !ctx.AdvancedMode) return null;
        if (ctx.Whitelist.IsItemExcluded(item.Id)) return null;

        switch (item.Kind)
        {
            case ItemKind.Directory:
                return item.Path is not null && ctx.Whitelist.IsPathExcluded(item.Path) ? null : item;

            case ItemKind.FileSet:
            {
                if (item.Files.Count == 0) return null;
                if (item.Path is not null && ctx.Whitelist.IsPathExcluded(item.Path)) return null;

                var kept = item.Files.Where(f => !ctx.Whitelist.IsPathExcluded(f.Path)).ToList();
                if (kept.Count == 0) return null;
                if (kept.Count == item.Files.Count) return item;

                return item with { Files = kept, SizeBytes = kept.Sum(f => f.Size) };
            }

            default:
                return item;
        }
    }
}
