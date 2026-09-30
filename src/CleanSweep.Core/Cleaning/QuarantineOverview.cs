namespace CleanSweep.Core.Cleaning;

/// <summary>一个卷上的隔离区概况（隔离区页顶部的概览卡）。</summary>
/// <param name="Root">卷根，如 C:\。</param>
/// <param name="Directory">该卷的隔离区目录，如 C:\$CleanSweep.Quarantine。</param>
/// <param name="ExpiredCount">已到期、下次"删除过期项"会清掉的项数。</param>
/// <param name="NextExpiryUtc">最早到期时间（不含已到期）。</param>
public sealed record QuarantineVolumeSummary(string Root, string Directory, int Count, long Bytes, int ExpiredCount, long ExpiredBytes, DateTime? NextExpiryUtc);

/// <summary>一次清理批次在隔离区里剩下的项。</summary>
public sealed record QuarantineBatchSummary(string BatchId, DateTime QuarantinedUtc, int Count, long Bytes, IReadOnlyList<string> ModuleIds);

/// <summary>隔离区的聚合视图：按卷、按批次。只做纯计算，不碰磁盘。</summary>
public static class QuarantineOverview
{
    public static IReadOnlyList<QuarantineVolumeSummary> ByVolume(IEnumerable<QuarantineEntry> entries, DateTime nowUtc, Func<string, string> quarantineRootOf)
    {
        var list = new List<QuarantineVolumeSummary>();
        foreach (var g in entries.GroupBy(e => Path.GetPathRoot(e.QuarantinePath) ?? "", StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var items = g.ToList();
            var expired = items.Where(e => e.ExpiresUtc <= nowUtc).ToList();
            var next = items.Where(e => e.ExpiresUtc > nowUtc).Select(e => (DateTime?)e.ExpiresUtc).DefaultIfEmpty(null).Min();
            string dir;
            try { dir = quarantineRootOf(items[0].QuarantinePath); } catch { dir = g.Key; }
            list.Add(new QuarantineVolumeSummary(g.Key, dir, items.Count, items.Sum(e => e.SizeBytes), expired.Count, expired.Sum(e => e.SizeBytes), next));
        }
        return list;
    }

    public static IReadOnlyList<QuarantineBatchSummary> ByBatch(IEnumerable<QuarantineEntry> entries)
    {
        return entries
            .GroupBy(e => e.BatchId, StringComparer.Ordinal)
            .Select(g => new QuarantineBatchSummary(g.Key, g.Min(e => e.QuarantinedUtc), g.Count(), g.Sum(e => e.SizeBytes),
                g.Select(e => e.ModuleId).Distinct(StringComparer.Ordinal).OrderBy(m => m, StringComparer.Ordinal).ToArray()))
            .OrderByDescending(b => b.QuarantinedUtc)
            .ToList();
    }

    /// <summary>关键字筛选：匹配原路径或来源名，大小写不敏感；空关键字全部命中。</summary>
    public static bool Matches(QuarantineEntry e, string? keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword)) return true;
        var k = keyword.Trim();
        return e.OriginalPath.Contains(k, StringComparison.OrdinalIgnoreCase) || e.DisplayName.Contains(k, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>条目是否在某个卷上（root 形如 C:\）。</summary>
    public static bool OnVolume(QuarantineEntry e, string root) =>
        string.Equals(Path.GetPathRoot(e.QuarantinePath) ?? "", root, StringComparison.OrdinalIgnoreCase);
}
