using System.Text.Json;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;

namespace CleanSweep.App.ViewModels;

public sealed record CleanReportRow(string ItemId, string Name, string? Path, CleanIssueKind? Kind,
    string Reason, int? ErrorCode = null)
{
    public string Category => Kind switch
    {
        null => "已处理", CleanIssueKind.InUse => "正在使用", CleanIssueKind.Permission => "权限不足",
        CleanIssueKind.Changed => "扫描后变化", CleanIssueKind.BackupFailed => "备份失败",
        CleanIssueKind.Excluded => "安全排除", CleanIssueKind.AlreadyAbsent => "已不存在",
        CleanIssueKind.NotProcessed => "未确认完成", _ => "其他失败",
    };

    public string NextStep => Kind switch
    {
        null => "需要撤销时查看隔离区或对应备份；系统命令与回收站有独立恢复限制。",
        CleanIssueKind.InUse => "保存工作并关闭相关程序，然后重新扫描。",
        CleanIssueKind.Permission => "检查目标权限；必要时从左下角以管理员身份重新启动并扫描。",
        CleanIssueKind.Changed => "重新扫描并核对最新内容，再决定是否清理。",
        CleanIssueKind.BackupFailed => "本次未执行该目标的删除；检查备份目录权限和剩余空间，保留错误详情。",
        CleanIssueKind.Excluded => "检查白名单或路径保护原因，不强制重试。",
        CleanIssueKind.AlreadyAbsent => "无需重试此目标；重新扫描可刷新列表。",
        CleanIssueKind.NotProcessed => "执行结果尚未确认，重新扫描当前状态；需要恢复时查看隔离区或备份。",
        _ => "查看原因和错误码；解决问题后重新扫描，可导出结果排查。",
    };
}

public sealed record CleanItemSummary(string Id, string ModuleId, string Name, string? Path,
    bool Complete, int? Succeeded, int? Skipped, int? Failed, int? AlreadyAbsent, bool ViaService);

/// <summary>一次执行的独立快照；界面筛选不改变导出内容和重新扫描范围。</summary>
public sealed record CleanExecutionReport(DateTime FinishedUtc, string Page, string AppVersion,
    string BatchId, bool Cancelled, string Summary, IReadOnlyList<CleanItemSummary> Items,
    IReadOnlyList<CleanReportRow> Rows, IReadOnlyList<string> Notes)
{
    public IReadOnlySet<string> IncompleteIds => Items.Where(i => !i.Complete).Select(i => i.Id).ToHashSet(StringComparer.Ordinal);
    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });

    public static CleanExecutionReport Create(string page, IReadOnlyList<ScanItem> selected, CleanReport local,
        IReadOnlySet<string> serviceIds, IReadOnlyDictionary<string, bool> serviceOutcomes,
        IReadOnlyList<CleanFailure> serviceIssues, string summary)
    {
        var details = local.Failures.Concat(local.InUseFiles).Concat(local.SkippedDetails).Concat(serviceIssues)
            .Select(f => new CleanReportRow(f.ItemId, f.ItemDisplayName, f.Path, f.Kind, f.Reason, f.ErrorCode)).ToList();
        var detailedIds = details.Select(r => r.ItemId).ToHashSet(StringComparer.Ordinal);
        var items = new List<CleanItemSummary>();
        foreach (var item in selected)
        {
            var viaService = serviceIds.Contains(item.Id);
            var outcome = local.Outcomes.GetValueOrDefault(item.Id);
            var complete = viaService ? serviceOutcomes.GetValueOrDefault(item.Id)
                : outcome is { Complete: true, Untouched: false };
            items.Add(new(item.Id, item.ModuleId, item.DisplayName, item.Path, complete,
                viaService ? null : outcome?.Succeeded, viaService ? null : outcome?.Skipped,
                viaService ? null : outcome?.Failed, viaService ? null : outcome?.AlreadyAbsent, viaService));
            if (complete && !detailedIds.Contains(item.Id))
                details.Add(new(item.Id, item.DisplayName, item.Path, null, viaService ? "提权服务确认条目处理完成。" : "条目处理完成，计数见导出结果。"));
            else if (!complete && !detailedIds.Contains(item.Id))
                details.Add(new(item.Id, item.DisplayName, item.Path, CleanIssueKind.NotProcessed, "未取得完整处理结果。"));
        }
        return new(DateTime.UtcNow, page, typeof(CleanExecutionReport).Assembly.GetName().Version?.ToString() ?? "unknown", local.BatchId,
            local.Cancelled, summary, items, details,
            serviceIds.Count > 0 ? ["服务结果包含逐项摘要；文件失败明细最多 50 条/请求，未返回的明细不能从本报告还原。未知计数为 null，不代表没有执行操作。"] : []);
    }
}
