using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Memory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Startup;

namespace CleanSweep.App.Services;

public sealed record QuickOptimizeRequest(QuickOptimizeScope Scope, bool ReleaseStandby);
public sealed record QuickOptimizeProgress(string Stage, string Detail, double Percent);
public sealed record QuickOptimizeResult(CleanReport Report, long? MemoryBefore, long? MemoryAfter,
    double? BootSeconds, string MemoryMessage, int Candidates, bool MemorySucceeded = false);

internal sealed class QuickOptimizer(AppServices services)
{
    public async Task<QuickOptimizeResult> RunAsync(QuickOptimizeRequest request, IProgress<QuickOptimizeProgress> progress, CancellationToken ct)
    {
        progress.Report(new("正在检查", "读取内存状态与启动记录", 0));
        var before = await Task.Run(ReadMemory, ct).ConfigureAwait(false);
        var boot = await Task.Run(ReadBoot, ct).ConfigureAwait(false);
        progress.Report(new("正在扫描", "只检查首页勾选的旧文件范围", 10));
        var items = await services.Scheduler.RunAsync([new QuickOptimizeScanner(request.Scope)], services.CreateScanContext(), null, ct).ConfigureAwait(false);
        // Keep this operation on the current user; no service delegation or UAC during one-click cleanup.
        var eligible = items.Where(i => i.Kind == ItemKind.FileSet && i.Risk == RiskLevel.Safe
            && i.PreActions.Count == 0 && !Core.Elevation.ElevationNeed.For(i, services.Guard)).ToList();
        progress.Report(new("正在整理", $"发现 {eligible.Sum(i => i.Files.Count):N0} 个候选文件，逐个核对后移入隔离区", 30));
        CleanReport report;
        try
        {
            report = await services.Engine.CleanAsync(eligible,
                new InlineProgress<CleanProgress>(p => progress.Report(new("正在整理", p.CurrentItem, 30 + 55.0 * p.Done / Math.Max(1, p.Total)))), ct).ConfigureAwait(false);
        }
        catch (CleanCancelledException ex) { report = ex.Report; }

        var memoryMessage = request.ReleaseStandby ? "内存操作尚未执行" : "未清空待机缓存；显示的是系统可用内存变化";
        var memorySucceeded = false;
        if (!report.Cancelled && !ct.IsCancellationRequested && request.ReleaseStandby)
        {
            progress.Report(new("正在处理内存", "仅释放低优先级待机缓存", 90));
            if (!services.Elevation.IsElevated) memoryMessage = "内存操作已跳过：需要管理员权限";
            else
            {
                try
                {
                    var error = await Task.Run(() => services.Memory.PurgeStandbyList(lowPriorityOnly: true), CancellationToken.None).ConfigureAwait(false);
                    memorySucceeded = error is null;
                    memoryMessage = error is null ? "已请求释放低优先级待机缓存；数值也受其他程序活动影响" : "内存操作失败：" + error;
                }
                catch (Exception ex) { memoryMessage = "内存操作失败：" + ex.Message; }
            }
        }
        report.Cancelled |= ct.IsCancellationRequested;
        var after = await Task.Run(ReadMemory, CancellationToken.None).ConfigureAwait(false);
        progress.Report(new(report.Cancelled ? "已停止" : "处理完成", "统计实际结果", 100));
        return new(report, before, after, boot?.BootTimeMs / 1000.0, memoryMessage, eligible.Sum(i => i.Files.Count), memorySucceeded);
    }

    private static long? ReadMemory()
    {
        try { var state = MemoryManager.GetStatus(includeStandby: false); return state.TotalBytes > 0 ? state.AvailableBytes : null; }
        catch { return null; }
    }

    private static BootRecord? ReadBoot()
    {
        try { return BootHistory.Read(1).FirstOrDefault(); }
        catch { return null; }
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
