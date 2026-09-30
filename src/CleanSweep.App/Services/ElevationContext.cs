using System.ComponentModel;
using System.Diagnostics;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.App.Services;

/// <summary>
/// 界面的权限状态（设计文档 7.4）：以什么权限运行、提权服务是否在线，以及两条提权执行通道：
/// 1. 提权服务（已安装时）：规则库产生的"安全"级文件 / 目录条目按规则 ID + 条目 ID + 内容快照交给服务；
/// 2. 以管理员身份重新启动：一切其他需要管理员的条目。
/// </summary>
public sealed class ElevationContext : INotifyPropertyChanged
{
    private bool _serviceAvailable;

    public ElevationContext(PathGuard guard)
    {
        Guard = guard;
        IsElevated = ProtectedDirectory.IsElevated();
    }

    public PathGuard Guard { get; }

    public bool IsElevated { get; }

    /// <summary>提权服务在线（启动时探测一次，之后每次需要时再探测）。</summary>
    public bool ServiceAvailable
    {
        get => _serviceAvailable;
        private set
        {
            if (_serviceAvailable == value) return;
            _serviceAvailable = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ServiceAvailable)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusText)));
        }
    }

    /// <summary>界面与服务共用同一份索引（ProgramData 数据目录）时，隔离项才能按 ID 交给服务。</summary>
    public static bool SharesMachineData => string.Equals(AppPaths.DataDir, AppPaths.MachineDataDir, StringComparison.OrdinalIgnoreCase);

    public string StatusText => IsElevated
        ? "以管理员身份运行"
        : ServiceAvailable ? "普通权限运行 · 提权服务在线" : "普通权限运行";

    public event PropertyChangedEventHandler? PropertyChanged;

    public async Task<bool> ProbeServiceAsync()
    {
        if (IsElevated) return ServiceAvailable = false;
        return ServiceAvailable = await ElevationClient.IsAvailableAsync().ConfigureAwait(false);
    }

    /// <summary>条目在当前权限下能否执行：已提权一律可以；否则不需要管理员的可以，需要管理员但服务能跑的也可以。</summary>
    public bool CanExecute(ScanItem item) => IsElevated || !ElevationNeed.For(item, Guard) || (ServiceAvailable && ElevationNeed.ServiceCanRun(item));

    /// <summary>条目需要走提权服务。</summary>
    public bool ViaService(ScanItem item) => !IsElevated && ServiceAvailable && ElevationNeed.For(item, Guard) && ElevationNeed.ServiceCanRun(item);

    /// <summary>隔离项的恢复 / 删除因权限失败时能否交给服务：非提权、服务在线、索引共用。</summary>
    public bool CanDelegateQuarantine => !IsElevated && ServiceAvailable && SharesMachineData;

    public string HintFor(ScanItem item)
    {
        if (IsElevated || !ElevationNeed.For(item, Guard)) return "";
        if (ServiceAvailable && ElevationNeed.ServiceCanRun(item)) return "由提权服务执行";
        return "需要管理员权限：点击左下角“以管理员身份重新启动”";
    }

    /// <summary>
    /// 把选中条目按规则分组交给提权服务，每个条目连同用户确认时的内容快照一起发送。
    /// 返回每个条目的结果：true 只在服务明确报告"done"时成立；服务没提到的条目一律视为未完成。
    /// </summary>
    public async Task<(Dictionary<string, bool> Outcomes, List<string> Messages, long QuarantinedBytes)> RunViaServiceAsync(IReadOnlyList<ScanItem> items, CancellationToken ct)
    {
        var outcomes = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var messages = new List<string>();
        long bytes = 0;
        var byId = items.ToDictionary(i => i.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var group in items.Where(i => i.RuleId is not null).GroupBy(i => i.RuleId!, StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            var refs = group.Select(i => new ElevationItemRef(i.Id, i.ContentSnapshot())).ToList();
            foreach (var r in refs) outcomes[r.Id] = false;
            foreach (var chunk in refs.Chunk(ElevationRequest.MaxItems))
            {
                ElevationResponse response;
                try
                {
                    response = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: group.Key, Items: chunk), TimeSpan.FromMinutes(30), ct: ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    messages.Add($"规则 {group.Key}：提权服务调用失败：{ex.Message}");
                    ServiceAvailable = false;
                    continue;
                }
                var payload = ElevatedOperations.ParsePayload(response.Payload);
                if (payload is null)
                {
                    messages.Add($"规则 {group.Key}：{response.Message}");
                    continue;
                }
                bytes += payload.QuarantinedBytes;
                foreach (var result in payload.Results)
                {
                    if (!outcomes.ContainsKey(result.ItemId)) continue;
                    outcomes[result.ItemId] = result.State == ElevatedOperations.StateDone;
                    if (result.State != ElevatedOperations.StateDone)
                        messages.Add($"{(byId.TryGetValue(result.ItemId, out var it) ? it.Path ?? it.DisplayName : result.ItemId)}：{result.Reason ?? result.State}");
                }
                foreach (var f in payload.Failures.Where(f => !payload.Results.Any(r => r.ItemId == f.ItemId && r.Reason == f.Reason)))
                    messages.Add($"{f.Path ?? f.ItemId}：{f.Reason}");
            }
        }
        return (outcomes, messages, bytes);
    }

    /// <summary>以管理员身份重新启动本程序。返回 null 表示新实例已启动（调用方应退出），否则为失败原因。</summary>
    public static string? RelaunchElevated()
    {
        var exe = System.Environment.ProcessPath;
        if (exe is null) return "无法确定程序路径";
        try
        {
            var p = Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", Arguments = "--relaunched" });
            return p is null ? "未能启动" : null;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "已取消提权";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
