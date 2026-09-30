using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Safety;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class QuarantineRow
{
    public required QuarantineEntry Entry { get; init; }
    public string Name => Path.GetFileName(Entry.OriginalPath);
    public string OriginalPath => Entry.OriginalPath;
    public string SizeText => Format.Bytes(Entry.SizeBytes);
    public string KindText => Entry.IsDirectory ? "目录" : "文件";
    public string QuarantinedText => Format.LocalTime(Entry.QuarantinedUtc);
    public string ExpiresText => Format.LocalTime(Entry.ExpiresUtc);
    public string Source => Entry.DisplayName;
}

public sealed partial class QuarantineViewModel : ObservableObject
{
    private readonly AppServices _s;

    [ObservableProperty]
    private ObservableCollection<QuarantineRow> _rows = new();

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreAllCommand), nameof(PurgeAllCommand), nameof(PurgeExpiredCommand), nameof(RestoreCommand), nameof(PurgeCommand))]
    private bool _isBusy;

    public QuarantineViewModel(AppServices s)
    {
        _s = s;
        Refresh();
    }

    private bool NotBusy => !IsBusy;

    [RelayCommand]
    private void Refresh()
    {
        var entries = _s.Quarantine.ListActive();
        // 一次性替换集合，避免大批量逐条 Add 触发几万次集合变更通知
        Rows = new ObservableCollection<QuarantineRow>(entries.Select(e => new QuarantineRow { Entry = e }));
        Summary = entries.Count == 0
            ? "隔离区为空。"
            : $"{entries.Count:N0} 项，共 {Format.Bytes(entries.Sum(e => e.SizeBytes))}。默认保留 {_s.Settings.RetentionDays} 天后自动删除。";
    }

    /// <summary>
    /// 非提权运行时，恢复到系统目录或删除提权实例移入的项会因权限失败；提权服务在线且两边共用同一份索引时，
    /// 按隔离项 ID + 对象标识交给服务重做一次（服务核对自己索引里的同一条与归属用户，再做同样的元数据与护栏校验）。
    /// "拒绝访问"同时认 UnauthorizedAccessException 与句柄级移动包装的 IOException。
    /// </summary>
    private async Task<string?> WithServiceFallbackAsync(Func<string?> local, ElevatedOperation op, QuarantineEntry entry)
    {
        try
        {
            return local();
        }
        catch (Exception ex) when (AccessDenied.Is(ex) && _s.Elevation.CanDelegateQuarantine)
        {
            return await DelegateAsync(op, entry);
        }
    }

    private static async Task<string> DelegateAsync(ElevatedOperation op, QuarantineEntry entry)
    {
        var r = await ElevationClient.SendAsync(new ElevationRequest(op, ItemId: entry.Id, ItemKey: Quarantine.ObjectKey(entry)), TimeSpan.FromMinutes(5));
        if (!r.Success) throw new InvalidOperationException("提权服务：" + r.Message);
        return r.Message;
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RestoreAsync(QuarantineRow? row)
    {
        if (row is null) return;
        try
        {
            var target = await WithServiceFallbackAsync(() => _s.Quarantine.Restore(row.Entry.Id), ElevatedOperation.RestoreQuarantineItem, row.Entry);
            _s.Log.Write(null, row.Entry.ModuleId, "restore", target, row.Entry.SizeBytes, true);
            Status = $"已恢复到 {target}";
        }
        catch (Exception ex)
        {
            _s.Log.Write(null, row.Entry.ModuleId, "restore", row.Entry.OriginalPath, 0, false, ex.Message);
            MessageBox.Show($"恢复失败：{ex.Message}" + ElevationAdvice(ex), "隔离区", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Refresh();
    }

    private string ElevationAdvice(Exception ex) =>
        AccessDenied.Is(ex) && !_s.Elevation.IsElevated ? "\n\n该位置需要管理员权限，请点击左下角“以管理员身份重新启动”后再试。" : "";

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RestoreAllAsync()
    {
        var rows = Rows.ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show($"恢复全部 {rows.Count:N0} 项到原位置？", "隔离区", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        await RunBulkAsync("正在恢复", rows, row =>
        {
            _s.Quarantine.Restore(row.Entry.Id);
            _s.Log.Write(null, row.Entry.ModuleId, "restore", row.Entry.OriginalPath, row.Entry.SizeBytes, true);
        }, ElevatedOperation.RestoreQuarantineItem, "已恢复");
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeAsync(QuarantineRow? row)
    {
        if (row is null) return;
        if (MessageBox.Show($"永久删除“{row.Name}”？此操作不可恢复。", "隔离区", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        try
        {
            await WithServiceFallbackAsync(() => { _s.Quarantine.Purge(row.Entry.Id); return null; }, ElevatedOperation.PurgeQuarantineItem, row.Entry);
            _s.Log.Write(null, row.Entry.ModuleId, "purge", row.Entry.OriginalPath, row.Entry.SizeBytes, true);
        }
        catch (Exception ex)
        {
            // 删除失败时记录保留，文件仍可恢复
            _s.Log.Write(null, row.Entry.ModuleId, "purge", row.Entry.OriginalPath, 0, false, ex.Message);
            MessageBox.Show($"删除失败：{ex.Message}\n\n该项仍保留在隔离区。" + ElevationAdvice(ex), "隔离区", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Refresh();
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeAllAsync()
    {
        var rows = Rows.ToList();
        if (rows.Count == 0) return;
        var bytes = rows.Sum(r => r.Entry.SizeBytes);
        if (MessageBox.Show($"永久删除隔离区全部 {rows.Count:N0} 项（{Format.Bytes(bytes)}）？此操作不可恢复。",
                "清空隔离区", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        await RunBulkAsync("正在删除", rows, row => _s.Quarantine.Purge(row.Entry.Id), ElevatedOperation.PurgeQuarantineItem, "已永久删除");
        _s.Log.Write(null, "quarantine", "purge-all", null, bytes, true, $"{rows.Count} 项");
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeExpiredAsync()
    {
        IsBusy = true;
        try
        {
            var n = await Task.Run(() =>
            {
                using var bulk = _s.Quarantine.BeginBulk();
                return _s.Quarantine.PurgeExpired();
            });
            Status = n == 0 ? "没有过期项。" : $"已删除 {n:N0} 个过期项。";
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }

    /// <summary>
    /// 批量操作：本地事务内逐项处理；因权限失败的项先记下来，事务结束后再逐个交给提权服务
    /// （不能在持有本地索引写事务时等服务：服务删完文件要写同一份索引，会互相等）。
    /// </summary>
    private async Task RunBulkAsync(string verb, List<QuarantineRow> rows, Action<QuarantineRow> action, ElevatedOperation op, string doneVerb)
    {
        IsBusy = true;
        int ok = 0, fail = 0;
        var needService = new List<QuarantineRow>();
        try
        {
            var progress = new Progress<int>(done => Status = $"{verb}… {done:N0}/{rows.Count:N0}");
            var delegateAllowed = _s.Elevation.CanDelegateQuarantine;
            await Task.Run(() =>
            {
                using var bulk = _s.Quarantine.BeginBulk();
                int done = 0;
                foreach (var row in rows)
                {
                    try
                    {
                        action(row);
                        ok++;
                    }
                    catch (Exception ex) when (delegateAllowed && AccessDenied.Is(ex))
                    {
                        needService.Add(row);
                    }
                    catch (Exception ex)
                    {
                        fail++;
                        _s.Log.Write(null, row.Entry.ModuleId, verb, row.Entry.OriginalPath, 0, false, ex.Message);
                    }
                    if ((++done & 0xFF) == 0) ((IProgress<int>)progress).Report(done);
                }
            });

            for (int i = 0; i < needService.Count; i++)
            {
                var row = needService[i];
                Status = $"{verb}（提权服务）… {i + 1}/{needService.Count}";
                try
                {
                    await DelegateAsync(op, row.Entry);
                    _s.Log.Write(null, row.Entry.ModuleId, verb, row.Entry.OriginalPath, row.Entry.SizeBytes, true, "提权服务");
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    _s.Log.Write(null, row.Entry.ModuleId, verb, row.Entry.OriginalPath, 0, false, ex.Message);
                }
            }
            Status = $"{doneVerb} {ok:N0} 项" + (fail > 0 ? $"，{fail:N0} 项失败（详见清理历史）" : "") + "。";
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }
}
