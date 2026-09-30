using System.Collections.ObjectModel;
using System.Diagnostics;
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
    public bool IsExpired => Entry.ExpiresUtc <= DateTime.UtcNow;
}

/// <summary>隔离区页顶部的"按磁盘"概览卡。</summary>
public sealed partial class QuarantineVolumeCard : ObservableObject
{
    public required QuarantineVolumeSummary Summary { get; init; }
    public string Root => Summary.Root;
    public string Directory => Summary.Directory;
    public string CountText => $"{Summary.Count:N0} 项";
    public string SizeText => Format.Bytes(Summary.Bytes);
    public string ExpiryText => Summary.ExpiredCount > 0
        ? $"已到期 {Summary.ExpiredCount:N0} 项（{Format.Bytes(Summary.ExpiredBytes)}），点“删除过期项”即可释放"
        : Summary.NextExpiryUtc is { } n ? $"最早 {Format.LocalTime(n)} 到期" : "";
    public bool HasExpired => Summary.ExpiredCount > 0;

    /// <summary>已选为筛选条件（只看此盘）。</summary>
    [ObservableProperty]
    private bool _isSelected;

    public string AutomationName => $"磁盘 {Root}";
}

public sealed class QuarantineBatchOption
{
    public QuarantineBatchSummary? Batch { get; init; }
    public string Label => Batch is null
        ? "全部批次"
        : $"{Format.LocalTime(Batch.QuarantinedUtc)} · {Batch.Count:N0} 项 · {Format.Bytes(Batch.Bytes)} · {string.Join("、", Batch.ModuleIds.Select(ModuleName))}";

    private static string ModuleName(string id) => id switch
    {
        "system-junk" => "系统清理",
        "app-cache" => "应用缓存",
        "residue" => "残留清理",
        "dev-cache" => "开发者缓存",
        "privacy" => "隐私清理",
        "registry" => "注册表清理",
        "uninstall" => "软件卸载",
        _ => id,
    };
}

public sealed partial class QuarantineViewModel : ObservableObject
{
    private readonly AppServices _s;
    private IReadOnlyList<QuarantineEntry> _all = Array.Empty<QuarantineEntry>();
    private bool _suppressFilter;

    [ObservableProperty]
    private ObservableCollection<QuarantineRow> _rows = new();

    /// <summary>按磁盘的概览卡；点卡片只看该盘。</summary>
    public ObservableCollection<QuarantineVolumeCard> Volumes { get; } = new();

    /// <summary>按清理批次筛选，第一项是"全部批次"。</summary>
    public ObservableCollection<QuarantineBatchOption> Batches { get; } = new();

    [ObservableProperty]
    private QuarantineBatchOption? _selectedBatch;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private string _summary = "";

    /// <summary>筛选后的说明（"显示 12 / 共 340 项"）；没有筛选时为空。</summary>
    [ObservableProperty]
    private string _filterText = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreAllCommand), nameof(PurgeAllCommand), nameof(PurgeExpiredCommand), nameof(RestoreCommand), nameof(PurgeCommand), nameof(PurgeVolumeCommand))]
    private bool _isBusy;

    public QuarantineViewModel(AppServices s)
    {
        _s = s;
        Refresh();
    }

    private bool NotBusy => !IsBusy;

    public bool IsFiltered => SelectedVolumeRoot is not null || SelectedBatch?.Batch is not null || !string.IsNullOrWhiteSpace(SearchText);

    private string? SelectedVolumeRoot => Volumes.FirstOrDefault(v => v.IsSelected)?.Root;

    [RelayCommand]
    private void Refresh()
    {
        _all = _s.Quarantine.ListActive();
        var now = DateTime.UtcNow;
        _suppressFilter = true;

        // 概览卡：保留已选中的盘（刷新后它还在的话）
        var selectedRoot = SelectedVolumeRoot;
        Volumes.Clear();
        foreach (var v in QuarantineOverview.ByVolume(_all, now, _s.Quarantine.GetQuarantineRoot))
        {
            var card = new QuarantineVolumeCard { Summary = v, IsSelected = string.Equals(v.Root, selectedRoot, StringComparison.OrdinalIgnoreCase) };
            card.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(QuarantineVolumeCard.IsSelected)) ApplyFilter(); };
            Volumes.Add(card);
        }

        var selectedBatchId = SelectedBatch?.Batch?.BatchId;
        Batches.Clear();
        Batches.Add(new QuarantineBatchOption());
        foreach (var b in QuarantineOverview.ByBatch(_all)) Batches.Add(new QuarantineBatchOption { Batch = b });
        SelectedBatch = Batches.FirstOrDefault(b => b.Batch?.BatchId == selectedBatchId) ?? Batches[0];

        Summary = _all.Count == 0
            ? "隔离区为空。"
            : $"{_all.Count:N0} 项，共 {Format.Bytes(_all.Sum(e => e.SizeBytes))}，分布在 {Volumes.Count} 个磁盘。默认保留 {_s.Settings.RetentionDays} 天后自动删除。";
        _suppressFilter = false;
        ApplyFilter();
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedBatchChanged(QuarantineBatchOption? value) => ApplyFilter();

    private void ApplyFilter()
    {
        if (_suppressFilter) return;
        var root = SelectedVolumeRoot;
        var batch = SelectedBatch?.Batch?.BatchId;
        IEnumerable<QuarantineEntry> q = _all;
        if (root is not null) q = q.Where(e => QuarantineOverview.OnVolume(e, root));
        if (batch is not null) q = q.Where(e => e.BatchId == batch);
        if (!string.IsNullOrWhiteSpace(SearchText)) q = q.Where(e => QuarantineOverview.Matches(e, SearchText));
        var list = q.ToList();
        // 一次性替换集合，避免大批量逐条 Add 触发几万次集合变更通知
        Rows = new ObservableCollection<QuarantineRow>(list.Select(e => new QuarantineRow { Entry = e }));
        FilterText = IsFiltered ? $"显示 {list.Count:N0} / 共 {_all.Count:N0} 项（{Format.Bytes(list.Sum(e => e.SizeBytes))}）" : "";
        OnPropertyChanged(nameof(IsFiltered));
    }

    /// <summary>点概览卡：只看这个盘；再点一次取消。</summary>
    [RelayCommand]
    private void SelectVolume(QuarantineVolumeCard? card)
    {
        if (card is null) return;
        var on = !card.IsSelected;
        _suppressFilter = true;
        foreach (var v in Volumes) v.IsSelected = false;
        card.IsSelected = on;
        _suppressFilter = false;
        ApplyFilter();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        _suppressFilter = true;
        foreach (var v in Volumes) v.IsSelected = false;
        SelectedBatch = Batches.FirstOrDefault();
        SearchText = "";
        _suppressFilter = false;
        ApplyFilter();
    }

    [RelayCommand]
    private void OpenVolumeDir(QuarantineVolumeCard? card)
    {
        if (card is null) return;
        try
        {
            if (!System.IO.Directory.Exists(card.Directory))
            {
                Status = $"目录不存在：{card.Directory}";
                return;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{card.Directory}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Status = "打开目录失败：" + ex.Message;
        }
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

    /// <summary>"全部恢复"作用于当前显示的项：有筛选时只恢复筛选结果，确认框里说清楚。</summary>
    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RestoreAllAsync()
    {
        var rows = Rows.ToList();
        if (rows.Count == 0) return;
        var scope = IsFiltered ? $"当前筛选出的 {rows.Count:N0} 项" : $"全部 {rows.Count:N0} 项";
        if (MessageBox.Show($"恢复{scope}到原位置？", "隔离区", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

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

    /// <summary>"清空隔离区"作用于当前显示的项：有筛选时只删筛选结果。</summary>
    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeAllAsync()
    {
        var rows = Rows.ToList();
        if (rows.Count == 0) return;
        var bytes = rows.Sum(r => r.Entry.SizeBytes);
        var scope = IsFiltered ? $"当前筛选出的 {rows.Count:N0} 项" : $"隔离区全部 {rows.Count:N0} 项";
        if (MessageBox.Show($"永久删除{scope}（{Format.Bytes(bytes)}）？此操作不可恢复。",
                "清空隔离区", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        await RunBulkAsync("正在删除", rows, row => _s.Quarantine.Purge(row.Entry.Id), ElevatedOperation.PurgeQuarantineItem, "已永久删除");
        _s.Log.Write(null, "quarantine", "purge-all", null, bytes, true, $"{rows.Count} 项");
    }

    /// <summary>概览卡上的"释放此盘"：永久删除该盘上的全部隔离项，不受当前筛选影响。</summary>
    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeVolumeAsync(QuarantineVolumeCard? card)
    {
        if (card is null) return;
        var rows = _all.Where(e => QuarantineOverview.OnVolume(e, card.Root)).Select(e => new QuarantineRow { Entry = e }).ToList();
        if (rows.Count == 0) return;
        var bytes = rows.Sum(r => r.Entry.SizeBytes);
        if (MessageBox.Show($"永久删除 {card.Root} 上的全部 {rows.Count:N0} 个隔离项（{Format.Bytes(bytes)}）？此操作不可恢复，其他磁盘的隔离项不受影响。",
                $"释放 {card.Root}", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        await RunBulkAsync("正在删除", rows, row => _s.Quarantine.Purge(row.Entry.Id), ElevatedOperation.PurgeQuarantineItem, "已永久删除");
        _s.Log.Write(null, "quarantine", "purge-volume", card.Root, bytes, true, $"{rows.Count} 项");
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
