using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Memory;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class ProcessRow
{
    public required ProcessInfoRow Info { get; init; }
    public string Name => Info.Name;
    public int Pid => Info.Pid;
    public string MemoryText => Format.Bytes(Info.WorkingSetBytes);
    public string CpuText => Info.CpuPercent >= 0.1 ? $"{Info.CpuPercent:0.0}%" : "";
    public string Publisher => Info.Publisher ?? "";
    public string Path => Info.Path ?? "";
    public bool CanKill => !Info.IsProtected;
    public string ProtectText => Info.ProtectReason ?? "";
}

public sealed partial class BackgroundAppRow : ObservableObject
{
    private readonly Func<BackgroundAppRow, bool, string?> _apply;
    private bool _suppress;

    public BackgroundAppRow(BackgroundApp app, Func<BackgroundAppRow, bool, string?> apply)
    {
        App = app;
        _apply = apply;
        _allowed = !app.Disabled;
    }

    public BackgroundApp App { get; }
    public string Name => App.DisplayName;
    public string Family => App.PackageFamilyName;

    [ObservableProperty]
    private bool _allowed;

    [ObservableProperty]
    private string? _error;

    partial void OnAllowedChanged(bool value)
    {
        if (_suppress) return;
        var err = _apply(this, value);
        if (err is not null)
        {
            Error = err;
            _suppress = true;
            Allowed = !value;
            _suppress = false;
        }
        else Error = null;
    }
}

/// <summary>内存与进程页（设计文档 4.3）。</summary>
public sealed partial class MemoryViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<ProcessRow> Processes { get; } = new();
    public ObservableCollection<BackgroundAppRow> BackgroundApps { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(PurgeStandbyCommand), nameof(KillCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _memoryText = "";

    [ObservableProperty]
    private double _usedPercent;

    [ObservableProperty]
    private string _standbyText = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private bool _showMicrosoftBackground;

    public bool HasLoaded { get; private set; }

    public MemoryViewModel(AppServices s)
    {
        _s = s;
    }

    private bool NotBusy => !IsBusy;

    partial void OnShowMicrosoftBackgroundChanged(bool value) => _ = LoadBackgroundAppsAsync();

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        Status = "正在采样进程…";
        try
        {
            var status = await Task.Run(MemoryManager.GetStatus);
            MemoryText = $"物理内存 {Format.Bytes(status.TotalBytes)}，已用 {Format.Bytes(status.InUseBytes)}，可用 {Format.Bytes(status.AvailableBytes)}；已提交 {Format.Bytes(status.CommitTotalBytes)} / {Format.Bytes(status.CommitLimitBytes)}";
            UsedPercent = status.UsedFraction * 100;
            StandbyText = $"待机列表（缓存）{Format.Bytes(status.StandbyBytes)}，系统缓存 {Format.Bytes(status.CachedBytes)}。待机列表是可随时释放的缓存，它占用内存是正常现象；清空只在内存紧张的游戏场景有一点价值，不是加速手段。";

            var rows = await MemoryManager.ListProcessesAsync(800);
            Processes.Clear();
            foreach (var r in rows.Take(60)) Processes.Add(new ProcessRow { Info = r });
            await LoadBackgroundAppsAsync();
            HasLoaded = true;
            Status = $"{rows.Count} 个进程，按内存占用列出前 {Processes.Count} 个。系统关键进程与受保护进程不提供“结束”。";
        }
        catch (Exception ex)
        {
            Status = "读取失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadBackgroundAppsAsync()
    {
        var inv = _s.Inventory.Last ?? await Task.Run(() => _s.Inventory.Scan());
        var apps = MemoryManager.ListBackgroundApps(inv);
        BackgroundApps.Clear();
        foreach (var a in apps.Where(a => ShowMicrosoftBackground || !a.IsMicrosoft))
            BackgroundApps.Add(new BackgroundAppRow(a, (row, allowed) => _s.Memory.SetBackgroundAllowed(row.Family, allowed)));
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task PurgeStandbyAsync()
    {
        if (MessageBox.Show("清空待机列表会丢弃系统缓存的文件内容，之后打开程序与文件会短暂变慢，直到缓存重新建立。只在内存紧张（如大型游戏前）时才有意义。\n\n继续？",
                "清空待机列表", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var before = MemoryManager.GetStatus();
            var err = await Task.Run(() => _s.Memory.PurgeStandbyList());
            if (err is not null)
            {
                Status = "清空失败：" + err;
                return;
            }
            await Task.Delay(500);
            var after = MemoryManager.GetStatus();
            Status = $"已清空待机列表：可用内存 {Format.Bytes(before.AvailableBytes)} → {Format.Bytes(after.AvailableBytes)}。";
            MemoryText = $"物理内存 {Format.Bytes(after.TotalBytes)}，已用 {Format.Bytes(after.InUseBytes)}，可用 {Format.Bytes(after.AvailableBytes)}";
            UsedPercent = after.UsedFraction * 100;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task KillAsync(ProcessRow? row)
    {
        if (row is null || !row.CanKill) return;
        if (MessageBox.Show($"结束进程 {row.Name}（PID {row.Pid}，{row.MemoryText}）？\n\n未保存的数据会丢失。只结束这个进程，不结束它启动的子进程。",
                "结束进程", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var err = await Task.Run(() => _s.Memory.Kill(row.Info));
            if (err is null)
            {
                Processes.Remove(row);
                Status = $"已结束 {row.Name}。";
            }
            else Status = $"未能结束 {row.Name}：{err}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
