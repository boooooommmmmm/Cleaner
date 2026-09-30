using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using CleanSweep.App.Services;
using CleanSweep.Core.SysInfo;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class HardwareReadingRow
{
    public required HardwareReading Reading { get; init; }
    public string Name => Reading.Name;
    public string Value => Reading.Value;
    public bool HasPercent => Reading.Percent is not null;
    public double Percent => Reading.Percent ?? 0;
    public bool Warning => Reading.Warning;
}

public sealed partial class HardwareGroupRow : ObservableObject
{
    public required string Title { get; init; }

    [ObservableProperty]
    private ObservableCollection<HardwareReadingRow> _items = new();
}

public sealed class ToolRow
{
    public required SystemTool Tool { get; init; }
    public string Title => Tool.Title;
    public string Description => Tool.Description;
    public string Badge => Tool.Restarts ? "需要重启" : Tool.NeedsAdmin ? "需要管理员" : "";
    public bool HasBadge => Badge.Length > 0;
}

/// <summary>
/// 硬件状态页：CPU / 内存 / 温度 / 显卡 / 磁盘 / 电池的只读采样，可自动刷新；下方是 Windows 自带工具入口。
/// 页面不在前台时停止自动刷新（由 Shell 设置 <see cref="IsActive"/>）。
/// </summary>
public sealed partial class HardwareViewModel : ObservableObject
{
    private readonly AppServices _s;
    private readonly DispatcherTimer _timer;
    private int _tick;
    private bool _refreshing;

    public ObservableCollection<HardwareGroupRow> Groups { get; } = new();
    public ObservableCollection<ToolRow> Tools { get; } = new();

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private string? _notes;

    /// <summary>每 2 秒刷新一次（磁盘 S.M.A.R.T. 每 10 次刷一次）。</summary>
    [ObservableProperty]
    private bool _autoRefresh;

    [ObservableProperty]
    private string _updatedText = "";

    public bool HasLoaded { get; private set; }

    public HardwareViewModel(AppServices s)
    {
        _s = s;
        foreach (var t in SystemTools.All) Tools.Add(new ToolRow { Tool = t });
        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += async (_, _) => await RefreshCoreAsync(includeStorage: ++_tick % 10 == 0);
        _autoRefresh = s.Settings.HardwareAutoRefresh;
    }

    private bool _isActive;

    /// <summary>页面是否在前台；离开时停表，回来时重新采样一次（CPU 基线重取）并按开关恢复自动刷新。</summary>
    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (_isActive == value) return;
            _isActive = value;
            if (value)
            {
                _ = RefreshCoreAsync(includeStorage: true, freshBaseline: true);
                if (AutoRefresh) _timer.Start();
            }
            else
            {
                _timer.Stop();
            }
        }
    }

    partial void OnAutoRefreshChanged(bool value)
    {
        if (value && IsActive) _timer.Start();
        else _timer.Stop();
        if (_s.Settings.HardwareAutoRefresh != value)
        {
            _s.Settings.HardwareAutoRefresh = value;
            try { _s.Settings.Save(); } catch { }
        }
    }

    [RelayCommand]
    private Task RefreshAsync() => RefreshCoreAsync(includeStorage: true);

    /// <param name="freshBaseline">先重取 CPU 基线再等 600 ms，占用率反映的是"现在"而不是上次离开页面到现在的平均。</param>
    private async Task RefreshCoreAsync(bool includeStorage, bool freshBaseline = false)
    {
        if (_refreshing) return;
        _refreshing = true;
        IsBusy = !HasLoaded;
        try
        {
            if (freshBaseline || !HasLoaded)
            {
                HardwareStatus.ResetCpuSample();
                await Task.Delay(600);
            }
            var snap = await Task.Run(() => HardwareStatus.Collect(includeStorage));
            Apply(snap, includeStorage);
            HasLoaded = true;
            UpdatedText = $"更新于 {snap.TakenUtc.ToLocalTime():HH:mm:ss}";
            Notes = snap.Notes.Count == 0 ? null : string.Join("\n", snap.Notes);
            Status = "全部只读。CPU 核心温度与机箱风扇转速需要内核驱动读取，本程序不安装驱动；显示的是 ACPI 温区、显卡自带工具与磁盘 S.M.A.R.T. 提供的数据。";
        }
        catch (Exception ex)
        {
            Status = "读取失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
            _refreshing = false;
        }
    }

    /// <summary>按组更新；组对象保持不变，只换内容，避免整页闪烁。没读磁盘的那次保留上次的存储组。</summary>
    private void Apply(HardwareSnapshot snap, bool includeStorage)
    {
        var order = new[] { HardwareStatus.GroupCpu, HardwareStatus.GroupMemory, HardwareStatus.GroupThermal, HardwareStatus.GroupGpu, HardwareStatus.GroupStorage, HardwareStatus.GroupPower };
        foreach (var title in order)
        {
            var readings = snap.Readings.Where(r => r.Group == title).ToList();
            var row = Groups.FirstOrDefault(g => g.Title == title);
            if (readings.Count == 0)
            {
                if (title == HardwareStatus.GroupStorage && !includeStorage) continue;
                if (row is not null) Groups.Remove(row);
                continue;
            }
            if (row is null)
            {
                row = new HardwareGroupRow { Title = title };
                var index = Groups.TakeWhile(g => Array.IndexOf(order, g.Title) < Array.IndexOf(order, title)).Count();
                Groups.Insert(index, row);
            }
            row.Items = new ObservableCollection<HardwareReadingRow>(readings.Select(r => new HardwareReadingRow { Reading = r }));
        }
    }

    [RelayCommand]
    private void LaunchTool(ToolRow? row)
    {
        if (row is null) return;
        var t = row.Tool;
        if (t.Restarts)
        {
            var r = MessageBox.Show($"{t.Title}\n\n{t.Description}\n\n打开后 Windows 会询问“立即重新启动”还是“下次启动时检查”。现在打开？",
                t.Title, MessageBoxButton.OKCancel, MessageBoxImage.Question);
            if (r != MessageBoxResult.OK) return;
        }
        var err = SystemTools.Launch(t);
        _s.Log.Write(null, "tools", "launch", t.Id, 0, err is null, err);
        Status = err is null ? $"已打开：{t.Title}。" : $"无法打开 {t.Title}：{err}";
    }
}
