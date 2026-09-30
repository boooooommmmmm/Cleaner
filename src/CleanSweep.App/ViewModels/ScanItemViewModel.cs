using System.Collections.ObjectModel;
using System.Diagnostics;
using CleanSweep.App.Helpers;
using CleanSweep.Core.Model;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed partial class ScanItemViewModel : ObservableObject
{
    public ScanItem Item { get; }
    private readonly Func<ScanItem, ItemExplanation.Text>? _explain;
    private ItemExplanation.Text? _explanation;

    [ObservableProperty]
    private bool _isSelected;

    /// <summary>"详情"展开：依据 / 影响 / 恢复方式。</summary>
    [ObservableProperty]
    private bool _isDetailOpen;

    /// <summary>是否被结果筛选框过滤掉（只影响显示，不影响勾选与清理）。</summary>
    [ObservableProperty]
    private bool _isVisible = true;

    public event EventHandler? SelectionChanged;

    public ScanItemViewModel(ScanItem item) : this(item, canSelect: true, elevationHint: "") { }

    /// <param name="canSelect">当前权限下能否执行（不能时复选框禁用、默认不勾选）。</param>
    /// <param name="elevationHint">权限说明（"由提权服务执行" / "需要管理员权限…"），空表示不需要说明。</param>
    /// <param name="explain">生成"依据 / 影响 / 恢复方式"说明；null 时用不带隔离区目录的默认说明。</param>
    public ScanItemViewModel(ScanItem item, bool canSelect, string elevationHint, Func<ScanItem, ItemExplanation.Text>? explain = null)
    {
        Item = item;
        CanSelect = canSelect;
        ElevationHint = elevationHint;
        _explain = explain;
        _isSelected = item.DefaultSelected && canSelect;
    }

    /// <summary>当前权限下能否执行。</summary>
    public bool CanSelect { get; }

    public string ElevationHint { get; }
    public bool HasElevationHint => ElevationHint.Length > 0;

    public string Name => Item.DisplayName;
    public RiskLevel Risk => Item.Risk;
    public long SizeBytes => Item.SizeBytes;
    public string SizeText => Item.Kind == ItemKind.Command ? "大小未知" : Item.IsRegistryLike ? "—" : Format.Bytes(Item.SizeBytes);
    /// <summary>说明文字；与名称相同、或名称只是"说明 + 括号后缀"（通配目录段展开的条目）时不重复显示。</summary>
    public string Description => Item.Description.Length == 0 || Item.DisplayName.StartsWith(Item.Description, StringComparison.Ordinal) ? "" : Item.Description;

    public bool HasDescription => Description.Length > 0;

    public string Detail => Item.Kind switch
    {
        ItemKind.FileSet => $"{Item.FileCount} 个文件 · {Item.Path}",
        ItemKind.Directory => $"整个目录 · {Item.Path}",
        ItemKind.RecycleBin => "系统回收站（不经过隔离区，不可恢复）",
        ItemKind.Command => $"{Item.Command} {Item.CommandArgs}",
        ItemKind.RegistryValue => $"注册表值 · {Item.Path}",
        ItemKind.RegistryKey => $"注册表键 · {Item.Path}",
        ItemKind.Service => $"服务 · {Item.ServiceName}",
        ItemKind.ScheduledTask => $"计划任务 · {Item.TaskPath}",
        _ => "",
    };

    public bool CanOpenLocation => Item.Path is not null && !Item.IsRegistryLike;

    private ItemExplanation.Text Explanation => _explanation ??= _explain?.Invoke(Item) ?? ItemExplanation.For(Item, 30);

    public string Basis => Explanation.Basis;
    public string Effect => Explanation.Effect;
    public string Recovery => Explanation.Recovery;
    public string? Preconditions => Explanation.Preconditions;

    /// <summary>结果筛选：名称、说明、路径任一包含关键字（不分大小写）。</summary>
    public bool MatchesFilter(string? keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword)) return true;
        var k = keyword.Trim();
        return Name.Contains(k, StringComparison.OrdinalIgnoreCase)
               || Description.Contains(k, StringComparison.OrdinalIgnoreCase)
               || Detail.Contains(k, StringComparison.OrdinalIgnoreCase);
    }

    partial void OnIsSelectedChanged(bool value) => SelectionChanged?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void ToggleDetail() => IsDetailOpen = !IsDetailOpen;

    [RelayCommand]
    private void OpenLocation()
    {
        var path = Item.Path;
        if (path is null) return;
        try
        {
            if (Directory.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
            else if (File.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch
        {
            // 打开资源管理器失败不影响主流程
        }
    }
}

public sealed partial class ScanGroupViewModel : ObservableObject
{
    public string Name { get; }
    public ObservableCollection<ScanItemViewModel> Items { get; } = new();

    [ObservableProperty]
    private bool _isExpanded = true;

    /// <summary>结果筛选后组内还有可见项。</summary>
    [ObservableProperty]
    private bool _isVisible = true;

    public event EventHandler? SelectionChanged;

    private bool _suppress;

    public ScanGroupViewModel(string name, IEnumerable<ScanItemViewModel> items)
    {
        Name = name;
        foreach (var i in items)
        {
            i.SelectionChanged += OnItemSelectionChanged;
            Items.Add(i);
        }
    }

    public long TotalBytes => Items.Sum(i => i.SizeBytes);
    public long SelectedBytes => Items.Where(i => i.IsSelected).Sum(i => i.SizeBytes);
    public int SelectedCount => Items.Count(i => i.IsSelected);
    public string TotalText => Format.Bytes(TotalBytes);
    public string SelectedText => $"已选 {SelectedCount}/{Items.Count} 项 · {Format.Bytes(SelectedBytes)}";

    public int CountByRisk(RiskLevel risk) => Items.Count(i => i.Risk == risk);

    private bool? _expandedBeforeFilter;

    /// <summary>
    /// 应用结果筛选：逐项设置可见性；筛选命中时把组展开让结果直接可见，清除筛选后恢复用户原来的折叠状态。
    /// </summary>
    public void ApplyFilter(string? keyword)
    {
        var filtering = !string.IsNullOrWhiteSpace(keyword);
        var any = false;
        foreach (var i in Items)
        {
            i.IsVisible = !filtering || i.MatchesFilter(keyword);
            any |= i.IsVisible;
        }
        IsVisible = any;
        if (filtering)
        {
            _expandedBeforeFilter ??= IsExpanded;
            if (any) IsExpanded = true;
        }
        else if (_expandedBeforeFilter is { } saved)
        {
            IsExpanded = saved;
            _expandedBeforeFilter = null;
        }
    }

    /// <summary>三态：全选 true、全不选 false、部分 null。只按当前权限下可选的条目计算，禁用的条目不算"未选"。</summary>
    public bool? IsChecked
    {
        get
        {
            var selectable = Items.Count(i => i.CanSelect);
            if (selectable == 0) return false;
            var n = SelectedCount;
            return n == 0 ? false : n == selectable ? true : null;
        }
        set
        {
            if (value is null) return;
            _suppress = true;
            foreach (var i in Items) i.IsSelected = value.Value && i.CanSelect;
            _suppress = false;
            RaiseSelectionChanged();
        }
    }

    public void Remove(ScanItemViewModel item)
    {
        item.SelectionChanged -= OnItemSelectionChanged;
        Items.Remove(item);
        RaiseSelectionChanged();
    }

    private void OnItemSelectionChanged(object? sender, EventArgs e)
    {
        if (_suppress) return;
        RaiseSelectionChanged();
    }

    private void RaiseSelectionChanged()
    {
        OnPropertyChanged(nameof(IsChecked));
        OnPropertyChanged(nameof(SelectedBytes));
        OnPropertyChanged(nameof(SelectedCount));
        OnPropertyChanged(nameof(SelectedText));
        OnPropertyChanged(nameof(TotalText));
        SelectionChanged?.Invoke(this, EventArgs.Empty);
    }
}
