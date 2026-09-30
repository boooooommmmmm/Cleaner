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

    [ObservableProperty]
    private bool _isSelected;

    public event EventHandler? SelectionChanged;

    public ScanItemViewModel(ScanItem item) : this(item, canSelect: true, elevationHint: "") { }

    /// <param name="canSelect">当前权限下能否执行（不能时复选框禁用、默认不勾选）。</param>
    /// <param name="elevationHint">权限说明（"由提权服务执行" / "需要管理员权限…"），空表示不需要说明。</param>
    public ScanItemViewModel(ScanItem item, bool canSelect, string elevationHint)
    {
        Item = item;
        CanSelect = canSelect;
        ElevationHint = elevationHint;
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
    /// <summary>说明文字；与名称相同时不重复显示。</summary>
    public string Description => string.Equals(Item.Description, Item.DisplayName, StringComparison.Ordinal) ? "" : Item.Description;

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

    partial void OnIsSelectedChanged(bool value) => SelectionChanged?.Invoke(this, EventArgs.Empty);

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
