using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CleanSweep.App.ViewModels;

public sealed partial class DuplicateFileViewModel : ObservableObject
{
    public FileEntry Entry { get; }
    public DuplicateGroupViewModel Group { get; }

    [ObservableProperty]
    private bool _isSelected;

    public DuplicateFileViewModel(FileEntry entry, DuplicateGroupViewModel group)
    {
        Entry = entry;
        Group = group;
    }

    public string Name => Path.GetFileName(Entry.Path);
    public string Directory => Path.GetDirectoryName(Entry.Path) ?? "";
    public string ModifiedText => Format.LocalTime(Entry.LastWriteUtc);

    partial void OnIsSelectedChanged(bool value) => Group.NotifySelectionChanged();
}

public sealed partial class DuplicateGroupViewModel : ObservableObject
{
    public DuplicateGroup Group { get; }
    public ObservableCollection<DuplicateFileViewModel> Files { get; } = new();
    public event EventHandler? SelectionChanged;

    public DuplicateGroupViewModel(DuplicateGroup group)
    {
        Group = group;
        foreach (var f in group.Files) Files.Add(new DuplicateFileViewModel(f, this));
    }

    public string Title => $"{Path.GetFileName(Group.Files[0].Path)} 等 {Group.Files.Count} 个相同文件";
    public string SizeText => $"单个 {Format.Bytes(Group.SizeBytes)} · 可释放 {Format.Bytes(Group.ReclaimableBytes)}";
    public int SelectedCount => Files.Count(f => f.IsSelected);

    /// <summary>保留最早修改的一份，选中其余。</summary>
    public void SelectAllButOldest()
    {
        var oldest = Files.OrderBy(f => f.Entry.LastWriteUtc).First();
        foreach (var f in Files) f.IsSelected = !ReferenceEquals(f, oldest);
    }

    public void NotifySelectionChanged()
    {
        OnPropertyChanged(nameof(SelectedCount));
        SelectionChanged?.Invoke(this, EventArgs.Empty);
    }
}

public sealed partial class DuplicatesViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<string> Roots { get; } = new();
    public ObservableCollection<DuplicateGroupViewModel> Groups { get; } = new();
    public ObservableCollection<DuplicateFileViewModel> FileRows { get; } = new();
    private readonly HashSet<DuplicateGroupViewModel> _observedGroups = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(FindCommand), nameof(QuarantineSelectedCommand), nameof(KeepOldestInAllGroupsCommand), nameof(ClearSelectionCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private int _minSizeMb;

    [ObservableProperty]
    private string _status = "添加要查找的文件夹，然后点击“开始查找”。默认不勾选任何文件，请自行决定保留哪一份。";

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(QuarantineSelectedCommand))]
    private string _selectedText = "";

    [ObservableProperty]
    private string? _selectedRoot;

    public DuplicatesViewModel(AppServices s) : this(s, s.Settings, s.Env.Variables["UserProfile"]) { }

    internal DuplicatesViewModel(AppServices s, AppSettings settings, string userProfile)
    {
        _s = s;
        Groups.CollectionChanged += OnGroupsChanged;
        _minSizeMb = Math.Max(0, settings.DuplicateMinSizeMb);
        foreach (var r in settings.DuplicateRoots.Where(Directory.Exists)) Roots.Add(r);
        if (Roots.Count == 0)
        {
            var profile = userProfile;
            foreach (var sub in new[] { "Downloads", "Documents", "Pictures", "Videos", "Desktop" })
            {
                var p = Path.Combine(profile, sub);
                if (Directory.Exists(p)) Roots.Add(p);
            }
        }
    }

    private void OnGroupsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        foreach (var group in _observedGroups.Where(g => !Groups.Contains(g)).ToArray())
        {
            group.SelectionChanged -= OnSelectionChanged;
            group.Files.CollectionChanged -= OnFilesChanged;
            _observedGroups.Remove(group);
        }
        foreach (var group in Groups.Where(g => !_observedGroups.Contains(g)))
        {
            group.SelectionChanged += OnSelectionChanged;
            group.Files.CollectionChanged += OnFilesChanged;
            _observedGroups.Add(group);
        }
        RefreshFileRows();
    }

    private void OnSelectionChanged(object? sender, EventArgs e) => UpdateSelected();
    private void OnFilesChanged(object? sender, NotifyCollectionChangedEventArgs e) => RefreshFileRows();

    private void RefreshFileRows()
    {
        // Keep surviving row objects and their selection when individual copies are removed.
        var desired = Groups.SelectMany(g => g.Files).ToList();
        var remaining = desired.ToHashSet();
        for (var i = FileRows.Count - 1; i >= 0; i--)
            if (!remaining.Contains(FileRows[i])) FileRows.RemoveAt(i);
        for (var i = 0; i < desired.Count; i++)
        {
            if (i < FileRows.Count && ReferenceEquals(FileRows[i], desired[i])) continue;
            var oldIndex = FileRows.IndexOf(desired[i]);
            if (oldIndex >= 0) FileRows.Move(oldIndex, i);
            else FileRows.Insert(i, desired[i]);
        }
        UpdateSelected();
    }

    private bool CanFind => !IsBusy && Roots.Count > 0;

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanFind))]
    private async Task FindAsync(CancellationToken ct)
    {
        IsBusy = true;
        Groups.Clear();
        Summary = "";
        SelectedText = "";
        Status = "正在查找…";
        SaveSettings();

        var progress = new Progress<ScanProgress>(p => Status = $"正在查找… {p.CurrentPath}");

        try
        {
            var groups = await _s.DuplicateFinder.FindAsync(Roots.ToList(), (long)MinSizeMb * 1024 * 1024, progress, ct);
            foreach (var g in groups)
            {
                var vm = new DuplicateGroupViewModel(g);
                Groups.Add(vm);
            }
            Summary = $"{Groups.Count} 组重复文件，共可释放 {Format.Bytes(groups.Sum(g => g.ReclaimableBytes))}";
            Status = Groups.Count == 0 ? "没有发现重复文件。" : "查找完成。勾选要移入隔离区的副本，每组至少保留一份。";
            UpdateSelected();
        }
        catch (OperationCanceledException)
        {
            Status = "已取消。";
        }
        catch (Exception ex)
        {
            Status = $"查找出错：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanChangeSelection => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanChangeSelection))]
    private void KeepOldestInAllGroups()
    {
        foreach (var g in Groups) g.SelectAllButOldest();
        UpdateSelected();
    }

    [RelayCommand(CanExecute = nameof(CanChangeSelection))]
    private void ClearSelection()
    {
        foreach (var f in Groups.SelectMany(g => g.Files)) f.IsSelected = false;
        UpdateSelected();
    }

    private bool CanQuarantine => !IsBusy && Groups.Any(g => g.SelectedCount > 0)
        && !Groups.Any(g => g.Files.Count > 0 && g.SelectedCount == g.Files.Count);

    [RelayCommand(CanExecute = nameof(CanQuarantine))]
    private async Task QuarantineSelectedAsync()
    {
        // 安全约束：任何一组都不允许全部选中
        var fullySelected = Groups.Where(g => g.SelectedCount == g.Files.Count).ToList();
        if (fullySelected.Count > 0)
        {
            MessageBox.Show($"有 {fullySelected.Count} 组重复文件被全部选中。每组必须至少保留一份，请取消其中一个副本。",
                "无法继续", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // 用户确认前先固定本次请求：每组拟移走的副本与拟保留的副本。确认后不再读界面的选择状态
        var plan = Groups
            .Where(g => g.SelectedCount > 0)
            .Select(g => (Group: g, Remove: g.Files.Where(f => f.IsSelected).ToList(), Keep: g.Files.Where(f => !f.IsSelected).ToList()))
            .ToList();
        var selectedCount = plan.Sum(p => p.Remove.Count);
        var bytes = plan.Sum(p => p.Remove.Sum(f => f.Entry.Size));
        if (MessageBox.Show($"将把 {selectedCount} 个重复副本移入隔离区，约 {Format.Bytes(bytes)}。\n隔离区保留 {_s.Settings.RetentionDays} 天，可随时恢复。",
                "确认", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        IsBusy = true;
        try
        {
            // 执行前（确认对话框之后）核对：每组至少有一份拟保留的副本此刻仍存在、大小未变且内容哈希与本组一致。
            // 只看大小不够——同长度改写会让"保留的那份"实际已不是原内容。核对在后台线程做，避免大文件哈希卡界面
            var stale = await Task.Run(() => plan
                .Where(p => !p.Keep.Any(f =>
                {
                    try
                    {
                        var fi = new FileInfo(f.Entry.Path);
                        if (!fi.Exists || fi.Length != f.Entry.Size || fi.LastWriteTimeUtc != f.Entry.LastWriteUtc) return false;
                        return string.Equals(DuplicateFinder.ComputeGroupHash(f.Entry.Path), p.Group.Group.Hash, StringComparison.OrdinalIgnoreCase);
                    }
                    catch { return false; }
                }))
                .ToList());

            if (stale.Count > 0)
            {
                MessageBox.Show($"有 {stale.Count} 组重复文件中拟保留的副本已不存在或内容已改变，为避免删光原内容的所有副本，这些组本次不会处理。请重新查找。",
                    "数据已过期", MessageBoxButton.OK, MessageBoxImage.Warning);
                foreach (var p in stale) foreach (var f in p.Group.Files) f.IsSelected = false;
                plan = plan.Except(stale).ToList();
                if (plan.Count == 0) return;
            }

            var items = plan
                .Select(p => new ScanItem
                {
                    Id = "dup-" + p.Group.Group.Hash[..12],
                    ModuleId = "duplicates",
                    Group = "重复文件",
                    DisplayName = p.Group.Title,
                    Kind = ItemKind.FileSet,
                    Files = p.Remove.Select(f => f.Entry).ToList(),
                    SizeBytes = p.Remove.Sum(f => f.Entry.Size),
                    Risk = RiskLevel.Confirm,
                })
                .ToList();

            var report = await _s.Engine.CleanAsync(items, null, CancellationToken.None);

            // 按本次固定的请求更新列表：真正移入隔离区的副本移除，失败或跳过的保留并取消勾选
            var notMoved = new HashSet<string>(report.Failures.Where(f => f.Path is not null).Select(f => f.Path!), StringComparer.OrdinalIgnoreCase);
            foreach (var p in plan)
            {
                foreach (var f in p.Remove)
                {
                    bool moved = !notMoved.Contains(f.Entry.Path) && !File.Exists(f.Entry.Path);
                    if (moved) p.Group.Files.Remove(f);
                    else f.IsSelected = false;
                }
                if (p.Group.Files.Count < 2) Groups.Remove(p.Group);
            }

            Status = $"已移入隔离区 {report.FilesQuarantined} 个文件（{Format.Bytes(report.QuarantinedBytes)}，到期后释放）" +
                     (report.Failures.Count > 0 ? $"，{report.Failures.Count} 个失败，仍保留在列表中" : "") +
                     (report.Skipped > 0 ? $"，{report.Skipped} 个因扫描后变化而跳过，仍保留在列表中" : "") + "。";
            UpdateSelected();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void AddRoot()
    {
        var dlg = new OpenFolderDialog { Title = "添加要查找的文件夹" };
        if (dlg.ShowDialog() == true && !Roots.Contains(dlg.FolderName, StringComparer.OrdinalIgnoreCase))
        {
            Roots.Add(dlg.FolderName);
            FindCommand.NotifyCanExecuteChanged();
            SaveSettings();
        }
    }

    [RelayCommand]
    private void RemoveRoot(string? root)
    {
        if (root is null) return;
        Roots.Remove(root);
        FindCommand.NotifyCanExecuteChanged();
        SaveSettings();
    }

    [RelayCommand]
    private void OpenFile(DuplicateFileViewModel? f)
    {
        if (f is null) return;
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{f.Entry.Path}\"") { UseShellExecute = true }); } catch { }
    }

    private void UpdateSelected()
    {
        var files = Groups.SelectMany(g => g.Files).Where(f => f.IsSelected).ToList();
        SelectedText = files.Count == 0 ? "未选择任何副本" : $"已选择 {files.Count} 个副本，{Format.Bytes(files.Sum(f => f.Entry.Size))}";
        var fullySelected = Groups.Count(g => g.Files.Count > 0 && g.SelectedCount == g.Files.Count);
        if (fullySelected > 0) SelectedText += $"；{fullySelected} 组已全选，请每组至少取消一份以保留。";
        QuarantineSelectedCommand.NotifyCanExecuteChanged();
    }

    private void SaveSettings()
    {
        _s.Settings.DuplicateRoots = Roots.ToList();
        _s.Settings.DuplicateMinSizeMb = MinSizeMb;
        _s.Settings.Save();
    }
}
