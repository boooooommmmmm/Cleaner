using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Privacy;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CleanSweep.App.ViewModels;

public sealed class ShredFileRow
{
    public ShredFileRow(string path)
    {
        Path = path;
        try { SizeText = Format.Bytes(new FileInfo(path).Length); } catch { SizeText = "-"; }
        var ssd = DiskMedia.IsSolidState(path);
        MediaText = ssd switch { true => "固态盘：覆写不保证擦除", false => "机械盘", _ => "介质未知" };
        IsSolidState = ssd != false;
    }

    public string Path { get; }
    public string SizeText { get; }
    public string MediaText { get; }
    public bool IsSolidState { get; }
    public string? Result { get; set; }
}

public sealed class DriveRow
{
    public required string Root { get; init; }
    public required string Label { get; init; }
    public string? Verdict { get; init; }
    public bool CanWipe => Verdict is null;
    public override string ToString() => Label;
}

/// <summary>文件粉碎与空闲空间擦除（设计文档 3.6）。都不经隔离区，不可恢复。</summary>
public sealed partial class ShredViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<ShredFileRow> Files { get; } = new();
    public ObservableCollection<DriveRow> Drives { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ShredCommand), nameof(WipeCommand), nameof(AddFilesCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private int _passes = 3;

    [ObservableProperty]
    private string _status = "选择要彻底删除的文件。文件内容会被多次覆写后删除，不进隔离区，无法恢复。";

    [ObservableProperty]
    private string _mediaWarning = "";

    [ObservableProperty]
    private DriveRow? _selectedDrive;

    [ObservableProperty]
    private string _wipeStatus = "";

    [ObservableProperty]
    private string _wipeProgress = "";

    public ShredViewModel(AppServices s)
    {
        _s = s;
        RefreshDrives();
    }

    private bool NotBusy => !IsBusy;

    partial void OnSelectedDriveChanged(DriveRow? value)
    {
        WipeStatus = value is null ? "" : value.Verdict ?? "机械盘，可以擦除空闲空间。过程会写满磁盘再释放，耗时与空闲容量成正比。";
        WipeCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void AddFiles()
    {
        var dlg = new OpenFileDialog { Title = "选择要粉碎的文件", Multiselect = true, CheckFileExists = true };
        if (dlg.ShowDialog() != true) return;
        foreach (var f in dlg.FileNames)
        {
            if (Files.Any(r => r.Path.Equals(f, StringComparison.OrdinalIgnoreCase))) continue;
            Files.Add(new ShredFileRow(f));
        }
        UpdateWarning();
        ShredCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void RemoveFile(ShredFileRow? row)
    {
        if (row is null) return;
        Files.Remove(row);
        UpdateWarning();
        ShredCommand.NotifyCanExecuteChanged();
    }

    private void UpdateWarning()
    {
        MediaWarning = Files.Any(f => f.IsSolidState)
            ? "有文件位于固态盘或介质未知的卷上：SSD 的磨损均衡会保留旧数据块，覆写不保证擦除。彻底防止恢复应依赖 BitLocker 加密与 TRIM。"
            : "";
    }

    private bool CanShred => !IsBusy && Files.Count > 0;

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanShred))]
    private async Task ShredAsync(CancellationToken ct)
    {
        var passes = Math.Clamp(Passes, FileShredder.MinPasses, FileShredder.MaxPasses);
        var msg = $"将覆写 {passes} 次并永久删除 {Files.Count} 个文件。此操作不经过隔离区，无法恢复。\n\n{string.Join("\n", Files.Take(10).Select(f => f.Path))}" +
                  (Files.Count > 10 ? $"\n… 另有 {Files.Count - 10} 个" : "") + (MediaWarning.Length > 0 ? "\n\n" + MediaWarning : "");
        if (MessageBox.Show(msg, "确认粉碎", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        IsBusy = true;
        var targets = Files.ToList();
        int ok = 0;
        try
        {
            foreach (var row in targets)
            {
                ct.ThrowIfCancellationRequested();
                Status = $"正在粉碎 {row.Path}…";
                var result = await Task.Run(() => FileShredder.Shred(row.Path, passes, _s.Guard, ct), CancellationToken.None);
                row.Result = result.Message;
                _s.Log.Write(null, "shred", "shred", row.Path, 0, result.Success, result.Message);
                if (result.Success)
                {
                    ok++;
                    Files.Remove(row);
                }
            }
            Status = $"已粉碎 {ok} 个文件" + (targets.Count - ok > 0 ? $"，{targets.Count - ok} 个失败（保留在列表中，鼠标悬停查看原因）" : "") + "。";
        }
        catch (OperationCanceledException)
        {
            Status = $"已取消。已粉碎 {ok} 个文件。";
        }
        finally
        {
            IsBusy = false;
            UpdateWarning();
        }
    }

    // ---------- 空闲空间擦除 ----------

    private void RefreshDrives()
    {
        Drives.Clear();
        try
        {
            foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
            {
                var root = d.RootDirectory.FullName;
                var free = Format.Bytes(d.AvailableFreeSpace);
                var verdict = FreeSpaceWiper.CheckVolume(root);
                Drives.Add(new DriveRow { Root = root, Label = $"{root.TrimEnd('\\')}  {d.VolumeLabel}（空闲 {free}）", Verdict = verdict });
            }
        }
        catch { }
        SelectedDrive = Drives.FirstOrDefault();
    }

    private bool CanWipe => !IsBusy && SelectedDrive is { CanWipe: true };

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanWipe))]
    private async Task WipeAsync(CancellationToken ct)
    {
        var drive = SelectedDrive;
        if (drive is null) return;
        var msg = $"将把 {drive.Root} 的全部空闲空间写零后释放，以覆盖已删除文件的残留数据。\n\n过程中该卷会被临时写满，正在运行的程序可能因磁盘满而报错；耗时与空闲容量成正比。确定继续？";
        if (MessageBox.Show(msg, "擦除空闲空间", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        IsBusy = true;
        WipeStatus = "正在擦除…";
        try
        {
            var progress = new Progress<long>(b => WipeProgress = $"已写入 {Format.Bytes(b)}");
            var (success, message, written) = await FreeSpaceWiper.WipeAsync(drive.Root, progress, ct);
            WipeStatus = message;
            _s.Log.Write(null, "shred", "wipe-free-space", drive.Root, written, success, message);
        }
        finally
        {
            IsBusy = false;
            WipeProgress = "";
            RefreshDrives();
        }
    }
}
