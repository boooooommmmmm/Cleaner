using System.Collections.ObjectModel;
using System.Diagnostics;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CleanSweep.App.ViewModels;

public sealed class DriveItem
{
    public required string Root { get; init; }
    public required string Label { get; init; }
}

public sealed class DirectoryRow
{
    public required DirectoryNode Node { get; init; }
    public required long ParentBytes { get; init; }
    public string Name => Node.Name;
    public string SizeText => Format.Bytes(Node.SizeBytes);
    public string PercentText => Format.Percent(Node.SizeBytes, ParentBytes);
    public double Percent => ParentBytes <= 0 ? 0 : 100.0 * Node.SizeBytes / ParentBytes;
    public string FilesText => $"{Node.FileCount:N0} 个文件";
    public bool AccessDenied => Node.AccessDenied;
}

public sealed class LargeFileRow
{
    public required FileEntry Entry { get; init; }
    public string Name => Path.GetFileName(Entry.Path);
    public string Directory => Path.GetDirectoryName(Entry.Path) ?? "";
    public string SizeText => Format.Bytes(Entry.Size);
    public string ModifiedText => Format.LocalTime(Entry.LastWriteUtc);
}

public sealed partial class SpaceAnalyzerViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<DriveItem> Drives { get; } = new();
    public ObservableCollection<DirectoryRow> Rows { get; } = new();
    public ObservableCollection<DirectoryNode> Breadcrumb { get; } = new();
    public ObservableCollection<LargeFileRow> LargestFiles { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    private string _targetPath = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "选择一个磁盘或文件夹，然后点击“开始分析”。";

    [ObservableProperty]
    private DirectoryNode? _root;

    [ObservableProperty]
    private DirectoryNode? _current;

    [ObservableProperty]
    private string _summary = "";

    public SpaceAnalyzerViewModel(AppServices s)
    {
        _s = s;
        foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable))
        {
            var label = string.IsNullOrEmpty(d.VolumeLabel) ? d.Name : $"{d.Name}  {d.VolumeLabel}";
            Drives.Add(new DriveItem
            {
                Root = d.RootDirectory.FullName,
                Label = $"{label}  ·  已用 {Format.Bytes(d.TotalSize - d.TotalFreeSpace)} / {Format.Bytes(d.TotalSize)}",
            });
        }
        TargetPath = Drives.FirstOrDefault()?.Root ?? "C:\\";
    }

    private bool CanAnalyze => !IsBusy && !string.IsNullOrWhiteSpace(TargetPath) && Directory.Exists(TargetPath);

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanAnalyze))]
    private async Task AnalyzeAsync(CancellationToken ct)
    {
        IsBusy = true;
        Root = null;
        Current = null;
        Rows.Clear();
        Breadcrumb.Clear();
        LargestFiles.Clear();
        Status = "正在分析…";

        var progress = new Progress<ScanProgress>(p => Status = $"正在分析… 已统计 {p.ItemsFound:N0} 个目录，{Format.Bytes(p.BytesFound)}");

        try
        {
            var report = await _s.SpaceAnalyzer.AnalyzeAsync(TargetPath, 200, progress, ct);
            Root = report.Root;
            foreach (var f in report.LargestFiles) LargestFiles.Add(new LargeFileRow { Entry = f });
            Navigate(report.Root);
            Summary = $"{Format.Bytes(report.TotalBytes)} · {report.TotalFiles:N0} 个文件 · {report.Root.DirectoryCount:N0} 个目录 · 耗时 {report.Elapsed.TotalSeconds:0.#} 秒";
            Status = "分析完成。双击目录可以深入查看；重解析点（Junction、符号链接）与云端占位文件不计入。";
        }
        catch (OperationCanceledException)
        {
            Status = "已取消。";
        }
        catch (Exception ex)
        {
            Status = $"分析出错：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void Navigate(DirectoryNode? node)
    {
        if (node is null || Root is null) return;
        Current = node;

        Rows.Clear();
        foreach (var c in node.Children) Rows.Add(new DirectoryRow { Node = c, ParentBytes = node.SizeBytes });

        Breadcrumb.Clear();
        foreach (var n in PathTo(Root, node)) Breadcrumb.Add(n);
    }

    [RelayCommand]
    private void NavigateUp()
    {
        if (Root is null || Current is null || Current == Root) return;
        var path = PathTo(Root, Current);
        if (path.Count >= 2) Navigate(path[^2]);
    }

    [RelayCommand]
    private void SelectDrive(DriveItem? drive)
    {
        if (drive is not null) TargetPath = drive.Root;
    }

    [RelayCommand]
    private void BrowseFolder()
    {
        var dlg = new OpenFolderDialog { Title = "选择要分析的文件夹", InitialDirectory = Directory.Exists(TargetPath) ? TargetPath : null };
        if (dlg.ShowDialog() == true) TargetPath = dlg.FolderName;
    }

    [RelayCommand]
    private void OpenInExplorer(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            if (Directory.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
            else if (File.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch
        {
        }
    }

    private static List<DirectoryNode> PathTo(DirectoryNode root, DirectoryNode target)
    {
        var path = new List<DirectoryNode>();
        Find(root, target, path);
        return path;

        static bool Find(DirectoryNode n, DirectoryNode t, List<DirectoryNode> acc)
        {
            acc.Add(n);
            if (ReferenceEquals(n, t)) return true;
            foreach (var c in n.Children)
            {
                if (Find(c, t, acc)) return true;
            }
            acc.RemoveAt(acc.Count - 1);
            return false;
        }
    }
}
