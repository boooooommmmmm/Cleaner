using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Uninstall;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class UninstallRow
{
    public UninstallRow(InstalledApp app)
    {
        App = app;
        IsBloatware = Bloatware.IsKnown(app);
        CanUninstall = Uninstaller.BuildCommand(app, quiet: false, out var error) is not null;
        CanRemoveEntry = !CanUninstall && Uninstaller.UninstallerMissing(app, out _);
        Note = CanRemoveEntry ? "卸载程序已不存在，只能移除登记项" : error;
    }

    /// <summary>卸载程序已不存在：不能卸载，但可以把"应用和功能"里这条登记项移除（备份后删键）。</summary>
    public bool CanRemoveEntry { get; }

    public InstalledApp App { get; }
    public string Name => App.Name;
    public string Publisher => App.Publisher ?? "未知";
    public string Version => App.Version ?? "";
    public string SizeText => App.EstimatedSizeBytes > 0 ? Format.Bytes(App.EstimatedSizeBytes) : "";
    public string InstallDateText => App.InstallDate is { } d ? d.ToString("yyyy-MM-dd") : "";
    public string SourceText => App.Source switch
    {
        AppSource.Registry => App.IsWindowsInstaller ? "MSI" : "程序",
        AppSource.Uwp => "应用商店",
        AppSource.Portable => "便携",
        _ => App.Source.ToString(),
    };
    public string Location => App.InstallLocation ?? "";
    public bool IsBloatware { get; }
    public bool CanUninstall { get; }
    public bool CanOpenLocation => !string.IsNullOrWhiteSpace(App.InstallLocation) && Directory.Exists(App.InstallLocation.Trim('"'));
    public string? Note { get; }
    public string Tags => string.Join(" · ", new[] { IsBloatware ? "预装软件" : null, App.IsSystemComponent ? "系统组件" : null, App.IsMicrosoft ? "微软" : null }.Where(t => t is not null));
}

/// <summary>软件卸载与安装监控页（设计文档 5.1）。</summary>
public sealed partial class UninstallViewModel : ObservableObject
{
    private readonly AppServices _s;
    private readonly Action<string> _scanResidueFor;

    public ObservableCollection<UninstallRow> Rows { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(UninstallCommand), nameof(UninstallQuietCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private bool _showSystemComponents;

    [ObservableProperty]
    private bool _onlyBloatware;

    [ObservableProperty]
    private string _status = "点击“刷新”读取已安装的软件。";

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private string _monitorStatus = "";

    [ObservableProperty]
    private string? _monitorResult;

    public bool HasScanned { get; private set; }

    public UninstallViewModel(AppServices s, Action<string> scanResidueFor)
    {
        _s = s;
        _scanResidueFor = scanResidueFor;
        View = CollectionViewSource.GetDefaultView(Rows);
        View.Filter = Filter;
        View.SortDescriptions.Add(new SortDescription(nameof(UninstallRow.Name), ListSortDirection.Ascending));
        UpdateMonitorStatus();
    }

    partial void OnSearchChanged(string value) => View.Refresh();
    partial void OnShowSystemComponentsChanged(bool value) => View.Refresh();
    partial void OnOnlyBloatwareChanged(bool value) => View.Refresh();

    private bool Filter(object o)
    {
        if (o is not UninstallRow r) return false;
        if (!ShowSystemComponents && r.App.IsSystemComponent) return false;
        if (OnlyBloatware && !r.IsBloatware) return false;
        if (string.IsNullOrWhiteSpace(Search)) return true;
        var q = Search.Trim();
        return r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private bool NotBusy => !IsBusy;

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        Status = "正在读取已安装的软件…";
        try
        {
            var snap = await Task.Run(() => _s.Inventory.Scan());
            Rows.Clear();
            foreach (var app in snap.Apps) Rows.Add(new UninstallRow(app));
            View.Refresh();
            HasScanned = true;
            var bloat = Rows.Count(r => r.IsBloatware);
            Summary = $"{snap.Apps.Count(a => !a.IsSystemComponent)} 个应用（另有 {snap.Apps.Count(a => a.IsSystemComponent)} 个系统组件）" + (bloat > 0 ? $"，{bloat} 个疑似预装软件" : "");
            Status = "卸载会调用软件自己的卸载程序，请按其提示操作；完成后可到“残留清理”处理遗留的用户数据。";
        }
        catch (Exception ex)
        {
            Status = $"读取失败：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>卸载程序已不存在时的出路：移除登记项（备份后删 Uninstall 键），不运行任何程序、不动安装目录。</summary>
    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RemoveEntryAsync(UninstallRow? row)
    {
        if (row is null || !Uninstaller.UninstallerMissing(row.App, out var exe)) return;
        var needsAdmin = row.App.RegistryKey!.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) && !_s.Elevation.IsElevated;
        var msg = $"移除“{row.Name}”的卸载登记项？\n\n它的卸载程序已不存在：\n{exe}\n\n这不会运行任何卸载逻辑，也不会删除程序目录，只是把“应用和功能”里这一条登记项删掉：\n{row.App.RegistryKey}\n\n删除前会导出 .reg 备份，可在“设置 → 备份与还原”中还原。之后可到“残留清理”处理它遗留的文件。" +
                  (needsAdmin ? "\n\n这个登记项在 HKLM 下，普通权限无法删除，请先点左下角“以管理员身份重新启动”。" : "");
        if (MessageBox.Show(msg, "移除卸载项", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        IsBusy = true;
        try
        {
            var backup = await Task.Run(() => _s.Uninstaller.RemoveEntry(row.App, _s.RegistryOps));
            Status = $"已移除“{row.Name}”的卸载登记项（备份 {backup}）。";
            await RefreshAsync();
            if (MessageBox.Show($"“{row.Name}”的登记项已移除。现在扫描它遗留在用户目录中的数据？", "扫描残留", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                _scanResidueFor(row.Name);
        }
        catch (Exception ex)
        {
            Status = $"移除失败：{ex.Message}" + (AccessDenied.Is(ex) && !_s.Elevation.IsElevated ? " 该登记项需要管理员权限，请点左下角“以管理员身份重新启动”后再试。" : "");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private Task UninstallAsync(UninstallRow? row) => RunUninstallAsync(row, quiet: false);

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private Task UninstallQuietAsync(UninstallRow? row) => RunUninstallAsync(row, quiet: true);

    private async Task RunUninstallAsync(UninstallRow? row, bool quiet)
    {
        if (row is null) return;
        var cmd = Uninstaller.BuildCommand(row.App, quiet, out var error);
        if (cmd is null)
        {
            MessageBox.Show(error, "无法卸载", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var msg = $"卸载“{row.Name}”？\n\n将运行它的官方卸载程序：\n{cmd.Exe} {cmd.Args}\n\n" +
                  (quiet ? "静默模式：不显示卸载程序界面，直接执行。" : "请按卸载程序的提示完成操作。") +
                  "\n\n卸载完成后可在“残留清理”中查看并清理遗留的用户数据。";
        if (MessageBox.Show(msg, "确认卸载", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        IsBusy = true;
        Status = $"正在卸载“{row.Name}”，等待卸载程序结束…";
        try
        {
            var result = await _s.Uninstaller.RunAsync(row.App, quiet, CancellationToken.None);
            Status = result.Message;
            if (result.Started) await RefreshAsync();
            if (result.Started && !result.StillInstalled)
            {
                if (MessageBox.Show($"“{row.Name}”已卸载。现在扫描它遗留在用户目录中的数据？", "扫描残留", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    _scanResidueFor(row.Name);
            }
        }
        catch (Exception ex)
        {
            Status = $"卸载出错：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ScanResidue(UninstallRow? row)
    {
        if (row is null) return;
        _scanResidueFor(row.Name);
    }

    [RelayCommand]
    private void OpenLocation(UninstallRow? row)
    {
        if (row is null || !row.CanOpenLocation) return;
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{row.App.InstallLocation!.Trim('"')}\"") { UseShellExecute = true }); } catch { }
    }

    // ---------- 安装监控 ----------

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task TakeSnapshotAsync()
    {
        IsBusy = true;
        Status = "正在记录安装前快照…";
        try
        {
            var snap = await Task.Run(() => _s.InstallMonitor.Take("before-install"));
            var file = _s.InstallMonitor.Save(snap);
            _s.Log.Write(null, "install-monitor", "snapshot", file, 0, true, $"{snap.Apps.Count} 个应用，{snap.Directories.Count} 个目录");
            MonitorResult = null;
            Status = "快照已保存。现在安装软件，装完后点“与快照比对”。";
        }
        catch (Exception ex)
        {
            Status = $"记录快照失败：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
            UpdateMonitorStatus();
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task CompareSnapshotAsync()
    {
        var before = _s.InstallMonitor.LoadLatest();
        if (before is null)
        {
            MessageBox.Show("还没有快照。请先在安装软件之前点“记录安装前快照”。", "安装监控", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        IsBusy = true;
        Status = "正在比对…";
        try
        {
            var after = await Task.Run(() => _s.InstallMonitor.Take("after-install"));
            var diff = InstallMonitor.Diff(before, after);
            var lines = new List<string> { $"与 {Format.LocalTime(before.TakenUtc)} 的快照相比：" };
            if (diff.IsEmpty) lines.Add("没有发现新增的应用、目录、服务或启动项。");
            if (diff.NewApps.Count > 0) lines.Add("新增应用：" + string.Join("、", diff.NewApps));
            if (diff.RemovedApps.Count > 0) lines.Add("消失的应用：" + string.Join("、", diff.RemovedApps));
            if (diff.NewDirectories.Count > 0) lines.Add("新增目录：\n  " + string.Join("\n  ", diff.NewDirectories.Take(40)) + (diff.NewDirectories.Count > 40 ? $"\n  … 另有 {diff.NewDirectories.Count - 40} 个" : ""));
            if (diff.NewServices.Count > 0) lines.Add("新增服务：" + string.Join("、", diff.NewServices) + "（可在“开机加速”中处理）");
            if (diff.NewRunEntries.Count > 0) lines.Add("新增启动项：" + string.Join("、", diff.NewRunEntries.Select(r => r.Name)) + "（可在“开机加速”中禁用）");
            MonitorResult = string.Join("\n", lines);
            _s.Log.Write(null, "install-monitor", "compare", null, 0, true, $"{diff.NewApps.Count} 个新应用，{diff.NewDirectories.Count} 个新目录");
            Status = "比对完成。新增目录若属于已卸载的软件，可在“残留清理”中移入隔离区。";
        }
        catch (Exception ex)
        {
            Status = $"比对失败：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ClearSnapshots()
    {
        _s.InstallMonitor.DeleteAll();
        MonitorResult = null;
        UpdateMonitorStatus();
    }

    private void UpdateMonitorStatus()
    {
        var latest = _s.InstallMonitor.LoadLatest();
        MonitorStatus = latest is null
            ? "安装软件前先记录快照，安装后比对，就能看到它新增了哪些目录、服务和启动项。"
            : $"最近的快照：{Format.LocalTime(latest.TakenUtc)}（{latest.Apps.Count} 个应用，{latest.Directories.Count} 个目录）。";
    }
}
