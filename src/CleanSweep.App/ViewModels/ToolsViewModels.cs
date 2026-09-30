using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Drivers;
using CleanSweep.Core.Popup;
using CleanSweep.Core.Repair;
using CleanSweep.Core.Storage;
using CleanSweep.Core.SysInfo;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CleanSweep.App.ViewModels;

// =====================================================================
// 驱动与更新
// =====================================================================

public sealed class DriverRow
{
    public required DriverPackageRow Row { get; init; }
    public string Published => Row.Package.PublishedName;
    public string Original => Row.Package.OriginalName;
    public string Provider => Row.Package.Provider;
    public string Class => Row.Package.ClassName;
    public string Version => $"{Row.Package.DriverVersion}（{Row.Package.DriverDate}）";
    public string Signer => Row.Package.Signer;
    public bool IsOld => !Row.IsNewestInFamily;
    public bool CanDelete => !Row.IsNewestInFamily && !Row.InUse && Row.FamilySize > 1;
    public string StateText => Row.IsNewestInFamily ? (Row.FamilySize > 1 ? "最新版本" : "") : Row.InUse ? "旧版本，仍有设备在用" : "旧版本，可删除";
}

public sealed class UpdateRow
{
    public required InstalledUpdate Update { get; init; }
    public string Id => Update.HotFixId;
    public string Description => Update.Description;
    public string InstalledText => Update.InstalledOn is { } d ? d.ToString("yyyy-MM-dd") : "";
}

public sealed partial class DriverViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<DriverRow> Drivers { get; } = new();
    public ObservableCollection<UpdateRow> Updates { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(DeleteOldCommand), nameof(ExportCommand), nameof(PauseCommand), nameof(ResumeCommand), nameof(UninstallUpdateCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private bool _onlyOld;

    [ObservableProperty]
    private string _pauseText = "";

    [ObservableProperty]
    private int _pauseDays = 7;

    [ObservableProperty]
    private string _output = "";

    public bool HasLoaded { get; private set; }
    private IReadOnlyList<DriverPackageRow> _all = Array.Empty<DriverPackageRow>();

    public DriverViewModel(AppServices s)
    {
        _s = s;
    }

    private bool NotBusy => !IsBusy;

    partial void OnOnlyOldChanged(bool value) => Fill();

    private void Fill()
    {
        Drivers.Clear();
        foreach (var r in _all.Where(r => !OnlyOld || !r.IsNewestInFamily)) Drivers.Add(new DriverRow { Row = r });
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        Status = "正在读取驱动包（pnputil）…";
        try
        {
            _all = await DriverStore.ListAsync();
            Fill();
            var old = _all.Count(r => !r.IsNewestInFamily);
            var deletable = _all.Count(r => !r.IsNewestInFamily && !r.InUse);
            Summary = $"{_all.Count} 个第三方驱动包，{old} 个是同一硬件的旧版本，其中 {deletable} 个没有设备在用、可以删除。";
            var pause = DriverStore.GetPauseState();
            PauseText = pause.Paused ? $"Windows 更新已暂停到 {pause.PausedUntil:yyyy-MM-dd HH:mm}。" : "Windows 更新未暂停。";
            Updates.Clear();
            foreach (var u in await Task.Run(DriverStore.GetInstalledUpdates)) Updates.Add(new UpdateRow { Update = u });
            HasLoaded = true;
            Status = _all.Count == 0 ? "没有读到驱动包。pnputil 需要管理员权限才能列出完整信息。" : "删除只针对旧版本且无设备使用的包，使用 pnputil /delete-driver（不带 /force）。";
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

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task DeleteOldAsync(DriverRow? row)
    {
        if (row is null || !row.CanDelete) return;
        if (MessageBox.Show($"删除旧版本驱动包 {row.Published}（{row.Original} {row.Version}，{row.Provider}）？\n\n同一硬件已有更新版本，且没有设备在使用这个包。删除后无法回滚到该版本，除非重新安装。\n\n建议先“导出全部驱动”备份。",
                "删除旧驱动包", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var (ok, msg) = await _s.Drivers.DeleteOldPackageAsync(row.Row);
            Status = msg;
            if (ok) await RefreshAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task ExportAsync()
    {
        var dlg = new OpenFolderDialog { Title = "选择驱动备份目录（会导出全部第三方驱动包）" };
        if (dlg.ShowDialog() != true) return;
        IsBusy = true;
        Output = "";
        Status = "正在导出驱动包…";
        try
        {
            var progress = new Progress<string>(l => Output += l + "\n");
            var (ok, msg) = await _s.Drivers.ExportAllAsync(dlg.FolderName, _s.Guard, CancellationToken.None, progress);
            Status = msg;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void Pause()
    {
        var (ok, msg) = _s.Drivers.PauseUpdates(PauseDays);
        Status = msg;
        if (ok) PauseText = msg;
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void Resume()
    {
        var (_, msg) = _s.Drivers.ResumeUpdates();
        Status = msg;
        PauseText = DriverStore.GetPauseState().Paused ? PauseText : "Windows 更新未暂停。";
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task UninstallUpdateAsync(UpdateRow? row)
    {
        if (row is null) return;
        if (MessageBox.Show($"卸载更新 {row.Id}（{row.Description}）？\n\n将运行 wusa /uninstall /kb:…，Windows 会提示是否重启。安全更新卸载后系统会重新变得易受攻击，请只在该更新确实导致问题时卸载。",
                "卸载更新", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var (_, msg) = await _s.Drivers.UninstallUpdateAsync(row.Id);
            Status = msg;
        }
        finally
        {
            IsBusy = false;
        }
    }
}

// =====================================================================
// 弹窗拦截
// =====================================================================

public sealed partial class BlockableRow : ObservableObject
{
    private readonly Func<string, bool, (bool, string)> _apply;
    private bool _suppress;

    public BlockableRow(string process, bool blocked, Func<string, bool, (bool, string)> apply)
    {
        Process = process;
        _blocked = blocked;
        _apply = apply;
    }

    public string Process { get; }

    [ObservableProperty]
    private bool _blocked;

    [ObservableProperty]
    private string? _message;

    partial void OnBlockedChanged(bool value)
    {
        if (_suppress) return;
        var (ok, msg) = _apply(Process, value);
        Message = msg;
        if (!ok)
        {
            _suppress = true;
            Blocked = !value;
            _suppress = false;
        }
    }
}

public sealed class PopupRuleRow
{
    public required PopupRule Rule { get; init; }
    public int Count { get; init; }
    public string Title => Rule.Title;
    public string Detail => $"进程 {Rule.Process}" + (Rule.WindowClass is not null ? $" · 类名 {Rule.WindowClass}" : "") + (Rule.WindowTitle is not null ? $" · 标题 {Rule.WindowTitle}" : "");
    public string Note => Rule.Note ?? "";
    public string CountText => Count > 0 ? $"已拦截 {Count} 次" : "";
}

public sealed partial class PopupViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<PopupRuleRow> Rules { get; } = new();
    public ObservableCollection<BlockableRow> Blockable { get; } = new();
    public ObservableCollection<string> Recent { get; } = new();

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private string _status = "";

    public PopupViewModel(AppServices s)
    {
        _s = s;
        _enabled = s.Settings.PopupBlockerEnabled;
        s.PopupBlocker.Closed += (_, hit) => Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            Recent.Insert(0, $"{hit.TimeUtc.ToLocalTime():HH:mm:ss} 关闭 {hit.ProcessName}（{hit.RuleId}）：{hit.WindowTitle}");
            if (Recent.Count > 100) Recent.RemoveAt(Recent.Count - 1);
            Refresh();
        });
        Refresh();
    }

    partial void OnEnabledChanged(bool value)
    {
        _s.Settings.PopupBlockerEnabled = value;
        _s.Settings.Save();
        _s.ApplyPopupBlocking();
        Refresh();
    }

    [RelayCommand]
    private void Refresh()
    {
        var counts = _s.PopupBlocker.Counts;
        Rules.Clear();
        foreach (var r in _s.PopupBlocker.Rules) Rules.Add(new PopupRuleRow { Rule = r, Count = counts.GetValueOrDefault(r.Id) });
        var blocked = new HashSet<string>(PopupBlocker.ListBlocked(), StringComparer.OrdinalIgnoreCase);
        Blockable.Clear();
        foreach (var p in _s.PopupBlocker.BlockableProcesses.OrderBy(p => p))
            Blockable.Add(new BlockableRow(p, blocked.Contains(p), (proc, b) => _s.PopupBlocker.SetBlocked(proc, b)));
        Status = _s.PopupBlocker.IsRunning
            ? $"正在运行：每 2 秒枚举顶层窗口，命中 {Rules.Count} 条规则之一就发送关闭消息（不结束进程，不注入，不钩子）。关闭本程序即停止。"
            : "已停止。开启后只在本程序运行期间生效。";
        if (_s.PopupBlocker.Rejected.Count > 0) Status += $" {_s.PopupBlocker.Rejected.Count} 条规则被拒绝加载。";
    }
}

// =====================================================================
// 系统修复
// =====================================================================

public sealed class RepairRow
{
    public required RepairAction Action { get; init; }
    public string Title => Action.Title;
    public string Description => Action.Description + (Action.NeedsAdmin ? "需要管理员权限。" : "") + (Action.LongRunning ? "" : "");
}

public sealed partial class RepairViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<RepairRow> Actions { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand), nameof(SaveHostsCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "选择一项修复操作。sfc 与 DISM 会持续数分钟到数十分钟，期间可以继续使用电脑。";

    [ObservableProperty]
    private string _output = "";

    [ObservableProperty]
    private string _hosts = "";

    [ObservableProperty]
    private string _hostsStatus = "";

    public RepairViewModel(AppServices s)
    {
        _s = s;
        foreach (var a in SystemRepair.Actions) Actions.Add(new RepairRow { Action = a });
        LoadHosts();
    }

    private bool NotBusy => !IsBusy;

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(NotBusy))]
    private async Task RunAsync(RepairRow? row, CancellationToken ct)
    {
        if (row is null) return;
        var cmd = SystemRepair.BuildCommand(row.Action.Operation);
        var msg = $"{row.Title}\n\n{row.Description}" + (cmd is not null ? $"\n\n将执行：{cmd.Value.Exe} {cmd.Value.Args}" : "") +
                  (row.Action.LongRunning ? "\n\n一旦开始不会中途强杀，取消只停止等待。" : "");
        if (MessageBox.Show(msg, row.Title, MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        IsBusy = true;
        Output = "";
        Status = $"正在执行：{row.Title}…";
        try
        {
            var progress = new Progress<string>(l => Output += l + "\n");
            var r = await _s.Repair.RunAsync(row.Action.Operation, ct, progress);
            if (string.IsNullOrWhiteSpace(Output)) Output = r.Output;
            Status = r.Success ? $"{row.Title} 完成（{r.Elapsed.TotalSeconds:0} 秒）。" : r.TimedOut ? $"{row.Title} 超时。" : $"{row.Title} 退出码 {r.ExitCode}（需要管理员权限的操作在非提权运行时会失败）。";
        }
        catch (Exception ex)
        {
            Status = $"{row.Title} 出错：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void LoadHosts()
    {
        try
        {
            Hosts = SystemRepair.ReadHosts();
            var backups = _s.Repair.ListHostsBackups();
            HostsStatus = $"{SystemRepair.HostsPath}" + (backups.Count > 0 ? $"，已有 {backups.Count} 个备份（{AppPaths.HostsBackupDir}）" : "");
        }
        catch (Exception ex)
        {
            HostsStatus = "读取失败：" + ex.Message;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void SaveHosts()
    {
        var bad = SystemRepair.ValidateHosts(Hosts);
        if (bad is not null)
        {
            HostsStatus = bad;
            return;
        }
        if (MessageBox.Show("保存 hosts 文件？原文件会先备份到数据目录。错误的 hosts 条目会导致网站无法访问。", "保存 hosts", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        var (_, msg) = _s.Repair.WriteHosts(Hosts);
        HostsStatus = msg;
    }

    [RelayCommand]
    private void ResetHosts()
    {
        if (MessageBox.Show("把 hosts 恢复为 Windows 默认内容？现有条目会先备份。", "恢复默认 hosts", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        Hosts = SystemRepair.DefaultHosts;
        var (_, msg) = _s.Repair.WriteHosts(Hosts);
        HostsStatus = msg;
    }
}

// =====================================================================
// 系统信息
// =====================================================================

public sealed partial class SystemInfoViewModel : ObservableObject
{
    public ObservableCollection<InfoItem> Items { get; } = new();

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "";

    public bool HasLoaded { get; private set; }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var items = await Task.Run(SystemInfo.Collect);
            Items.Clear();
            foreach (var i in items) Items.Add(i);
            HasLoaded = true;
            Status = $"{items.Count} 项。全部只读。";
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

    [RelayCommand]
    private void Copy()
    {
        try
        {
            Clipboard.SetText(string.Join("\n", Items.GroupBy(i => i.Group).Select(g => $"[{g.Key}]\n" + string.Join("\n", g.Select(i => $"{i.Name}: {i.Value}")))));
            Status = "已复制到剪贴板。";
        }
        catch (Exception ex)
        {
            Status = "复制失败：" + ex.Message;
        }
    }
}
