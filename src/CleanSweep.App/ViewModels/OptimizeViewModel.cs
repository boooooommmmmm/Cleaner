using System.Collections.ObjectModel;
using System.ServiceProcess;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Model;
using CleanSweep.Core.Optimize;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class ServiceTweakRow
{
    public required ServiceTweakState State { get; init; }
    public string Title => State.Tweak.Title;
    public string Description => State.Tweak.Description + (State.Tweak.Condition is { } c ? $"（{c}）" : "");
    public string RestoreHint => "恢复：" + State.Tweak.RestoreHint;
    public RiskLevel Risk => State.Tweak.Risk;
    public string StatusText => !State.Installed ? "未安装" :
        (State.StartMode switch { ServiceStartMode.Automatic => "自动启动", ServiceStartMode.Manual => "手动启动", ServiceStartMode.Disabled => "已禁用", _ => State.StartMode?.ToString() ?? "?" })
        + "，" + (State.Status switch { ServiceControllerStatus.Running => "正在运行", ServiceControllerStatus.Stopped => "已停止", _ => State.Status?.ToString() ?? "" });
    public bool CanOptimize => State.Installed && State.IsAutomatic;

    /// <summary>只有本程序改过（有原始启动类型记录）的服务才提供恢复：目录里不少服务默认就是手动 / 已禁用，不能把它们设成自动。</summary>
    public bool CanRestore => State.CanRestore;
    public string RecordText => State.RecordedOriginal is null ? "" : "（本程序已改为手动）";
}

public sealed partial class ContextMenuRow : ObservableObject
{
    private readonly Func<ContextMenuRow, bool, (bool, string)> _apply;
    private bool _suppress;

    public ContextMenuRow(ContextMenuHandler handler, Func<ContextMenuRow, bool, (bool, string)> apply)
    {
        Handler = handler;
        _apply = apply;
        _enabled = !handler.Blocked;
    }

    public ContextMenuHandler Handler { get; }
    public string Name => Handler.Name;
    public string Scope => Handler.Scope;
    public string Publisher => Handler.Publisher ?? (Handler.IsMicrosoft ? "Microsoft" : "未知");
    public string Dll => Handler.DllPath ?? "";
    public string Note => Handler.DllMissing ? "DLL 已不存在" : Handler.Signature is Core.Startup.SignatureState.Unsigned ? "未签名" : "";

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private string? _message;

    partial void OnEnabledChanged(bool value)
    {
        if (_suppress) return;
        var (ok, msg) = _apply(this, !value);
        Message = msg;
        if (!ok)
        {
            _suppress = true;
            Enabled = !value;
            _suppress = false;
        }
    }
}

/// <summary>系统优化页（设计文档 4.4）：服务优化、视觉效果、电源、休眠、虚拟内存、网络、右键菜单、搜索索引。</summary>
public sealed partial class OptimizeViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<ServiceTweakRow> Services { get; } = new();
    public ObservableCollection<PowerPlan> PowerPlans { get; } = new();
    public ObservableCollection<ContextMenuRow> ContextMenus { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(OptimizeServiceCommand), nameof(RestoreServiceCommand), nameof(ApplyPowerPlanCommand), nameof(ToggleHibernateCommand), nameof(NetworkFixCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private int _visualEffects;

    [ObservableProperty]
    private PowerPlan? _selectedPowerPlan;

    [ObservableProperty]
    private string _hibernateText = "";

    [ObservableProperty]
    private string _hibernateButton = "";

    [ObservableProperty]
    private string _pageFileText = "";

    [ObservableProperty]
    private bool _showMicrosoftMenus;

    [ObservableProperty]
    private string _networkOutput = "";

    public bool HasLoaded { get; private set; }

    public OptimizeViewModel(AppServices s)
    {
        _s = s;
        _visualEffects = SystemTweaks.GetVisualEffectsSetting();
    }

    private bool NotBusy => !IsBusy;

    partial void OnShowMicrosoftMenusChanged(bool value) => _ = LoadContextMenusAsync();

    partial void OnVisualEffectsChanged(int value)
    {
        if (!HasLoaded || value == SystemTweaks.GetVisualEffectsSetting()) return;
        var (ok, msg) = _s.SystemTweaks.SetVisualEffects(value);
        Status = msg;
        if (!ok) VisualEffects = SystemTweaks.GetVisualEffectsSetting();
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var states = await Task.Run(_s.ServiceTweaks.QueryStates);
            Services.Clear();
            foreach (var st in states.Where(x => x.Installed)) Services.Add(new ServiceTweakRow { State = st });

            var plans = await SystemTweaks.GetPowerPlansAsync();
            PowerPlans.Clear();
            foreach (var p in plans) PowerPlans.Add(p);
            SelectedPowerPlan = plans.FirstOrDefault(p => p.Active);

            var hib = SystemTweaks.IsHibernateEnabled();
            HibernateText = hib switch
            {
                true => $"休眠已开启，hiberfil.sys 占用 {Format.Bytes(SystemTweaks.HiberfilBytes())}。关闭会删除该文件并同时关闭“快速启动”。",
                false => "休眠已关闭（快速启动也随之关闭）。开启后会在系统盘创建 hiberfil.sys。",
                _ => "无法读取休眠状态。",
            };
            HibernateButton = hib == true ? "关闭休眠" : "开启休眠";

            var pf = SystemTweaks.GetPageFileInfo();
            PageFileText = pf.Files.Count == 0
                ? "没有页面文件。"
                : (pf.AutomaticallyManaged ? "由系统自动管理：" : "手动设置：") + string.Join("；", pf.Files.Select(f => $"{f.Path} 已分配 {f.AllocatedMb} MB，当前使用 {f.CurrentUsageMb} MB")) +
                  "。本程序不修改页面文件大小，需要调整请打开系统的性能选项。";

            VisualEffects = SystemTweaks.GetVisualEffectsSetting();
            await LoadContextMenusAsync();
            HasLoaded = true;
            Status = "每项都附风险说明与恢复方式，请逐项决定；本程序不提供“一键全关”。";
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


    private async Task LoadContextMenusAsync()
    {
        var handlers = await Task.Run(ContextMenuManager.List);
        ContextMenus.Clear();
        foreach (var h in handlers.Where(h => ShowMicrosoftMenus || !h.IsMicrosoft))
            ContextMenus.Add(new ContextMenuRow(h, (row, blocked) => _s.ContextMenus.SetBlocked(row.Handler, blocked)));
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task OptimizeServiceAsync(ServiceTweakRow? row) => await SetServiceAsync(row, manual: true);

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RestoreServiceAsync(ServiceTweakRow? row) => await SetServiceAsync(row, manual: false);

    private async Task SetServiceAsync(ServiceTweakRow? row, bool manual)
    {
        if (row is null) return;
        var verb = manual ? "改为手动启动" : "恢复为自动启动";
        var msg = $"把“{row.Title}”{verb}？\n\n{row.Description}\n\n{row.RestoreHint}\n\n修改前会导出服务键备份" + (_s.Settings.CreateRestorePoint ? "并尝试创建系统还原点" : "") + "。";
        if (MessageBox.Show(msg, verb, MessageBoxButton.OKCancel, row.Risk == RiskLevel.High ? MessageBoxImage.Warning : MessageBoxImage.Question) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var (ok, message) = await Task.Run(() => _s.ServiceTweaks.SetManual(row.State.Tweak.ServiceName, manual));
            Status = message;
            if (ok)
            {
                var states = await Task.Run(_s.ServiceTweaks.QueryStates);
                Services.Clear();
                foreach (var st in states.Where(x => x.Installed)) Services.Add(new ServiceTweakRow { State = st });
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task ApplyPowerPlanAsync()
    {
        if (SelectedPowerPlan is null || SelectedPowerPlan.Active) return;
        IsBusy = true;
        try
        {
            var (ok, msg) = await _s.SystemTweaks.SetActivePowerPlanAsync(SelectedPowerPlan.Id);
            Status = msg;
            if (ok)
            {
                var plans = await SystemTweaks.GetPowerPlansAsync();
                PowerPlans.Clear();
                foreach (var p in plans) PowerPlans.Add(p);
                SelectedPowerPlan = plans.FirstOrDefault(p => p.Active);
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task ToggleHibernateAsync()
    {
        var enabled = SystemTweaks.IsHibernateEnabled();
        if (enabled is null) return;
        var turningOff = enabled.Value;
        var msg = turningOff
            ? "关闭休眠会删除 hiberfil.sys，并同时关闭“快速启动”，之后开机会稍慢一些；笔记本将无法休眠（合盖只能睡眠或关机）。继续？"
            : "开启休眠会在系统盘创建与内存大小相当的 hiberfil.sys。继续？";
        if (MessageBox.Show(msg, turningOff ? "关闭休眠" : "开启休眠", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var (_, message) = await _s.SystemTweaks.SetHibernateAsync(!turningOff);
            Status = message;
            await RefreshAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task NetworkFixAsync(string? which)
    {
        if (which is null || !Enum.TryParse<SystemTweaks.NetworkFix>(which, out var fix)) return;
        var (exe, args, title, reboot) = SystemTweaks.Describe(fix);
        var msg = $"{title}？\n\n将执行：{exe} {args}" + (reboot ? "\n\n需要重启后生效，期间网络可能短暂中断。" : "");
        if (MessageBox.Show(msg, title, MessageBoxButton.OKCancel, reboot ? MessageBoxImage.Warning : MessageBoxImage.Question) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var r = await _s.SystemTweaks.RunNetworkFixAsync(fix);
            NetworkOutput = r.Output;
            Status = r.Success ? $"{title} 完成。" + (reboot ? "请重启电脑。" : "") : $"{title} 失败（退出码 {r.ExitCode}）。";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ShowTcpAsync()
    {
        var r = await SystemTweaks.ShowTcpGlobalsAsync();
        NetworkOutput = r.Output;
    }

    [RelayCommand]
    private async Task OpenPerformanceOptionsAsync() => await SystemTweaks.OpenPerformanceOptionsAsync();

    [RelayCommand]
    private async Task OpenIndexingOptionsAsync() => await SystemTweaks.OpenIndexingOptionsAsync();
}
