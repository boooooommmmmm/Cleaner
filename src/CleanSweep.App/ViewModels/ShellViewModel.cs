using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed partial class NavItem : ObservableObject
{
    public required string Title { get; init; }
    public required string Glyph { get; init; }
    public required object Page { get; init; }

    /// <summary>侧栏分组名；<see cref="NavGroup.Pinned"/> 表示固定在底部、不参与折叠（隔离区、设置）。</summary>
    public string Group { get; init; } = NavGroup.Pinned;

    [ObservableProperty]
    private bool _isSelected;
}

/// <summary>侧栏分组：标题 + 可折叠的导航项。折叠状态记进设置；当前页所在的组自动展开。</summary>
public sealed partial class NavGroup : ObservableObject
{
    public const string Pinned = "";

    /// <summary>分组顺序与默认折叠状态：清理与空间默认展开，优化与管理默认折叠。</summary>
    public static readonly IReadOnlyList<(string Title, bool ExpandedByDefault)> Order = new[]
    {
        ("清理", true), ("空间", true), ("优化", false), ("管理", false),
    };

    public required string Title { get; init; }
    public ObservableCollection<NavItem> Items { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CollapsedHint))]
    private bool _isExpanded;

    /// <summary>折叠时在标题右侧显示项数，让用户知道里面有东西。</summary>
    public string CollapsedHint => IsExpanded ? "" : $"{Items.Count} 项";

    public string AutomationName => $"分组 {Title}";
}

public sealed partial class ShellViewModel : ObservableObject
{
    private readonly AppServices _s;
    private readonly CleanPageViewModel _residuePage;

    /// <summary>全部导航项（含固定项），按加入顺序；"跳转到某页"按标题在这里找。</summary>
    public ObservableCollection<NavItem> Items { get; } = new();

    /// <summary>可折叠的分组（清理 / 空间 / 优化 / 管理），在侧栏滚动区内。</summary>
    public ObservableCollection<NavGroup> Groups { get; } = new();

    /// <summary>固定在侧栏底部、始终可见的项（隔离区、设置）。</summary>
    public ObservableCollection<NavItem> PinnedItems { get; } = new();

    [ObservableProperty]
    private NavItem? _selected;

    public string Version => $"v{typeof(ShellViewModel).Assembly.GetName().Version?.ToString(3)}";

    public ElevationContext Elevation => _s.Elevation;

    /// <summary>启动时后台检查到新版本的提示（侧栏显示）。</summary>
    [ObservableProperty]
    private string? _updateNotice;

    public async Task CheckUpdatesInBackgroundAsync()
    {
        if (!_s.Settings.CheckUpdatesOnStartup || _s.UpdateSources is null) return;
        try
        {
            var app = await _s.CheckAppUpdateAsync();
            if (app.Available) UpdateNotice = $"有新版本 {app.Release!.Version.ToString(3)}，到“设置”页更新";
            var data = await _s.UpdateDataSetsAsync();
            if (data.Any(r => r.Updated)) UpdateNotice = (UpdateNotice is null ? "" : UpdateNotice + "；") + "规则库已更新";
        }
        catch (Exception ex)
        {
            _s.Log.Write(null, "app", "startup-update-check", null, 0, false, ex.Message);
        }
    }

    /// <summary>以管理员身份重新启动：新实例启动成功后本实例退出（单实例互斥体由新实例等待接管）。</summary>
    [RelayCommand]
    private void RelaunchElevated()
    {
        if (Elevation.IsElevated) return;
        var err = ElevationContext.RelaunchElevated();
        if (err is not null)
        {
            if (err != "已取消提权") MessageBox.Show($"无法以管理员身份重新启动：{err}", "CleanSweep", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        Application.Current.Shutdown(0);
    }

    public ShellViewModel(AppServices s)
    {
        _s = s;
        _ = s.Elevation.ProbeServiceAsync();
        Add(new NavItem
        {
            Group = "清理", Title = "系统清理", Glyph = "",
            Page = new CleanPageViewModel(s, "系统清理", "临时文件、日志、更新缓存、回收站等系统垃圾。首次扫描默认只勾选“安全”级项目。",
                () => new[] { RuleScanner.SystemJunk() }),
        });
        Add(new NavItem
        {
            Group = "清理", Title = "应用缓存", Glyph = "",
            Page = new CleanPageViewModel(s, "应用缓存", "浏览器与常用软件的缓存。只清理已安装应用的缓存，配置与用户数据不会被触碰。",
                () => new[] { RuleScanner.AppCache() }),
        });

        _residuePage = new CleanPageViewModel(s, "残留清理",
            "已卸载软件遗留在用户目录中的配置、缓存与数据。按应用聚合，结合已安装软件清单、指纹库、卸载记录与目录活跃度判定；" +
            "“确认残留”默认勾选，“疑似残留”只展示体积。含登录态、许可证或存档的目录会单独提示。",
            s.CreateResidueScanners, ResidueNote);
        _residuePage.ScanCompleted += (_, _) => s.ResidueOptions.OnlyAppName = null;
        Add(new NavItem { Group = "清理", Title = "残留清理", Glyph = "", Page = _residuePage });

        Add(new NavItem { Group = "管理", Title = "软件卸载", Glyph = "", Page = new UninstallViewModel(s, ScanResidueFor) });
        Add(new NavItem
        {
            Group = "清理", Title = "开发者缓存", Glyph = "",
            Page = new CleanPageViewModel(s, "开发者缓存",
                "Gradle、Maven、NuGet、npm、pip、Docker 等工具的缓存目录，只清缓存不清配置；项目中长期未动的 node_modules；conda 环境只列出不默认勾选。" +
                "在“设置”中添加项目根目录后才会查找 node_modules。",
                s.CreateDevCacheScanners, DevNote),
        });
        Add(new NavItem
        {
            Group = "清理", Title = "注册表清理", Glyph = "",
            Page = new CleanPageViewModel(s, "注册表清理",
                "移除已卸载软件遗留的注册表配置，不是提速手段。安全级：无效卸载项、失效快捷方式、MUI 缓存孤儿；建议确认：遗留的软件键、失效文件关联与 App Paths、指向不存在程序的服务与计划任务；" +
                "高风险：失效 COM 注册与共享 DLL 计数。每一项删除前自动备份，可在“设置 → 备份与还原”中一键还原。",
                s.CreateRegistryScanners),
        });
        Add(new NavItem
        {
            Group = "清理", Title = "隐私清理", Glyph = "",
            Page = new CleanPageViewModel(s, "隐私清理",
                "最近使用的文件记录、跳转列表、运行 / 地址栏 / 搜索历史、文件对话框历史、活动历史。文件类走隔离区可恢复，注册表类删除前备份。" +
                "剪贴板历史请在“设置 → 系统 → 剪贴板”中清除；浏览器历史由各浏览器自行管理。",
                s.CreatePrivacyScanners),
        });
        Add(new NavItem { Group = "优化", Title = "开机加速", Glyph = "", Page = new StartupViewModel(s) });
        Add(new NavItem { Group = "优化", Title = "磁盘健康", Glyph = "", Page = new DiskViewModel(s) });
        Add(new NavItem { Group = "优化", Title = "内存与进程", Glyph = "", Page = new MemoryViewModel(s) });
        Add(new NavItem { Group = "优化", Title = "系统优化", Glyph = "", Page = new OptimizeViewModel(s) });
        Add(new NavItem { Group = "管理", Title = "驱动与更新", Glyph = "", Page = new DriverViewModel(s) });
        Add(new NavItem { Group = "管理", Title = "弹窗拦截", Glyph = "", Page = new PopupViewModel(s) });
        Add(new NavItem { Group = "管理", Title = "系统修复", Glyph = "", Page = new RepairViewModel(s) });
        Add(new NavItem { Group = "管理", Title = "系统信息", Glyph = "", Page = new SystemInfoViewModel() });
        Add(new NavItem { Group = "管理", Title = "硬件状态", Glyph = "", Page = new HardwareViewModel(s) });
        Add(new NavItem { Group = "空间", Title = "空间分析", Glyph = "", Page = new SpaceAnalyzerViewModel(s) });
        Add(new NavItem { Group = "空间", Title = "重复文件", Glyph = "", Page = new DuplicatesViewModel(s) });
        Add(new NavItem { Group = "空间", Title = "文件粉碎", Glyph = "", Page = new ShredViewModel(s) });
        Add(new NavItem { Title = "隔离区", Glyph = "", Page = new QuarantineViewModel(s) });
        Add(new NavItem { Title = "设置", Glyph = "", Page = new SettingsViewModel(s) });

        Items[0].IsSelected = true;

        s.UninstallWatcher.AppsRemoved += OnAppsRemoved;
        s.ApplyUninstallWatching();
        s.ApplyPopupBlocking();
    }

    private string? ResidueNote()
    {
        var inv = _s.Inventory.Last;
        if (inv is null) return null;
        var note = $"已安装软件清单：{inv.Apps.Count} 项（注册表 {inv.RegistryCount}、应用商店 {inv.UwpCount} 个包家族）。";
        if (!inv.RegistryReliable) note += " 注册表卸载项读取异常，本次未把“未找到卸载项”当作已卸载的证据。";
        if (_s.ResidueOptions.OnlyAppName is { } only) note += $" 本次为针对“{only}”的定向扫描。";
        return note;
    }

    private string? DevNote()
    {
        var disks = DevCacheScanner.DockerDisks(_s.Env);
        if (disks.Count == 0) return null;
        return "Docker Desktop 的 WSL 虚拟磁盘只显示体积，不提供删除：" + string.Join("；", disks.Select(d => $"{d.Path}（{Format.Bytes(d.Size)}）")) +
               "。可在 Docker Desktop 中执行 docker system prune 后压缩磁盘。";
    }

    /// <summary>切到残留清理页并针对某个应用做定向扫描。</summary>
    public void ScanResidueFor(string appName)
    {
        _s.ResidueOptions.OnlyAppName = appName;
        NavigateTo("残留清理");
        if (_residuePage.ScanCommand.CanExecute(null)) _residuePage.ScanCommand.Execute(null);
    }

    public void NavigateTo(string title)
    {
        var item = Items.FirstOrDefault(i => i.Title == title);
        if (item is not null) item.IsSelected = true;
    }

    private void OnAppsRemoved(object? sender, IReadOnlyList<InstalledApp> removed)
    {
        var app = removed[0];
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            var names = string.Join("、", removed.Select(a => a.Name).Take(3)) + (removed.Count > 3 ? $" 等 {removed.Count} 个应用" : "");
            var r = MessageBox.Show($"检测到“{names}”已卸载。现在扫描它遗留在用户目录中的数据？", "卸载后残留提醒", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (r == MessageBoxResult.Yes) ScanResidueFor(app.Name);
        });
    }

    private void Add(NavItem item)
    {
        item.PropertyChanged += OnNavItemChanged;
        Items.Add(item);
        if (item.Group == NavGroup.Pinned)
        {
            PinnedItems.Add(item);
            return;
        }
        var group = Groups.FirstOrDefault(g => g.Title == item.Group);
        if (group is null)
        {
            var def = NavGroup.Order.FirstOrDefault(o => o.Title == item.Group);
            var expanded = _s.Settings.NavGroupExpanded.TryGetValue(item.Group, out var saved) ? saved : def.ExpandedByDefault;
            group = new NavGroup { Title = item.Group, IsExpanded = expanded };
            group.PropertyChanged += OnNavGroupChanged;
            Groups.Add(group);
        }
        group.Items.Add(item);
    }

    /// <summary>折叠状态变化即保存；每次只写这一项，不动其他设置。</summary>
    private void OnNavGroupChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(NavGroup.IsExpanded) || sender is not NavGroup g) return;
        _s.Settings.NavGroupExpanded[g.Title] = g.IsExpanded;
        try { _s.Settings.Save(); } catch { }
    }

    private void OnNavItemChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(NavItem.IsSelected) || sender is not NavItem { IsSelected: true } item) return;
        Selected = item;
        // 程序内跳转（如"扫描残留"）到了折叠组里的页面：把组展开，让用户看到自己在哪
        if (Groups.FirstOrDefault(g => g.Items.Contains(item)) is { IsExpanded: false } group) group.IsExpanded = true;
    }

    partial void OnSelectedChanged(NavItem? oldValue, NavItem? newValue)
    {
        var value = newValue;
        // 硬件状态页的自动刷新只在它显示时跑
        if (oldValue?.Page is HardwareViewModel hwOld) hwOld.IsActive = false;
        if (value?.Page is HardwareViewModel hw) hw.IsActive = true; // 进入即采样一次
        if (value?.Page is QuarantineViewModel q) q.RefreshCommand.Execute(null);
        if (value?.Page is SettingsViewModel st) st.RefreshCommand.Execute(null);
        if (value?.Page is StartupViewModel su && !su.HasScanned && !su.IsBusy) su.RefreshCommand.Execute(null);
        if (value?.Page is UninstallViewModel un && !un.HasScanned && !un.IsBusy) un.RefreshCommand.Execute(null);
        if (value?.Page is DiskViewModel dk && !dk.HasLoaded && !dk.IsBusy) dk.RefreshCommand.Execute(null);
        if (value?.Page is MemoryViewModel mm && !mm.HasLoaded && !mm.IsBusy) mm.RefreshCommand.Execute(null);
        if (value?.Page is OptimizeViewModel op && !op.HasLoaded && !op.IsBusy) op.RefreshCommand.Execute(null);
        if (value?.Page is DriverViewModel dr && !dr.HasLoaded && !dr.IsBusy) dr.RefreshCommand.Execute(null);
        if (value?.Page is SystemInfoViewModel si && !si.HasLoaded && !si.IsBusy) si.RefreshCommand.Execute(null);
    }
}
