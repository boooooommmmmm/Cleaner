using CleanSweep.Core.Backup;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using Microsoft.Win32;

namespace CleanSweep.Core.Privacy;

public sealed class PrivacyOptions
{
    /// <summary>资源管理器用户键根，测试可指向 HKCU\Software\CleanSweepTests 下的假键。</summary>
    public string ExplorerKey { get; set; } = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer";
}

/// <summary>
/// 隐私清理（设计文档 3.6）：最近使用文件记录、跳转列表、运行 / 地址栏 / 搜索历史、文件对话框历史、活动历史。
/// 文件类目标走隔离区可恢复；注册表类目标删除前做备份。剪贴板历史、诊断数据、浏览器历史不在此模块（见页面说明）。
/// </summary>
public sealed class PrivacyScanner : IScanner
{
    public const string ModuleId = "privacy";

    private readonly PrivacyOptions _options;

    public PrivacyScanner(PrivacyOptions? options = null)
    {
        _options = options ?? new PrivacyOptions();
    }

    public string Id => ModuleId;
    public string DisplayName => "隐私清理";

    private sealed record MruKey(string Relative, string Title, string Description, RiskLevel Risk);

    private static readonly MruKey[] MruKeys =
    {
        new("RunMRU", "“运行”对话框历史", "Win+R 对话框记住的命令。删除键后系统自动重建", RiskLevel.Safe),
        new("TypedPaths", "资源管理器地址栏历史", "地址栏输入过的路径", RiskLevel.Safe),
        new("WordWheelQuery", "资源管理器搜索历史", "文件搜索框输入过的关键词", RiskLevel.Safe),
        new("RecentDocs", "最近打开的文档记录（注册表）", "按扩展名分类的最近文档列表，与“最近使用的文件”文件夹对应", RiskLevel.Safe),
        new(@"ComDlg32\OpenSavePidlMRU", "打开 / 保存对话框历史", "各类文件对话框记住的最近位置与文件", RiskLevel.Safe),
        new(@"ComDlg32\LastVisitedPidlMRU", "文件对话框最近访问目录", "各程序文件对话框上次打开的目录", RiskLevel.Safe),
        new(@"ComDlg32\LastVisitedPidlMRULegacy", "文件对话框最近访问目录（旧版）", "旧版通用对话框记录", RiskLevel.Safe),
        new("UserAssist", "程序使用统计（UserAssist）", "开始菜单用它统计程序启动次数与最近使用时间，删除后“最常用”列表重置", RiskLevel.Confirm),
    };

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run(() => Scan(ctx, progress, ct), ct);

    private IReadOnlyList<ScanItem> Scan(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var items = new List<ScanItem>();
        var v = ctx.Env.Variables;

        // 1. 最近使用的文件与跳转列表（文件，走隔离区）
        if (v.TryGetValue("AppData", out var appData))
        {
            var recent = Path.Combine(appData, @"Microsoft\Windows\Recent");
            AddFileSet(ctx, items, recent, "*.lnk", recurse: false, "最近使用的文件记录", "开始菜单与资源管理器“最近使用的文件”里的快捷方式，不影响文件本身", RiskLevel.Safe, ct);
            AddFileSet(ctx, items, Path.Combine(recent, "AutomaticDestinations"), "*", recurse: false, "跳转列表（自动）", "任务栏与开始菜单右键的“最近”“常用”列表", RiskLevel.Safe, ct);
            AddFileSet(ctx, items, Path.Combine(recent, "CustomDestinations"), "*", recurse: false, "跳转列表（应用自定义）", "应用固定到跳转列表的项目也会一起清除", RiskLevel.Confirm, ct);
        }

        // 2. 活动历史（时间线）
        if (v.TryGetValue("LocalAppData", out var local))
        {
            var cdp = Path.Combine(local, "ConnectedDevicesPlatform");
            if (Directory.Exists(cdp))
            {
                var files = ctx.Guard.EnumerateFiles(cdp, "ActivitiesCache.db*", recurse: true, ct).ToList();
                if (files.Count > 0)
                {
                    items.Add(new ScanItem
                    {
                        Id = RuleScanner.MakeId(ModuleId, "activities", cdp),
                        ModuleId = ModuleId,
                        Group = "活动历史",
                        DisplayName = "时间线 / 活动历史数据库",
                        Kind = ItemKind.FileSet,
                        Path = cdp,
                        Files = files,
                        SizeBytes = files.Sum(f => f.Size),
                        Risk = RiskLevel.Confirm,
                        Description = "Windows 时间线与跨设备活动记录。数据库被系统服务占用时会清理失败，可在“设置 → 隐私 → 活动历史”中先关闭",
                        LastWriteUtc = files.Max(f => f.LastWriteUtc),
                    });
                }
            }
        }

        // 3. 注册表 MRU（删除键，删除前整键备份）
        foreach (var mru in MruKeys)
        {
            ct.ThrowIfCancellationRequested();
            var keyPath = RegistryPath.Combine(_options.ExplorerKey, mru.Relative);
            try
            {
                using var k = RegistryPath.Open(keyPath, RegistryView.Registry64, writable: false);
                if (k is null) continue;
                var count = k.ValueCount + k.SubKeyCount;
                if (count == 0) continue;
                if (RegistryCleaning.RegistryGuard.CheckDeleteKey(keyPath, RegistryView.Registry64) is not null) continue;
                items.Add(new ScanItem
                {
                    Id = RuleScanner.MakeId(ModuleId, "mru", keyPath),
                    ModuleId = ModuleId,
                    Group = "资源管理器历史记录",
                    DisplayName = mru.Title,
                    Kind = ItemKind.RegistryKey,
                    Path = keyPath,
                    Registry = new RegistryTarget(keyPath, RegistryView.Registry64, null),
                    TargetSnapshot = RegistryCleaning.RegistrySnapshot.OfKey(keyPath, RegistryView.Registry64),
                    Risk = mru.Risk,
                    Description = $"{mru.Description}（{count} 项）。删除前导出 .reg 备份，可在设置中还原",
                });
            }
            catch
            {
            }
        }

        progress?.Report(new ScanProgress(Id, null, items.Count, items.Sum(i => i.SizeBytes)));
        return items;
    }

    private static void AddFileSet(ScanContext ctx, List<ScanItem> items, string dir, string pattern, bool recurse, string title, string description, RiskLevel risk, CancellationToken ct)
    {
        if (!Directory.Exists(dir) || PathGuard.IsReparsePoint(dir)) return;
        if (!ctx.Guard.Check(dir).Allowed) return;
        var files = ctx.Guard.EnumerateFiles(dir, pattern, recurse, ct).Where(f => !f.Path.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)).ToList();
        if (files.Count == 0) return;
        items.Add(new ScanItem
        {
            Id = RuleScanner.MakeId(ModuleId, "files", dir, pattern),
            ModuleId = ModuleId,
            Group = "最近使用记录",
            DisplayName = title,
            Kind = ItemKind.FileSet,
            Path = dir,
            Files = files,
            SizeBytes = files.Sum(f => f.Size),
            Risk = risk,
            Description = $"{description}。{files.Count} 项，移入隔离区可恢复",
            LastWriteUtc = files.Max(f => f.LastWriteUtc),
        });
    }
}
