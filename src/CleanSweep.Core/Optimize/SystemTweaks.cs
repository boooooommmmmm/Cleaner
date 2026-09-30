using System.Management;
using System.Text.RegularExpressions;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Optimize;

public sealed record PowerPlan(Guid Id, string Name, bool Active);

public sealed record PageFileInfo(bool AutomaticallyManaged, IReadOnlyList<(string Path, long AllocatedMb, long CurrentUsageMb)> Files);

/// <summary>
/// 系统优化项（设计文档 4.4）中除服务与右键菜单以外的部分：视觉效果、电源计划、休眠、虚拟内存（只读）、网络修复、搜索索引选项。
/// 所有命令来自固定操作表；注册表写入前值级备份。
/// </summary>
public sealed partial class SystemTweaks
{
    public const string ModuleId = "optimize";
    private const string VisualEffectsKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects";

    private readonly RegistryBackup _backup;
    private readonly OperationLog _log;

    public SystemTweaks(RegistryBackup backup, OperationLog log)
    {
        _backup = backup;
        _log = log;
    }

    // ---------- 视觉效果 ----------

    /// <summary>0 = 让 Windows 选择，1 = 最佳外观，2 = 最佳性能，3 = 自定义。</summary>
    public static int GetVisualEffectsSetting()
    {
        try
        {
            using var k = RegistryPath.Open(VisualEffectsKey, RegistryView.Registry64, writable: false);
            return k?.GetValue("VisualFXSetting") as int? ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    public (bool Success, string Message) SetVisualEffects(int setting)
    {
        if (setting is < 0 or > 2) return (false, "只支持 0（让 Windows 选择）、1（最佳外观）、2（最佳性能）");
        try
        {
            _backup.BackupValue(VisualEffectsKey, "VisualFXSetting", "视觉效果设置");
            using var k = RegistryPath.Open(VisualEffectsKey, RegistryView.Registry64, writable: true, create: true) ?? throw new InvalidOperationException("无法打开键");
            k.SetValue("VisualFXSetting", setting, RegistryValueKind.DWord);
            _log.Write(null, ModuleId, "visual-effects", setting.ToString(), 0, true);
            return (true, "已设置。部分效果需要重新登录后生效；可在“系统属性 → 高级 → 性能”中查看。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "visual-effects", setting.ToString(), 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    // ---------- 电源计划 ----------

    [GeneratedRegex(@"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b\s*\((.*?)\)\s*(\*?)")]
    private static partial Regex PowerPlanLine();

    public static async Task<IReadOnlyList<PowerPlan>> GetPowerPlansAsync(CancellationToken ct = default)
    {
        var r = await SystemCommand.RunAsync("powercfg.exe", "/list", TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        return ParsePowerPlans(r.Output);
    }

    internal static IReadOnlyList<PowerPlan> ParsePowerPlans(string output)
    {
        var list = new List<PowerPlan>();
        foreach (var line in output.Split('\n'))
        {
            var m = PowerPlanLine().Match(line);
            if (!m.Success) continue;
            if (!Guid.TryParse(m.Groups[1].Value, out var id)) continue;
            list.Add(new PowerPlan(id, m.Groups[2].Value.Trim(), m.Groups[3].Value == "*"));
        }
        return list;
    }

    public async Task<(bool Success, string Message)> SetActivePowerPlanAsync(Guid id, CancellationToken ct = default)
    {
        var plans = await GetPowerPlansAsync(ct).ConfigureAwait(false);
        if (!plans.Any(p => p.Id == id)) return (false, "不是本机存在的电源计划");
        var r = await SystemCommand.RunAsync("powercfg.exe", $"/setactive {id:D}", TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        _log.Write(null, ModuleId, "power-plan", id.ToString("D"), 0, r.Success, r.Output);
        return (r.Success, r.Success ? "已切换电源计划。" : r.Output);
    }

    // ---------- 休眠 ----------

    public static bool? IsHibernateEnabled()
    {
        try
        {
            using var k = RegistryPath.Open(@"HKLM\SYSTEM\CurrentControlSet\Control\Power", RegistryView.Registry64, writable: false);
            if (k?.GetValue("HibernateEnabled") is int v) return v != 0;
            // 值不存在（从未改过休眠设置）：看 hiberfil.sys 是否存在（非管理员读不到属性时仍为 null）
            var root = Path.GetPathRoot(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows))!;
            var hiberfil = Path.Combine(root, "hiberfil.sys");
            if (File.Exists(hiberfil)) return true;
            // 能列出卷根但没有 hiberfil：确实关闭；列不出（权限）→ 未知
            return Directory.EnumerateFiles(root).Any() ? false : null;
        }
        catch
        {
            return null;
        }
    }

    public static long HiberfilBytes()
    {
        try
        {
            var f = Path.Combine(Path.GetPathRoot(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows))!, "hiberfil.sys");
            return File.Exists(f) ? new FileInfo(f).Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>关闭休眠会删除 hiberfil.sys，同时关闭“快速启动”，调用方必须先提示。</summary>
    public async Task<(bool Success, string Message)> SetHibernateAsync(bool enabled, CancellationToken ct = default)
    {
        var r = await SystemCommand.RunAsync("powercfg.exe", enabled ? "/hibernate on" : "/hibernate off", TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        _log.Write(null, ModuleId, "hibernate", enabled ? "on" : "off", 0, r.Success, r.Output);
        return (r.Success, r.Success ? (enabled ? "已开启休眠。" : "已关闭休眠，hiberfil.sys 已删除，快速启动同时关闭。") : r.Output);
    }

    // ---------- 虚拟内存（只读）----------

    public static PageFileInfo GetPageFileInfo()
    {
        bool auto = false;
        var files = new List<(string, long, long)>();
        try
        {
            using var cs = new ManagementObjectSearcher("SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem");
            foreach (ManagementObject o in cs.Get()) auto = Convert.ToBoolean(o["AutomaticManagedPagefile"]);
            using var pf = new ManagementObjectSearcher("SELECT Name, AllocatedBaseSize, CurrentUsage FROM Win32_PageFileUsage");
            foreach (ManagementObject o in pf.Get()) files.Add((o["Name"]?.ToString() ?? "", Convert.ToInt64(o["AllocatedBaseSize"] ?? 0), Convert.ToInt64(o["CurrentUsage"] ?? 0)));
        }
        catch { }
        return new PageFileInfo(auto, files);
    }

    /// <summary>打开系统的性能选项（虚拟内存在“高级”页）。不在程序里改页面文件大小。</summary>
    public static Task<CommandResult> OpenPerformanceOptionsAsync() => SystemCommand.RunAsync("SystemPropertiesPerformance.exe", "", TimeSpan.FromSeconds(5));

    /// <summary>打开索引选项控制面板。索引范围由系统界面管理。</summary>
    public static Task<CommandResult> OpenIndexingOptionsAsync() => SystemCommand.RunAsync("control.exe", "srchadmin.dll", TimeSpan.FromSeconds(5));

    // ---------- 网络 ----------

    public enum NetworkFix
    {
        FlushDns,
        ResetWinsock,
        ResetTcpIp,
        RenewDhcp,
    }

    public static (string Exe, string Args, string Title, bool NeedsReboot) Describe(NetworkFix fix) => fix switch
    {
        NetworkFix.FlushDns => ("ipconfig.exe", "/flushdns", "刷新 DNS 缓存", false),
        NetworkFix.ResetWinsock => ("netsh.exe", "winsock reset", "重置 Winsock", true),
        NetworkFix.ResetTcpIp => ("netsh.exe", "int ip reset", "重置 TCP/IP 协议栈", true),
        NetworkFix.RenewDhcp => ("ipconfig.exe", "/renew", "重新获取 IP 地址", false),
        _ => throw new ArgumentOutOfRangeException(nameof(fix)),
    };

    public async Task<CommandResult> RunNetworkFixAsync(NetworkFix fix, CancellationToken ct = default)
    {
        var (exe, args, title, _) = Describe(fix);
        var r = await SystemCommand.RunAsync(exe, args, TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        _log.Write(null, ModuleId, "network-fix", title, 0, r.Success, r.Output.Length > 400 ? r.Output[..400] : r.Output);
        return r;
    }

    public static Task<CommandResult> ShowTcpGlobalsAsync(CancellationToken ct = default) => SystemCommand.RunAsync("netsh.exe", "int tcp show global", TimeSpan.FromSeconds(30), ct);
}
