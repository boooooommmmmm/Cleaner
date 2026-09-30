using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.Elevation;

/// <summary>
/// 判断一条扫描结果在不提权时能否执行（设计文档 7.4：界面以普通权限运行，需要管理员的条目标出来，交给提权服务或"以管理员身份重新启动"）。
/// 静态判断：HKLM、服务、计划任务、系统命令一律需要；文件类看路径是否在系统目录 / 其他用户目录之下。
/// </summary>
public static class ElevationNeed
{
    public static bool For(ScanItem item, PathGuard guard)
    {
        switch (item.Kind)
        {
            case ItemKind.Command:
            case ItemKind.Service:
            case ItemKind.ScheduledTask:
                return true;
            case ItemKind.RecycleBin:
                return false;
            case ItemKind.RegistryValue:
            case ItemKind.RegistryKey:
                return item.Registry is { } r && IsMachineHive(r.KeyPath);
            case ItemKind.Directory:
                return item.Path is not null && guard.RequiresElevation(item.Path);
            case ItemKind.FileSet:
                if (item.Path is not null && guard.RequiresElevation(item.Path)) return true;
                return item.Files.Any(f => guard.RequiresElevation(f.Path));
            default:
                return true;
        }
    }

    public static bool IsMachineHive(string keyPath)
    {
        var head = keyPath.Split('\\')[0];
        return head.Equals("HKLM", StringComparison.OrdinalIgnoreCase) || head.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
            || head.Equals("HKCR", StringComparison.OrdinalIgnoreCase) || head.Equals("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase)
            || head.Equals("HKU", StringComparison.OrdinalIgnoreCase) || head.Equals("HKEY_USERS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>能交给提权服务执行的条目：规则库产生、"安全"级、文件或目录。</summary>
    public static bool ServiceCanRun(ScanItem item) =>
        item.RuleId is not null && item.Risk == RiskLevel.Safe && item.Kind is ItemKind.FileSet or ItemKind.Directory;
}
