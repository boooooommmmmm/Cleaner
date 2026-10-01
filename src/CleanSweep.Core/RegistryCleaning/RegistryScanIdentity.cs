using CleanSweep.Core.Backup;
using CleanSweep.Core.Model;
using Microsoft.Win32;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>仅对已知共享的注册表路径合并视图；未知路径保留两个视图。</summary>
internal static class RegistryScanIdentity
{
    // Windows 7 及更新系统：Classes 中这些子树仍被 WOW64 重定向。
    // https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys
    private static readonly string[] RedirectedClasses =
        ["CLSID", "DirectShow", "Interface", "Media Type", "MediaFoundation"];

    internal static string ForItem(ScanItem item)
    {
        if (item.Registry is not { } target || !RegistryPath.TryParse(target.KeyPath, out var hive, out var sub))
            return item.Id;

        var view = target.View;
        if (IsShared(hive, sub)) view = RegistryView.Default;
        // 分隔符不能出现在注册表名称中；值名为空字符串表示默认值。
        return $"{item.Kind}\0{hive}\0{view}\0{sub}\0{target.ValueName}".ToUpperInvariant();
    }

    private static bool IsShared(RegistryHive hive, string sub)
    {
        if (hive == RegistryHive.ClassesRoot) return ClassesShared(sub);
        if (hive is not (RegistryHive.LocalMachine or RegistryHive.CurrentUser)) return false;
        const string classes = @"Software\Classes";
        if (Under(sub, classes))
            return ClassesShared(sub.Length == classes.Length ? "" : sub[(classes.Length + 1)..]);
        if (hive == RegistryHive.CurrentUser) return Under(sub, "Software");
        return Under(sub, @"Software\Microsoft\Windows\CurrentVersion\App Paths");
    }

    private static bool ClassesShared(string sub) =>
        !RedirectedClasses.Any(root => Under(sub, root)) && !Under(sub, "Wow6432Node");

    private static bool Under(string path, string root) =>
        path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
}
