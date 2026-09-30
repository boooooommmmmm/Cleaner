using CleanSweep.Core.Backup;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>
/// 注册表版 Path Guard（设计文档 3.4 安全机制的引擎层实现）：任何注册表删除都必须经过这里。
/// 1. 只允许删除位于"允许根"之下的键 / 值：HKCU\Software、HKLM\Software（含 WOW6432Node）、两者的 Classes；
/// 2. 允许根之下仍有一批"永不触碰"子树：Windows NT\CurrentVersion、Policies、Installer、Cryptography、Run 等；
/// 3. 不允许删除允许根本身或它的直接系统子键（HKCU\Software\Microsoft 之类）；
/// 4. 键删除只针对明确类型的键（卸载项、App Paths、ProgID、CLSID、厂商键），其余一律拒绝。
/// </summary>
public static class RegistryGuard
{
    private static readonly string[] AllowedRoots =
    {
        @"HKCU\Software",
        @"HKLM\Software",
        @"HKU\", // 其他用户 hive 下的 Software（提权服务用），按 HKU\<SID>\Software 校验
    };

    /// <summary>允许根之下永不触碰的子树（相对 Software 根，大小写不敏感，含 WOW6432Node 变体）。</summary>
    private static readonly string[] NeverTouchUnderSoftware =
    {
        @"Microsoft\Windows NT",
        @"Microsoft\Windows\CurrentVersion\Policies",
        @"Microsoft\Windows\CurrentVersion\Run",
        @"Microsoft\Windows\CurrentVersion\RunOnce",
        @"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        @"Microsoft\Windows\CurrentVersion\Installer",
        @"Microsoft\Windows\CurrentVersion\Component Based Servicing",
        @"Microsoft\Windows\CurrentVersion\SideBySide",
        @"Microsoft\Windows\CurrentVersion\WindowsUpdate",
        @"Microsoft\Windows\CurrentVersion\Setup",
        @"Microsoft\Windows\CurrentVersion\Authentication",
        @"Microsoft\Windows\CurrentVersion\Group Policy",
        @"Microsoft\Windows\CurrentVersion\Shell Extensions",
        @"Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
        @"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        @"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        @"Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        @"Microsoft\Windows\CurrentVersion\Uninstall\Microsoft",
        @"Microsoft\Windows\CurrentVersion\WINEVT",
        @"Microsoft\Windows\CurrentVersion\Appx",
        @"Microsoft\Windows Defender",
        @"Microsoft\Windows Advanced Threat Protection",
        @"Microsoft\Windows Search",
        @"Microsoft\Cryptography",
        @"Microsoft\SystemCertificates",
        @"Microsoft\EnterpriseCertificates",
        @"Microsoft\Active Setup",
        @"Microsoft\.NETFramework",
        @"Microsoft\NET Framework Setup",
        @"Microsoft\Ole",
        @"Microsoft\Rpc",
        @"Microsoft\Wbem",
        @"Microsoft\Windows Script Host",
        @"Microsoft\PolicyManager",
        @"Microsoft\Provisioning",
        @"Microsoft\SecurityManager",
        @"Microsoft\Security Center",
        @"Microsoft\Tracing",
        @"Microsoft\Windows\CurrentVersion\DeviceSetup",
        @"Microsoft\Windows\CurrentVersion\Device Installer",
        @"Microsoft\Windows\CurrentVersion\OEMInformation",
        @"Microsoft\Windows\CurrentVersion\Reliability",
        @"Microsoft\Windows\CurrentVersion\Diagnostics",
        @"Microsoft\Windows\CurrentVersion\Internet Settings",
        @"Microsoft\Windows\CurrentVersion\Telephony",
        @"Microsoft\Windows\CurrentVersion\WinTrust",
        @"Microsoft\Windows\CurrentVersion\Winlogon",
        @"Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        @"Policies",
        @"Classes\Installer",
        @"Classes\Interface",
        @"Classes\AppID",
        @"Classes\Wow6432Node\Interface",
        @"Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel",
        @"Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer",
        @"Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
        @"Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        @"Classes\Local Settings\ImmutableMuiCache",
        @"Clients",
        @"RegisteredApplications",
        @"ODBC",
        @"WOW6432Node\Microsoft\Windows NT",
        @"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"WOW6432Node\Microsoft\Windows\CurrentVersion\Installer",
        @"WOW6432Node\Microsoft\Windows\CurrentVersion\Policies",
        @"WOW6432Node\Microsoft\Cryptography",
        @"WOW6432Node\Policies",
        @"WOW6432Node\Classes\Installer",
        @"WOW6432Node\Classes\Interface",
        @"WOW6432Node\Classes\AppID",
        @"WOW6432Node\Clients",
        @"WOW6432Node\RegisteredApplications",
    };

    /// <summary>允许根的直接系统子键：不能被当作"厂商键"整体删除。</summary>
    private static readonly HashSet<string> ProtectedTopLevel = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Classes", "Policies", "Clients", "RegisteredApplications", "WOW6432Node", "ODBC", "Wow6432Node",
        "Intel", "AMD", "NVIDIA Corporation", "Realtek", "Khronos", "Google", "Mozilla", "Apple Inc.", "Apple Computer, Inc.",
        "Macromedia", "Adobe", "JavaSoft", "Oracle", "Dell", "HP", "Lenovo", "ASUS", "Synaptics", "ELAN", "Conexant", "Cirque",
        "Wow6432Node", "DefaultUserEnvironment", "Description", "Setup", "SimonTatham", "7-Zip", "Classes",
    };

    /// <summary>返回 null 表示允许，否则为拒绝原因。</summary>
    public static string? CheckDeleteValue(string keyPath, RegistryView view, string valueName)
    {
        var bad = CheckKeyIsUnderAllowedRoot(keyPath, out var relative);
        if (bad is not null) return bad;
        if (IsNeverTouch(StripWow(relative))) return $"该键属于永不触碰的系统区域：{keyPath}";
        return null;
    }

    /// <summary>WOW6432Node 下的路径与 64 位路径按同一套规则判断。</summary>
    internal static string StripWow(string relative) =>
        relative.StartsWith("WOW6432Node\\", StringComparison.OrdinalIgnoreCase) ? relative[12..] : relative;

    /// <summary>键删除：除了允许根 / 永不触碰的检查，还要求键至少两层深（HKCU\Software\Vendor 可以，HKCU\Software 不行），且不是受保护的顶层系统键。</summary>
    public static string? CheckDeleteKey(string keyPath, RegistryView view)
    {
        var bad = CheckKeyIsUnderAllowedRoot(keyPath, out var relative);
        if (bad is not null) return bad;
        if (relative.Length == 0) return "不允许删除 Software 根";
        var norm = StripWow(relative);
        if (norm.Length == 0) return "不允许删除 WOW6432Node 根";
        if (IsNeverTouch(norm)) return $"该键属于永不触碰的系统区域：{keyPath}";
        // 删除整树也会带走其下的受保护子树：受保护路径的任何祖先都不允许删除
        foreach (var never in NeverTouchUnderSoftware)
            if (never.StartsWith(norm + "\\", StringComparison.OrdinalIgnoreCase)) return $"该键包含永不触碰的子树（{never}）：{keyPath}";

        var segments = norm.Split('\\');
        if (segments.Length == 1 && ProtectedTopLevel.Contains(segments[0])) return $"不允许整体删除系统 / 硬件厂商的顶层键：{keyPath}";
        // Microsoft 下只允许删除具体条目（Uninstall\<app>、App Paths\<exe>、Explorer\RunMRU 这类第 5 层及更深的键），
        // 容器级的键（Microsoft\Windows\CurrentVersion\Uninstall 本身）一律拒绝
        if (segments[0].Equals("Microsoft", StringComparison.OrdinalIgnoreCase) && segments.Length <= 4)
            return $"不允许删除 Microsoft 下的容器级键：{keyPath}";
        if (segments[0].Equals("Classes", StringComparison.OrdinalIgnoreCase) && segments.Length == 1)
            return "不允许删除 Classes 根";
        return null;
    }

    private static string? CheckKeyIsUnderAllowedRoot(string keyPath, out string relative)
    {
        relative = "";
        if (!RegistryPath.TryParse(keyPath, out var hive, out var sub)) return $"注册表路径无效：{keyPath}";
        if (hive is RegistryHive.LocalMachine or RegistryHive.CurrentUser)
        {
            if (!sub.StartsWith("Software", StringComparison.OrdinalIgnoreCase)) return $"只允许在 Software 之下操作：{keyPath}";
            relative = sub.Length > 8 ? sub[9..] : "";
            if (sub.Length > 8 && sub[8] != '\\') return $"只允许在 Software 之下操作：{keyPath}";
            return null;
        }
        if (hive == RegistryHive.Users)
        {
            // HKU\<SID>\Software\...
            var parts = sub.Split('\\', 3);
            if (parts.Length < 2 || !parts[1].Equals("Software", StringComparison.OrdinalIgnoreCase)) return $"只允许在 HKU\\<SID>\\Software 之下操作：{keyPath}";
            if (parts[0].EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return "不允许直接操作用户 Classes hive";
            relative = parts.Length == 3 ? parts[2] : "";
            return null;
        }
        return $"不允许在该 hive 下操作：{keyPath}";
    }

    internal static bool IsNeverTouch(string relativeToSoftware)
    {
        foreach (var never in NeverTouchUnderSoftware)
        {
            if (relativeToSoftware.Equals(never, StringComparison.OrdinalIgnoreCase)
                || relativeToSoftware.StartsWith(never + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
