using Microsoft.Win32;

namespace CleanSweep.Core.Backup;

/// <summary>带 hive 前缀的注册表路径（如 HKCU\Software\...）的解析与打开。</summary>
public static class RegistryPath
{
    private static readonly Dictionary<string, RegistryHive> Hives = new(StringComparer.OrdinalIgnoreCase)
    {
        ["HKLM"] = RegistryHive.LocalMachine,
        ["HKEY_LOCAL_MACHINE"] = RegistryHive.LocalMachine,
        ["HKCU"] = RegistryHive.CurrentUser,
        ["HKEY_CURRENT_USER"] = RegistryHive.CurrentUser,
        ["HKU"] = RegistryHive.Users,
        ["HKEY_USERS"] = RegistryHive.Users,
        ["HKCR"] = RegistryHive.ClassesRoot,
        ["HKEY_CLASSES_ROOT"] = RegistryHive.ClassesRoot,
    };

    public static bool TryParse(string keyPath, out RegistryHive hive, out string subKey)
    {
        hive = default;
        subKey = "";
        if (string.IsNullOrWhiteSpace(keyPath)) return false;
        if (keyPath.IndexOfAny(new[] { '"', '\r', '\n', '\0' }) >= 0) return false;

        var idx = keyPath.IndexOf('\\');
        var head = idx < 0 ? keyPath : keyPath[..idx];
        if (!Hives.TryGetValue(head, out hive)) return false;

        subKey = idx < 0 ? "" : keyPath[(idx + 1)..].Trim('\\');
        return true;
    }

    public static bool IsValid(string keyPath) => TryParse(keyPath, out _, out _);

    /// <summary>打开键。不存在时返回 null；create 为 true 时创建。</summary>
    public static RegistryKey? Open(string keyPath, RegistryView view, bool writable, bool create = false)
    {
        if (!TryParse(keyPath, out var hive, out var sub))
            throw new ArgumentException($"无效的注册表路径：{keyPath}", nameof(keyPath));

        var baseKey = RegistryKey.OpenBaseKey(hive, view);
        if (sub.Length == 0) return baseKey;

        try
        {
            if (create)
                return baseKey.CreateSubKey(sub, writable);
            return baseKey.OpenSubKey(sub, writable);
        }
        finally
        {
            baseKey.Dispose();
        }
    }

    public static bool Exists(string keyPath, RegistryView view)
    {
        try
        {
            using var k = Open(keyPath, view, writable: false);
            return k is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>从给定键向上找到第一个存在的祖先（含自身）。</summary>
    public static string? NearestExisting(string keyPath, RegistryView view)
    {
        if (!TryParse(keyPath, out _, out _)) return null;
        var current = keyPath;
        while (true)
        {
            if (Exists(current, view)) return current;
            var idx = current.LastIndexOf('\\');
            if (idx <= 0) return null;
            current = current[..idx];
        }
    }

    public static string Parent(string keyPath)
    {
        var idx = keyPath.LastIndexOf('\\');
        return idx <= 0 ? keyPath : keyPath[..idx];
    }

    public static string Combine(string keyPath, string child) => keyPath.TrimEnd('\\') + "\\" + child.Trim('\\');
}
