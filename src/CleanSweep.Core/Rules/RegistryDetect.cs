using CleanSweep.Core.Environment;
using Microsoft.Win32;

namespace CleanSweep.Core.Rules;

/// <summary>规则 detect 条件的求值。</summary>
public static class RegistryDetect
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

    public static bool IsValidKeyPath(string keyPath)
    {
        var idx = keyPath.IndexOf('\\');
        if (idx <= 0 || idx == keyPath.Length - 1) return false;
        return Hives.ContainsKey(keyPath[..idx]);
    }

    /// <summary>键是否存在。同时查 64 位与 32 位视图。</summary>
    public static bool KeyExists(string keyPath)
    {
        var idx = keyPath.IndexOf('\\');
        if (idx <= 0) return false;
        if (!Hives.TryGetValue(keyPath[..idx], out var hive)) return false;
        var sub = keyPath[(idx + 1)..];

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(sub, writable: false);
                if (key is not null) return true;
            }
            catch
            {
                // 无权限或视图不可用，继续尝试
            }
        }
        return false;
    }

    /// <summary>detect 为 null 视为"已安装"（系统规则）。</summary>
    public static bool IsInstalled(RuleDetect? detect, IEnvironmentResolver env)
    {
        if (detect is null) return true;

        bool any = detect.AnyOf is null || detect.AnyOf.Count == 0 || detect.AnyOf.Any(c => Eval(c, env));
        bool all = detect.AllOf is null || detect.AllOf.All(c => Eval(c, env));
        return any && all;
    }

    private static bool Eval(DetectCondition c, IEnvironmentResolver env)
    {
        if (c.Registry is not null) return KeyExists(c.Registry);

        if (c.File is not null)
            return env.TryExpand(c.File, out var f, out _) && File.Exists(f);

        if (c.Directory is not null)
            return env.TryExpand(c.Directory, out var d, out _) && Directory.Exists(d);

        return false;
    }
}
