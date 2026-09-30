using CleanSweep.Core.Backup;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.Inventory;

/// <summary>本机一个用户配置文件。</summary>
public sealed record UserProfile(string Sid, string Path, bool IsCurrentUser, bool IsSystemAccount);

/// <summary>Users 目录下没有对应 ProfileList 项的目录：账户已删除但配置文件遗留。</summary>
public sealed record OrphanProfile(string Path);

/// <summary>枚举 ProfileList 里登记的用户配置文件，以及 Users 目录下已删除账户遗留的目录（设计文档 3.3.4 多用户支持）。</summary>
public static class UserProfiles
{
    private const string ProfileListKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private static readonly HashSet<string> SpecialDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount", "desktop.ini",
    };

    public static IReadOnlyList<UserProfile> List()
    {
        var result = new List<UserProfile>();
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        try
        {
            using var root = RegistryPath.Open(ProfileListKey, RegistryView.Registry64, writable: false);
            if (root is null) return result;
            foreach (var sid in root.GetSubKeyNames())
            {
                try
                {
                    using var k = root.OpenSubKey(sid);
                    if (k?.GetValue("ProfileImagePath") is not string raw || raw.Length == 0) continue;
                    var path = System.Environment.ExpandEnvironmentVariables(raw);
                    // S-1-5-18/19/20：SYSTEM、LocalService、NetworkService，配置文件在 Windows 目录下
                    var isSystem = sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20";
                    result.Add(new UserProfile(sid, PathGuard.Normalize(path), string.Equals(sid, me, StringComparison.OrdinalIgnoreCase), isSystem));
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
        return result;
    }

    /// <summary>Users 目录下不属于任何登记账户、也不是系统特殊目录的目录。只在能读到 ProfileList 时给出结果。</summary>
    public static IReadOnlyList<OrphanProfile> FindOrphans(string usersDirectory, IReadOnlyList<UserProfile> profiles)
    {
        var result = new List<OrphanProfile>();
        if (profiles.Count == 0 || !Directory.Exists(usersDirectory)) return result;
        var known = new HashSet<string>(profiles.Select(p => p.Path), StringComparer.OrdinalIgnoreCase);

        IEnumerable<string> dirs;
        try { dirs = Directory.EnumerateDirectories(usersDirectory); } catch { return result; }
        foreach (var d in dirs)
        {
            try
            {
                var name = Path.GetFileName(d);
                if (SpecialDirs.Contains(name)) continue;
                if (PathGuard.IsReparsePoint(d)) continue;
                var full = PathGuard.Normalize(d);
                if (known.Contains(full)) continue;
                // 有 NTUSER.DAT 才像一个配置文件目录；没有的可能是用户自建目录
                if (!File.Exists(Path.Combine(full, "NTUSER.DAT"))) continue;
                result.Add(new OrphanProfile(full));
            }
            catch
            {
            }
        }
        return result;
    }
}
