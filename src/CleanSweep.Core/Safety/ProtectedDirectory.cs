using System.Security.AccessControl;
using System.Security.Principal;

namespace CleanSweep.Core.Safety;

/// <summary>
/// 只允许 SYSTEM、Administrators 与当前用户访问的目录：隔离区根、程序数据目录（索引、注册表备份）。
/// 这些目录里的内容会被提权运行的程序信任并写回系统，不能让其他本地进程改得动。
/// 可信的判定不只看所有者：已存在的目录还要核对 DACL，任何其他主体持有写权限都视为不可信，
/// 所有者可信时尝试收紧权限修复，修复不了就拒绝使用。
/// </summary>
public static class ProtectedDirectory
{
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteAttributes |
        FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 确保目录存在且可信：已存在的目录不能是重解析点，所有者必须是 SYSTEM、Administrators 或当前用户，
    /// DACL 不能给其他主体写权限（不满足时尝试收紧，失败即拒绝）；新建目录必须成功设置 ACL（NTFS 上失败即删除并抛出）。
    /// </summary>
    public static void EnsureTrusted(string dir, bool hidden = false)
    {
        bool created = false;
        if (Directory.Exists(dir))
        {
            if (PathGuard.IsReparsePoint(dir))
                throw new IOException($"目录是重解析点，拒绝使用：{dir}");
            VerifyOwner(dir);
            VerifyAcl(dir, repair: true);
        }
        else
        {
            Directory.CreateDirectory(dir);
            created = true;
        }

        if (hidden)
        {
            try
            {
                File.SetAttributes(dir, FileAttributes.Directory | FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed);
            }
            catch
            {
                // 属性设置失败不影响功能
            }
        }

        if (created && !RestrictAcl(dir) && IsNtfs(dir))
        {
            try { Directory.Delete(dir); } catch { }
            throw new IOException($"无法为目录设置访问权限，拒绝使用：{dir}");
        }
    }

    public static void VerifyOwner(string dir)
    {
        if (!OperatingSystem.IsWindows() || !IsNtfs(dir)) return;
        SecurityIdentifier? owner;
        try
        {
            owner = new DirectoryInfo(dir).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch (Exception ex)
        {
            throw new IOException($"无法读取目录所有者：{ex.Message}（{dir}）");
        }
        if (owner is null) throw new IOException($"目录没有所有者信息：{dir}");

        if (!IsTrustedIdentity(owner))
            throw new IOException($"目录 {dir} 的所有者（{owner}）不可信，拒绝使用。请以管理员身份删除该目录后重试。");
    }

    /// <summary>
    /// 核对 DACL：除 SYSTEM、Administrators、当前用户外，任何主体都不得持有写类权限，且不能继承父目录的规则
    /// （卷根默认给 Authenticated Users 建子目录的权限）。repair 为 true 时先尝试用 <see cref="RestrictAcl"/> 收紧再复查。
    /// </summary>
    public static void VerifyAcl(string dir, bool repair)
    {
        if (!OperatingSystem.IsWindows() || !IsNtfs(dir)) return;

        var problem = FindAclProblem(dir);
        if (problem is null) return;

        if (repair && RestrictAcl(dir))
        {
            problem = FindAclProblem(dir);
            if (problem is null) return;
        }

        throw new IOException($"目录 {dir} 的访问权限不可信（{problem}），拒绝使用。请以管理员身份删除该目录后重试。");
    }

    /// <summary>返回 null 表示 DACL 可信，否则为问题描述。</summary>
    internal static string? FindAclProblem(string dir)
    {
        DirectorySecurity security;
        try
        {
            security = new DirectoryInfo(dir).GetAccessControl(AccessControlSections.Access);
        }
        catch (Exception ex)
        {
            return $"无法读取权限：{ex.Message}";
        }

        if (!security.AreAccessRulesProtected)
            return "继承了父目录的权限";

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if ((rule.FileSystemRights & WriteRights) == 0 && (rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl) continue;
            if (rule.IdentityReference is SecurityIdentifier sid && IsTrustedIdentity(sid)) continue;
            return $"{rule.IdentityReference} 拥有写权限";
        }
        return null;
    }

    private static bool IsTrustedIdentity(SecurityIdentifier sid)
    {
        if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) return true;
        try
        {
            var me = WindowsIdentity.GetCurrent().User;
            return me is not null && sid == me;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsNtfs(string dir)
    {
        try { return string.Equals(new DriveInfo(Path.GetPathRoot(dir)!).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    /// <summary>去掉继承，只保留 SYSTEM、Administrators 与当前用户的完全控制。</summary>
    public static bool RestrictAcl(string dir)
    {
        if (!OperatingSystem.IsWindows()) return true;
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            void Allow(IdentityReference id) =>
                security.AddAccessRule(new FileSystemAccessRule(id, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

            Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            var me = WindowsIdentity.GetCurrent().User;
            if (me is not null) Allow(me);

            new DirectoryInfo(dir).SetAccessControl(security);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
