using CleanSweep.Core.Backup;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Optimize;

public sealed record ContextMenuHandler(
    string Clsid, string Name, string Scope, string? DllPath, string? Publisher, SignatureState Signature, bool IsMicrosoft, bool Blocked, string RegistryKey, RegistryView View, bool DllMissing);

/// <summary>
/// 右键菜单管理（设计文档 4.4）：枚举 Shell 扩展的 ContextMenuHandlers，禁用通过系统提供的机制
/// HKLM\...\Shell Extensions\Blocked（登记 CLSID）实现，不删除注册。写入前值级备份，可随时恢复。微软自带的默认隐藏。
/// </summary>
public sealed class ContextMenuManager
{
    public const string ModuleId = "context-menu";
    private const string BlockedKey = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
    private const string BlockedKeyUser = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";

    private static readonly (string Relative, string Scope)[] HandlerRoots =
    {
        (@"*\shellex\ContextMenuHandlers", "所有文件"),
        (@"Directory\shellex\ContextMenuHandlers", "文件夹"),
        (@"Directory\Background\shellex\ContextMenuHandlers", "文件夹背景"),
        (@"Folder\shellex\ContextMenuHandlers", "文件夹（含虚拟）"),
        (@"Drive\shellex\ContextMenuHandlers", "驱动器"),
        (@"AllFilesystemObjects\shellex\ContextMenuHandlers", "所有文件系统对象"),
        (@"DesktopBackground\shellex\ContextMenuHandlers", "桌面背景"),
    };

    private readonly RegistryBackup _backup;
    private readonly OperationLog _log;

    public ContextMenuManager(RegistryBackup backup, OperationLog log)
    {
        _backup = backup;
        _log = log;
    }

    /// <summary>用当前用户身份写 HKLM 需要管理员；非提权时写 HKCU 的 Blocked（同样被资源管理器尊重）。</summary>
    private static string TargetBlockedKey => Safety.ProtectedDirectory.IsElevated() ? BlockedKey : BlockedKeyUser;

    public static IReadOnlyList<ContextMenuHandler> List()
    {
        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var bk in new[] { BlockedKey, BlockedKeyUser })
        {
            try
            {
                using var b = RegistryPath.Open(bk, RegistryView.Registry64, writable: false);
                if (b is not null) foreach (var v in b.GetValueNames()) blocked.Add(v.Trim());
            }
            catch { }
        }

        var result = new List<ContextMenuHandler>();
        foreach (var (rootPath, view) in new[] { (@"HKLM\Software\Classes", RegistryView.Registry64), (@"HKCU\Software\Classes", RegistryView.Registry64) })
        {
            foreach (var (relative, scope) in HandlerRoots)
            {
                RegistryKey? k;
                try { k = RegistryPath.Open(RegistryPath.Combine(rootPath, relative), view, writable: false); }
                catch { continue; }
                if (k is null) continue;
                using (k)
                {
                    foreach (var sub in k.GetSubKeyNames())
                    {
                        try
                        {
                            using var h = k.OpenSubKey(sub);
                            var clsid = (h?.GetValue(null) as string)?.Trim();
                            if (string.IsNullOrEmpty(clsid) || !clsid.StartsWith('{')) clsid = sub.StartsWith('{') ? sub : null;
                            if (clsid is null) continue;

                            var (dll, name) = ResolveClsid(clsid);
                            var sig = FileSignature.Inspect(dll);
                            var missing = dll is not null && RegistryProbe.ProbePath(dll) == FileProbe.Missing;
                            result.Add(new ContextMenuHandler(clsid, name ?? sub, scope, dll, sig.Publisher, sig.State, sig.IsMicrosoft || (dll is not null && RegistryProbe.IsUnderWindows(dll)),
                                blocked.Contains(clsid), RegistryPath.Combine(RegistryPath.Combine(rootPath, relative), sub), view, missing));
                        }
                        catch { }
                    }
                }
            }
        }
        return result.GroupBy(r => r.Clsid + "|" + r.Scope, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
            .OrderBy(r => r.IsMicrosoft).ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    private static (string? Dll, string? Name) ResolveClsid(string clsid)
    {
        foreach (var root in new[] { @"HKCU\Software\Classes\CLSID\", @"HKLM\Software\Classes\CLSID\" })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var k = RegistryPath.Open(root + clsid, view, writable: false);
                    if (k is null) continue;
                    var name = k.GetValue(null) as string;
                    string? dll = null;
                    using (var s = k.OpenSubKey("InprocServer32"))
                        dll = RegistryProbe.ExtractPath(s?.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string, isCommandLine: false);
                    if (string.IsNullOrWhiteSpace(name) && dll is not null)
                    {
                        try { name = System.Diagnostics.FileVersionInfo.GetVersionInfo(dll).FileDescription; } catch { }
                    }
                    return (dll, string.IsNullOrWhiteSpace(name) ? null : name);
                }
                catch { }
            }
        }
        return (null, null);
    }

    /// <summary>禁用 = 在 Blocked 键登记 CLSID；启用 = 删除登记。资源管理器下次打开菜单时生效（或重启资源管理器）。</summary>
    public (bool Success, string Message) SetBlocked(ContextMenuHandler handler, bool blocked)
    {
        if (!handler.Clsid.StartsWith('{') || !handler.Clsid.EndsWith('}') || !Guid.TryParse(handler.Clsid, out _)) return (false, "CLSID 无效");
        try
        {
            var key = TargetBlockedKey;
            _backup.BackupValue(key, handler.Clsid, $"{(blocked ? "禁用" : "启用")}右键菜单扩展 {handler.Name}");
            using var k = RegistryPath.Open(key, RegistryView.Registry64, writable: true, create: true) ?? throw new InvalidOperationException("无法打开 Blocked 键");
            if (blocked) k.SetValue(handler.Clsid, handler.Name, RegistryValueKind.String);
            else
            {
                k.DeleteValue(handler.Clsid, false);
                // 另一处（HKLM / HKCU）若也登记了，能删就删
                try
                {
                    var other = key == BlockedKey ? BlockedKeyUser : BlockedKey;
                    using var o = RegistryPath.Open(other, RegistryView.Registry64, writable: true);
                    if (o?.GetValue(handler.Clsid) is not null)
                    {
                        _backup.BackupValue(other, handler.Clsid, $"启用右键菜单扩展 {handler.Name}");
                        o.DeleteValue(handler.Clsid, false);
                    }
                }
                catch { }
            }
            _log.Write(null, ModuleId, blocked ? "block" : "unblock", $"{handler.Clsid} {handler.Name}", 0, true);
            return (true, blocked ? $"已禁用“{handler.Name}”。重新打开右键菜单即生效，若仍显示请重启资源管理器。" : $"已启用“{handler.Name}”。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, blocked ? "block" : "unblock", handler.Clsid, 0, false, ex.Message);
            return (false, ex.Message);
        }
    }
}
