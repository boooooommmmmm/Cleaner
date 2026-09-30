using System.Diagnostics;
using System.Text.RegularExpressions;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Uninstall;

/// <summary>要执行的官方卸载命令。</summary>
public sealed record UninstallCommand(string Exe, string Args, string Kind);

public sealed record UninstallResult(bool Started, bool Completed, int? ExitCode, bool StillInstalled, string Message);

/// <summary>
/// 强力卸载（设计文档 5.1）：只调用官方卸载程序（注册表 UninstallString / QuietUninstallString、MSI 产品代码、
/// 应用商店包移除），等待其结束后重新扫描清单确认，并写入卸载历史供残留清理定向扫描。不做进程注入，不强杀卸载程序。
/// </summary>
public sealed partial class Uninstaller
{
    public const string ModuleId = "uninstall";

    private readonly AppInventory _inventory;
    private readonly UninstallHistory _history;
    private readonly OperationLog _log;

    public Uninstaller(AppInventory inventory, UninstallHistory history, OperationLog log)
    {
        _inventory = inventory;
        _history = history;
        _log = log;
    }

    [GeneratedRegex(@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")]
    private static partial Regex ProductCode();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9.\-]*_[0-9]+(\.[0-9]+){1,3}_[A-Za-z0-9]+_[A-Za-z0-9~.\-]*_[a-z0-9]{13}$")]
    private static partial Regex PackageFullName();

    /// <summary>根据清单条目构造卸载命令。返回 null 并给出原因表示无法卸载。</summary>
    public static UninstallCommand? BuildCommand(InstalledApp app, bool quiet, out string? error)
    {
        error = null;
        var system32 = System.Environment.SystemDirectory;

        if (app.Source == AppSource.Uwp)
        {
            if (app.PackageFullName is null || !PackageFullName().IsMatch(app.PackageFullName))
            {
                error = "包全名格式无效";
                return null;
            }
            if (app.IsSystemComponent)
            {
                error = "系统组件包不允许卸载";
                return null;
            }
            var ps = Path.Combine(system32, "WindowsPowerShell", "v1.0", "powershell.exe");
            return new UninstallCommand(ps, $"-NoProfile -NonInteractive -Command \"Remove-AppxPackage -Package '{app.PackageFullName}'\"", "uwp");
        }

        if (app.Source == AppSource.Portable)
        {
            error = "便携软件没有卸载程序，可在残留清理中把它的目录移入隔离区";
            return null;
        }

        var raw = quiet && !string.IsNullOrWhiteSpace(app.QuietUninstallString) ? app.QuietUninstallString! : app.UninstallString;
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "没有卸载命令";
            return null;
        }
        raw = System.Environment.ExpandEnvironmentVariables(raw.Trim());

        // MSI：统一改写为 msiexec /x {ProductCode}，不信任注册表里的其余参数
        if (raw.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
        {
            var m = ProductCode().Match(raw);
            if (!m.Success)
            {
                error = "MSI 卸载命令缺少产品代码";
                return null;
            }
            var args = $"/x {m.Value}";
            if (quiet) args += " /qb- /norestart";
            return new UninstallCommand(Path.Combine(system32, "msiexec.exe"), args, "msi");
        }

        var (exe, args2) = CommandLine.Split(raw);
        if (exe is null || !Path.IsPathRooted(exe))
        {
            error = $"无法解析卸载程序路径：{raw}";
            return null;
        }
        if (!File.Exists(exe))
        {
            error = $"卸载程序不存在：{exe}。可在残留清理中处理它遗留的文件，或在“应用和功能”中移除该条目";
            return null;
        }
        return new UninstallCommand(exe, args2 ?? "", "exe");
    }

    /// <summary>
    /// 注册表卸载项的卸载程序已不存在（非 MSI、非应用商店、命令里的可执行文件路径是绝对路径但文件没了）：
    /// 这条登记项在"应用和功能"里既卸不掉也修不了，唯一的出路是移除登记项本身。
    /// </summary>
    public static bool UninstallerMissing(InstalledApp app, out string? exe)
    {
        exe = null;
        if (app.Source != AppSource.Registry || string.IsNullOrWhiteSpace(app.RegistryKey)) return false;
        var raw = app.UninstallString;
        if (string.IsNullOrWhiteSpace(raw) || raw.Contains("msiexec", StringComparison.OrdinalIgnoreCase)) return false;
        raw = System.Environment.ExpandEnvironmentVariables(raw.Trim());
        var (candidate, _) = CommandLine.Split(raw);
        if (candidate is null || !Path.IsPathRooted(candidate) || File.Exists(candidate)) return false;
        exe = candidate;
        return true;
    }

    /// <summary>
    /// 移除卸载程序已不存在的登记项：只删这一条 Uninstall 键（RegistryOps 先导出 .reg 备份，可在设置页还原），
    /// 不运行任何程序、不动安装目录（Program Files 全树保护），并写入卸载历史让残留清理定向扫描。返回备份文件名。
    /// </summary>
    public string RemoveEntry(InstalledApp app, RegistryCleaning.RegistryOps ops)
    {
        if (!UninstallerMissing(app, out var exe)) throw new InvalidOperationException("只有卸载程序已不存在的登记项才能移除");

        // 清单可能是几分钟前读的：重新读键里的 UninstallString，与清单不一致（软件被重装 / 修复）就拒绝
        using (var k = Backup.RegistryPath.Open(app.RegistryKey!, app.View, writable: false) ?? throw new InvalidOperationException("登记项已不存在，请刷新"))
        {
            var now = (k.GetValue("UninstallString", null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames) as string)?.Trim();
            if (!string.Equals(now, app.UninstallString?.Trim(), StringComparison.Ordinal))
                throw new InvalidOperationException("登记项在读取后已变化（软件可能已重新安装或修复），请刷新后再试");
        }
        // 删除前快照 + 重探卸载程序仍不存在（RegistryOps 的统一核对）
        var snapshot = RegistryCleaning.RegistrySnapshot.OfKey(app.RegistryKey!, app.View);
        var backup = ops.DeleteKey(new Model.RegistryTarget(app.RegistryKey!, app.View, null), $"移除卸载项：{app.Name}（卸载程序 {exe} 已不存在）", snapshot, exe);
        _history.Record(app, "entry-removed");
        _log.Write(null, ModuleId, "remove-entry", app.RegistryKey, 0, true, $"卸载程序 {exe} 已不存在；备份：{backup}");
        return backup;
    }

    /// <summary>运行官方卸载程序并等待结束。取消只停止等待，不终止卸载程序（中途强杀会留下半卸载状态）。</summary>
    public async Task<UninstallResult> RunAsync(InstalledApp app, bool quiet, CancellationToken ct)
    {
        var cmd = BuildCommand(app, quiet, out var error);
        if (cmd is null)
        {
            _log.Write(null, ModuleId, "uninstall", app.Name, 0, false, error);
            return new UninstallResult(false, false, null, true, error!);
        }

        _log.Write(null, ModuleId, "uninstall-start", app.Name, 0, true, $"{cmd.Exe} {cmd.Args}");
        Process p;
        try
        {
            p = Process.Start(new ProcessStartInfo(cmd.Exe, cmd.Args) { UseShellExecute = false }) ?? throw new InvalidOperationException("进程未启动");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "uninstall", app.Name, 0, false, ex.Message);
            return new UninstallResult(false, false, null, true, $"启动卸载程序失败：{ex.Message}");
        }

        int? exitCode = null;
        bool completed;
        using (p)
        {
            try
            {
                await p.WaitForExitAsync(ct).ConfigureAwait(false);
                exitCode = p.ExitCode;
                completed = true;
            }
            catch (OperationCanceledException)
            {
                completed = false;
            }
        }

        // 部分卸载程序会把自己复制到 Temp 再退出，真正的卸载在后台继续：等一小会儿再核对
        if (completed) await Task.Delay(TimeSpan.FromSeconds(2), CancellationToken.None).ConfigureAwait(false);

        var snapshot = _inventory.Scan(CancellationToken.None);
        var still = snapshot.Apps.Any(a => a.Id.Equals(app.Id, StringComparison.OrdinalIgnoreCase));
        if (!still) _history.Record(app, "uninstaller");

        string message;
        if (!completed) message = "已停止等待，卸载程序仍在运行；完成后请刷新列表。";
        else if (!still) message = $"“{app.Name}”已卸载（退出码 {exitCode}）。可在“残留清理”中查看它遗留的用户数据。";
        else if (exitCode == 1602 || exitCode == 1223) message = "用户取消了卸载。";
        else if (exitCode == 3010 || exitCode == 1641) message = "卸载完成，需要重启后生效。";
        else message = $"卸载程序已退出（退出码 {exitCode}），但应用仍在清单中；可能需要重启，或卸载程序未真正执行。";

        _log.Write(null, ModuleId, "uninstall-end", app.Name, 0, !still, message);
        return new UninstallResult(true, completed, exitCode, still, message);
    }
}
