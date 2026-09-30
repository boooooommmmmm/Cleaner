using System.Diagnostics;
using System.Text.RegularExpressions;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Repair;

public enum RepairOperation
{
    SfcScan,
    DismCheckHealth,
    DismScanHealth,
    DismRestoreHealth,
    ResetStoreCache,
    RestartExplorer,
    OpenDefaultApps,
}

public sealed record RepairAction(RepairOperation Operation, string Title, string Description, bool NeedsAdmin, bool LongRunning);

/// <summary>
/// 系统修复（设计文档 5.4）：一键运行 sfc / DISM、重置商店缓存、重启资源管理器（图标 / 缩略图缓存由清理规则移入隔离区后重启生效）、
/// 打开默认应用设置；Hosts 文件查看 / 编辑（修改前备份到数据目录、逐行校验、可恢复默认）。所有命令来自固定操作表。
/// </summary>
public sealed partial class SystemRepair
{
    public const string ModuleId = "repair";

    public static readonly IReadOnlyList<RepairAction> Actions = new[]
    {
        new RepairAction(RepairOperation.SfcScan, "系统文件检查（sfc /scannow）", "扫描并修复受保护的系统文件。需要几分钟到几十分钟。", true, true),
        new RepairAction(RepairOperation.DismCheckHealth, "组件存储快速检查（DISM /CheckHealth）", "只检查组件存储是否被标记为损坏，几秒完成。", true, false),
        new RepairAction(RepairOperation.DismScanHealth, "组件存储深度扫描（DISM /ScanHealth）", "扫描组件存储损坏情况，不修复。需要几分钟。", true, true),
        new RepairAction(RepairOperation.DismRestoreHealth, "组件存储修复（DISM /RestoreHealth）", "用 Windows 更新的源修复组件存储，是 sfc 无法修复时的下一步。需要联网，可能持续较长时间。", true, true),
        new RepairAction(RepairOperation.ResetStoreCache, "重置 Microsoft Store 缓存（wsreset）", "商店打不开、下载卡住时使用。会弹出商店窗口。", false, false),
        new RepairAction(RepairOperation.RestartExplorer, "重启资源管理器", "任务栏、开始菜单、右键菜单异常或清理图标缓存后使用。打开的文件夹窗口会关闭。", false, false),
        new RepairAction(RepairOperation.OpenDefaultApps, "修复文件关联（打开默认应用设置）", "文件关联由系统设置管理，本程序不直接改写关联表。", false, false),
    };

    private readonly OperationLog _log;
    private readonly string _backupDir;

    public SystemRepair(OperationLog log, string backupDir)
    {
        _log = log;
        _backupDir = backupDir;
    }

    public static (string Exe, string Args)? BuildCommand(RepairOperation op) => op switch
    {
        RepairOperation.SfcScan => ("sfc.exe", "/scannow"),
        RepairOperation.DismCheckHealth => ("dism.exe", "/Online /Cleanup-Image /CheckHealth"),
        RepairOperation.DismScanHealth => ("dism.exe", "/Online /Cleanup-Image /ScanHealth"),
        RepairOperation.DismRestoreHealth => ("dism.exe", "/Online /Cleanup-Image /RestoreHealth"),
        RepairOperation.ResetStoreCache => ("wsreset.exe", ""),
        _ => null,
    };

    public async Task<CommandResult> RunAsync(RepairOperation op, CancellationToken ct, IProgress<string>? output = null)
    {
        switch (op)
        {
            case RepairOperation.RestartExplorer:
                return RestartExplorer();
            case RepairOperation.OpenDefaultApps:
                try
                {
                    Process.Start(new ProcessStartInfo("ms-settings:defaultapps") { UseShellExecute = true });
                    return new CommandResult(0, "已打开“默认应用”设置。", TimeSpan.Zero, false);
                }
                catch (Exception ex)
                {
                    return new CommandResult(-1, ex.Message, TimeSpan.Zero, false);
                }
        }

        var cmd = BuildCommand(op);
        if (cmd is null) return new CommandResult(-1, "未知操作", TimeSpan.Zero, false);
        var timeout = op is RepairOperation.DismCheckHealth or RepairOperation.ResetStoreCache ? TimeSpan.FromMinutes(5) : TimeSpan.FromHours(2);
        var r = await SystemCommand.RunAsync(cmd.Value.Exe, cmd.Value.Args, timeout, ct, output).ConfigureAwait(false);
        _log.Write(null, ModuleId, op.ToString(), $"{cmd.Value.Exe} {cmd.Value.Args}", 0, r.Success, r.TimedOut ? "超时" : $"退出码 {r.ExitCode}");
        return r;
    }

    /// <summary>
    /// 结束当前会话的 explorer.exe 并重新启动一个（Windows 会自动补齐任务栏）。
    /// 本程序提权运行时，新 explorer 必须用旧 explorer 的普通用户令牌启动：直接 Process.Start 出来的是提权的 explorer，
    /// 拖放会失效、从它启动的每个程序都变成管理员。拿不到令牌时退回普通启动并在消息里说明。
    /// </summary>
    private CommandResult RestartExplorer()
    {
        var sw = Stopwatch.StartNew();
        var token = IntPtr.Zero;
        try
        {
            var mySession = Process.GetCurrentProcess().SessionId;
            var elevated = ProtectedDirectory.IsElevated();
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                using (p)
                {
                    try
                    {
                        if (p.SessionId != mySession) continue;
                        if (elevated && token == IntPtr.Zero) token = UnelevatedProcess.DuplicatePrimaryTokenOf(p);
                        p.Kill();
                        p.WaitForExit(5000);
                    }
                    catch { }
                }
            }
            Thread.Sleep(800);
            var note = "";
            if (Process.GetProcessesByName("explorer").All(p => { using (p) return p.SessionId != mySession; }))
            {
                var exe = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows), "explorer.exe");
                string? err = elevated ? UnelevatedProcess.TryStart(token, exe, null) : "未提权，直接启动";
                if (err is not null)
                {
                    Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
                    if (elevated) note = $"（未能以普通用户令牌启动：{err}；新的资源管理器以管理员权限运行，注销再登录可恢复正常）";
                }
            }
            _log.Write(null, ModuleId, "restart-explorer", null, 0, true, note.Length > 0 ? note : null);
            return new CommandResult(0, "已重启资源管理器。" + note, sw.Elapsed, false);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "restart-explorer", null, 0, false, ex.Message);
            return new CommandResult(-1, ex.Message, sw.Elapsed, false);
        }
        finally
        {
            UnelevatedProcess.CloseToken(token);
        }
    }

    // ---------- Hosts ----------

    public static string HostsPath => Path.Combine(System.Environment.SystemDirectory, "drivers", "etc", "hosts");

    public const string DefaultHosts = """
        # Copyright (c) 1993-2009 Microsoft Corp.
        #
        # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
        #
        # This file contains the mappings of IP addresses to host names. Each
        # entry should be kept on an individual line. The IP address should
        # be placed in the first column followed by the corresponding host name.
        # The IP address and the host name should be separated by at least one
        # space.
        #
        # Additionally, comments (such as these) may be inserted on individual
        # lines or following the machine name denoted by a '#' symbol.
        #
        # For example:
        #
        #      102.54.94.97     rhino.acme.com          # source server
        #       38.25.63.10     x.acme.com              # x client host

        # localhost name resolution is handled within DNS itself.
        #	127.0.0.1       localhost
        #	::1             localhost
        """;

    public static string ReadHosts() => File.Exists(HostsPath) ? File.ReadAllText(HostsPath) : "";

    [GeneratedRegex(@"^\s*(\S+)\s+(\S+)(\s+\S+)*\s*(#.*)?$")]
    private static partial Regex HostsLine();

    /// <summary>逐行校验：空行、# 注释、"IP 主机名 [主机名…] [# 注释]"。返回第一处错误，null 表示合法。</summary>
    public static string? ValidateHosts(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) continue;
            var m = HostsLine().Match(line);
            if (!m.Success) return $"第 {i + 1} 行格式错误：{line}";
            if (!System.Net.IPAddress.TryParse(m.Groups[1].Value, out _)) return $"第 {i + 1} 行不是合法 IP 地址：{m.Groups[1].Value}";
            foreach (var host in line.Split('#')[0].Split(' ', '\t').Skip(1).Where(s => s.Length > 0))
            {
                if (host.Length > 253 || !Regex.IsMatch(host, @"^[A-Za-z0-9._-]+$")) return $"第 {i + 1} 行主机名非法：{host}";
            }
        }
        return null;
    }

    /// <summary>写入 hosts：先校验，再把现有文件备份到数据目录，然后写到同目录临时文件并原子替换（中途失败不会留下截断的 hosts）。需要管理员权限。</summary>
    public (bool Success, string Message) WriteHosts(string content) => WriteHostsFile(HostsPath, content);

    internal (bool Success, string Message) WriteHostsFile(string hostsPath, string content)
    {
        var bad = ValidateHosts(content);
        if (bad is not null) return (false, bad);
        try
        {
            Directory.CreateDirectory(_backupDir);
            // 名字带毫秒与随机后缀：同一秒内连续保存不会冲突
            var backup = Path.Combine(_backupDir, $"hosts-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid().ToString("N")[..6]}.bak");
            var exists = File.Exists(hostsPath);
            if (exists) File.Copy(hostsPath, backup, overwrite: false);

            var bytes = new System.Text.UTF8Encoding(false).GetBytes(content.Replace("\r\n", "\n").Replace("\n", "\r\n"));
            var dir = Path.GetDirectoryName(hostsPath)!;
            Directory.CreateDirectory(dir);
            var temp = Path.Combine(dir, $"hosts.{Guid.NewGuid():N}.tmp");
            try
            {
                File.WriteAllBytes(temp, bytes);
                if (exists) File.Replace(temp, hostsPath, null); // ReplaceFile 保留原文件的 ACL 与属性
                else File.Move(temp, hostsPath);
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            }
            _log.Write(null, ModuleId, "hosts-write", hostsPath, 0, true, exists ? "备份：" + Path.GetFileName(backup) : "新建");
            return (true, exists ? $"已保存，原文件备份为 {Path.GetFileName(backup)}。DNS 缓存可能需要刷新。" : "已保存。DNS 缓存可能需要刷新。");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "没有写入权限：修改 hosts 需要以管理员身份运行。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "hosts-write", hostsPath, 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    public IReadOnlyList<string> ListHostsBackups()
    {
        if (!Directory.Exists(_backupDir)) return Array.Empty<string>();
        return Directory.EnumerateFiles(_backupDir, "hosts-*.bak").OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
