using System.Management;
using System.Text.RegularExpressions;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Drivers;

public sealed record DriverPackage(string PublishedName, string OriginalName, string Provider, string ClassName, string ClassGuid, string DriverDate, string DriverVersion, string Signer)
{
    /// <summary>同一硬件（原始 inf 名 + 厂商 + 类）的分组键。</summary>
    public string FamilyKey => $"{OriginalName}|{Provider}|{ClassGuid}".ToLowerInvariant();

    public Version? ParsedVersion => Version.TryParse(DriverVersion, out var v) ? v : null;
}

public sealed record DriverPackageRow(DriverPackage Package, bool IsNewestInFamily, bool InUse, int FamilySize);

public sealed record InstalledUpdate(string HotFixId, string Description, DateTime? InstalledOn);

/// <summary>
/// 驱动与更新管理（设计文档 5.2）。驱动包信息来自 pnputil /enum-drivers（按字段顺序解析，与界面语言无关）；
/// 只删除"同一硬件有更新版本且当前没有设备在用"的旧版本包，用 pnputil /delete-driver（不带 /force）；导出备份用 /export-driver。
/// Windows 更新：暂停 / 恢复写 WindowsUpdate\UX\Settings 的暂停时间值（写前备份），卸载补丁用 wusa /uninstall /kb:N（交互式）。
/// </summary>
public sealed partial class DriverStore
{
    public const string ModuleId = "drivers";
    private const string UpdateSettingsKey = @"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";

    private readonly RegistryBackup _backup;
    private readonly OperationLog _log;

    public DriverStore(RegistryBackup backup, OperationLog log)
    {
        _backup = backup;
        _log = log;
    }

    [GeneratedRegex(@"^oem\d{1,5}\.inf$", RegexOptions.IgnoreCase)]
    private static partial Regex PublishedNamePattern();

    [GeneratedRegex(@"^\d{6,8}$")]
    private static partial Regex KbPattern();

    // ---------- 枚举 ----------

    public static async Task<IReadOnlyList<DriverPackageRow>> ListAsync(CancellationToken ct = default)
    {
        var r = await SystemCommand.RunAsync("pnputil.exe", "/enum-drivers", TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        var packages = ParseEnumDrivers(r.Output);
        var inUse = await InUsePackagesAsync(ct).ConfigureAwait(false);
        return Classify(packages, inUse);
    }

    /// <summary>
    /// 按块解析：每个驱动包一块，块内按行顺序取冒号后的值：发布名、原始名、提供程序、类名、类 GUID、驱动版本（日期 版本）、签名者。
    /// 不依赖字段名的语言。
    /// </summary>
    internal static IReadOnlyList<DriverPackage> ParseEnumDrivers(string output)
    {
        var list = new List<DriverPackage>();
        var block = new List<string>();
        void Flush()
        {
            if (block.Count >= 6 && PublishedNamePattern().IsMatch(block[0].Trim()))
            {
                var (date, version) = SplitDateVersion(block[5]);
                list.Add(new DriverPackage(block[0].Trim(), block[1].Trim(), block[2].Trim(), block[3].Trim(), block[4].Trim(), date, version, block.Count > 6 ? block[6].Trim() : ""));
            }
            block.Clear();
        }
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                Flush();
                continue;
            }
            var idx = line.IndexOf(':');
            if (idx < 0) continue;
            var value = line[(idx + 1)..].Trim();
            // 第一行必须是 oemNN.inf，否则这是标题行（"Microsoft PnP Utility"）
            if (block.Count == 0 && !PublishedNamePattern().IsMatch(value)) continue;
            block.Add(value);
        }
        Flush();
        return list;
    }

    private static (string Date, string Version) SplitDateVersion(string s)
    {
        var parts = s.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2) return (parts[0], parts[^1]);
        return ("", s.Trim());
    }

    /// <summary>pnputil /enum-devices /drivers（Win10 2004+）列出每个设备正在用的 oemNN.inf。失败时返回空集，此时不删除任何包。</summary>
    private static async Task<HashSet<string>?> InUsePackagesAsync(CancellationToken ct)
    {
        var r = await SystemCommand.RunAsync("pnputil.exe", "/enum-devices /drivers", TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        if (!r.Success) return null;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in Regex.Matches(r.Output, @"\boem\d{1,5}\.inf\b", RegexOptions.IgnoreCase)) set.Add(m.Value);
        return set;
    }

    internal static IReadOnlyList<DriverPackageRow> Classify(IReadOnlyList<DriverPackage> packages, HashSet<string>? inUse)
    {
        var rows = new List<DriverPackageRow>();
        foreach (var family in packages.GroupBy(p => p.FamilyKey))
        {
            var ordered = family.OrderByDescending(p => p.ParsedVersion ?? new Version(0, 0)).ThenByDescending(p => p.DriverDate).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                // 读不到设备使用情况时，一律视为"可能在用"，不允许删除
                var used = inUse is null || inUse.Contains(ordered[i].PublishedName);
                rows.Add(new DriverPackageRow(ordered[i], i == 0, used, ordered.Count));
            }
        }
        return rows.OrderBy(r => r.Package.ClassName).ThenBy(r => r.Package.Provider).ThenBy(r => r.Package.OriginalName).ThenByDescending(r => r.Package.ParsedVersion).ToList();
    }

    // ---------- 删除旧版本 ----------

    /// <summary>只允许删除：非最新版本、没有设备在用的包。不带 /force。</summary>
    public async Task<(bool Success, string Message)> DeleteOldPackageAsync(DriverPackageRow row, CancellationToken ct = default)
    {
        if (!PublishedNamePattern().IsMatch(row.Package.PublishedName)) return (false, "发布名格式无效");
        if (row.IsNewestInFamily) return (false, "这是该硬件最新的驱动包，不删除");
        if (row.InUse) return (false, "有设备正在使用这个驱动包（或无法确认使用情况），不删除");
        if (row.FamilySize < 2) return (false, "该硬件只有一个驱动包");

        var r = await SystemCommand.RunAsync("pnputil.exe", $"/delete-driver {row.Package.PublishedName}", TimeSpan.FromMinutes(5), ct).ConfigureAwait(false);
        _log.Write(null, ModuleId, "delete-driver", $"{row.Package.PublishedName} ({row.Package.OriginalName} {row.Package.DriverVersion})", 0, r.Success, r.Output.Length > 400 ? r.Output[..400] : r.Output);
        return (r.Success, r.Success ? $"已删除 {row.Package.PublishedName}（{row.Package.OriginalName} {row.Package.DriverVersion}）。" : $"pnputil 退出码 {r.ExitCode}：{r.Output}");
    }

    /// <summary>导出全部第三方驱动包到目录（pnputil /export-driver * dir）。目录须通过 Path Guard 且不在系统目录内。</summary>
    public async Task<(bool Success, string Message)> ExportAllAsync(string directory, PathGuard guard, CancellationToken ct = default, IProgress<string>? output = null)
    {
        string full;
        try { full = PathGuard.Normalize(directory); }
        catch (Exception ex) { return (false, "目录无效：" + ex.Message); }
        var verdict = guard.Check(full);
        if (!verdict.Allowed) return (false, "目标目录不可用：" + verdict.Reason);
        if (full.Contains('"')) return (false, "目录名含非法字符");
        Directory.CreateDirectory(full);
        if (PathGuard.IsReparsePoint(full)) return (false, "目标目录是重解析点");

        var r = await SystemCommand.RunAsync("pnputil.exe", $"/export-driver * \"{full}\"", TimeSpan.FromMinutes(30), ct, output).ConfigureAwait(false);
        _log.Write(null, ModuleId, "export-drivers", full, 0, r.Success, r.TimedOut ? "超时" : $"退出码 {r.ExitCode}");
        return (r.Success, r.Success ? $"已导出到 {full}。" : $"pnputil 退出码 {r.ExitCode}：{(r.Output.Length > 400 ? r.Output[..400] : r.Output)}");
    }

    // ---------- Windows 更新 ----------

    public sealed record UpdatePauseState(DateTime? PausedUntil, bool Paused);

    public static UpdatePauseState GetPauseState()
    {
        try
        {
            using var k = RegistryPath.Open(UpdateSettingsKey, RegistryView.Registry64, writable: false);
            var raw = k?.GetValue("PauseUpdatesExpiryTime") as string;
            if (raw is not null && DateTime.TryParse(raw, null, System.Globalization.DateTimeStyles.RoundtripKind, out var until))
                return new UpdatePauseState(until.ToLocalTime(), until > DateTime.UtcNow);
        }
        catch { }
        return new UpdatePauseState(null, false);
    }

    /// <summary>暂停 1 到 35 天（与设置界面相同的上限）。写入前值级备份。</summary>
    public (bool Success, string Message) PauseUpdates(int days)
    {
        if (days is < 1 or > 35) return (false, "只能暂停 1 到 35 天");
        try
        {
            var start = DateTime.UtcNow;
            var end = start.AddDays(days);
            string Iso(DateTime d) => d.ToString("yyyy-MM-ddTHH:mm:ssZ");
            foreach (var name in new[] { "PauseUpdatesExpiryTime", "PauseFeatureUpdatesStartTime", "PauseFeatureUpdatesEndTime", "PauseQualityUpdatesStartTime", "PauseQualityUpdatesEndTime", "PauseUpdatesStartTime" })
                _backup.BackupValue(UpdateSettingsKey, name, $"暂停 Windows 更新 {days} 天");
            using var k = RegistryPath.Open(UpdateSettingsKey, RegistryView.Registry64, writable: true, create: true) ?? throw new InvalidOperationException("无法打开键");
            k.SetValue("PauseUpdatesStartTime", Iso(start));
            k.SetValue("PauseUpdatesExpiryTime", Iso(end));
            k.SetValue("PauseFeatureUpdatesStartTime", Iso(start));
            k.SetValue("PauseFeatureUpdatesEndTime", Iso(end));
            k.SetValue("PauseQualityUpdatesStartTime", Iso(start));
            k.SetValue("PauseQualityUpdatesEndTime", Iso(end));
            _log.Write(null, ModuleId, "pause-updates", days.ToString(), 0, true);
            return (true, $"已暂停 Windows 更新到 {end.ToLocalTime():yyyy-MM-dd HH:mm}。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "pause-updates", days.ToString(), 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    public (bool Success, string Message) ResumeUpdates()
    {
        try
        {
            using var k = RegistryPath.Open(UpdateSettingsKey, RegistryView.Registry64, writable: true);
            if (k is null) return (true, "当前没有暂停。");
            foreach (var name in new[] { "PauseUpdatesExpiryTime", "PauseFeatureUpdatesStartTime", "PauseFeatureUpdatesEndTime", "PauseQualityUpdatesStartTime", "PauseQualityUpdatesEndTime", "PauseUpdatesStartTime" })
            {
                if (k.GetValue(name) is null) continue;
                _backup.BackupValue(UpdateSettingsKey, name, "恢复 Windows 更新");
                k.DeleteValue(name, false);
            }
            _log.Write(null, ModuleId, "resume-updates", null, 0, true);
            return (true, "已恢复 Windows 更新。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "resume-updates", null, 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    public static IReadOnlyList<InstalledUpdate> GetInstalledUpdates()
    {
        var list = new List<InstalledUpdate>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
            foreach (ManagementObject o in searcher.Get())
            {
                try
                {
                    var id = o["HotFixID"]?.ToString() ?? "";
                    DateTime? on = DateTime.TryParse(o["InstalledOn"]?.ToString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var d) ? d : null;
                    list.Add(new InstalledUpdate(id, o["Description"]?.ToString() ?? "", on));
                }
                catch { }
            }
        }
        catch { }
        return list.OrderByDescending(u => u.InstalledOn ?? DateTime.MinValue).ToList();
    }

    /// <summary>wusa /uninstall /kb:N，交互式（让系统提示重启）。KB 号严格校验。</summary>
    public static (string Exe, string Args)? BuildUninstallUpdate(string hotFixId, out string? error)
    {
        error = null;
        var kb = hotFixId.Trim();
        if (kb.StartsWith("KB", StringComparison.OrdinalIgnoreCase)) kb = kb[2..];
        if (!KbPattern().IsMatch(kb))
        {
            error = "KB 编号格式无效";
            return null;
        }
        return ("wusa.exe", $"/uninstall /kb:{kb}");
    }

    public async Task<(bool Success, string Message)> UninstallUpdateAsync(string hotFixId, CancellationToken ct = default)
    {
        var cmd = BuildUninstallUpdate(hotFixId, out var error);
        if (cmd is null) return (false, error!);
        var r = await SystemCommand.RunAsync(cmd.Value.Exe, cmd.Value.Args, TimeSpan.FromHours(1), ct).ConfigureAwait(false);
        _log.Write(null, ModuleId, "uninstall-update", hotFixId, 0, r.Success, $"退出码 {r.ExitCode}");
        return (r.Success || r.ExitCode == 3010, r.ExitCode switch
        {
            0 => "已卸载。",
            3010 => "已卸载，需要重启。",
            2359303 => "该更新不存在或已卸载。",
            -2145124330 => "该更新是系统的一部分，不能卸载。",
            _ => $"wusa 退出码 {r.ExitCode}。",
        });
    }
}
