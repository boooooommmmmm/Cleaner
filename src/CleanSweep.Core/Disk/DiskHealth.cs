using System.Management;
using System.Text.RegularExpressions;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Disk;

public enum MediaKind
{
    Unknown,
    Hdd,
    Ssd,
    Scm,
}

public sealed record PhysicalDiskInfo(
    int Number, string FriendlyName, MediaKind Media, string BusType, long SizeBytes, string HealthStatus, string? SerialNumber, string? FirmwareVersion);

public sealed record VolumeInfo(string Letter, string Label, string FileSystem, long SizeBytes, long FreeBytes, int? DiskNumber, MediaKind Media, DriveType Type)
{
    public double UsedFraction => SizeBytes <= 0 ? 0 : 1.0 - (double)FreeBytes / SizeBytes;
}

public sealed record SmartInfo(int DiskNumber, bool? PredictFailure, int? TemperatureCelsius, int? WearPercent, long? PowerOnHours, long? ReadErrorsTotal, long? WriteErrorsTotal, string? Note);

public sealed record OptimizeScheduleInfo(bool TaskFound, bool Enabled, DateTime? LastRun, DateTime? NextRun, int? LastResult, string? Note);

/// <summary>
/// 磁盘健康与优化（设计文档 4.2）：介质识别、系统优化计划状态、S.M.A.R.T.、chkdsk 调度、手动触发 defrag.exe。
/// 不自研碎片整理；对固态盘绝不允许传统碎片整理（/D），这是引擎层硬约束。
/// </summary>
public static class DiskHealth
{
    private const string StorageScope = @"root\Microsoft\Windows\Storage";

    public static IReadOnlyList<PhysicalDiskInfo> GetPhysicalDisks()
    {
        var list = new List<PhysicalDiskInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(StorageScope, "SELECT DeviceId, FriendlyName, MediaType, BusType, Size, HealthStatus, SerialNumber, FirmwareVersion FROM MSFT_PhysicalDisk");
            foreach (ManagementObject d in searcher.Get())
            {
                try
                {
                    var number = int.TryParse(d["DeviceId"]?.ToString(), out var n) ? n : -1;
                    var media = Convert.ToInt32(d["MediaType"] ?? 0) switch { 3 => MediaKind.Hdd, 4 => MediaKind.Ssd, 5 => MediaKind.Scm, _ => MediaKind.Unknown };
                    var bus = Convert.ToInt32(d["BusType"] ?? 0) switch
                    {
                        1 => "SCSI", 2 => "ATAPI", 3 => "ATA", 4 => "IEEE 1394", 5 => "SSA", 6 => "Fibre Channel", 7 => "USB", 8 => "RAID", 9 => "iSCSI",
                        10 => "SAS", 11 => "SATA", 12 => "SD", 13 => "MMC", 14 => "Virtual", 15 => "File Backed Virtual", 16 => "Storage Spaces", 17 => "NVMe", 18 => "SCM", 19 => "UFS", _ => "未知",
                    };
                    var health = Convert.ToInt32(d["HealthStatus"] ?? 0) switch { 0 => "健康", 1 => "警告", 2 => "不健康", 5 => "未知", _ => "未知" };
                    list.Add(new PhysicalDiskInfo(number, d["FriendlyName"]?.ToString() ?? $"磁盘 {number}", media, bus, Convert.ToInt64(d["Size"] ?? 0L), health,
                        d["SerialNumber"]?.ToString()?.Trim(), d["FirmwareVersion"]?.ToString()?.Trim()));
                }
                catch { }
            }
        }
        catch { }
        return list.OrderBy(d => d.Number).ToList();
    }

    /// <summary>卷 → 磁盘的映射来自 MSFT_Partition（DriveLetter、DiskNumber）；映射不到时用寻道开销探测介质。</summary>
    public static IReadOnlyList<VolumeInfo> GetVolumes(IReadOnlyList<PhysicalDiskInfo>? disks = null)
    {
        disks ??= GetPhysicalDisks();
        var letterToDisk = new Dictionary<char, int>();
        try
        {
            using var searcher = new ManagementObjectSearcher(StorageScope, "SELECT DriveLetter, DiskNumber FROM MSFT_Partition");
            foreach (ManagementObject p in searcher.Get())
            {
                try
                {
                    var letter = p["DriveLetter"];
                    if (letter is null) continue;
                    var ch = letter is char c ? c : letter.ToString() is { Length: > 0 } s ? s[0] : '\0';
                    if (ch == '\0') continue;
                    letterToDisk[char.ToUpperInvariant(ch)] = Convert.ToInt32(p["DiskNumber"]);
                }
                catch { }
            }
        }
        catch { }

        var result = new List<VolumeInfo>();
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); } catch { return result; }
        foreach (var d in drives)
        {
            try
            {
                if (!d.IsReady) continue;
                var letter = char.ToUpperInvariant(d.Name[0]);
                int? diskNumber = letterToDisk.TryGetValue(letter, out var n) ? n : null;
                var media = diskNumber is { } dn ? disks.FirstOrDefault(x => x.Number == dn)?.Media ?? MediaKind.Unknown : MediaKind.Unknown;
                if (media == MediaKind.Unknown && d.DriveType == DriveType.Fixed)
                    media = DiskMedia.IsSolidState(d.RootDirectory.FullName) switch { true => MediaKind.Ssd, false => MediaKind.Hdd, _ => MediaKind.Unknown };
                result.Add(new VolumeInfo(letter + ":", d.VolumeLabel, d.DriveFormat, d.TotalSize, d.AvailableFreeSpace, diskNumber, media, d.DriveType));
            }
            catch { }
        }
        return result;
    }

    /// <summary>S.M.A.R.T. 预警与可靠性计数器。两者都可能需要管理员权限；读不到的字段为 null。</summary>
    public static IReadOnlyList<SmartInfo> GetSmart(IReadOnlyList<PhysicalDiskInfo> disks)
    {
        var result = new List<SmartInfo>();
        // 可靠性计数器（Storage Spaces API，Win8+）
        var counters = new Dictionary<int, (int? Temp, int? Wear, long? Hours, long? ReadErr, long? WriteErr)>();
        try
        {
            using var searcher = new ManagementObjectSearcher(StorageScope, "SELECT DeviceId, Temperature, Wear, PowerOnHours, ReadErrorsTotal, WriteErrorsTotal FROM MSFT_StorageReliabilityCounter");
            foreach (ManagementObject c in searcher.Get())
            {
                try
                {
                    // DeviceId 形如 "{guid}" 或 "0"；能解析成数字的直接用
                    var id = c["DeviceId"]?.ToString();
                    if (!int.TryParse(id, out var num)) continue;
                    counters[num] = (ToInt(c["Temperature"]), ToInt(c["Wear"]), ToLong(c["PowerOnHours"]), ToLong(c["ReadErrorsTotal"]), ToLong(c["WriteErrorsTotal"]));
                }
                catch { }
            }
        }
        catch { }

        // 经典 SMART 预警（root\wmi）：InstanceName 是设备实例路径（加 "_0"），与 Win32_DiskDrive.PNPDeviceID 对应，
        // 由此映射到磁盘号；映射不到的磁盘显示未知，绝不按枚举顺序猜
        var predictByInstance = new List<(string Instance, bool Predict)>();
        string? note = null;
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\wmi", "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus");
            foreach (ManagementObject s in searcher.Get())
            {
                try { predictByInstance.Add((s["InstanceName"]?.ToString() ?? "", Convert.ToBoolean(s["PredictFailure"]))); } catch { }
            }
        }
        catch (Exception ex)
        {
            note = "读取 S.M.A.R.T. 预警失败（通常需要管理员权限，NVMe 与 USB 磁盘可能不支持）：" + ex.Message;
        }
        var drives = new List<(int Index, string PnpId)>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Index, PNPDeviceID FROM Win32_DiskDrive");
            foreach (ManagementObject d in searcher.Get())
            {
                try { drives.Add((Convert.ToInt32(d["Index"]), d["PNPDeviceID"]?.ToString() ?? "")); } catch { }
            }
        }
        catch { }
        var predicts = MapPredictions(predictByInstance, drives);

        foreach (var d in disks)
        {
            counters.TryGetValue(d.Number, out var c);
            bool? predict = predicts.TryGetValue(d.Number, out var p) ? p : null;
            result.Add(new SmartInfo(d.Number, predict, c.Temp, c.Wear, c.Hours, c.ReadErr, c.WriteErr, note));
        }
        return result;
    }

    /// <summary>InstanceName（如 "SCSI\Disk&amp;Ven_X\4&amp;1a2b_0"）去掉尾部 "_N" 后与 PNPDeviceID 相等才算同一磁盘。</summary>
    internal static Dictionary<int, bool> MapPredictions(IReadOnlyList<(string Instance, bool Predict)> predictions, IReadOnlyList<(int Index, string PnpId)> drives)
    {
        var map = new Dictionary<int, bool>();
        foreach (var (instance, predict) in predictions)
        {
            var key = instance;
            var us = key.LastIndexOf('_');
            if (us > 0 && key[(us + 1)..].All(char.IsDigit)) key = key[..us];
            foreach (var (index, pnp) in drives)
            {
                if (pnp.Length > 0 && string.Equals(pnp, key, StringComparison.OrdinalIgnoreCase))
                {
                    map[index] = predict;
                    break;
                }
            }
        }
        return map;
    }

    private static int? ToInt(object? o) => o is null ? null : Convert.ToInt32(o) is var v && v > 0 ? v : null;
    private static long? ToLong(object? o) => o is null ? null : Convert.ToInt64(o);

    /// <summary>系统自带的"优化驱动器"计划任务状态。</summary>
    public static OptimizeScheduleInfo GetOptimizeSchedule()
    {
        try
        {
            var t = Type.GetTypeFromProgID("Schedule.Service");
            if (t is null) return new OptimizeScheduleInfo(false, false, null, null, null, "任务计划程序不可用");
            dynamic svc = Activator.CreateInstance(t)!;
            svc.Connect();
            dynamic folder = svc.GetFolder(@"\Microsoft\Windows\Defrag");
            dynamic task = folder.GetTask("ScheduledDefrag");
            bool enabled = task.Enabled;
            DateTime last = task.LastRunTime;
            DateTime next = task.NextRunTime;
            int lastResult = task.LastTaskResult;
            return new OptimizeScheduleInfo(true, enabled, last.Year > 2000 ? last : null, next.Year > 2000 ? next : null, lastResult, null);
        }
        catch (Exception ex)
        {
            return new OptimizeScheduleInfo(false, false, null, null, null, ex.Message);
        }
    }

    // ---------- 固定操作表 ----------

    public enum DiskOperation
    {
        /// <summary>defrag /A：只分析，不写。</summary>
        Analyze,

        /// <summary>defrag /O：按介质执行合适的优化（HDD 整理、SSD 修剪）。</summary>
        Optimize,

        /// <summary>defrag /L：重新修剪（TRIM），仅固态盘。</summary>
        Retrim,

        /// <summary>defrag /D：传统碎片整理，仅机械盘。</summary>
        Defragment,

        /// <summary>chkntfs /C：下次启动时检查磁盘。</summary>
        ScheduleCheckDisk,

        /// <summary>chkntfs X:：查询是否已计划检查 / 是否脏。</summary>
        QueryCheckDisk,
    }

    private static readonly Regex LetterPattern = new("^[A-Z]:$", RegexOptions.Compiled);

    /// <summary>构造命令。SSD 上的 Defragment 与 HDD 上的 Retrim 直接拒绝。</summary>
    public static (string Exe, string Args)? BuildCommand(DiskOperation op, string letter, MediaKind media, out string? error)
    {
        error = null;
        letter = letter.Trim().ToUpperInvariant();
        if (letter.Length == 1) letter += ":";
        if (!LetterPattern.IsMatch(letter))
        {
            error = "驱动器号无效";
            return null;
        }
        switch (op)
        {
            case DiskOperation.Analyze: return ("defrag.exe", $"{letter} /A /U");
            case DiskOperation.Optimize: return ("defrag.exe", $"{letter} /O /U");
            case DiskOperation.Retrim:
                if (media != MediaKind.Ssd && media != MediaKind.Scm) { error = "重新修剪只适用于固态盘"; return null; }
                return ("defrag.exe", $"{letter} /L /U");
            case DiskOperation.Defragment:
                if (media != MediaKind.Hdd) { error = "禁止对固态盘或介质未知的卷做碎片整理（硬性约束）"; return null; }
                return ("defrag.exe", $"{letter} /D /U");
            case DiskOperation.ScheduleCheckDisk: return ("chkntfs.exe", $"/C {letter}");
            case DiskOperation.QueryCheckDisk: return ("chkntfs.exe", letter);
            default: error = "未知操作"; return null;
        }
    }

    /// <summary>defrag 的所有操作与 chkntfs /C 都需要管理员身份；普通权限下 defrag 什么都不做，只打印错误且退出码仍为 0。</summary>
    public static bool RequiresElevation(DiskOperation op) => op != DiskOperation.QueryCheckDisk;

    public static async Task<CommandResult> RunAsync(DiskOperation op, string letter, MediaKind media, CancellationToken ct, IProgress<string>? output = null)
    {
        var cmd = BuildCommand(op, letter, media, out var error);
        if (cmd is null) return new CommandResult(-1, error!, TimeSpan.Zero, false);
        var timeout = op is DiskOperation.Analyze or DiskOperation.QueryCheckDisk or DiskOperation.ScheduleCheckDisk ? TimeSpan.FromMinutes(10) : TimeSpan.FromHours(6);
        var result = await SystemCommand.RunAsync(cmd.Value.Exe, cmd.Value.Args, timeout, ct, output).ConfigureAwait(false);
        return Normalize(result);
    }

    /// <summary>
    /// defrag.exe 出错时（权限不足 0x89000024、卷无效 0x89000001、正在被别的优化任务使用 0x89000018 等）退出码仍是 0，
    /// 只在输出里印一个 (0x89xxxxxx) 错误码。按退出码判定会把"什么都没做"报成"完成"，这里把错误码提升为失败退出码。
    /// </summary>
    public static CommandResult Normalize(CommandResult result)
    {
        if (!result.Success) return result;
        var code = ParseDefragError(result.Output);
        return code is null ? result : result with { ExitCode = code.Value };
    }

    private static readonly Regex DefragErrorPattern = new(@"\(0x(89[0-9A-Fa-f]{6})\)", RegexOptions.Compiled);

    /// <summary>从 defrag 输出里取错误码（0x89 开头的存储优化器错误）；没有则为 null。</summary>
    public static int? ParseDefragError(string? output)
    {
        if (string.IsNullOrEmpty(output)) return null;
        var m = DefragErrorPattern.Match(output);
        return m.Success ? unchecked((int)Convert.ToUInt32(m.Groups[1].Value, 16)) : null;
    }

    /// <summary>把退出码翻译成用户能看懂的原因；未知码返回 null。</summary>
    public static string? DescribeExitCode(int exitCode) => unchecked((uint)exitCode) switch
    {
        0x89000024 => "权限不足：需要以管理员身份运行",
        0x89000001 => "卷路径无效",
        _ => null,
    };
}
