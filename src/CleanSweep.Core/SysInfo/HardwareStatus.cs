using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.SysInfo;

/// <summary>一条硬件状态读数。<see cref="Percent"/> 有值时界面画进度条；<see cref="Warning"/> 为真时标红。</summary>
public sealed record HardwareReading(string Group, string Name, string Value, double? Percent = null, bool Warning = false);

public sealed record HardwareSnapshot(IReadOnlyList<HardwareReading> Readings, DateTime TakenUtc, IReadOnlyList<string> Notes);

/// <summary>
/// 硬件状态（设计文档 5.5 扩展）：只用 Windows 公开接口与系统自带工具读取，不装内核驱动、不读 SMBus / EC。
/// 因此 CPU 核心温度与机箱风扇转速在多数台式机上读不到，界面明确说"未提供"而不是猜。
/// 每次 <see cref="Collect"/> 都是一次只读采样；CPU 占用按两次采样之间的系统时间差计算。
/// </summary>
public static class HardwareStatus
{
    public const string GroupCpu = "处理器";
    public const string GroupMemory = "内存";
    public const string GroupThermal = "温度与风扇";
    public const string GroupGpu = "显卡";
    public const string GroupStorage = "存储";
    public const string GroupPower = "电源";

    private static readonly object Gate = new();
    private static (ulong Idle, ulong Kernel, ulong User)? _lastCpu;

    /// <summary>处理器型号 / 核心数 / 标称频率不会变，进程内只查一次 WMI。</summary>
    private static readonly Lazy<(string Name, string Cores, int? MaxMhz)> CpuInfo = new(() =>
    {
        string name = "", cores = "";
        int? max = null;
        Wmi("SELECT Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", o =>
        {
            if (name.Length > 0) return;
            name = o["Name"]?.ToString()?.Trim() ?? "";
            cores = $"{o["NumberOfCores"]} / {o["NumberOfLogicalProcessors"]}";
            max = ToInt(o["MaxClockSpeed"]);
        });
        return (name, cores, max);
    });

    /// <summary>ACPI 温区查询在这台机器上明确"不支持"后不再每次重试（WMI 抛异常较慢）。</summary>
    private static volatile bool _thermalUnsupported;

    /// <summary>Win32_Fan 第一次查询为空后不再重试。</summary>
    private static volatile bool _noFans;

    /// <param name="includeStorage">是否读取磁盘 S.M.A.R.T.（WMI 查询较慢，自动刷新时可隔几次读一次）。</param>
    public static HardwareSnapshot Collect(bool includeStorage = true)
    {
        var items = new List<HardwareReading>();
        var notes = new List<string>();
        void Add(string g, string n, string v, double? pct = null, bool warn = false) => items.Add(new HardwareReading(g, n, v, pct, warn));

        // 处理器：型号等静态信息缓存；占用率按两次采样的系统时间差算。Win32_Processor.CurrentClockSpeed 在多数机器上
        // 固定等于标称值，不当"当前频率"展示，以免误导
        var info = CpuInfo.Value;
        if (info.Name.Length > 0) Add(GroupCpu, "型号", info.Name);
        var cpu = CpuUsagePercent();
        Add(GroupCpu, "占用率", cpu is { } c ? $"{c:0}%" : "采样中…", cpu, cpu >= 95);
        if (info.Cores.Length > 0) Add(GroupCpu, "核心 / 线程", info.Cores + (info.MaxMhz is { } mm && mm > 0 ? $" · 标称 {mm} MHz" : ""));

        // 内存
        if (TryMemory(out var mem))
        {
            var used = mem.Total - mem.Available;
            var pct = mem.Total > 0 ? used * 100.0 / mem.Total : 0;
            Add(GroupMemory, "物理内存", $"已用 {Gb(used)} / {Gb(mem.Total)} GB（{pct:0}%）", pct, pct >= 90);
            var commitUsed = mem.CommitLimit - mem.CommitAvailable;
            var cpct = mem.CommitLimit > 0 ? commitUsed * 100.0 / mem.CommitLimit : 0;
            Add(GroupMemory, "已提交（含页面文件）", $"{Gb(commitUsed)} / {Gb(mem.CommitLimit)} GB", cpct, cpct >= 90);
        }
        var diag = CachedMemoryDiagnostic();
        Add(GroupMemory, "上次内存诊断", diag ?? "没有找到 Windows 内存诊断的结果记录。可在下方“系统工具”中运行内存诊断（需要重启）。", warn: diag is not null && diag.Contains("错误"));

        // 温度与风扇：ACPI 温区（部分机器、多数需要管理员）；Win32_Fan 只有极少数主板上报
        int zones = 0;
        string? thermalError = null;
        if (_thermalUnsupported) thermalError = "Not supported";
        else try
        {
            using var searcher = new ManagementObjectSearcher(@"root\wmi", "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
            foreach (ManagementObject o in searcher.Get())
            {
                try
                {
                    var tenthsKelvin = Convert.ToDouble(o["CurrentTemperature"]);
                    var celsius = tenthsKelvin / 10.0 - 273.15;
                    if (celsius is < -40 or > 150) continue;
                    var name = ZoneName(o["InstanceName"]?.ToString());
                    Add(GroupThermal, $"温区 {name}", $"{celsius:0.#} °C", null, celsius >= 90);
                    zones++;
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            thermalError = ex.Message;
            if (thermalError.Contains("Not supported", StringComparison.OrdinalIgnoreCase)) _thermalUnsupported = true;
        }
        if (zones == 0)
        {
            Add(GroupThermal, "ACPI 温区", thermalError is null || thermalError.Contains("Not supported", StringComparison.OrdinalIgnoreCase)
                ? "主板未通过 ACPI 提供温度读数（WMI 报告不支持；不少台式机主板没有这个接口）。"
                : "读取失败（可能需要管理员权限）：" + thermalError);
        }
        int fans = 0;
        if (!_noFans)
        {
            Wmi("SELECT Name, DesiredSpeed, Status, ActiveCooling FROM Win32_Fan", o =>
            {
                var speed = ToLong(o["DesiredSpeed"]);
                Add(GroupThermal, o["Name"]?.ToString() ?? "风扇", speed is { } s && s > 0 ? $"{s} RPM · {o["Status"]}" : $"{o["Status"]}");
                fans++;
            });
            if (fans == 0) _noFans = true;
        }
        if (fans == 0) Add(GroupThermal, "风扇转速", "主板未通过标准接口上报。CPU 核心温度与风扇转速需要读取 SMBus / EC 的内核驱动，本程序不安装驱动，请使用主板或笔记本厂商工具查看。");

        // 显卡：NVIDIA 驱动自带的 nvidia-smi（System32）只读查询；其他厂商只列型号
        var gpus = NvidiaSmi();
        if (gpus.Count > 0)
        {
            foreach (var g in gpus)
            {
                Add(GroupGpu, g.Name, $"{(g.Utilization is { } u ? $"占用 {u}%" : "占用 —")}" +
                                     $"{(g.TemperatureC is { } t ? $" · {t} °C" : "")}" +
                                     $"{(g.MemoryUsedMb is { } mu && g.MemoryTotalMb is { } mt ? $" · 显存 {mu / 1024.0:0.#} / {mt / 1024.0:0.#} GB" : "")}" +
                                     $"{(g.FanPercent is { } f ? $" · 风扇 {f}%" : "")}" +
                                     $"{(g.PowerW is { } p ? $" · {p:0} W" : "")}",
                    g.Utilization, g.TemperatureC >= 90);
            }
        }
        else
        {
            Wmi("SELECT Name, DriverVersion FROM Win32_VideoController", o =>
                Add(GroupGpu, o["Name"]?.ToString() ?? "显卡", $"驱动 {o["DriverVersion"]}。占用与温度：NVIDIA 显卡在驱动自带 nvidia-smi 可用时显示；其他厂商请用其控制面板查看。"));
        }

        // 存储：复用磁盘健康页的 S.M.A.R.T. 读取
        if (includeStorage)
        {
            try
            {
                var disks = DiskHealth.GetPhysicalDisks();
                var smart = DiskHealth.GetSmart(disks);
                foreach (var d in disks)
                {
                    var s = smart.FirstOrDefault(x => x.DiskNumber == d.Number);
                    var parts = new List<string> { d.Media switch { MediaKind.Ssd => "固态盘", MediaKind.Hdd => "机械盘", _ => "未知介质" }, d.HealthStatus };
                    if (s?.PredictFailure is { } p) parts.Add(p ? "S.M.A.R.T. 预测故障！" : "S.M.A.R.T. 正常");
                    if (s?.TemperatureCelsius is { } t) parts.Add($"{t} °C");
                    if (s?.WearPercent is { } w) parts.Add($"磨损 {w}%");
                    if (s?.PowerOnHours is { } h) parts.Add($"通电 {h} 小时");
                    var warn = s?.PredictFailure == true || d.HealthStatus != "健康" || (s?.TemperatureCelsius ?? 0) >= 70;
                    Add(GroupStorage, d.FriendlyName, string.Join(" · ", parts), null, warn);
                    if (s?.Note is { } note && !notes.Contains(note)) notes.Add(note);
                }
            }
            catch (Exception ex)
            {
                Add(GroupStorage, "磁盘", "读取失败：" + ex.Message, warn: true);
            }
        }

        // 电源
        if (TryPower(out var power))
        {
            if (power.HasBattery)
            {
                var pct = power.BatteryPercent;
                var v = $"{(pct is { } bp ? $"{bp}%" : "电量未知")} · {(power.OnAc ? "已接电源" : "使用电池")}" +
                        (power.RemainingSeconds is { } sec && !power.OnAc ? $" · 剩余约 {TimeSpan.FromSeconds(sec).TotalHours:0.#} 小时" : "") +
                        (power.Charging ? " · 充电中" : "");
                Add(GroupPower, "电池", v, pct, pct is < 15 && !power.OnAc);
            }
            else
            {
                Add(GroupPower, "电源", "台式机 / 无电池，已接电源");
            }
        }

        return new HardwareSnapshot(items, DateTime.UtcNow, notes);
    }

    /// <summary>
    /// 重新取一次 CPU 采样基线（页面重新进入时调用，避免用很久以前的一次采样算平均）。
    /// 只读系统时间，不做其他采集；随后的 <see cref="Collect"/> 就能直接给出占用率。
    /// </summary>
    public static void ResetCpuSample()
    {
        lock (Gate)
        {
            _lastCpu = GetSystemTimes(out var idle, out var kernel, out var user) ? (ToUlong(idle), ToUlong(kernel), ToUlong(user)) : null;
        }
    }

    // ---------------- CPU ----------------

    private static double? CpuUsagePercent()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
        var now = (ToUlong(idle), ToUlong(kernel), ToUlong(user));
        lock (Gate)
        {
            var last = _lastCpu;
            _lastCpu = now;
            if (last is null) return null;
            var idleDelta = now.Item1 - last.Value.Idle;
            var total = (now.Item2 - last.Value.Kernel) + (now.Item3 - last.Value.User); // kernel 已含 idle
            if (total == 0) return null;
            var busy = 100.0 * (total - idleDelta) / total;
            return Math.Clamp(busy, 0, 100);
        }
    }

    private static ulong ToUlong(System.Runtime.InteropServices.ComTypes.FILETIME ft) => ((ulong)(uint)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out System.Runtime.InteropServices.ComTypes.FILETIME idle, out System.Runtime.InteropServices.ComTypes.FILETIME kernel, out System.Runtime.InteropServices.ComTypes.FILETIME user);

    // ---------------- 内存 ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

    private static bool TryMemory(out (long Total, long Available, long CommitLimit, long CommitAvailable) mem)
    {
        var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (!GlobalMemoryStatusEx(ref m))
        {
            mem = default;
            return false;
        }
        mem = ((long)m.ullTotalPhys, (long)m.ullAvailPhys, (long)m.ullTotalPageFile, (long)m.ullAvailPageFile);
        return true;
    }

    private static string Gb(long bytes) => (bytes / (1024.0 * 1024 * 1024)).ToString("0.#", CultureInfo.InvariantCulture);

    private static (DateTime AtUtc, string? Text) _diagCache;

    /// <summary>事件日志查询每次几十毫秒，自动刷新时没必要 2 秒读一次：结果缓存 60 秒。</summary>
    private static string? CachedMemoryDiagnostic()
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _diagCache.AtUtc < TimeSpan.FromSeconds(60)) return _diagCache.Text;
        }
        var text = LastMemoryDiagnostic();
        lock (Gate) _diagCache = (DateTime.UtcNow, text);
        return text;
    }

    /// <summary>系统日志里 Windows 内存诊断（mdsched）最近一次的结果：事件 1201 无错误、1202 检测到错误。</summary>
    public static string? LastMemoryDiagnostic()
    {
        try
        {
            var query = new EventLogQuery("System", PathType.LogName,
                "*[System[Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results'] and (EventID=1201 or EventID=1202)]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var ev = reader.ReadEvent();
            if (ev is null) return null;
            var when = ev.TimeCreated?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "";
            return ev.Id == 1202 ? $"{when}：检测到内存错误！建议更换内存条或逐条排查。" : $"{when}：未检测到错误。";
        }
        catch
        {
            return null;
        }
    }

    // ---------------- 温度 ----------------

    /// <summary>InstanceName 形如 "ACPI\ThermalZone\TZ00_0"，只留最后一段。</summary>
    internal static string ZoneName(string? instance)
    {
        if (string.IsNullOrWhiteSpace(instance)) return "?";
        var last = instance.Split('\\')[^1];
        var us = last.LastIndexOf('_');
        if (us > 0 && last[(us + 1)..].All(char.IsDigit)) last = last[..us];
        return last;
    }

    // ---------------- 显卡 ----------------

    public sealed record GpuReading(string Name, int? TemperatureC, double? Utilization, long? MemoryUsedMb, long? MemoryTotalMb, int? FanPercent, double? PowerW);

    private const string NvidiaSmiArgs = "--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,fan.speed,power.draw --format=csv,noheader,nounits";

    private static IReadOnlyList<GpuReading> NvidiaSmi()
    {
        try
        {
            if (!File.Exists(SystemCommand.System32("nvidia-smi.exe"))) return Array.Empty<GpuReading>();
            var r = SystemCommand.RunAsync("nvidia-smi.exe", NvidiaSmiArgs, TimeSpan.FromSeconds(8)).GetAwaiter().GetResult();
            return r.Success ? ParseNvidiaSmi(r.Output) : Array.Empty<GpuReading>();
        }
        catch
        {
            return Array.Empty<GpuReading>();
        }
    }

    /// <summary>解析 nvidia-smi 的 csv,noheader,nounits 输出；"[N/A]"、"[Not Supported]" 等按空处理。</summary>
    public static IReadOnlyList<GpuReading> ParseNvidiaSmi(string output)
    {
        var list = new List<GpuReading>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var f = line.Split(',').Select(x => x.Trim()).ToArray();
            if (f.Length < 2 || f[0].Length == 0) continue;
            list.Add(new GpuReading(
                f[0],
                Int(f, 1),
                Dbl(f, 2),
                Lng(f, 3),
                Lng(f, 4),
                Int(f, 5),
                Dbl(f, 6)));
        }
        return list;

        static string? Field(string[] f, int i) => i < f.Length && !f[i].StartsWith('[') && f[i].Length > 0 ? f[i] : null;
        static int? Int(string[] f, int i) => Field(f, i) is { } s && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? (int)Math.Round(v) : null;
        static long? Lng(string[] f, int i) => Field(f, i) is { } s && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? (long)Math.Round(v) : null;
        static double? Dbl(string[] f, int i) => Field(f, i) is { } s && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    // ---------------- 电源 ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

    private static bool TryPower(out (bool HasBattery, bool OnAc, bool Charging, int? BatteryPercent, int? RemainingSeconds) power)
    {
        if (!GetSystemPowerStatus(out var s))
        {
            power = default;
            return false;
        }
        var hasBattery = s.BatteryFlag != 128 && s.BatteryFlag != 255;
        power = (hasBattery, s.ACLineStatus == 1, (s.BatteryFlag & 8) != 0,
            s.BatteryLifePercent == 255 ? null : s.BatteryLifePercent,
            s.BatteryLifeTime < 0 ? null : s.BatteryLifeTime);
        return true;
    }

    // ---------------- 工具 ----------------

    private static void Wmi(string query, Action<ManagementObject> each)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject o in searcher.Get())
            {
                try { each(o); } catch { }
            }
        }
        catch { }
    }

    private static int? ToInt(object? o) => o is null ? null : Convert.ToInt32(o);
    private static long? ToLong(object? o) => o is null ? null : Convert.ToInt64(o);
}
