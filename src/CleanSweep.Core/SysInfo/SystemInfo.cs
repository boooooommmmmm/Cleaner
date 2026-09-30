using System.Management;
using CleanSweep.Core.Backup;
using Microsoft.Win32;

namespace CleanSweep.Core.SysInfo;

public sealed record InfoItem(string Group, string Name, string Value);

/// <summary>系统信息与硬件检测面板（设计文档 5.5）。全部只读。</summary>
public static class SystemInfo
{
    public static IReadOnlyList<InfoItem> Collect()
    {
        var items = new List<InfoItem>();
        void Add(string g, string n, string? v) { if (!string.IsNullOrWhiteSpace(v)) items.Add(new InfoItem(g, n, v.Trim())); }

        // 系统
        try
        {
            using var k = RegistryPath.Open(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", RegistryView.Registry64, writable: false);
            var product = k?.GetValue("ProductName") as string;
            var display = k?.GetValue("DisplayVersion") as string ?? k?.GetValue("ReleaseId") as string;
            var build = k?.GetValue("CurrentBuild") as string;
            var ubr = k?.GetValue("UBR") as int?;
            // Windows 11 的 ProductName 仍写 Windows 10，按内部版本号纠正
            if (product is not null && int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
            Add("系统", "Windows 版本", $"{product} {display}（内部版本 {build}.{ubr}）");
            if (k?.GetValue("InstallDate") is int installEpoch) Add("系统", "安装日期", DateTimeOffset.FromUnixTimeSeconds(installEpoch).ToLocalTime().ToString("yyyy-MM-dd"));
            Add("系统", "注册用户", k?.GetValue("RegisteredOwner") as string);
        }
        catch { }
        Add("系统", "计算机名", System.Environment.MachineName);
        Add("系统", "当前用户", System.Environment.UserName);
        Add("系统", "已运行", FormatUptime(TimeSpan.FromMilliseconds(System.Environment.TickCount64)));
        Add("系统", "系统目录", System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows));
        Add("系统", ".NET 运行时", System.Environment.Version.ToString());
        Add("系统", "体系结构", System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString());

        Wmi("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, L2CacheSize, L3CacheSize FROM Win32_Processor", o =>
        {
            Add("处理器", "型号", o["Name"]?.ToString());
            Add("处理器", "核心 / 线程", $"{o["NumberOfCores"]} / {o["NumberOfLogicalProcessors"]}");
            Add("处理器", "最高频率", $"{o["MaxClockSpeed"]} MHz");
            Add("处理器", "L2 / L3 缓存", $"{o["L2CacheSize"]} KB / {o["L3CacheSize"]} KB");
        });
        Wmi("SELECT Manufacturer, Product, Version FROM Win32_BaseBoard", o => Add("主板", "型号", $"{o["Manufacturer"]} {o["Product"]} {o["Version"]}"));
        Wmi("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS", o => Add("主板", "BIOS", $"{o["Manufacturer"]} {o["SMBIOSBIOSVersion"]}（{WmiDate(o["ReleaseDate"]?.ToString())}）"));

        long totalMem = 0;
        var sticks = new List<string>();
        Wmi("SELECT Capacity, Speed, Manufacturer, PartNumber, DeviceLocator FROM Win32_PhysicalMemory", o =>
        {
            var cap = Convert.ToInt64(o["Capacity"] ?? 0L);
            totalMem += cap;
            sticks.Add($"{o["DeviceLocator"]}: {cap / (1024.0 * 1024 * 1024):0.#} GB {o["Speed"]} MT/s {o["Manufacturer"]} {o["PartNumber"]?.ToString()?.Trim()}");
        });
        if (totalMem > 0) Add("内存", "总容量", $"{totalMem / (1024.0 * 1024 * 1024):0.#} GB（{sticks.Count} 条）");
        foreach (var s in sticks) Add("内存", "内存条", s);

        Wmi("SELECT Name, AdapterRAM, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate FROM Win32_VideoController", o =>
        {
            var ram = Convert.ToInt64(o["AdapterRAM"] ?? 0L);
            Add("显卡", o["Name"]?.ToString() ?? "显卡", $"{(ram > 0 ? $"{ram / (1024.0 * 1024 * 1024):0.#} GB 显存，" : "")}驱动 {o["DriverVersion"]}" +
                (o["CurrentHorizontalResolution"] is not null ? $"，{o["CurrentHorizontalResolution"]}×{o["CurrentVerticalResolution"]} @ {o["CurrentRefreshRate"]} Hz" : ""));
        });

        foreach (var d in Disk.DiskHealth.GetPhysicalDisks())
            Add("存储", d.FriendlyName, $"{d.SizeBytes / (1024.0 * 1024 * 1024):0.#} GB · {d.Media switch { Disk.MediaKind.Ssd => "固态盘", Disk.MediaKind.Hdd => "机械盘", _ => "未知" }} · {d.BusType} · {d.HealthStatus}");

        Wmi("SELECT Name, MACAddress, Speed, NetConnectionID FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE AND PhysicalAdapter = TRUE", o =>
        {
            var speed = Convert.ToInt64(o["Speed"] ?? 0L);
            Add("网络", o["NetConnectionID"]?.ToString() ?? "网卡", $"{o["Name"]}，{o["MACAddress"]}{(speed > 0 ? $"，{speed / 1_000_000} Mbps" : "")}");
        });
        Wmi("SELECT Name, Manufacturer, Status FROM Win32_SoundDevice", o => Add("声卡", o["Name"]?.ToString() ?? "声卡", $"{o["Manufacturer"]}，{o["Status"]}"));
        Wmi("SELECT Name, EstimatedChargeRemaining, BatteryStatus, DesignVoltage FROM Win32_Battery", o =>
            Add("电池", o["Name"]?.ToString() ?? "电池", $"电量 {o["EstimatedChargeRemaining"]}%，状态码 {o["BatteryStatus"]}"));

        return items;
    }

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

    private static string WmiDate(string? s)
    {
        if (s is null || s.Length < 8) return "";
        return $"{s[..4]}-{s[4..6]}-{s[6..8]}";
    }

    private static string FormatUptime(TimeSpan t) => t.TotalDays >= 1 ? $"{(int)t.TotalDays} 天 {t.Hours} 小时 {t.Minutes} 分" : $"{t.Hours} 小时 {t.Minutes} 分";
}
