using System.Globalization;
using System.Xml.Linq;

namespace CleanSweep.Core.Startup;

public sealed record ProcessStartupSample(string Name, string? CommandLine, double CpuMs, long DiskBytes);

public sealed record ImpactStats(double CpuMs, long DiskBytes, int Boots);

/// <summary>
/// 启动耗时数据源：%LocalAppData%\Microsoft\Windows\StartupInfo\*.xml（任务管理器同源，每次开机一个文件）。
/// 评级阈值与任务管理器一致：CPU 大于 1 秒或磁盘大于 3 MB 为"高"，CPU 大于 300 毫秒或磁盘大于 300 KB 为"中"。
/// </summary>
public static class StartupInfoParser
{
    public static string DefaultDirectory(string localAppData) =>
        Path.Combine(localAppData, "Microsoft", "Windows", "StartupInfo");

    public static IReadOnlyList<ProcessStartupSample> Parse(string xml) => Parse(XDocument.Parse(xml));

    public static IReadOnlyList<ProcessStartupSample> Parse(XDocument doc)
    {
        var list = new List<ProcessStartupSample>();
        foreach (var p in doc.Descendants("Process"))
        {
            var name = (string?)p.Attribute("Name") ?? "";
            var cmd = (string?)p.Element("CommandLine");

            double cpuMs = 0;
            var cpu = p.Element("CpuUsage");
            if (cpu is not null && double.TryParse(cpu.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var cpuRaw))
            {
                var units = (string?)cpu.Attribute("units") ?? "us";
                cpuMs = units.ToLowerInvariant() switch
                {
                    "us" => cpuRaw / 1000.0,
                    "ms" => cpuRaw,
                    "ns" => cpuRaw / 1_000_000.0,
                    "s" => cpuRaw * 1000.0,
                    _ => cpuRaw / 1000.0,
                };
            }

            long disk = 0;
            var d = p.Element("DiskUsage");
            if (d is not null && long.TryParse(d.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var diskRaw))
            {
                var units = (string?)d.Attribute("units") ?? "bytes";
                disk = units.ToLowerInvariant() switch
                {
                    "kb" => diskRaw * 1024,
                    "mb" => diskRaw * 1024 * 1024,
                    _ => diskRaw,
                };
            }

            list.Add(new ProcessStartupSample(name, cmd, cpuMs, disk));
        }
        return list;
    }

    /// <summary>读取目录里最近的 maxFiles 次开机记录，解析失败的文件跳过。</summary>
    public static IReadOnlyList<IReadOnlyList<ProcessStartupSample>> LoadDirectory(string dir, int maxFiles = 10)
    {
        var boots = new List<IReadOnlyList<ProcessStartupSample>>();
        if (!Directory.Exists(dir)) return boots;

        var files = new DirectoryInfo(dir).EnumerateFiles("*.xml")
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(maxFiles);
        foreach (var f in files)
        {
            try
            {
                boots.Add(Parse(XDocument.Load(f.FullName)));
            }
            catch
            {
                // 单个文件损坏不影响其余
            }
        }
        return boots;
    }

    /// <summary>汇总多次开机：同一次开机内同一可执行文件的多个进程求和，再跨开机取平均。键为小写可执行文件路径。</summary>
    public static Dictionary<string, ImpactStats> Aggregate(
        IEnumerable<IReadOnlyList<ProcessStartupSample>> boots, Func<string, bool>? fileExists = null)
    {
        fileExists ??= _ => true;
        var sums = new Dictionary<string, (double cpu, long disk, int boots)>(StringComparer.OrdinalIgnoreCase);

        foreach (var boot in boots)
        {
            var perBoot = new Dictionary<string, (double cpu, long disk)>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in boot)
            {
                var key = KeyFor(s, fileExists);
                perBoot.TryGetValue(key, out var acc);
                perBoot[key] = (acc.cpu + s.CpuMs, acc.disk + s.DiskBytes);
            }
            foreach (var (key, v) in perBoot)
            {
                sums.TryGetValue(key, out var acc);
                sums[key] = (acc.cpu + v.cpu, acc.disk + v.disk, acc.boots + 1);
            }
        }

        return sums.ToDictionary(
            kv => kv.Key,
            kv => new ImpactStats(kv.Value.cpu / kv.Value.boots, kv.Value.disk / kv.Value.boots, kv.Value.boots),
            StringComparer.OrdinalIgnoreCase);
    }

    private static string KeyFor(ProcessStartupSample s, Func<string, bool> fileExists)
    {
        var (exe, _) = CommandLine.Split(s.CommandLine, fileExists);
        var key = exe ?? s.Name;
        return key.Trim().ToLowerInvariant();
    }

    public static StartupImpact Rate(double cpuMs, long diskBytes)
    {
        if (cpuMs > 1000 || diskBytes > 3L * 1024 * 1024) return StartupImpact.High;
        if (cpuMs > 300 || diskBytes > 300L * 1024) return StartupImpact.Medium;
        return StartupImpact.Low;
    }
}
