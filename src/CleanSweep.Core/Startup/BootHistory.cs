using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;

namespace CleanSweep.Core.Startup;

/// <summary>开机时间历史：Diagnostics-Performance 事件日志，事件 ID 100（设计文档 4.1）。</summary>
public static class BootHistory
{
    public const string LogName = "Microsoft-Windows-Diagnostics-Performance/Operational";

    public static IReadOnlyList<BootRecord> Read(int max = 30) => Read(max, out _);

    /// <summary>读取最近 max 次开机记录。读取失败时 error 给出原因（无权限 / 日志不存在）。</summary>
    public static IReadOnlyList<BootRecord> Read(int max, out string? error)
    {
        error = null;
        var list = new List<BootRecord>();
        try
        {
            var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=100)]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            EventRecord? e;
            while (list.Count < max && (e = reader.ReadEvent()) is not null)
            {
                using (e)
                {
                    var rec = ParseEvent(e.ToXml(), e.TimeCreated?.ToUniversalTime());
                    if (rec is not null) list.Add(rec);
                }
            }
            if (list.Count == 0) error = "事件日志中没有开机性能记录（事件 ID 100）。";
        }
        catch (EventLogNotFoundException)
        {
            error = "事件日志 Diagnostics-Performance 不存在。";
        }
        catch (UnauthorizedAccessException)
        {
            error = "读取事件日志需要管理员权限。";
        }
        catch (EventLogException ex)
        {
            error = ex.Message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("拒绝", StringComparison.Ordinal)
                ? "读取事件日志需要管理员权限。"
                : $"读取事件日志失败：{ex.Message}";
        }
        return list;
    }

    internal static BootRecord? ParseEvent(string xml, DateTime? timeUtc)
    {
        var doc = XDocument.Parse(xml);
        var data = doc.Descendants()
            .Where(x => x.Name.LocalName == "Data")
            .ToDictionary(x => (string?)x.Attribute("Name") ?? "", x => x.Value, StringComparer.OrdinalIgnoreCase);

        int Get(string name) =>
            data.TryGetValue(name, out var v) && int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : 0;

        var boot = Get("BootTime");
        if (boot <= 0) return null;

        var t = timeUtc;
        if (t is null)
        {
            var st = doc.Descendants().FirstOrDefault(x => x.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            if (st is not null && DateTime.TryParse(st, null, DateTimeStyles.RoundtripKind, out var dt)) t = dt.ToUniversalTime();
        }

        return new BootRecord(t ?? DateTime.MinValue, boot, Get("MainPathBootTime"), Get("BootPostBootTime"));
    }
}
