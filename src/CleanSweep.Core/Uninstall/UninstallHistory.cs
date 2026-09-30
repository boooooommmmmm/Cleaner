using System.Globalization;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Uninstall;

public sealed record UninstallRecord(long Id, DateTime TsUtc, string AppId, string Name, string? Publisher, string? InstallLocation, string Source, string DetectedBy);

/// <summary>
/// 已卸载应用的历史：由卸载事件监听或强力卸载写入。残留清理把"目录名匹配到最近卸载的应用"当作强证据
/// （设计文档 3.3.2 信号 A：昨天刚卸载的应用目录很新，但仍应判为确认残留）。
/// </summary>
public sealed class UninstallHistory
{
    private readonly CleanSweepDb _db;

    public UninstallHistory(CleanSweepDb db)
    {
        _db = db;
    }

    public void Record(InstalledApp app, string detectedBy)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            INSERT INTO uninstall_history(ts, app_id, name, publisher, install_location, source, detected_by)
            VALUES($ts, $id, $n, $p, $l, $s, $d)
            """;
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$id", app.Id);
        cmd.Parameters.AddWithValue("$n", app.Name);
        cmd.Parameters.AddWithValue("$p", (object?)app.Publisher ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$l", (object?)app.InstallLocation ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", app.Source.ToString());
        cmd.Parameters.AddWithValue("$d", detectedBy);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<UninstallRecord> List(int limit = 200)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "SELECT id, ts, app_id, name, publisher, install_location, source, detected_by FROM uninstall_history ORDER BY id DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        var list = new List<UninstallRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new UninstallRecord(
                r.GetInt64(0),
                DateTime.Parse(r.GetString(1), null, DateTimeStyles.RoundtripKind),
                r.GetString(2), r.GetString(3),
                r.IsDBNull(4) ? null : r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5),
                r.GetString(6), r.GetString(7)));
        }
        return list;
    }

    /// <summary>名字与某条卸载记录匹配（归一化前缀匹配）则返回该记录。</summary>
    public UninstallRecord? FindByName(string? name, IReadOnlyList<UninstallRecord>? cache = null)
    {
        var key = NameKey.Normalize(name);
        if (key.Length < 3) return null;
        foreach (var rec in cache ?? List())
        {
            if (NameKey.Matches(rec.Name, name)) return rec;
        }
        return null;
    }

    public int PurgeOlderThan(int days)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "DELETE FROM uninstall_history WHERE ts < $c";
        cmd.Parameters.AddWithValue("$c", DateTime.UtcNow.AddDays(-days).ToString("O"));
        return cmd.ExecuteNonQuery();
    }
}
