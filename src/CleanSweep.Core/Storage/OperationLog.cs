using Microsoft.Data.Sqlite;

namespace CleanSweep.Core.Storage;

public sealed record OperationRecord(
    long Id, DateTime TsUtc, string? BatchId, string ModuleId, string Action, string? Target, long SizeBytes, bool Success, string? Message);

public sealed record BatchRecord(
    string BatchId, DateTime StartedUtc, DateTime? FinishedUtc, string ModuleIds, int ItemCount, long FreedBytes);

/// <summary>操作日志（设计文档 6.1 第 8 条）：每个动作一条记录，批次用于识别半完成状态。</summary>
public sealed class OperationLog
{
    private readonly CleanSweepDb _db;

    public OperationLog(CleanSweepDb db)
    {
        _db = db;
    }

    /// <summary>批量模式：共享连接与事务，供清理引擎在一次批次内使用。</summary>
    public IDisposable BeginBulk() => _db.BeginBulk();

    public void BeginBatch(string batchId, IEnumerable<string> moduleIds, int itemCount)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "INSERT INTO batches(batch_id, started_at, module_ids, item_count) VALUES($b, $t, $m, $c)";
        cmd.Parameters.AddWithValue("$b", batchId);
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$m", string.Join(",", moduleIds.Distinct()));
        cmd.Parameters.AddWithValue("$c", itemCount);
        cmd.ExecuteNonQuery();
    }

    public void EndBatch(string batchId, long freedBytes)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "UPDATE batches SET finished_at=$t, freed_bytes=$f WHERE batch_id=$b";
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$f", freedBytes);
        cmd.Parameters.AddWithValue("$b", batchId);
        cmd.ExecuteNonQuery();
    }

    public void Write(string? batchId, string moduleId, string action, string? target, long sizeBytes, bool success, string? message = null)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            INSERT INTO operations(ts, batch_id, module_id, action, target, size_bytes, success, message)
            VALUES($ts, $b, $m, $a, $t, $s, $ok, $msg)
            """;
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$b", (object?)batchId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$m", moduleId);
        cmd.Parameters.AddWithValue("$a", action);
        cmd.Parameters.AddWithValue("$t", (object?)target ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", sizeBytes);
        cmd.Parameters.AddWithValue("$ok", success ? 1 : 0);
        cmd.Parameters.AddWithValue("$msg", (object?)message ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>未正常结束的批次，供启动时提示（设计文档 6.1 第 8 条）。</summary>
    public IReadOnlyList<BatchRecord> GetUnfinishedBatches()
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "SELECT batch_id, started_at, finished_at, module_ids, item_count, freed_bytes FROM batches WHERE finished_at IS NULL ORDER BY started_at DESC";
        return ReadBatches(cmd);
    }

    public IReadOnlyList<BatchRecord> GetRecentBatches(int limit = 50)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "SELECT batch_id, started_at, finished_at, module_ids, item_count, freed_bytes FROM batches ORDER BY started_at DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        return ReadBatches(cmd);
    }

    public IReadOnlyList<OperationRecord> GetOperations(string? batchId = null, int limit = 500)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = batchId is null
            ? "SELECT id, ts, batch_id, module_id, action, target, size_bytes, success, message FROM operations ORDER BY id DESC LIMIT $l"
            : "SELECT id, ts, batch_id, module_id, action, target, size_bytes, success, message FROM operations WHERE batch_id=$b ORDER BY id DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        if (batchId is not null) cmd.Parameters.AddWithValue("$b", batchId);

        var list = new List<OperationRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new OperationRecord(
                r.GetInt64(0),
                DateTime.Parse(r.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                r.IsDBNull(2) ? null : r.GetString(2),
                r.GetString(3),
                r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5),
                r.GetInt64(6),
                r.GetInt64(7) != 0,
                r.IsDBNull(8) ? null : r.GetString(8)));
        }
        return list;
    }

    private static List<BatchRecord> ReadBatches(SqliteCommand cmd)
    {
        var list = new List<BatchRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new BatchRecord(
                r.GetString(0),
                DateTime.Parse(r.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                r.IsDBNull(2) ? null : DateTime.Parse(r.GetString(2), null, System.Globalization.DateTimeStyles.RoundtripKind),
                r.GetString(3),
                (int)r.GetInt64(4),
                r.GetInt64(5)));
        }
        return list;
    }
}
