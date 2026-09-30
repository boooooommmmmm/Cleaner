using Microsoft.Data.Sqlite;

namespace CleanSweep.Core.Storage;

/// <summary>
/// SQLite 数据库：隔离区索引与操作日志。
/// 支持"批量模式"：清理引擎在一次批次内共享一个连接与事务，每 <see cref="BulkCommitEvery"/> 次操作提交一次，
/// 既避免每个文件一次 fsync 的开销，又保证进程崩溃时最多丢失最近几百条索引。
/// </summary>
public sealed class CleanSweepDb : IDisposable
{
    public const int BulkCommitEvery = 500;

    private readonly string _connectionString;
    private readonly SqliteConnection? _keepAlive;
    private readonly object _lock = new();

    private SqliteConnection? _bulkConn;
    private SqliteTransaction? _bulkTx;
    private int _bulkDepth;
    private int _leaseDepth;
    private int _bulkOps;

    public CleanSweepDb(string dbPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = true }.ToString();
        EnsureSchema(fileBacked: true);
    }

    /// <summary>测试用的内存数据库。</summary>
    public static CleanSweepDb InMemory()
    {
        // 每个实例独立命名，避免并行测试之间共享同一个内存库
        return new CleanSweepDb("memdb-" + Guid.NewGuid().ToString("N"), keepAlive: true);
    }

    private CleanSweepDb(string dataSource, bool keepAlive)
    {
        _connectionString = new SqliteConnectionStringBuilder { DataSource = dataSource, Mode = SqliteOpenMode.Memory, Cache = SqliteCacheMode.Shared }.ToString();
        if (keepAlive)
        {
            _keepAlive = new SqliteConnection(_connectionString);
            _keepAlive.Open();
        }
        EnsureSchema(fileBacked: false);
    }

    /// <summary>一次数据库使用的租约。批量模式下复用共享连接并串行化访问；否则独占一个新连接。</summary>
    public sealed class Lease : IDisposable
    {
        private readonly CleanSweepDb _db;
        private readonly bool _owns;
        private bool _disposed;

        internal Lease(CleanSweepDb db, SqliteConnection connection, SqliteTransaction? transaction, bool owns)
        {
            _db = db;
            Connection = connection;
            Transaction = transaction;
            _owns = owns;
        }

        public SqliteConnection Connection { get; }
        public SqliteTransaction? Transaction { get; }

        public SqliteCommand CreateCommand()
        {
            var cmd = Connection.CreateCommand();
            cmd.Transaction = Transaction;
            return cmd;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_owns)
            {
                Connection.Dispose();
                return;
            }
            _db.ReleaseBulkLease();
        }
    }

    public Lease Open()
    {
        // 锁顺序：先连接监视器，后 _lock。ReleaseBulkLease 在持有监视器时取 _lock，这里必须保持同一顺序，否则死锁。
        while (true)
        {
            SqliteConnection? bulk;
            lock (_lock) bulk = _bulkConn;
            if (bulk is null) break;

            Monitor.Enter(bulk);
            lock (_lock)
            {
                if (ReferenceEquals(_bulkConn, bulk))
                {
                    _leaseDepth++;
                    return new Lease(this, bulk, _bulkTx, owns: false);
                }
            }
            // 批量模式在等待期间已结束，放弃并重试
            Monitor.Exit(bulk);
        }

        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return new Lease(this, conn, null, owns: true);
    }

    /// <summary>进入批量模式。可嵌套；最外层释放时提交。</summary>
    public IDisposable BeginBulk()
    {
        lock (_lock)
        {
            if (_bulkDepth++ == 0)
            {
                _bulkConn = new SqliteConnection(_connectionString);
                _bulkConn.Open();
                _bulkTx = _bulkConn.BeginTransaction();
                _bulkOps = 0;
            }
        }
        return new BulkScope(this);
    }

    private void ReleaseBulkLease()
    {
        var conn = _bulkConn;
        if (conn is null) return;

        bool commitNow = false;
        lock (_lock)
        {
            _leaseDepth--;
            _bulkOps++;
            if (_leaseDepth == 0 && _bulkOps >= BulkCommitEvery) commitNow = true;
        }

        if (commitNow) CommitAndRestart();
        Monitor.Exit(conn);
    }

    private void CommitAndRestart()
    {
        lock (_lock)
        {
            if (_bulkConn is null || _bulkTx is null) return;
            _bulkTx.Commit();
            _bulkTx.Dispose();
            _bulkTx = _bulkConn.BeginTransaction();
            _bulkOps = 0;
        }
    }

    private void EndBulk()
    {
        SqliteConnection? conn;
        lock (_lock)
        {
            if (--_bulkDepth > 0) return;
            conn = _bulkConn;
        }
        if (conn is null) return;

        // 等待其他线程的租约结束后再提交并关闭（锁顺序同 Open：先监视器，后 _lock）
        Monitor.Enter(conn);
        try
        {
            lock (_lock)
            {
                try
                {
                    _bulkTx?.Commit();
                }
                finally
                {
                    _bulkTx?.Dispose();
                    _bulkTx = null;
                    _bulkConn = null;
                    _leaseDepth = 0;
                    _bulkOps = 0;
                }
            }
        }
        finally
        {
            Monitor.Exit(conn);
            conn.Dispose();
        }
    }

    private sealed class BulkScope : IDisposable
    {
        private CleanSweepDb? _db;
        public BulkScope(CleanSweepDb db) => _db = db;

        public void Dispose()
        {
            var db = Interlocked.Exchange(ref _db, null);
            db?.EndBulk();
        }
    }

    private void EnsureSchema(bool fileBacked)
    {
        using var lease = Open();
        using var cmd = lease.CreateCommand();
        if (fileBacked)
        {
            // WAL：读写不互斥；synchronous=NORMAL：提交不强制 fsync，仅检查点时同步，进程崩溃不丢数据
            cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
            cmd.ExecuteNonQuery();
        }

        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS quarantine_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                is_directory INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                quarantined_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                restored_at TEXT NULL,
                purged_at TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_quarantine_active ON quarantine_items(restored_at, purged_at);

            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                batch_id TEXT NULL,
                module_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NULL,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL,
                message TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_operations_ts ON operations(ts);

            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT NULL,
                module_ids TEXT NOT NULL,
                item_count INTEGER NOT NULL,
                freed_bytes INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS registry_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                key_path TEXT NOT NULL,
                view INTEGER NOT NULL DEFAULT 64,
                file TEXT NOT NULL,
                reason TEXT NOT NULL,
                restored_at TEXT NULL,
                sha256 TEXT NULL,
                value_name TEXT NULL
            );
            """;
        cmd.ExecuteNonQuery();

        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS uninstall_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                app_id TEXT NOT NULL,
                name TEXT NOT NULL,
                publisher TEXT NULL,
                install_location TEXT NULL,
                source TEXT NOT NULL,
                detected_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_uninstall_history_ts ON uninstall_history(ts);
            """;
        cmd.ExecuteNonQuery();

        // 旧库升级：缺少的列逐个补上
        EnsureColumn(lease, "registry_backups", "sha256", "TEXT NULL");
        EnsureColumn(lease, "registry_backups", "value_name", "TEXT NULL");
        EnsureColumn(lease, "quarantine_items", "owner_sid", "TEXT NULL");
    }

    private static void EnsureColumn(Lease lease, string table, string column, string ddl)
    {
        using var check = lease.CreateCommand();
        check.CommandText = $"PRAGMA table_info({table})";
        using (var r = check.ExecuteReader())
        {
            while (r.Read())
            {
                if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return;
            }
        }
        using var alter = lease.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {ddl}";
        alter.ExecuteNonQuery();
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _bulkTx?.Dispose();
            _bulkConn?.Dispose();
            _bulkTx = null;
            _bulkConn = null;
        }
        _keepAlive?.Dispose();
    }
}
