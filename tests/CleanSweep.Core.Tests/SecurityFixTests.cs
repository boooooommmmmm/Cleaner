using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using Microsoft.Data.Sqlite;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 2026-09-28 安全审查（docs/archive/安全审查-2026-09-28.md）的回归基线：审查用例反转为"必须安全"的断言。
/// Junction 创建失败一律断言失败，不允许静默跳过。
/// </summary>
public sealed class SecurityFixTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private string QRoot => Path.Combine(_t.Root, "Q");
    private Quarantine Q => new(_db, null, _ => QRoot);
    private CleanEngine Engine(Whitelist? wl = null) => new(_t.Guard, Q, new OperationLog(_db), new NullPreActionRunner(), wl);

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private void Sql(string sql, string? path = null)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = sql;
        if (path != null) cmd.Parameters.AddWithValue("$p", path);
        cmd.ExecuteNonQuery();
    }

    private RuleLoadResult Load(string target) =>
        new RuleLoader(_t.Guard).LoadJson(
            "{\"rules\":[{\"id\":\"audit\",\"app\":\"audit\",\"category\":\"system\",\"targets\":[" + target + "]}]}", "audit.json");

    private ScanContext Context(string target, Whitelist? wl = null)
    {
        var loaded = Load(target);
        Assert.Empty(loaded.Rejected);
        return new() { Env = _t.Env, Guard = _t.Guard, Whitelist = wl ?? new(), Rules = loaded.Rules };
    }

    private Task<IReadOnlyList<ScanItem>> Scan(ScanContext ctx) =>
        new ScanScheduler().RunAsync(new[] { RuleScanner.SystemJunk() }, ctx, null, default);

    // ---------- 1. 索引不可信 ----------

    [Fact]
    public void ForgedIndex_PurgeRefusesPathOutsideQuarantine()
    {
        var entry = Q.MoveIn(_t.File("source.txt"), false, 5, "m", "b", "source");
        var victim = _t.File(Path.Combine(_t.Vars["Windir"], "System32", "audit.txt"));
        Sql("UPDATE quarantine_items SET quarantine_path=$p, expires_at='2000-01-01T00:00:00Z'", victim);

        Assert.Equal(0, Q.PurgeExpired());
        Assert.True(File.Exists(victim));
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.Single(Q.ListActive());
        Assert.Throws<InvalidOperationException>(() => Q.Purge(entry.Id));
        Assert.Throws<InvalidOperationException>(() => Q.Restore(entry.Id));
    }

    [Fact]
    public void ForgedIndex_PathInsideQuarantineButWrongBatch_IsRefused()
    {
        var entry = Q.MoveIn(_t.File("source.txt"), false, 5, "m", "b", "source");
        var other = _t.File(Path.Combine(QRoot, "other", "x.txt"));
        Sql("UPDATE quarantine_items SET quarantine_path=$p", other);
        Assert.Throws<InvalidOperationException>(() => Q.Purge(entry.Id));
        Assert.True(File.Exists(other));
    }

    // ---------- 2. 重解析点 ----------

    [Fact]
    public void Restore_RefusesReplacedParentJunction()
    {
        var source = _t.File(@"data\source.txt");
        var entry = Q.MoveIn(source, false, 5, "m", "b", "source");
        var parent = Path.GetDirectoryName(source)!;
        Directory.Delete(parent);
        var redirected = _t.Dir(@"Windows\System32\audit");
        Assert.True(TestEnv.TryCreateJunction(parent, redirected));
        try
        {
            Assert.Throws<IOException>(() => Q.Restore(entry.Id));
            Assert.False(File.Exists(Path.Combine(redirected, "source.txt")));
            Assert.True(File.Exists(entry.QuarantinePath));
            Assert.Single(Q.ListActive());
        }
        finally
        {
            Directory.Delete(parent);
        }
    }

    [Fact]
    public void MoveIn_RefusesPreexistingQuarantineJunction()
    {
        var redirected = _t.Dir("redirected");
        Assert.True(TestEnv.TryCreateJunction(QRoot, redirected));
        try
        {
            var source = _t.File("source.txt");
            Assert.Throws<IOException>(() => Q.MoveIn(source, false, 5, "m", "b", "source"));
            Assert.True(File.Exists(source));
            Assert.Empty(Directory.GetFiles(redirected, "*", SearchOption.AllDirectories));
            Assert.Empty(Q.ListActive());
        }
        finally
        {
            Directory.Delete(QRoot);
        }
    }

    [Fact]
    public void HandleMove_RefusesDestinationDirectoryThatIsAJunction()
    {
        var real = _t.Dir("real");
        var link = Path.Combine(_t.Root, "link");
        Assert.True(TestEnv.TryCreateJunction(link, real));
        try
        {
            var source = _t.File("source.txt");
            Assert.Throws<IOException>(() => HandleMove.Move(source, link, "moved.txt"));
            Assert.True(File.Exists(source));
            Assert.Empty(Directory.GetFiles(real));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public void HandleMove_MovesFilesAndDirectories()
    {
        var dest = _t.Dir("dest");
        var file = _t.File("a.txt", "abc");
        HandleMove.Move(file, dest, "b.txt");
        Assert.False(File.Exists(file));
        Assert.Equal("abc", File.ReadAllText(Path.Combine(dest, "b.txt")));

        var dir = _t.Dir("srcdir");
        _t.File(Path.Combine(dir, "inner.txt"));
        HandleMove.Move(dir, dest, "moveddir");
        Assert.False(Directory.Exists(dir));
        Assert.True(File.Exists(Path.Combine(dest, "moveddir", "inner.txt")));

        Assert.Throws<ArgumentException>(() => HandleMove.Move(Path.Combine(dest, "b.txt"), dest, @"..\escape.txt"));

        // 目标已存在：不覆盖，且错误统一为 IOException（调用方按单项失败处理）
        var another = _t.File("c.txt", "zzz");
        Assert.Throws<IOException>(() => HandleMove.Move(another, dest, "b.txt"));
        Assert.Equal("abc", File.ReadAllText(Path.Combine(dest, "b.txt")));
        Assert.True(File.Exists(another));
    }

    [Fact]
    public void Restore_DoesNotCreateDirectoriesThroughJunction()
    {
        var source = _t.File(@"data\deep\source.txt");
        var entry = Q.MoveIn(source, false, 5, "m", "b", "source");
        Directory.Delete(Path.Combine(_t.Root, "data"), true);
        var redirected = _t.Dir("redirected");
        Assert.True(TestEnv.TryCreateJunction(Path.Combine(_t.Root, "data"), redirected));
        try
        {
            Assert.Throws<IOException>(() => Q.Restore(entry.Id));
            // 既没有恢复文件，也没有穿过链接创建 deep 目录
            Assert.Empty(Directory.GetFileSystemEntries(redirected));
        }
        finally
        {
            Directory.Delete(Path.Combine(_t.Root, "data"));
        }
    }

    [Fact]
    public void Purge_DirectoryContainingJunction_DeletesOnlyTheLink()
    {
        var secret = _t.Dir("secret");
        var secretFile = _t.File(Path.Combine(secret, "keep.txt"));
        var dir = _t.Dir("victimdir");
        _t.File(Path.Combine(dir, "junk.txt"));
        Assert.True(TestEnv.TryCreateJunction(Path.Combine(dir, "link"), secret));

        var entry = Q.MoveIn(dir, true, 10, "m", "b", "dir");
        Q.Purge(entry.Id);

        Assert.False(Directory.Exists(entry.QuarantinePath));
        Assert.True(File.Exists(secretFile));
        Assert.Empty(Q.ListActive());
    }

    // ---------- 3. 整目录清理 ----------

    [Fact]
    public void DirectoryTarget_ContainingProtectedObject_IsRejectedAtLoad()
    {
        var loaded = Load("""{"path":"%UserProfile%\\AppData","kind":"directory"}""");
        var rejection = Assert.Single(loaded.Rejected);
        Assert.Contains("受保护", rejection.Reason);
    }

    [Fact]
    public void Guard_RejectsTargetsThatContainProtectedPaths()
    {
        Assert.False(_t.Guard.Check(Path.Combine(_t.Vars["UserProfile"], "AppData")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(_t.Vars["AppData"], "Microsoft")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(_t.Vars["LocalAppData"], "SomeApp", "Cache")).Allowed);
        Assert.True(_t.Guard.Check(_t.Vars["Temp"]).Allowed);
    }

    [Fact]
    public async Task DirectoryTarget_RefusesFilesCreatedAfterScan()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "Audit");
        _t.File(Path.Combine(root, "old.txt"));
        var items = await Scan(Context("""{"path":"%LocalAppData%\\Audit","kind":"directory"}"""));
        var added = _t.File(Path.Combine(root, "new-important.txt"));

        var result = await Engine().CleanAsync(items, null, default);

        Assert.Equal(0, result.DirectoriesQuarantined);
        Assert.True(File.Exists(added));
        var failure = Assert.Single(result.Failures);
        Assert.Contains("发生变化", failure.Reason);
        Assert.Contains(items[0].Id, result.FailedItemIds);
    }

    // ---------- 4. 文件系统与索引一致 ----------

    [Fact]
    public void InsertFailure_MovesFileBackAndLeavesNoOrphan()
    {
        Sql("CREATE TRIGGER fail_insert BEFORE INSERT ON quarantine_items BEGIN SELECT RAISE(ABORT, 'audit failure'); END;");
        var source = _t.File("source.txt");

        Assert.Throws<SqliteException>(() => Q.MoveIn(source, false, 5, "m", "b", "source"));

        Assert.True(File.Exists(source));
        Assert.Empty(Directory.Exists(QRoot) ? Directory.GetFiles(QRoot, "*", SearchOption.AllDirectories) : Array.Empty<string>());
        Assert.Empty(Q.ListActive());
    }

    [Fact]
    public void UncommittedBatch_ReconcileRebuildsIndex()
    {
        var dbPath = Path.Combine(_t.Root, "audit.db");
        var source = _t.File("source.txt", "payload");
        QuarantineEntry entry;
        using (var db = new CleanSweepDb(dbPath))
        {
            db.BeginBulk(); // 故意丢失作用域，模拟未提交事务随进程消失
            entry = new Quarantine(db, null, _ => QRoot).MoveIn(source, false, 7, "m", "batch1", "source");
        }

        using var reopened = new CleanSweepDb(dbPath);
        var q = new Quarantine(reopened, null, _ => QRoot);
        Assert.Empty(q.ListActive());
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.True(File.Exists(entry.QuarantinePath + Quarantine.MetaSuffix));

        Assert.Equal(1, q.Reconcile(new[] { QRoot }));
        var rebuilt = Assert.Single(q.ListActive());
        Assert.Equal(source, rebuilt.OriginalPath, ignoreCase: true);
        Assert.Equal("batch1", rebuilt.BatchId);

        Assert.Equal(0, q.Reconcile(new[] { QRoot }));
        var restored = q.Restore(rebuilt.Id);
        Assert.Equal("payload", File.ReadAllText(restored));
        Assert.False(File.Exists(entry.QuarantinePath + Quarantine.MetaSuffix));
    }

    [Fact]
    public void Reconcile_MarksEntriesWhoseFileVanished()
    {
        var entry = Q.MoveIn(_t.File("source.txt"), false, 5, "m", "b", "source");
        File.Delete(entry.QuarantinePath);
        Q.Reconcile(new[] { QRoot });
        Assert.Empty(Q.ListActive());
    }

    // ---------- 5. 删除失败 ----------

    [Fact]
    public void PurgeFailure_KeepsRecordUntilDeletionSucceeds()
    {
        var entry = Q.MoveIn(_t.File("source.txt"), false, 5, "m", "b", "source");
        using (new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.ThrowsAny<IOException>(() => Q.Purge(entry.Id));
            Assert.True(File.Exists(entry.QuarantinePath));
            Assert.Single(Q.ListActive());
            Assert.Equal(0, Q.PurgeExpired(DateTime.UtcNow.AddYears(1)));
        }
        Q.Purge(entry.Id);
        Assert.False(File.Exists(entry.QuarantinePath));
        Assert.Empty(Q.ListActive());
    }

    // ---------- 6. 白名单在执行前生效 ----------

    [Fact]
    public async Task WhitelistAddedAfterScan_IsHonoredByCleanup()
    {
        var source = _t.File(Path.Combine(_t.Vars["Temp"], "source.txt"));
        var wl = new Whitelist();
        var items = await Scan(Context("""{"path":"%Temp%"}""", wl));
        wl.AddPath(_t.Vars["Temp"]);

        var result = await Engine(wl).CleanAsync(items, null, default);

        Assert.Equal(0, result.FilesQuarantined);
        Assert.True(File.Exists(source));
        Assert.Equal(1, result.Skipped);
    }

    [Fact]
    public async Task DirectoryTarget_RefusesWhenItContainsWhitelistedPath()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "Audit");
        var keep = _t.File(Path.Combine(root, "keep.txt"));
        var wl = new Whitelist();
        var items = await Scan(Context("""{"path":"%LocalAppData%\\Audit","kind":"directory"}""", wl));
        Assert.Single(items);
        wl.AddPath(keep);

        var result = await Engine(wl).CleanAsync(items, null, default);

        Assert.Equal(0, result.DirectoriesQuarantined);
        Assert.True(File.Exists(keep));
        Assert.Contains("白名单", Assert.Single(result.Failures).Reason);
    }

    [Fact]
    public async Task ItemAddedToWhitelistAfterScan_IsSkipped()
    {
        var source = _t.File(Path.Combine(_t.Vars["Temp"], "source.txt"));
        var wl = new Whitelist();
        var items = await Scan(Context("""{"path":"%Temp%"}""", wl));
        wl.AddItem(items[0].Id);

        var result = await Engine(wl).CleanAsync(items, null, default);
        Assert.True(File.Exists(source));
        Assert.Equal(1, result.Skipped);
    }

    // ---------- 7. 固定操作与风险下限 ----------

    [Fact]
    public void RuleLoader_RejectsNonCleanupCommandArguments()
    {
        var loaded = Load("""{"kind":"command","command":"dism.exe","args":"/Online /Disable-Feature /FeatureName:ExampleFeature /NoRestart","risk":"safe"}""");
        Assert.Contains("操作表", Assert.Single(loaded.Rejected).Reason);
        Assert.False(RuleLoader.IsAllowedOperation("dism.exe", "/Online /Cleanup-Image /StartComponentCleanup /ResetBase"));
        Assert.True(RuleLoader.IsAllowedOperation("dism.exe", "  /Online   /Cleanup-Image /StartComponentCleanup "));
    }

    [Fact]
    public void RuleLoader_EnforcesRiskFloorForIrreversibleTargets()
    {
        var command = Load("""{"kind":"command","command":"dism.exe","args":"/Online /Cleanup-Image /StartComponentCleanup","risk":"safe"}""");
        Assert.Equal(RiskLevel.Confirm, command.Rules[0].Targets[0].Risk);

        var recycle = Load("""{"kind":"recycleBin","risk":"safe"}""");
        Assert.Equal(RiskLevel.Confirm, recycle.Rules[0].Targets[0].Risk);

        var high = Load("""{"kind":"recycleBin","risk":"high"}""");
        Assert.Equal(RiskLevel.High, high.Rules[0].Targets[0].Risk);
    }

    // ---------- 8. JSON null ----------

    [Theory]
    [InlineData("{\"rules\":[null]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"category\":null,\"targets\":[{}]}]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"targets\":[null]}]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"category\":\"system\",\"targets\":[{\"path\":\"%Temp%\",\"risk\":null}]}]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"category\":\"system\",\"targets\":[{\"path\":\"%Temp%\",\"preActions\":[null]}]}]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"category\":\"system\",\"targets\":[{\"path\":\"%Temp%\",\"minAgeDays\":99999}]}]}")]
    [InlineData("{\"rules\":[{\"id\":\"x\",\"app\":\"x\",\"category\":\"system\",\"detect\":{\"anyOf\":[null]},\"targets\":[{\"path\":\"%Temp%\"}]}]}")]
    public void RuleLoader_RejectsInsteadOfCrashingOnNulls(string json)
    {
        var loaded = new RuleLoader(_t.Guard).LoadJson(json, "audit.json");
        Assert.Empty(loaded.Rules);
        Assert.NotEmpty(loaded.Rejected);
    }

    // ---------- 9. 年龄策略 ----------

    [Fact]
    public async Task FileTarget_RespectsMinAgeDays()
    {
        _t.File(Path.Combine(_t.Vars["Temp"], "recent.tmp"));
        var items = await Scan(Context("""{"path":"%Temp%\\recent.tmp","minAgeDays":30}"""));
        Assert.Empty(items);
    }

    [Fact]
    public async Task BundledNuGetRule_SkipsFreshTemporaryFile()
    {
        var fresh = _t.File(Path.Combine(_t.Vars["Temp"], "NuGetScratch", "recent.tmp"));
        _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "NuGet"));
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "rules", "dev.json"))) dir = dir.Parent;
        Assert.NotNull(dir);

        var rules = new RuleLoader(_t.Guard).LoadDirectory(Path.Combine(dir!.FullName, "rules"));
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new(), Rules = rules.Rules };
        var items = await new ScanScheduler().RunAsync(new[] { RuleScanner.AppCache() }, ctx, null, default);
        Assert.DoesNotContain(items, i => i.Files.Any(f => f.Path == fresh));
    }

    // ---------- 10. 前置动作 ----------

    private sealed class FailedPreAction : IPreActionRunner
    {
        public IDisposable? Run(string action, out string? error)
        {
            error = "audit service stop failed";
            return null;
        }
    }

    private sealed class TimedOutPreAction : IPreActionRunner
    {
        public bool Restored;

        public IDisposable? Run(string action, out string? error)
        {
            error = "停止超时";
            return new RestoreFlag(this);
        }

        private sealed class RestoreFlag : IDisposable
        {
            private readonly TimedOutPreAction _o;
            public RestoreFlag(TimedOutPreAction o) => _o = o;
            public void Dispose() => _o.Restored = true;
        }
    }

    [Fact]
    public async Task FailedServiceStop_SkipsDependentItems()
    {
        var source = _t.File(Path.Combine(_t.Vars["Temp"], "source.txt"));
        var ctx = Context("""{"path":"%Temp%","preActions":["stopService:wuauserv"]}""");
        var engine = new CleanEngine(_t.Guard, Q, new OperationLog(_db), new FailedPreAction());

        var report = await engine.CleanAsync(await Scan(ctx), null, default);

        Assert.Equal(0, report.FilesQuarantined);
        Assert.True(File.Exists(source));
        Assert.Contains(report.Failures, f => f.Reason.Contains("前置动作"));
    }

    [Fact]
    public async Task TimedOutServiceStop_SkipsItemsButStillRestoresService()
    {
        _t.File(Path.Combine(_t.Vars["Temp"], "source.txt"));
        var ctx = Context("""{"path":"%Temp%","preActions":["stopService:wuauserv"]}""");
        var runner = new TimedOutPreAction();
        var engine = new CleanEngine(_t.Guard, Q, new OperationLog(_db), runner);

        var report = await engine.CleanAsync(await Scan(ctx), null, default);

        Assert.Equal(0, report.FilesQuarantined);
        Assert.True(runner.Restored);
    }

    // ---------- 11. 统计口径 ----------

    [Fact]
    public async Task Report_SeparatesQuarantinedFromFreedBytes()
    {
        _t.File(Path.Combine(_t.Vars["Temp"], "a.txt"), "12345");
        var report = await Engine().CleanAsync(await Scan(Context("""{"path":"%Temp%"}""")), null, default);
        Assert.Equal(5, report.QuarantinedBytes);
        Assert.Equal(0, report.FreedBytes);
        Assert.Equal(5, report.ProcessedBytes);
    }

    // ---------- 13. 空间分析 ----------

    [Fact]
    public async Task SpaceAnalyzer_RefusesRootJunction()
    {
        var target = _t.Dir("target");
        _t.File(Path.Combine(target, "secret.txt"));
        var link = Path.Combine(_t.Root, "link");
        Assert.True(TestEnv.TryCreateJunction(link, target));
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => new SpaceAnalyzer(_t.Guard).AnalyzeAsync(link, 10, null, default));
        }
        finally
        {
            Directory.Delete(link);
        }
    }
}
