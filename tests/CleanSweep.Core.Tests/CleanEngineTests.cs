using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class CleanEngineTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly CleanEngine _engine;
    private readonly OperationLog _log;

    public CleanEngineTests()
    {
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"));
        _log = new OperationLog(_db);
        _engine = new CleanEngine(_t.Guard, q, _log, new NullPreActionRunner());
    }

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private static FileEntry Snapshot(string path)
    {
        var fi = new FileInfo(path);
        return new FileEntry(fi.FullName, fi.Length, fi.LastWriteTimeUtc);
    }

    private static ScanItem FileSet(string root, params FileEntry[] files) => new()
    {
        Id = "i1", ModuleId = "test", Group = "g", DisplayName = "set", Kind = ItemKind.FileSet,
        Path = root, Files = files, SizeBytes = files.Sum(f => f.Size),
    };

    [Fact]
    public async Task FileSet_MovesAllFilesToQuarantine()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "App", "Cache");
        var a = _t.File(Path.Combine(root, "a.bin"), "aaaa");
        var b = _t.File(Path.Combine(root, "sub", "b.bin"), "bb");

        var report = await _engine.CleanAsync(new[] { FileSet(root, Snapshot(a), Snapshot(b)) }, null, default);

        Assert.Empty(report.Failures);
        Assert.Equal(2, report.FilesQuarantined);
        Assert.Equal(6, report.QuarantinedBytes);
        Assert.Equal(0, report.FreedBytes);
        Assert.False(File.Exists(a));
        Assert.False(File.Exists(b));
        Assert.Single(_log.GetRecentBatches());
        Assert.NotNull(_log.GetRecentBatches()[0].FinishedUtc);
    }

    [Fact]
    public async Task FileSet_RemovesEmptiedSubdirectories_ButKeepsRootAndNonEmpty()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "App", "Cache");
        var a = _t.File(Path.Combine(root, "deep", "er", "a.bin"), "1");
        var b = _t.File(Path.Combine(root, "keep", "b.bin"), "2");
        _t.File(Path.Combine(root, "keep", "stay.txt"), "3");
        var link = Path.Combine(root, "linked");
        var outside = _t.Dir("Outside");
        var hasLink = TestEnv.TryCreateJunction(link, outside);

        var report = await _engine.CleanAsync(new[] { FileSet(root, Snapshot(a), Snapshot(b)) }, null, default);

        Assert.Empty(report.Failures);
        Assert.Equal(2, report.EmptyDirectoriesRemoved);
        Assert.False(Directory.Exists(Path.Combine(root, "deep")));
        Assert.True(Directory.Exists(Path.Combine(root, "keep")));
        Assert.True(Directory.Exists(root));
        if (hasLink)
        {
            Assert.True(Directory.Exists(link));
            Assert.True(Directory.Exists(outside));
        }
    }

    [Fact]
    public async Task FileSet_SkipsFileChangedAfterScan()
    {
        var root = Path.Combine(_t.Vars["LocalAppData"], "App", "Cache");
        var a = _t.File(Path.Combine(root, "a.bin"), "aaaa");
        var snap = Snapshot(a);
        File.WriteAllText(a, "changed content");
        File.SetLastWriteTimeUtc(a, snap.LastWriteUtc.AddMinutes(1));

        var report = await _engine.CleanAsync(new[] { FileSet(root, snap) }, null, default);

        Assert.Equal(1, report.Skipped);
        Assert.Equal(0, report.FilesQuarantined);
        Assert.True(File.Exists(a));
    }

    [Fact]
    public async Task FileSet_RefusesProtectedPathEvenIfItemClaimsIt()
    {
        var evil = _t.File(Path.Combine(_t.Vars["ProgramFiles"], "Foo", "important.dll"), "dll");

        var report = await _engine.CleanAsync(new[] { FileSet(Path.GetDirectoryName(evil)!, Snapshot(evil)) }, null, default);

        Assert.Single(report.Failures);
        Assert.Contains("护栏", report.Failures[0].Reason);
        Assert.True(File.Exists(evil));
    }

    [Fact]
    public async Task FileSet_RefusesFileReachedThroughJunction()
    {
        var target = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "RealData"));
        var secret = _t.File(Path.Combine(target, "secret.txt"), "secret");
        var scanRoot = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "App", "Cache"));
        var link = Path.Combine(scanRoot, "link");
        if (!TestEnv.TryCreateJunction(link, target)) return;

        var viaLink = Path.Combine(link, "secret.txt");
        var report = await _engine.CleanAsync(new[] { FileSet(scanRoot, Snapshot(viaLink)) }, null, default);

        Assert.Single(report.Failures);
        Assert.Contains("重解析点", report.Failures[0].Reason);
        Assert.True(File.Exists(secret));
    }

    [Fact]
    public async Task Directory_MovesWholeDirectory()
    {
        var dir = _t.Dir(Path.Combine(_t.Vars["AppData"], "OldApp"));
        _t.File(Path.Combine(dir, "settings.json"), "{}");

        var item = new ScanItem { Id = "d", ModuleId = "test", Group = "g", DisplayName = "OldApp", Kind = ItemKind.Directory, Path = dir, SizeBytes = 2 };
        var report = await _engine.CleanAsync(new[] { item }, null, default);

        Assert.Empty(report.Failures);
        Assert.Equal(1, report.DirectoriesQuarantined);
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public async Task Directory_RefusesReparsePointItself()
    {
        var target = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "RealData2"));
        _t.File(Path.Combine(target, "keep.txt"));
        var link = Path.Combine(_t.Vars["AppData"], "LinkApp");
        if (!TestEnv.TryCreateJunction(link, target)) return;

        var item = new ScanItem { Id = "d", ModuleId = "test", Group = "g", DisplayName = "Link", Kind = ItemKind.Directory, Path = link, SizeBytes = 1 };
        var report = await _engine.CleanAsync(new[] { item }, null, default);

        Assert.Single(report.Failures);
        Assert.True(File.Exists(Path.Combine(target, "keep.txt")));
    }

    [Fact]
    public async Task FileSet_ManyFiles_BulkModeKeepsIndexConsistent()
    {
        // 超过批量提交阈值（500）两倍以上，验证分段提交后索引完整，且清理中途从其他线程读取隔离区不会崩溃
        var root = Path.Combine(_t.Vars["LocalAppData"], "Big", "Cache");
        var files = new List<FileEntry>();
        for (int i = 0; i < 1200; i++)
        {
            var p = _t.File(Path.Combine(root, $"f{i:D4}.bin"), "x");
            files.Add(Snapshot(p));
        }
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"));

        var reader = Task.Run(() =>
        {
            for (int i = 0; i < 20; i++)
            {
                _ = q.ListActive();
                Thread.Sleep(5);
            }
        });

        var report = await _engine.CleanAsync(new[] { FileSet(root, files.ToArray()) }, null, default);
        await reader;

        Assert.Empty(report.Failures);
        Assert.Equal(1200, report.FilesQuarantined);
        Assert.Equal(1200, q.ListActive().Count);
        Assert.True(_log.GetOperations(limit: 5000).Count >= 1200);
        Assert.Empty(Directory.EnumerateFiles(root));
    }

    [Fact]
    public async Task Command_NotInAllowlist_IsRefused()
    {
        var item = new ScanItem { Id = "c", ModuleId = "test", Group = "g", DisplayName = "cmd", Kind = ItemKind.Command, Command = "cmd.exe", CommandArgs = "/c echo hi" };

        var report = await _engine.CleanAsync(new[] { item }, null, default);

        Assert.Single(report.Failures);
        Assert.Contains("操作表", report.Failures[0].Reason);
    }
}
