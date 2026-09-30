using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class QuarantineTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private Quarantine Create(QuarantineOptions? opts = null) =>
        new(_db, opts, _ => Path.Combine(_t.Root, "Q"));

    [Fact]
    public void MoveIn_ThenRestore_RoundTrips()
    {
        var q = Create();
        var file = _t.File(@"data\doc.txt", "content");

        var entry = q.MoveIn(file, isDirectory: false, 7, "mod", "batch1", "doc");

        Assert.False(File.Exists(file));
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.Single(q.ListActive());

        var restored = q.Restore(entry.Id);

        Assert.Equal(file, restored, ignoreCase: true);
        Assert.Equal("content", File.ReadAllText(file));
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public void Restore_WhenOriginalExists_UsesSuffix()
    {
        var q = Create();
        var file = _t.File(@"data\doc.txt", "old");
        var entry = q.MoveIn(file, false, 3, "mod", "b", "doc");
        _t.File(file, "new");

        var restored = q.Restore(entry.Id);

        Assert.EndsWith("doc.restored.txt", restored);
        Assert.Equal("old", File.ReadAllText(restored));
        Assert.Equal("new", File.ReadAllText(file));
    }

    [Fact]
    public void MoveIn_Directory_MovesWholeTree()
    {
        var q = Create();
        var dir = _t.Dir(@"data\app");
        _t.File(Path.Combine(dir, "a.txt"));
        _t.File(Path.Combine(dir, "sub", "b.txt"));

        var entry = q.MoveIn(dir, isDirectory: true, 10, "mod", "b", "app");

        Assert.False(Directory.Exists(dir));
        Assert.True(File.Exists(Path.Combine(entry.QuarantinePath, "sub", "b.txt")));

        q.Restore(entry.Id);
        Assert.True(File.Exists(Path.Combine(dir, "sub", "b.txt")));
    }

    [Fact]
    public void Restore_WhenQuarantinedFileWasDeletedExternally_MarksPurgedAndThrows()
    {
        var q = Create();
        var entry = q.MoveIn(_t.File(@"data\gone.txt"), false, 5, "m", "b", "gone");
        File.Delete(entry.QuarantinePath);

        Assert.Throws<FileNotFoundException>(() => q.Restore(entry.Id));
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public void Purge_DeletesPermanently()
    {
        var q = Create();
        var file = _t.File(@"data\x.txt");
        var entry = q.MoveIn(file, false, 5, "mod", "b", "x");

        q.Purge(entry.Id);

        Assert.False(File.Exists(entry.QuarantinePath));
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public void PurgeExpired_RemovesOnlyExpired()
    {
        var q = Create(new QuarantineOptions { RetentionDays = 30 });
        var f1 = _t.File(@"data\1.txt");
        var f2 = _t.File(@"data\2.txt");
        var e1 = q.MoveIn(f1, false, 5, "m", "b", "1");
        q.MoveIn(f2, false, 5, "m", "b", "2");

        var purged = q.PurgeExpired(DateTime.UtcNow.AddDays(31));

        Assert.Equal(2, purged);
        Assert.Empty(q.ListActive());
        Assert.False(File.Exists(e1.QuarantinePath));
    }

    [Fact]
    public void EnforceSizeLimit_PurgesOldestFirst()
    {
        var q = Create(new QuarantineOptions { MaxBytesAbsolute = 12, MaxVolumeFraction = 1.0 });
        var e1 = q.MoveIn(_t.File(@"data\1.txt"), false, 5, "m", "b", "1");
        Thread.Sleep(20);
        var e2 = q.MoveIn(_t.File(@"data\2.txt"), false, 5, "m", "b", "2");
        Thread.Sleep(20);
        var e3 = q.MoveIn(_t.File(@"data\3.txt"), false, 5, "m", "b", "3");

        var purged = q.EnforceSizeLimit();

        Assert.Equal(1, purged);
        var remaining = q.ListActive().Select(e => e.Id).ToHashSet();
        Assert.DoesNotContain(e1.Id, remaining);
        Assert.Contains(e2.Id, remaining);
        Assert.Contains(e3.Id, remaining);
    }
}
