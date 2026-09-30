using CleanSweep.Core.Modules;

namespace CleanSweep.Core.Tests;

public sealed class DuplicateFinderTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    [Fact]
    public async Task FindsIdenticalFiles_AndIgnoresHardLinks()
    {
        var root = _t.Dir("dups");
        var a = _t.RandomFile(Path.Combine(root, "a.bin"), 300 * 1024, seed: 1);
        var b = _t.RandomFile(Path.Combine(root, "sub", "b.bin"), 300 * 1024, seed: 1);
        _t.RandomFile(Path.Combine(root, "c.bin"), 300 * 1024, seed: 2);
        _t.RandomFile(Path.Combine(root, "d.bin"), 100, seed: 1);
        var hard = Path.Combine(root, "a-hardlink.bin");
        var hasHardLink = TestEnv.TryCreateHardLink(hard, a);

        var groups = await new DuplicateFinder(_t.Guard).FindAsync(new[] { root }, minSizeBytes: 1, null, default);

        var g = Assert.Single(groups);
        Assert.Equal(300 * 1024, g.SizeBytes);
        Assert.Equal(2, g.Files.Count);
        Assert.Equal(300 * 1024, g.ReclaimableBytes);
        Assert.Contains(g.Files, f => string.Equals(f.Path, b, StringComparison.OrdinalIgnoreCase));
        if (hasHardLink)
        {
            // a 与 a-hardlink 是同一文件，只能出现其中一个
            Assert.Equal(1, g.Files.Count(f => f.Path.EndsWith("a.bin", StringComparison.OrdinalIgnoreCase) || f.Path.EndsWith("a-hardlink.bin", StringComparison.OrdinalIgnoreCase)));
        }
    }

    [Fact]
    public async Task SameSizeDifferentContent_IsNotDuplicate()
    {
        var root = _t.Dir("dups2");
        _t.RandomFile(Path.Combine(root, "a.bin"), 200 * 1024, seed: 10);
        _t.RandomFile(Path.Combine(root, "b.bin"), 200 * 1024, seed: 11);

        var groups = await new DuplicateFinder(_t.Guard).FindAsync(new[] { root }, 1, null, default);

        Assert.Empty(groups);
    }

    [Fact]
    public async Task SameHeadAndTail_DifferentMiddle_IsNotDuplicate()
    {
        var root = _t.Dir("dups3");
        var buf = new byte[400 * 1024];
        new Random(5).NextBytes(buf);
        File.WriteAllBytes(Path.Combine(root, "a.bin"), buf);
        buf[200 * 1024] ^= 0xFF;
        File.WriteAllBytes(Path.Combine(root, "b.bin"), buf);

        var groups = await new DuplicateFinder(_t.Guard).FindAsync(new[] { root }, 1, null, default);

        Assert.Empty(groups);
    }
}
