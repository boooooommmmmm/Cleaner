using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Tests;

public sealed class PathGuardTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    [Fact]
    public void Check_VolumeRoot_IsDenied()
    {
        var drive = Path.GetPathRoot(_t.Root)!;
        Assert.False(_t.Guard.Check(drive).Allowed);
        Assert.False(_t.Guard.Check(drive.TrimEnd('\\')).Allowed);
    }

    [Fact]
    public void Check_VolumeLevelProtectedObjects_AreDenied()
    {
        var drive = Path.GetPathRoot(_t.Root)!;
        Assert.False(_t.Guard.Check(Path.Combine(drive, "System Volume Information")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(drive, "$Recycle.Bin", "S-1-5-21")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(drive, "Recovery")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(drive, "pagefile.sys")).Allowed);
    }

    [Fact]
    public void Check_TooBroadRoots_AreDenied_ButChildrenAllowed()
    {
        var local = _t.Vars["LocalAppData"];
        Assert.False(_t.Guard.Check(local).Allowed);
        Assert.False(_t.Guard.Check(_t.Vars["UserProfile"]).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(local, "Microsoft")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(local, "SomeApp", "Cache")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(local, "Microsoft", "Windows", "Explorer")).Allowed);
    }

    [Fact]
    public void Check_WindowsDirectory_OnlyAllowlistedSubdirs()
    {
        var win = _t.Vars["Windir"];
        Assert.False(_t.Guard.Check(win).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(win, "System32")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(win, "System32", "drivers")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(win, "Temp")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(win, "Temp", "x", "y.tmp")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(win, "SoftwareDistribution", "Download")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(win, "SoftwareDistribution")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(win, "MEMORY.DMP")).Allowed);
    }

    [Fact]
    public void Check_ProgramFiles_IsDenied()
    {
        Assert.False(_t.Guard.Check(_t.Vars["ProgramFiles"]).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(_t.Vars["ProgramFiles"], "Foo", "bar.dll")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(_t.Vars["ProgramFilesX86"], "Foo")).Allowed);
    }

    [Fact]
    public void Check_UncPath_IsDenied()
    {
        Assert.False(_t.Guard.Check(@"\\server\share\folder").Allowed);
    }

    [Theory]
    [InlineData(@"C:\Users\me\AppData\Local\Foo", "必须以已知环境变量开头")]
    [InlineData(@"%LocalAppData%\..\Roaming", "不得包含 ..")]
    [InlineData(@"%LocalAppData%\Foo\..\..\Bar", "不得包含 ..")]
    [InlineData(@"%NoSuchVar%\Foo", "未知环境变量")]
    [InlineData(@"%LocalAppData%", "范围过大")]
    [InlineData(@"%ProgramFiles%\Foo", "Program Files")]
    [InlineData(@"%Windir%\System32\config", "Windows 系统目录")]
    public void ValidateRulePath_RejectsUnsafePaths(string raw, string reasonFragment)
    {
        var v = _t.Guard.ValidateRulePath(raw);
        Assert.False(v.Allowed);
        Assert.Contains(reasonFragment, v.Reason);
    }

    [Theory]
    [InlineData(@"%LocalAppData%\Foo\Cache")]
    [InlineData(@"%Temp%")]
    [InlineData(@"%Windir%\Temp")]
    [InlineData(@"%Windir%\Logs\CBS")]
    [InlineData(@"%UserProfile%\.gradle\caches")]
    public void ValidateRulePath_AcceptsSafePaths(string raw)
    {
        var v = _t.Guard.ValidateRulePath(raw);
        Assert.True(v.Allowed, v.Reason);
        Assert.NotNull(v.FullPath);
        Assert.DoesNotContain("%", v.FullPath);
    }

    [Fact]
    public void EnumerateFiles_DoesNotFollowJunction()
    {
        var a = _t.Dir("A");
        var secret = _t.File(Path.Combine(a, "secret.txt"));
        var b = _t.Dir("B");
        var normal = _t.File(Path.Combine(b, "sub", "normal.txt"));
        var link = Path.Combine(b, "link");

        if (!TestEnv.TryCreateJunction(link, a))
        {
            return; // 当前文件系统不支持 Junction，跳过
        }

        var files = _t.Guard.EnumerateFiles(b, "*", recurse: true).Select(f => f.Path).ToList();

        Assert.Contains(normal, files, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(files, f => f.EndsWith("secret.txt", StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(secret));
    }

    [Fact]
    public void EnumerateFiles_MatchesMultiplePatterns()
    {
        var d = _t.Dir("P");
        _t.File(Path.Combine(d, "a.log"));
        _t.File(Path.Combine(d, "b.tmp"));
        _t.File(Path.Combine(d, "c.txt"));

        var names = _t.Guard.EnumerateFiles(d, "*.log;*.tmp", recurse: false).Select(f => Path.GetFileName(f.Path)).OrderBy(n => n).ToList();

        Assert.Equal(new[] { "a.log", "b.tmp" }, names);
    }

    [Fact]
    public void AnyAncestorIsReparsePoint_DetectsJunctionInPath()
    {
        var a = _t.Dir("A2");
        _t.File(Path.Combine(a, "secret.txt"));
        var b = _t.Dir("B2");
        var link = Path.Combine(b, "link");
        if (!TestEnv.TryCreateJunction(link, a)) return;

        var viaLink = Path.Combine(link, "secret.txt");
        Assert.True(File.Exists(viaLink));
        Assert.True(PathGuard.AnyAncestorIsReparsePoint(viaLink, b));
        Assert.False(PathGuard.AnyAncestorIsReparsePoint(Path.Combine(b, "x", "y.txt"), b));
    }

    [Fact]
    public void MeasureDirectory_SumsSizes()
    {
        var d = _t.Dir("M");
        _t.File(Path.Combine(d, "a.bin"), "12345");
        _t.File(Path.Combine(d, "sub", "b.bin"), "123");

        var (size, count, _) = _t.Guard.MeasureDirectory(d);

        Assert.Equal(8, size);
        Assert.Equal(2, count);
    }
}
