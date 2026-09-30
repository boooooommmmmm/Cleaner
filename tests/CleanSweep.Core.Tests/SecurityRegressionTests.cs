using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

/// <summary>针对评审中发现的提权与误删场景的回归测试。</summary>
public sealed class SecurityRegressionTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly CleanEngine _engine;

    public SecurityRegressionTests()
    {
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"));
        _engine = new CleanEngine(_t.Guard, q, new OperationLog(_db), new NullPreActionRunner());
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

    [Fact]
    public void EnumerateFiles_SkipsRootThatIsJunction()
    {
        var real = _t.Dir("RealCache");
        _t.File(Path.Combine(real, "a.bin"));
        var link = Path.Combine(_t.Vars["LocalAppData"], "App", "Cache");
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (!TestEnv.TryCreateJunction(link, real)) return;

        var files = _t.Guard.EnumerateFiles(link, "*", recurse: true).ToList();

        Assert.Empty(files);
    }

    [Fact]
    public async Task CleanEngine_RefusesFileWhoseScanRootIsJunction()
    {
        // 攻击模型：低权限用户把 %AppData%\App\Cache 换成指向受保护位置的 Junction，
        // 扫描结果（可能来自旧快照）仍列出该路径下的文件，提权后的引擎必须拒绝。
        var protectedDir = _t.Dir(Path.Combine(_t.Vars["ProgramFiles"], "Victim"));
        var victim = _t.File(Path.Combine(protectedDir, "victim.dll"), "dll");
        var link = Path.Combine(_t.Vars["AppData"], "App", "Cache");
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (!TestEnv.TryCreateJunction(link, protectedDir)) return;

        var viaLink = Path.Combine(link, "victim.dll");
        var item = new ScanItem
        {
            Id = "x", ModuleId = "t", Group = "g", DisplayName = "cache", Kind = ItemKind.FileSet,
            Path = link, Files = new[] { Snapshot(viaLink) }, SizeBytes = 3,
        };

        var report = await _engine.CleanAsync(new[] { item }, null, default);

        Assert.Single(report.Failures);
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public async Task CleanEngine_RefusesFileWhoseGrandparentIsJunction()
    {
        // Junction 在扫描根之上：%LocalAppData%\App → 其他位置，扫描根为 %LocalAppData%\App\Cache
        var real = _t.Dir("Elsewhere");
        var cacheReal = _t.Dir(Path.Combine(real, "Cache"));
        var target = _t.File(Path.Combine(cacheReal, "data.bin"), "data");
        var link = Path.Combine(_t.Vars["LocalAppData"], "App");
        if (!TestEnv.TryCreateJunction(link, real)) return;

        var root = Path.Combine(link, "Cache");
        var viaLink = Path.Combine(root, "data.bin");
        var item = new ScanItem
        {
            Id = "y", ModuleId = "t", Group = "g", DisplayName = "cache", Kind = ItemKind.FileSet,
            Path = root, Files = new[] { Snapshot(viaLink) }, SizeBytes = 4,
        };

        var report = await _engine.CleanAsync(new[] { item }, null, default);

        Assert.Single(report.Failures);
        Assert.Contains("重解析点", report.Failures[0].Reason);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public void ResolveFinalPath_MatchesLogicalPathForPlainFile_AndDiffersThroughJunction()
    {
        var real = _t.Dir("R");
        var plain = _t.File(Path.Combine(real, "p.txt"));
        Assert.True(PathGuard.IsSamePhysicalPath(plain, PathGuard.ResolveFinalPath(plain)));
        Assert.True(_t.Guard.VerifyPhysical(plain).Allowed);

        var link = Path.Combine(_t.Root, "L");
        if (!TestEnv.TryCreateJunction(link, real)) return;
        var viaLink = Path.Combine(link, "p.txt");

        var final = PathGuard.ResolveFinalPath(viaLink);
        Assert.NotNull(final);
        Assert.False(PathGuard.IsSamePhysicalPath(viaLink, final));
        Assert.False(_t.Guard.VerifyPhysical(viaLink).Allowed);
    }

    [Fact]
    public void ResolveFinalPath_HandlesShortNames()
    {
        var dir = _t.Dir("LongDirectoryName");
        var file = _t.File(Path.Combine(dir, "file.txt"));
        var longPath = PathGuard.ToLongPath(file);
        Assert.Equal(file, longPath, ignoreCase: true);
        Assert.True(PathGuard.IsSamePhysicalPath(file, PathGuard.ResolveFinalPath(file)));
    }

    [Theory]
    [InlineData("NTUSER.DAT", "UserProfile")]
    [InlineData(@"Microsoft\Windows\UsrClass.dat", "LocalAppData")]
    [InlineData(@"Microsoft\Protect\S-1-5-21\key", "AppData")]
    [InlineData(@"Microsoft\Credentials", "AppData")]
    [InlineData(@"Microsoft\Windows\Start Menu\Programs", "AppData")]
    public void Check_UserProfileCriticalObjects_AreDenied(string relative, string var)
    {
        var v = _t.Guard.Check(Path.Combine(_t.Vars[var], relative));
        Assert.False(v.Allowed);
    }

    [Theory]
    [InlineData("Documents")]
    [InlineData("Desktop")]
    [InlineData("Downloads")]
    [InlineData("Pictures")]
    [InlineData("OneDrive")]
    public void Check_KnownUserFolders_AreTooBroad_ButSubfoldersAllowed(string folder)
    {
        var root = Path.Combine(_t.Vars["UserProfile"], folder);
        Assert.False(_t.Guard.Check(root).Allowed);
        Assert.False(_t.Guard.ValidateRulePath($"%UserProfile%\\{folder}").Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(root, "SomeGame", "cache")).Allowed);
    }

    [Fact]
    public void Check_LocalAppDataMicrosoftWindows_IsTooBroad_ButExplorerAllowed()
    {
        var local = _t.Vars["LocalAppData"];
        Assert.False(_t.Guard.Check(Path.Combine(local, "Microsoft", "Windows")).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(_t.Vars["AppData"], "Microsoft", "Windows")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(local, "Microsoft", "Windows", "Explorer")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(local, "Microsoft", "Windows", "WER")).Allowed);
    }

    [Fact]
    public void ResolveTemp_FallsBackWhenTempIsNotATempFolder()
    {
        var local = _t.Vars["LocalAppData"];
        var docs = _t.Dir("Documents");
        var realTemp = _t.Dir(@"SomeWhere\Temp");
        var tmp = _t.Dir(@"SomeWhere\tmp");

        Assert.Equal(Path.Combine(local, "Temp"), CurrentUserEnvironmentResolver.ResolveTemp(local, docs), ignoreCase: true);
        Assert.Equal(Path.Combine(local, "Temp"), CurrentUserEnvironmentResolver.ResolveTemp(local, Path.GetPathRoot(docs)!), ignoreCase: true);
        Assert.Equal(realTemp, CurrentUserEnvironmentResolver.ResolveTemp(local, realTemp + "\\"), ignoreCase: true);
        Assert.Equal(tmp, CurrentUserEnvironmentResolver.ResolveTemp(local, tmp), ignoreCase: true);
    }
}
