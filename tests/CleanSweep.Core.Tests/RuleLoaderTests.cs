using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;

namespace CleanSweep.Core.Tests;

public sealed class RuleLoaderTests : IDisposable
{
    private readonly TestEnv _t = new();
    private RuleLoader Loader => new(_t.Guard);

    public void Dispose() => _t.Dispose();

    private static string Wrap(string rulesJson) => $$"""{ "version": 1, "rules": [ {{rulesJson}} ] }""";

    [Fact]
    public void ValidRule_Loads()
    {
        var json = Wrap("""
            {
              "id": "test.app", "app": "Test App", "category": "app",
              "detect": { "anyOf": [ { "file": "%LocalAppData%\\Test\\app.exe" } ] },
              "targets": [
                { "path": "%LocalAppData%\\Test\\Cache", "pattern": "*", "risk": "safe", "when": "installed", "description": "cache" },
                { "path": "%LocalAppData%\\Test", "kind": "directory", "risk": "high", "when": "uninstalled" }
              ]
            }
            """);

        var r = Loader.LoadJson(json, "test.json");

        Assert.Empty(r.Rejected);
        var rule = Assert.Single(r.Rules);
        Assert.Equal("test.app", rule.Id);
        Assert.Equal(2, rule.Targets.Count);
        Assert.Equal(RiskLevel.Safe, rule.Targets[0].Risk);
        Assert.Equal(RuleWhen.Installed, rule.Targets[0].When);
        Assert.Equal(TargetKind.Directory, rule.Targets[1].Kind);
        Assert.EndsWith(@"\Test\Cache", rule.Targets[0].ExpandedPath);
    }

    [Theory]
    [InlineData("""{ "path": "%LocalAppData%\\..\\Roaming", "risk": "safe" }""", "..")]
    [InlineData("""{ "path": "C:\\Windows\\Temp", "risk": "safe" }""", "环境变量开头")]
    [InlineData("""{ "path": "%ProgramFiles%\\Foo", "risk": "safe" }""", "Program Files")]
    [InlineData("""{ "path": "%LocalAppData%", "risk": "safe" }""", "范围过大")]
    [InlineData("""{ "path": "%Windir%\\System32", "risk": "safe" }""", "Windows 系统目录")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo", "pattern": "..\\*", "risk": "safe" }""", "分隔符")]
    [InlineData("""{ "kind": "command", "command": "cmd.exe", "args": "/c rd /s /q C:\\", "risk": "safe" }""", "白名单")]
    [InlineData("""{ "kind": "command", "command": "dism.exe", "path": "%Temp%", "risk": "safe" }""", "不得携带")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo", "risk": "banana" }""", "risk")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo", "risk": "safe", "preActions": ["stopService:a b"] }""", "preAction")]
    [InlineData("""{ "path": "%LocalAppData%\\Foo", "risk": "safe", "preActions": ["killProcess:x"] }""", "preAction")]
    public void UnsafeTarget_RejectsWholeRule(string targetJson, string reasonFragment)
    {
        var json = Wrap($$"""
            { "id": "bad", "app": "Bad", "category": "system",
              "targets": [ { "path": "%Temp%", "risk": "safe" }, {{targetJson}} ] }
            """);

        var r = Loader.LoadJson(json, "bad.json");

        Assert.Empty(r.Rules);
        var rej = Assert.Single(r.Rejected);
        Assert.Equal("bad", rej.RuleId);
        Assert.Contains(reasonFragment, rej.Reason);
    }

    [Fact]
    public void InstalledWhen_WithoutDetect_IsRejected()
    {
        var json = Wrap("""
            { "id": "x", "app": "X", "category": "app",
              "targets": [ { "path": "%LocalAppData%\\X\\Cache", "risk": "safe", "when": "installed" } ] }
            """);

        var r = Loader.LoadJson(json, "x.json");

        Assert.Empty(r.Rules);
        Assert.Contains("detect", Assert.Single(r.Rejected).Reason);
    }

    [Fact]
    public void DuplicateId_SecondIsRejected()
    {
        var json = Wrap("""
            { "id": "dup", "app": "A", "category": "system", "targets": [ { "path": "%Temp%", "risk": "safe" } ] },
            { "id": "dup", "app": "B", "category": "system", "targets": [ { "path": "%Temp%", "risk": "safe" } ] }
            """);

        var r = Loader.LoadJson(json, "dup.json");

        Assert.Single(r.Rules);
        Assert.Contains("重复", Assert.Single(r.Rejected).Reason);
    }

    [Fact]
    public void MalformedJson_IsRejectedWithoutThrowing()
    {
        var r = Loader.LoadJson("{ not json", "broken.json");

        Assert.Empty(r.Rules);
        Assert.Contains("JSON", Assert.Single(r.Rejected).Reason);
    }

    [Fact]
    public void BundledRules_AllLoadAgainstRealEnvironment()
    {
        // 用真实环境解析器校验随程序分发的规则文件本身没有写错
        var env = new Core.Environment.CurrentUserEnvironmentResolver();
        var guard = new Core.Safety.PathGuard(env);
        var dir = FindRulesDir();
        Assert.NotNull(dir);

        var r = new RuleLoader(guard).LoadDirectory(dir!);

        Assert.True(r.Rejected.Count == 0, string.Join("\n", r.Rejected.Select(x => $"{x.SourceFile} [{x.RuleId}]: {x.Reason}")));
        Assert.True(r.Rules.Count >= 20);
    }

    private static string? FindRulesDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && d is not null; i++)
        {
            var candidate = Path.Combine(d, "rules");
            if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "system.json"))) return candidate;
            d = Path.GetDirectoryName(d);
        }
        return null;
    }
}
