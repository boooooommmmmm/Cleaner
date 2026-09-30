using System.IO.Pipes;
using System.Security.Principal;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

/// <summary>提权服务安全测试（设计文档 9.2）：同用户连通、未登记程序被拒、非法帧被拒、枚举外指令被拒、隔离操作只按 ID。</summary>
public sealed class ElevationTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly List<string> _log = new();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private static string MySid => WindowsIdentity.GetCurrent().User!.Value;
    private static string MyExe => Path.GetFullPath(System.Environment.ProcessPath!);

    private ElevationServer Start(string pipe, bool allowMyExe = true, bool allowMySid = true, IElevatedOperations? ops = null)
    {
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        ops ??= new ElevatedOperations(q, new OperationLog(_db), new RuleLoadResult(), new Whitelist(), _ => _t.Guard);
        var server = new ElevationServer(ops, new ElevationServerOptions
        {
            PipeName = pipe,
            AllowedClientSids = allowMySid ? new HashSet<string> { MySid } : new HashSet<string>(),
            AllowedClientExePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { allowMyExe ? MyExe : @"C:\nowhere\CleanSweep.exe" },
            RequireSignedClient = false,
            Log = (m, ok) => { lock (_log) _log.Add((ok ? "ok " : "!! ") + m); },
        });
        server.Start();
        return server;
    }

    private static string Pipe() => "CleanSweepTests." + Guid.NewGuid().ToString("N");

    [Fact]
    public async Task Ping_round_trip()
    {
        var pipe = Pipe();
        using var server = Start(pipe);
        var r = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.Ping), TimeSpan.FromSeconds(10), pipe);
        Assert.True(r.Success, r.Message);
        Assert.Equal("pong", r.Message);
        Assert.True(await ElevationClient.IsAvailableAsync(pipe));
    }

    [Fact]
    public async Task Status_reports_service_facts()
    {
        var pipe = Pipe();
        using var server = Start(pipe);
        var r = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.GetStatus), TimeSpan.FromSeconds(10), pipe);
        Assert.True(r.Success);
        Assert.Contains("\"version\"", r.Payload);
    }

    [Fact]
    public async Task Unregistered_client_executable_is_refused()
    {
        var pipe = Pipe();
        using var server = Start(pipe, allowMyExe: false);
        var r = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.Ping), TimeSpan.FromSeconds(10), pipe);
        Assert.False(r.Success);
        Assert.Contains("未登记", r.Message);
    }

    [Fact]
    public async Task Same_user_is_accepted_via_sid_or_admin_group()
    {
        // 当前用户不在列表里：只有属于 Administrators（提权运行测试时）才通过，否则被拒——两种结果都不能是"静默接受"
        var pipe = Pipe();
        using var server = Start(pipe, allowMySid: false);
        var r = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.Ping), TimeSpan.FromSeconds(10), pipe);
        var isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        Assert.Equal(isAdmin, r.Success);
        if (!isAdmin) Assert.Contains("不在允许列表", r.Message);
    }

    [Fact]
    public async Task Unknown_operation_is_refused()
    {
        var pipe = Pipe();
        using var server = Start(pipe);
        var r = await ElevationClient.SendAsync(new ElevationRequest((ElevatedOperation)999), TimeSpan.FromSeconds(10), pipe);
        Assert.False(r.Success);
        Assert.Contains("未知指令", r.Message);
    }

    [Fact]
    public async Task Oversized_or_garbage_frame_is_refused_without_crashing_server()
    {
        var pipe = Pipe();
        using var server = Start(pipe);

        using (var client = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
        {
            await client.ConnectAsync(5000);
            await client.WriteAsync(BitConverter.GetBytes(int.MaxValue));
            await client.FlushAsync();
            var buf = new byte[4096];
            int n;
            try { n = await client.ReadAsync(buf); } catch { n = 0; }
            // 要么收到拒绝回应，要么被直接断开；无论哪种服务器都还活着
            if (n > 4) Assert.Contains("非法", System.Text.Encoding.UTF8.GetString(buf, 4, n - 4));
        }

        using (var client = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
        {
            await client.ConnectAsync(5000);
            var junk = System.Text.Encoding.UTF8.GetBytes("{not json");
            await client.WriteAsync(BitConverter.GetBytes(junk.Length));
            await client.WriteAsync(junk);
            await client.FlushAsync();
            var resp = await ElevationProtocol.ReadAsync<ElevationResponse>(client, default);
            Assert.NotNull(resp);
            Assert.False(resp!.Success);
        }

        var ping = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.Ping), TimeSpan.FromSeconds(10), pipe);
        Assert.True(ping.Success);
    }

    [Fact]
    public async Task Quarantine_purge_by_id_only_and_missing_id_refused()
    {
        var pipe = Pipe();
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        var ops = new ElevatedOperations(q, new OperationLog(_db), new RuleLoadResult(), new Whitelist(), _ => _t.Guard);
        using var server = Start(pipe, ops: ops);

        var file = _t.File("data/x.txt", "x");
        var entry = q.MoveIn(file, false, 1, "m", "b", "x");

        var missing = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem), TimeSpan.FromSeconds(10), pipe);
        Assert.False(missing.Success);

        var purge = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, entry.Id), TimeSpan.FromSeconds(10), pipe);
        Assert.True(purge.Success, purge.Message);
        Assert.False(File.Exists(entry.QuarantinePath));
        Assert.Empty(q.ListActive());

        var again = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.RestoreQuarantineItem, entry.Id), TimeSpan.FromSeconds(10), pipe);
        Assert.False(again.Success);
    }

    [Fact]
    public async Task Rule_clean_refuses_unknown_rule_and_runs_known_safe_rule()
    {
        var pipe = Pipe();
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        var ruleFile = _t.File("rules/t.json", """
            { "rules": [ { "id": "elev.test", "app": "T", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\ElevCache", "pattern": "*", "risk": "safe", "when": "always", "description": "c" },
                           { "path": "%LocalAppData%\\ElevKeep", "pattern": "*", "risk": "high", "when": "always", "description": "k" } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        Assert.Empty(rules.Rejected);
        _t.File(Path.Combine(_t.Vars["LocalAppData"], "ElevCache", "a.bin"), "1234");
        var keep = _t.File(Path.Combine(_t.Vars["LocalAppData"], "ElevKeep", "k.bin"), "1234");

        // 测试里的连接方 SID 对应真实用户配置文件，但规则用测试环境校验；guardFactory 固定返回测试护栏，环境用测试环境
        var ops = new TestOps(new ElevatedOperations(q, new OperationLog(_db), rules, new Whitelist(), _ => _t.Guard), _t);
        using var server = Start(pipe, ops: ops);

        var unknown = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "nope"), TimeSpan.FromSeconds(10), pipe);
        Assert.False(unknown.Success);

        var run = await ElevationClient.SendAsync(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "elev.test"), TimeSpan.FromSeconds(30), pipe);
        Assert.True(run.Success, run.Message);
        Assert.Single(q.ListActive());
        Assert.True(File.Exists(keep), "high 级目标不得被提权清理执行");
    }

    /// <summary>规则清理需要把路径按连接方展开；测试里把"连接方的环境"替换成 TestEnv。</summary>
    private sealed class TestOps : IElevatedOperations
    {
        private readonly ElevatedOperations _inner;
        private readonly TestEnv _t;
        public TestOps(ElevatedOperations inner, TestEnv t) { _inner = inner; _t = t; }

        public ElevationResponse Execute(ElevationRequest request, ElevationClientIdentity client, CancellationToken ct)
        {
            if (request.Operation != ElevatedOperation.RunRuleClean) return _inner.Execute(request, client, ct);
            return _inner.ExecuteRuleCleanWithEnvironment(request, _t.Env, _t.Guard, ct);
        }
    }

    [Fact]
    public void Pipe_security_denies_network_and_has_no_everyone_ace()
    {
        var server = new ElevationServer(new NullOps(), new ElevationServerOptions { AllowedClientSids = new HashSet<string> { MySid }, RequireSignedClient = false });
        var sec = server.BuildSecurity();
        var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        Assert.Contains(rules, r => r.IdentityReference is SecurityIdentifier s && s.IsWellKnown(WellKnownSidType.NetworkSid) && r.AccessControlType == System.Security.AccessControl.AccessControlType.Deny);
        Assert.DoesNotContain(rules, r => r.IdentityReference is SecurityIdentifier s && (s.IsWellKnown(WellKnownSidType.WorldSid) || s.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)) && r.AccessControlType == System.Security.AccessControl.AccessControlType.Allow);
        Assert.Contains(rules, r => r.IdentityReference is SecurityIdentifier s && s.Value == MySid);
    }

    private sealed class NullOps : IElevatedOperations
    {
        public ElevationResponse Execute(ElevationRequest request, ElevationClientIdentity client, CancellationToken ct) => new(true, "ok");
    }
}
