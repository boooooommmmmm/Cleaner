using CleanSweep.Core.SysInfo;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class ReviewOctoberTests
{
    [Fact]
    public void Service_preserves_in_use_reason_for_locked_files()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var file = t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "locked.dat"));
        var rule = t.File("rules/review.json", """
            {"rules":[{"id":"review.locked","app":"Review","category":"system","targets":[
                {"path":"%LocalAppData%\\ReviewCache","risk":"safe","when":"always","pattern":"*"}
            ]}]}
            """);
        var rules = new RuleLoader(t.Guard).LoadFiles(new[] { rule });
        Assert.Empty(rules.Rejected);
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"), t.Guard);
        var ops = new ElevatedOperations(q, new OperationLog(db), rules, new Whitelist());
        using var locked = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None);
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "review.locked"), t.Env, t.Guard, default);
        var payload = ElevatedOperations.ParsePayload(response.Payload)!;
        var result = Assert.Single(payload.Results);
        Assert.Equal(ElevatedOperations.StateSkipped, result.State);
        Assert.Contains("正在被其他程序使用", result.Reason);
        Assert.True(File.Exists(file));
        Assert.Empty(q.ListActive());
    }

    [Theory]
    [InlineData(1201, false)]
    [InlineData(1202, true)]
    public void Memory_diagnostic_warning_uses_event_result_not_the_word_error(int eventId, bool warning)
    {
        var result = HardwareStatus.DescribeMemoryDiagnostic(eventId, DateTime.UtcNow);
        Assert.NotNull(result);
        Assert.Contains("错误", result.Text); // Both positive and negative messages contain this word.
        Assert.Equal(warning, result.HasErrors);
    }

    [Fact]
    public void Unknown_memory_diagnostic_is_not_reported_as_healthy()
        => Assert.Null(HardwareStatus.DescribeMemoryDiagnostic(9999, null));
}
