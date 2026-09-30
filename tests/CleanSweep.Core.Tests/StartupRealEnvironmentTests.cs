using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;
using Xunit.Abstractions;

namespace CleanSweep.Core.Tests;

/// <summary>在真实机器上只读扫描启动项：任何来源都不得抛异常写入日志，且各来源都能枚举。</summary>
public class StartupRealEnvironmentTests
{
    private readonly ITestOutputHelper _out;

    public StartupRealEnvironmentTests(ITestOutputHelper output)
    {
        _out = output;
    }

    [Fact]
    public void Scan_real_machine_reports_no_source_errors()
    {
        var dir = Path.Combine(Path.GetTempPath(), "CleanSweepTests", "startup-" + Guid.NewGuid().ToString("N"));
        using var db = CleanSweepDb.InMemory();
        var log = new OperationLog(db);
        var manager = new StartupManager(new CurrentUserEnvironmentResolver(), new RegistryBackup(db, dir), new RestorePointService(), new Quarantine(db), log);
        try
        {
            var items = manager.Scan(includeMicrosoft: true);

            foreach (var g in items.GroupBy(i => i.Kind).OrderBy(g => g.Key))
                _out.WriteLine($"{g.Key}: {g.Count()} 项，已启用 {g.Count(i => i.Enabled)}");
            foreach (var i in items.Where(i => i.Kind is StartupKind.ScheduledTask or StartupKind.UwpStartupTask).Take(15))
                _out.WriteLine($"  [{i.Kind}] {i.Name} | {i.Location} | {i.Publisher} | {i.Signature} | {i.Note}");

            // 单项跳过（scan-skip，如非管理员无权读某个服务的键）允许；整个来源失败（scan）不允许
            var failures = log.GetOperations().Where(o => !o.Success).ToList();
            foreach (var e in failures) _out.WriteLine($"{e.Action} {e.Target}: {e.Message}");
            Assert.DoesNotContain(failures, f => f.Action == "scan");

            // 每台 Windows 机器至少有一些 Microsoft 计划任务带登录 / 开机触发器，以及注册表 Run 项
            Assert.Contains(items, i => i.Kind == StartupKind.ScheduledTask);
            Assert.Contains(items, i => i.Kind == StartupKind.RegistryRun);
            Assert.Contains(items, i => i.Kind == StartupKind.Service);

            // Id 唯一
            Assert.Equal(items.Count, items.Select(i => i.Id).Distinct().Count());
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}
