using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Settings;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

public sealed class CleanReportDetailsTests : IDisposable
{
    private readonly TestEnv _env = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private CleanEngine Engine(Whitelist? whitelist = null, RegistryOps? registry = null) => new(_env.Guard,
        new Quarantine(_db, null, _ => Path.Combine(_env.Root, "Q")), new OperationLog(_db), new NullPreActionRunner(), whitelist, registry);

    private ScanItem Item(string id)
    {
        var path = _env.File(Path.Combine(_env.Vars["LocalAppData"], "ReportTest", id + ".tmp"));
        var f = new FileInfo(path);
        return new ScanItem { Id = id, ModuleId = "test", Group = "test", DisplayName = id, Kind = ItemKind.FileSet,
            Path = f.DirectoryName, Files = [new(path, f.Length, f.LastWriteTimeUtc)] };
    }

    [Fact]
    public async Task Changed_missing_and_whitelisted_files_have_distinct_details()
    {
        var changed = Item("changed");
        var missing = Item("missing");
        var excluded = Item("excluded");
        File.AppendAllText(changed.Files[0].Path, "longer");
        File.Delete(missing.Files[0].Path);
        var whitelist = new Whitelist(Path.Combine(_env.Root, "whitelist.json"));
        whitelist.AddItem(excluded.Id);
        var result = await Engine(whitelist).CleanAsync([changed, missing, excluded], null, default);
        Assert.Equal(3, result.Skipped);
        Assert.Empty(result.Failures);
        Assert.Equal(CleanIssueKind.Changed, Assert.Single(result.SkippedDetails, f => f.ItemId == changed.Id).Kind);
        Assert.Equal(CleanIssueKind.AlreadyAbsent, Assert.Single(result.SkippedDetails, f => f.ItemId == missing.Id).Kind);
        Assert.Equal(CleanIssueKind.Excluded, Assert.Single(result.SkippedDetails, f => f.ItemId == excluded.Id).Kind);
        Assert.True(File.Exists(changed.Files[0].Path));
        Assert.True(File.Exists(excluded.Files[0].Path));
    }

    [Fact]
    public async Task Locked_file_is_in_use_not_a_failure()
    {
        var item = Item("locked");
        using var locked = File.Open(item.Files[0].Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var result = await Engine().CleanAsync([item], null, default);
        Assert.Empty(result.Failures);
        Assert.Equal(CleanIssueKind.InUse, Assert.Single(result.InUseFiles).Kind);
        Assert.True(File.Exists(item.Files[0].Path));
    }

    [Fact]
    public async Task Cancellation_preserves_successful_outcomes_and_unprocessed_items()
    {
        var first = Item("first");
        var second = Item("second");
        using var cancel = new CancellationTokenSource();
        var progress = new InlineProgress(p => { if (p.Done == 1) cancel.Cancel(); });
        var error = await Assert.ThrowsAsync<CleanCancelledException>(() => Engine().CleanAsync([first, second], progress, cancel.Token));
        Assert.True(error.Report.Cancelled);
        Assert.Equal(1, error.Report.FilesQuarantined);
        Assert.Equal(1, error.Report.Outcomes[first.Id].Succeeded);
        Assert.True(error.Report.Outcomes[second.Id].Untouched);
        Assert.False(File.Exists(first.Files[0].Path));
        Assert.True(File.Exists(second.Files[0].Path));
        Assert.NotNull(new OperationLog(_db).GetRecentBatches()[0].FinishedUtc);
    }

    [Fact]
    public async Task Backup_failure_keeps_registry_value_and_reports_backup_category()
    {
        var key = @"Software\CleanSweepReportTests\" + Guid.NewGuid().ToString("N");
        try
        {
            using (var k = Registry.CurrentUser.CreateSubKey(key)) k.SetValue("value", "keep");
            var backupPath = Path.Combine(_env.Root, "backups");
            var backup = new RegistryBackup(_db, backupPath);
            Directory.Delete(backupPath);
            File.WriteAllText(backupPath, "blocks creating directory");
            var target = new RegistryTarget(@"HKCU\" + key, RegistryView.Registry64, "value");
            var item = new ScanItem { Id = "registry", ModuleId = "test", Group = "test", DisplayName = "registry",
                Kind = ItemKind.RegistryValue, Registry = target,
                TargetSnapshot = RegistrySnapshot.OfValue(target.KeyPath, target.View, target.ValueName!) };
            var result = await Engine(registry: new RegistryOps(backup)).CleanAsync([item], null, default);
            Assert.Equal(CleanIssueKind.BackupFailed, Assert.Single(result.Failures).Kind);
            using var remaining = Registry.CurrentUser.OpenSubKey(key);
            Assert.Equal("keep", remaining!.GetValue("value"));
            Assert.Equal(0, result.RegistryEntriesRemoved);
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(key, false); }
    }

    [Fact]
    public void Permission_classification_uses_types_and_codes_not_error_words()
    {
        Assert.Equal(CleanIssueKind.Permission, CleanIssueClassifier.FromException(new UnauthorizedAccessException("different language")));
        Assert.Equal(CleanIssueKind.Permission, CleanIssueClassifier.FromException(new System.ComponentModel.Win32Exception(5)));
        Assert.Equal(CleanIssueKind.Failure, CleanIssueClassifier.FromException(new IOException("权限不足")));
        Assert.Equal(CleanIssueKind.BackupFailed, CleanIssueClassifier.FromException(new CleanBackupException("backup", new UnauthorizedAccessException())));
    }

    [Fact]
    public void Service_payload_accepts_previous_version_without_category()
    {
        var payload = Core.Elevation.ElevatedOperations.ParsePayload("""
            {"QuarantinedBytes":0,"Files":0,"Directories":0,
             "Results":[{"ItemId":"item","State":"skipped","Reason":"old reason"}],"Failures":[]}
            """);
        Assert.NotNull(payload);
        Assert.Null(Assert.Single(payload.Results).Kind);
        Assert.Equal("old reason", payload.Results[0].Reason);
    }

    private sealed class InlineProgress(Action<CleanProgress> report) : IProgress<CleanProgress>
    {
        public void Report(CleanProgress value) => report(value);
    }
    public void Dispose() { _db.Dispose(); _env.Dispose(); }
}
