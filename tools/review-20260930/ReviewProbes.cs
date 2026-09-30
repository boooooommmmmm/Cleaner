using System.Security.Principal;
using System.Security.AccessControl;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Model;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

// PASS in Repro_ means the defect was reproduced. All payloads are disposable test data.
public sealed class ThirdRoundProbes
{
    [Fact]
    public void Repro_AppUpdate_StagedExecutableCanChangeAfterVerification()
    {
        using var t = new TestEnv();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var package = t.Dir("package");
        t.File(Path.Combine(package, "CleanSweep.exe"), "verified executable bytes");
        foreach (var kind in new[] { "rules", "fingerprints", "popups" })
        {
            var dir = t.Dir(Path.Combine(package, kind));
            t.File(Path.Combine(dir, "a.json"), "{}");
            SignedManifest.Sign(dir, kind, 1, key, "review");
        }
        var zip = Path.Combine(t.Root, "release.zip");
        System.IO.Compression.ZipFile.CreateFromDirectory(package, zip);
        var release = ReleaseManifest.Sign("0.15.0", zip, "https://review.invalid/release.zip", "", key, "review");
        var keys = new Dictionary<string, byte[]> { ["review"] = key.ExportSubjectPublicKeyInfo() };
        Assert.NotNull(ReleaseManifest.Verify(release, keys, out _));
        Assert.Equal(release.Sha256, SignedManifest.HashFile(zip));
        var stage = Path.Combine(t.Root, "stage");
        var updater = new AppUpdater(trustedKeys: keys);
        Assert.Null(updater.Stage(zip, stage));
        File.WriteAllText(Path.Combine(stage, "CleanSweep.exe"), "replaced after verification");
        var install = t.Dir("install");
        Assert.Null(AppUpdater.CopyDirectory(stage, install));
        Assert.Equal("replaced after verification", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
    }

    [Fact]
    public void Repro_AppUpdate_MirrorDeletesFilesOutsideInstallThroughJunction()
    {
        using var t = new TestEnv();
        var source = t.Dir("update-source");
        var target = t.Dir("install");
        var outside = t.Dir("unrelated-data");
        t.File(Path.Combine(source, "CleanSweep.exe"), "new");
        t.File(Path.Combine(target, "CleanSweep.exe"), "old");
        var victim = t.File(Path.Combine(outside, "user-data.txt"), "outside installation");
        var link = Path.Combine(target, "linked-data");
        Assert.True(TestEnv.TryCreateJunction(link, outside));
        try
        {
            Assert.Null(AppUpdater.CopyDirectory(source, target));
            Assert.False(File.Exists(victim));
        }
        finally { Directory.Delete(link, false); }
    }

    [Fact]
    public void Repro_AppUpdate_LockedLaterFileLeavesEarlierFileReplaced()
    {
        using var t = new TestEnv();
        var source = t.Dir("update-source");
        var target = t.Dir("install");
        t.File(Path.Combine(source, "first.dll"), "new-first");
        t.File(Path.Combine(source, "second.dll"), "new-second");
        var order = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).ToList();
        var first = Path.Combine(target, Path.GetFileName(order[0]));
        var second = Path.Combine(target, Path.GetFileName(order[1]));
        File.WriteAllText(first, "old-first");
        File.WriteAllText(second, "old-second");
        using var held = new FileStream(second, FileMode.Open, FileAccess.Read, FileShare.Read);
        var result = AppUpdater.CopyDirectory(source, target);
        Assert.NotNull(result);
        Assert.Equal(File.ReadAllText(order[0]), File.ReadAllText(first));
        Assert.Equal("old-second", File.ReadAllText(second));
    }

    private static RuleLoadResult Rules(TestEnv t)
    {
        var file = t.File("rules/review.json", """
            {"rules":[{"id":"review","app":"Review","category":"system","targets":[
              {"path":"%LocalAppData%\\ReviewCache","risk":"safe","when":"always","pattern":"*"}
            ]}]}
            """);
        var rules = new RuleLoader(t.Guard).LoadJson(File.ReadAllText(file), file);
        Assert.Empty(rules.Rejected);
        return rules;
    }

    private static Quarantine Q(TestEnv t, CleanSweepDb db) => new(db, null, _ => Path.Combine(t.Root, "Q"), t.Guard);

    [Fact]
    public async Task Repro_ServiceRescan_MovesFilesCreatedAfterUserScan()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var original = t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "original.txt"));
        var rules = Rules(t);
        var items = await RuleScanner.SystemJunk().ScanAsync(new ScanContext { Env=t.Env, Guard=t.Guard, Whitelist=new Whitelist(), Rules=rules.Rules }, null, default);
        var selected = Assert.Single(items);
        Assert.Single(selected.Files!);
        var added = t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "new-after-confirmation.txt"), "not part of the confirmed snapshot");
        var q = Q(t, db);
        var ops = new ElevatedOperations(q, new OperationLog(db), rules, new Whitelist());
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId:"review", ItemIds:new[] {selected.Id}), t.Env, t.Guard, default);
        Assert.True(response.Success);
        Assert.False(File.Exists(original));
        Assert.False(File.Exists(added));
        Assert.Equal(2, q.ListActive().Count);
    }

    [Fact]
    public void Repro_ServiceUsesStaleWhitelist_AfterUiAddsPath()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var rules = Rules(t);
        var path = t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "keep.txt"));
        var storage = Path.Combine(t.Root, "whitelist.json");
        var serviceWhitelist = new Whitelist(storage);
        var uiWhitelist = new Whitelist(storage);
        uiWhitelist.AddPath(path);
        Assert.True(new Whitelist(storage).IsPathExcluded(path));
        var ops = new ElevatedOperations(Q(t, db), new OperationLog(db), rules, serviceWhitelist);
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId:"review"), t.Env, t.Guard, default);
        Assert.True(response.Success);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Repro_SeparateIndexes_ForwardedNumericIdPurgesDifferentFile()
    {
        using var t = new TestEnv();
        using var guiDb = CleanSweepDb.InMemory();
        using var serviceDb = CleanSweepDb.InMemory();
        var guiQ = Q(t, guiDb);
        var serviceQ = Q(t, serviceDb);
        var a = guiQ.MoveIn(t.File("data/user-selected.txt"), false, 5, "review", "gui-batch", "A");
        var b = serviceQ.MoveIn(t.File("data/unrelated.txt"), false, 5, "review", "service-batch", "B");
        Assert.Equal(a.Id, b.Id);
        Assert.NotEqual(a.OriginalPath, b.OriginalPath);
        var ops = new ElevatedOperations(serviceQ, new OperationLog(serviceDb), new RuleLoadResult(), new Whitelist());
        var client = new ElevationClientIdentity(WindowsIdentity.GetCurrent().User!, "same user", System.Environment.ProcessId, null);
        var response = ops.Execute(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, ItemId:a.Id), client, default);
        Assert.True(response.Success);
        Assert.True(File.Exists(a.QuarantinePath));
        Assert.False(File.Exists(b.QuarantinePath));
    }

    [Fact]
    public async Task Repro_UnknownRequestedItem_IsAbsentFromIncompletePayload()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var rules = Rules(t);
        t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "a.txt"));
        var scanned = await RuleScanner.SystemJunk().ScanAsync(new ScanContext { Env=t.Env, Guard=t.Guard, Whitelist=new Whitelist(), Rules=rules.Rules }, null, default);
        var selected = Assert.Single(scanned);
        var ops = new ElevatedOperations(Q(t, db), new OperationLog(db), rules, new Whitelist());
        const string disappearedId = "requested-but-no-longer-emitted";
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId:"review", ItemIds:new[] {selected.Id, disappearedId}), t.Env, t.Guard, default);
        var payload = ElevatedOperations.ParsePayload(response.Payload)!;
        Assert.NotNull(payload);
        Assert.True(response.Success);
        Assert.Equal(1, payload.Files);
        Assert.DoesNotContain(disappearedId, payload.Incomplete);
        // ElevationContext.RunViaServiceAsync treats this expression as completion.
        Assert.True(!payload.Incomplete.Contains(disappearedId));
    }

    [Fact]
    public void Repro_RegistrySnapshot_TruncationHidesChangedValue()
    {
        var sub = @"Software\CleanSweepReview20260930\" + Guid.NewGuid().ToString("N");
        try
        {
            using (var k = Registry.CurrentUser.CreateSubKey(sub))
                for (var i=0; i<5001; i++) k.SetValue($"v{i:D5}", "before");
            var path = "HKCU\\" + sub;
            var before = RegistrySnapshot.OfKey(path, RegistryView.Registry64);
            Assert.NotNull(before);
            using (var k = Registry.CurrentUser.OpenSubKey(sub, true)!) k.SetValue("v05000", "changed after scan");
            var after = RegistrySnapshot.OfKey(path, RegistryView.Registry64);
            Assert.Equal(before, after);
            Assert.True(RegistrySnapshot.Matches(before, after));
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(sub, false); }
    }

    [Fact]
    public async Task Repro_BulkScope_BlocksServiceIndexWriteAfterPayloadDeletion()
    {
        using var t = new TestEnv();
        var dbPath = Path.Combine(t.Root, "shared.db");
        using var guiDb = new CleanSweepDb(dbPath);
        using var serviceDb = new CleanSweepDb(dbPath);
        var q = Q(t, serviceDb);
        var entry = q.MoveIn(t.File("data/payload.txt"), false, 5, "review", "batch", "payload");
        var bulk = guiDb.BeginBulk();
        Task? purging = null;
        try
        {
            purging = Task.Run(() => q.Purge(entry.Id));
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (File.Exists(entry.QuarantinePath) && DateTime.UtcNow < deadline) await Task.Delay(20);
            Assert.False(File.Exists(entry.QuarantinePath));
            await Task.Delay(150);
            Assert.False(purging.IsCompleted, "service waits for GUI transaction although file is already gone");
        }
        finally
        {
            bulk.Dispose();
            if (purging is not null) await purging.WaitAsync(TimeSpan.FromSeconds(10));
        }
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public void Repro_MoveAccessDenied_IsNotTheExceptionCaughtByServiceFallback()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var source = new FileInfo(t.File("source/blocked.txt"));
        var parent = source.Directory!;
        var originalFileAcl = source.GetAccessControl();
        var originalDirAcl = parent.GetAccessControl();
        var sid = WindowsIdentity.GetCurrent().User!;
        try
        {
            var fileAcl = source.GetAccessControl();
            fileAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.Delete, AccessControlType.Deny));
            source.SetAccessControl(fileAcl);
            var dirAcl = parent.GetAccessControl();
            dirAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Deny));
            parent.SetAccessControl(dirAcl);
            var error = Record.Exception(() => Q(t, db).MoveIn(source.FullName, false, source.Length, "review", "batch", "blocked"));
            var io = Assert.IsType<IOException>(error);
            Assert.Equal(5, io.HResult);
            Assert.False(error is UnauthorizedAccessException);
            Assert.True(source.Exists);
        }
        finally
        {
            source.SetAccessControl(originalFileAcl);
            parent.SetAccessControl(originalDirAcl);
        }
    }

    [Fact]
    public async Task Repro_DataUpdate_BodyReadOutlivesHttpTimeout()
    {
        using var t = new TestEnv();
        using var stream = new StalledStream();
        using var http = new HttpClient(new ReplyHandler(stream)) { Timeout=TimeSpan.FromMilliseconds(50) };
        using var cts = new CancellationTokenSource();
        var updater = new DataUpdater(http);
        var updating = updater.UpdateAsync(DataKind.Rules, "https://review.invalid", 1, Path.Combine(t.Root, "updates", "rules"), cts.Token);
        try
        {
            await stream.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await Task.Delay(300);
            Assert.False(updating.IsCompleted, "the body has no timeout despite HttpClient.Timeout");
        }
        finally
        {
            cts.Cancel();
            await updating.WaitAsync(TimeSpan.FromSeconds(2));
        }
    }

    private sealed class ReplyHandler(Stream stream) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content=new StreamContent(stream) });
    }

    private sealed class StalledStream : MemoryStream
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    [Fact]
    public async Task Regression_UserCancellation_PreservesCommandTimeout()
    {
        using var cts = new CancellationTokenSource(100);
        var result = await SystemCommand.RunAsync("ping.exe", "-n 4 127.0.0.1", TimeSpan.FromMilliseconds(700), cts.Token);
        Assert.True(result.TimedOut);
        Assert.False(result.Success);
    }

    [Fact]
    public void Regression_VerifiedRuleBytes_AreNotReopenedAfterTampering()
    {
        using var t = new TestEnv();
        var rules = Rules(t);
        var source = rules.Rules.Single().SourceFile;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SignedManifest.Sign(Path.GetDirectoryName(source)!, "rules", 1, key, "review");
        var keys = new Dictionary<string, byte[]> { ["review"]=key.ExportSubjectPublicKeyInfo() };
        var verdict = SignedManifest.Verify(Path.GetDirectoryName(source)!, "rules", keys);
        Assert.True(verdict.Ok);
        File.WriteAllText(source, "this is no longer signed JSON");
        var loaded = new RuleLoader(t.Guard).LoadContents(verdict.Contents);
        Assert.Single(loaded.Rules);
        Assert.Empty(loaded.Rejected);
        Assert.False(SignedManifest.Verify(Path.GetDirectoryName(source)!, "rules", keys).Ok);
    }
}
