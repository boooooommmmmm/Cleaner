using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using CleanSweep.App.Services;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

// These tests PASS when the reviewed defect is reproduced. They are not safety regression tests.
public sealed class ReviewProbes
{
    private static long InsertBackup(CleanSweepDb db, string file)
    {
        using var lease = db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "INSERT INTO registry_backups(ts,key_path,view,file,reason) VALUES($ts,'HKCU\\Software\\CleanSweepReview',64,$f,'review'); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.AddYears(-1).ToString("O"));
        cmd.Parameters.AddWithValue("$f", file);
        return (long)cmd.ExecuteScalar()!;
    }

    [Fact]
    public void Repro_BackupPurge_DeletesOutsideBackupDirectory()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var backup = new RegistryBackup(db, t.Dir("Backups"));
        var victim = t.File("Outside/important.txt", "keep me");
        InsertBackup(db, victim);
        Assert.Equal(1, backup.PurgeOlderThan(1, 0));
        Assert.False(File.Exists(victim));
    }

    [Fact]
    public void Repro_BackupPurge_DropsRecordWhenDeletionFails()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var backup = new RegistryBackup(db, t.Dir("Backups"));
        var file = t.File("Backups/locked.reg");
        var id = InsertBackup(db, file);
        using var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.Equal(1, backup.PurgeOlderThan(1, 0));
        Assert.True(File.Exists(file));
        Assert.Null(backup.Get(id));
    }

    [Fact]
    public void Repro_TrustedDirectory_AcceptsEveryoneModify()
    {
        using var t = new TestEnv();
        var dir = t.Dir("BroadAcl");
        var info = new DirectoryInfo(dir);
        var acl = info.GetAccessControl();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        acl.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
        ProtectedDirectory.EnsureTrusted(dir);
        Assert.Contains(info.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>(), r => r.IdentityReference == everyone
            && r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & FileSystemRights.WriteData) != 0);
    }

    [Fact]
    public void Repro_QuarantineRestore_TrustsModifiedOriginalPath()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"));
        var source = t.File("UserCache/payload.txt", "payload");
        var entry = q.MoveIn(source, false, 7, "review", "batch", "review");
        var target = Path.Combine(t.Vars["Windir"], "System32", "review.txt");
        Assert.False(t.Guard.Check(target).Allowed);
        using (var lease = db.Open())
        using (var cmd = lease.CreateCommand())
        {
            cmd.CommandText = "UPDATE quarantine_items SET original_path=$p WHERE id=$id";
            cmd.Parameters.AddWithValue("$p", target);
            cmd.Parameters.AddWithValue("$id", entry.Id);
            cmd.ExecuteNonQuery();
        }
        Assert.Equal(target, q.Restore(entry.Id));
        Assert.Equal("payload", File.ReadAllText(target));
    }

    [Fact]
    public async Task Repro_DirectorySnapshot_MissesSameSizeChangeToOlderFile()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var dir = t.Dir(Path.Combine(t.Vars["LocalAppData"], "ReviewCache"));
        var newest = t.File(Path.Combine(dir, "new.txt"), "aaaa");
        var older = t.File(Path.Combine(dir, "old.txt"), "bbbb");
        var now = DateTime.UtcNow;
        File.SetLastWriteTimeUtc(newest, now);
        File.SetLastWriteTimeUtc(older, now.AddDays(-2));
        var snap = t.Guard.MeasureDirectory(dir);
        var item = new ScanItem { Id = "dir", ModuleId = "review", Group = "review", DisplayName = "review",
            Kind = ItemKind.Directory, Path = dir, SizeBytes = snap.Size, LastWriteUtc = snap.LastWriteUtc };
        File.WriteAllText(older, "cccc");
        File.SetLastWriteTimeUtc(older, now.AddDays(-1));
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"));
        var engine = new CleanEngine(t.Guard, q, new OperationLog(db), new NullPreActionRunner());
        var report = await engine.CleanAsync(new[] { item }, null, default);
        Assert.Empty(report.Failures);
        Assert.Equal(1, report.DirectoriesQuarantined);
        Assert.False(Directory.Exists(dir));
        Assert.Equal("cccc", File.ReadAllText(Path.Combine(q.ListActive().Single().QuarantinePath, "old.txt")));
    }

    [Fact]
    public void Repro_SignatureCache_RemainsMicrosoftAfterReplacement()
    {
        using var t = new TestEnv();
        var file = Path.Combine(t.Root, "copy.exe");
        File.Copy(Path.Combine(System.Environment.SystemDirectory, "cmd.exe"), file);
        var before = FileSignature.Inspect(file);
        Assert.True(before.IsMicrosoft);
        File.WriteAllText(file, "unsigned replacement");
        var fresh = t.File("fresh.exe", "unsigned replacement");
        Assert.False(FileSignature.Inspect(fresh).IsMicrosoft);
        Assert.True(FileSignature.Inspect(file).IsMicrosoft);
    }

    [Fact]
    public void Repro_DelayedTaskNames_Collide()
    {
        var method = typeof(StartupManager).GetMethod("SanitizeTaskName", BindingFlags.Static | BindingFlags.NonPublic)!;
        string Name(string value) => (string)method.Invoke(null, new object[] { value })!;
        Assert.Equal(Name("Product/A"), Name("Product\\A"));
        Assert.Equal(Name(new string('x', 60) + "A"), Name(new string('x', 60) + "B"));
    }

    [Fact]
    public void Repro_Settings_NullRootsSurviveValidation()
    {
        using var t = new TestEnv();
        var file = t.File("settings.json", "{\"DuplicateRoots\":null}");
        var settings = AppSettings.Load(file);
        Assert.Null(settings.DuplicateRoots);
        Assert.Throws<ArgumentNullException>(() => settings.DuplicateRoots!.Where(Directory.Exists).ToList());
    }

    [Fact]
    public void Repro_StartupBackup_DoesNotUndoFirstDisable()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var sub = @"Software\CleanSweepReview\" + Guid.NewGuid().ToString("N");
        try
        {
            using (var key = Registry.CurrentUser.CreateSubKey(sub)) key.SetValue("ExistingMarker", "keep");
            var backup = new RegistryBackup(db, t.Dir("Backups"));
            var manager = new StartupManager(t.Env, backup, new RestorePointService(),
                new Quarantine(db, null, _ => Path.Combine(t.Root, "Q")), new OperationLog(db));
            var item = new StartupItem { Id = "review", Kind = StartupKind.RegistryRun, Scope = StartupScope.CurrentUser,
                Name = "ReviewOnly", Location = "test", Enabled = true,
                Handle = new StartupHandle(ApprovedKey: "HKCU\\" + sub, ValueName: "ReviewOnly") };
            Assert.True(manager.SetEnabled(item, false).Success);
            backup.Restore(backup.List().Single().Id);
            using var restored = Registry.CurrentUser.OpenSubKey(sub);
            var value = Assert.IsType<byte[]>(restored!.GetValue("ReviewOnly"));
            Assert.Equal(3, value[0]);
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(sub, false); }
    }

    [Fact]
    public async Task Repro_DuplicateKeeper_SameSizeDifferentContentPassesUiPredicate()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var dir = t.Dir(Path.Combine(t.Vars["LocalAppData"], "DuplicateReview"));
        var keeper = t.File(Path.Combine(dir, "keep.txt"), "original");
        var selected = t.File(Path.Combine(dir, "remove.txt"), "original");
        var groups = await new DuplicateFinder(t.Guard).FindAsync(new[] { dir }, 0, null, default);
        var group = Assert.Single(groups);
        var keeperEntry = group.Files.Single(f => f.Path == keeper);
        File.WriteAllText(keeper, "modified");
        // Exact retained-copy predicate in DuplicatesViewModel; UI dialog itself is not driven.
        var fi = new FileInfo(keeper);
        Assert.True(fi.Exists && fi.Length == keeperEntry.Size);
        var selectedEntry = group.Files.Single(f => f.Path == selected);
        var item = new ScanItem { Id = "dup", ModuleId = "duplicates", Group = "review", DisplayName = "review",
            Files = new[] { selectedEntry }, SizeBytes = selectedEntry.Size };
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"));
        var result = await new CleanEngine(t.Guard, q, new OperationLog(db), new NullPreActionRunner())
            .CleanAsync(new[] { item }, null, default);
        Assert.Equal(1, result.FilesQuarantined);
        Assert.False(File.Exists(selected));
        Assert.Equal("modified", File.ReadAllText(keeper));
    }

    [Fact]
    public async Task Repro_CancelDuringFileSet_ContinuesAllFilesAndReportsSuccess()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        using var cts = new CancellationTokenSource();
        var files = Enumerable.Range(0, 4).Select(i =>
        {
            var path = t.File(Path.Combine(t.Vars["LocalAppData"], "CancelReview", i + ".txt"));
            var fi = new FileInfo(path);
            return new FileEntry(path, fi.Length, fi.LastWriteTimeUtc);
        }).ToArray();
        var q = new Quarantine(db, null, _ => { cts.Cancel(); return Path.Combine(t.Root, "Q"); });
        var log = new OperationLog(db);
        var item = new ScanItem { Id = "cancel", ModuleId = "review", Group = "review", DisplayName = "review",
            Files = files, SizeBytes = files.Sum(f => f.Size) };
        var result = await new CleanEngine(t.Guard, q, log, new NullPreActionRunner())
            .CleanAsync(new[] { item }, null, cts.Token);
        Assert.True(cts.IsCancellationRequested);
        Assert.Equal(4, result.FilesQuarantined);
        Assert.Equal(0, result.FreedBytes);
        Assert.Equal(result.QuarantinedBytes, log.GetRecentBatches().Single().FreedBytes);
    }

    [Fact]
    public async Task Repro_ServiceTempRule_SelectsNewFileByDefault()
    {
        using var t = new TestEnv();
        var path = t.File(Path.Combine(t.Vars["Windir"], @"ServiceProfiles\LocalService\AppData\Local\Temp\new.tmp"));
        var loaded = new RuleLoader(t.Guard).LoadJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "rules/system.json")), "system.json");
        Assert.Empty(loaded.Rejected);
        var ctx = new ScanContext { Env = t.Env, Guard = t.Guard, Whitelist = new Whitelist(),
            Rules = loaded.Rules.Where(r => r.Id == "windows.temp").ToList() };
        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);
        Assert.Contains(items, i => i.DefaultSelected && i.Files.Any(f => f.Path == path));
    }

    [Fact]
    public void Repro_RegistryRestore_ModifiedRecordAndFileRedirectImport()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var sub = @"Software\CleanSweepReview\" + Guid.NewGuid().ToString("N");
        try
        {
            using (var key = Registry.CurrentUser.CreateSubKey(sub + @"\Original")) key.SetValue("Marker", "original");
            var backup = new RegistryBackup(db, t.Dir("Backups"));
            var record = backup.Backup("HKCU\\" + sub + "\\Original", "review");
            var target = sub + "\\DifferentTarget";
            File.WriteAllText(record.File, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\" + target + "]\r\n\"Marker\"=\"redirected\"\r\n", System.Text.Encoding.Unicode);
            using (var lease = db.Open())
            using (var cmd = lease.CreateCommand())
            {
                cmd.CommandText = "UPDATE registry_backups SET key_path=$p WHERE id=$id";
                cmd.Parameters.AddWithValue("$p", "HKCU\\" + target);
                cmd.Parameters.AddWithValue("$id", record.Id);
                cmd.ExecuteNonQuery();
            }
            backup.Restore(record.Id);
            using var check = Registry.CurrentUser.OpenSubKey(target);
            Assert.Equal("redirected", check!.GetValue("Marker"));
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(sub, false); }
    }
}
