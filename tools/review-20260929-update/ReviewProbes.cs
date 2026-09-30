using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Memory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Privacy;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

// PASS means that the defect was reproduced. No real system cleanup is executed.
public sealed class UpdateReviewProbes
{
    [Fact]
    public void Repro_ShredHardLink_DestroysUnselectedProtectedFile()
    {
        using var t = new TestEnv();
        var original = t.File(Path.Combine(t.Vars["ProgramFiles"], "ReviewApp", "important.bin"), "must survive");
        var alias = Path.Combine(t.Dir("UserData"), "alias.bin");
        Assert.True(TestEnv.TryCreateHardLink(alias, original));
        Assert.False(t.Guard.Check(original).Allowed);
        var result = FileShredder.Shred(alias, 1, t.Guard);
        Assert.True(result.Success, result.Message);
        Assert.True(File.Exists(original));
        Assert.Equal(0, new FileInfo(original).Length);
    }

    [Fact]
    public void Repro_BackupPurge_FollowsBackupRootJunction()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var root = t.Dir("Backups");
        var backup = new RegistryBackup(db, root);
        var elsewhere = t.Dir("Elsewhere");
        var victim = t.File(Path.Combine(elsewhere, "victim.reg"), "keep");
        Directory.Delete(root);
        Assert.True(TestEnv.TryCreateJunction(root, elsewhere));
        try
        {
            using (var lease = db.Open())
            using (var cmd = lease.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO registry_backups(ts,key_path,view,file,reason) VALUES($ts,'HKCU\\Software\\Review',64,$file,'review')";
                cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.AddYears(-1).ToString("O"));
                cmd.Parameters.AddWithValue("$file", Path.Combine(root, "victim.reg"));
                cmd.ExecuteNonQuery();
            }
            Assert.Equal(1, backup.PurgeOlderThan(1, 0));
            Assert.False(File.Exists(victim));
        }
        finally { Directory.Delete(root); }
    }

    [Fact]
    public void Repro_BackupRestore_AllThreeWritableCopiesCanBeForged()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var sub = @"Software\CleanSweepReviewUpdate\" + Guid.NewGuid().ToString("N");
        try
        {
            using (var k = Registry.CurrentUser.CreateSubKey(sub + @"\Original")) k.SetValue("V", "original");
            var backup = new RegistryBackup(db, t.Dir("Backups"));
            var rec = backup.Backup("HKCU\\" + sub + "\\Original", "review");
            var target = sub + "\\DifferentTarget";
            File.WriteAllText(rec.File, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\" + target + "]\r\n\"V\"=\"redirected\"\r\n", Encoding.Unicode);
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(rec.File)));
            var metaPath = rec.File + RegistryBackup.MetaSuffix;
            var meta = JsonNode.Parse(File.ReadAllText(metaPath))!;
            meta["KeyPath"] = "HKCU\\" + target;
            meta["Sha256"] = hash;
            File.WriteAllText(metaPath, meta.ToJsonString());
            using (var lease = db.Open())
            using (var cmd = lease.CreateCommand())
            {
                cmd.CommandText = "UPDATE registry_backups SET key_path=$p,sha256=$h WHERE id=$id";
                cmd.Parameters.AddWithValue("$p", "HKCU\\" + target);
                cmd.Parameters.AddWithValue("$h", hash);
                cmd.Parameters.AddWithValue("$id", rec.Id);
                cmd.ExecuteNonQuery();
            }
            backup.Restore(rec.Id);
            using var check = Registry.CurrentUser.OpenSubKey(target);
            Assert.Equal("redirected", check!.GetValue("V"));
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(sub, false); }
    }

    [Fact]
    public async Task Repro_ElevationRuleClean_IgnoresRequiredServicePreAction()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var ruleFile = t.File("rules/test.json", """
            { "rules": [{ "id":"review", "app":"Review", "category":"system", "targets":[
              {"path":"%LocalAppData%\\ReviewCache", "risk":"safe", "preActions":["stopService:ReviewNotAllowed"]}
            ]}] }
            """);
        var file = t.File(Path.Combine(t.Vars["LocalAppData"], "ReviewCache", "important.txt"));
        var rules = new RuleLoader(t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        Assert.Empty(rules.Rejected);
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"), t.Guard);
        var ops = new ElevatedOperations(q, new OperationLog(db), rules, new Whitelist());
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "review"), t.Env, t.Guard, default);
        Assert.True(response.Success);
        Assert.False(File.Exists(file));
        Assert.Single(q.ListActive());
    }

    [Fact]
    public void Repro_ElevationPurge_DoesNotCheckItemOwner()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"), t.Guard);
        var entry = q.MoveIn(t.File("OtherUser/private.txt"), false, 5, "review", "batch", "private");
        var ops = new ElevatedOperations(q, new OperationLog(db), new RuleLoadResult(), new Whitelist());
        var unrelated = new ElevationClientIdentity(new SecurityIdentifier("S-1-5-21-101-202-303-1001"), "review-other-user", 123, null);
        var result = ops.Execute(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, entry.Id), unrelated, default);
        Assert.True(result.Success);
        Assert.False(File.Exists(entry.QuarantinePath));
    }

    [Theory]
    [InlineData(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion")]
    [InlineData(@"HKCU\Software\Classes\Local Settings")]
    public void Repro_RegistryGuard_AllowsDeletingAncestorsOfProtectedKeys(string key)
    {
        Assert.Null(RegistryGuard.CheckDeleteKey(key, RegistryView.Registry64));
    }

    [Fact]
    public async Task Repro_RegistryCleaning_DeletesRepairedEntryFromStaleScan()
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var sub = @"Software\CleanSweepReviewUpdate\" + Guid.NewGuid().ToString("N");
        var root = "HKCU\\" + sub;
        try
        {
            var exe = Path.Combine(t.Root, "App", "app.exe");
            using (var k = Registry.CurrentUser.CreateSubKey(sub + @"\AppPaths\app.exe")) k.SetValue("", exe);
            var inventory = new AppInventory(t.Env);
            inventory.UseSnapshot(EmptyInventory());
            var options = new RegistryCleanerOptions { UninstallKeys = new(), MuiCacheKeys = new(), SoftwareRoots = new(), ClassesRoots = new(),
                AppPathsKeys = new() { (root + "\\AppPaths", RegistryView.Registry64) }, IncludeServices = false, IncludeTasks = false,
                IncludeShortcuts = false, IncludeCom = false, IncludeSharedDlls = false };
            var scanner = new RegistryCleanerScanner(inventory, null, options);
            var ctx = new ScanContext { Env = t.Env, Guard = t.Guard, Whitelist = new Whitelist() };
            var items = await scanner.ScanAsync(ctx, null, default);
            Assert.Single(items);
            t.File(exe, "reinstalled");
            var backup = new RegistryBackup(db, t.Dir("Backups"));
            var q = new Quarantine(db, null, _ => Path.Combine(t.Root, "Q"), t.Guard);
            var engine = new CleanEngine(t.Guard, q, new OperationLog(db), new NullPreActionRunner(), registry: new RegistryOps(backup));
            var report = await engine.CleanAsync(items, null, default);
            Assert.Empty(report.Failures);
            Assert.Equal(1, report.RegistryEntriesRemoved);
            using var gone = Registry.CurrentUser.OpenSubKey(sub + @"\AppPaths\app.exe");
            Assert.Null(gone);
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(sub, false); }
    }

    [Fact]
    public async Task Repro_Residue_UnreliableInventoryStillDefaultsFingerprintToSafe()
    {
        using var t = new TestEnv();
        var data = t.File(Path.Combine(t.Vars["AppData"], "ReviewApp", "settings.json"), "valuable settings");
        var fp = AppFingerprintDb.FromJson("""
            {"fingerprints":[{"id":"review","app":"ReviewApp","paths":["%AppData%\\ReviewApp"],
            "detect":{"anyOf":[{"installedName":"ReviewApp"}]}}]}
            """, "review", t.Guard);
        Assert.Empty(fp.Rejected);
        var inventory = new AppInventory(t.Env);
        inventory.UseSnapshot(EmptyInventory());
        Assert.False(inventory.Last!.RegistryReliable);
        var scanner = new ResidueScanner(inventory, fp, null, new ResidueOptions());
        var items = await scanner.ScanAsync(new ScanContext { Env = t.Env, Guard = t.Guard, Whitelist = new Whitelist() }, null, default);
        var item = Assert.Single(items);
        Assert.True(item.DefaultSelected);
        Assert.Equal(Path.GetDirectoryName(data), item.Path);
    }

    [Fact]
    public void Repro_TokenPrivileges_ManagedLayoutHasWrongLuidOffset()
    {
        var type = typeof(MemoryManager).GetNestedType("TOKEN_PRIVILEGES", BindingFlags.NonPublic)!;
        Assert.Equal(8, Marshal.OffsetOf(type, "Luid").ToInt32());
        Assert.Equal(16, Marshal.OffsetOf(type, "Attributes").ToInt32());
        Assert.Equal(24, Marshal.SizeOf(type));
    }

    private static InventorySnapshot EmptyInventory() => new() { Apps = Array.Empty<InstalledApp>(), TakenUtc = DateTime.UtcNow,
        RegistryCount = 0, UwpCount = 0, RunningExecutables = new HashSet<string>() };

    [Fact]
    public async Task Repro_SystemCommand_UserCancellationDisablesTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var result = await SystemCommand.RunAsync("ping.exe", "-n 4 127.0.0.1", TimeSpan.FromMilliseconds(700), cts.Token);
        Assert.False(result.TimedOut);
        Assert.True(result.Elapsed > TimeSpan.FromSeconds(2), result.Elapsed.ToString());
        Assert.True(result.Success);
    }

    [Fact]
    public async Task Repro_TargetedResidueScan_RuleScannerIncludesUnrelatedApplication()
    {
        using var t = new TestEnv();
        t.File(Path.Combine(t.Vars["AppData"], "UnrelatedApp", "settings.json"));
        var rules = new RuleLoader(t.Guard).LoadJson("""
            {"rules":[{"id":"unrelated","app":"UnrelatedApp","category":"app",
              "detect":{"anyOf":[{"file":"%LocalAppData%\\MissingApplication.exe"}]},
              "targets":[{"path":"%AppData%\\UnrelatedApp","when":"uninstalled","risk":"safe"}]}]}
            """, "review");
        Assert.Empty(rules.Rejected);
        var inventory = new AppInventory(t.Env);
        inventory.UseSnapshot(EmptyInventory());
        var options = new ResidueOptions { OnlyAppName = "RequestedApp" };
        var heuristic = new ResidueScanner(inventory, new AppFingerprintDb(), null, options);
        var ctx = new ScanContext { Env = t.Env, Guard = t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var heuristicItems = await heuristic.ScanAsync(ctx, null, default);
        var ruleItems = await RuleScanner.Residue().ScanAsync(ctx, null, default);
        Assert.Empty(heuristicItems);
        var unrelated = Assert.Single(ruleItems);
        Assert.Equal("UnrelatedApp", unrelated.Group);
        Assert.True(unrelated.DefaultSelected);
    }
}
