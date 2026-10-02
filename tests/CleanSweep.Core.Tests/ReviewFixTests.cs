using System.Security.AccessControl;
using System.Security.Principal;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 2026-09-29 全量审查（docs/archive/全量审查-2026-09-29.md）F02–F16 的回归基线：把审查工程里"复现缺陷即通过"的探针反转为"缺陷不再出现"。
/// </summary>
public sealed class ReviewFixTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private Quarantine Q => new(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);

    private static long InsertBackup(CleanSweepDb db, string file)
    {
        using var lease = db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "INSERT INTO registry_backups(ts,key_path,view,file,reason) VALUES($ts,'HKCU\\Software\\CleanSweepTests',64,$f,'review'); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.AddYears(-1).ToString("O"));
        cmd.Parameters.AddWithValue("$f", file);
        return (long)cmd.ExecuteScalar()!;
    }

    // ---------- F02 ----------

    [Fact]
    public void BackupPurge_NeverDeletesOutsideBackupDirectory()
    {
        var backup = new RegistryBackup(_db, _t.Dir("Backups"));
        var victim = _t.File("Outside/important.txt", "keep me");
        var id = InsertBackup(_db, victim);

        var removed = backup.PurgeOlderThan(1, 0);

        Assert.True(File.Exists(victim));
        Assert.Equal(1, removed);          // 被改过的记录本身删掉
        Assert.Null(backup.Get(id));
    }

    // ---------- F10 ----------

    [Fact]
    public void BackupPurge_KeepsRecordWhenFileCannotBeDeleted()
    {
        var backup = new RegistryBackup(_db, _t.Dir("Backups"));
        var file = _t.File("Backups/locked.reg");
        var id = InsertBackup(_db, file);
        using var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);

        Assert.Equal(0, backup.PurgeOlderThan(1, 0));
        Assert.True(File.Exists(file));
        Assert.NotNull(backup.Get(id));
    }

    // ---------- F03 ----------

    [Fact]
    public void TrustedDirectory_RemovesEveryoneWriteAccess()
    {
        var dir = _t.Dir("BroadAcl");
        if (!ProtectedDirectory.IsNtfs(dir)) return;
        var info = new DirectoryInfo(dir);
        var acl = info.GetAccessControl();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        acl.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
        Assert.NotNull(ProtectedDirectory.FindAclProblem(dir));

        ProtectedDirectory.EnsureTrusted(dir);

        Assert.Null(ProtectedDirectory.FindAclProblem(dir));
        Assert.DoesNotContain(info.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            r => r.IdentityReference == everyone && r.AccessControlType == AccessControlType.Allow);
    }

    // ---------- F04 ----------

    [Fact]
    public void QuarantineRestore_RefusesModifiedOriginalPath()
    {
        var q = Q;
        var source = _t.File("UserCache/payload.txt", "payload");
        var entry = q.MoveIn(source, false, 7, "review", "batch", "review");
        var target = Path.Combine(_t.Vars["Windir"], "System32", "review.txt");
        using (var lease = _db.Open())
        using (var cmd = lease.CreateCommand())
        {
            cmd.CommandText = "UPDATE quarantine_items SET original_path=$p WHERE id=$id";
            cmd.Parameters.AddWithValue("$p", target);
            cmd.Parameters.AddWithValue("$id", entry.Id);
            cmd.ExecuteNonQuery();
        }

        var ex = Assert.Throws<InvalidOperationException>(() => q.Restore(entry.Id));
        Assert.Contains("不一致", ex.Message);
        Assert.False(File.Exists(target));
        Assert.True(File.Exists(entry.QuarantinePath));
    }

    [Fact]
    public void QuarantineRestore_RefusesProtectedTargetEvenWhenMetaAgrees()
    {
        // 元数据与索引一致但目标在 Windows\System32：护栏兜底
        var q = Q;
        var source = _t.File("UserCache/payload2.txt", "payload");
        var entry = q.MoveIn(source, false, 7, "review", "batch", "review");
        var target = Path.Combine(_t.Vars["Windir"], "System32", "review2.txt");
        using (var lease = _db.Open())
        using (var cmd = lease.CreateCommand())
        {
            cmd.CommandText = "UPDATE quarantine_items SET original_path=$p WHERE id=$id";
            cmd.Parameters.AddWithValue("$p", target);
            cmd.Parameters.AddWithValue("$id", entry.Id);
            cmd.ExecuteNonQuery();
        }
        var metaFile = entry.QuarantinePath + Quarantine.MetaSuffix;
        var metaText = File.ReadAllText(metaFile);
        var from = PathGuard.Normalize(source).Replace("\\", "\\\\");
        Assert.Contains(from, metaText);
        File.WriteAllText(metaFile, metaText.Replace(from, target.Replace("\\", "\\\\")));

        var ex = Assert.Throws<InvalidOperationException>(() => q.Restore(entry.Id));
        Assert.Contains("护栏", ex.Message);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void RestoreTargetCheck_AllowsStartupFolderButNotHiveOrWindows()
    {
        var g = _t.Guard;
        Assert.True(g.CheckRestoreTarget(Path.Combine(_t.Vars["AppData"], @"Microsoft\Windows\Start Menu\Programs\Startup\x.lnk")).Allowed);
        Assert.True(g.CheckRestoreTarget(Path.Combine(_t.Vars["LocalAppData"], @"Foo\a.txt")).Allowed);
        Assert.True(g.CheckRestoreTarget(Path.Combine(_t.Vars["Windir"], @"Temp\a.txt")).Allowed);
        Assert.False(g.CheckRestoreTarget(Path.Combine(_t.Vars["Windir"], @"System32\a.dll")).Allowed);
        Assert.False(g.CheckRestoreTarget(Path.Combine(_t.Vars["ProgramFiles"], @"App\a.exe")).Allowed);
        Assert.False(g.CheckRestoreTarget(Path.Combine(_t.Vars["UserProfile"], "NTUSER.DAT")).Allowed);
        Assert.False(g.CheckRestoreTarget(Path.Combine(_t.Vars["AppData"], @"Microsoft\Crypto\x")).Allowed);
    }

    // ---------- F07 ----------

    [Fact]
    public async Task DirectorySnapshot_DetectsSameSizeChangeToOlderFile()
    {
        var dir = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "ReviewCache"));
        var newest = _t.File(Path.Combine(dir, "new.txt"), "aaaa");
        var older = _t.File(Path.Combine(dir, "old.txt"), "bbbb");
        var now = DateTime.UtcNow;
        File.SetLastWriteTimeUtc(newest, now);
        File.SetLastWriteTimeUtc(older, now.AddDays(-2));

        var (size, count, last, fp) = _t.Guard.FingerprintDirectory(dir);
        var item = new ScanItem
        {
            Id = "dir", ModuleId = "review", Group = "review", DisplayName = "review", Kind = ItemKind.Directory, Path = dir,
            SizeBytes = size, LastWriteUtc = last, DirectoryFingerprint = fp, DirectoryFileCount = count,
        };

        File.WriteAllText(older, "cccc");
        File.SetLastWriteTimeUtc(older, now.AddDays(-1));

        var q = Q;
        var report = await new CleanEngine(_t.Guard, q, new OperationLog(_db), new NullPreActionRunner()).CleanAsync(new[] { item }, null, default);

        Assert.Single(report.Failures);
        Assert.Contains("发生变化", report.Failures[0].Reason);
        Assert.True(Directory.Exists(dir));
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public async Task RuleScanner_DirectoryItemsCarryFingerprint()
    {
        var dir = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "FpApp"));
        _t.File(Path.Combine(dir, "a.txt"), "1");
        var rules = new RuleLoader(_t.Guard).LoadJson("""
            { "rules": [ { "id": "fp", "app": "Fp", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\FpApp", "kind": "directory", "risk": "safe", "when": "always", "description": "d" } ] } ] }
            """, "t.json");
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var item = Assert.Single(await RuleScanner.SystemJunk().ScanAsync(ctx, null, default));
        Assert.NotNull(item.DirectoryFingerprint);
        Assert.Equal(1, item.DirectoryFileCount);
    }

    // ---------- F11 ----------

    [Fact]
    public void SignatureCache_IsInvalidatedWhenFileReplaced()
    {
        var file = Path.Combine(_t.Root, "copy.exe");
        File.Copy(Path.Combine(System.Environment.SystemDirectory, "cmd.exe"), file);
        var before = FileSignature.Inspect(file);
        if (!before.IsMicrosoft) return; // 无法验证系统签名的环境（离线 catalog 缺失）不做断言

        File.WriteAllText(file, "unsigned replacement");
        Assert.False(FileSignature.Inspect(file).IsMicrosoft);
    }

    // ---------- F08 ----------

    [Fact]
    public void DelayedTaskNames_AreUniquePerItem()
    {
        StartupItem Make(string name, string location) => new()
        {
            Id = RuleScanner.MakeId("RegistryRun", location, name), Kind = StartupKind.RegistryRun, Scope = StartupScope.CurrentUser,
            Name = name, Location = location, Handle = new StartupHandle(),
        };
        Assert.NotEqual(StartupManager.DelayedTaskName(Make("Product/A", "HKCU")), StartupManager.DelayedTaskName(Make("Product\\A", "HKCU")));
        Assert.NotEqual(StartupManager.DelayedTaskName(Make("Same", "HKCU")), StartupManager.DelayedTaskName(Make("Same", "HKLM")));
        Assert.NotEqual(StartupManager.DelayedTaskName(Make(new string('x', 60) + "A", "HKCU")), StartupManager.DelayedTaskName(Make(new string('x', 60) + "B", "HKCU")));
        Assert.DoesNotContain(StartupManager.DelayedTaskName(Make("a/b:c", "HKCU")), new[] { '/', ':' }.Select(c => c.ToString()), StringComparer.Ordinal);
    }

    // ---------- F13 ----------

    [Fact]
    public async Task CancelDuringFileSet_StopsBetweenFilesAndReportsCancelled()
    {
        using var cts = new CancellationTokenSource();
        var files = Enumerable.Range(0, 4).Select(i =>
        {
            var path = _t.File(Path.Combine(_t.Vars["LocalAppData"], "CancelReview", i + ".txt"));
            var fi = new FileInfo(path);
            return new FileEntry(path, fi.Length, fi.LastWriteTimeUtc);
        }).ToArray();
        // 第一次解析隔离区根（即第一个文件移入时）触发取消
        var q = new Quarantine(_db, null, _ => { cts.Cancel(); return Path.Combine(_t.Root, "Q"); });
        var log = new OperationLog(_db);
        var item = new ScanItem { Id = "cancel", ModuleId = "review", Group = "review", DisplayName = "review", Files = files, SizeBytes = files.Sum(f => f.Size) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new CleanEngine(_t.Guard, q, log, new NullPreActionRunner()).CleanAsync(new[] { item }, null, cts.Token));

        var moved = files.Count(f => !File.Exists(f.Path));
        Assert.Equal(1, moved);
        Assert.NotNull(log.GetRecentBatches().Single().FinishedUtc); // 批次已关闭，不会被当成半完成批次
    }

    [Fact]
    public async Task Report_KeepsItemsWithSkippedFilesIncomplete()
    {
        var a = _t.File(Path.Combine(_t.Vars["LocalAppData"], "Skip", "a.txt"), "1");
        var b = _t.File(Path.Combine(_t.Vars["LocalAppData"], "Skip", "b.txt"), "2");
        var fa = new FileInfo(a);
        var fb = new FileInfo(b);
        var item = new ScanItem
        {
            Id = "skip", ModuleId = "review", Group = "g", DisplayName = "d", Path = Path.GetDirectoryName(a),
            Files = new[] { new FileEntry(a, fa.Length, fa.LastWriteTimeUtc), new FileEntry(b, fb.Length, fb.LastWriteTimeUtc) }, SizeBytes = 2,
        };
        File.WriteAllText(b, "22"); // 扫描后变化 → 跳过

        var report = await new CleanEngine(_t.Guard, Q, new OperationLog(_db), new NullPreActionRunner()).CleanAsync(new[] { item }, null, default);

        Assert.Equal(1, report.FilesQuarantined);
        Assert.Equal(1, report.Skipped);
        Assert.Empty(report.Failures);
        Assert.Contains("skip", report.IncompleteItemIds);
        Assert.False(report.Outcomes["skip"].Complete);
    }

    // ---------- F14 ----------

    [Fact]
    public async Task BundledServiceTempRules_SkipFreshFiles()
    {
        var path = _t.File(Path.Combine(_t.Vars["Windir"], @"ServiceProfiles\LocalService\AppData\Local\Temp\new.tmp"));
        var loaded = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "rules/system.json")), "system.json");
        Assert.Empty(loaded.Rejected);
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = loaded.Rules.Where(r => r.Id == "windows.temp").ToList() };

        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);

        Assert.DoesNotContain(items, i => i.Files.Any(f => f.Path == path));
    }

    [Fact]
    public void Loader_ForcesMinimumAgeOnTempDirectories()
    {
        var loaded = new RuleLoader(_t.Guard).LoadJson("""
            { "rules": [ { "id": "x", "app": "X", "category": "system",
              "targets": [
                { "path": "%LocalAppData%\\Foo\\Temp", "pattern": "*", "risk": "safe", "when": "always", "description": "t" },
                { "path": "%LocalAppData%\\Foo\\Cache", "pattern": "*", "risk": "safe", "when": "always", "description": "c" } ] } ] }
            """, "t.json");
        Assert.Empty(loaded.Rejected);
        var rule = Assert.Single(loaded.Rules);
        Assert.Equal(1, rule.Targets[0].MinAgeDays);
        Assert.Equal(0, rule.Targets[1].MinAgeDays);
        Assert.True(RuleLoader.IsTempDirectory(@"C:\Users\x\AppData\Local\Temp"));
        Assert.False(RuleLoader.IsTempDirectory(@"C:\Users\x\AppData\Local\Temp\CleanSweepTests\abc"));
    }

    // ---------- F06 ----------

    [Fact]
    public async Task DuplicateGroupHash_RevealsSameSizeContentChange()
    {
        var dir = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "DuplicateReview"));
        var keeper = _t.File(Path.Combine(dir, "keep.txt"), "original");
        _t.File(Path.Combine(dir, "remove.txt"), "original");
        var group = Assert.Single(await new DuplicateFinder(_t.Guard).FindAsync(new[] { dir }, 0, null, default));

        Assert.Equal(group.Hash, DuplicateFinder.ComputeGroupHash(keeper), ignoreCase: true);
        File.WriteAllText(keeper, "modified");
        Assert.NotEqual(group.Hash, DuplicateFinder.ComputeGroupHash(keeper), StringComparer.OrdinalIgnoreCase);
    }

    // ---------- 观察项：裸可执行文件名解析 ----------

    [Fact]
    public void CommandLine_ResolvesBareSystemExecutables()
    {
        var (exe, args) = CommandLine.Split("rundll32.exe foo.dll,Entry");
        Assert.NotNull(exe);
        Assert.True(Path.IsPathRooted(exe));
        Assert.True(File.Exists(exe));
        Assert.Equal("foo.dll,Entry", args);
    }
}

/// <summary>F05 / F09：注册表备份的绑定与操作级撤销。使用 HKCU\Software\CleanSweepTests 下的临时键。</summary>
public sealed class ReviewRegistryFixTests : IDisposable
{
    private const string TestRoot = @"Software\CleanSweepTests";
    private readonly string _keyName = "review-" + Guid.NewGuid().ToString("N")[..8];
    private readonly string _keyPath;
    private readonly string _dir;
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private readonly RegistryBackup _backup;

    public ReviewRegistryFixTests()
    {
        _keyPath = $@"HKCU\{TestRoot}\{_keyName}";
        _dir = Path.Combine(Path.GetTempPath(), "CleanSweepTests", "regfix-" + _keyName);
        _backup = new RegistryBackup(_db, _dir);
        using var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_keyName}");
        k.SetValue("Marker", "original");
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_keyName}", false); } catch { }
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void Sql(string sql, long id, string value)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$p", value);
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    // ---------- F05 ----------

    [Fact]
    public void Restore_RefusesWhenIndexAndFileBothRedirected()
    {
        var record = _backup.Backup(_keyPath, "review");
        var target = _keyPath + @"\DifferentTarget";
        File.WriteAllText(record.File,
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\" + TestRoot + "\\" + _keyName + "\\DifferentTarget]\r\n\"Marker\"=\"redirected\"\r\n",
            System.Text.Encoding.Unicode);
        Sql("UPDATE registry_backups SET key_path=$p WHERE id=$id", record.Id, target);

        var ex = Assert.Throws<InvalidOperationException>(() => _backup.Restore(record.Id));
        Assert.Contains("不一致", ex.Message);
        Assert.False(RegistryPath.Exists(target, RegistryView.Registry64));
    }

    [Fact]
    public void Restore_RefusesWhenSidecarMissing()
    {
        var record = _backup.Backup(_keyPath, "review");
        File.Delete(record.File + RegistryBackup.MetaSuffix);
        Assert.Throws<InvalidOperationException>(() => _backup.Restore(record.Id));
    }

    [Fact]
    public void Restore_RefusesRecordPointingToFileWithSameNameElsewhere()
    {
        // 索引里的 file 列被改成备份目录之外的同名文件：路径只能由"备份目录 + 文件名"推导，改过就拒绝
        var record = _backup.Backup(_keyPath, "review");
        var elsewhere = Path.Combine(Path.GetTempPath(), "CleanSweepTests", "elsewhere-" + _keyName);
        Directory.CreateDirectory(elsewhere);
        var copy = Path.Combine(elsewhere, Path.GetFileName(record.File));
        File.Copy(record.File, copy);
        File.Copy(record.File + RegistryBackup.MetaSuffix, copy + RegistryBackup.MetaSuffix);
        try
        {
            Sql("UPDATE registry_backups SET file=$p WHERE id=$id", record.Id, copy);
            var ex = Assert.Throws<InvalidOperationException>(() => _backup.Restore(record.Id));
            Assert.Contains("备份目录", ex.Message);
        }
        finally
        {
            try { Directory.Delete(elsewhere, true); } catch { }
        }
    }

    // ---------- F09 ----------

    [Fact]
    public void ValueBackup_UndoesFirstCreationOfValue()
    {
        // 值原本不存在 → 备份删除标记 → 本程序写入 → 还原后值消失
        var rec = _backup.BackupValue(_keyPath, "Approved", "test");
        Assert.Equal("Approved", rec.ValueName);
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}", true)!)
            k.SetValue("Approved", new byte[] { 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);

        _backup.Restore(rec.Id);

        using var check = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}")!;
        Assert.Null(check.GetValue("Approved"));
        Assert.Equal("original", check.GetValue("Marker")); // 其他值不受影响
    }

    [Theory]
    [InlineData(RegistryValueKind.String)]
    [InlineData(RegistryValueKind.ExpandString)]
    [InlineData(RegistryValueKind.DWord)]
    [InlineData(RegistryValueKind.QWord)]
    [InlineData(RegistryValueKind.Binary)]
    [InlineData(RegistryValueKind.MultiString)]
    public void ValueBackup_RestoresOriginalDataOfEveryKind(RegistryValueKind kind)
    {
        object original = kind switch
        {
            RegistryValueKind.String => "héllo \"quoted\" \\ back",
            RegistryValueKind.ExpandString => "%SystemRoot%\\x",
            RegistryValueKind.DWord => 0x12345678,
            RegistryValueKind.QWord => 0x1122334455667788L,
            RegistryValueKind.Binary => Enumerable.Range(0, 70).Select(i => (byte)i).ToArray(),
            _ => new[] { "a", "b c", "" },
        };
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}", true)!)
            k.SetValue("V", original, kind);

        var rec = _backup.BackupValue(_keyPath, "V", "test");
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}", true)!)
            k.DeleteValue("V");

        _backup.Restore(rec.Id);

        using var check = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}")!;
        Assert.Equal(kind, check.GetValueKind("V"));
        var restored = check.GetValue("V", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (original is byte[] ob) Assert.Equal(ob, (byte[])restored!);
        else if (original is string[] os) Assert.Equal(os.Where(s => s.Length > 0), ((string[])restored!).Where(s => s.Length > 0)); // 空串段的处理各版本 reg.exe 不同，只比较非空段
        else Assert.Equal(original, restored);
    }

    [Fact]
    public void StartupDisable_ThenRestore_RemovesApprovedValueCreatedByUs()
    {
        using var t = new TestEnv();
        var manager = new StartupManager(t.Env, _backup, new RestorePointService(),
            new Quarantine(_db, null, _ => Path.Combine(t.Root, "Q")), new OperationLog(_db));
        var item = new StartupItem
        {
            Id = "review", Kind = StartupKind.RegistryRun, Scope = StartupScope.CurrentUser, Name = "ReviewOnly", Location = "test", Enabled = true,
            Handle = new StartupHandle(ApprovedKey: _keyPath, ValueName: "ReviewOnly"),
        };

        Assert.True(manager.SetEnabled(item, false).Success);
        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}")!)
            Assert.Equal(3, ((byte[])k.GetValue("ReviewOnly")!)[0]);

        _backup.Restore(_backup.List().Single().Id);

        using var restored = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}")!;
        Assert.Null(restored.GetValue("ReviewOnly"));
    }
}
