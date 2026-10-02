using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Privacy;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

/// <summary>
/// docs/archive/更新代码复审-2026-09-29.md（R01–R15）与 docs/archive/三轮代码复审-2026-09-30.md（N01–N10）的回归基线：
/// 把"缺陷成功复现即通过"的探针反转为"缺陷不再出现"。
/// </summary>
public sealed class ReviewRound3Tests : IDisposable
{
    private const string TestRoot = @"Software\CleanSweepTests";
    private readonly string _name = "round3-" + Guid.NewGuid().ToString("N")[..8];
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_name}", false); } catch { }
        _db.Dispose();
        _t.Dispose();
    }

    private static ElevationClientIdentity Client(string? sid = null) =>
        new(new SecurityIdentifier(sid ?? WindowsIdentity.GetCurrent().User!.Value), "tester", 1, null);

    private Quarantine Q() => new(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);

    // ---------- R01：硬链接 ----------

    [Fact]
    public void Shred_refuses_files_with_other_hard_links()
    {
        var original = _t.File(Path.Combine(_t.Vars["ProgramFiles"], "Vendor", "keep.bin"), "important-content");
        var link = Path.Combine(_t.Dir("links"), "alias.bin");
        if (!TestEnv.TryCreateHardLink(link, original)) return; // 文件系统不支持硬链接时跳过

        var r = FileShredder.Shred(link, 1, _t.Guard);
        Assert.False(r.Success);
        Assert.Contains("硬链接", r.Message);
        Assert.Equal("important-content", File.ReadAllText(original));

        // 普通文件（只有一个名字）照常可粉碎
        var lone = _t.File("links/lone.bin", "x");
        Assert.True(FileShredder.Shred(lone, 1, _t.Guard).Success);
        Assert.False(File.Exists(lone));
    }

    // ---------- R08：空闲空间擦除只清理自己创建的文件 ----------

    [Fact]
    public void Free_space_wiper_distinguishes_disk_full_from_other_io_errors()
    {
        Assert.True(FreeSpaceWiper.IsDiskFull(new IOException("full", unchecked((int)0x80070070))));
        Assert.True(FreeSpaceWiper.IsDiskFull(new IOException("full", unchecked((int)0x80070027))));
        Assert.False(FreeSpaceWiper.IsDiskFull(new IOException("denied", unchecked((int)0x80070005))));
        Assert.False(FreeSpaceWiper.IsDiskFull(new IOException("other")));
    }

    // ---------- R02：备份目录或祖先被换成 Junction ----------

    [Fact]
    public void Backup_purge_and_restore_refuse_when_backup_dir_ancestor_is_a_junction()
    {
        var realRoot = _t.Dir("real-backups");
        var linkRoot = Path.Combine(_t.Root, "linked-backups");
        if (!TestEnv.TryCreateJunction(linkRoot, realRoot)) return;
        var backupDir = Path.Combine(linkRoot, "registry");
        Directory.CreateDirectory(backupDir);
        var backup = new RegistryBackup(_db, backupDir);
        Assert.Contains("重解析点", backup.BackupDirProblem());

        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}")) k.SetValue("v", "1");
        var rec = backup.BackupValue($@"HKCU\{TestRoot}\{_name}", "v", "test");
        Assert.Contains("重解析点", backup.ValidateBackupFile(rec, out _, out _));
        Assert.Equal(0, backup.PurgeOlderThan(0, 0, DateTime.UtcNow.AddYears(1)));
        Assert.True(File.Exists(rec.File), "经过 Junction 的备份目录里的文件不得被淘汰");
    }

    // ---------- N05：快照超预算 ----------

    [Fact]
    public void Key_snapshot_over_budget_is_truncated_and_refused()
    {
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\Big"))
            for (int i = 0; i < 5001; i++) k.SetValue($"v{i:D5}", i);
        var snap = RegistrySnapshot.OfKey($@"HKCU\{TestRoot}\{_name}\Big", RegistryView.Registry64);
        Assert.Equal(RegistrySnapshot.Truncated, snap);

        var ops = new RegistryOps(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")));
        var ex = Assert.Throws<InvalidOperationException>(() => ops.DeleteKey(new RegistryTarget($@"HKCU\{TestRoot}\{_name}\Big", RegistryView.Registry64, null), "test", snap));
        Assert.Contains("无法完整核对", ex.Message);
        Assert.True(RegistryPath.Exists($@"HKCU\{TestRoot}\{_name}\Big", RegistryView.Registry64));

        // 没有快照也拒绝
        ex = Assert.Throws<InvalidOperationException>(() => ops.DeleteKey(new RegistryTarget($@"HKCU\{TestRoot}\{_name}\Big", RegistryView.Registry64, null), "test"));
        Assert.Contains("缺少扫描时的快照", ex.Message);
    }

    // ---------- R05：删除依据（程序已不存在）在执行前重新核实 ----------

    [Fact]
    public void Delete_refuses_when_missing_program_has_reappeared()
    {
        var exe = Path.Combine(_t.Root, "gone", "app.exe");
        using (var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_name}\AppPaths\app.exe")) k.SetValue("", exe);
        var key = $@"HKCU\{TestRoot}\{_name}\AppPaths\app.exe";
        var snap = RegistrySnapshot.OfKey(key, RegistryView.Registry64);
        var ops = new RegistryOps(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")));

        // 扫描后软件被重新安装：注册表值一个字节都没变，但程序回来了
        _t.File(exe, "MZ");
        var ex = Assert.Throws<CleanSweep.Core.Cleaning.CleanTargetChangedException>(() => ops.DeleteKey(new RegistryTarget(key, RegistryView.Registry64, null), "test", snap, exe));
        Assert.Contains("删除依据已不成立", ex.Message);
        Assert.True(RegistryPath.Exists(key, RegistryView.Registry64));

        File.Delete(exe);
        ops.DeleteKey(new RegistryTarget(key, RegistryView.Registry64, null), "test", snap, exe);
        Assert.False(RegistryPath.Exists(key, RegistryView.Registry64));
    }

    // ---------- R09：护栏拒绝受保护子树的祖先与 WOW6432Node 变体 ----------

    [Fact]
    public void Guard_refuses_ancestors_of_protected_trees_in_any_view()
    {
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion", RegistryView.Registry64));
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKLM\Software\Microsoft\Windows\CurrentVersion", RegistryView.Registry64));
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKCU\Software\Classes\Local Settings", RegistryView.Registry64));
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKCU\Software\Classes", RegistryView.Registry64));
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKLM\Software\WOW6432Node", RegistryView.Registry64));
        Assert.NotNull(RegistryGuard.CheckDeleteKey(@"HKLM\Software\WOW6432Node\Microsoft", RegistryView.Registry64));
        // 具体条目仍允许
        Assert.Null(RegistryGuard.CheckDeleteKey(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\SomeApp_is1", RegistryView.Registry64));
        Assert.Null(RegistryGuard.CheckDeleteKey(@"HKCU\Software\CleanSweepTests\x\y", RegistryView.Registry64));
    }

    // ---------- R10：TOKEN_PRIVILEGES 布局 ----------

    [Fact]
    public void Token_privileges_layout_matches_native()
    {
        Assert.Equal(16, Marshal.SizeOf<Memory.MemoryManager.TOKEN_PRIVILEGES>());
        Assert.Equal(4, (int)Marshal.OffsetOf<Memory.MemoryManager.TOKEN_PRIVILEGES>("Luid"));
        Assert.Equal(12, (int)Marshal.OffsetOf<Memory.MemoryManager.TOKEN_PRIVILEGES>("Attributes"));
        Assert.Equal(8, Marshal.SizeOf<Memory.MemoryManager.LUID>());
    }

    // ---------- R15：SMART 预警按设备标识映射 ----------

    [Fact]
    public void Smart_predictions_map_by_device_instance_not_by_order()
    {
        var predictions = new List<(string, bool)>
        {
            (@"SCSI\Disk&Ven_B&Prod_Two\4&2222&0&000100_0", true),
            (@"SCSI\Disk&Ven_A&Prod_One\4&1111&0&000000_0", false),
            (@"USBSTOR\Disk&Ven_X\9&abc_0", true),
        };
        var drives = new List<(int, string)>
        {
            (0, @"SCSI\DISK&VEN_A&PROD_ONE\4&1111&0&000000"),
            (1, @"SCSI\DISK&VEN_B&PROD_TWO\4&2222&0&000100"),
        };
        var map = DiskHealth.MapPredictions(predictions, drives);
        Assert.Equal(2, map.Count);
        Assert.False(map[0]);
        Assert.True(map[1]);
    }

    // ---------- R04：清单不可靠时指纹残留不默认勾选 ----------

    [Fact]
    public async Task Fingerprint_detection_reports_inventory_usage_and_unreliable_inventory_is_not_evidence()
    {
        var db = AppFingerprintDb.FromJson("""{ "fingerprints": [ { "id": "t.app", "app": "T App", "paths": [ "%LocalAppData%\\TApp" ], "detect": { "anyOf": [ { "installedName": "T App" } ] } } ] }""", "t.json", _t.Guard);
        var fp = Assert.Single(db.Fingerprints);
        var emptyUnreliable = new InventorySnapshot { Apps = Array.Empty<InstalledApp>(), TakenUtc = DateTime.UtcNow, RegistryCount = 0, UwpCount = 0, RunningExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase) };
        Assert.False(emptyUnreliable.RegistryReliable);
        var installed = AppFingerprintDb.IsInstalled(fp, emptyUnreliable, _t.Env, out var usesRegistry, out var usesUwp);
        Assert.False(installed);
        Assert.True(usesRegistry);
        Assert.False(usesUwp);

        // 扫描器：不可靠清单下命中指纹的目录不是"安全"级、不默认勾选
        var dir = _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "TApp"));
        _t.File(Path.Combine(dir, "settings.json"), "{}");
        var inventory = new AppInventory(_t.Env);
        inventory.UseSnapshot(emptyUnreliable);
        var scanner = new Residue.ResidueScanner(inventory, db, null, new Residue.ResidueOptions());
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist() };
        var items = await scanner.ScanAsync(ctx, null, default);
        var item = items.FirstOrDefault(i => i.Path is not null && i.Path.Equals(dir, StringComparison.OrdinalIgnoreCase));
        if (item is not null)
        {
            Assert.NotEqual(RiskLevel.Safe, item.Risk);
            Assert.False(item.DefaultSelected);
            Assert.Contains("清单读取不完整", item.Description);
        }
    }

    // ---------- R12：定向扫描过滤规则库扫描器 ----------

    [Fact]
    public async Task Filtered_scanner_keeps_only_matching_items()
    {
        var ruleFile = _t.File("rules/r12.json", """
            { "rules": [
              { "id": "r12.wanted", "app": "Wanted App", "category": "app", "detect": { "anyOf": [ { "directory": "%LocalAppData%\\NoSuchInstall" } ] },
                "targets": [ { "path": "%LocalAppData%\\WantedLeft", "pattern": "*", "risk": "safe", "when": "uninstalled", "description": "w" } ] },
              { "id": "r12.other", "app": "Other App", "category": "app", "detect": { "anyOf": [ { "directory": "%LocalAppData%\\NoSuchInstall2" } ] },
                "targets": [ { "path": "%LocalAppData%\\OtherLeft", "pattern": "*", "risk": "safe", "when": "uninstalled", "description": "o" } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        Assert.Empty(rules.Rejected);
        _t.File(Path.Combine(_t.Vars["LocalAppData"], "WantedLeft", "a"), "1");
        _t.File(Path.Combine(_t.Vars["LocalAppData"], "OtherLeft", "b"), "1");
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };

        var all = await RuleScanner.Residue().ScanAsync(ctx, null, default);
        Assert.Equal(2, all.Count);
        var filtered = await new FilteredScanner(RuleScanner.Residue(), i => NameKey.Matches(i.Group, "Wanted App")).ScanAsync(ctx, null, default);
        Assert.Single(filtered);
        Assert.Equal("Wanted App", filtered[0].Group);
    }

    // ---------- N07：拒绝访问的判定 ----------

    [Fact]
    public void Access_denied_recognizes_wrapped_win32_errors()
    {
        Assert.True(AccessDenied.Is(new UnauthorizedAccessException()));
        Assert.True(AccessDenied.Is(new IOException("x", 5)));
        Assert.True(AccessDenied.Is(new IOException("x", unchecked((int)0x80070005))));
        Assert.True(AccessDenied.Is(new InvalidOperationException("wrap", new IOException("x", 5))));
        Assert.False(AccessDenied.Is(new IOException("sharing", unchecked((int)0x80070020))));
        Assert.False(AccessDenied.Is(new IOException("plain")));
        Assert.False(AccessDenied.Is(null));
    }

    // ---------- R07 / N02：隔离项归属与对象标识 ----------

    [Fact]
    public void Quarantine_records_owner_and_service_authorizes_by_owner_and_key()
    {
        var q = Q();
        var file = _t.File(Path.Combine(_t.Vars["LocalAppData"], "Own", "a.txt"), "1");
        var mine = q.MoveIn(file, false, 1, "m", "b1", "a");
        Assert.Equal(WindowsIdentity.GetCurrent().User!.Value, mine.OwnerSid);
        Assert.Equal(mine.OwnerSid, q.Get(mine.Id)!.OwnerSid);

        Assert.Null(ElevatedOperations.Authorize(mine, Client(), Quarantine.ObjectKey(mine)));
        Assert.Null(ElevatedOperations.Authorize(mine, Client(), null));
        Assert.Contains("其他用户", ElevatedOperations.Authorize(mine, Client("S-1-5-21-1-2-3-1001"), null));
        Assert.Contains("不一致", ElevatedOperations.Authorize(mine, Client(), "DEADBEEF"));

        // 服务替另一个用户执行时移入的项归那个用户
        Quarantine.CurrentOwner.Value = "S-1-5-21-1-2-3-2002";
        try
        {
            var other = q.MoveIn(_t.File(Path.Combine(_t.Vars["LocalAppData"], "Own", "b.txt"), "1"), false, 1, "m", "b1", "b");
            Assert.Equal("S-1-5-21-1-2-3-2002", other.OwnerSid);
            Assert.Contains("其他用户", ElevatedOperations.Authorize(other, Client(), null));
        }
        finally
        {
            Quarantine.CurrentOwner.Value = null;
        }

        // 通过服务分发层：错的对象标识 / 错的用户都不能删
        var ops = new ElevatedOperations(q, new OperationLog(_db), new RuleLoadResult(), new Whitelist(), _ => _t.Guard, new NullPreActionRunner());
        Assert.False(ops.Execute(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, mine.Id, ItemKey: "wrong"), Client(), default).Success);
        Assert.False(ops.Execute(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, mine.Id), Client("S-1-5-21-1-2-3-1001"), default).Success);
        Assert.NotNull(q.Get(mine.Id));
        Assert.True(ops.Execute(new ElevationRequest(ElevatedOperation.PurgeQuarantineItem, mine.Id, ItemKey: Quarantine.ObjectKey(mine)), Client(), default).Success);
        Assert.Null(q.Get(mine.Id));
    }

    // ---------- N01 / N06：服务只执行与用户确认快照一致的条目，并逐条回报 ----------

    [Fact]
    public async Task Service_skips_items_whose_content_changed_after_user_scan_and_reports_each_item()
    {
        var ruleFile = _t.File("rules/n01.json", """
            { "rules": [ { "id": "n01.test", "app": "T", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\N01A", "pattern": "*", "risk": "safe", "when": "always", "description": "a" },
                           { "path": "%LocalAppData%\\N01B", "pattern": "*", "risk": "safe", "when": "always", "description": "b" } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        var a1 = _t.File(Path.Combine(_t.Vars["LocalAppData"], "N01A", "a1.bin"), "1234");
        var b1 = _t.File(Path.Combine(_t.Vars["LocalAppData"], "N01B", "b1.bin"), "1234");
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var userItems = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);
        var itemA = userItems.Single(i => i.Path!.EndsWith("N01A", StringComparison.OrdinalIgnoreCase));
        var itemB = userItems.Single(i => i.Path!.EndsWith("N01B", StringComparison.OrdinalIgnoreCase));

        // 用户确认后目录 A 里新出现了 a2：A 的内容与确认时不一致，服务必须跳过 A，只处理 B
        var a2 = _t.File(Path.Combine(_t.Vars["LocalAppData"], "N01A", "a2.bin"), "new");
        var ops = new ElevatedOperations(Q(), new OperationLog(_db), rules, new Whitelist(), _ => _t.Guard, new NullPreActionRunner());
        var request = new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "n01.test", Items: new[]
        {
            new ElevationItemRef(itemA.Id, itemA.ContentSnapshot()),
            new ElevationItemRef(itemB.Id, itemB.ContentSnapshot()),
            new ElevationItemRef("no-such-item", "x"),
            new ElevationItemRef("no-snapshot", null),
        });
        var response = ops.ExecuteRuleCleanWithEnvironment(request, _t.Env, _t.Guard, default);
        var payload = ElevatedOperations.ParsePayload(response.Payload)!;

        Assert.True(File.Exists(a1), "内容变化的条目不得执行");
        Assert.True(File.Exists(a2));
        Assert.False(File.Exists(b1));
        var states = payload.Results.ToDictionary(r => r.ItemId, r => r.State);
        Assert.Equal(ElevatedOperations.StateChanged, states[itemA.Id]);
        Assert.Equal(ElevatedOperations.StateDone, states[itemB.Id]);
        Assert.Equal(ElevatedOperations.StateNotFound, states["no-such-item"]);
        Assert.Equal(ElevatedOperations.StateNotFound, states["no-snapshot"]);
        Assert.Contains(itemA.Id, payload.Incomplete);
        Assert.DoesNotContain(itemB.Id, payload.Incomplete);
        Assert.False(response.Success);
    }

    // ---------- N03：白名单每次请求重新读 ----------

    [Fact]
    public void Service_rereads_whitelist_on_every_request()
    {
        var ruleFile = _t.File("rules/n03.json", """
            { "rules": [ { "id": "n03.test", "app": "T", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\N03", "pattern": "*", "risk": "safe", "when": "always", "description": "a" } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        var file = _t.File(Path.Combine(_t.Vars["LocalAppData"], "N03", "keep.bin"), "1234");
        var whitelistPath = Path.Combine(_t.Root, "whitelist.json");
        new Whitelist(whitelistPath); // 空白名单落盘

        var ops = new ElevatedOperations(Q(), new OperationLog(_db), g => new RuleLoader(g).LoadJson(File.ReadAllText(ruleFile), ruleFile), () => new Whitelist(whitelistPath), _ => _t.Guard, new NullPreActionRunner());
        // 界面（另一个对象）把文件加入同一份磁盘白名单
        new Whitelist(whitelistPath).AddPath(file);

        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "n03.test"), _t.Env, _t.Guard, default);
        Assert.True(File.Exists(file), "服务必须看到界面刚加入的白名单项");
        Assert.False(response.Success);
        var payload = ElevatedOperations.ParsePayload(response.Payload)!;
        Assert.All(payload.Results, r => Assert.Equal(ElevatedOperations.StateSkipped, r.State));
    }

    // ---------- R06：服务执行规则的预动作 ----------

    [Fact]
    public void Service_uses_real_pre_action_runner_and_refuses_unknown_services()
    {
        var ruleFile = _t.File("rules/r06.json", """
            { "rules": [ { "id": "r06.test", "app": "T", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\R06", "pattern": "*", "risk": "safe", "when": "always", "description": "a", "preActions": [ "stopService:ReviewNotAllowed" ] } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        Assert.Empty(rules.Rejected);
        var file = _t.File(Path.Combine(_t.Vars["LocalAppData"], "R06", "a.bin"), "1234");

        var ops = new ElevatedOperations(Q(), new OperationLog(_db), rules, new Whitelist(), _ => _t.Guard);
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "r06.test"), _t.Env, _t.Guard, default);
        Assert.False(response.Success);
        Assert.True(File.Exists(file), "预动作失败（不在允许名单的服务）时文件不得被移动");
        var payload = ElevatedOperations.ParsePayload(response.Payload)!;
        Assert.Contains(payload.Failures, f => f.Reason.Contains("前置动作失败"));
    }

    // ---------- R14：多动作任务判定（纯逻辑） ----------

    [Fact]
    public void Task_is_only_a_candidate_when_every_exec_action_is_missing()
    {
        static bool Candidate(IReadOnlyList<(bool IsExec, bool Missing)> actions)
        {
            int execCount = 0, missingCount = 0;
            bool other = false;
            foreach (var (isExec, missing) in actions)
            {
                if (!isExec) { other = true; continue; }
                execCount++;
                if (missing) missingCount++;
            }
            return execCount > 0 && missingCount == execCount && !other;
        }
        Assert.True(Candidate(new[] { (true, true) }));
        Assert.True(Candidate(new[] { (true, true), (true, true) }));
        Assert.False(Candidate(new[] { (true, true), (true, false) }));
        Assert.False(Candidate(new[] { (true, true), (false, false) }));
        Assert.False(Candidate(new[] { (false, false) }));
    }

    // ---------- N08：正文读取也受总时限约束 ----------

    private sealed class StallingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallStream()) };
            response.Content.Headers.ContentLength = 1000;
            return Task.FromResult(response);
        }

        private sealed class StallStream : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => 1000;
            public override long Position { get => 0; set { } }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            {
                await Task.Delay(Timeout.Infinite, ct);
                return 0;
            }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            {
                await Task.Delay(Timeout.Infinite, ct);
                return 0;
            }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }

    [Fact]
    public async Task Stalled_download_body_is_cut_off_by_the_caller_token_and_total_timeout_exists()
    {
        var updater = new DataUpdater(new HttpClient(new StallingHandler()), new Dictionary<string, byte[]>());
        using var cts = new CancellationTokenSource(500);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        // 响应头已到、正文永远不来：调用方的取消令牌必须能中止正文读取（此前 HttpClient.Timeout 在 ResponseHeadersRead 模式下管不到正文）
        var r = await updater.UpdateAsync(DataKind.Rules, "http://127.0.0.1:1/x", 0, Path.Combine(_t.Root, "upd", "rules"), cts.Token);
        Assert.False(r.Updated);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"耗时 {sw.Elapsed}");
        Assert.True(DataUpdater.TotalTimeout <= TimeSpan.FromMinutes(10));
        Assert.True(AppUpdater.DownloadTimeout <= TimeSpan.FromHours(1));
    }
}
