using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Popup;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 发布前横切工作的回归：界面切普通权限（权限判定、提权服务按条目 ID 执行）、数据集签名清单、在线更新。
/// </summary>
public sealed class ReleaseWorkTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    // ---------- 权限判定 ----------

    [Fact]
    public void Requires_elevation_for_system_and_other_user_paths_only()
    {
        var g = _t.Guard;
        Assert.True(g.RequiresElevation(Path.Combine(_t.Vars["Windir"], "Temp", "x.tmp")));
        Assert.True(g.RequiresElevation(Path.Combine(_t.Vars["ProgramFiles"], "App", "cache")));
        Assert.True(g.RequiresElevation(Path.Combine(_t.Vars["ProgramData"], "Vendor", "cache")));
        Assert.True(g.RequiresElevation(Path.Combine(_t.Root, "Users", "other", "AppData", "Local", "Temp")));
        Assert.False(g.RequiresElevation(Path.Combine(_t.Vars["LocalAppData"], "Temp", "x.tmp")));
        Assert.False(g.RequiresElevation(Path.Combine(_t.Vars["Public"], "Documents", "x")));
        Assert.False(g.RequiresElevation(Path.Combine(Path.GetPathRoot(_t.Root)!, "Data", "x")));
    }

    [Fact]
    public void Elevation_need_by_item_kind()
    {
        static ScanItem Item(ItemKind kind, string? path = null, RegistryTarget? reg = null, string? rule = null, RiskLevel risk = RiskLevel.Safe) => new()
        {
            Id = "i", ModuleId = "m", Group = "g", DisplayName = "d", Kind = kind, Path = path, Registry = reg, RuleId = rule, Risk = risk,
            ServiceName = kind == ItemKind.Service ? "svc" : null, TaskPath = kind == ItemKind.ScheduledTask ? @"\T" : null,
        };
        var g = _t.Guard;
        Assert.True(ElevationNeed.For(Item(ItemKind.Command), g));
        Assert.True(ElevationNeed.For(Item(ItemKind.Service), g));
        Assert.True(ElevationNeed.For(Item(ItemKind.ScheduledTask), g));
        Assert.False(ElevationNeed.For(Item(ItemKind.RecycleBin), g));
        Assert.True(ElevationNeed.For(Item(ItemKind.RegistryKey, reg: new RegistryTarget(@"HKLM\Software\X", RegistryView.Registry64, null)), g));
        Assert.False(ElevationNeed.For(Item(ItemKind.RegistryValue, reg: new RegistryTarget(@"HKCU\Software\X", RegistryView.Registry64, "v")), g));
        Assert.True(ElevationNeed.For(Item(ItemKind.Directory, Path.Combine(_t.Vars["Windir"], "Temp")), g));
        Assert.False(ElevationNeed.For(Item(ItemKind.Directory, Path.Combine(_t.Vars["LocalAppData"], "Temp")), g));

        Assert.True(ElevationNeed.ServiceCanRun(Item(ItemKind.FileSet, rule: "r")));
        Assert.False(ElevationNeed.ServiceCanRun(Item(ItemKind.FileSet, rule: "r", risk: RiskLevel.Confirm)));
        Assert.False(ElevationNeed.ServiceCanRun(Item(ItemKind.FileSet)));
        Assert.False(ElevationNeed.ServiceCanRun(Item(ItemKind.Command, rule: "r")));
    }

    [Fact]
    public async Task Rule_items_carry_rule_id_and_service_honours_item_id_filter()
    {
        var ruleFile = _t.File("rules/t.json", """
            { "rules": [ { "id": "rel.test", "app": "T", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\RelA", "pattern": "*", "risk": "safe", "when": "always", "description": "a" },
                           { "path": "%LocalAppData%\\RelB", "pattern": "*", "risk": "safe", "when": "always", "description": "b" } ] } ] }
            """);
        var rules = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        Assert.Empty(rules.Rejected);
        var a = _t.File(Path.Combine(_t.Vars["LocalAppData"], "RelA", "a.bin"), "1234");
        var b = _t.File(Path.Combine(_t.Vars["LocalAppData"], "RelB", "b.bin"), "1234");

        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules.Rules };
        var items = await RuleScanner.SystemJunk().ScanAsync(ctx, null, default);
        Assert.Equal(2, items.Count);
        Assert.All(items, i => Assert.Equal("rel.test", i.RuleId));
        var onlyA = items.Single(i => i.Path!.EndsWith("RelA", StringComparison.OrdinalIgnoreCase));

        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        var ops = new ElevatedOperations(q, new OperationLog(_db), rules, new Whitelist(), _ => _t.Guard);
        var response = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "rel.test", Items: new[] { new ElevationItemRef(onlyA.Id, onlyA.ContentSnapshot()) }), _t.Env, _t.Guard, default);

        Assert.True(response.Success, response.Message);
        var payload = ElevatedOperations.ParsePayload(response.Payload);
        Assert.NotNull(payload);
        Assert.Equal(1, payload!.Files);
        Assert.Empty(payload.Incomplete);
        Assert.False(File.Exists(a));
        Assert.True(File.Exists(b), "未在 itemIds 里的条目不得被执行");

        var tooMany = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "rel.test", ItemIds: Enumerable.Range(0, ElevationRequest.MaxItems + 1).Select(i => i.ToString()).ToList()), _t.Env, _t.Guard, default);
        Assert.False(tooMany.Success);
    }

    // ---------- 签名清单 ----------

    private static (ECDsa Key, Dictionary<string, byte[]> Trusted) NewKey(string id = "test")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = SignedManifest.PublicKeyFromBase64(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        return (key, new Dictionary<string, byte[]>(StringComparer.Ordinal) { [id] = pub });
    }

    private string SignedDir(string name, ECDsa key, string keyId, int version, params (string File, string Json)[] files)
    {
        var dir = _t.Dir(name);
        foreach (var (f, json) in files) File.WriteAllText(Path.Combine(dir, f), json);
        SignedManifest.Sign(dir, "rules", version, key, keyId);
        return dir;
    }

    private const string RuleJson = """{ "rules": [ { "id": "s.a", "app": "A", "category": "system", "targets": [ { "path": "%LocalAppData%\\SA", "pattern": "*", "risk": "safe", "when": "always", "description": "a" } ] } ] }""";

    [Fact]
    public void Manifest_roundtrip_and_tampering_detection()
    {
        var (key, trusted) = NewKey();
        var dir = SignedDir("sig", key, "test", 3, ("a.json", RuleJson));
        var ok = SignedManifest.Verify(dir, "rules", trusted);
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal(3, ok.Version);
        Assert.Single(ok.Files);

        // 目录里多出来的文件不在清单里：校验仍通过，但不会被加载
        File.WriteAllText(Path.Combine(dir, "extra.json"), RuleJson.Replace("s.a", "s.extra"));
        var withExtra = SignedManifest.Verify(dir, "rules", trusted);
        Assert.True(withExtra.Ok);
        var loaded = new RuleLoader(_t.Guard).LoadContents(withExtra.Contents);
        Assert.Single(loaded.Rules);
        Assert.Equal("s.a", loaded.Rules[0].Id);

        // 改文件内容 → 拒绝
        File.WriteAllText(Path.Combine(dir, "a.json"), RuleJson.Replace("safe", "high"));
        Assert.Contains("已被改动", SignedManifest.Verify(dir, "rules", trusted).Reason);
        File.WriteAllText(Path.Combine(dir, "a.json"), RuleJson);

        // 改清单版本号 → 签名失效
        var manifest = Path.Combine(dir, SignedManifest.FileName);
        var dto = JsonSerializer.Deserialize<ManifestDto>(File.ReadAllText(manifest))!;
        dto.Version = 99;
        File.WriteAllText(manifest, JsonSerializer.Serialize(dto));
        Assert.Contains("签名验证失败", SignedManifest.Verify(dir, "rules", trusted).Reason);

        // 类型不符 / 未知密钥
        SignedManifest.Sign(dir, "rules", 3, key, "test");
        Assert.Contains("类型不符", SignedManifest.Verify(dir, "fingerprints", trusted).Reason);
        Assert.Contains("不受信任", SignedManifest.Verify(dir, "rules", new Dictionary<string, byte[]>()).Reason);
        Assert.Contains("不受信任", SignedManifest.Verify(dir, "rules", TrustedKeys.Current).Reason);
    }

    [Fact]
    public void Manifest_rejects_unsafe_file_names_even_when_signed()
    {
        var (key, trusted) = NewKey();
        var dir = _t.Dir("unsafe");
        var files = new SortedDictionary<string, string>(StringComparer.Ordinal) { [@"..\evil.json"] = new string('0', 64), ["ok.json"] = SignedManifest.HashBytes(Encoding.UTF8.GetBytes(RuleJson)) };
        File.WriteAllText(Path.Combine(dir, "ok.json"), RuleJson);
        var generated = "2026-09-30T00:00:00Z";
        var sig = key.SignData(SignedManifest.Canonical("rules", 1, generated, files), HashAlgorithmName.SHA256);
        var dto = new ManifestDto { Kind = "rules", Version = 1, Generated = generated, Files = files, KeyId = "test", Signature = Convert.ToBase64String(sig) };
        File.WriteAllText(Path.Combine(dir, SignedManifest.FileName), JsonSerializer.Serialize(dto));
        var v = SignedManifest.Verify(dir, "rules", trusted);
        Assert.False(v.Ok);
        Assert.Contains("文件名非法", v.Reason);

        Assert.False(SignedManifest.IsSafeName("manifest.json"));
        Assert.False(SignedManifest.IsSafeName("a/b.json"));
        Assert.False(SignedManifest.IsSafeName("a.txt"));
        Assert.True(SignedManifest.IsSafeName("system.json"));
    }

    [Fact]
    public void Bundled_data_sets_are_signed_with_a_trusted_key()
    {
        foreach (var kind in new[] { DataKind.Rules, DataKind.Fingerprints, DataKind.Popups })
        {
            var dir = Path.Combine(AppContext.BaseDirectory, DataSets.KindName(kind));
            var v = SignedManifest.Verify(dir, DataSets.KindName(kind), TrustedKeys.Current);
            Assert.True(v.Ok, $"{kind}: {v.Reason}（改过数据文件后需运行 tools/sign-data.ps1 重新签名）");
            Assert.NotEmpty(v.Files);
            // 目录里每个数据文件都在清单内，没有漏签的
            var onDisk = Directory.EnumerateFiles(dir, "*.json").Select(Path.GetFileName).Where(f => f != SignedManifest.FileName).OrderBy(f => f).ToList();
            Assert.Equal(onDisk, v.Files.Select(Path.GetFileName).OrderBy(f => f).ToList());
        }
        Assert.DoesNotContain("dev-2026-09", TrustedKeys.Current.Keys);
        Assert.Contains(TrustedKeys.ReleaseKeyId, TrustedKeys.Current.Keys);
    }

    [Fact]
    public void Locate_prefers_verified_newer_update_and_ignores_bad_or_older_ones()
    {
        var (key, trusted) = NewKey();
        var bundled = SignedDir("bundled", key, "test", 2, ("a.json", RuleJson));
        var older = SignedDir("upd-older", key, "test", 1, ("a.json", RuleJson));
        var newer = SignedDir("upd-newer", key, "test", 5, ("a.json", RuleJson));
        var bad = SignedDir("upd-bad", key, "test", 9, ("a.json", RuleJson));
        File.WriteAllText(Path.Combine(bad, "a.json"), RuleJson + " ");

        Assert.False(DataSets.Locate(DataKind.Rules, bundled, older, trusted).FromUpdate);
        Assert.False(DataSets.Locate(DataKind.Rules, bundled, bad, trusted).FromUpdate);
        Assert.False(DataSets.Locate(DataKind.Rules, bundled, null, trusted).FromUpdate);
        var chosen = DataSets.Locate(DataKind.Rules, bundled, newer, trusted);
        Assert.True(chosen.FromUpdate);
        Assert.Equal(5, chosen.Verdict.Version);

        // 内置目录本身校验失败 → 什么都不加载
        File.WriteAllText(Path.Combine(bundled, "a.json"), RuleJson + " ");
        var broken = DataSets.Locate(DataKind.Rules, bundled, null, trusted);
        Assert.False(broken.Verdict.Ok);
        Assert.Empty(broken.Files);
        Assert.Empty(new RuleLoader(_t.Guard).LoadContents(broken.Contents).Rules);
    }

    [Fact]
    public void Loaders_only_read_listed_files()
    {
        var dir = _t.Dir("fp");
        File.WriteAllText(Path.Combine(dir, "listed.json"), """{ "fingerprints": [ { "id": "fp.a", "app": "A", "paths": [ "%LocalAppData%\\A" ] } ] }""");
        File.WriteAllText(Path.Combine(dir, "unlisted.json"), """{ "fingerprints": [ { "id": "fp.b", "app": "B", "paths": [ "%LocalAppData%\\B" ] } ] }""");
        var db = AppFingerprintDb.LoadFiles(new[] { Path.Combine(dir, "listed.json") }, _t.Guard);
        Assert.Single(db.Fingerprints);
        Assert.Equal("fp.a", db.Fingerprints[0].Id);

        var blocker = new PopupBlocker(new Backup.RegistryBackup(_db, Path.Combine(_t.Root, "Backups")), new OperationLog(_db));
        File.WriteAllText(Path.Combine(dir, "p1.json"), """{ "rules": [ { "id": "p1", "processPattern": "a\\.exe", "titlePattern": "x" } ] }""");
        File.WriteAllText(Path.Combine(dir, "p2.json"), """{ "rules": [ { "id": "p2", "processPattern": "b\\.exe", "titlePattern": "x" } ] }""");
        blocker.LoadFiles(new[] { Path.Combine(dir, "p1.json") });
        Assert.Single(blocker.Rules);
        Assert.Equal("p1", blocker.Rules[0].Id);
    }

    // ---------- 在线更新 ----------

    private static (HttpListener Listener, string BaseUrl, Task Serving) Serve(string root, CancellationToken ct)
    {
        var port = 40000 + Random.Shared.Next(20000);
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serving = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch { break; }
                var rel = Uri.UnescapeDataString(ctx.Request.Url!.AbsolutePath.TrimStart('/')).Replace('/', Path.DirectorySeparatorChar);
                var file = Path.Combine(root, rel);
                if (File.Exists(file))
                {
                    var bytes = File.ReadAllBytes(file);
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                }
                else ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        });
        return (listener, $"http://127.0.0.1:{port}", serving);
    }

    [Fact]
    public async Task Updater_installs_newer_signed_set_and_refuses_tampered_or_same_version()
    {
        var (key, trusted) = NewKey();
        var remoteRoot = _t.Dir("remote");
        var remoteRules = Path.Combine(remoteRoot, "rules");
        Directory.CreateDirectory(remoteRules);
        File.WriteAllText(Path.Combine(remoteRules, "a.json"), RuleJson);
        SignedManifest.Sign(remoteRules, "rules", 7, key, "test");

        using var cts = new CancellationTokenSource();
        var (listener, baseUrl, serving) = Serve(remoteRoot, cts.Token);
        try
        {
            var updater = new DataUpdater(new HttpClient(), trusted);
            var target = Path.Combine(_t.Root, "data", "updates", "rules");

            var same = await updater.UpdateAsync(DataKind.Rules, baseUrl, 7, target);
            Assert.False(same.Updated);
            Assert.Contains("已是最新", same.Message);
            Assert.False(Directory.Exists(target));

            var r = await updater.UpdateAsync(DataKind.Rules, baseUrl, 1, target);
            Assert.True(r.Updated, r.Message);
            Assert.Equal(7, r.RemoteVersion);
            var v = SignedManifest.Verify(target, "rules", trusted);
            Assert.True(v.Ok, v.Reason);
            Assert.DoesNotContain(Directory.EnumerateDirectories(Path.GetDirectoryName(target)!), d => d.Contains(".tmp") || d.Contains(".old"));

            // 远端文件被换掉但清单没变 → 哈希不符，现有更新目录原样保留
            File.WriteAllText(Path.Combine(remoteRules, "a.json"), RuleJson.Replace("safe", "high"));
            var dto = JsonSerializer.Deserialize<ManifestDto>(File.ReadAllText(Path.Combine(remoteRules, SignedManifest.FileName)))!;
            dto.Version = 8;
            dto.Signature = Convert.ToBase64String(key.SignData(SignedManifest.Canonical("rules", 8, dto.Generated!, dto.Files!), HashAlgorithmName.SHA256));
            File.WriteAllText(Path.Combine(remoteRules, SignedManifest.FileName), JsonSerializer.Serialize(dto));
            var tampered = await updater.UpdateAsync(DataKind.Rules, baseUrl, 7, target);
            Assert.False(tampered.Updated);
            Assert.Contains("哈希不符", tampered.Message);
            Assert.Equal(7, SignedManifest.Verify(target, "rules", trusted).Version);

            // 不受信任的密钥签的远端清单：连文件都不下载
            var (otherKey, _) = NewKey("other");
            File.WriteAllText(Path.Combine(remoteRules, "a.json"), RuleJson);
            SignedManifest.Sign(remoteRules, "rules", 9, otherKey, "other");
            var untrusted = await updater.UpdateAsync(DataKind.Rules, baseUrl, 7, target);
            Assert.False(untrusted.Updated);
            Assert.Contains("不受信任", untrusted.Message);
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            try { await serving; } catch { }
        }
    }

    // ---------- 第一轮 review：提权服务每次请求重新加载规则；管道不存在时快速判定；数据目录迁移后备份索引修正 ----------

    [Fact]
    public void Service_reloads_rules_from_provider_on_every_request()
    {
        var ruleFile = _t.File("rules/p.json", """
            { "rules": [ { "id": "prov.a", "app": "P", "category": "system",
              "targets": [ { "path": "%LocalAppData%\\ProvA", "pattern": "*", "risk": "safe", "when": "always", "description": "a" } ] } ] }
            """);
        int calls = 0;
        RuleLoadResult Provider(Safety.PathGuard g)
        {
            calls++;
            return new RuleLoader(g).LoadJson(File.ReadAllText(ruleFile), ruleFile);
        }
        var q = new Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        var ops = new ElevatedOperations(q, new OperationLog(_db), Provider, () => new Whitelist(), _ => _t.Guard);
        _t.File(Path.Combine(_t.Vars["LocalAppData"], "ProvA", "a.bin"), "1234");

        var first = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "prov.a"), _t.Env, _t.Guard, default);
        Assert.True(first.Success, first.Message);
        Assert.Equal(1, calls);

        // 规则文件在服务运行期间被换掉（例如签名校验失败后提供者不再返回它）：下一次请求看到的是新状态，不沿用旧副本
        File.WriteAllText(ruleFile, """{ "rules": [ { "id": "prov.other", "app": "P", "category": "system", "targets": [ { "path": "%LocalAppData%\\ProvB", "pattern": "*", "risk": "safe", "when": "always", "description": "b" } ] } ] }""");
        var second = ops.ExecuteRuleCleanWithEnvironment(new ElevationRequest(ElevatedOperation.RunRuleClean, RuleId: "prov.a"), _t.Env, _t.Guard, default);
        Assert.False(second.Success);
        Assert.Contains("不存在", second.Message);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Missing_pipe_is_detected_without_waiting_for_connect_timeout()
    {
        var name = "CleanSweepTests.NoSuchPipe." + Guid.NewGuid().ToString("N");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(ElevationClient.PipeExists(name));
        Assert.False(await ElevationClient.IsAvailableAsync(name));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"耗时 {sw.Elapsed}");
    }

    [Fact]
    public void Registry_backup_index_is_relocated_after_data_dir_move()
    {
        const string testRoot = @"Software\CleanSweepTests";
        var name = "reloc-" + Guid.NewGuid().ToString("N")[..8];
        using (var k = Registry.CurrentUser.CreateSubKey($@"{testRoot}\{name}")) k.SetValue("v", "1");
        try
        {
            var oldDir = Path.Combine(_t.Root, "old", "backups", "registry");
            var backup = new Backup.RegistryBackup(_db, oldDir);
            var rec = backup.BackupValue($@"HKCU\{testRoot}\{name}", "v", "test");
            Assert.StartsWith(Path.Combine(_t.Root, "old"), rec.File, StringComparison.OrdinalIgnoreCase);

            // 整个数据目录搬家
            Directory.Move(Path.Combine(_t.Root, "old"), Path.Combine(_t.Root, "new"));
            var moved = new Backup.RegistryBackup(_db, Path.Combine(_t.Root, "new", "backups", "registry"));
            Assert.Contains("不在备份目录内", moved.ValidateBackupFile(moved.Get(rec.Id)!, out _, out _));

            Assert.Equal(1, moved.RelocateFrom(oldDir));
            Assert.Equal(0, moved.RelocateFrom(oldDir));
            Assert.Null(moved.ValidateBackupFile(moved.Get(rec.Id)!, out _, out _));

            using (var k = Registry.CurrentUser.CreateSubKey($@"{testRoot}\{name}")) k.SetValue("v", "2");
            moved.Restore(rec.Id);
            using (var k = Registry.CurrentUser.OpenSubKey($@"{testRoot}\{name}")!) Assert.Equal("1", k.GetValue("v"));
        }
        finally
        {
            try { Registry.CurrentUser.DeleteSubKeyTree($@"{testRoot}\{name}", false); } catch { }
        }
    }

    [Fact]
    public void Update_url_must_be_https_except_loopback()
    {
        Assert.Null(DataUpdater.ValidateBaseUrl("https://updates.example.com/cleansweep"));
        Assert.Null(DataUpdater.ValidateBaseUrl("http://127.0.0.1:8080/x"));
        Assert.NotNull(DataUpdater.ValidateBaseUrl("http://updates.example.com/cleansweep"));
        Assert.NotNull(DataUpdater.ValidateBaseUrl("ftp://x"));
        Assert.NotNull(DataUpdater.ValidateBaseUrl(""));
        Assert.NotNull(DataUpdater.ValidateBaseUrl("not a url"));
    }
}
