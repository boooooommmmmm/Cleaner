using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.Core.Integrity;

namespace CleanSweep.Core.Tests;

/// <summary>程序自更新：发布信息签名、来源解析、下载核对、解压校验、覆盖复制。</summary>
public sealed class AppUpdateTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    private static (ECDsa Key, Dictionary<string, byte[]> Trusted) NewKey(string id = "test")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = SignedManifest.PublicKeyFromBase64(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        return (key, new Dictionary<string, byte[]>(StringComparer.Ordinal) { [id] = pub });
    }

    [Fact]
    public void Update_source_resolves_github_repo_or_https_root_only()
    {
        var gh = UpdateSources.Resolve("someone/CleanSweep");
        Assert.NotNull(gh);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/main", gh!.DataBaseUrl);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/main/release/latest.json", gh.ReleaseInfoUrl);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/dev", UpdateSources.Resolve("someone/CleanSweep@dev")!.DataBaseUrl);
        Assert.Equal("https://updates.example.com/cs", UpdateSources.Resolve("https://updates.example.com/cs/")!.DataBaseUrl);
        Assert.Null(UpdateSources.Resolve(""));
        Assert.Null(UpdateSources.Resolve("http://updates.example.com/cs"));
        Assert.Null(UpdateSources.Resolve("a/b/c"));
        Assert.Null(UpdateSources.Resolve("some one/repo"));
        Assert.Null(UpdateSources.Resolve("owner/repo@br anch"));
    }

    [Fact]
    public void Release_info_roundtrip_and_rejections()
    {
        var (key, trusted) = NewKey();
        var zip = _t.File("out/CleanSweep-win-x64-0.15.0.zip", "zipbytes");
        var dto = ReleaseManifest.Sign("0.15.0", zip, "https://github.com/o/r/releases/download/v0.15.0/CleanSweep-win-x64-0.15.0.zip", "修复若干问题", key, "test");
        var json = ReleaseManifest.ToJson(dto);
        var back = JsonSerializer.Deserialize<ReleaseInfoDto>(json);

        var info = ReleaseManifest.Verify(back, trusted, out var error);
        Assert.NotNull(info);
        Assert.Null(error);
        Assert.Equal(new Version(0, 15, 0), info!.Version);
        Assert.Equal(8, info.Size);
        Assert.Equal(SignedManifest.HashFile(zip), info.Sha256);

        back!.Url = "https://evil.example.com/x.zip";
        Assert.Null(ReleaseManifest.Verify(back, trusted, out error));
        Assert.Contains("签名验证失败", error);

        back = JsonSerializer.Deserialize<ReleaseInfoDto>(json)!;
        back.Version = "0.99.0";
        Assert.Contains("签名验证失败", ReleaseManifest.Verify(back, trusted, out error) is null ? error : "");

        Assert.Null(ReleaseManifest.Verify(JsonSerializer.Deserialize<ReleaseInfoDto>(json), new Dictionary<string, byte[]>(), out error));
        Assert.Contains("不受信任", error);

        var http = ReleaseManifest.Sign("0.15.0", zip, "http://mirror.example.com/x.zip", "", key, "test");
        Assert.Null(ReleaseManifest.Verify(http, trusted, out error));
        Assert.Contains("https", error);

        Assert.Throws<ArgumentException>(() => ReleaseManifest.Sign("v1", zip, "https://x/y.zip", "", key, "test"));
    }

    [Fact]
    public void Newer_compares_first_three_parts()
    {
        Assert.True(ReleaseManifest.IsNewer(new Version(0, 15, 0), new Version(0, 14, 0)));
        Assert.False(ReleaseManifest.IsNewer(new Version(0, 14, 0), new Version(0, 14, 0)));
        Assert.False(ReleaseManifest.IsNewer(new Version(0, 14, 0, 5), new Version(0, 14, 0)));
        Assert.True(ReleaseManifest.IsNewer(new Version(1, 0), new Version(0, 99, 99)));
    }

    [Fact]
    public void Stage_rejects_traversal_entries_and_missing_exe_and_unsigned_data()
    {
        var (_, trusted) = NewKey();
        var updater = new AppUpdater(new HttpClient(), trusted);
        var stage = Path.Combine(_t.Root, "stage");

        var traversal = Path.Combine(_t.Root, "traversal.zip");
        using (var z = ZipFile.Open(traversal, ZipArchiveMode.Create))
        {
            var e = z.CreateEntry("../evil.txt");
            using var w = new StreamWriter(e.Open());
            w.Write("x");
        }
        Assert.Contains("路径非法", updater.Stage(traversal, stage));

        var noExe = Path.Combine(_t.Root, "noexe.zip");
        using (var z = ZipFile.Open(noExe, ZipArchiveMode.Create)) z.CreateEntry("readme.txt");
        Assert.Contains("没有 CleanSweep.exe", updater.Stage(noExe, stage));

        // 有 exe 但数据集没签名（或不是受信任密钥签的）
        var src = _t.Dir("pkg/CleanSweep");
        File.WriteAllText(Path.Combine(src, "CleanSweep.exe"), "exe");
        Directory.CreateDirectory(Path.Combine(src, "rules"));
        File.WriteAllText(Path.Combine(src, "rules", "a.json"), "{}");
        var unsigned = Path.Combine(_t.Root, "unsigned.zip");
        ZipFile.CreateFromDirectory(Path.Combine(_t.Root, "pkg"), unsigned);
        var reason = updater.Stage(unsigned, stage);
        Assert.NotNull(reason);
        Assert.Contains("rules 签名校验失败", reason);
    }

    [Fact]
    public void Stage_accepts_package_whose_data_sets_are_signed_with_trusted_key()
    {
        var (key, trusted) = NewKey();
        var src = _t.Dir("pkg2/CleanSweep");
        File.WriteAllText(Path.Combine(src, "CleanSweep.exe"), "exe");
        foreach (var kind in new[] { "rules", "fingerprints", "popups" })
        {
            var d = Path.Combine(src, kind);
            Directory.CreateDirectory(d);
            File.WriteAllText(Path.Combine(d, "a.json"), "{}");
            SignedManifest.Sign(d, kind, 1, key, "test");
        }
        var zip = Path.Combine(_t.Root, "ok.zip");
        ZipFile.CreateFromDirectory(Path.Combine(_t.Root, "pkg2"), zip);
        var stage = Path.Combine(_t.Root, "stage2");
        Assert.Null(new AppUpdater(new HttpClient(), trusted).Stage(zip, stage));
        var root = AppUpdater.FindAppRoot(stage);
        Assert.NotNull(root);
        Assert.True(File.Exists(Path.Combine(root!, "CleanSweep.exe")));
    }

    [Fact]
    public void Copy_directory_mirrors_and_removes_stale_files()
    {
        var src = _t.Dir("src");
        var dst = _t.Dir("dst");
        File.WriteAllText(Path.Combine(src, "CleanSweep.exe"), "new");
        Directory.CreateDirectory(Path.Combine(src, "rules"));
        File.WriteAllText(Path.Combine(src, "rules", "a.json"), "a");
        File.WriteAllText(Path.Combine(dst, "CleanSweep.exe"), "old");
        File.WriteAllText(Path.Combine(dst, "stale.dll"), "stale");

        Assert.Null(AppUpdater.CopyDirectory(src, dst));
        Assert.Equal("new", File.ReadAllText(Path.Combine(dst, "CleanSweep.exe")));
        Assert.Equal("a", File.ReadAllText(Path.Combine(dst, "rules", "a.json")));
        Assert.False(File.Exists(Path.Combine(dst, "stale.dll")));
    }

    private static (HttpListener Listener, string BaseUrl, Task Serving) Serve(Dictionary<string, byte[]> files, CancellationToken ct)
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
                var rel = ctx.Request.Url!.AbsolutePath.TrimStart('/');
                if (files.TryGetValue(rel, out var bytes))
                {
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
    public async Task Check_and_download_verify_version_size_and_hash()
    {
        var (key, trusted) = NewKey();
        var zipBytes = new byte[100_000];
        Random.Shared.NextBytes(zipBytes);
        var zipPath = Path.Combine(_t.Root, "CleanSweep-win-x64-0.15.0.zip");
        File.WriteAllBytes(zipPath, zipBytes);

        using var cts = new CancellationTokenSource();
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var (listener, baseUrl, serving) = Serve(files, cts.Token);
        try
        {
            var url = baseUrl + "/dl/CleanSweep-win-x64-0.15.0.zip";
            var dto = ReleaseManifest.Sign("0.15.0", zipPath, url, "notes", key, "test");
            files["release/latest.json"] = System.Text.Encoding.UTF8.GetBytes(ReleaseManifest.ToJson(dto));
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = zipBytes;
            var updater = new AppUpdater(new HttpClient(), trusted);

            var same = await updater.CheckAsync(baseUrl + "/release/latest.json", new Version(0, 15, 0));
            Assert.False(same.Available);
            Assert.Contains("已是最新", same.Message);

            var check = await updater.CheckAsync(baseUrl + "/release/latest.json", new Version(0, 14, 0));
            Assert.True(check.Available, check.Message);
            Assert.NotNull(check.Release);

            var missing = await updater.CheckAsync(baseUrl + "/nope/latest.json", new Version(0, 14, 0));
            Assert.False(missing.Available);
            Assert.Contains("还没有发布信息", missing.Message);

            var staging = Path.Combine(_t.Root, "staging");
            var downloaded = await updater.DownloadAsync(check.Release!, staging);
            Assert.Equal(zipBytes, File.ReadAllBytes(downloaded));
            Assert.Empty(Directory.EnumerateFiles(staging, "*.part"));

            // 服务器上的包被换掉：大小相同但内容不同 → 哈希不符；大小不同 → 直接拒绝
            var swapped = (byte[])zipBytes.Clone();
            swapped[10] ^= 0xFF;
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = swapped;
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAsync(check.Release!, staging));
            Assert.Contains("哈希", ex.Message);
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = zipBytes.Take(50_000).ToArray();
            ex = await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAsync(check.Release!, staging));
            Assert.Contains("大小", ex.Message);
            Assert.Empty(Directory.EnumerateFiles(staging, "*.part"));
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            try { await serving; } catch { }
        }
    }
}
