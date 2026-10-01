using System.Net;
using System.Security.Cryptography;
using CleanSweep.Core.Integrity;

namespace CleanSweep.Core.Tests;

public sealed class UpdateDownloadCacheTests
{
    [Fact]
    public async Task Restart_reuses_verified_zip_rebuilds_sidecar_and_redownloads_tampered_cache()
    {
        using var env = new TestEnv();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var source = Path.Combine(env.Dir("source"), "update.zip");
        var bytes = new byte[] { 1, 2, 3, 4 };
        File.WriteAllBytes(source, bytes);
        var dto = ReleaseManifest.Sign("0.19.0", source, "https://example.com/update.zip", "", key, "test");
        var keys = new Dictionary<string, byte[]> { ["test"] = key.ExportSubjectPublicKeyInfo() };
        var release = ReleaseManifest.Verify(dto, keys, out var error)!;
        Assert.Null(error);
        var requests = 0;
        using var client = new HttpClient(new Handler(() => { requests++; return bytes; }));
        var staging = env.Dir("cache");
        var zip = await new AppUpdater(client, keys).DownloadAsync(release, staging, reuseExisting: true);
        File.Delete(zip + AppUpdater.ReleaseInfoSuffix);
        await new AppUpdater(client, keys).DownloadAsync(release, staging, reuseExisting: true);
        Assert.Equal(1, requests);
        Assert.True(File.Exists(zip + AppUpdater.ReleaseInfoSuffix));
        File.WriteAllBytes(zip, [4, 3, 2, 1]);
        await new AppUpdater(client, keys).DownloadAsync(release, staging, reuseExisting: true);
        Assert.Equal(2, requests);
        Assert.Equal(bytes, File.ReadAllBytes(zip));
    }

    private sealed class Handler(Func<byte[]> data) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data()) });
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("missing")]
    [InlineData("invalid-json")]
    [InlineData("tampered-signature")]
    [InlineData("different-version")]
    [InlineData("tampered-asset")]
    public void Prepared_asset_requires_matching_signed_sidecar_and_unchanged_bytes(string state)
    {
        using var env = new TestEnv();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var zip = env.File("update.zip", "test package");
        var dto = ReleaseManifest.Sign("0.19.0", zip, "https://example.com/update.zip", "", key, "test");
        var keys = new Dictionary<string, byte[]> { ["test"] = key.ExportSubjectPublicKeyInfo() };
        var expected = ReleaseManifest.Verify(dto, keys, out _)!;
        if (state == "tampered-signature") dto.Version = "0.20.0";
        if (state == "different-version") dto = ReleaseManifest.Sign("0.20.0", zip, expected.Url, "", key, "test");
        if (state != "missing") File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix,
            state == "invalid-json" ? "broken" : ReleaseManifest.ToJson(dto));
        if (state == "tampered-asset") File.WriteAllText(zip, "test packagE");
        var error = ReleaseManifest.VerifyPreparedAsset(expected, zip, keys);
        if (state == "valid") Assert.Null(error);
        else Assert.NotNull(error);
    }
}
