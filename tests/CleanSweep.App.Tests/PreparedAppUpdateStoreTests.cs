using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.App.Services;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class PreparedAppUpdateStoreTests
{
    [Theory]
    [InlineData("valid")]
    [InlineData("source-changed")]
    [InlineData("already-installed")]
    [InlineData("older")]
    [InlineData("missing-package")]
    [InlineData("corrupt-package")]
    [InlineData("missing-signature")]
    [InlineData("corrupt-signature")]
    [InlineData("unknown-key")]
    [InlineData("corrupt-index")]
    [InlineData("traversal")]
    [InlineData("absolute-path")]
    public void Restart_restores_only_newer_trusted_unchanged_package_from_same_source(string state)
    {
        var root = Path.Combine(Path.GetTempPath(), "CleanSweep-update-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            const string source = "https://example.com/release/latest.json";
            var zip = Path.Combine(root, "update.zip");
            File.WriteAllBytes(zip, [1, 2, 3, 4]);
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var dto = ReleaseManifest.Sign("0.20.0", zip, "https://example.com/update.zip", "notes", key, "test");
            var keys = new Dictionary<string, byte[]> { ["test"] = key.ExportSubjectPublicKeyInfo() };
            var release = ReleaseManifest.Verify(dto, keys, out _)!;
            File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
            new PreparedAppUpdateStore(root, keys).Save(source, release);

            if (state == "missing-package") File.Delete(zip);
            if (state == "corrupt-package") File.WriteAllBytes(zip, [4, 3, 2, 1]);
            if (state == "missing-signature") File.Delete(zip + AppUpdater.ReleaseInfoSuffix);
            if (state == "corrupt-signature")
            {
                dto.Version = "0.21.0";
                File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
            }
            if (state == "unknown-key") keys.Clear();
            var index = Path.Combine(root, "prepared-update.json");
            if (state == "corrupt-index") File.WriteAllText(index, "broken json");
            if (state is "traversal" or "absolute-path")
                File.WriteAllText(index, JsonSerializer.Serialize(new { Source = source,
                    Asset = state == "traversal" ? "../update.zip" : zip }));

            // A fresh store represents the next process; no network dependency is involved.
            var current = new Version(state == "older" ? "0.21.0" : state == "already-installed" ? "0.20.0" : "0.19.0");
            var restored = new PreparedAppUpdateStore(root, keys).Load(state == "source-changed" ? source + "?other" : source, current);
            if (state == "valid")
            {
                Assert.NotNull(restored);
                Assert.Equal(release.Version, restored.Release.Version);
                Assert.Equal(release.Asset, restored.Release.Asset);
                Assert.Equal(release.Url, restored.Release.Url);
                Assert.Equal(release.Sha256, restored.Release.Sha256);
                Assert.Equal(release.Size, restored.Release.Size);
                Assert.Equal(ReleaseManifest.ToJson(dto), ReleaseManifest.ToJson(restored.Release.Source!));
                Assert.Equal(zip, restored.Zip);
            }
            else Assert.Null(restored);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
