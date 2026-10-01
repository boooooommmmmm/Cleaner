using System.Diagnostics;
using System.Security.Cryptography;
using CleanSweep.Core.Integrity;

namespace CleanSweep.Core.Tests;

public sealed class ReleaseVerificationTests
{
    [Fact]
    public void Published_asset_must_match_signed_name_size_and_content()
    {
        using var t = new TestEnv();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var zip = t.File("release.zip", "original");
        var dto = ReleaseManifest.Sign("0.17.0", zip, "https://example.invalid/release.zip", "", key, "test");
        var release = ReleaseManifest.Verify(dto, new Dictionary<string, byte[]> { ["test"] = key.ExportSubjectPublicKeyInfo() }, out _)!;
        Assert.Null(ReleaseManifest.VerifyAsset(release, zip));
        Assert.Contains("文件名", ReleaseManifest.VerifyAsset(release, t.File("other.zip", "original")));
        File.WriteAllText(zip, "tampered");
        Assert.Contains("哈希", ReleaseManifest.VerifyAsset(release, zip));
        File.WriteAllText(zip, "short");
        Assert.Contains("大小", ReleaseManifest.VerifyAsset(release, zip));
    }

    [Fact]
    public void Publishing_rejects_untracked_source_and_staged_changes_but_allows_generated_metadata()
    {
        using var t = new TestEnv();
        var repo = t.Dir("repo");
        t.File(Path.Combine(repo, "tracked.txt"));
        t.File(Path.Combine(repo, "release/latest.json"), "{}");
        Git(repo, "init", "--quiet");
        Git(repo, "add", ".");
        Git(repo, "-c", "user.name=Review", "-c", "user.email=review@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "test");
        Assert.Equal(0, Check(repo).ExitCode);
        t.File(Path.Combine(repo, "release/latest.json"), "{\"generated\":true}");
        Assert.Equal(0, Check(repo).ExitCode);
        var untracked = t.File(Path.Combine(repo, "src/untracked.cs"), "class Uncommitted {}");
        Assert.NotEqual(0, Check(repo).ExitCode);
        Git(repo, "add", "src/untracked.cs");
        Assert.NotEqual(0, Check(repo).ExitCode);
        // The fixture directory is disposable; no repository or global Git configuration is changed.
    }

    private static (int ExitCode, string Output) Check(string repo)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "tools/verify-release-source.ps1"))) current = current.Parent;
        Assert.NotNull(current);
        var script = Path.Combine(current.FullName, "tools/verify-release-source.ps1");
        var ps = Path.Combine(System.Environment.SystemDirectory, "WindowsPowerShell/v1.0/powershell.exe");
        return Run(repo, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-RepositoryRoot", repo);
    }

    private static void Git(string repo, params string[] args)
    {
        var r = Run(repo, "git", args);
        Assert.True(r.ExitCode == 0, r.Output);
    }

    private static (int ExitCode, string Output) Run(string dir, string exe, params string[] args)
    {
        var start = new ProcessStartInfo(exe) { WorkingDirectory = dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var errors = p.StandardError.ReadToEndAsync();
        // Hosted Windows runners can take more than 20 seconds to cold-start PowerShell.
        // Keep a bounded wait without weakening any source-cleanliness assertions.
        if (!p.WaitForExit(120_000))
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException($"Release verification fixture timed out after 120 seconds: {Path.GetFileName(exe)}");
        }
        return (p.ExitCode, output.GetAwaiter().GetResult() + errors.GetAwaiter().GetResult());
    }
}
