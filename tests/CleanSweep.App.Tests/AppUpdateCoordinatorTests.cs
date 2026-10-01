using System.IO;
using System.Security.Cryptography;
using CleanSweep.App.Services;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class AppUpdateCoordinatorTests
{
    private static readonly ReleaseInfo Release = new(new Version(0, 19, 0), "update.zip", "https://example.com/update.zip", "hash", 10, "notes", "test");

    private sealed class Scenario
    {
        public List<string> Events { get; } = [];
        public TaskCompletionSource<string>? DownloadGate;
        public bool Accept;
        public bool Valid = true;
        public bool Available = true;
        public Exception? DownloadError;
        public string? LaunchError;
        public AppUpdateCoordinator Create() => new(
            _ => { Events.Add("check"); return Task.FromResult(new AppUpdateCheck(Available, Available ? Release : null, "最新版本")); },
            async (_, _, _) =>
            {
                Events.Add("download");
                if (DownloadError is { } ex) throw ex;
                return DownloadGate is null ? "update.zip" : await DownloadGate.Task;
            },
            (_, _) => { Events.Add("confirm"); return Task.FromResult(Accept); },
            _ => { Events.Add("launch"); return LaunchError; },
            () => Events.Add("shutdown"),
            (_, _) => { Events.Add("validate"); return Task.FromResult(Valid); });
    }

    [Fact]
    public async Task Failed_recheck_keeps_prepared_package_available_for_offline_install()
    {
        var s = new Scenario();
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        s.Available = false; // 无可验证的发布信息，与网络失败时的返回结构相同。
        await updates.CheckAndPrepareAsync();
        Assert.NotNull(updates.ReadyRelease);
        s.Accept = true;
        await updates.InstallPreparedAsync();
        Assert.Contains("launch", s.Events);
        Assert.Single(s.Events, e => e == "download");
    }

    [Fact]
    public async Task Source_change_cancels_inflight_network_work()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = false;
        var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, Release, "")),
            async (_, _, ct) =>
            {
                entered.SetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); }
                catch (OperationCanceledException) { cancelled = true; throw; }
                return "unused.zip";
            }, (_, _) => throw new InvalidOperationException("Unexpected prompt"), _ => null, () => { });
        var work = updates.CheckAndPrepareAsync();
        await entered.Task;
        updates.ResetSource();
        await work.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(cancelled);
        Assert.False(updates.IsBusy);
        Assert.Contains("来源已改变", updates.Status);
    }

    [Fact]
    public async Task Cancellation_after_download_prevents_prompt_even_if_downloader_returns()
    {
        var s = new Scenario { Accept = true, DownloadGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        using var cancellation = new CancellationTokenSource();
        var updates = s.Create();
        var work = updates.CheckAndPrepareAsync(ct: cancellation.Token);
        cancellation.Cancel();
        s.DownloadGate.SetResult("update.zip");
        await work;
        Assert.DoesNotContain("confirm", s.Events);
        Assert.DoesNotContain("launch", s.Events);
    }

    [Fact]
    public async Task Default_validation_rejects_corrupt_release_sidecar_before_prompt()
    {
        var root = Path.Combine(Path.GetTempPath(), "CleanSweep-review-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var zip = Path.Combine(root, "update.zip");
            var bytes = new byte[] { 1, 2, 3, 4 };
            File.WriteAllBytes(zip, bytes);
            File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, "broken json");
            var release = Release with { Size = bytes.Length, Sha256 = Convert.ToHexString(SHA256.HashData(bytes)) };
            var prompts = 0;
            var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, release, "")),
                (_, _, _) => Task.FromResult(zip), (_, _) => { prompts++; return Task.FromResult(false); }, _ => null, () => { });
            await updates.CheckAndPrepareAsync();
            Assert.Equal(0, prompts);
            Assert.Null(updates.ReadyRelease);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task Verified_no_update_result_clears_previous_prepared_state()
    {
        var available = true;
        var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(available, Release, "已是最新")),
            (_, _, _) => Task.FromResult("update.zip"), (_, _) => Task.FromResult(false), _ => null, () => { }, (_, _) => Task.FromResult(true));
        await updates.CheckAndPrepareAsync();
        Assert.NotNull(updates.ReadyRelease);
        available = false;
        await updates.CheckAndPrepareAsync();
        Assert.Null(updates.ReadyRelease);
        Assert.Equal("已是最新", updates.Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_or_source_change_during_confirmation_never_launches(bool changeSource)
    {
        using var cancellation = new CancellationTokenSource();
        var confirmation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var launches = 0;
        var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, Release, "")),
            (_, _, _) => Task.FromResult("update.zip"), (_, _) => { entered.SetResult(); return confirmation.Task; },
            _ => { launches++; return null; }, () => throw new InvalidOperationException("Unexpected shutdown"), (_, _) => Task.FromResult(true));
        var work = updates.CheckAndPrepareAsync(ct: cancellation.Token);
        await entered.Task;
        if (changeSource) updates.ResetSource(); else cancellation.Cancel();
        confirmation.SetResult(true);
        await work;
        Assert.Equal(0, launches);
        Assert.False(updates.InstallationStarted);
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public async Task Already_cancelled_check_does_not_start_network_work()
    {
        var s = new Scenario();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var updates = s.Create();
        await updates.CheckAndPrepareAsync(ct: cancellation.Token);
        Assert.Empty(s.Events);
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public async Task No_prompt_before_download_and_validation_then_consent_precedes_install()
    {
        var s = new Scenario { Accept = true, DownloadGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var updates = s.Create();
        var work = updates.CheckAndPrepareAsync();
        Assert.True(updates.IsBusy);
        Assert.Null(updates.ReadyRelease);
        Assert.Equal(new[] { "check", "download" }, s.Events);
        s.DownloadGate.SetResult("update.zip");
        await work;
        Assert.Equal(new[] { "check", "download", "validate", "confirm", "launch", "shutdown" }, s.Events);
        Assert.True(updates.InstallationStarted);
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public async Task Declining_keeps_package_for_later_and_does_not_prompt_repeatedly_in_background()
    {
        var s = new Scenario();
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        await updates.CheckAndPrepareAsync();
        Assert.Single(s.Events, e => e == "download");
        Assert.Single(s.Events, e => e == "confirm");
        Assert.DoesNotContain("launch", s.Events);
        Assert.NotNull(updates.ReadyRelease);
        s.Accept = true;
        await updates.InstallPreparedAsync();
        Assert.Single(s.Events, e => e == "download");
        Assert.Contains("shutdown", s.Events);
    }

    [Fact]
    public async Task Manual_recheck_can_prompt_again_without_redownloading()
    {
        var s = new Scenario();
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        await updates.CheckAndPrepareAsync(promptAgain: true);
        Assert.Equal(2, s.Events.Count(e => e == "confirm"));
        Assert.Single(s.Events, e => e == "download");
    }

    [Fact]
    public async Task Startup_and_manual_checks_cannot_download_or_prompt_twice()
    {
        var s = new Scenario { DownloadGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var updates = s.Create();
        var first = updates.CheckAndPrepareAsync();
        await updates.CheckAndPrepareAsync(promptAgain: true);
        await updates.InstallPreparedAsync();
        s.DownloadGate.SetResult("update.zip");
        await first;
        Assert.Single(s.Events, e => e == "check");
        Assert.Single(s.Events, e => e == "download");
        Assert.Single(s.Events, e => e == "confirm");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Download_failure_or_cancellation_does_not_prompt_and_can_retry(bool cancelled)
    {
        var s = new Scenario { DownloadError = cancelled ? new OperationCanceledException() : new IOException("offline") };
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        Assert.Null(updates.ReadyRelease);
        Assert.False(updates.IsBusy);
        Assert.DoesNotContain("confirm", s.Events);
        s.DownloadError = null;
        await updates.CheckAndPrepareAsync();
        Assert.Contains("confirm", s.Events);
    }

    [Fact]
    public async Task Source_change_during_download_discards_old_result()
    {
        var s = new Scenario { DownloadGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var updates = s.Create();
        var work = updates.CheckAndPrepareAsync();
        updates.ResetSource();
        s.DownloadGate.SetResult("old-source.zip");
        await work;
        Assert.Null(updates.ReadyRelease);
        Assert.DoesNotContain("confirm", s.Events);
        Assert.Contains("来源已改变", updates.Status);
    }

    [Fact]
    public async Task Damaged_cached_package_cannot_prompt_or_install()
    {
        var s = new Scenario();
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        s.Valid = false;
        await updates.InstallPreparedAsync();
        Assert.Single(s.Events, e => e == "confirm");
        Assert.DoesNotContain("launch", s.Events);
        Assert.Null(updates.ReadyRelease);
        Assert.Contains("校验失败", updates.Status);
    }

    [Fact]
    public async Task Failed_installer_launch_keeps_app_open_and_package_available()
    {
        var s = new Scenario { Accept = true, LaunchError = "已取消提权" };
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        Assert.DoesNotContain("shutdown", s.Events);
        Assert.NotNull(updates.ReadyRelease);
        Assert.False(updates.InstallationStarted);
        Assert.Contains("已取消提权", updates.Status);
    }

    [Fact]
    public async Task Newly_downloaded_but_invalid_package_never_prompts()
    {
        var s = new Scenario { Valid = false, Accept = true };
        var updates = s.Create();
        await updates.CheckAndPrepareAsync();
        Assert.Null(updates.ReadyRelease);
        Assert.DoesNotContain("confirm", s.Events);
        Assert.DoesNotContain("launch", s.Events);
    }

    [Fact]
    public async Task Latest_version_never_downloads_or_prompts()
    {
        var s = new Scenario { Available = false };
        await s.Create().CheckAndPrepareAsync();
        Assert.Equal(new[] { "check" }, s.Events);
    }
}
