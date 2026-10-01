using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class AppUpdateImprovementsTests
{
    private static readonly ReleaseInfo Release = new(new Version(0, 20, 0), "update.zip", "https://example.com/update.zip", "hash", 10, "notes", "test");

    [Fact]
    public async Task Cancel_interrupts_download_and_allows_explicit_retry()
    {
        var attempts = 0;
        var prompts = 0;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, Release, "")),
            async (_, _, ct) =>
            {
                if (++attempts == 1) { entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, ct); }
                return "update.zip";
            }, (_, _) => { prompts++; return Task.FromResult(false); }, _ => throw new Exception("Unexpected install"), () => { },
            (_, _) => Task.FromResult(true));
        var work = updates.CheckAndPrepareAsync();
        await entered.Task;
        Assert.True(updates.IsDownloading);
        Assert.True(updates.CancelCommand.CanExecute(null));
        updates.CancelCommand.Execute(null);
        await work.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(updates.IsBusy);
        Assert.False(updates.IsDownloading);
        Assert.False(updates.CancelCommand.CanExecute(null));
        Assert.Null(updates.ReadyRelease);
        Assert.Equal(0, prompts);
        await updates.CheckAndPrepareAsync();
        Assert.Equal(2, attempts);
        Assert.Equal(1, prompts);
        Assert.Equal(Release, updates.ReadyRelease);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Restore_validates_local_package_without_network_or_prompt(bool valid)
    {
        var prompts = 0;
        var launches = 0;
        var updates = new AppUpdateCoordinator(_ => throw new Exception("Unexpected network check"),
            (_, _, _) => throw new Exception("Unexpected download"),
            (_, _) => { prompts++; return Task.FromResult(true); }, _ => { launches++; return null; }, () => { },
            (_, _) => Task.FromResult(valid),
            _ => Task.FromResult<PreparedAppUpdate?>(new(Release, "update.zip")));
        await updates.RestorePreparedAsync();
        Assert.Equal(valid ? Release : null, updates.ReadyRelease);
        Assert.Equal(0, prompts);
        Assert.Equal(0, launches);
        await updates.InstallPreparedAsync();
        Assert.Equal(valid ? 1 : 0, prompts);
        Assert.Equal(valid ? 1 : 0, launches);
    }

    [Fact]
    public async Task Source_change_during_restore_discards_old_package()
    {
        var gate = new TaskCompletionSource<PreparedAppUpdate?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var updates = new AppUpdateCoordinator(_ => throw new Exception(), (_, _, _) => throw new Exception(),
            (_, _) => throw new Exception(), _ => throw new Exception(), () => { },
            (_, _) => Task.FromResult(true), _ => gate.Task);
        var work = updates.RestorePreparedAsync();
        updates.ResetSource();
        gate.SetResult(new(Release, "update.zip"));
        await work;
        Assert.Null(updates.ReadyRelease);
        Assert.Contains("来源已改变", updates.Status);
        Assert.False(updates.IsBusy);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Busy_task_before_or_during_confirmation_defers_install_until_manual_retry(bool busyDuringPrompt)
    {
        var busy = !busyDuringPrompt;
        var prompts = 0;
        var launches = 0;
        var shutdowns = 0;
        var updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, Release, "")),
            (_, _, _) => Task.FromResult("update.zip"),
            (_, _) => { prompts++; if (busyDuringPrompt && prompts == 1) busy = true; return Task.FromResult(true); },
            _ => { launches++; return null; }, () => shutdowns++, (_, _) => Task.FromResult(true),
            installBlocker: () => busy ? "清理正在运行" : null);
        await updates.CheckAndPrepareAsync();
        Assert.Equal(busyDuringPrompt ? 1 : 0, prompts);
        Assert.Equal(0, launches);
        Assert.Equal(0, shutdowns);
        Assert.NotNull(updates.ReadyRelease);
        Assert.Contains("清理正在运行", updates.Status);
        busy = false;
        await updates.InstallPreparedAsync();
        Assert.Equal(1, launches);
        Assert.Equal(1, shutdowns);
    }

    [Fact]
    public void Installation_guard_includes_busy_page_that_is_not_selected()
    {
        var cleaning = new CleanPageViewModel(null!, "系统清理", "", () => []) { IsBusy = true };
        NavItem[] items = [
            new() { Title = "设置", Glyph = "", Page = new object(), IsSelected = true },
            new() { Title = "系统清理", Glyph = "", Page = cleaning, IsSelected = false }
        ];
        Assert.Contains("系统清理", UpdateInstallGuard.BlockReason(items));
        cleaning.IsBusy = false;
        Assert.Null(UpdateInstallGuard.BlockReason(items));
    }
}
