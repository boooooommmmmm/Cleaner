using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Interop;
using Ellipse = System.Windows.Shapes.Ellipse;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Cleaning;

namespace CleanSweep.App.Tests;

public sealed class QuickOptimizeTests
{
    private static QuickOptimizeResult Result(bool cancel = false) => new(
        new CleanReport { FilesQuarantined = 12, QuarantinedBytes = 32 * 1024 * 1024, FreedBytes = 0, Cancelled = cancel },
        1024 * 1024 * 1024, 900 * 1024 * 1024, 23.4, "仅测量", 15);

    [Fact]
    public async Task Results_distinguish_quarantine_from_freed_space_and_preserve_negative_memory_change()
    {
        var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result()));
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.Equal(12, vm.ProcessedFiles);
        Assert.Equal(32 * 1024 * 1024, vm.QuarantinedBytes);
        Assert.Equal(0, vm.FreedBytes);
        Assert.Equal(-124 * 1024 * 1024, vm.MemoryDelta);
        Assert.Equal(23.4, vm.BootSeconds);
        Assert.True(vm.HasResult);
        Assert.False(vm.ReleaseStandby);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task Missing_samples_are_unknown_instead_of_zero_or_estimated_benefits()
    {
        var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result() with { MemoryAfter = null, BootSeconds = null }));
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.True(double.IsNaN(vm.MemoryDelta));
        Assert.True(double.IsNaN(vm.BootSeconds));
        Assert.Contains("未读取", vm.MemoryDetail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Requested_memory_operation_only_claims_completion_when_it_succeeded(bool succeeded)
    {
        var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result() with
        { MemorySucceeded = succeeded, MemoryMessage = succeeded ? "已请求释放" : "内存操作已跳过：需要管理员权限" }))
        { ReleaseStandby = true };
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.Equal(!succeeded, vm.Headline.Contains("内存操作未完成"));
        Assert.Equal(12, vm.ProcessedFiles);
        Assert.True(vm.HasResult);
    }

    [Fact]
    public async Task Cancellation_keeps_partial_results_and_unhandled_failure_never_claims_success()
    {
        var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result(cancel: true)));
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.Contains("已停止", vm.Headline);
        Assert.Equal(12, vm.ProcessedFiles);
        Assert.True(vm.HasResult);
        var failed = new QuickOptimizeViewModel((_, _, _) => throw new IOException("simulated disk error"));
        await failed.OptimizeCommand.ExecuteAsync(null);
        Assert.False(failed.HasResult);
        Assert.True(double.IsNaN(failed.FreedBytes));
        Assert.Contains("未完成", failed.Headline);
        Assert.False(failed.IsBusy);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Busy_external_task_and_empty_scope_do_not_run(bool busy)
    {
        var vm = new QuickOptimizeViewModel((_, _, _) => throw new InvalidOperationException("must not run"),
            () => busy ? "清理正在运行" : null) { CleanTemp = busy, CleanCache = false, CleanLogs = false };
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.False(vm.IsBusy);
        Assert.False(vm.HasResult);
        Assert.Contains(busy ? "等待完成" : "至少勾选", vm.Detail);
    }

    [Fact]
    public async Task Run_is_single_flight_uses_a_scope_snapshot_and_cancellation_reaches_worker()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        QuickOptimizeRequest? seen = null;
        var calls = 0;
        var vm = new QuickOptimizeViewModel(async (request, _, ct) =>
        {
            calls++;
            seen = request;
            entered.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return Result();
        }) { CleanCache = false, CleanLogs = false };
        var work = vm.OptimizeCommand.ExecuteAsync(null);
        await entered.Task;
        Assert.False(vm.CanEditScope);
        Assert.False(vm.OptimizeCommand.CanExecute(null));
        Assert.False(vm.NavigateCommand.CanExecute("隔离区"));
        Assert.Contains("一键优化", UpdateInstallGuard.BlockReason([new NavItem { Title = "一键优化", Glyph = "", Page = vm }]));
        vm.CleanTemp = false;
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.Equal(1, calls);
        Assert.True(seen!.Scope.Temp);
        Assert.False(seen.Scope.WebCache);
        Assert.False(seen.Scope.Logs);
        Assert.False(seen.ReleaseStandby);
        vm.OptimizeCancelCommand.Execute(null);
        await work.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(vm.IsBusy);
        Assert.False(vm.HasResult);
        Assert.Null(UpdateInstallGuard.BlockReason([new NavItem { Title = "一键优化", Glyph = "", Page = vm }]));
    }

    [Fact]
    public void Late_progress_does_not_overwrite_completed_results()
    {
        WpfTestHost.Run(() =>
        {
            IProgress<QuickOptimizeProgress>? captured = null;
            var vm = new QuickOptimizeViewModel((_, progress, _) => { captured = progress; return Task.FromResult(Result()); });
            vm.OptimizeCommand.ExecuteAsync(null).GetAwaiter().GetResult();
            captured!.Report(new("stale", "stale", 10));
            WpfTestHost.Drain();
            Assert.Equal("本次结果", vm.Stage);
            Assert.Equal(100, vm.Progress);
        });
    }

    [Theory]
    [InlineData(740, 560)]
    [InlineData(960, 720)]
    public void Real_page_binds_results_scope_and_actions_without_horizontal_overflow(int width, int height)
    {
        WpfTestHost.Run(() =>
        {
            var navigated = "";
            var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result()), navigate: title => navigated = title);
            var page = new QuickOptimizePage { DataContext = vm, FontFamily = new FontFamily("Segoe UI, Microsoft YaHei UI") };
            Layout(page, width, height);
            var descendants = Descendants(page).ToArray();
            var action = Assert.Single(descendants.OfType<Button>(), b => Equals(b.Content, "一键优化"));
            Assert.Same(vm.OptimizeCommand, action.Command);
            Assert.True(action.IsEnabled);
            var checkboxes = descendants.OfType<CheckBox>().ToArray();
            Assert.Equal(4, checkboxes.Length);
            Assert.Equal(3, checkboxes.Count(c => c.IsChecked == true));
            Assert.Equal(0, Assert.Single(descendants.OfType<ScrollViewer>(), s => s.Content is StackPanel).ScrollableWidth);
            SaveImage(page, $"home-idle-{width}.png", width, height);
            vm.OptimizeCommand.ExecuteAsync(null).GetAwaiter().GetResult();
            Layout(page, width, height);
            var metrics = descendants.OfType<AnimatedMetric>().ToArray();
            Assert.Equal(5, metrics.Length);
            Assert.Contains(metrics, m => m.Text.StartsWith("−") && m.Kind == "signedBytes");
            Assert.Contains(metrics, m => m.Value == 0 && m.Text == "0 B");
            Assert.Contains(metrics, m => m.Text.Contains("23.4"));
            var link = Assert.Single(descendants.OfType<Button>(), b => Equals(b.CommandParameter, "开机加速"));
            link.Command!.Execute(link.CommandParameter);
            Assert.Equal("开机加速", navigated);
            SaveImage(page, $"home-result-{width}.png", width, height);
        });
    }

    [Fact]
    public async Task Real_page_shows_stop_and_disables_scope_while_worker_is_running()
    {
        Task? work = null;
        QuickOptimizeViewModel? vm = null;
        QuickOptimizePage? page = null;
        WpfTestHost.Run(() =>
        {
            vm = new QuickOptimizeViewModel(async (_, _, ct) => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return Result(); });
            page = new QuickOptimizePage { DataContext = vm };
            Layout(page, 960, 720);
            work = vm.OptimizeCommand.ExecuteAsync(null);
            WpfTestHost.Drain();
            var children = Descendants(page).ToArray();
            Assert.All(children.OfType<CheckBox>(), c => Assert.False(c.IsEnabled));
            var stop = Assert.Single(children.OfType<Button>(), b => Equals(b.Content, "停止优化"));
            Assert.Equal(Visibility.Visible, stop.Visibility);
            Assert.True(stop.IsEnabled);
            Assert.Same(vm.OptimizeCancelCommand, stop.Command);
            stop.Command!.Execute(null);
        });
        await work!.WaitAsync(TimeSpan.FromSeconds(5));
        WpfTestHost.Run(() =>
        {
            WpfTestHost.Drain();
            Assert.False(vm!.IsBusy);
            Assert.All(Descendants(page!).OfType<CheckBox>(), c => Assert.True(c.IsEnabled));
        });
    }

    [Fact]
    public void Metric_formats_unknown_zero_negative_and_changed_units()
    {
        WpfTestHost.Run(() =>
        {
            var metric = new AnimatedMetric();
            Assert.Equal("—", metric.Text);
            metric.Value = -1024;
            metric.Kind = "signedBytes";
            Assert.Equal("−1 KB", metric.Text);
            metric.Value = 0;
            Assert.Equal("0 B", metric.Text);
            metric.Value = double.NaN;
            Assert.Equal("—", metric.Text);
        });
    }

    [Fact]
    public void Loaded_page_starts_and_stops_animation_with_the_running_state()
    {
        WpfTestHost.Run(() =>
        {
            // A hidden HWND attaches the real visual tree without showing a window or starting services.
            using var source = new HwndSource(new HwndSourceParameters("CleanSweep animation verification")
            { Width = 960, Height = 720, WindowStyle = unchecked((int)0x80000000) });
            var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result()));
            var page = new QuickOptimizePage { DataContext = vm };
            source.RootVisual = page;
            Layout(page, 960, 720);
            Assert.True(page.IsLoaded);
            var orbit = Assert.Single(Descendants(page).OfType<Ellipse>(), e => e.RenderTransform is RotateTransform);
            var rotation = (RotateTransform)orbit.RenderTransform;
            vm.IsBusy = true;
            WpfTestHost.Drain();
            Assert.Equal(SystemParameters.ClientAreaAnimation && orbit.IsVisible, rotation.HasAnimatedProperties);
            var metric = Assert.Single(Descendants(page).OfType<AnimatedMetric>(), m => m.Kind == "signedBytes");
            vm.MemoryDelta = 1024 * 1024;
            WpfTestHost.Drain();
            Assert.Equal(SystemParameters.ClientAreaAnimation, metric.HasAnimatedProperties);
            vm.IsBusy = false;
            WpfTestHost.Drain();
            Assert.False(rotation.HasAnimatedProperties);
            source.RootVisual = null;
            WpfTestHost.Drain();
        });
    }

    private static void Layout(FrameworkElement page, int width, int height)
    {
        page.Measure(new Size(width, height));
        page.Arrange(new Rect(0, 0, width, height));
        page.UpdateLayout();
        WpfTestHost.Drain();
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    private static void SaveImage(Visual page, string name, int width, int height)
    {
        var directory = Environment.GetEnvironmentVariable("CLEANSWEEP_UI_ARTIFACTS");
        if (string.IsNullOrWhiteSpace(directory)) return;
        Directory.CreateDirectory(directory);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(page);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(directory, name));
        encoder.Save(file);
    }
}
