using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class TargetedPreviewTests
{
    private static ScanItem Item => new() { Id = "cache", ModuleId = "orphan-directories", Group = "app", DisplayName = "cache", Risk = RiskLevel.Confirm };

    [Fact]
    public async Task Preview_never_restores_selections_and_repeated_scan_keeps_scope()
    {
        var settings = new AppSettings();
        settings.RememberCleaningSelection(Item, true);
        var page = new CleanPageViewModel("test", (_, _) => Task.FromResult<IReadOnlyList<ScanItemViewModel>>([new(Item)]), settings);
        Assert.True(page.TrySetScanScope(() => [], "仅此应用"));
        for (var i = 0; i < 2; i++)
        {
            await page.ScanCommand.ExecuteAsync(null);
            Assert.True(page.HasScanScope);
            Assert.Equal("仅此应用", page.ScanScopeText);
            Assert.False(Assert.Single(Assert.Single(page.Groups).Items).IsSelected);
            Assert.True(settings.CleaningSelectionFor(Item));
            Assert.False(page.CleanCommand.CanExecute(null));
        }
    }

    [Fact]
    public void Switching_scope_clears_old_results_and_filters_but_busy_switch_is_refused()
    {
        var page = new CleanPageViewModel("test", (_, _) => Task.FromResult<IReadOnlyList<ScanItemViewModel>>([]));
        page.Groups.Add(new ScanGroupViewModel("old", [new(Item)]));
        page.FilterText = "old";
        page.RiskFilter = CleanRiskFilter.High;
        page.IsBusy = true;
        Assert.False(page.TrySetScanScope(() => [], "new"));
        Assert.Single(page.Groups);
        Assert.False(page.HasScanScope);
        Assert.False(page.ScanAllCommand.CanExecute(null));
        page.IsBusy = false;
        Assert.True(page.TrySetScanScope(() => [], "new"));
        Assert.Empty(page.Groups);
        Assert.False(page.HasResults);
        Assert.False(page.HasActiveFilter);
    }

    [Fact]
    public async Task Scan_all_clears_scope_and_restores_normal_selection_behavior()
    {
        var settings = new AppSettings();
        settings.RememberCleaningSelection(Item, true);
        var page = new CleanPageViewModel("test", (_, _) => Task.FromResult<IReadOnlyList<ScanItemViewModel>>([new(Item)]), settings);
        page.TrySetScanScope(() => [], "target");
        await page.ScanCommand.ExecuteAsync(null);
        page.ScanAllCommand.Execute(null);
        if (page.ScanCommand.ExecutionTask is { } task) await task;
        Assert.False(page.HasScanScope);
        Assert.Null(page.ScanScopeText);
        Assert.True(Assert.Single(Assert.Single(page.Groups).Items).IsSelected);
    }

    [Fact]
    public async Task Failed_preview_keeps_scope_and_does_not_leave_actionable_rows()
    {
        var page = new CleanPageViewModel("test", (_, _) => throw new IOException("scan unavailable"));
        page.TrySetScanScope(() => [], "target");
        await page.ScanCommand.ExecuteAsync(null);
        Assert.True(page.HasScanScope);
        Assert.Empty(page.Groups);
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.Contains("scan unavailable", page.Status);
    }

    [Fact]
    public async Task Cancelled_preview_keeps_scope_for_retry()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var page = new CleanPageViewModel("test", async (_, ct) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return [];
        });
        page.TrySetScanScope(() => [], "target");
        var scan = page.ScanCommand.ExecuteAsync(null);
        await started.Task;
        page.CancelCommand.Execute(null);
        await scan;
        Assert.True(page.HasScanScope);
        Assert.False(page.IsBusy);
        Assert.Empty(page.Groups);
        Assert.Contains("取消", page.Status);
    }

    [Fact]
    public void Scope_banner_and_scan_all_button_bind_on_real_page()
    {
        WpfTestHost.Run(() =>
        {
            var model = new CleanPageViewModel(null!, "test", "", () => []);
            var view = new CleanPage { DataContext = model };
            view.Measure(new Size(1200, 1000));
            view.Arrange(new Rect(0, 0, 1200, 1000));
            view.UpdateLayout();
            var button = Descendants(view).OfType<Button>().Single(b => Equals(b.Content, "扫描全部应用残留"));
            var banner = Assert.IsType<WrapPanel>(VisualTreeHelper.GetParent(button));
            Assert.Equal(Visibility.Collapsed, banner.Visibility);
            model.TrySetScanScope(() => [], "当前仅预览：测试应用");
            WpfTestHost.Drain();
            view.UpdateLayout();
            Assert.Equal(Visibility.Visible, banner.Visibility);
            Assert.Same(model.ScanAllCommand, button.Command);
            Assert.Contains(Descendants(view).OfType<TextBlock>(), t => t.Text == model.ScanScopeText);
            model.IsBusy = true;
            WpfTestHost.Drain();
            Assert.False(button.IsEnabled);
        });
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }
}
