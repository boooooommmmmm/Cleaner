using System.Text.Json;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class CleanExecutionReportTests
{
    private static ScanItem Item(string id) => new() { Id = id, DisplayName = id, ModuleId = "test", Group = "test", Path = @"C:\cache\" + id };
    private static CleanExecutionReport Report(params ScanItem[] items)
    {
        var report = new CleanReport();
        foreach (var item in items) report.Failures.Add(new(item.Id, item.DisplayName, item.Path, "changed", CleanIssueKind.Changed));
        return CleanExecutionReport.Create("test", items, report, new HashSet<string>(), new Dictionary<string, bool>(), [], "summary");
    }

    [Fact]
    public void Filtering_does_not_truncate_export_or_change_rescan_scope()
    {
        var items = Enumerable.Range(0, 125).Select(i => Item("item-" + i)).ToArray();
        var snapshot = Report(items);
        var page = new CleanPageViewModel(null!, "test", "", () => []);
        page.SetExecutionReport(snapshot);
        page.ReportFilter = page.ReportFilters.Single(f => f.Kind == CleanIssueKind.Permission);
        Assert.Empty(page.ReportRows);
        using var doc = JsonDocument.Parse(snapshot.ToJson());
        Assert.Equal(125, doc.RootElement.GetProperty("Rows").GetArrayLength());
        Assert.Equal(125, snapshot.IncompleteIds.Count);
        Assert.True(page.RescanIncompleteCommand.CanExecute(null));
        page.IsBusy = true;
        Assert.False(page.RescanIncompleteCommand.CanExecute(null));
        Assert.False(page.ExportReportCommand.CanExecute(null));
    }

    [Fact]
    public async Task Rescan_replaces_stale_rows_limits_ids_and_never_restores_selection()
    {
        var old = Item("old");
        var fresh = new ScanItemViewModel(old with { SizeBytes = 1000 });
        var other = new ScanItemViewModel(Item("new-unrelated"));
        var settings = new AppSettings();
        settings.RememberCleaningSelection(old, true);
        int scans = 0;
        var page = new CleanPageViewModel("test", (_, _) =>
        {
            scans++;
            return Task.FromResult<IReadOnlyList<ScanItemViewModel>>([fresh, other]);
        }, settings);
        var stale = new ScanItemViewModel(old);
        page.Groups.Add(new ScanGroupViewModel("test", [stale]));
        var snapshot = Report(old, Item("disappeared"));
        page.SetExecutionReport(snapshot);
        await page.RescanIncompleteCommand.ExecuteAsync(null);
        Assert.Equal(1, scans);
        Assert.Same(fresh, Assert.Single(Assert.Single(page.Groups).Items));
        Assert.False(fresh.IsSelected);
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.True(settings.CleaningSelectionFor(old));
        Assert.Same(snapshot, page.ExecutionReport);
        Assert.Contains("不代表此前删除成功", page.Status);
    }

    [Fact]
    public async Task Cancelled_rescan_keeps_report_and_does_not_publish_late_rows()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var page = new CleanPageViewModel("test", async (_, ct) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return [new ScanItemViewModel(Item("late"))];
        });
        var snapshot = Report(Item("old"));
        page.SetExecutionReport(snapshot);
        var scan = page.RescanIncompleteCommand.ExecuteAsync(null);
        await started.Task;
        page.CancelCommand.Execute(null);
        await scan;
        Assert.Empty(page.Groups);
        Assert.False(page.HasResults);
        Assert.Same(snapshot, page.ExecutionReport);
        Assert.True(page.ExportReportCommand.CanExecute(null));
    }

    [Fact]
    public void Unknown_service_result_is_not_success_and_export_records_limits()
    {
        var item = Item("service");
        var report = CleanExecutionReport.Create("test", [item], new CleanReport(),
            new HashSet<string> { item.Id }, new Dictionary<string, bool>(), [], "summary");
        Assert.False(Assert.Single(report.Items).Complete);
        Assert.Null(report.Items[0].Succeeded);
        Assert.Equal(CleanIssueKind.NotProcessed, Assert.Single(report.Rows).Kind);
        Assert.NotEmpty(report.Notes);
    }

    [Fact]
    public async Task Failed_rescan_clears_old_actionable_rows_and_keeps_export_available()
    {
        var page = new CleanPageViewModel("test", (_, _) => throw new IOException("scan failed"));
        page.Groups.Add(new ScanGroupViewModel("test", [new ScanItemViewModel(Item("old"))]));
        var snapshot = Report(Item("old"));
        page.SetExecutionReport(snapshot);
        await page.RescanIncompleteCommand.ExecuteAsync(null);
        Assert.Empty(page.Groups);
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.True(page.ExportReportCommand.CanExecute(null));
        Assert.Same(snapshot, page.ExecutionReport);
        Assert.Contains("scan failed", page.Status);
    }

    [Fact]
    public void Real_page_binds_result_filter_rows_and_busy_commands()
    {
        WpfTestHost.Run(() =>
        {
            var model = new CleanPageViewModel(null!, "test", "", () => []);
            model.SetExecutionReport(Report(Item("a")));
            var page = new CleanPage { DataContext = model };
            page.Measure(new Size(1200, 1000));
            page.Arrange(new Rect(0, 0, 1200, 1000));
            page.UpdateLayout();
            var expander = Descendants(page).OfType<Expander>().Single(e => Equals(e.Header, "上次清理结果与处理建议"));
            expander.IsExpanded = true;
            page.UpdateLayout();
            WpfTestHost.Drain();
            var combo = Descendants(page).OfType<ComboBox>().Single(c => AutomationProperties.GetName(c) == "清理结果分类");
            var grid = Descendants(page).OfType<DataGrid>().Single();
            Assert.Single(grid.Items.Cast<object>());
            combo.SelectedItem = model.ReportFilters.Single(f => f.Kind == CleanIssueKind.Permission);
            WpfTestHost.Drain();
            Assert.Empty(grid.Items.Cast<object>());
            var export = Descendants(page).OfType<Button>().Single(b => Equals(b.Content, "导出全部结果"));
            Assert.Same(model.ExportReportCommand, export.Command);
            Assert.True(export.IsEnabled);
            model.IsBusy = true;
            WpfTestHost.Drain();
            Assert.False(export.IsEnabled);
        });
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }
}
