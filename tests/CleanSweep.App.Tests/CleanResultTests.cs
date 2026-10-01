using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class CleanResultTests
{
    private static ScanItemViewModel Row(string name, RiskLevel risk, long size = 10, bool allowed = true) => new(new ScanItem
    {
        Id = name, DisplayName = name, ModuleId = "test", Group = "cache", Risk = risk,
        SizeBytes = size, Path = @"C:\cache\" + name,
    }, allowed, "");

    private static CleanPageViewModel Page(params ScanItemViewModel[] rows)
    {
        var page = new CleanPageViewModel(null!, "test", "", () => []);
        page.Groups.Add(new ScanGroupViewModel("cache", rows));
        page.HasResults = true;
        return page;
    }

    [Theory]
    [InlineData(CleanRiskFilter.Safe, RiskLevel.Safe)]
    [InlineData(CleanRiskFilter.Confirm, RiskLevel.Confirm)]
    [InlineData(CleanRiskFilter.High, RiskLevel.High)]
    [InlineData(CleanRiskFilter.NotRecommended, RiskLevel.NotRecommended)]
    public void Risk_filter_and_keyword_must_both_match(CleanRiskFilter filter, RiskLevel expected)
    {
        var rows = Enum.GetValues<RiskLevel>().Select(r => Row("Cache-" + r, r)).Append(Row("Other", expected)).ToArray();
        var page = Page(rows);
        page.FilterText = "cache-";
        page.RiskFilter = filter;
        var visible = Assert.Single(rows, r => r.IsVisible);
        Assert.Equal(expected, visible.Risk);
        Assert.StartsWith("Cache-", visible.Name);
        Assert.StartsWith("显示 1/5 项", page.VisibleResultsText);
        Assert.True(page.HasActiveFilter);
    }

    [Fact]
    public void Risk_filter_never_selects_items_and_bulk_commands_leave_hidden_selection_alone()
    {
        var safe = Row("safe", RiskLevel.Safe);
        var high = Row("high", RiskLevel.High);
        var denied = Row("denied", RiskLevel.High, allowed: false);
        var page = Page(safe, high, denied);
        page.RiskFilter = CleanRiskFilter.High;
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.False(high.IsSelected);
        Assert.True(safe.IsSelected);
        page.Groups[0].IsChecked = true;
        Assert.True(page.CleanCommand.CanExecute(null));
        Assert.False(denied.IsSelected);
        Assert.Equal(new[] { high }, page.Groups[0].SelectedVisibleItems);
        Assert.Contains("筛选外 1 项本次不处理", page.SelectedText);
        page.SelectNoneCommand.Execute(null);
        Assert.True(safe.IsSelected);
        Assert.False(high.IsSelected);
        page.ClearFilterCommand.Execute(null);
        Assert.Equal(new[] { safe }, page.Groups[0].SelectedVisibleItems);
    }

    [Fact]
    public void Clear_restores_collapsed_groups_and_empty_results_disable_cleanup()
    {
        var page = Page(Row("Alpha", RiskLevel.Safe));
        var group = page.Groups[0];
        group.IsExpanded = false;
        page.RiskFilter = CleanRiskFilter.Safe;
        Assert.True(group.IsExpanded);
        page.FilterText = "missing";
        Assert.True(page.HasNoVisibleResults);
        Assert.False(group.IsVisible);
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.StartsWith("显示 0/1 项", page.VisibleResultsText);
        page.SortOrder = CleanSortOrder.SizeDescending;
        page.ClearFilterCommand.Execute(null);
        Assert.False(page.HasNoVisibleResults);
        Assert.False(page.HasActiveFilter);
        Assert.False(group.IsExpanded);
        Assert.True(group.IsVisible);
        Assert.Equal(CleanSortOrder.SizeDescending, page.SortOrder);
        Assert.True(page.CleanCommand.CanExecute(null));
    }

    [Fact]
    public void Sorting_is_stable_preserves_rows_and_restores_original_order_after_removal()
    {
        var beta = Row("Beta", RiskLevel.High, 20);
        var alpha = Row("Alpha", RiskLevel.Confirm, 50);
        var gamma = Row("Gamma", RiskLevel.Safe, 50);
        var page = Page(beta, alpha, gamma);
        var group = page.Groups[0];
        alpha.IsSelected = true;
        alpha.IsDetailOpen = true;
        page.SortOrder = CleanSortOrder.SizeDescending;
        Assert.Equal(new[] { alpha, gamma, beta }, group.Items);
        page.SortOrder = CleanSortOrder.RiskAscending;
        Assert.Equal(new[] { gamma, alpha, beta }, group.Items);
        page.SortOrder = CleanSortOrder.NameAscending;
        Assert.Equal(new[] { alpha, beta, gamma }, group.Items);
        page.RiskFilter = CleanRiskFilter.Confirm;
        Assert.Equal(new[] { alpha }, group.SelectedVisibleItems);
        Assert.True(alpha.IsDetailOpen);
        Assert.False(beta.IsSelected);
        group.Remove(alpha);
        page.SortOrder = CleanSortOrder.ScanOrder;
        Assert.Equal(new[] { beta, gamma }, group.Items);
        Assert.True(page.HasNoVisibleResults);
        page.ClearFilterCommand.Execute(null);
        Assert.Equal(new[] { gamma }, group.SelectedVisibleItems);
    }

    [Fact]
    public void Newly_added_groups_use_active_filter_and_sort_and_removed_groups_stop_notifying()
    {
        var page = Page(Row("first", RiskLevel.Safe));
        page.RiskFilter = CleanRiskFilter.High;
        page.SortOrder = CleanSortOrder.SizeDescending;
        var small = Row("small", RiskLevel.High, 1);
        var large = Row("large", RiskLevel.High, 99);
        var hidden = Row("hidden", RiskLevel.Safe, 100);
        var added = new ScanGroupViewModel("new", [small, large, hidden]);
        page.Groups.Add(added);
        Assert.Equal(new[] { large, small }, added.Items.Where(i => i.IsVisible));
        Assert.False(hidden.IsVisible);
        Assert.StartsWith("显示 2/4 项", page.VisibleResultsText);
        page.Groups.Remove(added);
        var changes = 0;
        page.PropertyChanged += (_, _) => changes++;
        large.IsSelected = true;
        Assert.Equal(0, changes);
    }

    [Fact]
    public void Ignore_command_rejects_busy_or_stale_rows()
    {
        var row = Row("selected", RiskLevel.Safe);
        var page = Page(row);
        Assert.True(page.IgnoreItemCommand.CanExecute(row));
        page.IsBusy = true;
        Assert.False(page.IgnoreItemCommand.CanExecute(row));
        page.IsBusy = false;
        page.Groups[0].Remove(row);
        Assert.False(page.IgnoreItemCommand.CanExecute(row));
        Assert.False(page.IgnoreItemCommand.CanExecute(null));
    }

    [Fact]
    public void Real_page_selectors_update_filter_sort_and_clear_button()
    {
        WpfTestHost.Run(() =>
        {
            var small = Row("small", RiskLevel.Safe, 10);
            var large = Row("large", RiskLevel.Safe, 100);
            var high = Row("high", RiskLevel.High, 200);
            var model = Page(small, large, high);
            var page = new CleanPage { DataContext = model };
            page.Measure(new Size(1100, 850));
            page.Arrange(new Rect(0, 0, 1100, 850));
            page.UpdateLayout();
            WpfTestHost.Drain();
            var combos = Descendants(page).OfType<ComboBox>().ToArray();
            var risk = Assert.Single(combos, c => AutomationProperties.GetName(c) == "按风险筛选");
            var sort = Assert.Single(combos, c => AutomationProperties.GetName(c) == "组内排序");
            var ignoreButtons = Descendants(page).OfType<Button>().Where(b => Equals(b.Content, "忽略")).ToArray();
            Assert.NotEmpty(ignoreButtons);
            Assert.All(ignoreButtons, button => Assert.True(button.IsEnabled));
            model.IsBusy = true;
            WpfTestHost.Drain();
            Assert.All(ignoreButtons, button => Assert.False(button.IsEnabled));
            model.IsBusy = false;
            WpfTestHost.Drain();
            Assert.All(ignoreButtons, button => Assert.True(button.IsEnabled));
            risk.SelectedValue = CleanRiskFilter.Safe;
            sort.SelectedValue = CleanSortOrder.SizeDescending;
            WpfTestHost.Drain();
            Assert.Equal(CleanRiskFilter.Safe, model.RiskFilter);
            Assert.Equal(CleanSortOrder.SizeDescending, model.SortOrder);
            Assert.Equal(new[] { large, small }, model.Groups[0].Items.Where(i => i.IsVisible));
            var clear = Assert.Single(Descendants(page).OfType<Button>(), b => Equals(b.Content, "清除筛选"));
            Assert.Equal(Visibility.Visible, clear.Visibility);
            Assert.Same(model.ClearFilterCommand, clear.Command);
            clear.Command.Execute(null);
            WpfTestHost.Drain();
            Assert.Equal(CleanRiskFilter.All, risk.SelectedValue);
            Assert.Equal(Visibility.Collapsed, clear.Visibility);
            Assert.True(high.IsVisible);
            Assert.False(high.IsSelected);
        });
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
}
