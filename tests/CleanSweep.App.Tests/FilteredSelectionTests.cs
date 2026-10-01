using CleanSweep.App.ViewModels;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class FilteredSelectionTests
{
    private static ScanItemViewModel Item(string name, bool canSelect = true) => new(new ScanItem
    {
        Id = name, ModuleId = "review", Group = "cache", DisplayName = name,
        Path = @"C:\cache\" + name, SizeBytes = 10, Risk = RiskLevel.Safe,
    }, canSelect, "");

    [Fact]
    public void Filtered_execution_excludes_hidden_selection_and_preserves_it_for_later()
    {
        var chrome = Item("Chrome");
        var edge = Item("Edge");
        var group = new ScanGroupViewModel("cache", new[] { chrome, edge });
        group.ApplyFilter("Chrome");
        Assert.Equal(new[] { chrome }, group.SelectedVisibleItems);
        Assert.Equal(10, group.SelectedBytes);
        Assert.True(edge.IsSelected);
        group.ApplyFilter("");
        Assert.Equal(2, group.SelectedCount);
    }

    [Fact]
    public void Group_checkbox_only_changes_visible_selectable_items()
    {
        var visible = Item("Chrome");
        var hidden = Item("Edge");
        var denied = Item("Chrome protected", false);
        var group = new ScanGroupViewModel("cache", new[] { visible, hidden, denied });
        group.ApplyFilter("Chrome");
        group.IsChecked = false;
        Assert.False(visible.IsSelected);
        Assert.True(hidden.IsSelected);
        Assert.False(group.IsChecked);
        group.IsChecked = true;
        Assert.True(visible.IsSelected);
        Assert.False(denied.IsSelected);
        Assert.True(group.IsChecked);
    }

    [Fact]
    public void Filter_changes_notify_selection_and_hide_empty_groups()
    {
        var item = Item("Chrome");
        var group = new ScanGroupViewModel("cache", new[] { item });
        var notifications = 0;
        group.SelectionChanged += (_, _) => notifications++;
        group.ApplyFilter("missing");
        Assert.False(group.IsVisible);
        Assert.Empty(group.SelectedVisibleItems);
        Assert.True(notifications > 0);
        group.ApplyFilter("Chrome");
        group.Remove(item);
        Assert.False(group.IsVisible);
    }

    [Fact]
    public void Page_disables_clean_when_only_hidden_items_are_selected()
    {
        // These commands only manage selection; no services or disk operations are invoked.
        var page = new CleanPageViewModel(null!, "review", "", () => []);
        var visible = Item("Chrome");
        var hidden = Item("Edge");
        var group = new ScanGroupViewModel("cache", new[] { visible, hidden });
        page.Groups.Add(group);
        page.HasResults = true;
        page.FilterText = "Chrome";
        Assert.True(page.CleanCommand.CanExecute(null));
        page.SelectNoneCommand.Execute(null);
        Assert.False(page.CleanCommand.CanExecute(null));
        Assert.True(hidden.IsSelected);
        page.FilterText = "Edge";
        Assert.True(page.CleanCommand.CanExecute(null));
    }
}
