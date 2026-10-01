using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Model;
using CleanSweep.Core.Modules;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.Tests;

public sealed class DuplicateSelectionTests
{
    private static DuplicatesViewModel Model(int copies = 3)
    {
        var model = new DuplicatesViewModel(null!, new AppSettings(), Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        foreach (var name in new[] { "first", "second" })
            model.Groups.Add(new DuplicateGroupViewModel(new DuplicateGroup(10, name,
                Enumerable.Range(0, copies).Select(i => new FileEntry($@"C:\{name}\{i}.txt", 10, DateTime.UtcNow.AddDays(i))).ToArray())));
        return model;
    }

    private static (DuplicatesPage Page, ListBox List) Page(DuplicatesViewModel model)
    {
        var page = new DuplicatesPage { DataContext = model };
        page.Measure(new Size(1400, 800));
        page.Arrange(new Rect(0, 0, 1400, 800));
        page.UpdateLayout();
        WpfTestHost.Drain();
        return (page, (ListBox)page.FindName("FilesList"));
    }

    [Fact]
    public void Real_page_row_click_checkbox_and_multi_selection_share_one_state() => WpfTestHost.Run(() =>
    {
        var model = Model();
        var (page, list) = Page(model);
        Assert.Equal(SelectionMode.Extended, list.SelectionMode);
        Assert.Equal(6, list.Items.Count);
        var row = (ListBoxItem)list.ItemContainerGenerator.ContainerFromItem(model.FileRows[1]);
        // Enter WPF's real click-selection path without giving a test window desktop focus.
        typeof(ListBox).GetMethod("NotifyListItemClicked", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(list, [row, MouseButton.Left]);
        WpfTestHost.Drain();
        Assert.True(model.FileRows[1].IsSelected);
        Assert.Single(list.SelectedItems);

        list.SelectedItems.Add(model.FileRows[4]);
        Assert.True(model.FileRows[4].IsSelected);
        Assert.Contains("2 个副本", model.SelectedText);
        var checkbox = Descendants(row).OfType<CheckBox>().Single();
        typeof(CheckBox).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(checkbox, null);
        WpfTestHost.Drain();
        Assert.False(model.FileRows[1].IsSelected);
        Assert.True(model.FileRows[4].IsSelected);
        Assert.Single(list.SelectedItems);

        var open = Descendants(row).OfType<Button>().Single();
        var opened = false;
        open.Command = new RelayCommand(() => opened = true);
        typeof(Button).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(open, null);
        Assert.True(opened);
        Assert.False(model.FileRows[1].IsSelected);
        Assert.Single(list.SelectedItems);

        model.ClearSelectionCommand.Execute(null);
        WpfTestHost.Drain();
        Assert.Empty(list.SelectedItems);
        Assert.False(model.QuarantineSelectedCommand.CanExecute(null));
        GC.KeepAlive(page);
    });

    [Fact]
    public void Shift_ranges_cross_groups_shrink_and_ctrl_shift_adds_a_range() => WpfTestHost.Run(() =>
    {
        var model = Model();
        var (_, list) = Page(model);
        void Select(string method, int index, params object[] arguments)
        {
            var row = list.ItemContainerGenerator.ContainerFromItem(model.FileRows[index]);
            // Exercise WPF's modifier-key branches without changing the user's keyboard state.
            typeof(ListBox).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(list, new object[] { row }.Concat(arguments).ToArray());
            WpfTestHost.Drain();
        }
        int[] Selected() => model.FileRows.Select((row, index) => (row, index))
            .Where(p => p.row.IsSelected).Select(p => p.index).ToArray();

        Select("MakeSingleSelection", 1);
        Select("MakeAnchorSelection", 4, true);
        Assert.Equal(new[] { 1, 2, 3, 4 }, Selected());
        Select("MakeAnchorSelection", 0, true);
        Assert.Equal(new[] { 0, 1 }, Selected());
        Select("MakeToggleSelection", 5);
        Assert.Equal(new[] { 0, 1, 5 }, Selected());
        Select("MakeAnchorSelection", 4, false);
        Assert.Equal(new[] { 0, 1, 4, 5 }, Selected());
        Select("MakeToggleSelection", 0);
        Assert.Equal(new[] { 1, 4, 5 }, Selected());
    });

    [Fact]
    public void Select_all_includes_offscreen_groups_and_escape_clears_them() => WpfTestHost.Run(() =>
    {
        var model = Model(50);
        var (_, list) = Page(model);
        var selectAll = (RoutedCommand)typeof(ListBox).GetField("SelectAllCommand", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        selectAll.Execute(null, list);
        WpfTestHost.Drain();
        Assert.Equal(100, list.SelectedItems.Count);
        Assert.All(model.FileRows, f => Assert.True(f.IsSelected));
        Assert.All(model.Groups, g => Assert.Equal(g.Files.Count, g.SelectedCount));
        Assert.False(model.QuarantineSelectedCommand.CanExecute(null));
        Assert.Contains("2 组已全选", model.SelectedText);
        list.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, new TestPresentationSource(), 0, Key.Escape)
            { RoutedEvent = Keyboard.PreviewKeyDownEvent });
        Assert.Empty(list.SelectedItems);
        Assert.All(model.FileRows, f => Assert.False(f.IsSelected));
    });

    [Fact]
    public void Toolbar_updates_visual_selection_and_is_disabled_while_busy() => WpfTestHost.Run(() =>
    {
        var model = Model();
        var (_, list) = Page(model);
        model.KeepOldestInAllGroupsCommand.Execute(null);
        WpfTestHost.Drain();
        Assert.Equal(4, list.SelectedItems.Count);
        Assert.All(model.Groups, g => Assert.False(g.Files[0].IsSelected));
        Assert.True(model.QuarantineSelectedCommand.CanExecute(null));
        model.IsBusy = true;
        WpfTestHost.Drain();
        Assert.False(list.IsEnabled);
        Assert.False(model.ClearSelectionCommand.CanExecute(null));
        Assert.False(model.KeepOldestInAllGroupsCommand.CanExecute(null));
    });

    [Fact]
    public void Removing_rows_preserves_other_selections_and_rescan_unsubscribes_old_groups() => WpfTestHost.Run(() =>
    {
        var model = Model();
        var (_, list) = Page(model);
        list.SelectedItems.Add(model.FileRows[1]);
        var survivor = model.FileRows[4];
        list.SelectedItems.Add(survivor);
        model.Groups[0].Files.RemoveAt(1);
        WpfTestHost.Drain();
        Assert.True(survivor.IsSelected);
        Assert.Single(list.SelectedItems);
        Assert.Equal(5, model.FileRows.Count);
        var old = model.Groups[1];
        model.Groups.Clear();
        WpfTestHost.Drain();
        old.Files.Add(new DuplicateFileViewModel(new FileEntry(@"C:\old.txt", 10, DateTime.UtcNow), old));
        Assert.Empty(model.FileRows);
        Assert.Empty(list.Items);
    });

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    private sealed class TestPresentationSource : PresentationSource
    {
        public override Visual RootVisual { get; set; } = null!;
        public override bool IsDisposed => false;
        protected override CompositionTarget GetCompositionTargetCore() => null!;
    }
}
