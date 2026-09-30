using System.Windows.Controls;
using System.Windows.Input;
using CleanSweep.App.ViewModels;
using CleanSweep.Core.Modules;

namespace CleanSweep.App.Views;

public partial class SpacePage : UserControl
{
    public SpacePage()
    {
        InitializeComponent();
    }

    private SpaceAnalyzerViewModel? Vm => DataContext as SpaceAnalyzerViewModel;

    private void TreeMapNodeClicked(object? sender, DirectoryNode node) => Vm?.NavigateCommand.Execute(node);

    private void RowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListView { SelectedItem: DirectoryRow row }) Vm?.NavigateCommand.Execute(row.Node);
    }

    private void FileDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListView { SelectedItem: LargeFileRow row }) Vm?.OpenInExplorerCommand.Execute(row.Entry.Path);
    }

    private void DriveChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox { SelectedItem: DriveItem d }) Vm?.SelectDriveCommand.Execute(d);
    }
}
