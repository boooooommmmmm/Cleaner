using System.Windows.Controls;
using System.Windows.Input;

namespace CleanSweep.App.Views;

public partial class DuplicatesPage : UserControl
{
    public DuplicatesPage()
    {
        InitializeComponent();
    }

    private void FilesList_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Escape || !FilesList.IsEnabled) return;
        FilesList.UnselectAll();
        e.Handled = true;
    }
}
