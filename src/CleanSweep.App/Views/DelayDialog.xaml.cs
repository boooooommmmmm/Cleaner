using System.Windows;
using System.Windows.Controls;

namespace CleanSweep.App.Views;

public partial class DelayDialog : Window
{
    public DelayDialog(string itemName)
    {
        InitializeComponent();
        TitleText.Text = $"延迟启动“{itemName}”";
    }

    public int Seconds { get; private set; } = 60;

    private void OnOk(object sender, RoutedEventArgs e)
    {
        if (DelayBox.SelectedItem is ComboBoxItem { Tag: string tag } && int.TryParse(tag, out var s))
            Seconds = s;
        DialogResult = true;
    }
}
