using System.Windows;

namespace CleanSweep.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Closing += (_, e) =>
        {
            if (DataContext is not ViewModels.ShellViewModel { Home.IsBusy: true } shell) return;
            shell.Home.OptimizeCancelCommand.Execute(null);
            shell.Home.Detail = "正在停止优化并保存已处理结果，请稍后再关闭窗口。";
            e.Cancel = true;
        };
    }
}
