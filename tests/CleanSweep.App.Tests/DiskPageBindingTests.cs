using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Disk;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.Tests;

public sealed class DiskPageBindingTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("D:")]
    [InlineData("D:|999")]
    [InlineData("Z:|Analyze")]
    public async Task Invalid_or_stale_request_reports_a_status_without_running_a_command(string? parameter)
    {
        var model = new DiskViewModel(null!);
        await model.RunCommand.ExecuteAsync(parameter);
        Assert.StartsWith("无法执行：", model.Status);
        Assert.False(model.IsBusy);
    }

    [Fact]
    public void Volume_buttons_send_the_displayed_volume_and_operation_to_the_command()
    {
        WpfTestHost.Run(() =>
        {
                // Load the real compiled page/resources without starting the application,
                // opening a window, requesting elevation or running any disk commands.
                var context = new DiskPageContext();
                var page = new DiskPage { DataContext = context };
                page.Measure(new Size(1400, 1000));
                page.Arrange(new Rect(0, 0, 1400, 1000));
                page.UpdateLayout();
                Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);

                var expected = new Dictionary<string, string>
                {
                    ["分析"] = "Analyze", ["优化"] = "Optimize", ["重新修剪"] = "Retrim",
                    ["碎片整理"] = "Defragment", ["计划检查磁盘"] = "ScheduleCheckDisk",
                };
                var buttons = Descendants(page).OfType<Button>()
                    .Where(b => expected.ContainsKey(b.Content?.ToString() ?? "")).ToArray();
                Assert.Equal(10, buttons.Length);
                foreach (var button in buttons)
                {
                    var row = Assert.IsType<VolumeRow>(button.DataContext);
                    var operation = expected[button.Content.ToString()!];
                    Assert.Equal($"{row.Letter}|{operation}", button.CommandParameter);
                    Assert.Same(context.RunCommand, button.Command);
                    context.LastParameter = null;
                    // OnClick executes the command; raising only the routed event does not.
                    typeof(Button).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .Invoke(button, null);
                    Assert.Equal(button.CommandParameter, context.LastParameter);
                }
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

    public sealed class DiskPageContext
    {
        public VolumeRow[] Volumes { get; } =
        [
            new() { Volume = new("D:", "Data", "NTFS", 1000, 500, 0, MediaKind.Hdd, DriveType.Fixed) },
            new() { Volume = new("E:", "SSD", "NTFS", 1000, 500, 1, MediaKind.Ssd, DriveType.Fixed) },
        ];
        public string? LastParameter { get; set; }
        public RelayCommand<string> RunCommand { get; }
        public DiskPageContext() => RunCommand = new(value => LastParameter = value);
    }
}
