using System.Runtime.ExceptionServices;
using System.Windows.Threading;

namespace CleanSweep.App.Tests;

internal static class WpfTestHost
{
    private static readonly Lazy<Dispatcher> Ui = new(() =>
    {
        using var ready = new ManualResetEventSlim();
        Dispatcher? dispatcher = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                // Resources only: no App.Run, startup services, window or disk operation.
                var app = new global::CleanSweep.App.App();
                app.InitializeComponent();
                dispatcher = Dispatcher.CurrentDispatcher;
            }
            catch (Exception ex) { failure = ex; }
            finally { ready.Set(); }
            if (dispatcher is not null) Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!ready.Wait(TimeSpan.FromSeconds(30))) throw new TimeoutException("WPF initialization timed out");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        return dispatcher!;
    });

    public static void Run(Action action) => Ui.Value.Invoke(action);

    public static void Drain() => Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
}
