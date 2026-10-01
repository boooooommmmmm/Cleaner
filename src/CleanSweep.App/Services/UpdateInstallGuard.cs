using CleanSweep.App.ViewModels;

namespace CleanSweep.App.Services;

/// <summary>检查所有导航页，避免切换页面后漏掉仍在运行的任务。</summary>
internal static class UpdateInstallGuard
{
    internal static string? BlockReason(IEnumerable<NavItem> items)
    {
        foreach (var item in items)
        {
            var busy = item.Page switch
            {
                CleanPageViewModel page => page.IsBusy,
                DuplicatesViewModel page => page.IsBusy,
                DiskViewModel page => page.IsBusy,
                UninstallViewModel page => page.IsBusy,
                QuarantineViewModel page => page.IsBusy,
                ShredViewModel page => page.IsBusy,
                StartupViewModel page => page.IsBusy,
                OptimizeViewModel page => page.IsBusy,
                DriverViewModel page => page.IsBusy,
                RepairViewModel page => page.IsBusy,
                MemoryViewModel page => page.IsBusy,
                HardwareViewModel page => page.IsBusy,
                SpaceAnalyzerViewModel page => page.IsBusy,
                SystemInfoViewModel page => page.IsBusy,
                SettingsViewModel page => page.IsUpdating,
                _ => false,
            };
            if (busy) return $"“{item.Title}”正在执行任务";
        }
        return null;
    }
}
