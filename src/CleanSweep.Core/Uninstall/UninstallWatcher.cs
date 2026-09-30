using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Storage;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Uninstall;

/// <summary>
/// 卸载事件监听（设计文档 3.3.4）：RegNotifyChangeKeyValue 监视 Uninstall 键（HKLM 64 / 32、HKCU）与应用商店包仓库，
/// 再加 Windows Installer 事件日志（MsiInstaller 1034 产品已移除）。任一信号触发后去抖 3 秒重新扫描清单，
/// 比对出消失的应用写入卸载历史并抛出事件。只在程序运行期间生效，默认关闭，开启时界面明确告知。
/// </summary>
public sealed class UninstallWatcher : IDisposable
{
    private const int RegNotifyChangeName = 0x1;
    private const int RegNotifyChangeLastSet = 0x4;

    private readonly AppInventory _inventory;
    private readonly UninstallHistory _history;
    private readonly OperationLog _log;
    private readonly ManualResetEvent _stop = new(false);
    private readonly List<(RegistryKey Key, AutoResetEvent Event)> _watches = new();
    private EventLogWatcher? _eventLog;
    private Thread? _thread;
    private Dictionary<string, InstalledApp> _known = new(StringComparer.OrdinalIgnoreCase);

    public UninstallWatcher(AppInventory inventory, UninstallHistory history, OperationLog log)
    {
        _inventory = inventory;
        _history = history;
        _log = log;
    }

    /// <summary>检测到应用消失。在后台线程触发。</summary>
    public event EventHandler<IReadOnlyList<InstalledApp>>? AppsRemoved;

    public bool IsRunning => _thread is { IsAlive: true };

    public void Start()
    {
        if (IsRunning) return;
        _stop.Reset();
        _known = _inventory.Scan().Apps.ToDictionary(a => a.Id, a => a, StringComparer.OrdinalIgnoreCase);

        foreach (var (hive, view, sub) in new[]
                 {
                     (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (RegistryHive.CurrentUser, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (RegistryHive.CurrentUser, RegistryView.Registry64, @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"),
                 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                var key = baseKey.OpenSubKey(sub, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.Notify | RegistryRights.ReadKey);
                if (key is null) continue;
                var evt = new AutoResetEvent(false);
                Arm(key.Handle, evt);
                _watches.Add((key, evt));
            }
            catch (Exception ex)
            {
                _log.Write(null, "uninstall-watch", "start", $"{hive}\\{sub}", 0, false, ex.Message);
            }
        }

        try
        {
            var query = new EventLogQuery("Application", PathType.LogName,
                "*[System[Provider[@Name='MsiInstaller'] and (EventID=1034 or EventID=11724)]]");
            _eventLog = new EventLogWatcher(query);
            _eventLog.EventRecordWritten += (_, _) => Poke();
            _eventLog.Enabled = true;
        }
        catch (Exception ex)
        {
            _eventLog = null;
            _log.Write(null, "uninstall-watch", "start", "eventlog", 0, false, ex.Message);
        }

        _thread = new Thread(Loop) { IsBackground = true, Name = "CleanSweep.UninstallWatcher" };
        _thread.Start();
        _log.Write(null, "uninstall-watch", "start", null, 0, true, $"监视 {_watches.Count} 个注册表键{(_eventLog is null ? "" : "与 MsiInstaller 事件")}");
    }

    private readonly AutoResetEvent _poke = new(false);

    private void Poke() => _poke.Set();

    private void Arm(SafeRegistryHandle handle, AutoResetEvent evt)
    {
        var rc = RegNotifyChangeKeyValue(handle, true, RegNotifyChangeName | RegNotifyChangeLastSet, evt.SafeWaitHandle, true);
        if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
    }

    private void Loop()
    {
        var handles = new List<WaitHandle> { _stop, _poke };
        handles.AddRange(_watches.Select(w => (WaitHandle)w.Event));
        var arr = handles.ToArray();

        while (true)
        {
            var idx = WaitHandle.WaitAny(arr);
            if (idx == 0) return;

            // 去抖：卸载过程会连续改动多次，等 3 秒安静后再扫
            while (WaitHandle.WaitAny(arr, TimeSpan.FromSeconds(3)) is var again && again != WaitHandle.WaitTimeout)
            {
                if (again == 0) return;
            }

            // 通知是一次性的，重新布防（在扫描前，避免漏掉扫描期间的变化）
            foreach (var (key, evt) in _watches)
            {
                try { Arm(key.Handle, evt); } catch { }
            }

            try { Rescan(); }
            catch (Exception ex) { _log.Write(null, "uninstall-watch", "rescan", null, 0, false, ex.Message); }
        }
    }

    private void Rescan()
    {
        var now = _inventory.Scan().Apps.ToDictionary(a => a.Id, a => a, StringComparer.OrdinalIgnoreCase);
        var removed = _known.Values.Where(a => !now.ContainsKey(a.Id)).ToList();
        _known = now;
        if (removed.Count == 0) return;

        foreach (var app in removed)
        {
            _history.Record(app, "watcher");
            _log.Write(null, "uninstall-watch", "removed", app.Name, 0, true, app.Publisher);
        }
        AppsRemoved?.Invoke(this, removed);
    }

    public void Stop()
    {
        _stop.Set();
        try { _thread?.Join(TimeSpan.FromSeconds(5)); } catch { }
        _thread = null;
        if (_eventLog is not null)
        {
            try { _eventLog.Enabled = false; _eventLog.Dispose(); } catch { }
            _eventLog = null;
        }
        foreach (var (key, evt) in _watches)
        {
            try { key.Dispose(); } catch { }
            try { evt.Dispose(); } catch { }
        }
        _watches.Clear();
    }

    public void Dispose()
    {
        Stop();
        _stop.Dispose();
        _poke.Dispose();
    }

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern int RegNotifyChangeKeyValue(SafeRegistryHandle hKey, bool bWatchSubtree, int dwNotifyFilter, SafeWaitHandle hEvent, bool fAsynchronous);
}
