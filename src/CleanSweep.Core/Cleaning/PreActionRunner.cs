using System.ServiceProcess;
using CleanSweep.Core.Rules;

namespace CleanSweep.Core.Cleaning;

/// <summary>执行清理前动作，并在清理后恢复（如停止 wuauserv 再重启）。</summary>
public interface IPreActionRunner
{
    /// <summary>执行动作，返回用于恢复的句柄；失败返回 null 并给出原因。</summary>
    IDisposable? Run(string action, out string? error);
}

public sealed class ServicePreActionRunner : IPreActionRunner
{
    private static readonly IReadOnlySet<string> AllowedServices =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "wuauserv", "bits", "DoSvc", "FontCache", "SysMain", "WSearch" };

    /// <summary>停止命令发出后等待服务停下的时间。</summary>
    public TimeSpan StopTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>恢复时若服务仍在停止过程中（StopPending），再等待多久。</summary>
    public TimeSpan RestoreWait { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>恢复失败（服务没能重新启动）时的回调，供调用方记录日志。</summary>
    public Action<string>? OnRestoreFailure { get; init; }

    public IDisposable? Run(string action, out string? error)
    {
        error = null;
        var (verb, arg) = PreActionSyntax.Parse(action);

        if (verb != PreActionSyntax.StopService)
        {
            error = $"未知动作：{verb}";
            return null;
        }

        if (!AllowedServices.Contains(arg))
        {
            error = $"服务不在允许停止的列表内：{arg}";
            return null;
        }

        try
        {
            var sc = new ServiceController(arg);
            var status = sc.Status;
            if (status == ServiceControllerStatus.Stopped)
            {
                sc.Dispose();
                return new NoopRestore();
            }

            if (!sc.CanStop)
            {
                error = $"服务不允许停止：{arg}";
                sc.Dispose();
                return null;
            }

            sc.Stop();
            try
            {
                sc.WaitForStatus(ServiceControllerStatus.Stopped, StopTimeout);
            }
            catch (System.ServiceProcess.TimeoutException)
            {
                // 停止命令已发出但未在期限内停下：视为失败（依赖它的项目跳过），但仍返回恢复句柄，
                // 服务稍后停下时由本次操作负责重新启动
                error = $"停止服务 {arg} 超时，服务可能稍后才停止";
                return new RestartOnDispose(sc, RestoreWait, OnRestoreFailure);
            }
            return new RestartOnDispose(sc, RestoreWait, OnRestoreFailure);
        }
        catch (Exception ex)
        {
            error = $"停止服务 {arg} 失败：{ex.Message}";
            return null;
        }
    }

    private sealed class NoopRestore : IDisposable
    {
        public void Dispose() { }
    }

    /// <summary>
    /// 恢复：本次操作发出过停止命令，就要负责把服务拉起来。服务还在 StopPending 时等它停稳再启动；
    /// 等不到或启动失败都通过回调报告，不能静默放过。
    /// </summary>
    private sealed class RestartOnDispose : IDisposable
    {
        private readonly ServiceController _sc;
        private readonly TimeSpan _wait;
        private readonly Action<string>? _onFailure;

        public RestartOnDispose(ServiceController sc, TimeSpan wait, Action<string>? onFailure)
        {
            _sc = sc;
            _wait = wait;
            _onFailure = onFailure;
        }

        public void Dispose()
        {
            try
            {
                _sc.Refresh();
                if (_sc.Status == ServiceControllerStatus.StopPending)
                {
                    try { _sc.WaitForStatus(ServiceControllerStatus.Stopped, _wait); }
                    catch (System.ServiceProcess.TimeoutException)
                    {
                        _onFailure?.Invoke($"服务 {_sc.ServiceName} 在 {_wait.TotalSeconds:0} 秒内仍未停止，无法重新启动；它是按需启动的服务，系统需要时会自动拉起");
                        return;
                    }
                    _sc.Refresh();
                }

                if (_sc.Status == ServiceControllerStatus.Stopped)
                {
                    _sc.Start();
                    try { _sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); }
                    catch (System.ServiceProcess.TimeoutException)
                    {
                        _onFailure?.Invoke($"服务 {_sc.ServiceName} 已发出启动命令但 30 秒内未进入运行状态");
                    }
                }
            }
            catch (Exception ex)
            {
                _onFailure?.Invoke($"重新启动服务 {_sc.ServiceName} 失败：{ex.Message}");
            }
            finally
            {
                _sc.Dispose();
            }
        }
    }
}

/// <summary>测试用：不执行任何真实动作。</summary>
public sealed class NullPreActionRunner : IPreActionRunner
{
    public IDisposable? Run(string action, out string? error)
    {
        error = null;
        return new Noop();
    }

    private sealed class Noop : IDisposable { public void Dispose() { } }
}
