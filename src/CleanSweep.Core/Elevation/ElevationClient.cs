using System.IO.Pipes;

namespace CleanSweep.Core.Elevation;

/// <summary>界面侧的提权服务客户端。服务不存在时调用方退回单进程提权模式。</summary>
public static class ElevationClient
{
    public static async Task<ElevationResponse> SendAsync(ElevationRequest request, TimeSpan timeout, string pipeName = ElevationProtocol.DefaultPipeName, CancellationToken ct = default)
    {
        // Identification 级模拟：服务端只能读取我们的身份（SID），不能以我们的身份执行任何操作
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        await pipe.ConnectAsync((int)Math.Min(timeout.TotalMilliseconds, int.MaxValue), cts.Token).ConfigureAwait(false);
        await ElevationProtocol.WriteAsync(pipe, request, cts.Token).ConfigureAwait(false);
        var response = await ElevationProtocol.ReadAsync<ElevationResponse>(pipe, cts.Token).ConfigureAwait(false);
        return response ?? new ElevationResponse(false, "服务在回应前断开了连接");
    }

    /// <summary>管道对象是否存在（服务未安装时立即返回 false，不必等连接超时）。</summary>
    public static bool PipeExists(string pipeName = ElevationProtocol.DefaultPipeName)
    {
        try { return File.Exists(@"\\.\pipe\" + pipeName); }
        catch { return false; }
    }

    /// <summary>服务是否在线（管道存在且 Ping 成功）。</summary>
    public static async Task<bool> IsAvailableAsync(string pipeName = ElevationProtocol.DefaultPipeName)
    {
        if (!PipeExists(pipeName)) return false;
        try
        {
            var r = await SendAsync(new ElevationRequest(ElevatedOperation.Ping), TimeSpan.FromSeconds(2), pipeName).ConfigureAwait(false);
            return r.Success;
        }
        catch
        {
            return false;
        }
    }
}
