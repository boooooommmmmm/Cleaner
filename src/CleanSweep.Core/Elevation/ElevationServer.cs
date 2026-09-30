using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using CleanSweep.Core.Startup;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Elevation;

/// <summary>经核实的连接方身份。</summary>
public sealed record ElevationClientIdentity(SecurityIdentifier Sid, string UserName, int ProcessId, string? ExePath);

public interface IElevatedOperations
{
    ElevationResponse Execute(ElevationRequest request, ElevationClientIdentity client, CancellationToken ct);
}

public sealed class ElevationServerOptions
{
    public string PipeName { get; init; } = ElevationProtocol.DefaultPipeName;

    /// <summary>允许连接的用户 SID（安装服务的交互用户）。Administrators 组始终允许。</summary>
    public IReadOnlySet<string> AllowedClientSids { get; init; } = new HashSet<string>();

    /// <summary>允许的客户端可执行文件完整路径（安装时登记的 CleanSweep.exe）。为空则只允许与服务同目录的可执行文件。</summary>
    public IReadOnlySet<string> AllowedClientExePaths { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>要求客户端可执行文件带有效签名且发布者与服务自身一致。开发构建未签名时关闭。</summary>
    public bool RequireSignedClient { get; init; } = true;

    /// <summary>单个连接的处理超时。</summary>
    public TimeSpan ConnectionTimeout { get; init; } = TimeSpan.FromMinutes(30);

    public Action<string, bool>? Log { get; init; }
}

/// <summary>
/// 提权服务的命名管道服务端（设计文档 7.4 安全要求）：
/// 1. 管道 ACL 只给 Administrators 与登记的交互用户 SID；
/// 2. 每次连接核对客户端进程的 SID（管道模拟令牌）与可执行文件路径 / 签名；
/// 3. 只接受 <see cref="ElevationRequest"/> 枚举型指令，每个连接处理一条请求后断开；
/// 4. 所有文件操作由 <see cref="IElevatedOperations"/> 实现方经 Path Guard 与全部引擎约束执行。
/// </summary>
public sealed class ElevationServer : IDisposable
{
    private readonly IElevatedOperations _ops;
    private readonly ElevationServerOptions _options;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public ElevationServer(IElevatedOperations ops, ElevationServerOptions options)
    {
        _ops = ops;
        _options = options;
    }

    public string PipeName => _options.PipeName;

    public void Start()
    {
        if (_loop is not null) return;
        _loop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = NamedPipeServerStreamAcl.Create(_options.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, ElevationProtocol.MaxFrameBytes, ElevationProtocol.MaxFrameBytes,
                    BuildSecurity());
            }
            catch (Exception ex)
            {
                _options.Log?.Invoke("创建管道失败：" + ex.Message, false);
                await Task.Delay(1000, ct).ConfigureAwait(false);
                continue;
            }

            try
            {
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                server.Dispose();
                return;
            }
            catch (Exception ex)
            {
                _options.Log?.Invoke("等待连接失败：" + ex.Message, false);
                server.Dispose();
                continue;
            }

            _ = Task.Run(() => HandleAsync(server, ct), ct);
        }
    }

    /// <summary>管道 DACL：Administrators 与登记的用户 SID 可读写；没有其他 ACE，其余主体连接被拒。</summary>
    internal PipeSecurity BuildSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        var me = WindowsIdentity.GetCurrent().User;
        if (me is not null) security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (var sid in _options.AllowedClientSids)
        {
            try { security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid), PipeAccessRights.ReadWrite, AccessControlType.Allow)); }
            catch { /* 非法 SID 忽略 */ }
        }
        // 显式拒绝网络登录：命名管道可被远程访问
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return security;
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken outer)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(outer);
        timeout.CancelAfter(_options.ConnectionTimeout);
        var ct = timeout.Token;
        using (pipe)
        {
            ElevationClientIdentity? client = null;
            try
            {
                var verdict = VerifyClient(pipe, out client);
                if (verdict is not null)
                {
                    _options.Log?.Invoke($"拒绝连接：{verdict}", false);
                    await TryWrite(pipe, new ElevationResponse(false, "连接被拒绝：" + verdict), ct).ConfigureAwait(false);
                    return;
                }

                ElevationRequest? request;
                try
                {
                    request = await ElevationProtocol.ReadAsync<ElevationRequest>(pipe, ct).ConfigureAwait(false);
                }
                catch (InvalidDataException ex)
                {
                    _options.Log?.Invoke($"{client!.UserName} 发送了非法请求：{ex.Message}", false);
                    await TryWrite(pipe, new ElevationResponse(false, "请求格式非法"), ct).ConfigureAwait(false);
                    return;
                }
                if (request is null) return;

                if (!Enum.IsDefined(request.Operation))
                {
                    await TryWrite(pipe, new ElevationResponse(false, $"未知指令 {(int)request.Operation}"), ct).ConfigureAwait(false);
                    return;
                }

                ElevationResponse response;
                try
                {
                    response = _ops.Execute(request, client!, ct);
                }
                catch (Exception ex)
                {
                    response = new ElevationResponse(false, ex.Message);
                }
                _options.Log?.Invoke($"{client!.UserName} → {ElevationProtocol.Describe(request)}：{response.Message}", response.Success);
                await TryWrite(pipe, response, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _options.Log?.Invoke($"处理连接出错（{client?.UserName ?? "未知"}）：{ex.Message}", false);
            }
        }
    }

    private static async Task TryWrite(Stream s, ElevationResponse r, CancellationToken ct)
    {
        try { await ElevationProtocol.WriteAsync(s, r, ct).ConfigureAwait(false); } catch { }
    }

    /// <summary>核对连接方。返回 null 表示通过，否则为拒绝原因。</summary>
    internal string? VerifyClient(NamedPipeServerStream pipe, out ElevationClientIdentity? client)
    {
        client = null;

        // 1. 客户端进程 → 进程令牌 → SID。直接读对方进程的令牌，不在服务线程上做模拟（模拟会改变本线程后续所有操作的身份）
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) return "无法获取客户端进程 ID";

        SecurityIdentifier? sid;
        string userName;
        bool isAdmin;
        string? exe;
        try
        {
            using var p = Process.GetProcessById((int)pid);
            exe = p.MainModule?.FileName;
            using var identity = IdentityOfProcess(p.Handle);
            sid = identity.User;
            userName = identity.Name;
            isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex)
        {
            return "无法读取客户端进程身份：" + ex.Message;
        }
        if (sid is null) return "客户端没有 SID";

        bool sidOk = _options.AllowedClientSids.Contains(sid.Value) || isAdmin;
        if (!sidOk) return $"用户 {userName} 不在允许列表内";

        // 2. 客户端进程可执行文件
        if (exe is null) return "无法读取客户端进程映像";

        var exeFull = Path.GetFullPath(exe);
        bool pathOk = _options.AllowedClientExePaths.Count == 0
            ? string.Equals(Path.GetDirectoryName(exeFull), AppContext.BaseDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
            : _options.AllowedClientExePaths.Contains(exeFull);
        if (!pathOk) return $"客户端程序 {exeFull} 未登记";

        if (_options.RequireSignedClient)
        {
            var sig = FileSignature.Inspect(exeFull);
            if (sig.State is not (SignatureState.Signed or SignatureState.SignedMicrosoft)) return "客户端程序没有有效签名";
            var mine = FileSignature.Inspect(System.Environment.ProcessPath);
            if (!string.Equals(sig.Publisher, mine.Publisher, StringComparison.Ordinal)) return "客户端程序的签名发布者与服务不一致";
        }

        client = new ElevationClientIdentity(sid, userName, (int)pid, exeFull);
        return null;
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        _cts.Dispose();
    }

    /// <summary>TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE：WindowsIdentity 会复制令牌，IsInRole 需要模拟级副本。</summary>
    private const uint TokenAccess = 0x0008 | 0x0002 | 0x0004;

    private static WindowsIdentity IdentityOfProcess(IntPtr processHandle)
    {
        if (!OpenProcessToken(processHandle, TokenAccess, out var token))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken 失败");
        try
        {
            return new WindowsIdentity(token);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
