using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CleanSweep.Core.Safety;

/// <summary>
/// 从提权进程启动"不提权"的程序。本程序以管理员身份运行时直接 Process.Start 出来的子进程都带提权令牌，
/// 重启资源管理器时尤其要避免：提权的 explorer 会让拖放失效、从它启动的每个程序都变成管理员。
/// 做法：在结束旧 explorer 之前复制它的（普通用户）主令牌，用 CreateProcessWithTokenW 以该令牌启动新进程。
/// 拿不到令牌或调用失败时由调用方退回普通启动并明确告知。
/// </summary>
public static class UnelevatedProcess
{
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;

    /// <summary>复制目标进程的主令牌（TOKEN_DUPLICATE 需要对方与自己同用户，或自己是管理员）。失败返回 IntPtr.Zero。</summary>
    public static IntPtr DuplicatePrimaryTokenOf(Process process)
    {
        try
        {
            if (!OpenProcessToken(process.Handle, TokenQuery | TokenDuplicate, out var source)) return IntPtr.Zero;
            try
            {
                if (!DuplicateTokenEx(source, TokenQuery | TokenDuplicate | TokenAssignPrimary | TokenAdjustDefault | TokenAdjustSessionId,
                        IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var primary))
                    return IntPtr.Zero;
                return primary;
            }
            finally
            {
                CloseHandle(source);
            }
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    public static void CloseToken(IntPtr token)
    {
        if (token != IntPtr.Zero) CloseHandle(token);
    }

    /// <summary>用给定主令牌启动程序。需要 SeImpersonatePrivilege（管理员有）。返回 null 表示成功，否则为失败原因。</summary>
    public static string? TryStart(IntPtr token, string exePath, string? arguments)
    {
        if (token == IntPtr.Zero) return "没有可用的令牌";
        var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        var commandLine = "\"" + exePath + "\"" + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
        if (!CreateProcessWithTokenW(token, 0, exePath, commandLine, 0, IntPtr.Zero, Path.GetDirectoryName(exePath), ref si, out var pi))
            return new Win32Exception(Marshal.GetLastWin32Error()).Message;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return null;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes, int impersonationLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string? applicationName, string commandLine, uint creationFlags,
        IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
