namespace CleanSweep.Core.Safety;

/// <summary>
/// "拒绝访问"的统一判定。句柄级移动（<see cref="Cleaning.HandleMove"/>）把 Win32 错误包装成带原生错误码的 IOException，
/// 而 .NET 自己的文件 API 抛 UnauthorizedAccessException；界面决定是否交给提权服务时两种都要认，但不能把所有 IOException 当成权限问题。
/// </summary>
public static class AccessDenied
{
    private const int ErrorAccessDenied = 5;
    private const int ErrorPrivilegeNotHeld = 1314;

    public static bool Is(Exception? ex)
    {
        while (ex is not null)
        {
            if (ex is UnauthorizedAccessException) return true;
            if (ex is IOException io && (io.HResult & 0xFFFF) is ErrorAccessDenied or ErrorPrivilegeNotHeld && (io.HResult >> 16 & 0x7FFF) is 0 or 0x0007) return true;
            ex = ex.InnerException;
        }
        return false;
    }
}
