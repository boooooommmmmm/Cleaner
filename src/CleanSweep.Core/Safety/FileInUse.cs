namespace CleanSweep.Core.Safety;

/// <summary>
/// "文件正在被其他程序使用"的统一判定：ERROR_SHARING_VIOLATION（32）与 ERROR_LOCK_VIOLATION（33）。
/// 句柄级移动把 Win32 错误码原样放进 IOException.HResult，.NET 自己的文件 API 则给 0x8007xxxx 形式的 HRESULT，两种都认。
/// 显卡驱动的着色器缓存、开始菜单进程的磁贴缓存、浏览器运行中的缓存都属于这一类：不是错误，
/// 只是这次不能动，清理引擎按"跳过"计数而不是"失败"，界面不为它们弹失败对话框。
/// </summary>
public static class FileInUse
{
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;

    public static bool Is(Exception? ex)
    {
        while (ex is not null)
        {
            if (ex is IOException io && (io.HResult & 0xFFFF) is ErrorSharingViolation or ErrorLockViolation && (io.HResult >> 16 & 0x7FFF) is 0 or 0x0007) return true;
            ex = ex.InnerException;
        }
        return false;
    }
}
