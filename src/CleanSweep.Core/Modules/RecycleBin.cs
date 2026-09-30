using System.Runtime.InteropServices;

namespace CleanSweep.Core.Modules;

/// <summary>系统回收站，只经 Shell API 操作（设计文档 6.2 第 2 条）。</summary>
public static class RecycleBin
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO
    {
        public uint cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    private const uint SHERB_NOCONFIRMATION = 0x1;
    private const uint SHERB_NOPROGRESSUI = 0x2;
    private const uint SHERB_NOSOUND = 0x4;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBinW(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBinW(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    /// <summary>所有卷回收站的总大小与项数。</summary>
    public static (long SizeBytes, long Items) Query()
    {
        var info = new SHQUERYRBINFO { cbSize = (uint)Marshal.SizeOf<SHQUERYRBINFO>() };
        var hr = SHQueryRecycleBinW(null, ref info);
        return hr == 0 ? (info.i64Size, info.i64NumItems) : (0, 0);
    }

    public static (bool Ok, string? Error) Empty()
    {
        var hr = SHEmptyRecycleBinW(IntPtr.Zero, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        // E_UNEXPECTED (0x8000FFFF) 在回收站已为空时返回，视为成功
        if (hr == 0 || hr == unchecked((int)0x8000FFFF)) return (true, null);
        return (false, $"SHEmptyRecycleBin 返回 0x{hr:X8}");
    }
}
