using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using CleanSweep.Core.Safety;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Cleaning;

/// <summary>
/// 基于句柄的移动。先打开源对象与目标目录，向内核核对两者的真实路径与调用方给出的逻辑路径一致，
/// 再通过同一个句柄执行重命名。校验和移动作用于同一个已打开的对象，路径在两步之间被换成
/// Junction / 符号链接也不会移错对象或落到错误位置，消除"检查后再按路径移动"的竞态窗口。
/// 源对象以"不跟随重解析点"方式打开：若源本身是链接，移动的只是链接本身。
/// </summary>
internal static class HandleMove
{
    private const uint Delete = 0x00010000;
    private const uint FileReadAttributes = 0x80;
    private const uint FileListDirectory = 0x1;
    private const uint FileTraverse = 0x20;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorInvalidName = 123;

    public static void Move(string sourcePath, string destDirectory, string destName)
    {
        if (string.IsNullOrEmpty(destName) || destName.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || destName is "." or "..")
            throw new ArgumentException("目标名称非法", nameof(destName));

        var source = PathGuard.Normalize(sourcePath);
        var destDir = PathGuard.Normalize(destDirectory);

        using var hSource = Open(source, Delete | FileReadAttributes, FileFlagBackupSemantics | FileFlagOpenReparsePoint, "源对象");
        VerifySame(hSource, source, "源对象");

        using var hDir = Open(destDir, FileReadAttributes | FileTraverse | FileListDirectory, FileFlagBackupSemantics, "目标目录");
        VerifySame(hDir, destDir, "目标目录");

        try
        {
            // 只用"目标目录句柄 + 相对名"这一种方式。不退回按绝对路径重命名：那会重新引入"检查后按路径移动"的窗口。
            // 文件系统不接受相对目标名时直接失败，该项按失败处理。
            Rename(hSource, hDir, destName);
        }
        catch (Win32Exception ex)
        {
            // 统一为 IOException，调用方按“该项失败”处理而不是中断整个批次
            var hint = ex.NativeErrorCode is ErrorInvalidParameter or ErrorInvalidName ? "（文件系统不支持按目录句柄重命名）" : "";
            throw new IOException($"移动失败：{ex.Message}{hint}（{source} → {destDir}\\{destName}）", ex.NativeErrorCode);
        }
    }

    /// <summary>\\?\ 扩展路径前缀，支持长路径；UNC 路径用 \\?\UNC\ 形式。</summary>
    private static string Extended(string path) =>
        path.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + path[2..] : @"\\?\" + path;

    private static SafeFileHandle Open(string path, uint access, uint flags, string what)
    {
        // 源对象不共享 Delete：从打开到重命名完成，其他进程不能同时删除 / 改名它
        var share = access == (Delete | FileReadAttributes) ? FileShare.ReadWrite : FileShare.ReadWrite | FileShare.Delete;
        var h = CreateFileW(Extended(path), access, share, IntPtr.Zero, FileMode.Open, flags, IntPtr.Zero);
        if (h.IsInvalid)
        {
            var err = Marshal.GetLastWin32Error();
            h.Dispose();
            throw new IOException($"无法打开{what}：{new Win32Exception(err).Message}（{path}）", err);
        }
        return h;
    }

    private static void VerifySame(SafeFileHandle handle, string expected, string what)
    {
        var final = FinalPath(handle);
        if (!PathGuard.IsSamePhysicalPath(expected, final))
            throw new IOException($"{what}的真实位置（{final ?? "未知"}）与路径不一致，拒绝移动：{expected}");
    }

    internal static string? FinalPath(SafeFileHandle handle)
    {
        var sb = new StringBuilder(1024);
        var len = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
        if (len == 0) return null;
        if (len > sb.Capacity)
        {
            sb.EnsureCapacity((int)len + 1);
            len = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
            if (len == 0) return null;
        }
        var s = sb.ToString();
        if (s.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + s[8..];
        if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) return s[4..];
        return s;
    }

    /// <summary>
    /// FILE_RENAME_INFORMATION：{ BOOLEAN ReplaceIfExists; HANDLE RootDirectory; ULONG FileNameLength; WCHAR FileName[]; }
    /// 直接调用 NtSetInformationFile(FileRenameInformation)：kernel32 的 SetFileInformationByHandle 对带 RootDirectory 的
    /// 相对目标名返回 ERROR_INVALID_PARAMETER，只有原生调用接受"目标目录句柄 + 相对名"。
    /// </summary>
    private static void Rename(SafeFileHandle hSource, SafeFileHandle hRootDir, string name)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var size = 20 + nameBytes.Length + 2;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            for (var i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
            Marshal.WriteByte(buf, 0, 0);                                      // ReplaceIfExists = FALSE
            Marshal.WriteIntPtr(buf, 8, hRootDir.DangerousGetHandle());        // RootDirectory
            Marshal.WriteInt32(buf, 16, nameBytes.Length);                     // FileNameLength（字节）
            Marshal.Copy(nameBytes, 0, buf + 20, nameBytes.Length);

            var status = NtSetInformationFile(hSource, out _, buf, (uint)size, FileRenameInformation);
            if (status != 0)
                throw new Win32Exception((int)RtlNtStatusToDosError(status));
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private const int FileRenameInformation = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock, IntPtr fileInformation, uint length, int fileInformationClass);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, FileShare dwShareMode, IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);}
