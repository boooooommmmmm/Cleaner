using System.Security.Cryptography;
using CleanSweep.Core.Disk;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Privacy;

public sealed record ShredResult(string Path, bool Success, string Message);

/// <summary>
/// 文件粉碎（设计文档 3.6）：多次覆写后改名删除，不经隔离区、不可恢复。
/// SSD 上覆写不保证擦除（磨损均衡会保留旧块），调用方必须先用 <see cref="DiskMedia.IsSolidState"/> 提示用户。
/// 只接受通过 Path Guard 的普通文件：不接受目录、重解析点、云端占位文件、Windows / Program Files 下的文件。
/// </summary>
public static class FileShredder
{
    public const int MinPasses = 1;
    public const int MaxPasses = 7;
    private const int ChunkSize = 1024 * 1024;

    public static ShredResult Shred(string path, int passes, PathGuard guard, CancellationToken ct = default, IProgress<long>? progress = null)
    {
        if (passes is < MinPasses or > MaxPasses) return new ShredResult(path, false, $"覆写次数须在 {MinPasses} 到 {MaxPasses} 之间");

        string full;
        try { full = PathGuard.Normalize(path); }
        catch (Exception ex) { return new ShredResult(path, false, "路径无效：" + ex.Message); }

        var verdict = guard.Check(full);
        if (!verdict.Allowed) return new ShredResult(full, false, "护栏拒绝：" + verdict.Reason);

        FileInfo fi;
        try
        {
            fi = new FileInfo(full);
            if (!fi.Exists) return new ShredResult(full, false, "文件不存在");
            if ((fi.Attributes & FileAttributes.Directory) != 0) return new ShredResult(full, false, "只能粉碎文件，不能粉碎目录");
            if (PathGuard.IsReparsePoint(fi.Attributes)) return new ShredResult(full, false, "文件是重解析点（符号链接），拒绝");
            if (PathGuard.IsCloudPlaceholder(fi.Attributes)) return new ShredResult(full, false, "云端占位文件，本地没有内容，请在云盘中删除");
        }
        catch (Exception ex)
        {
            return new ShredResult(full, false, ex.Message);
        }

        var physical = guard.VerifyPhysical(full);
        if (!physical.Allowed) return new ShredResult(full, false, physical.Reason!);

        try
        {
            if ((fi.Attributes & FileAttributes.ReadOnly) != 0) fi.Attributes &= ~FileAttributes.ReadOnly;
            var length = fi.Length;
            using (var fs = new FileStream(full, FileMode.Open, FileAccess.ReadWrite, FileShare.None, ChunkSize, FileOptions.WriteThrough))
            {
                // 硬链接不是重解析点，路径检查看不出来：同一个文件对象若还有其他名字，覆写会把用户没选的那些也毁掉
                var links = HardLinkCount(fs.SafeFileHandle);
                if (links is null) return new ShredResult(full, false, "无法读取文件的硬链接数，拒绝粉碎");
                if (links > 1) return new ShredResult(full, false, $"该文件有 {links} 个硬链接（其他路径下是同一个文件），粉碎会同时破坏它们，拒绝");
                var buffer = new byte[ChunkSize];
                for (var pass = 0; pass < passes; pass++)
                {
                    ct.ThrowIfCancellationRequested();
                    fs.Position = 0;
                    long remaining = length;
                    while (remaining > 0)
                    {
                        ct.ThrowIfCancellationRequested();
                        var n = (int)Math.Min(ChunkSize, remaining);
                        FillPattern(buffer.AsSpan(0, n), pass);
                        fs.Write(buffer, 0, n);
                        remaining -= n;
                        progress?.Report(length - remaining);
                    }
                    fs.Flush(flushToDisk: true);
                }
                // 最后把长度截为 0，目录项里也不留原大小
                fs.SetLength(0);
                fs.Flush(flushToDisk: true);
            }

            // 改成随机名再删，目录里不留原文件名
            var dir = Path.GetDirectoryName(full)!;
            var temp = Path.Combine(dir, Guid.NewGuid().ToString("N"));
            File.Move(full, temp);
            File.Delete(temp);
            return new ShredResult(full, true, $"已覆写 {passes} 次并删除");
        }
        catch (OperationCanceledException)
        {
            return new ShredResult(full, false, "已取消（文件内容已被部分覆写，不可恢复）");
        }
        catch (Exception ex)
        {
            return new ShredResult(full, false, ex.Message);
        }
    }

    /// <summary>从已打开的句柄读硬链接数（同一文件对象的名字数量）。读不到返回 null。</summary>
    internal static uint? HardLinkCount(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        try
        {
            return GetFileInformationByHandle(handle, out var info) ? info.NumberOfLinks : null;
        }
        catch
        {
            return null;
        }
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    /// <summary>第 1 遍全 0，第 2 遍全 1，之后随机。</summary>
    internal static void FillPattern(Span<byte> buffer, int pass)
    {
        switch (pass)
        {
            case 0: buffer.Fill(0x00); break;
            case 1: buffer.Fill(0xFF); break;
            default: RandomNumberGenerator.Fill(buffer); break;
        }
    }
}

/// <summary>
/// 空闲空间擦除（设计文档 3.6）：仅在确认为机械盘的卷上提供。往卷上写零直到写满再删除，覆盖已删除文件残留的数据。
/// SSD 或无法判定介质时拒绝（对 SSD 无意义且加速磨损，应依赖 TRIM 与 BitLocker）。
/// </summary>
public static class FreeSpaceWiper
{
    public const string WorkFolderName = "$CleanSweep.Wipe";
    private const int ChunkSize = 64 * 1024 * 1024;

    /// <summary>返回 null 表示允许，否则为拒绝原因。</summary>
    public static string? CheckVolume(string volumeRoot)
    {
        DriveInfo d;
        try { d = new DriveInfo(volumeRoot); }
        catch (Exception ex) { return "卷无效：" + ex.Message; }
        if (!d.IsReady) return "卷未就绪";
        if (d.DriveType != DriveType.Fixed) return "只对本机固定磁盘提供空闲空间擦除";
        return DiskMedia.IsSolidState(d.RootDirectory.FullName) switch
        {
            true => "该卷位于固态盘：覆写不保证擦除且加速磨损，请依赖 TRIM 与 BitLocker 加密",
            null => "无法判定该卷的介质类型，为安全起见不提供擦除",
            false => null,
        };
    }

    /// <summary>ERROR_DISK_FULL（112）与 ERROR_HANDLE_DISK_FULL（39）才是"写满了"，其他 I/O 错误不能当成功。</summary>
    internal static bool IsDiskFull(IOException ex) => (ex.HResult & 0xFFFF) is 112 or 39;

    public static async Task<(bool Success, string Message, long BytesWritten)> WipeAsync(string volumeRoot, IProgress<long>? progress, CancellationToken ct)
    {
        var bad = CheckVolume(volumeRoot);
        if (bad is not null) return (false, bad, 0);

        // 每次用新建的随机工作目录：固定名字的目录可能已被别人建成 Junction 或放了同名文件
        var work = Path.Combine(new DriveInfo(volumeRoot).RootDirectory.FullName, $"{WorkFolderName}-{Guid.NewGuid():N}");
        if (Directory.Exists(work) || File.Exists(work)) return (false, "工作目录已存在，拒绝使用", 0);
        Directory.CreateDirectory(work);
        if (PathGuard.IsReparsePoint(work)) return (false, "工作目录是重解析点，拒绝使用", 0);
        long written = 0;
        var buffer = new byte[ChunkSize];
        var files = new List<string>(); // 只登记本次成功创建的文件，清理时不会碰别的东西
        try
        {
            // 单个文件最多 4 GB，避免 FAT32 上限与巨大单文件
            for (var index = 0; ; index++)
            {
                var file = Path.Combine(work, $"wipe-{index:D4}.bin");
                using var fs = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.WriteThrough);
                files.Add(file);
                long inFile = 0;
                bool full = false;
                while (inFile < 4L * 1024 * 1024 * 1024)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        await fs.WriteAsync(buffer, ct).ConfigureAwait(false);
                    }
                    catch (IOException ex) when (IsDiskFull(ex))
                    {
                        full = true;
                        break;
                    }
                    inFile += buffer.Length;
                    written += buffer.Length;
                    progress?.Report(written);
                }
                if (full) break;
            }
            return (true, $"已写入并释放 {written / (1024.0 * 1024 * 1024):0.##} GB 空闲空间", written);
        }
        catch (OperationCanceledException)
        {
            return (false, "已取消", written);
        }
        catch (IOException ex)
        {
            return (false, "写入出错（不是磁盘已满）：" + ex.Message, written);
        }
        finally
        {
            foreach (var f in files)
            {
                try { File.Delete(f); } catch { }
            }
            try { Directory.Delete(work); } catch { }
        }
    }
}
