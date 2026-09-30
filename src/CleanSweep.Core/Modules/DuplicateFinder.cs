using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Modules;

public sealed record DuplicateGroup(long SizeBytes, string Hash, IReadOnlyList<FileEntry> Files)
{
    /// <summary>删除除一份以外的其他副本可释放的空间。</summary>
    public long ReclaimableBytes => SizeBytes * (Files.Count - 1);
}

/// <summary>
/// 重复文件查找（设计文档 3.5）：按大小分组 → 首尾 64KB 哈希 → 全量哈希。
/// 跳过云端占位文件与重解析点；用文件 ID 排除同一文件的硬链接。
/// </summary>
public sealed class DuplicateFinder
{
    private const int PartialBytes = 64 * 1024;
    private readonly PathGuard _guard;

    public DuplicateFinder(PathGuard guard)
    {
        _guard = guard;
    }

    public Task<IReadOnlyList<DuplicateGroup>> FindAsync(
        IEnumerable<string> roots, long minSizeBytes, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        return Task.Run<IReadOnlyList<DuplicateGroup>>(() =>
        {
            // 阶段 1：枚举并按大小分组
            var bySize = new Dictionary<long, List<FileEntry>>();
            int seen = 0;
            foreach (var root in roots)
            {
                foreach (var f in _guard.EnumerateFiles(root, null, recurse: true, ct))
                {
                    if (f.Size < minSizeBytes) continue;
                    if (!bySize.TryGetValue(f.Size, out var list)) bySize[f.Size] = list = new List<FileEntry>();
                    list.Add(f);
                    if ((++seen & 0x3FF) == 0) progress?.Report(new ScanProgress("duplicates", f.Path, seen, 0));
                }
            }

            var candidates = bySize.Values.Where(l => l.Count > 1).ToList();
            bySize.Clear();

            // 阶段 2：排除硬链接，首尾哈希
            var results = new List<DuplicateGroup>();
            int processed = 0;
            foreach (var group in candidates)
            {
                ct.ThrowIfCancellationRequested();

                var distinct = DistinctByFileId(group);
                if (distinct.Count < 2) continue;

                var byPartial = new Dictionary<string, List<FileEntry>>();
                foreach (var f in distinct)
                {
                    var h = TryHash(f.Path, partial: true);
                    if (h is null) continue;
                    if (!byPartial.TryGetValue(h, out var l)) byPartial[h] = l = new List<FileEntry>();
                    l.Add(f);
                }

                // 阶段 3：全量哈希
                foreach (var pg in byPartial.Values.Where(l => l.Count > 1))
                {
                    var byFull = new Dictionary<string, List<FileEntry>>();
                    foreach (var f in pg)
                    {
                        ct.ThrowIfCancellationRequested();
                        var h = f.Size <= 2 * PartialBytes ? TryHash(f.Path, partial: true) : TryHash(f.Path, partial: false);
                        if (h is null) continue;
                        if (!byFull.TryGetValue(h, out var l)) byFull[h] = l = new List<FileEntry>();
                        l.Add(f);
                    }

                    foreach (var (hash, files) in byFull)
                    {
                        if (files.Count > 1)
                            results.Add(new DuplicateGroup(files[0].Size, hash, files.OrderBy(f => f.LastWriteUtc).ToList()));
                    }
                }

                processed++;
                if ((processed & 0x3F) == 0)
                    progress?.Report(new ScanProgress("duplicates", group[0].Path, processed, results.Sum(r => r.ReclaimableBytes)));
            }

            return results.OrderByDescending(r => r.ReclaimableBytes).ToList();
        }, ct);
    }

    /// <summary>
    /// 计算与分组时一致的全量哈希（小文件用整文件，大文件同样整文件），供执行前核对"保留副本内容仍与本组一致"。
    /// 读不到时返回 null。
    /// </summary>
    public static string? ComputeGroupHash(string path) => TryHash(path, partial: false);

    private static string? TryHash(string path, bool partial)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            using var sha = SHA256.Create();

            if (!partial || fs.Length <= 2 * PartialBytes)
            {
                return Convert.ToHexString(sha.ComputeHash(fs));
            }

            var buf = new byte[PartialBytes];
            fs.ReadExactly(buf);
            sha.TransformBlock(buf, 0, buf.Length, null, 0);
            fs.Seek(-PartialBytes, SeekOrigin.End);
            fs.ReadExactly(buf);
            sha.TransformFinalBlock(buf, 0, buf.Length);
            return Convert.ToHexString(sha.Hash!);
        }
        catch
        {
            return null;
        }
    }

    // ---------- 硬链接识别 ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    private static (uint Volume, ulong Index)? GetFileId(string path)
    {
        try
        {
            using var h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(h, out var info)) return null;
            return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
        }
        catch
        {
            return null;
        }
    }

    private static List<FileEntry> DistinctByFileId(List<FileEntry> files)
    {
        var seen = new HashSet<(uint, ulong)>();
        var result = new List<FileEntry>(files.Count);
        foreach (var f in files)
        {
            var id = GetFileId(f.Path);
            if (id is null) continue;
            if (seen.Add(id.Value)) result.Add(f);
        }
        return result;
    }
}
