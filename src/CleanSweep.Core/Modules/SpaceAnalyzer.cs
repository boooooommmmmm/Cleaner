using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Modules;

/// <summary>目录树节点。Children 按大小降序。</summary>
public sealed class DirectoryNode
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public long SizeBytes { get; set; }
    public int FileCount { get; set; }
    public int DirectoryCount { get; set; }
    public bool AccessDenied { get; set; }
    public List<DirectoryNode> Children { get; } = new();

    /// <summary>直接位于本目录下的文件总大小（不含子目录）。</summary>
    public long OwnFilesBytes { get; set; }
}

public sealed class SpaceReport
{
    public required DirectoryNode Root { get; init; }
    public required IReadOnlyList<FileEntry> LargestFiles { get; init; }
    public long TotalBytes => Root.SizeBytes;
    public int TotalFiles => Root.FileCount;
    public TimeSpan Elapsed { get; init; }
}

/// <summary>磁盘空间分析：构建目录大小树并记录最大的 N 个文件。不跟随重解析点。</summary>
public sealed class SpaceAnalyzer
{
    private readonly PathGuard _guard;

    public SpaceAnalyzer(PathGuard guard)
    {
        _guard = guard;
    }

    public Task<SpaceReport> AnalyzeAsync(string rootPath, int topLargest, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        // 递归深度与目录层级成正比，极深的目录树（如嵌套 node_modules）可能超出默认 1 MB 线程栈，因此用专用大栈线程
        var tcs = new TaskCompletionSource<SpaceReport>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var rootFull = PathGuard.Normalize(rootPath);
                if (PathGuard.IsReparsePoint(rootFull))
                    throw new InvalidOperationException("该文件夹是 Junction / 符号链接 / 挂载点，空间分析不跟随重解析点，请选择它指向的实际位置");
                var root = new DirectoryNode { Name = rootPath, FullPath = rootFull };
                var heap = new PriorityQueue<FileEntry, long>();
                int visited = 0;
                long bytes = 0;

                Walk(root, heap, topLargest, ref visited, ref bytes, progress, ct);

                var largest = new List<FileEntry>();
                while (heap.Count > 0) largest.Add(heap.Dequeue());
                largest.Reverse();

                tcs.SetResult(new SpaceReport { Root = root, LargestFiles = largest, Elapsed = sw.Elapsed });
            }
            catch (OperationCanceledException)
            {
                tcs.SetCanceled(ct);
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        }, maxStackSize: 64 * 1024 * 1024) { IsBackground = true, Name = "CleanSweep.SpaceAnalyzer" };
        thread.Start();
        return tcs.Task;
    }

    private void Walk(DirectoryNode node, PriorityQueue<FileEntry, long> heap, int topN, ref int visited, ref long bytes, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        DirectoryInfo di;
        IEnumerator<FileSystemInfo> it;
        try
        {
            di = new DirectoryInfo(node.FullPath);
            // 任何递归入口（含根）都不进入重解析点
            if (PathGuard.IsReparsePoint(di.Attributes))
            {
                node.AccessDenied = true;
                return;
            }
            it = di.EnumerateFileSystemInfos("*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 }).GetEnumerator();
        }
        catch
        {
            node.AccessDenied = true;
            return;
        }

        using var enumerator = it;
        while (true)
        {
            FileSystemInfo e;
            try
            {
                if (!it.MoveNext()) break;
                e = it.Current;
            }
            catch
            {
                node.AccessDenied = true;
                break;
            }

            FileAttributes attr;
            try { attr = e.Attributes; }
            catch { continue; }

            if (PathGuard.IsReparsePoint(attr)) continue;

            if ((attr & FileAttributes.Directory) != 0)
            {
                var child = new DirectoryNode { Name = e.Name, FullPath = e.FullName };
                Walk(child, heap, topN, ref visited, ref bytes, progress, ct);
                node.Children.Add(child);
                node.SizeBytes += child.SizeBytes;
                node.FileCount += child.FileCount;
                node.DirectoryCount += child.DirectoryCount + 1;
                continue;
            }

            if (PathGuard.IsCloudPlaceholder(attr)) continue;

            long len;
            DateTime lw;
            try
            {
                var fi = (FileInfo)e;
                len = fi.Length;
                lw = fi.LastWriteTimeUtc;
            }
            catch
            {
                continue;
            }

            node.OwnFilesBytes += len;
            node.SizeBytes += len;
            node.FileCount++;
            bytes += len;

            if (heap.Count < topN)
            {
                heap.Enqueue(new FileEntry(e.FullName, len, lw), len);
            }
            else if (heap.TryPeek(out _, out var minLen) && len > minLen)
            {
                heap.Dequeue();
                heap.Enqueue(new FileEntry(e.FullName, len, lw), len);
            }
        }

        node.Children.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

        visited++;
        if ((visited & 0xFF) == 0)
            progress?.Report(new ScanProgress("space", node.FullPath, visited, bytes));
    }
}
