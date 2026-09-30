using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Integrity;

/// <summary>更新来源：一个 GitHub 仓库（owner/name[@branch]）或任意 https 根地址。规则库与程序发布信息都从这里取。</summary>
public sealed record UpdateSources(string DataBaseUrl, string ReleaseInfoUrl, string Display)
{
    /// <summary>
    /// "owner/repo" 或 "owner/repo@branch" → raw.githubusercontent.com；以 http(s):// 开头 → 直接当根地址。
    /// 返回 null 表示未设置或格式无效。
    /// </summary>
    public static UpdateSources? Resolve(string? setting)
    {
        var s = (setting ?? "").Trim().TrimEnd('/');
        if (s.Length == 0) return null;
        if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (DataUpdater.ValidateBaseUrl(s) is not null) return null;
            return new UpdateSources(s, s + "/release/latest.json", s);
        }
        var branch = "main";
        var at = s.IndexOf('@');
        if (at > 0) { branch = s[(at + 1)..]; s = s[..at]; }
        var parts = s.Split('/');
        if (parts.Length != 2 || parts.Any(p => p.Length == 0 || p.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))) return null;
        if (branch.Length == 0 || branch.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or '/'))) return null;
        var root = $"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{branch}";
        return new UpdateSources(root, root + "/release/latest.json", $"github.com/{parts[0]}/{parts[1]}@{branch}");
    }
}

public sealed record AppUpdateCheck(bool Available, ReleaseInfo? Release, string Message);

/// <summary>
/// 程序自更新：取签名的发布信息 → 版本更高才下载压缩包 → 流式核对 SHA-256 与大小 → 解压到数据目录的暂存区并校验暂存区里的数据集签名
/// → 用暂存区里的新 CleanSweep.exe 以 --apply-update 方式把文件复制到安装目录（安装目录不可写时提权），再启动新版本。
/// 任何一步失败都不动现有安装。
/// </summary>
public sealed class AppUpdater
{
    private readonly HttpClient _http;
    private readonly IReadOnlyDictionary<string, byte[]> _keys;

    public AppUpdater(HttpClient? http = null, IReadOnlyDictionary<string, byte[]>? trustedKeys = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
        if (!_http.DefaultRequestHeaders.Contains("User-Agent")) _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "CleanSweep-AppUpdater/1");
        _keys = trustedKeys ?? TrustedKeys.Current;
    }

    public static readonly TimeSpan CheckTimeout = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(30);

    public async Task<AppUpdateCheck> CheckAsync(string releaseInfoUrl, Version current, CancellationToken outerCt = default)
    {
        using var timeout = new CancellationTokenSource(CheckTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(outerCt, timeout.Token);
        var ct = linked.Token;
        ReleaseInfoDto? dto;
        try
        {
            using var response = await _http.GetAsync(releaseInfoUrl, ct).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return new AppUpdateCheck(false, null, "更新来源里还没有发布信息（release/latest.json）");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            dto = JsonSerializer.Deserialize<ReleaseInfoDto>(json);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !outerCt.IsCancellationRequested)
        {
            return new AppUpdateCheck(false, null, "获取发布信息超时");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new AppUpdateCheck(false, null, "获取发布信息失败：" + ex.Message);
        }
        var info = ReleaseManifest.Verify(dto, _keys, out var error);
        if (info is null) return new AppUpdateCheck(false, null, "发布信息无效：" + error);
        if (!ReleaseManifest.IsNewer(info.Version, current)) return new AppUpdateCheck(false, info, $"已是最新版本（当前 {current.ToString(3)}，发布 {info.Version.ToString(3)}）");
        return new AppUpdateCheck(true, info, $"有新版本 {info.Version.ToString(3)}（{info.Size / (1024.0 * 1024):0.#} MB）");
    }

    /// <summary>下载到 stagingRoot 下的 &lt;asset&gt;，边下边算哈希，大小与哈希都必须与签名的发布信息一致。</summary>
    public async Task<string> DownloadAsync(ReleaseInfo release, string stagingRoot, IProgress<(long Done, long Total)>? progress = null, CancellationToken outerCt = default)
    {
        using var timeout = new CancellationTokenSource(DownloadTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(outerCt, timeout.Token);
        var ct = linked.Token;
        Directory.CreateDirectory(stagingRoot);
        var target = Path.Combine(stagingRoot, release.Asset);
        var temp = target + ".part";
        try
        {
            using var response = await _http.GetAsync(release.Url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } len && len != release.Size) throw new InvalidDataException($"服务器给出的大小（{len}）与发布信息不符（{release.Size}）");
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long done = 0;
            using (var input = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            {
                var buffer = new byte[1 << 16];
                int n;
                while ((n = await input.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    done += n;
                    if (done > release.Size) throw new InvalidDataException("下载的数据超过发布信息给出的大小");
                    sha.AppendData(buffer, 0, n);
                    await output.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
                    progress?.Report((done, release.Size));
                }
            }
            if (done != release.Size) throw new InvalidDataException($"下载不完整：{done} / {release.Size}");
            var hash = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            if (!string.Equals(hash, release.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("压缩包哈希与签名的发布信息不符");
            File.Move(temp, target, overwrite: true);
            return target;
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    /// <summary>解压到 stageDir（先清空），并检查新版本的必要文件与数据集签名。返回 null 表示通过，否则为拒绝原因。</summary>
    public string? Stage(string zipPath, string stageDir)
    {
        try
        {
            if (Directory.Exists(stageDir)) Directory.Delete(stageDir, recursive: true);
            Directory.CreateDirectory(stageDir);
            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    // 只接受普通相对路径；ExtractToDirectory 自身也拒绝逃出目标目录的条目，这里再挡一层
                    var name = entry.FullName.Replace('\\', '/');
                    if (name.StartsWith('/') || name.Contains("../") || name.Contains(':')) return $"压缩包里的路径非法：{entry.FullName}";
                }
            }
            ZipFile.ExtractToDirectory(zipPath, stageDir, overwriteFiles: true);
            var root = FindAppRoot(stageDir);
            if (root is null) return "压缩包里没有 CleanSweep.exe";
            foreach (var kind in new[] { DataKind.Rules, DataKind.Fingerprints, DataKind.Popups })
            {
                var v = SignedManifest.Verify(Path.Combine(root, DataSets.KindName(kind)), DataSets.KindName(kind), _keys);
                if (!v.Ok) return $"新版本的 {DataSets.KindName(kind)} 签名校验失败：{v.Reason}";
            }
            return null;
        }
        catch (Exception ex)
        {
            return "解压失败：" + ex.Message;
        }
    }

    /// <summary>压缩包可能带一层顶级目录：找到含 CleanSweep.exe 的目录。</summary>
    public static string? FindAppRoot(string stageDir)
    {
        if (File.Exists(Path.Combine(stageDir, "CleanSweep.exe"))) return stageDir;
        foreach (var sub in Directory.EnumerateDirectories(stageDir))
            if (File.Exists(Path.Combine(sub, "CleanSweep.exe"))) return sub;
        return null;
    }

    public static bool IsWritable(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, ".write-probe-" + Guid.NewGuid().ToString("N")[..8]);
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 启动暂存区里的新 CleanSweep.exe 执行覆盖：--apply-update "&lt;安装目录&gt;" &lt;当前进程 ID&gt;。安装目录不可写时以管理员身份启动。
    /// 返回 null 表示已启动（调用方应立即退出），否则为失败原因。
    /// </summary>
    public static string? LaunchApply(string stagedAppRoot, string installDir)
    {
        var exe = Path.Combine(stagedAppRoot, "CleanSweep.exe");
        if (!File.Exists(exe)) return "暂存区里没有 CleanSweep.exe";
        try
        {
            var psi = new ProcessStartInfo(exe, $"--apply-update \"{installDir.TrimEnd('\\')}\" {System.Environment.ProcessId}") { UseShellExecute = true, WorkingDirectory = stagedAppRoot };
            if (!IsWritable(installDir)) psi.Verb = "runas";
            return Process.Start(psi) is null ? "未能启动更新程序" : null;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "已取消提权";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>
    /// 在新版本进程里执行：等旧进程退出，把自己所在目录复制到安装目录（安装目录里多余的旧文件删除），然后启动安装目录里的新版本。
    /// 复制期间旧程序若仍占用文件会重试；失败时安装目录可能处于混合状态，错误信息里说明重新运行安装即可。
    /// </summary>
    public static string? ApplyFromCurrentDirectory(string installDir, int oldPid, Action<string>? log = null)
    {
        var source = AppContext.BaseDirectory.TrimEnd('\\');
        installDir = PathGuard.Normalize(installDir);
        if (string.Equals(source, installDir, StringComparison.OrdinalIgnoreCase)) return "暂存目录与安装目录相同";
        if (!File.Exists(Path.Combine(installDir, "CleanSweep.exe"))) return $"安装目录里没有 CleanSweep.exe：{installDir}";
        if (PathGuard.IsReparsePoint(installDir)) return "安装目录是重解析点";
        try
        {
            using var old = Process.GetProcessById(oldPid);
            if (!old.WaitForExit(60_000)) return "旧版本进程在 60 秒内没有退出";
        }
        catch (ArgumentException) { /* 已退出 */ }

        var error = CopyDirectory(source, installDir, log);
        if (error is not null) return error;
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(installDir, "CleanSweep.exe"), "--updated") { UseShellExecute = true, WorkingDirectory = installDir });
        }
        catch (Exception ex)
        {
            return "已复制文件，但启动新版本失败：" + ex.Message;
        }
        return null;
    }

    /// <summary>镜像复制：目标里不存在于源的文件删除；每个文件最多重试 10 次（旧进程释放句柄需要时间）。</summary>
    public static string? CopyDirectory(string source, string target, Action<string>? log = null)
    {
        var sourceFiles = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(source, f)).ToList();
        foreach (var rel in sourceFiles)
        {
            var from = Path.Combine(source, rel);
            var to = Path.Combine(target, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            Exception? last = null;
            for (int attempt = 0; attempt < 10; attempt++)
            {
                try
                {
                    File.Copy(from, to, overwrite: true);
                    last = null;
                    break;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    last = ex;
                    Thread.Sleep(500);
                }
            }
            if (last is not null) return $"复制 {rel} 失败：{last.Message}。可重新运行安装程序修复。";
        }
        var keep = new HashSet<string>(sourceFiles, StringComparer.OrdinalIgnoreCase);
        foreach (var f in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).ToList())
        {
            var rel = Path.GetRelativePath(target, f);
            if (keep.Contains(rel)) continue;
            try { File.Delete(f); log?.Invoke("删除旧文件 " + rel); } catch { }
        }
        return null;
    }
}
