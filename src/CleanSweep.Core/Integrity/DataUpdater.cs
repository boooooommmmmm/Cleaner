using System.Net.Http;
using System.Text.Json;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Integrity;

public sealed record DataUpdateResult(DataKind Kind, bool Updated, int? RemoteVersion, string Message);

/// <summary>
/// 数据集在线更新（设计文档 6.2 第 4 条的更新渠道）：
/// 从 {baseUrl}/{kind}/manifest.json 取清单，签名必须能用内置公钥验证、版本必须高于当前采用的版本，
/// 然后逐个下载清单列出的文件到临时目录，哈希一致后整体切换到 updates\{kind}。任何一步失败都不改动现有数据。
/// 只接受 https（127.0.0.1 / localhost 的 http 用于测试），单个文件不超过 4 MB。
/// </summary>
public sealed class DataUpdater
{
    public const long MaxFileBytes = 4 * 1024 * 1024;

    private readonly HttpClient _http;
    private readonly IReadOnlyDictionary<string, byte[]> _keys;

    public DataUpdater(HttpClient? http = null, IReadOnlyDictionary<string, byte[]>? trustedKeys = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        if (!_http.DefaultRequestHeaders.Contains("User-Agent")) _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "CleanSweep-DataUpdater/1");
        _keys = trustedKeys ?? TrustedKeys.Current;
    }

    public static string? ValidateBaseUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "未设置更新地址";
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return "更新地址不是合法的 URL";
        var local = uri.Host is "127.0.0.1" or "localhost" or "::1";
        if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && local)) return "更新地址必须使用 https";
        return null;
    }

    /// <param name="currentVersion">当前采用的版本（内置或已装更新中较高者）。</param>
    /// <param name="updateDir">安装目标目录 updates\{kind}。</param>
    /// <summary>一个数据集从取清单到落盘的总时限（HttpClient.Timeout 只管到响应头，正文读取靠这里）。</summary>
    public static readonly TimeSpan TotalTimeout = TimeSpan.FromMinutes(5);

    public async Task<DataUpdateResult> UpdateAsync(DataKind kind, string baseUrl, int currentVersion, string updateDir, CancellationToken outerCt = default)
    {
        var bad = ValidateBaseUrl(baseUrl);
        if (bad is not null) return new DataUpdateResult(kind, false, null, bad);
        using var timeout = new CancellationTokenSource(TotalTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(outerCt, timeout.Token);
        var ct = linked.Token;
        try
        {
            return await UpdateCoreAsync(kind, baseUrl, currentVersion, updateDir, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !outerCt.IsCancellationRequested)
        {
            return new DataUpdateResult(kind, false, null, $"更新超时（超过 {TotalTimeout.TotalMinutes:0} 分钟）");
        }
    }

    private async Task<DataUpdateResult> UpdateCoreAsync(DataKind kind, string baseUrl, int currentVersion, string updateDir, CancellationToken ct)
    {
        var name = DataSets.KindName(kind);
        var root = baseUrl.Trim().TrimEnd('/') + "/" + name + "/";

        ManifestDto? dto;
        try
        {
            var bytes = await DownloadAsync(root + SignedManifest.FileName, ct).ConfigureAwait(false);
            dto = JsonSerializer.Deserialize<ManifestDto>(bytes);
        }
        catch (Exception ex)
        {
            return new DataUpdateResult(kind, false, null, "下载清单失败：" + ex.Message);
        }
        if (dto is null || dto.Files is null) return new DataUpdateResult(kind, false, null, "远端清单为空");

        // 先验签名（不看文件），再决定要不要下载
        var preVerdict = VerifySignatureOnly(dto, name);
        if (preVerdict is not null) return new DataUpdateResult(kind, false, dto.Version, "远端清单：" + preVerdict);
        if (dto.Version <= currentVersion) return new DataUpdateResult(kind, false, dto.Version, $"已是最新（本地 {currentVersion}，远端 {dto.Version}）");

        var parent = Path.GetDirectoryName(updateDir)!;
        Directory.CreateDirectory(parent);
        var temp = Path.Combine(parent, $".{name}-{Guid.NewGuid():N}.tmp");
        Directory.CreateDirectory(temp);
        try
        {
            foreach (var (file, hash) in dto.Files)
            {
                ct.ThrowIfCancellationRequested();
                if (!SignedManifest.IsSafeName(file)) return new DataUpdateResult(kind, false, dto.Version, $"远端清单里的文件名非法：{file}");
                var bytes = await DownloadAsync(root + Uri.EscapeDataString(file), ct).ConfigureAwait(false);
                if (!string.Equals(SignedManifest.HashBytes(bytes), hash, StringComparison.OrdinalIgnoreCase))
                    return new DataUpdateResult(kind, false, dto.Version, $"下载的文件与清单哈希不符：{file}");
                File.WriteAllBytes(Path.Combine(temp, file), bytes);
            }
            File.WriteAllText(Path.Combine(temp, SignedManifest.FileName), JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));

            // 落盘后再完整校验一次（签名 + 每个文件），通过才切换
            var verdict = SignedManifest.Verify(temp, name, _keys);
            if (!verdict.Ok) return new DataUpdateResult(kind, false, dto.Version, "下载结果校验失败：" + verdict.Reason);

            Swap(temp, updateDir);
            return new DataUpdateResult(kind, true, dto.Version, $"已更新到版本 {dto.Version}（{dto.Files.Count} 个文件）");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new DataUpdateResult(kind, false, dto.Version, "更新失败：" + ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(temp)) Directory.Delete(temp, recursive: true); } catch { }
        }
    }

    private string? VerifySignatureOnly(ManifestDto dto, string kind)
    {
        if (!string.Equals(dto.Kind, kind, StringComparison.Ordinal)) return "类型不符";
        if (dto.KeyId is null || !_keys.TryGetValue(dto.KeyId, out var spki)) return "签名密钥不受信任";
        return SignedManifest.VerifySignature(dto, spki);
    }

    private async Task<byte[]> DownloadAsync(string url, CancellationToken ct)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxFileBytes) throw new InvalidDataException("文件过大");
        using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int n;
        while ((n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buffer, 0, n);
            if (ms.Length > MaxFileBytes) throw new InvalidDataException("文件过大");
        }
        return ms.ToArray();
    }

    /// <summary>用临时目录替换目标目录：旧目录先改名再删除，切换过程中任何时刻磁盘上都有一份完整的数据。</summary>
    private static void Swap(string temp, string target)
    {
        if (PathGuard.IsReparsePoint(Path.GetDirectoryName(target)!)) throw new InvalidOperationException("更新目录的父目录是重解析点");
        string? old = null;
        if (Directory.Exists(target))
        {
            old = target + ".old-" + Guid.NewGuid().ToString("N")[..6];
            Directory.Move(target, old);
        }
        try
        {
            Directory.Move(temp, target);
        }
        catch
        {
            if (old is not null && !Directory.Exists(target)) Directory.Move(old, target);
            throw;
        }
        if (old is not null) { try { Directory.Delete(old, recursive: true); } catch { } }
    }
}
