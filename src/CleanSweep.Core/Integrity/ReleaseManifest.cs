using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CleanSweep.Core.Integrity;

/// <summary>程序发布元数据（release/latest.json）：版本、压缩包名、下载地址、SHA-256、大小、说明，以及对这些字段的 ECDSA 签名。</summary>
public sealed class ReleaseInfoDto
{
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("asset")] public string? Asset { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("generated")] public string? Generated { get; set; }
    [JsonPropertyName("keyId")] public string? KeyId { get; set; }
    [JsonPropertyName("signature")] public string? Signature { get; set; }
}

/// <summary>校验通过的发布信息。Source 是签名原文，下载后原样存到压缩包旁供安装阶段独立复验。</summary>
public sealed record ReleaseInfo(Version Version, string Asset, string Url, string Sha256, long Size, string Notes, string KeyId, ReleaseInfoDto? Source = null);

/// <summary>
/// 程序自更新的元数据签名（与数据集签名同一把密钥）：程序没有代码签名证书时，靠这份签名保证下载的压缩包确实是我们发布的。
/// 下载地址必须是 https；压缩包名只允许普通文件名。
/// </summary>
public static class ReleaseManifest
{
    public const long MaxAssetBytes = 1024L * 1024 * 1024;

    /// <summary>安装提示前核对磁盘中的签名发布信息和压缩包；安装进程仍须独立复验。</summary>
    public static string? VerifyPreparedAsset(ReleaseInfo expected, string assetPath,
        IReadOnlyDictionary<string, byte[]>? trustedKeys = null)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(assetPath + AppUpdater.ReleaseInfoSuffix));
            var actual = Verify(dto, trustedKeys ?? TrustedKeys.Current, out var error);
            if (actual is null) return "本地发布信息无效：" + error;
            if (actual.Version != expected.Version || actual.Asset != expected.Asset || actual.Url != expected.Url
                || actual.Size != expected.Size || actual.KeyId != expected.KeyId
                || !actual.Sha256.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase))
                return "本地发布信息与准备安装的版本不一致";
            return VerifyAsset(actual, assetPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return "无法读取本地发布信息：" + ex.Message;
        }
    }

    /// <summary>发布前将本地资产与已验签的元数据核对，不解压或执行资产。</summary>
    public static string? VerifyAsset(ReleaseInfo release, string assetPath)
    {
        try
        {
            if (!string.Equals(Path.GetFileName(assetPath), release.Asset, StringComparison.Ordinal)) return "资产文件名与发布信息不一致";
            if (new FileInfo(assetPath).Length != release.Size) return "资产大小与发布信息不一致";
            return string.Equals(SignedManifest.HashFile(assetPath), release.Sha256, StringComparison.OrdinalIgnoreCase)
                ? null : "资产哈希与发布信息不一致";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "无法读取发布资产：" + ex.Message;
        }
    }

    public static byte[] Canonical(string version, string asset, string url, string sha256, long size, string generated)
    {
        var sb = new StringBuilder();
        sb.Append("cleansweep-release/1\n");
        sb.Append("version:").Append(version).Append('\n');
        sb.Append("asset:").Append(asset).Append('\n');
        sb.Append("url:").Append(url).Append('\n');
        sb.Append("sha256:").Append(sha256.ToLowerInvariant()).Append('\n');
        sb.Append("size:").Append(size).Append('\n');
        sb.Append("generated:").Append(generated).Append('\n');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public static ReleaseInfoDto Sign(string version, string assetPath, string url, string notes, ECDsa privateKey, string keyId, DateTime? nowUtc = null)
    {
        if (!System.Version.TryParse(version, out _)) throw new ArgumentException("版本号格式无效", nameof(version));
        var asset = Path.GetFileName(assetPath);
        var size = new FileInfo(assetPath).Length;
        var hash = SignedManifest.HashFile(assetPath);
        var generated = (nowUtc ?? DateTime.UtcNow).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var signature = privateKey.SignData(Canonical(version, asset, url, hash, size, generated), HashAlgorithmName.SHA256);
        return new ReleaseInfoDto
        {
            Version = version, Asset = asset, Url = url, Sha256 = hash, Size = size, Notes = notes, Generated = generated, KeyId = keyId,
            Signature = Convert.ToBase64String(signature),
        };
    }

    public static string ToJson(ReleaseInfoDto dto) => JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

    /// <summary>校验并解析。返回 null 时 error 给出原因。</summary>
    public static ReleaseInfo? Verify(ReleaseInfoDto? dto, IReadOnlyDictionary<string, byte[]> trustedKeys, out string? error)
    {
        error = null;
        if (dto is null) { error = "发布信息为空"; return null; }
        if (string.IsNullOrWhiteSpace(dto.Version) || !System.Version.TryParse(dto.Version, out var version)) { error = "版本号无效"; return null; }
        if (string.IsNullOrWhiteSpace(dto.Asset) || dto.Asset.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || dto.Asset.IndexOfAny(new[] { '\\', '/' }) >= 0 || !dto.Asset.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        { error = "压缩包名非法"; return null; }
        if (string.IsNullOrWhiteSpace(dto.Url) || !Uri.TryCreate(dto.Url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            var local = Uri.TryCreate(dto.Url ?? "", UriKind.Absolute, out var u2) && u2.Scheme == Uri.UriSchemeHttp && u2.Host is "127.0.0.1" or "localhost";
            if (!local) { error = "下载地址必须是 https"; return null; }
        }
        if (string.IsNullOrWhiteSpace(dto.Sha256) || dto.Sha256.Length != 64) { error = "哈希无效"; return null; }
        if (dto.Size <= 0 || dto.Size > MaxAssetBytes) { error = "大小无效"; return null; }
        if (string.IsNullOrEmpty(dto.Generated)) { error = "缺少生成时间"; return null; }
        if (dto.KeyId is null || !trustedKeys.TryGetValue(dto.KeyId, out var spki)) { error = $"签名密钥不受信任：{dto.KeyId ?? "(无)"}"; return null; }
        byte[] signature;
        try { signature = Convert.FromBase64String(dto.Signature ?? ""); }
        catch { error = "签名格式无效"; return null; }
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out _);
            if (!key.VerifyData(Canonical(dto.Version, dto.Asset, dto.Url!, dto.Sha256, dto.Size, dto.Generated), signature, HashAlgorithmName.SHA256))
            { error = "签名验证失败（发布信息被改动或不是可信来源签发）"; return null; }
        }
        catch (Exception ex)
        {
            error = "签名验证出错：" + ex.Message;
            return null;
        }
        return new ReleaseInfo(version, dto.Asset, dto.Url!, dto.Sha256.ToLowerInvariant(), dto.Size, dto.Notes ?? "", dto.KeyId, dto);
    }

    /// <summary>只比较前三段（Major.Minor.Build）。</summary>
    public static bool IsNewer(Version candidate, Version current)
    {
        static Version Norm(Version v) => new(Math.Max(v.Major, 0), Math.Max(v.Minor, 0), Math.Max(v.Build, 0));
        return Norm(candidate) > Norm(current);
    }
}
