namespace CleanSweep.Core.Integrity;

/// <summary>
/// 数据集签名的受信任公钥（ECDSA P-256，SubjectPublicKeyInfo base64）。
/// 只有这里列出的密钥签发的规则库 / 指纹库 / 弹窗规则才会被加载。
/// 私钥不在仓库里（发布者的 %USERPROFILE%\.cleansweep\keys\，或离线介质）。轮换密钥：新旧公钥并存一个版本，旧私钥销毁后再移除旧公钥。
/// 测试用的密钥由测试自己生成，不在这里。
/// </summary>
public static class TrustedKeys
{
    public const string ReleaseKeyId = "release-2026-09";

    private static readonly (string KeyId, string Spki)[] Keys =
    {
        (ReleaseKeyId, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXeAvkWQhDjB0weq6kPc0S3vcqWLDAXKu6lPPWBPefGHR0RaqF2UzEFgfL0BsvsVBvxxI/VEQH++wSwV+xNBPBA=="),
    };

    private static readonly Lazy<IReadOnlyDictionary<string, byte[]>> Loaded = new(() =>
    {
        var dict = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (id, spki) in Keys)
        {
            try { dict[id] = SignedManifest.PublicKeyFromBase64(spki); }
            catch { /* 占位或损坏的公钥直接不信任 */ }
        }
        return dict;
    });

    public static IReadOnlyDictionary<string, byte[]> Current => Loaded.Value;

}
