using System.Security.Cryptography;
using CleanSweep.Core.Integrity;

// 数据集签名工具（规则库 / 指纹库 / 弹窗规则）。
//   keygen <私钥.pem> <keyId>                     生成 ECDSA P-256 密钥对，打印要嵌入 TrustedKeys 的公钥
//   sign   <目录> <kind> <版本> <私钥.pem> <keyId>  为目录下的 *.json 写 manifest.json
//   verify <目录> <kind>                          用内置公钥校验
// 私钥不进仓库：keygen 生成后放在 %USERPROFILE%\.cleansweep\keys\（或离线介质），只把打印出的公钥写进 Integrity/TrustedKeys.cs。

//   sign-release <版本> <压缩包路径> <下载 URL> <输出 json> <私钥.pem> <keyId> [说明]   生成程序发布信息 release/latest.json
//   verify-release <发布信息.json> [压缩包.zip]   只用公钥验证发布信息及可选资产
static int Usage()
{
    Console.Error.WriteLine("发布验证：verify-release <release.json> [asset.zip]");
    Console.Error.WriteLine("用法：\n  keygen <private.pem> <keyId>\n  sign <dir> <rules|fingerprints|popups> <version> <private.pem> <keyId>\n  verify <dir> <rules|fingerprints|popups>\n  sign-release <version> <zip> <url> <out.json> <private.pem> <keyId> [notes]");
    return 2;
}

if (args.Length == 0) return Usage();
switch (args[0])
{
    case "keygen":
    {
        if (args.Length != 3) return Usage();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(args[1], key.ExportPkcs8PrivateKeyPem());
        Console.WriteLine($"keyId: {args[2]}");
        Console.WriteLine($"public (SPKI base64): {Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())}");
        return 0;
    }
    case "sign":
    {
        if (args.Length != 6 || !int.TryParse(args[3], out var version)) return Usage();
        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(args[4]));
        var dto = SignedManifest.Sign(args[1], args[2], version, key, args[5]);
        Console.WriteLine($"已签名 {dto.Files!.Count} 个文件，版本 {version}，密钥 {args[5]}");
        return 0;
    }
    case "sign-release":
    {
        if (args.Length is < 7 or > 8) return Usage();
        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(args[5]));
        var dto = ReleaseManifest.Sign(args[1], args[2], args[3], args.Length == 8 ? args[7] : "", key, args[6]);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[4]))!);
        File.WriteAllText(args[4], ReleaseManifest.ToJson(dto));
        Console.WriteLine($"已生成 {args[4]}：版本 {dto.Version}，{dto.Asset}，{dto.Size} 字节");
        return 0;
    }
    case "verify":
    {
        if (args.Length != 3) return Usage();
        var v = SignedManifest.Verify(args[1], args[2], TrustedKeys.Current);
        Console.WriteLine(v.Ok ? $"通过：版本 {v.Version}，{v.Files.Count} 个文件，密钥 {v.KeyId}" : "失败：" + v.Reason);
        return v.Ok ? 0 : 1;
    }
    case "verify-release":
    {
        if (args.Length is < 2 or > 3) return Usage();
        try
        {
            if (new FileInfo(args[1]).Length > 1024 * 1024) throw new InvalidDataException("发布信息超过 1 MiB");
            var dto = System.Text.Json.JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(args[1]));
            var release = ReleaseManifest.Verify(dto, TrustedKeys.Current, out var error);
            if (release is not null && args.Length == 3) error = ReleaseManifest.VerifyAsset(release, args[2]);
            if (release is null || error is not null)
            {
                Console.Error.WriteLine("失败：" + error);
                return 1;
            }
            Console.WriteLine($"通过：发布版本 {release.Version}，资产 {release.Asset}，密钥 {release.KeyId}");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            Console.Error.WriteLine("失败：" + ex.Message);
            return 1;
        }
    }
    default:
        return Usage();
}
