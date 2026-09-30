using System.Security.Cryptography;
using CleanSweep.Core.Integrity;

// 数据集签名工具（规则库 / 指纹库 / 弹窗规则）。
//   keygen <私钥.pem> <keyId>                     生成 ECDSA P-256 密钥对，打印要嵌入 TrustedKeys 的公钥
//   sign   <目录> <kind> <版本> <私钥.pem> <keyId>  为目录下的 *.json 写 manifest.json
//   verify <目录> <kind>                          用内置公钥校验
// 私钥不进仓库：keygen 生成后放在 %USERPROFILE%\.cleansweep\keys\（或离线介质），只把打印出的公钥写进 Integrity/TrustedKeys.cs。

//   sign-release <版本> <压缩包路径> <下载 URL> <输出 json> <私钥.pem> <keyId> [说明]   生成程序发布信息 release/latest.json
static int Usage()
{
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
    default:
        return Usage();
}
