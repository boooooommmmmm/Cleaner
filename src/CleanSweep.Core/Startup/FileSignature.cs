using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CleanSweep.Core.Startup;

public sealed record SignatureInfo(SignatureState State, string? Publisher, bool IsMicrosoft);

/// <summary>
/// Authenticode 签名检查：先查内嵌签名，再查系统目录（catalog）签名，两者均通过 WinVerifyTrust 验证。
/// 不做联网吊销检查，避免扫描被网络拖慢。
/// </summary>
public static class FileSignature
{
    private static readonly ConcurrentDictionary<string, SignatureInfo> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly SignatureInfo UnknownInfo = new(SignatureState.Unknown, null, false);

    private static Guid _actionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TrustENoSignature = unchecked((int)0x800B0100);

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    public static SignatureInfo Inspect(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return UnknownInfo;
        string full;
        long length;
        DateTime lastWrite;
        try
        {
            full = Path.GetFullPath(path);
            var fi = new FileInfo(full);
            if (!fi.Exists) return UnknownInfo;
            length = fi.Length;
            lastWrite = fi.LastWriteTimeUtc;
        }
        catch
        {
            return UnknownInfo;
        }
        // 缓存键绑定文件身份（路径 + 大小 + 修改时间）：同一路径被替换成别的文件后必须重新验证，不能沿用旧结论
        var key = $"{full}|{length}|{lastWrite.Ticks}";
        return Cache.GetOrAdd(key, _ => InspectCore(full));
    }

    /// <summary>清空缓存（刷新启动项列表时调用）。</summary>
    public static void ClearCache() => Cache.Clear();

    /// <summary>
    /// 是否为微软自身的签名主体。"Microsoft Windows Hardware Compatibility Publisher"（WHQL）与
    /// "Microsoft Windows Third Party Component CA" 签的是第三方驱动 / 组件，不算微软自带。
    /// </summary>
    public static bool IsMicrosoftPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var p = publisher.Trim();
        if (p.Contains("Hardware Compatibility", StringComparison.OrdinalIgnoreCase)) return false;
        if (p.Contains("Third Party", StringComparison.OrdinalIgnoreCase)) return false;
        return p.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
               || p.Equals("Microsoft Windows", StringComparison.OrdinalIgnoreCase)
               || p.Equals("Microsoft Windows Publisher", StringComparison.OrdinalIgnoreCase)
               || p.StartsWith("Microsoft Windows Production", StringComparison.OrdinalIgnoreCase)
               || p.Equals("Microsoft Corporation (Windows)", StringComparison.OrdinalIgnoreCase);
    }

    private static SignatureInfo InspectCore(string path)
    {
        var state = SignatureState.Unknown;
        string? publisher = null;

        try
        {
            var hr = VerifyEmbedded(path);
            if (hr == 0)
            {
                state = SignatureState.Signed;
                publisher = SignerName(path);
            }
            else if (hr == TrustENoSignature)
            {
                var (catHr, catFile) = VerifyCatalog(path);
                if (catHr == 0)
                {
                    state = SignatureState.Signed;
                    publisher = catFile is null ? null : SignerName(catFile);
                }
                else if (catHr is null || catHr == TrustENoSignature)
                {
                    state = SignatureState.Unsigned;
                }
                else
                {
                    state = SignatureState.Invalid;
                }
            }
            else
            {
                state = SignatureState.Invalid;
            }
        }
        catch
        {
            state = SignatureState.Unknown;
        }

        publisher ??= CompanyName(path);
        var ms = state == SignatureState.Signed && IsMicrosoftPublisher(publisher);
        if (ms) state = SignatureState.SignedMicrosoft;
        return new SignatureInfo(state, publisher, ms);
    }

    private static string? CompanyName(string path)
    {
        try
        {
            var c = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim();
            return string.IsNullOrEmpty(c) ? null : c;
        }
        catch
        {
            return null;
        }
    }

    private static string? SignerName(string signedFile)
    {
        try
        {
            // Authenticode 签名者证书没有非过时的托管替代 API（X509CertificateLoader 只加载证书文件），只用于显示发布者名
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(signedFile);
#pragma warning restore SYSLIB0057
            var dn = new X500DistinguishedName(cert.Subject);
            foreach (var rdn in dn.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.GetSingleElementType().Value == "2.5.4.3")
                    return rdn.GetSingleElementValue();
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    // ---------- 内嵌签名 ----------

    private static int VerifyEmbedded(string path)
    {
        var filePath = Marshal.StringToHGlobalUni(path);
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
            };
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pUnion = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
            };
            Marshal.StructureToPtr(data, dataPtr, false);

            var hr = WinVerifyTrust(new IntPtr(-1), ref _actionGenericVerifyV2, dataPtr);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(dataPtr);
            data.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(data, dataPtr, false);
            WinVerifyTrust(new IntPtr(-1), ref _actionGenericVerifyV2, dataPtr);
            return hr;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
            Marshal.FreeHGlobal(filePath);
        }
    }

    // ---------- Catalog 签名（系统文件大多如此） ----------

    private static (int? Hr, string? CatalogFile) VerifyCatalog(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hFile = fs.SafeFileHandle.DangerousGetHandle();

        foreach (var alg in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var hAdmin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
            try
            {
                uint cb = 0;
                CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, ref cb, null, 0);
                if (cb == 0) continue;
                var hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, ref cb, hash, 0)) continue;

                var prev = IntPtr.Zero;
                var hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, cb, 0, ref prev);
                if (hCat == IntPtr.Zero) continue;
                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(hCat, ref info, 0)) continue;
                    var hr = VerifyWithCatalog(info.wszCatalogFile, Convert.ToHexString(hash), path, hFile, hash, hAdmin);
                    return (hr, info.wszCatalogFile);
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(hAdmin, 0);
            }
        }
        return (null, null);
    }

    private static int VerifyWithCatalog(string catalogFile, string memberTag, string memberFile, IntPtr hMemberFile, byte[] hash, IntPtr hAdmin)
    {
        var pCatalog = Marshal.StringToHGlobalUni(catalogFile);
        var pTag = Marshal.StringToHGlobalUni(memberTag);
        var pMember = Marshal.StringToHGlobalUni(memberFile);
        var pHash = Marshal.AllocHGlobal(hash.Length);
        var catInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.Copy(hash, 0, pHash, hash.Length);
            var catInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = pCatalog,
                pcwszMemberTag = pTag,
                pcwszMemberFilePath = pMember,
                hMemberFile = hMemberFile,
                pbCalculatedFileHash = pHash,
                cbCalculatedFileHash = (uint)hash.Length,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = hAdmin,
            };
            Marshal.StructureToPtr(catInfo, catInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceCatalog,
                pUnion = catInfoPtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
            };
            Marshal.StructureToPtr(data, dataPtr, false);

            var hr = WinVerifyTrust(new IntPtr(-1), ref _actionGenericVerifyV2, dataPtr);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(dataPtr);
            data.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(data, dataPtr, false);
            WinVerifyTrust(new IntPtr(-1), ref _actionGenericVerifyV2, dataPtr);
            return hr;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(catInfoPtr);
            Marshal.FreeHGlobal(pHash);
            Marshal.FreeHGlobal(pMember);
            Marshal.FreeHGlobal(pTag);
            Marshal.FreeHGlobal(pCatalog);
        }
    }

    // ---------- P/Invoke ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
}
