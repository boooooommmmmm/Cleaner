using System.Security.Cryptography;
using System.Text;
using CleanSweep.Core.Backup;
using Microsoft.Win32;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>
/// 注册表类条目（值、键、服务、计划任务）的扫描时快照，与整目录清理的逐文件指纹（<see cref="Safety.PathGuard.FingerprintDirectory"/>）对应：
/// 扫描时记录目标内容的哈希，删除前重新计算，任何变化（例如软件在扫描后被重新安装、卸载键被重写）都拒绝删除，让用户重新扫描。
/// 读不到时返回 null；带快照的条目在删除前若读不到当前状态也视为变化（宁可拒绝）。
/// </summary>
public static class RegistrySnapshot
{
    /// <summary>目标不存在时的快照值。</summary>
    public const string Missing = "missing";

    /// <summary>键内容超过预算、没有完整覆盖时的快照值：不能作为"扫描后未变化"的证明，删除一律拒绝。</summary>
    public const string Truncated = "truncated";

    private const int MaxEntries = 5000;

    /// <summary>单个值：类型 + 数据。</summary>
    public static string? OfValue(string keyPath, RegistryView view, string valueName)
    {
        try
        {
            using var k = RegistryPath.Open(keyPath, view, writable: false);
            var (kind, value) = RegFile.ReadValue(k, valueName);
            if (kind is null || value is null) return Missing;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            AppendValue(sha, kind.Value, value);
            return Convert.ToHexString(sha.GetHashAndReset());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>整个键：递归所有子键名、值名、类型与数据（按名称排序，最多 5000 项）。</summary>
    public static string? OfKey(string keyPath, RegistryView view)
    {
        try
        {
            using var k = RegistryPath.Open(keyPath, view, writable: false);
            if (k is null) return Missing;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int budget = MaxEntries;
            AppendKey(sha, k, "", ref budget);
            if (budget <= 0) return Truncated;
            return Convert.ToHexString(sha.GetHashAndReset());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>服务：只取决定"指向哪个程序、怎么启动"的值（Type、Start、ImagePath、ObjectName、Parameters\ServiceDll）。</summary>
    public static string? OfServiceKey(string serviceKeyPath)
    {
        try
        {
            using var k = RegistryPath.Open(serviceKeyPath, RegistryView.Registry64, writable: false);
            if (k is null) return Missing;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var name in new[] { "Type", "Start", "ImagePath", "ObjectName", "DisplayName" })
            {
                var (kind, value) = RegFile.ReadValue(k, name);
                sha.AppendData(Encoding.UTF8.GetBytes(name + "\u001f"));
                if (kind is not null && value is not null) AppendValue(sha, kind.Value, value);
                sha.AppendData(new byte[] { 0 });
            }
            using (var p = k.OpenSubKey("Parameters"))
            {
                var (kind, value) = RegFile.ReadValue(p, "ServiceDll");
                sha.AppendData(Encoding.UTF8.GetBytes("ServiceDll\u001f"));
                if (kind is not null && value is not null) AppendValue(sha, kind.Value, value);
            }
            return Convert.ToHexString(sha.GetHashAndReset());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>计划任务：任务定义 XML 的哈希。</summary>
    public static string? OfTask(string taskPath)
    {
        try
        {
            var t = Type.GetTypeFromProgID("Schedule.Service");
            if (t is null) return null;
            dynamic svc = Activator.CreateInstance(t)!;
            svc.Connect();
            var folderPath = taskPath[..taskPath.LastIndexOf('\\')];
            if (folderPath.Length == 0) folderPath = "\\";
            var name = taskPath[(taskPath.LastIndexOf('\\') + 1)..];
            dynamic folder = svc.GetFolder(folderPath);
            dynamic task;
            try { task = folder.GetTask(name); }
            catch (System.IO.FileNotFoundException) { return Missing; }
            catch (System.Runtime.InteropServices.COMException ex) when ((uint)ex.HResult == 0x80070002) { return Missing; }
            string xml = task.Xml;
            return OfTaskXml(xml);
        }
        catch
        {
            return null;
        }
    }

    public static string OfTaskXml(string xml) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(xml)));

    /// <summary>扫描时与删除前的快照都必须存在、都完整，且相同。没有快照、读不到、超出预算都不算通过。</summary>
    public static bool Matches(string? expected, string? current) => Check(expected, current) is null;

    /// <summary>返回 null 表示通过，否则为拒绝原因。</summary>
    public static string? Check(string? expected, string? current)
    {
        if (expected is null) return "缺少扫描时的快照，无法核对目标是否变化，拒绝删除";
        if (expected == Truncated || current == Truncated) return $"键内容超过 {MaxEntries} 项，无法完整核对扫描后是否变化，请缩小范围或手动处理";
        if (current is null) return "无法读取目标当前状态，拒绝删除";
        return string.Equals(expected, current, StringComparison.OrdinalIgnoreCase) ? null : "目标在扫描后发生变化，请重新扫描后再清理";
    }

    private static void AppendKey(IncrementalHash sha, RegistryKey k, string relative, ref int budget)
    {
        if (budget <= 0) return;
        sha.AppendData(Encoding.UTF8.GetBytes("K" + relative + "\u001f"));
        foreach (var name in k.GetValueNames().OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            if (--budget <= 0) { sha.AppendData(Encoding.UTF8.GetBytes("truncated")); return; }
            var (kind, value) = RegFile.ReadValue(k, name);
            sha.AppendData(Encoding.UTF8.GetBytes("V" + name + "\u001f"));
            if (kind is not null && value is not null) AppendValue(sha, kind.Value, value);
            sha.AppendData(new byte[] { 0 });
        }
        foreach (var sub in k.GetSubKeyNames().OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            if (--budget <= 0) { sha.AppendData(Encoding.UTF8.GetBytes("truncated")); return; }
            try
            {
                using var child = k.OpenSubKey(sub);
                if (child is null) continue;
                AppendKey(sha, child, relative + "\\" + sub, ref budget);
            }
            catch
            {
                sha.AppendData(Encoding.UTF8.GetBytes("unreadable:" + sub));
            }
        }
    }

    private static void AppendValue(IncrementalHash sha, RegistryValueKind kind, object value)
    {
        sha.AppendData(BitConverter.GetBytes((int)kind));
        sha.AppendData(RegFile.ToBytes(kind, value));
    }
}
