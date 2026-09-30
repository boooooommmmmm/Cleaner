using System.Globalization;
using System.Management;
using Microsoft.Win32;

namespace CleanSweep.Core.Backup;

public enum RestorePointStatus
{
    /// <summary>已创建新的还原点。</summary>
    Created,
    /// <summary>创建频率限制内已有还原点（Windows 默认 24 小时一个），视为已受保护。</summary>
    SkippedRecent,
    /// <summary>系统保护未启用，无法创建。</summary>
    ProtectionDisabled,
    /// <summary>调用失败。</summary>
    Failed,
}

public sealed record RestorePointOutcome(RestorePointStatus Status, string Message, long? SequenceNumber = null)
{
    /// <summary>是否已有可回滚的还原点（新建或近期已有）。</summary>
    public bool Protected => Status is RestorePointStatus.Created or RestorePointStatus.SkippedRecent;
}

public sealed record RestorePointInfo(long SequenceNumber, DateTime CreationUtc, string Description);

/// <summary>
/// 系统还原点（设计文档 6.1 第 5 条）。通过 WMI root\default:SystemRestore 创建与枚举。
/// 创建失败时由调用方降级为注册表备份 + 隔离区，并在界面提示。
/// </summary>
public sealed class RestorePointService
{
    private const string SrKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
    private const string SrPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore";
    public const int DefaultFrequencyMinutes = 1440;

    private const uint ModifySettings = 12;      // RESTOREPOINTTYPE: MODIFY_SETTINGS
    private const uint BeginSystemChange = 100;  // EVENTTYPE: BEGIN_SYSTEM_CHANGE

    private RestorePointOutcome? _lastOutcome;
    private DateTime _lastOutcomeUtc;

    /// <summary>系统保护是否启用（注册表 RPSessionInterval 与策略 DisableSR）。</summary>
    public static bool IsProtectionEnabled()
    {
        try
        {
            using var policy = Registry.LocalMachine.OpenSubKey(SrPolicyKey);
            if (policy?.GetValue("DisableSR") is int p && p == 1) return false;

            using var key = Registry.LocalMachine.OpenSubKey(SrKey);
            if (key is null) return false;
            if (key.GetValue("DisableSR") is int d && d == 1) return false;
            return key.GetValue("RPSessionInterval") is int i && i == 1;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>SystemRestorePointCreationFrequency（分钟）。未设置时为 1440；0 表示不限制。</summary>
    public static int GetFrequencyMinutes()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SrKey);
            return key?.GetValue("SystemRestorePointCreationFrequency") is int m && m >= 0 ? m : DefaultFrequencyMinutes;
        }
        catch
        {
            return DefaultFrequencyMinutes;
        }
    }

    internal static bool ShouldSkip(DateTime? lastCreationUtc, int frequencyMinutes, DateTime nowUtc) =>
        lastCreationUtc is { } t && frequencyMinutes > 0 && nowUtc - t < TimeSpan.FromMinutes(frequencyMinutes) && nowUtc >= t;

    /// <summary>解析 WMI CIM_DATETIME（yyyyMMddHHmmss.ffffff±UUU）为 UTC。</summary>
    internal static DateTime? ParseWmiDateTime(string? s)
    {
        if (s is null || s.Length < 15) return null;
        if (!DateTime.TryParseExact(s[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            return null;

        // 小数秒
        if (s.Length > 15 && s[14] == '.')
        {
            var end = 15;
            while (end < s.Length && char.IsDigit(s[end])) end++;
            if (end > 15 && int.TryParse(s[15..end].PadRight(6, '0')[..6], out var micro))
                dt = dt.AddTicks(micro * 10L);
            s = s[end..];
        }
        else
        {
            s = s[14..];
        }

        // 时区偏移（分钟），"***" 表示未指定，按 UTC 处理
        if (s.Length >= 4 && (s[0] == '+' || s[0] == '-') && int.TryParse(s[1..4], out var offset))
        {
            var sign = s[0] == '-' ? -1 : 1;
            dt = dt.AddMinutes(-sign * offset);
        }
        return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
    }

    public IReadOnlyList<RestorePointInfo> List()
    {
        var list = new List<RestorePointInfo>();
        var scope = new ManagementScope(@"\\.\root\default");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT SequenceNumber, CreationTime, Description FROM SystemRestore"));
        using var results = searcher.Get();
        foreach (var o in results)
        {
            using (o)
            {
                var seq = Convert.ToInt64(o["SequenceNumber"], CultureInfo.InvariantCulture);
                var created = ParseWmiDateTime(o["CreationTime"] as string) ?? DateTime.MinValue;
                list.Add(new RestorePointInfo(seq, created, o["Description"] as string ?? ""));
            }
        }
        return list;
    }

    /// <summary>创建还原点。同一实例在 10 分钟内重复调用直接返回上次结果，避免一批操作里反复创建。</summary>
    public RestorePointOutcome EnsureRecent(string description)
    {
        if (_lastOutcome is { Protected: true } last && DateTime.UtcNow - _lastOutcomeUtc < TimeSpan.FromMinutes(10))
            return last;
        var outcome = TryCreate(description);
        _lastOutcome = outcome;
        _lastOutcomeUtc = DateTime.UtcNow;
        return outcome;
    }

    public RestorePointOutcome TryCreate(string description)
    {
        try
        {
            if (!IsProtectionEnabled())
                return new RestorePointOutcome(RestorePointStatus.ProtectionDisabled, "系统保护未启用，无法创建还原点。本次操作仅有注册表备份与隔离区保护。");

            RestorePointInfo? latest = null;
            try
            {
                latest = List().OrderByDescending(p => p.CreationUtc).FirstOrDefault();
            }
            catch
            {
                // 枚举失败不阻止创建
            }

            if (ShouldSkip(latest?.CreationUtc, GetFrequencyMinutes(), DateTime.UtcNow))
            {
                return new RestorePointOutcome(RestorePointStatus.SkippedRecent,
                    $"{latest!.CreationUtc.ToLocalTime():yyyy-MM-dd HH:mm} 已有还原点“{latest.Description}”，Windows 在创建频率限制内不允许再建，将使用该还原点。",
                    latest.SequenceNumber);
            }

            var scope = new ManagementScope(@"\\.\root\default");
            scope.Connect();
            using var cls = new ManagementClass(scope, new ManagementPath("SystemRestore"), new ObjectGetOptions());
            using var inParams = cls.GetMethodParameters("CreateRestorePoint");
            inParams["Description"] = description;
            inParams["RestorePointType"] = ModifySettings;
            inParams["EventType"] = BeginSystemChange;
            using var outParams = cls.InvokeMethod("CreateRestorePoint", inParams, null);
            var rc = Convert.ToUInt32(outParams["ReturnValue"], CultureInfo.InvariantCulture);
            if (rc != 0)
            {
                var hint = rc switch
                {
                    1058 => "系统还原服务已禁用",
                    1717 => "接口未注册",
                    _ => $"错误码 {rc}",
                };
                return new RestorePointOutcome(RestorePointStatus.Failed, $"创建还原点失败：{hint}。本次操作仅有注册表备份与隔离区保护。");
            }

            long? seq = null;
            try { seq = List().OrderByDescending(p => p.CreationUtc).FirstOrDefault()?.SequenceNumber; } catch { }
            return new RestorePointOutcome(RestorePointStatus.Created, $"已创建系统还原点“{description}”。", seq);
        }
        catch (Exception ex)
        {
            return new RestorePointOutcome(RestorePointStatus.Failed, $"创建还原点失败：{ex.Message}。本次操作仅有注册表备份与隔离区保护。");
        }
    }
}
