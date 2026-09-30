namespace CleanSweep.Core.Startup;

/// <summary>
/// 任务管理器"启动"页使用的 StartupApproved 键。值为 12 字节：
/// 字节 0 最低位为 1 表示禁用（0x03 / 0x07），为 0 表示启用（0x02 / 0x06）；字节 4..11 为禁用时刻的 FILETIME。
/// 禁用只写这里，不删除原 Run 值（设计文档 4.1）。
/// </summary>
public static class StartupApproved
{
    private const string Base = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    public const string HkcuRun = @"HKCU\" + Base + @"\Run";
    public const string HkcuStartupFolder = @"HKCU\" + Base + @"\StartupFolder";
    public const string HklmRun = @"HKLM\" + Base + @"\Run";
    public const string HklmRun32 = @"HKLM\" + Base + @"\Run32";
    public const string HklmStartupFolder = @"HKLM\" + Base + @"\StartupFolder";

    public static bool IsEnabled(byte[]? data) =>
        data is null || data.Length == 0 || (data[0] & 1) == 0;

    public static DateTime? DisabledAtUtc(byte[]? data)
    {
        if (data is null || data.Length < 12 || IsEnabled(data)) return null;
        var ft = BitConverter.ToInt64(data, 4);
        if (ft <= 0) return null;
        try { return DateTime.FromFileTimeUtc(ft); } catch { return null; }
    }

    /// <summary>生成新值。保留原值字节 0 的高位标志，仅翻转最低位。</summary>
    public static byte[] Encode(bool enabled, byte[]? existing = null, DateTime? nowUtc = null)
    {
        var b = new byte[12];
        byte flags = existing is { Length: > 0 } ? existing[0] : (byte)0x02;
        if (flags < 2) flags = 0x02;
        b[0] = enabled ? (byte)(flags & ~1) : (byte)(flags | 1);
        if (!enabled)
            BitConverter.TryWriteBytes(b.AsSpan(4), (nowUtc ?? DateTime.UtcNow).ToFileTimeUtc());
        return b;
    }
}
