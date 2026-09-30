using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CleanSweep.Core.Elevation;

/// <summary>
/// 提权服务只接受枚举型指令（设计文档 7.4 第 2 条）：没有任何指令携带任意路径。
/// 路径都由服务侧根据指令里的 ID 从自己的索引 / 规则库解析，用户目录按连接方的 SID 展开。
/// </summary>
public enum ElevatedOperation
{
    /// <summary>连通性测试。</summary>
    Ping = 0,

    /// <summary>服务状态（版本、数据目录、是否提权）。</summary>
    GetStatus = 1,

    /// <summary>永久删除隔离区中 ID 为 ItemId 的项。</summary>
    PurgeQuarantineItem = 10,

    /// <summary>恢复隔离区中 ID 为 ItemId 的项。</summary>
    RestoreQuarantineItem = 11,

    /// <summary>淘汰过期隔离项。</summary>
    PurgeExpiredQuarantine = 12,

    /// <summary>按规则 ID 执行一次"安全"级清理（用户目录按连接方 SID 解析）。</summary>
    RunRuleClean = 20,
}

/// <summary>规则清理请求里的一个条目：扫描条目 ID（模块 + 规则 + 路径的哈希，不是路径）与用户确认时的内容快照。</summary>
public sealed record ElevationItemRef(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("snap")] string? Snapshot);

/// <summary>
/// 请求。Items 给出时服务只执行重新扫描结果中 ID 匹配且内容快照一致的条目，让用户在界面上的勾选与确认时看到的内容原样生效；
/// ItemKey 为隔离项的对象标识（<see cref="Cleaning.Quarantine.ObjectKey"/>），服务核对自己索引里的同一条。
/// </summary>
public sealed record ElevationRequest(
    [property: JsonPropertyName("op")] ElevatedOperation Operation,
    [property: JsonPropertyName("itemId")] long? ItemId = null,
    [property: JsonPropertyName("ruleId")] string? RuleId = null,
    [property: JsonPropertyName("itemIds")] IReadOnlyList<string>? ItemIds = null,
    [property: JsonPropertyName("items")] IReadOnlyList<ElevationItemRef>? Items = null,
    [property: JsonPropertyName("itemKey")] string? ItemKey = null)
{
    public const int MaxItems = 500;
}

public sealed record ElevationResponse(
    [property: JsonPropertyName("ok")] bool Success,
    [property: JsonPropertyName("msg")] string Message,
    [property: JsonPropertyName("payload")] string? Payload = null);

/// <summary>长度前缀 + UTF-8 JSON 的帧格式。单帧上限 64 KB，超长即断开。</summary>
public static class ElevationProtocol
{
    public const string DefaultPipeName = "CleanSweep.Elevation.v1";
    public const int MaxFrameBytes = 64 * 1024;

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        if (bytes.Length > MaxFrameBytes) throw new InvalidOperationException("消息过长");
        var len = BitConverter.GetBytes(bytes.Length);
        await stream.WriteAsync(len, ct).ConfigureAwait(false);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>读取一帧。对方断开返回 null；帧长非法抛出 <see cref="InvalidDataException"/>。</summary>
    public static async Task<T?> ReadAsync<T>(Stream stream, CancellationToken ct) where T : class
    {
        var lenBuf = new byte[4];
        if (!await ReadExactlyAsync(stream, lenBuf, ct).ConfigureAwait(false)) return null;
        var len = BitConverter.ToInt32(lenBuf);
        if (len <= 0 || len > MaxFrameBytes) throw new InvalidDataException($"非法帧长度 {len}");
        var buf = new byte[len];
        if (!await ReadExactlyAsync(stream, buf, ct).ConfigureAwait(false)) return null;
        try
        {
            return JsonSerializer.Deserialize<T>(buf, Json);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("消息不是合法 JSON：" + ex.Message);
        }
    }

    private static async Task<bool> ReadExactlyAsync(Stream stream, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            var n = await stream.ReadAsync(buf.AsMemory(read), ct).ConfigureAwait(false);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    public static string Describe(ElevationRequest r) => r.Operation switch
    {
        ElevatedOperation.PurgeQuarantineItem or ElevatedOperation.RestoreQuarantineItem => $"{r.Operation}({r.ItemId})",
        ElevatedOperation.RunRuleClean => $"{r.Operation}({r.RuleId})",
        _ => r.Operation.ToString(),
    };

    internal static string ToJson<T>(T value) => JsonSerializer.Serialize(value, Json);
    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}
