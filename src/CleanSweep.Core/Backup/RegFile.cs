using System.Text;
using Microsoft.Win32;

namespace CleanSweep.Core.Backup;

/// <summary>
/// 生成 reg.exe 能导入的 .reg 文本。用于"操作级撤销"：只记录一个值修改前的状态（存在则原样、不存在则删除标记），
/// 这样撤销时既能恢复原数据，也能删掉本程序新建的值——整键合并导入做不到后者。
/// 全部数据以 hex(type) 形式写出，避免字符串转义歧义。
/// </summary>
public static class RegFile
{
    public const string Header = "Windows Registry Editor Version 5.00";

    /// <summary>生成 [key] 段内单个值的快照。value 为 null 表示值不存在，写成 "name"=-（导入时删除该值）。</summary>
    public static string ValueSnapshot(string hiveLongKeyPath, string valueName, RegistryValueKind? kind, object? value)
    {
        var sb = new StringBuilder();
        sb.Append(Header).Append("\r\n\r\n");
        sb.Append('[').Append(hiveLongKeyPath).Append("]\r\n");
        sb.Append(valueName.Length == 0 ? "@" : "\"" + EscapeName(valueName) + "\"").Append('=');
        if (kind is null || value is null)
        {
            sb.Append("-\r\n");
            return sb.ToString();
        }

        var bytes = ToBytes(kind.Value, value);
        var typeCode = (int)kind.Value;
        sb.Append(typeCode == 3 ? "hex:" : $"hex({typeCode:x}):");
        AppendHex(sb, bytes);
        sb.Append("\r\n");
        return sb.ToString();
    }

    /// <summary>读取值当前状态。键或值不存在时 kind/value 都为 null。</summary>
    public static (RegistryValueKind? Kind, object? Value) ReadValue(RegistryKey? key, string valueName)
    {
        if (key is null) return (null, null);
        var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null) return (null, null);
        RegistryValueKind kind;
        try { kind = key.GetValueKind(valueName); }
        catch { return (null, null); }
        return (kind, value);
    }

    internal static byte[] ToBytes(RegistryValueKind kind, object value)
    {
        switch (kind)
        {
            case RegistryValueKind.String:
            case RegistryValueKind.ExpandString:
                return Utf16Z(value.ToString() ?? "");
            case RegistryValueKind.DWord:
                return BitConverter.GetBytes(Convert.ToInt32(value));
            case RegistryValueKind.QWord:
                return BitConverter.GetBytes(Convert.ToInt64(value));
            case RegistryValueKind.MultiString:
            {
                var parts = value as string[] ?? new[] { value.ToString() ?? "" };
                var list = new List<byte>();
                foreach (var p in parts) list.AddRange(Utf16Z(p));
                list.AddRange(new byte[] { 0, 0 });
                return list.ToArray();
            }
            default:
                return value as byte[] ?? Array.Empty<byte>();
        }
    }

    private static byte[] Utf16Z(string s)
    {
        var bytes = Encoding.Unicode.GetBytes(s);
        var result = new byte[bytes.Length + 2];
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }

    /// <summary>regedit 风格：每行最多 25 个字节，用 "\" 续行。</summary>
    private static void AppendHex(StringBuilder sb, byte[] bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
                if (i % 25 == 0) sb.Append("\\\r\n  ");
            }
            sb.Append(bytes[i].ToString("x2"));
        }
    }

    private static string EscapeName(string name) => name.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
