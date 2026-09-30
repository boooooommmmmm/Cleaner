using System.Text;
using System.Text.RegularExpressions;

namespace CleanSweep.Core.Inventory;

/// <summary>
/// 应用名 / 厂商名 / 目录名的归一化比较（设计文档 3.3.2 信号 B）：
/// 大小写、空格、下划线、连字符、版本号、"(x64)"、"64-bit"、"Inc." 之类的公司后缀都不参与比较。
/// </summary>
public static partial class NameKey
{
    private static readonly HashSet<string> Noise = new(StringComparer.OrdinalIgnoreCase)
    {
        "x64", "x86", "amd64", "arm64", "64bit", "32bit", "64", "32", "bit", "version", "edition", "release",
        "inc", "llc", "ltd", "limited", "corporation", "corp", "co", "gmbh", "sa", "ag", "the", "software", "technologies", "technology",
        "有限公司", "股份有限公司", "科技", "软件", "公司",
    };

    [GeneratedRegex(@"\((?:x64|x86|64[- ]?bit|32[- ]?bit|arm64|[\d.]+)\)", RegexOptions.IgnoreCase)]
    private static partial Regex ParenNoise();

    [GeneratedRegex(@"\b(?:v(?:er(?:sion)?)?\s*)?\d+(?:\.\d+){1,3}\b", RegexOptions.IgnoreCase)]
    private static partial Regex VersionToken();

    /// <summary>归一化键：只保留字母数字（含中日韩字符），去掉版本、位数、公司后缀。空输入返回空串。</summary>
    public static string Normalize(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var s = name.Trim();
        s = ParenNoise().Replace(s, " ");
        s = VersionToken().Replace(s, " ");
        var sb = new StringBuilder(s.Length);
        foreach (var token in Tokens(s))
        {
            if (Noise.Contains(token)) continue;
            sb.Append(token);
        }
        return sb.ToString();
    }

    /// <summary>拆成小写字母数字词。</summary>
    public static IEnumerable<string> Tokens(string s)
    {
        var sb = new StringBuilder();
        foreach (var ch in s)
        {
            if (char.IsLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
            else if (sb.Length > 0)
            {
                yield return sb.ToString();
                sb.Clear();
            }
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    /// <summary>
    /// 两个名字是否指同一应用：归一化后相等，或一个是另一个的前缀且短的那个至少 4 个字符
    /// （"Visual Studio Code" 与 "Code" 不算，"IntelliJIdea2023.1" 与 "IntelliJ IDEA" 算）。
    /// </summary>
    public static bool Matches(string? a, string? b)
    {
        var ka = Normalize(a);
        var kb = Normalize(b);
        if (ka.Length == 0 || kb.Length == 0) return false;
        if (ka == kb) return true;
        var shorter = ka.Length < kb.Length ? ka : kb;
        var longer = ReferenceEquals(shorter, ka) ? kb : ka;
        return shorter.Length >= 4 && longer.StartsWith(shorter, StringComparison.Ordinal);
    }
}
