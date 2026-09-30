using System.Text.Json.Serialization;
using CleanSweep.Core.Model;

namespace CleanSweep.Core.Rules;

/// <summary>规则目标何时生效（设计文档 7.3 语义说明）。</summary>
public enum RuleWhen
{
    /// <summary>应用已安装时生效，归入"应用缓存清理"。</summary>
    Installed,

    /// <summary>应用已卸载时生效，归入"用户目录残留清理"。</summary>
    Uninstalled,

    /// <summary>始终生效（系统垃圾规则）。</summary>
    Always,
}

public enum TargetKind
{
    Files,
    Directory,
    Command,
    RecycleBin,
}

/// <summary>规则 JSON 的 detect 条件之一。三者任填其一。</summary>
public sealed class DetectCondition
{
    /// <summary>注册表键路径，如 HKCU\Software\Foo。存在即命中。</summary>
    public string? Registry { get; set; }

    /// <summary>文件路径，可含 %变量%。</summary>
    public string? File { get; set; }

    /// <summary>目录路径，可含 %变量%。</summary>
    public string? Directory { get; set; }
}

public sealed class RuleDetect
{
    public List<DetectCondition>? AnyOf { get; set; }
    public List<DetectCondition>? AllOf { get; set; }
}

/// <summary>JSON 反序列化用的目标 DTO。</summary>
public sealed class RuleTargetDto
{
    public string? Path { get; set; }
    public string? Pattern { get; set; }
    public bool Recurse { get; set; } = true;
    public string? Risk { get; set; } = "safe";
    public string? When { get; set; } = "always";
    public string? Kind { get; set; } = "files";
    public string? Description { get; set; }
    public List<string>? PreActions { get; set; }
    public string? Command { get; set; }
    public string? Args { get; set; }

    /// <summary>仅清理最后修改早于 N 天的文件（0 表示不限制）。</summary>
    public int MinAgeDays { get; set; }

    /// <summary>按文件名排除的通配模式（如 "TileCache_*"），用于目录里长期被进程独占、清了也只会报"正在使用"的文件。只对 files 目标有效。</summary>
    public List<string>? Exclude { get; set; }
}

/// <summary>JSON 反序列化用的规则 DTO。</summary>
public sealed class CleanRuleDto
{
    public string? Id { get; set; }
    public string? App { get; set; }
    public string? Publisher { get; set; }

    /// <summary>system / browser / app / dev。</summary>
    public string? Category { get; set; } = "app";

    public RuleDetect? Detect { get; set; }
    public List<RuleTargetDto>? Targets { get; set; }
}

public sealed class RuleFileDto
{
    public int Version { get; set; } = 1;
    public List<CleanRuleDto>? Rules { get; set; }
}

/// <summary>校验通过、可直接执行的规则目标。</summary>
public sealed record RuleTarget(
    string? RawPath,
    string? ExpandedPath,
    string? Pattern,
    bool Recurse,
    RiskLevel Risk,
    RuleWhen When,
    TargetKind Kind,
    string Description,
    IReadOnlyList<string> PreActions,
    string? Command,
    string? Args,
    int MinAgeDays,
    IReadOnlyList<string> Exclude)
{
    /// <summary>路径含通配目录段：ExpandedPath 是展开后的模板（仍含 *），扫描时逐个解析成具体目录。</summary>
    public bool HasWildcard => RawPath is not null && Safety.PathGuard.HasWildcardSegment(RawPath);
}

/// <summary>校验通过的规则。</summary>
public sealed record CleanRule(
    string Id,
    string App,
    string? Publisher,
    string Category,
    RuleDetect? Detect,
    IReadOnlyList<RuleTarget> Targets,
    string SourceFile);

public sealed record RuleRejection(string SourceFile, string? RuleId, string Reason);

public sealed class RuleLoadResult
{
    public List<CleanRule> Rules { get; } = new();
    public List<RuleRejection> Rejected { get; } = new();
}
