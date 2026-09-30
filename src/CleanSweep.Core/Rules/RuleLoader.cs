using System.Text.Json;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Rules;

/// <summary>
/// 加载并校验 JSON 规则。任何一条目标不合法，整条规则拒绝加载（设计文档 6.2 第 3 条）。
/// 签名校验（6.2 第 4 条）由调用方在传入目录前完成；M1 只加载随程序分发的内置规则。
/// </summary>
public sealed class RuleLoader
{
    /// <summary>Command 类目标允许的可执行文件白名单（仅文件名，实际从 System32 解析）。</summary>
    public static readonly IReadOnlySet<string> AllowedCommands =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "dism.exe", "cleanmgr.exe" };

    /// <summary>
    /// 固定操作表：命令与参数必须与这里精确匹配（空白归一后），规则只能引用经过审查的操作，不能自定义参数。
    /// </summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> AllowedOperations =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["dism.exe"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "/Online /Cleanup-Image /StartComponentCleanup",
            },
            ["cleanmgr.exe"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "/autoclean",
            },
        };

    public static bool IsAllowedOperation(string? command, string? args)
    {
        if (command is null || !AllowedOperations.TryGetValue(command, out var allowed)) return false;
        var normalized = string.Join(' ', (args ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return allowed.Contains(normalized);
    }

    /// <summary>不经隔离区、不可恢复的目标类型最低风险等级为"建议确认"，规则不能把它们标成"安全"。</summary>
    public static RiskLevel ApplyRiskFloor(TargetKind kind, RiskLevel risk) =>
        kind is TargetKind.Command or TargetKind.RecycleBin && risk < RiskLevel.Confirm ? RiskLevel.Confirm : risk;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private readonly PathGuard _guard;

    public RuleLoader(PathGuard guard)
    {
        _guard = guard;
    }

    /// <summary>不校验签名地加载目录下全部 *.json（测试与工具用）。程序加载数据集走 <see cref="LoadFiles"/> + 签名清单。</summary>
    public RuleLoadResult LoadDirectory(string directory)
    {
        var result = new RuleLoadResult();
        if (!Directory.Exists(directory))
        {
            result.Rejected.Add(new RuleRejection(directory, null, "规则目录不存在"));
            return result;
        }
        return LoadFiles(Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories)
            .Where(f => !Path.GetFileName(f).Equals(Integrity.SignedManifest.FileName, StringComparison.OrdinalIgnoreCase)), result);
    }

    /// <summary>加载签名清单校验通过的文件内容（校验时读到的字节，不重读磁盘）。</summary>
    public RuleLoadResult LoadContents(IEnumerable<Integrity.VerifiedFile> files)
    {
        var result = new RuleLoadResult();
        foreach (var f in files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)) LoadJson(f.Content, f.Path, result);
        return result;
    }

    /// <summary>按路径加载给定的文件（测试与工具用）。</summary>
    public RuleLoadResult LoadFiles(IEnumerable<string> files, RuleLoadResult? into = null)
    {
        var result = into ?? new RuleLoadResult();
        foreach (var file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            string json;
            try
            {
                json = File.ReadAllText(file);
            }
            catch (Exception ex)
            {
                result.Rejected.Add(new RuleRejection(file, null, $"读取失败：{ex.Message}"));
                continue;
            }

            LoadJson(json, file, result);
        }

        return result;
    }

    public RuleLoadResult LoadJson(string json, string sourceName)
    {
        var result = new RuleLoadResult();
        LoadJson(json, sourceName, result);
        return result;
    }

    private void LoadJson(string json, string sourceName, RuleLoadResult result)
    {
        RuleFileDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<RuleFileDto>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            result.Rejected.Add(new RuleRejection(sourceName, null, $"JSON 解析失败：{ex.Message}"));
            return;
        }

        if (dto?.Rules is null || dto.Rules.Count == 0)
        {
            result.Rejected.Add(new RuleRejection(sourceName, null, "文件中没有 rules 数组"));
            return;
        }

        var seen = new HashSet<string>(result.Rules.Select(r => r.Id), StringComparer.OrdinalIgnoreCase);

        foreach (var r in dto.Rules)
        {
            if (r is null)
            {
                result.Rejected.Add(new RuleRejection(sourceName, null, "规则为 null"));
                continue;
            }

            (CleanRule? rule, string? reason) = (null, null);
            try
            {
                (rule, reason) = Validate(r, sourceName);
            }
            catch (Exception ex)
            {
                reason = $"规则校验异常：{ex.Message}";
            }
            if (rule is null)
            {
                result.Rejected.Add(new RuleRejection(sourceName, r.Id, reason!));
                continue;
            }

            if (!seen.Add(rule.Id))
            {
                result.Rejected.Add(new RuleRejection(sourceName, r.Id, "规则 ID 重复"));
                continue;
            }

            result.Rules.Add(rule);
        }
    }

    private (CleanRule? Rule, string? Reason) Validate(CleanRuleDto dto, string source)
    {
        if (string.IsNullOrWhiteSpace(dto.Id)) return (null, "缺少 id");
        if (string.IsNullOrWhiteSpace(dto.App)) return (null, "缺少 app");
        if (dto.Targets is null || dto.Targets.Count == 0) return (null, "缺少 targets");
        if (dto.Targets.Any(t => t is null)) return (null, "targets 中存在 null");

        var category = (dto.Category ?? "").Trim().ToLowerInvariant();
        if (category is not ("system" or "browser" or "app" or "dev"))
            return (null, $"未知 category：{dto.Category}");

        if (dto.Detect is not null)
        {
            var conds = (dto.Detect.AnyOf ?? new()).Concat(dto.Detect.AllOf ?? new());
            foreach (var c in conds)
            {
                if (c is null) return (null, "detect 条件为 null");
                var filled = (c.Registry is not null ? 1 : 0) + (c.File is not null ? 1 : 0) + (c.Directory is not null ? 1 : 0);
                if (filled != 1) return (null, "detect 条件必须且只能填写 registry / file / directory 之一");
                if (c.Registry is not null && !RegistryDetect.IsValidKeyPath(c.Registry))
                    return (null, $"detect 注册表路径无效：{c.Registry}");
            }
        }

        var targets = new List<RuleTarget>();
        foreach (var t in dto.Targets)
        {
            if (!TryParseRisk(t.Risk ?? "", out var risk)) return (null, $"未知 risk：{t.Risk}");
            if (!TryParseWhen(t.When ?? "", out var when)) return (null, $"未知 when：{t.When}");
            if (!TryParseKind(t.Kind ?? "", out var kind)) return (null, $"未知 kind：{t.Kind}");
            risk = ApplyRiskFloor(kind, risk);

            if (when != RuleWhen.Always && dto.Detect is null)
                return (null, "when 为 installed / uninstalled 时必须提供 detect");

            if (t.MinAgeDays is < 0 or > 3650) return (null, $"minAgeDays 超出范围（0 到 3650）：{t.MinAgeDays}");

            if (t.PreActions is not null)
            {
                foreach (var pa in t.PreActions)
                {
                    if (pa is null || !PreActionSyntax.IsValid(pa)) return (null, $"无效 preAction：{pa ?? "null"}");
                }
            }

            string? expanded = null;
            switch (kind)
            {
                case TargetKind.Files:
                case TargetKind.Directory:
                {
                    if (string.IsNullOrWhiteSpace(t.Path)) return (null, "files / directory 目标缺少 path");
                    if (PathGuard.HasWildcardSegment(t.Path))
                    {
                        var tv = _guard.ValidateRuleTemplate(t.Path, out var template);
                        if (!tv.Allowed) return (null, $"通配路径被拒绝（{t.Path}）：{tv.Reason}");
                        expanded = template;
                    }
                    else
                    {
                        var verdict = _guard.ValidateRulePath(t.Path);
                        if (!verdict.Allowed) return (null, $"路径被拒绝（{t.Path}）：{verdict.Reason}");
                        expanded = verdict.FullPath;
                    }

                    if (t.Pattern is not null && t.Pattern.IndexOfAny(new[] { '\\', '/', ':' }) >= 0)
                        return (null, $"pattern 不得包含路径分隔符：{t.Pattern}");

                    if (kind == TargetKind.Directory && t.Pattern is not null)
                        return (null, "directory 目标不支持 pattern");
                    break;
                }
                case TargetKind.Command:
                {
                    if (string.IsNullOrWhiteSpace(t.Command)) return (null, "command 目标缺少 command");
                    if (!AllowedCommands.Contains(t.Command)) return (null, $"命令不在白名单内：{t.Command}");
                    if (t.Path is not null || t.Pattern is not null) return (null, "command 目标不得携带 path / pattern");
                    if (!IsAllowedOperation(t.Command, t.Args)) return (null, $"命令参数不在允许的操作表内：{t.Command} {t.Args}");
                    break;
                }
                case TargetKind.RecycleBin:
                    if (t.Path is not null || t.Pattern is not null) return (null, "recycleBin 目标不得携带 path / pattern");
                    break;
            }

            // 临时目录统一保护：任何 Temp / Tmp 目录下的 files 目标最少 24 小时年龄，规则忘了写也不会清到正在使用的临时文件
            var minAge = Math.Max(0, t.MinAgeDays);
            if (kind == TargetKind.Files && expanded is not null && IsTempDirectory(expanded) && minAge < 1) minAge = 1;

            targets.Add(new RuleTarget(
                RawPath: t.Path,
                ExpandedPath: expanded,
                Pattern: t.Pattern,
                Recurse: t.Recurse,
                Risk: risk,
                When: when,
                Kind: kind,
                Description: t.Description ?? t.Path ?? t.Command ?? dto.App!,
                PreActions: t.PreActions?.AsReadOnly() ?? (IReadOnlyList<string>)Array.Empty<string>(),
                Command: t.Command,
                Args: t.Args,
                MinAgeDays: minAge));
        }

        return (new CleanRule(dto.Id!.Trim(), dto.App!.Trim(), dto.Publisher, category, dto.Detect, targets, source), null);
    }

    /// <summary>目标目录自身的名字为 Temp / Tmp / SystemTemp 即视为临时目录（只看最后一级：祖先里有 Temp 不算）。</summary>
    internal static bool IsTempDirectory(string expandedPath)
    {
        var last = Path.GetFileName(Path.TrimEndingDirectorySeparator(expandedPath));
        return last.Equals("Temp", StringComparison.OrdinalIgnoreCase)
               || last.Equals("Tmp", StringComparison.OrdinalIgnoreCase)
               || last.Equals("SystemTemp", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseRisk(string s, out RiskLevel risk)
    {
        switch (s.Trim().ToLowerInvariant())
        {
            case "safe": risk = RiskLevel.Safe; return true;
            case "confirm": risk = RiskLevel.Confirm; return true;
            case "high": risk = RiskLevel.High; return true;
            case "not-recommended":
            case "notrecommended": risk = RiskLevel.NotRecommended; return true;
            default: risk = default; return false;
        }
    }

    private static bool TryParseWhen(string s, out RuleWhen when)
    {
        switch (s.Trim().ToLowerInvariant())
        {
            case "installed": when = RuleWhen.Installed; return true;
            case "uninstalled": when = RuleWhen.Uninstalled; return true;
            case "always": when = RuleWhen.Always; return true;
            default: when = default; return false;
        }
    }

    private static bool TryParseKind(string s, out TargetKind kind)
    {
        switch (s.Trim().ToLowerInvariant())
        {
            case "files": kind = TargetKind.Files; return true;
            case "directory": kind = TargetKind.Directory; return true;
            case "command": kind = TargetKind.Command; return true;
            case "recyclebin": kind = TargetKind.RecycleBin; return true;
            default: kind = default; return false;
        }
    }
}

/// <summary>preAction 字符串语法："stopService:名称"。</summary>
public static class PreActionSyntax
{
    public const string StopService = "stopService";

    public static bool IsValid(string action)
    {
        var parts = action.Split(':', 2);
        if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[1])) return false;
        return parts[0] == StopService && parts[1].All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '-' or '.');
    }

    public static (string Verb, string Arg) Parse(string action)
    {
        var parts = action.Split(':', 2);
        return (parts[0], parts[1]);
    }
}
