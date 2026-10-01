using System.Text;

namespace CleanSweep.Core.Model;

/// <summary>
/// 给每个清理项一份"依据 / 影响 / 恢复方式"的说明（设计文档 6.1 第 1 条：用户能看懂每项操作）。
/// 说明只从条目已有的结构化字段推导（规则 ID、类型、风险、快照、前置动作、缺失路径），不另外猜测用途；
/// 界面展示与执行前校验用的是同一份信息。
/// </summary>
public static class ItemExplanation
{
    public sealed record Text(string Basis, string Effect, string Recovery, string? Preconditions);

    /// <param name="retentionDays">隔离区保留天数（设置）。</param>
    /// <param name="quarantineRootOf">路径 → 该卷隔离区目录；为 null 时不写具体目录。</param>
    public static Text For(ScanItem item, int retentionDays, Func<string, string>? quarantineRootOf = null)
        => new(Basis(item), Effect(item), Recovery(item, retentionDays, quarantineRootOf), Preconditions(item));

    /// <summary>为什么会列出来。</summary>
    public static string Basis(ScanItem item)
    {
        var sb = new StringBuilder();
        if (item.RuleId is { Length: > 0 } rule)
            sb.Append("规则库规则 ").Append(rule).Append("（模块 ").Append(item.ModuleId).Append("）命中");
        else
            sb.Append(ModuleName(item.ModuleId)).Append("扫描判定");
        if (item.MissingPath is { Length: > 0 } missing)
            sb.Append("；指向的目标已不存在：").Append(missing);
        if (item.Kind is ItemKind.FileSet && item.FileCount > 0)
            sb.Append("；扫描到 ").Append(item.FileCount.ToString("N0")).Append(" 个文件");
        if (item.Kind is ItemKind.Directory && item.DirectoryFileCount > 0)
            sb.Append("；目录内 ").Append(item.DirectoryFileCount.ToString("N0")).Append(" 个文件");
        if (item.LastWriteUtc is { } lw)
            sb.Append("，最后修改 ").Append(lw.ToLocalTime().ToString("yyyy-MM-dd"));
        sb.Append('。');
        return sb.ToString();
    }

    /// <summary>清理后会怎样。</summary>
    public static string Effect(ScanItem item)
    {
        var kind = item.Kind switch
        {
            ItemKind.FileSet => "删除这些文件",
            ItemKind.Directory => "删除整个目录",
            ItemKind.RecycleBin => "清空系统回收站",
            ItemKind.Command => "执行一条系统命令",
            ItemKind.RegistryValue => "删除一个注册表值",
            ItemKind.RegistryKey => "删除一个注册表键及其子键",
            ItemKind.Service => "删除一个服务的登记",
            ItemKind.ScheduledTask => "删除一个计划任务",
            _ => "处理该项",
        };
        // "安全"级的后果按条目类型措辞：文件类是缓存会重建，注册表类是失效登记项，回收站与命令另说
        var risk = item.Risk switch
        {
            RiskLevel.Safe when item.Kind is ItemKind.RecycleBin => "回收站里是你已经删除的内容，清空后不再占用空间。",
            RiskLevel.Safe when item.Kind is ItemKind.Command => "由系统命令按微软自己的规则处理，不影响已安装的程序；执行需要几分钟。",
            RiskLevel.Safe when item.IsRegistryLike => "扫描时判定为失效登记项，执行前仍需核对其内容与删除依据。",
            RiskLevel.Safe => "按当前规则判为安全，具体用途以条目说明为准。缓存通常会重新生成；残留配置、日志或历史记录不会因此自动恢复。",
            RiskLevel.Confirm => "可能包含你还会用到的记录、设置或存档，清理前请确认不再需要。",
            RiskLevel.High => "可能影响程序或系统功能，只有确定不再需要时才清理。",
            RiskLevel.NotRecommended => "一般不建议清理，收益很小或有副作用。",
            _ => "",
        };
        return $"{kind}。{risk}";
    }

    /// <summary>后悔了怎么办。</summary>
    public static string Recovery(ScanItem item, int retentionDays, Func<string, string>? quarantineRootOf)
    {
        switch (item.Kind)
        {
            case ItemKind.FileSet:
            case ItemKind.Directory:
            {
                string where = "同一磁盘的隔离区";
                if (quarantineRootOf is not null && item.Path is { Length: > 0 } p)
                {
                    try { where = quarantineRootOf(p); } catch { }
                }
                return $"先移入 {where}，默认保留 {retentionDays} 天；未被永久删除前可在“隔离区”页恢复。到期或超过隔离区容量上限时可能被自动淘汰。";
            }
            case ItemKind.RecycleBin:
                return "不经过隔离区，清空后不可恢复。";
            case ItemKind.Command:
                return "系统命令执行后不可撤销。";
            case ItemKind.RegistryValue:
                return "删除前为该值保存 .reg 备份，可在“设置 → 备份与还原”中还原该值。";
            case ItemKind.RegistryKey:
                return "删除前先把整个键导出为 .reg 备份，可在“设置 → 备份与还原”中一键还原。";
            case ItemKind.Service:
                return "删除前先导出服务的注册表键备份，可在“设置 → 备份与还原”中还原（还原后需重启生效）。";
            case ItemKind.ScheduledTask:
                return "删除前先把任务定义 XML 存到备份目录，可在“设置 → 计划任务备份”中重新注册。";
            default:
                return "";
        }
    }

    /// <summary>执行前的核对与前置动作；没有则为 null。</summary>
    public static string? Preconditions(ScanItem item)
    {
        var parts = new List<string>();
        foreach (var a in item.PreActions)
        {
            var (verb, arg) = a.Contains(':') ? Rules.PreActionSyntax.Parse(a) : (a, "");
            parts.Add(verb == Rules.PreActionSyntax.StopService ? $"先停止服务 {arg}（清理完成后恢复启动）" : a);
        }
        if (item.Kind is ItemKind.Directory && item.DirectoryFingerprint is not null)
            parts.Add("移动前重新核对目录内容，扫描后有任何变化则拒绝");
        if (item.Kind is ItemKind.FileSet && item.FileCount > 0)
            parts.Add("逐个文件核对大小与修改时间，扫描后变化的文件跳过");
        if (item.TargetSnapshot is not null)
            parts.Add("删除前重新读取并比对内容，扫描后被改写则拒绝");
        if (item.MissingPath is { Length: > 0 })
            parts.Add("删除前再次探测目标路径，重新出现则拒绝");
        return parts.Count == 0 ? null : string.Join("；", parts) + "。";
    }

    private static string ModuleName(string moduleId) => moduleId switch
    {
        "residue" => "残留清理",
        "dev-cache" => "开发者缓存",
        "registry" => "注册表清理",
        "privacy" => "隐私清理",
        "startup" => "开机加速",
        "uninstall" => "软件卸载",
        _ => "本模块",
    };
}
