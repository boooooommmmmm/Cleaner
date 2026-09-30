namespace CleanSweep.Core.Environment;

/// <summary>
/// 把规则中的 %变量% 解析为目标用户的真实路径。
/// 只允许一组已知变量，未知变量视为规则错误（设计文档 6.2 第 3 条）。
/// M1 阶段只有当前用户实现；M3 提权服务需要按 SID 解析（设计文档 7.4 第 3 条）。
/// </summary>
public interface IEnvironmentResolver
{
    /// <summary>已知变量名（不含百分号）到绝对路径的映射，键不区分大小写。</summary>
    IReadOnlyDictionary<string, string> Variables { get; }

    /// <summary>展开路径中的全部 %变量%。任何未知变量都导致失败。</summary>
    bool TryExpand(string raw, out string expanded, out string? error);
}
