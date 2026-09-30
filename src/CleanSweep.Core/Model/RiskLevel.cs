namespace CleanSweep.Core.Model;

/// <summary>
/// 风险等级。对应设计文档 6.1 第 2 条：默认只勾选 Safe；NotRecommended 仅高级模式可见。
/// </summary>
public enum RiskLevel
{
    /// <summary>安全，默认勾选。</summary>
    Safe = 0,

    /// <summary>建议确认，默认不勾选。</summary>
    Confirm = 1,

    /// <summary>高风险，默认不勾选，界面标红。</summary>
    High = 2,

    /// <summary>不建议清理，默认隐藏，仅高级模式显示。</summary>
    NotRecommended = 3,
}
