namespace CleanSweep.Core.RegistryCleaning;

/// <summary>已确认目标不存在，无需执行删除；不可用它表示权限不足或读取失败。</summary>
public sealed class RegistryTargetMissingException : InvalidOperationException
{
    public RegistryTargetMissingException() : base("注册表目标已不存在，无需清理") { }
}
