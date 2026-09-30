using Microsoft.Win32;

namespace CleanSweep.Core.Startup;

public enum StartupKind
{
    RegistryRun,
    RegistryRunOnce,
    StartupFolder,
    ScheduledTask,
    Service,
    UwpStartupTask,
}

public enum StartupScope
{
    CurrentUser,
    AllUsers,
}

public enum SignatureState
{
    Unknown,
    Unsigned,
    Invalid,
    Signed,
    SignedMicrosoft,
}

public enum StartupImpact
{
    NotMeasured,
    Low,
    Medium,
    High,
}

public enum StartupSuggestion
{
    Keep,
    CanDisable,
    RecommendDisable,
}

/// <summary>各来源用于定位与写回的内部句柄。</summary>
public sealed record StartupHandle(
    string? RegistryKey = null,
    RegistryView View = RegistryView.Registry64,
    string? ValueName = null,
    string? ApprovedKey = null,
    string? FilePath = null,
    string? TaskPath = null,
    string? ServiceName = null,
    string? UwpKey = null);

/// <summary>一条开机启动项（设计文档 4.1）。</summary>
public sealed class StartupItem
{
    public required string Id { get; init; }
    public required StartupKind Kind { get; init; }
    public required StartupScope Scope { get; init; }
    public required string Name { get; init; }

    /// <summary>原始命令行 / 镜像路径。</summary>
    public string? Command { get; init; }

    /// <summary>解析出的可执行文件绝对路径。</summary>
    public string? ExePath { get; init; }
    public string? Arguments { get; init; }

    /// <summary>注册表键、启动文件夹、任务路径或服务名，用于展示。</summary>
    public required string Location { get; init; }

    public string? Publisher { get; init; }
    public SignatureState Signature { get; init; }
    public bool IsMicrosoft { get; init; }

    public bool Enabled { get; init; }
    public bool CanToggle { get; init; } = true;
    public bool CanDelete { get; init; }
    public bool CanDelay { get; init; }

    public StartupImpact Impact { get; init; }
    public double CpuMs { get; init; }
    public long DiskBytes { get; init; }

    public StartupSuggestion Suggestion { get; init; }

    /// <summary>补充说明：服务启动类型、触发方式、策略锁定等。</summary>
    public string? Note { get; init; }

    public required StartupHandle Handle { get; init; }
}

public sealed record BootRecord(DateTime TimeUtc, int BootTimeMs, int MainPathMs, int PostBootMs);
