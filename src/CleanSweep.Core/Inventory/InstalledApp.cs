using Microsoft.Win32;

namespace CleanSweep.Core.Inventory;

public enum AppSource
{
    /// <summary>注册表 Uninstall 键。</summary>
    Registry,

    /// <summary>应用商店 / UWP 包。</summary>
    Uwp,

    /// <summary>便携软件：目录里有可执行文件但没有卸载项。</summary>
    Portable,
}

/// <summary>已安装软件清单中的一条（设计文档 7.2 App Inventory）。</summary>
public sealed record InstalledApp
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Publisher { get; init; }
    public string? Version { get; init; }
    public string? InstallLocation { get; init; }
    public string? UninstallString { get; init; }
    public string? QuietUninstallString { get; init; }
    public required AppSource Source { get; init; }

    /// <summary>Registry 来源：Uninstall 子键完整路径（含 hive 前缀）。</summary>
    public string? RegistryKey { get; init; }
    public RegistryView View { get; init; } = RegistryView.Registry64;

    /// <summary>Uwp 来源：包全名与包家族名。</summary>
    public string? PackageFullName { get; init; }
    public string? PackageFamilyName { get; init; }

    /// <summary>SystemComponent=1：不在"应用和功能"中显示的组件（运行库、驱动包）。</summary>
    public bool IsSystemComponent { get; init; }

    /// <summary>WindowsInstaller=1：由 MSI 安装。</summary>
    public bool IsWindowsInstaller { get; init; }

    public DateTime? InstallDate { get; init; }
    public long EstimatedSizeBytes { get; init; }
    public string? DisplayIcon { get; init; }

    /// <summary>微软自带（发布者或包家族后缀）。</summary>
    public bool IsMicrosoft { get; init; }

    /// <summary>用户可见、可卸载（有卸载命令或为 UWP 包，且不是系统组件）。</summary>
    public bool IsUninstallable => !IsSystemComponent && (Source == AppSource.Uwp || !string.IsNullOrWhiteSpace(UninstallString) || !string.IsNullOrWhiteSpace(QuietUninstallString));

    public string NameKeyValue => NameKey.Normalize(Name);
}
