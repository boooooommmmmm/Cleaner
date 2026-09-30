using SysEnv = System.Environment;

namespace CleanSweep.Core.Environment;

/// <summary>
/// 以任意用户配置文件目录为目标的解析器（设计文档 7.4 第 3 条：%AppData% 之类的变量必须按目标用户解析，
/// 在 SYSTEM 或另一个管理员账户的上下文里直接展开是错误的）。用户级变量按 Windows 默认布局从 profile 根推导，
/// 机器级变量（Windir、ProgramData、ProgramFiles）取自本机。
/// </summary>
public sealed class ProfileEnvironmentResolver : IEnvironmentResolver
{
    private readonly CurrentUserEnvironmentResolver _inner;

    public ProfileEnvironmentResolver(string profileRoot)
    {
        profileRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(profileRoot));
        var windir = SysEnv.GetFolderPath(SysEnv.SpecialFolder.Windows);
        var sysDrive = Path.GetPathRoot(windir)!.TrimEnd('\\');
        var local = Path.Combine(profileRoot, "AppData", "Local");
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["UserProfile"] = profileRoot,
            ["LocalAppData"] = local,
            ["AppData"] = Path.Combine(profileRoot, "AppData", "Roaming"),
            ["LocalAppDataLow"] = Path.Combine(profileRoot, "AppData", "LocalLow"),
            ["Temp"] = Path.Combine(local, "Temp"),
            ["Windir"] = windir,
            ["SystemRoot"] = windir,
            ["SystemDrive"] = sysDrive,
            ["ProgramData"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.CommonApplicationData),
            ["ProgramFiles"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.ProgramFiles),
            ["ProgramFilesX86"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.ProgramFilesX86),
            ["Public"] = SysEnv.GetEnvironmentVariable("PUBLIC") ?? Path.Combine(sysDrive + "\\", "Users", "Public"),
        };
        _inner = new CurrentUserEnvironmentResolver(vars);
        ProfileRoot = profileRoot;
    }

    public string ProfileRoot { get; }

    public IReadOnlyDictionary<string, string> Variables => _inner.Variables;

    public bool TryExpand(string raw, out string expanded, out string? error) => _inner.TryExpand(raw, out expanded, out error);
}
