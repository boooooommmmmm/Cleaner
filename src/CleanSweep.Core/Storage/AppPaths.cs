using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Storage;

/// <summary>
/// 程序自身的数据目录。
/// 提权运行（含提权服务）时使用 %ProgramData%\CleanSweep 并把权限限制为 SYSTEM、Administrators 与当前用户：
/// 隔离区索引、注册表备份都会被提权进程信任并写回系统，不能放在其他本地进程改得动的位置。
/// 界面以普通权限运行时，若该目录已由同一用户的提权实例创建（ACL 里有自己，能写），就共用同一份数据：
/// 提权实例移入隔离区的文件、做过的备份在普通权限下也能看到；其他用户或目录不存在时退回 %LocalAppData%\CleanSweep。
/// 索引本身始终按不可信输入处理（sidecar、哈希、护栏），同一用户的普通进程能改它不会扩大提权实例的行为范围。
/// </summary>
public static class AppPaths
{
    public static bool Elevated { get; } = ProtectedDirectory.IsElevated();

    public static string MachineDataDir { get; } = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData), "CleanSweep");
    public static string UserDataDir { get; } = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData), "CleanSweep");

    public static string DataDir { get; } = Elevated ? MachineDataDir : (CanUseMachineDir() ? MachineDataDir : UserDataDir);

    /// <summary>本次启动把用户数据目录迁移到了机器数据目录时，这里是原目录（用于修正备份索引里的路径）。</summary>
    public static string? MigratedFromUserDir { get; private set; }

    /// <summary>
    /// 首次以管理员身份运行时，若此前只以普通权限用过（%LocalAppData%\CleanSweep 存在而 %ProgramData%\CleanSweep 不存在），
    /// 把整个目录搬到 ProgramData：设置、白名单、隔离区索引、注册表备份都跟着走，用户不会在"以管理员身份重新启动"后发现一切归零。
    /// 只在提权、目标不存在、源不是重解析点时进行；搬不动就保留原样，各用各的。
    /// </summary>
    public static void MigrateUserDataIfNeeded()
    {
        if (!Elevated || Directory.Exists(MachineDataDir) || !Directory.Exists(UserDataDir)) return;
        try
        {
            if (PathGuard.IsReparsePoint(UserDataDir)) return;
            Directory.Move(UserDataDir, MachineDataDir);
            MigratedFromUserDir = UserDataDir;
        }
        catch
        {
            MigratedFromUserDir = null;
        }
    }

    /// <summary>共用 ProgramData 目录的条件：目录存在、不是重解析点、能在其中创建文件。</summary>
    private static bool CanUseMachineDir()
    {
        try
        {
            if (!Directory.Exists(MachineDataDir) || PathGuard.IsReparsePoint(MachineDataDir)) return false;
            var probe = Path.Combine(MachineDataDir, ".probe-" + Guid.NewGuid().ToString("N")[..8]);
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string DbPath => Path.Combine(DataDir, "cleansweep.db");
    public static string WhitelistPath => Path.Combine(DataDir, "whitelist.json");
    public static string SettingsPath => Path.Combine(DataDir, "settings.json");
    public static string LogDir => Path.Combine(DataDir, "logs");
    public static string RegistryBackupDir => Path.Combine(DataDir, "backups", "registry");

    /// <summary>随程序分发的规则目录。</summary>
    public static string BundledRulesDir => Path.Combine(AppContext.BaseDirectory, "rules");

    /// <summary>随程序分发的应用指纹库目录。</summary>
    public static string BundledFingerprintsDir => Path.Combine(AppContext.BaseDirectory, "fingerprints");

    /// <summary>随程序分发的弹窗规则目录。</summary>
    public static string BundledPopupRulesDir => Path.Combine(AppContext.BaseDirectory, "popups");

    public static string BundledDir(Integrity.DataKind kind) => Path.Combine(AppContext.BaseDirectory, Integrity.DataSets.KindName(kind));

    /// <summary>程序自更新的下载与解压暂存目录。</summary>
    public static string AppUpdateStagingDir => Path.Combine(DataDir, "updates", "app");

    /// <summary>在线更新下载的数据集目录（签名校验通过且版本高于内置时采用）。</summary>
    public static string UpdateDir(Integrity.DataKind kind) => Path.Combine(DataDir, "updates", Integrity.DataSets.KindName(kind));

    /// <summary>hosts 文件备份目录。</summary>
    public static string HostsBackupDir => Path.Combine(DataDir, "backups", "hosts");

    /// <summary>服务优化记录（本程序改过哪些服务、原来的启动类型），恢复只依据它。</summary>
    public static string ServiceTweakRecordsPath => Path.Combine(DataDir, "service-tweaks.json");

    /// <summary>安装监控快照目录。</summary>
    public static string MonitorDir => Path.Combine(DataDir, "monitor");

    public const string QuarantineFolderName = "$CleanSweep.Quarantine";

    /// <summary>创建数据目录。提权模式下目录必须可信（所有者与 ACL 校验），否则抛出异常由界面提示。</summary>
    public static void EnsureCreated()
    {
        if (Elevated)
            ProtectedDirectory.EnsureTrusted(DataDir);
        else
            Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(LogDir);
    }
}
