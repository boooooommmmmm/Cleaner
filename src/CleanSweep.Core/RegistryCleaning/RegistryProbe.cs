using CleanSweep.Core.Startup;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>
/// 注册表里引用的文件是否存在的判定。"不存在"要过得了这些坎才算：环境变量展开、引号与参数剥离、rundll32 载荷、
/// \??\ 与 \SystemRoot\ 前缀、8.3 短名、System32 / SysWOW64 重定向、不可用的驱动器（可移动 / 网络盘不算不存在）。
/// 判定为 Missing 才允许作为清理依据；Unknown 一律放过。
/// </summary>
public enum FileProbe
{
    Exists,
    Missing,
    Unknown,
}

public static class RegistryProbe
{
    public static Func<string, bool> FileExists { get; set; } = File.Exists;
    public static Func<string, bool> DirectoryExists { get; set; } = Directory.Exists;
    public static Func<string, bool> DriveReady { get; set; } = DefaultDriveReady;

    private static readonly string[] ExecutableExtensions = { ".exe", ".dll", ".ocx", ".ax", ".cpl", ".scr", ".sys", ".com", ".bat", ".cmd" };

    /// <summary>
    /// 把注册表里的值解析成要检查的文件路径。返回 null 表示不是可判定的文件引用（URL、shell 命名空间、未解析变量等）。
    /// isCommandLine 为 true 时按命令行处理（可带参数、rundll32 载荷）；为 false 时整个值就是一个路径（InstallLocation、任务动作路径）。
    /// 不带引号且含空格的路径（C:\Program Files\x\a.dll）绝不能被截成 "C:\Program"：找不到可执行扩展名的分界就判为无法判定。
    /// </summary>
    public static string? ExtractPath(string? raw, bool isCommandLine = true)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = System.Environment.ExpandEnvironmentVariables(raw.Trim());
        // shell 命令里的参数占位符（"%1"、%L、%*、%V）不是环境变量
        s = System.Text.RegularExpressions.Regex.Replace(s, @"%[0-9*lLiIdDvVwW]", "");
        if (s.Contains('%')) return null; // 仍有未解析的变量：无法判定
        if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("::{", StringComparison.Ordinal)) return null;
        s = CommandLine.NormalizeNtPrefix(s, null);

        if (!isCommandLine)
        {
            var p = s.Trim().Trim('"').TrimEnd('\\', '/').Replace('/', '\\');
            return Path.IsPathRooted(p) && p.Length > 3 ? p : null;
        }

        string? exe;
        string? args;
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            if (end < 0) return null;
            exe = s[1..end];
            args = s[(end + 1)..].Trim();
        }
        else
        {
            // 无引号：只接受以可执行扩展名结尾的最短前缀作为程序路径；找不到就无法判定（不能在第一个空格处截断）
            var parts = s.Split(' ');
            exe = null;
            args = null;
            for (var i = 1; i <= parts.Length; i++)
            {
                var cand = string.Join(' ', parts[..i]);
                var candNoComma = cand.Split(',')[0];
                if (ExecutableExtensions.Any(e => candNoComma.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                {
                    exe = candNoComma;
                    args = i < parts.Length ? string.Join(' ', parts[i..]) : (cand.Length > candNoComma.Length ? cand[(candNoComma.Length + 1)..] : null);
                    break;
                }
            }
            if (exe is null) return null;
        }
        exe = exe.Trim().Trim('"').Replace('/', '\\');

        // rundll32 foo.dll,Entry：真正的载荷是 DLL
        var bare = CommandLine.ResolveBareExecutable(exe, FileExists, null);
        if (CommandLine.IsHostProcess(bare))
        {
            var payload = StartupManager.PayloadPath(bare, args);
            if (payload is null || string.Equals(payload, bare, StringComparison.OrdinalIgnoreCase)) return null; // svchost / cmd 之类无法判定
            exe = payload.Trim('"');
        }

        if (!Path.IsPathRooted(exe)) return null;
        // 图标索引写法：C:\x\a.exe,0
        var comma = exe.LastIndexOf(',');
        if (comma > 3 && ExecutableExtensions.Any(e => exe[..comma].EndsWith(e, StringComparison.OrdinalIgnoreCase))) exe = exe[..comma];
        return exe;
    }

    public static FileProbe Probe(string? raw)
    {
        var path = ExtractPath(raw);
        return path is null ? FileProbe.Unknown : ProbePath(path);
    }

    /// <summary>已解析出的绝对路径是否存在。</summary>
    public static FileProbe ProbePath(string path)
    {
        try
        {
            if (!Path.IsPathRooted(path)) return FileProbe.Unknown;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return FileProbe.Unknown; // 网络路径不判定
            var root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root) || !DriveReady(root)) return FileProbe.Unknown;

            if (FileExists(path) || DirectoryExists(path)) return FileProbe.Exists;

            foreach (var alt in RedirectionAlternatives(path))
            {
                if (FileExists(alt) || DirectoryExists(alt)) return FileProbe.Exists;
            }
            // 无扩展名：可能省略了 .exe
            if (!Path.HasExtension(path) && FileExists(path + ".exe")) return FileProbe.Exists;
            return FileProbe.Missing;
        }
        catch
        {
            return FileProbe.Unknown;
        }
    }

    /// <summary>System32 ↔ SysWOW64、Program Files ↔ Program Files (x86)：32 位注册的路径在 64 位进程里可能对不上。</summary>
    internal static IEnumerable<string> RedirectionAlternatives(string path)
    {
        var windir = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);
        var sys32 = Path.Combine(windir, "System32");
        var wow64 = Path.Combine(windir, "SysWOW64");
        if (path.StartsWith(sys32 + "\\", StringComparison.OrdinalIgnoreCase)) yield return wow64 + path[sys32.Length..];
        if (path.StartsWith(wow64 + "\\", StringComparison.OrdinalIgnoreCase)) yield return sys32 + path[wow64.Length..];

        var pf = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles);
        var pf86 = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(pf86) && path.StartsWith(pf + "\\", StringComparison.OrdinalIgnoreCase)) yield return pf86 + path[pf.Length..];
        if (!string.IsNullOrEmpty(pf86) && path.StartsWith(pf86 + "\\", StringComparison.OrdinalIgnoreCase)) yield return pf + path[pf86.Length..];
    }

    private static bool DefaultDriveReady(string root)
    {
        try
        {
            var d = new DriveInfo(root);
            return d.IsReady && d.DriveType == DriveType.Fixed;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>路径是否位于 Windows 目录之下（系统组件缺文件多半是可选功能未安装，不当垃圾）。</summary>
    public static bool IsUnderWindows(string path)
    {
        var windir = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);
        return path.StartsWith(windir + "\\", StringComparison.OrdinalIgnoreCase);
    }
}
