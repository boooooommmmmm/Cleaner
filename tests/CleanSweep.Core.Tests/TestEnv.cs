using System.Diagnostics;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Tests;

/// <summary>在临时目录里搭一套假的系统目录结构，让 PathGuard 的保护路径指向它。</summary>
public sealed class TestEnv : IDisposable
{
    public string Root { get; }
    public CurrentUserEnvironmentResolver Env { get; }
    public PathGuard Guard { get; }
    public IReadOnlyDictionary<string, string> Vars => Env.Variables;

    public TestEnv()
    {
        Root = Path.Combine(Path.GetTempPath(), "CleanSweepTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);

        var windir = Path.Combine(Root, "Windows");
        var profile = Path.Combine(Root, "Users", "me");
        var local = Path.Combine(profile, "AppData", "Local");
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Windir"] = windir,
            ["SystemRoot"] = windir,
            ["SystemDrive"] = Path.GetPathRoot(Root)!.TrimEnd('\\'),
            ["ProgramFiles"] = Path.Combine(Root, "Program Files"),
            ["ProgramFilesX86"] = Path.Combine(Root, "Program Files (x86)"),
            ["UserProfile"] = profile,
            ["AppData"] = Path.Combine(profile, "AppData", "Roaming"),
            ["LocalAppData"] = local,
            ["LocalAppDataLow"] = Path.Combine(profile, "AppData", "LocalLow"),
            ["Temp"] = Path.Combine(local, "Scratch"),
            ["ProgramData"] = Path.Combine(Root, "ProgramData"),
            ["Public"] = Path.Combine(Root, "Users", "Public"),
        };
        foreach (var v in vars.Values.Where(v => v.Length > 3)) Directory.CreateDirectory(v);

        Env = new CurrentUserEnvironmentResolver(vars);
        Guard = new PathGuard(Env);
    }

    public string Dir(string relative)
    {
        var p = Path.Combine(Root, relative);
        Directory.CreateDirectory(p);
        return p;
    }

    public string File(string absoluteOrRelative, string content = "hello")
    {
        var p = Path.IsPathRooted(absoluteOrRelative) ? absoluteOrRelative : Path.Combine(Root, absoluteOrRelative);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        System.IO.File.WriteAllText(p, content);
        return p;
    }

    public string RandomFile(string absoluteOrRelative, int bytes, int seed)
    {
        var p = Path.IsPathRooted(absoluteOrRelative) ? absoluteOrRelative : Path.Combine(Root, absoluteOrRelative);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        var buf = new byte[bytes];
        new Random(seed).NextBytes(buf);
        System.IO.File.WriteAllBytes(p, buf);
        return p;
    }

    /// <summary>创建目录 Junction（无需管理员权限）。返回是否成功。</summary>
    public static bool TryCreateJunction(string link, string target)
    {
        return RunCmd($"mklink /J \"{link}\" \"{target}\"") && PathGuard.IsReparsePoint(link);
    }

    /// <summary>创建硬链接（无需管理员权限）。</summary>
    public static bool TryCreateHardLink(string link, string target)
    {
        return RunCmd($"mklink /H \"{link}\" \"{target}\"") && System.IO.File.Exists(link);
    }

    private static bool RunCmd(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit(10000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        try
        {
            // 先删掉重解析点本身，避免递归删除跟进目标
            foreach (var d in Directory.EnumerateDirectories(Root, "*", SearchOption.AllDirectories).ToList())
            {
                if (PathGuard.IsReparsePoint(d))
                {
                    try { Directory.Delete(d, false); } catch { }
                }
            }
            Directory.Delete(Root, recursive: true);
        }
        catch
        {
            // 测试临时目录清理失败不影响结果
        }
    }
}
