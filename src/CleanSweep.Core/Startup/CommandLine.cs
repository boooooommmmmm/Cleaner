namespace CleanSweep.Core.Startup;

/// <summary>把 Run 值、服务 ImagePath、快捷方式目标之类的命令行拆成可执行文件与参数。</summary>
public static class CommandLine
{
    private static readonly string[] ExecutableExtensions = { ".exe", ".com", ".bat", ".cmd", ".scr" };

    private static readonly HashSet<string> HostProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "rundll32.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "explorer.exe", "conhost.exe", "regsvr32.exe", "svchost.exe",
    };

    public static (string? Exe, string? Args) Split(string? command, Func<string, bool>? fileExists = null, string? systemRoot = null)
    {
        fileExists ??= File.Exists;
        if (string.IsNullOrWhiteSpace(command)) return (null, null);

        var s = System.Environment.ExpandEnvironmentVariables(command.Trim());
        s = NormalizeNtPrefix(s, systemRoot);

        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            if (end < 0) return (ResolveBareExecutable(s.Trim('"'), fileExists, systemRoot), null);
            var exe = s[1..end];
            var args = s[(end + 1)..].Trim();
            return (ResolveBareExecutable(exe, fileExists, systemRoot), args.Length == 0 ? null : args);
        }

        // 无引号：路径可能含空格。优先取实际存在的最长前缀
        var parts = s.Split(' ');
        for (var i = 1; i <= parts.Length; i++)
        {
            var cand = string.Join(' ', parts[..i]);
            if (cand.Length > 3 && fileExists(cand))
                return (cand, Rest(parts, i));
        }

        // 其次取第一个以可执行扩展名结尾的前缀
        for (var i = 1; i <= parts.Length; i++)
        {
            var cand = string.Join(' ', parts[..i]);
            if (ExecutableExtensions.Any(e => cand.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                return (ResolveBareExecutable(cand, fileExists, systemRoot), Rest(parts, i));
        }

        var idx = s.IndexOf(' ');
        var bare = idx < 0 ? s : s[..idx];
        return (ResolveBareExecutable(bare, fileExists, systemRoot), idx < 0 ? null : s[(idx + 1)..].Trim());
    }

    /// <summary>
    /// 不带目录的可执行文件名（rundll32.exe、regsvr32.exe）按系统搜索顺序解析：System32、Windows、PATH。
    /// 解析不到就原样返回，调用方会把它当成"文件不存在"。
    /// </summary>
    internal static string ResolveBareExecutable(string exe, Func<string, bool> fileExists, string? systemRoot)
    {
        if (string.IsNullOrEmpty(exe) || exe.Contains('\\') || exe.Contains('/') || exe.Contains(':')) return exe;
        systemRoot ??= System.Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

        var candidates = new List<string> { Path.Combine(systemRoot, "System32"), systemRoot };
        var path = System.Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(path))
            candidates.AddRange(path.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        var names = Path.HasExtension(exe) ? new[] { exe } : ExecutableExtensions.Select(e => exe + e).ToArray();
        foreach (var dir in candidates)
        {
            foreach (var name in names)
            {
                string full;
                try { full = Path.Combine(dir, name); } catch { continue; }
                if (fileExists(full)) return full;
            }
        }
        return exe;
    }

    private static string? Rest(string[] parts, int from)
    {
        if (from >= parts.Length) return null;
        var r = string.Join(' ', parts[from..]).Trim();
        return r.Length == 0 ? null : r;
    }

    /// <summary>服务 ImagePath 常见的 \??\ 与 \SystemRoot\ 前缀。</summary>
    internal static string NormalizeNtPrefix(string s, string? systemRoot)
    {
        systemRoot ??= System.Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var quoted = s.StartsWith('"');
        var body = quoted ? s[1..] : s;

        if (body.StartsWith(@"\??\", StringComparison.Ordinal)) body = body[4..];
        if (body.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) body = Path.Combine(systemRoot, body[12..]);
        else if (body.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase)) body = Path.Combine(systemRoot, body[11..]);
        else if (body.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) body = Path.Combine(systemRoot, body);

        return quoted ? "\"" + body : body;
    }

    /// <summary>宿主进程：真正的载荷在参数里（rundll32 xxx.dll、svchost -k ...）。</summary>
    public static bool IsHostProcess(string? exe) =>
        exe is not null && HostProcesses.Contains(Path.GetFileName(exe));
}
