using System.Diagnostics;
using System.Text;

namespace CleanSweep.Core.Safety;

public sealed record CommandResult(int ExitCode, string Output, TimeSpan Elapsed, bool TimedOut)
{
    public bool Success => ExitCode == 0 && !TimedOut;
}

/// <summary>
/// 系统命令的统一执行器。只运行 System32 下的可执行文件，参数由各模块的固定操作表生成（调用方负责校验），
/// 不走 shell、不拼接用户输入。命令启动后不强杀，只在超过上限时终止。
/// </summary>
public static class SystemCommand
{
    public static string System32(string exeName)
    {
        if (string.IsNullOrWhiteSpace(exeName) || exeName.IndexOfAny(new[] { '\\', '/', ':', ' ', '"' }) >= 0)
            throw new ArgumentException("命令名只能是文件名", nameof(exeName));
        return Path.Combine(System.Environment.SystemDirectory, exeName);
    }

    public static async Task<CommandResult> RunAsync(string exeName, string args, TimeSpan timeout, CancellationToken ct = default, IProgress<string>? output = null)
    {
        var exe = System32(exeName);
        if (!File.Exists(exe)) return new CommandResult(-1, $"系统命令不存在：{exe}", TimeSpan.Zero, false);

        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = OutputEncoding(),
            StandardErrorEncoding = OutputEncoding(),
        };
        var sw = Stopwatch.StartNew();
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("进程未启动");
        var sb = new StringBuilder();
        var lock_ = new object();
        void OnLine(object sender, DataReceivedEventArgs e)
        {
            if (e.Data is null) return;
            lock (lock_) sb.AppendLine(e.Data);
            output?.Report(e.Data);
        }
        p.OutputDataReceived += OnLine;
        p.ErrorDataReceived += OnLine;
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
        bool timedOut = false;
        try
        {
            await p.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (timeoutCts.IsCancellationRequested)
            {
                timedOut = true;
                try { p.Kill(entireProcessTree: true); } catch { }
            }
            else
            {
                // 用户取消：不强杀系统命令，等它自己结束；但总时限仍然有效，超过上限照样视为卡死终止
                try
                {
                    await p.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    timedOut = true;
                    try { p.Kill(entireProcessTree: true); } catch { }
                }
            }
        }
        p.WaitForExit();
        string text;
        lock (lock_) text = sb.ToString();
        return new CommandResult(timedOut ? -2 : p.ExitCode, text.Trim(), sw.Elapsed, timedOut);
    }

    /// <summary>控制台程序（defrag、chkntfs、powercfg）用 OEM 代码页输出。</summary>
    private static Encoding OutputEncoding()
    {
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(GetOEMCP());
        }
        catch
        {
            return Encoding.Default;
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern int GetOEMCP();
}
