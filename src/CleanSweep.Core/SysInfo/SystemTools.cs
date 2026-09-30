using System.Diagnostics;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.SysInfo;

/// <summary>系统自带工具的启动方式：System32 下的可执行文件、mmc 管理单元（.msc）或系统设置 URI。</summary>
public enum ToolLaunch
{
    Exe,
    Msc,
    SettingsUri,
}

/// <param name="Target">Exe / Msc 时是 System32 下的文件名；SettingsUri 时是 ms-settings: 或 windowsdefender: 一类的 URI。</param>
/// <param name="NeedsAdmin">工具自己带 requireAdministrator 清单，启动时系统会弹 UAC。</param>
/// <param name="Restarts">运行后需要重启电脑才会真正执行（内存诊断）。</param>
public sealed record SystemTool(string Id, string Title, string Description, ToolLaunch Launch, string Target, string Args = "", bool NeedsAdmin = false, bool Restarts = false);

/// <summary>
/// "系统工具"入口（参考常见工具箱软件的做法，但只调用 Windows 自带程序，不内置第三方工具）。
/// 固定表：目标一律是 System32 下的文件名或 ms-settings URI，不接受用户输入，不走 cmd。
/// </summary>
public static class SystemTools
{
    public static readonly IReadOnlyList<SystemTool> All = new[]
    {
        new SystemTool("mdsched", "Windows 内存诊断", "检测内存条坏道 / 错误。选择后需要重启，重启时自动跑完整测试，结果记录在系统日志（本页“上次内存诊断”会显示）。", ToolLaunch.Exe, "mdsched.exe", NeedsAdmin: true, Restarts: true),
        new SystemTool("resmon", "资源监视器", "按进程查看 CPU、内存、磁盘、网络的实时占用，找出谁在读写磁盘。", ToolLaunch.Exe, "resmon.exe"),
        new SystemTool("taskmgr", "任务管理器", "进程、性能、启动项、服务。", ToolLaunch.Exe, "taskmgr.exe"),
        new SystemTool("perfmon-rel", "可靠性历史记录", "按天查看应用崩溃、系统错误与更新记录，排查“最近为什么变卡 / 蓝屏”。", ToolLaunch.Exe, "perfmon.exe", "/rel"),
        new SystemTool("eventvwr", "事件查看器", "系统与应用日志。", ToolLaunch.Msc, "eventvwr.msc"),
        new SystemTool("devmgmt", "设备管理器", "查看设备与驱动状态、带感叹号的问题设备。", ToolLaunch.Msc, "devmgmt.msc"),
        new SystemTool("diskmgmt", "磁盘管理", "分区、卷标、盘符。", ToolLaunch.Msc, "diskmgmt.msc"),
        new SystemTool("msinfo32", "系统信息（msinfo32）", "Windows 自带的完整硬件与软件环境报告，可导出。", ToolLaunch.Exe, "msinfo32.exe"),
        new SystemTool("dxdiag", "DirectX 诊断工具", "显卡、显示器、声音设备与 DirectX 状态。", ToolLaunch.Exe, "dxdiag.exe"),
        new SystemTool("msconfig", "系统配置（msconfig）", "启动模式、服务、引导选项。", ToolLaunch.Exe, "msconfig.exe", NeedsAdmin: true),
        new SystemTool("winver", "关于 Windows", "版本与内部版本号。", ToolLaunch.Exe, "winver.exe"),
        new SystemTool("storage", "存储设置", "系统的存储感知与各盘占用分类（系统设置）。", ToolLaunch.SettingsUri, "ms-settings:storagesense"),
        new SystemTool("windowsupdate", "Windows 更新", "检查与安装系统更新（系统设置）。", ToolLaunch.SettingsUri, "ms-settings:windowsupdate"),
        new SystemTool("defender", "Windows 安全中心", "病毒防护、防火墙与设备健康。", ToolLaunch.SettingsUri, "windowsdefender:"),
    };

    public static SystemTool? Find(string id) => All.FirstOrDefault(t => t.Id == id);

    /// <summary>构造启动信息；文件不存在时返回 null 并给出原因。</summary>
    public static ProcessStartInfo? Build(SystemTool tool, out string? error)
    {
        error = null;
        switch (tool.Launch)
        {
            case ToolLaunch.Exe:
            {
                var exe = SystemCommand.System32(tool.Target);
                if (!File.Exists(exe))
                {
                    error = $"此版本的 Windows 没有 {tool.Target}。";
                    return null;
                }
                return new ProcessStartInfo(exe, tool.Args) { UseShellExecute = true };
            }
            case ToolLaunch.Msc:
            {
                var msc = SystemCommand.System32(tool.Target);
                if (!File.Exists(msc))
                {
                    error = $"此版本的 Windows 没有 {tool.Target}。";
                    return null;
                }
                // 管理单元由 mmc.exe 承载；直接 ShellExecute .msc 也可以，但显式指定 mmc 不依赖文件关联
                return new ProcessStartInfo(SystemCommand.System32("mmc.exe"), $"\"{msc}\"") { UseShellExecute = true };
            }
            case ToolLaunch.SettingsUri:
                if (!IsAllowedUri(tool.Target))
                {
                    error = "不支持的设置地址。";
                    return null;
                }
                return new ProcessStartInfo(tool.Target) { UseShellExecute = true };
            default:
                error = "未知的启动方式。";
                return null;
        }
    }

    /// <summary>只允许系统设置协议，防止表里误写成 http 之类会打开浏览器的地址。</summary>
    internal static bool IsAllowedUri(string uri) =>
        uri.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) || uri.Equals("windowsdefender:", StringComparison.OrdinalIgnoreCase);

    /// <summary>启动工具。返回错误说明，成功为 null。</summary>
    public static string? Launch(SystemTool tool)
    {
        var psi = Build(tool, out var error);
        if (psi is null) return error;
        try
        {
            using var p = Process.Start(psi);
            return null;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "已取消（未通过管理员确认）。";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
