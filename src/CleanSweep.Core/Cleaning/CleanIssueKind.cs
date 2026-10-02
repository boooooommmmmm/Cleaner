using System.ComponentModel;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Cleaning;

public enum CleanIssueKind
{
    Failure, InUse, Permission, Changed, BackupFailed, Excluded, AlreadyAbsent, NotProcessed,
}

/// <summary>按异常类型和原生错误码分类，不从本地化错误文本猜测原因。</summary>
public static class CleanIssueClassifier
{
    public static CleanIssueKind FromException(Exception ex) => ex switch
    {
        CleanBackupException => CleanIssueKind.BackupFailed,
        CleanTargetChangedException => CleanIssueKind.Changed,
        _ when AccessDenied.Is(ex) || ex is Win32Exception { NativeErrorCode: 5 or 1314 }
            => CleanIssueKind.Permission,
        _ when FileInUse.Is(ex) => CleanIssueKind.InUse,
        _ => CleanIssueKind.Failure,
    };
}

public sealed class CleanBackupException(string message, Exception inner) : InvalidOperationException(message, inner);
public sealed class CleanTargetChangedException(string message) : InvalidOperationException(message);

/// <summary>保留取消之前已得到的结果，仍兼容 OperationCanceledException 调用方。</summary>
public sealed class CleanCancelledException(CleanReport report, CancellationToken token) : OperationCanceledException(token)
{
    public CleanReport Report { get; } = report;
}
