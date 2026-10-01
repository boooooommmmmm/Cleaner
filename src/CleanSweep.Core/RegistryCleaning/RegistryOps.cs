using System.Runtime.InteropServices;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using Microsoft.Win32;

namespace CleanSweep.Core.RegistryCleaning;

/// <summary>
/// 注册表 / 服务 / 计划任务的删除执行器：先经 <see cref="RegistryGuard"/>，再做备份（值级 .reg、整键导出、任务 XML），再删。
/// 已消失的目标由引擎单独统计，其余失败保留在列表中。
/// </summary>
public sealed class RegistryOps
{
    private readonly RegistryBackup _backup;

    public RegistryOps(RegistryBackup backup)
    {
        _backup = backup;
    }

    public string TaskBackupDir => Path.Combine(_backup.BackupDir, "tasks");

    /// <summary>快照必须一致；删除依据（扫描时缺失的程序）重新出现即拒绝。</summary>
    private static void Require(string? expectedSnapshot, string? currentSnapshot, string? missingPath)
    {
        if (RegistrySnapshot.Check(expectedSnapshot, currentSnapshot) is { } bad) throw new InvalidOperationException(bad);
        if (missingPath is not null && RegistryProbe.ProbePath(missingPath) != FileProbe.Missing)
            throw new InvalidOperationException($"删除依据已不成立：{missingPath} 现在存在（软件可能已重新安装或修复），请重新扫描");
    }

    /// <summary>删除值。返回备份文件名。expectedSnapshot 为扫描时快照，不一致即拒绝。</summary>
    public string DeleteValue(RegistryTarget t, string reason, string? expectedSnapshot = null, string? missingPath = null)
    {
        if (t.ValueName is null) throw new ArgumentException("缺少值名");
        var bad = RegistryGuard.CheckDeleteValue(t.KeyPath, t.View, t.ValueName);
        if (bad is not null) throw new InvalidOperationException("注册表护栏拒绝：" + bad);
        // 枚举值名确认缺失，不能把读取值内容失败误报为“已不存在”。
        using (var existing = RegistryPath.Open(t.KeyPath, t.View, writable: false))
        {
            if (existing is null || !existing.GetValueNames().Contains(t.ValueName, StringComparer.OrdinalIgnoreCase))
                throw new RegistryTargetMissingException();
        }
        Require(expectedSnapshot, RegistrySnapshot.OfValue(t.KeyPath, t.View, t.ValueName), missingPath);

        var rec = BeforeDeleteBackup(() => _backup.BackupValue(t.KeyPath, t.ValueName, reason, t.View));
        using var k = RegistryPath.Open(t.KeyPath, t.View, writable: true) ?? throw new InvalidOperationException("键已不存在");
        k.DeleteValue(t.ValueName, throwOnMissingValue: false);
        return Path.GetFileName(rec.File);
    }

    /// <summary>删除键及子树。返回备份文件名。</summary>
    public string DeleteKey(RegistryTarget t, string reason, string? expectedSnapshot = null, string? missingPath = null)
    {
        var bad = RegistryGuard.CheckDeleteKey(t.KeyPath, t.View);
        if (bad is not null) throw new InvalidOperationException("注册表护栏拒绝：" + bad);
        var current = RegistrySnapshot.OfKey(t.KeyPath, t.View);
        if (current == RegistrySnapshot.Missing) throw new RegistryTargetMissingException();
        Require(expectedSnapshot, current, missingPath);

        var rec = BeforeDeleteBackup(() => _backup.Backup(t.KeyPath, reason, t.View));
        var parent = RegistryPath.Parent(t.KeyPath);
        var name = t.KeyPath[(t.KeyPath.LastIndexOf('\\') + 1)..];
        using var p = RegistryPath.Open(parent, t.View, writable: true) ?? throw new InvalidOperationException("父键已不存在");
        p.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
        return Path.GetFileName(rec.File);
    }

    private static RegistryBackupRecord BeforeDeleteBackup(Func<RegistryBackupRecord> backup)
    {
        try { return backup(); }
        catch (Exception ex)
        {
            throw new InvalidOperationException("备份阶段失败，未执行删除：" + ex.Message, ex);
        }
    }

    // ---------- 服务 ----------

    private const string ServicesKey = @"HKLM\SYSTEM\CurrentControlSet\Services";
    private const uint ScManagerConnect = 0x0001;
    private const uint DeleteAccess = 0x00010000;
    private const uint ServiceQueryConfig = 0x0001;

    /// <summary>删除服务：先导出服务键，再 DeleteService。只允许用户态服务（Type 0x10 / 0x20），驱动一律拒绝。</summary>
    public string DeleteService(string serviceName, string reason, string? expectedSnapshot = null, string? missingPath = null)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.IndexOfAny(new[] { '\\', '/', '"' }) >= 0) throw new ArgumentException("服务名非法");
        var keyPath = RegistryPath.Combine(ServicesKey, serviceName);
        Require(expectedSnapshot, RegistrySnapshot.OfServiceKey(keyPath), missingPath);
        using (var k = RegistryPath.Open(keyPath, RegistryView.Registry64, writable: false) ?? throw new InvalidOperationException("服务不存在"))
        {
            var type = k.GetValue("Type") as int? ?? 0;
            if ((type & 0x30) == 0) throw new InvalidOperationException("只允许删除用户态服务，驱动与内核服务拒绝");
            var start = k.GetValue("Start") as int? ?? 0;
            if (start is 0 or 1) throw new InvalidOperationException("启动类型为 Boot / System 的服务拒绝删除");
        }

        var rec = _backup.Backup(keyPath, reason);

        var scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "无法连接服务控制管理器");
        try
        {
            var svc = OpenServiceW(scm, serviceName, DeleteAccess | ServiceQueryConfig);
            if (svc == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"无法打开服务 {serviceName}");
            try
            {
                if (!DeleteServiceNative(svc)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"删除服务 {serviceName} 失败");
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
        return Path.GetFileName(rec.File);
    }

    // ---------- 计划任务 ----------

    /// <summary>删除计划任务：先把任务定义 XML 写到备份目录，再删除。微软的任务（\Microsoft\ 下）拒绝。</summary>
    public string DeleteScheduledTask(string taskPath, string reason, string? expectedSnapshot = null, string? missingPath = null)
    {
        if (string.IsNullOrWhiteSpace(taskPath) || !taskPath.StartsWith('\\')) throw new ArgumentException("任务路径非法");
        if (taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("不允许删除 Microsoft 的计划任务");

        var t = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("任务计划程序服务不可用");
        dynamic svc = Activator.CreateInstance(t)!;
        svc.Connect();
        var folderPath = taskPath[..taskPath.LastIndexOf('\\')];
        if (folderPath.Length == 0) folderPath = "\\";
        var name = taskPath[(taskPath.LastIndexOf('\\') + 1)..];
        dynamic folder = svc.GetFolder(folderPath);
        dynamic task = folder.GetTask(name);
        string xml = task.Xml;
        Require(expectedSnapshot, RegistrySnapshot.OfTaskXml(xml), missingPath);

        var file = WriteTaskBackup(taskPath, xml, reason);
        folder.DeleteTask(name, 0);
        return Path.GetFileName(file);
    }

    /// <summary>计划任务备份的元数据（sidecar），与注册表备份一样带 SHA-256，恢复时三者一致才导入。</summary>
    public sealed record TaskBackupRecord(string FileName, string TaskPath, string Reason, DateTime TsUtc, string Sha256, DateTime? RestoredUtc);

    private sealed record TaskMeta(string TaskPath, string Reason, DateTime Ts, string? Sha256, DateTime? RestoredUtc);

    internal string WriteTaskBackup(string taskPath, string xml, string reason)
    {
        Directory.CreateDirectory(TaskBackupDir);
        var file = Path.Combine(TaskBackupDir, $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Sanitize(taskPath)}-{Guid.NewGuid().ToString("N")[..6]}.xml");
        var bytes = new System.Text.UTF8Encoding(false).GetBytes(xml);
        File.WriteAllBytes(file, bytes);
        var meta = new TaskMeta(taskPath, reason, DateTime.UtcNow, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)), null);
        File.WriteAllText(file + RegistryBackup.MetaSuffix, System.Text.Json.JsonSerializer.Serialize(meta));
        return file;
    }

    /// <summary>列出计划任务备份（只认备份目录里带合法 sidecar 的文件）。</summary>
    public IReadOnlyList<TaskBackupRecord> ListTaskBackups()
    {
        var list = new List<TaskBackupRecord>();
        if (!Directory.Exists(TaskBackupDir)) return list;
        foreach (var file in Directory.EnumerateFiles(TaskBackupDir, "*.xml"))
        {
            try
            {
                var meta = System.Text.Json.JsonSerializer.Deserialize<TaskMeta>(File.ReadAllText(file + RegistryBackup.MetaSuffix));
                if (meta is null || meta.Sha256 is null || string.IsNullOrWhiteSpace(meta.TaskPath)) continue;
                list.Add(new TaskBackupRecord(Path.GetFileName(file), meta.TaskPath, meta.Reason, meta.Ts, meta.Sha256, meta.RestoredUtc));
            }
            catch { }
        }
        return list.OrderByDescending(r => r.TsUtc).ToList();
    }

    /// <summary>
    /// 用备份重新注册计划任务。文件只能按"备份目录 + 文件名"定位；内容哈希必须与 sidecar 一致；
    /// 任务路径取自 sidecar（不接受调用方指定），Microsoft 下的拒绝；登录类型按 XML 里的 LogonType 映射，需要密码的任务无法自动恢复。
    /// </summary>
    public string RestoreScheduledTask(string fileName)
    {
        var name = Path.GetFileName(fileName);
        if (string.IsNullOrEmpty(name) || name != fileName || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || !name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("备份文件名非法");
        var full = Path.Combine(TaskBackupDir, name);
        if (!File.Exists(full)) throw new FileNotFoundException("备份文件已不存在", full);
        if (PathGuard.IsReparsePoint(TaskBackupDir) || PathGuard.IsReparsePoint(new FileInfo(full).Attributes)) throw new InvalidOperationException("备份目录或文件是重解析点，拒绝使用");

        var meta = System.Text.Json.JsonSerializer.Deserialize<TaskMeta>(File.ReadAllText(full + RegistryBackup.MetaSuffix)) ?? throw new InvalidOperationException("备份元数据缺失");
        if (meta.Sha256 is null || string.IsNullOrWhiteSpace(meta.TaskPath) || !meta.TaskPath.StartsWith('\\')) throw new InvalidOperationException("备份元数据不完整");
        if (meta.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("不恢复 Microsoft 下的任务");

        var bytes = File.ReadAllBytes(full);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        if (!string.Equals(hash, meta.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("备份文件内容与记录的哈希不一致（文件已被改动），拒绝恢复");
        var xml = System.Text.Encoding.UTF8.GetString(bytes);

        var doc = new System.Xml.XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        if (doc.DocumentElement?.LocalName != "Task") throw new InvalidOperationException("备份不是任务定义 XML");
        var logonType = TaskLogonType(doc);
        if (logonType is null) throw new InvalidOperationException("该任务以密码登录方式运行，无法自动恢复；可在任务计划程序里用备份目录中的 XML 手动导入");

        var t = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("任务计划程序服务不可用");
        dynamic svc = Activator.CreateInstance(t)!;
        svc.Connect();
        var folderPath = meta.TaskPath[..meta.TaskPath.LastIndexOf('\\')];
        if (folderPath.Length == 0) folderPath = "\\";
        var taskName = meta.TaskPath[(meta.TaskPath.LastIndexOf('\\') + 1)..];
        dynamic folder;
        try { folder = svc.GetFolder(folderPath); }
        catch
        {
            dynamic root = svc.GetFolder("\\");
            folder = root.CreateFolder(folderPath.TrimStart('\\'), null);
        }
        const int TaskCreate = 2;
        folder.RegisterTask(taskName, xml, TaskCreate, null, null, logonType.Value, null);

        File.WriteAllText(full + RegistryBackup.MetaSuffix, System.Text.Json.JsonSerializer.Serialize(meta with { RestoredUtc = DateTime.UtcNow }));
        return meta.TaskPath;
    }

    /// <summary>XML 的 Principals/Principal/LogonType → TASK_LOGON_TYPE。Password 类型返回 null（需要密码）。</summary>
    internal static int? TaskLogonType(System.Xml.XmlDocument doc)
    {
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("t", doc.DocumentElement!.NamespaceURI);
        var node = doc.SelectSingleNode("/t:Task/t:Principals/t:Principal/t:LogonType", ns);
        var text = node?.InnerText?.Trim() ?? "InteractiveToken";
        return text switch
        {
            "InteractiveToken" => 3,
            "S4U" => 2,
            "ServiceAccount" => 5,
            "Group" => 4,
            "InteractiveTokenOrPassword" => 6,
            "None" => 0,
            _ => null, // Password
        };
    }

    private static string Sanitize(string s)
    {
        var name = s.Trim('\\').Replace('\\', '_');
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Length > 80 ? name[..80] : name;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "DeleteService", SetLastError = true)]
    private static extern bool DeleteServiceNative(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
