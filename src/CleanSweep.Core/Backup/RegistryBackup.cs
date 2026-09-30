using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Backup;

public sealed record RegistryBackupRecord(
    long Id, DateTime TsUtc, string KeyPath, RegistryView View, string File, string Reason, DateTime? RestoredUtc, string? Sha256 = null, string? ValueName = null);

/// <summary>
/// 注册表自动备份（设计文档 6.1 第 4 条）：每次修改注册表前导出所改的键（或单个值的快照）为 .reg 文件，
/// 索引存 SQLite，保留历史，可一键还原。
///
/// 信任边界：索引与备份文件都可能被有写权限的进程改动，因此
/// 1. 备份文件路径只能由"备份目录 + 文件名"推导，不接受索引里的任意路径，也不接受重解析点；
/// 2. 每个备份旁有元数据 sidecar（键路径、视图、SHA-256），索引、sidecar、文件内容三者必须一致；
/// 3. 还原前校验 .reg 内容只包含当初备份的键，然后把校验过的内容写到一个新临时文件再交给 reg.exe，导入的就是校验过的字节；
/// 4. 淘汰时先删文件再删记录，删不掉就保留记录。
/// </summary>
public sealed class RegistryBackup
{
    public const string MetaSuffix = ".meta.json";

    private sealed record Meta(string KeyPath, int View, string Sha256, string Reason, DateTime TsUtc, string? ValueName);

    private readonly CleanSweepDb _db;

    public RegistryBackup(CleanSweepDb db, string backupDir)
    {
        _db = db;
        BackupDir = PathGuard.Normalize(backupDir);
        Directory.CreateDirectory(BackupDir);
    }

    public string BackupDir { get; }

    // ---------- 备份 ----------

    /// <summary>导出整个键。键不存在时抛出 <see cref="InvalidOperationException"/>。</summary>
    public RegistryBackupRecord Backup(string keyPath, string reason, RegistryView view = RegistryView.Registry64)
    {
        if (!RegistryPath.IsValid(keyPath))
            throw new ArgumentException($"无效的注册表路径：{keyPath}", nameof(keyPath));
        if (!RegistryPath.Exists(keyPath, view))
            throw new InvalidOperationException($"注册表键不存在：{keyPath}");

        var now = DateTime.UtcNow;
        var file = NewFilePath(now, keyPath);

        RunReg($"export \"{keyPath}\" \"{file}\" /y {ViewFlag(view)}");

        if (!System.IO.File.Exists(file) || new FileInfo(file).Length == 0)
            throw new IOException($"导出 {keyPath} 的结果为空");

        return Register(file, keyPath, view, reason, now, valueName: null);
    }

    /// <summary>备份给定键最近的一个存在的祖先（目标键尚未创建时使用）。找不到任何存在的祖先则返回 null。</summary>
    public RegistryBackupRecord? BackupNearestExisting(string keyPath, string reason, RegistryView view = RegistryView.Registry64)
    {
        var existing = RegistryPath.NearestExisting(keyPath, view);
        if (existing is null) return null;
        // 根 hive 本身不导出（体积巨大且无意义）
        if (!existing.Contains('\\')) return null;
        return Backup(existing, reason, view);
    }

    /// <summary>
    /// 操作级备份：只记录一个值修改前的状态。值不存在时记录"删除标记"，还原会删掉本程序随后新建的值；
    /// 键不存在时同样记录删除标记（还原时 reg.exe 会创建空键再删值，留下的空键无害）。
    /// </summary>
    public RegistryBackupRecord BackupValue(string keyPath, string valueName, string reason, RegistryView view = RegistryView.Registry64)
    {
        if (!RegistryPath.TryParse(keyPath, out _, out var sub))
            throw new ArgumentException($"无效的注册表路径：{keyPath}", nameof(keyPath));
        var hiveShort = keyPath.Split('\\')[0];
        if (!HiveLongNames.TryGetValue(hiveShort, out var hive))
            throw new ArgumentException($"无效的注册表路径：{keyPath}", nameof(keyPath));
        if (valueName.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
            throw new ArgumentException("值名含非法字符", nameof(valueName));

        RegistryValueKind? kind;
        object? value;
        using (var key = RegistryPath.Open(keyPath, view, writable: false))
        {
            (kind, value) = RegFile.ReadValue(key, valueName);
        }

        var longKey = sub.Length == 0 ? hive : hive + "\\" + sub;
        var text = RegFile.ValueSnapshot(longKey, valueName, kind, value);

        var now = DateTime.UtcNow;
        var file = NewFilePath(now, keyPath + "@" + (valueName.Length == 0 ? "(默认)" : valueName));
        System.IO.File.WriteAllText(file, text, new UnicodeEncoding(false, true));

        return Register(file, keyPath, view, reason, now, valueName);
    }

    private string NewFilePath(DateTime now, string label) =>
        Path.Combine(BackupDir, $"{now:yyyyMMdd-HHmmss}-{Sanitize(label)}-{Guid.NewGuid().ToString("N")[..6]}.reg");

    private RegistryBackupRecord Register(string file, string keyPath, RegistryView view, string reason, DateTime now, string? valueName)
    {
        var hash = HashFile(file);
        var meta = new Meta(keyPath, view == RegistryView.Registry32 ? 32 : 64, hash, reason, now, valueName);
        System.IO.File.WriteAllText(file + MetaSuffix, JsonSerializer.Serialize(meta));

        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            INSERT INTO registry_backups(ts, key_path, view, file, reason, sha256, value_name) VALUES($ts, $k, $v, $f, $r, $h, $n);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$ts", now.ToString("O"));
        cmd.Parameters.AddWithValue("$k", keyPath);
        cmd.Parameters.AddWithValue("$v", meta.View);
        cmd.Parameters.AddWithValue("$f", file);
        cmd.Parameters.AddWithValue("$r", reason);
        cmd.Parameters.AddWithValue("$h", hash);
        cmd.Parameters.AddWithValue("$n", (object?)valueName ?? DBNull.Value);
        var id = (long)cmd.ExecuteScalar()!;
        return new RegistryBackupRecord(id, now, keyPath, view, file, reason, null, hash, valueName);
    }

    // ---------- 还原 ----------

    /// <summary>用备份文件还原键内容（reg import）。索引、sidecar、文件内容任一不一致都拒绝。</summary>
    public RegistryBackupRecord Restore(long id)
    {
        var rec = Get(id) ?? throw new KeyNotFoundException($"备份 {id} 不存在");

        var bad = ValidateBackupFile(rec, out var full, out var content);
        if (bad is not null) throw new InvalidOperationException(bad);

        var text = DecodeRegText(content);
        bad = ValidateRegFileScope(text, rec.KeyPath);
        if (bad is not null) throw new InvalidOperationException(bad);

        // 把校验过的字节写到新的临时文件再导入：reg.exe 打开的就是校验过的内容，不存在校验与导入之间被替换的窗口
        var temp = Path.Combine(BackupDir, $".import-{Guid.NewGuid():N}.reg");
        try
        {
            using (var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                fs.Write(content, 0, content.Length);
            RunReg($"import \"{temp}\" {ViewFlag(rec.View)}");
        }
        finally
        {
            try { System.IO.File.Delete(temp); } catch { }
        }

        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "UPDATE registry_backups SET restored_at=$t WHERE id=$id";
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
        return rec with { RestoredUtc = DateTime.UtcNow };
    }

    /// <summary>
    /// 备份文件的路径只能是"备份目录 + 文件名"；不能是重解析点；sidecar 的键路径、视图、哈希必须与索引一致；
    /// 文件内容的哈希必须与两者一致。返回 null 表示通过。
    /// </summary>
    internal string? ValidateBackupFile(RegistryBackupRecord rec, out string fullPath, out byte[] content)
    {
        fullPath = "";
        content = Array.Empty<byte>();

        string name;
        try
        {
            name = Path.GetFileName(rec.File);
            if (string.IsNullOrEmpty(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || !name.EndsWith(".reg", StringComparison.OrdinalIgnoreCase))
                return "备份记录的文件名非法";
            fullPath = Path.Combine(BackupDir, name);
            if (!string.Equals(PathGuard.Normalize(rec.File), fullPath, StringComparison.OrdinalIgnoreCase))
                return "备份文件不在备份目录内，拒绝使用";
        }
        catch (Exception ex)
        {
            return $"备份记录的路径无效：{ex.Message}";
        }

        if (BackupDirProblem() is { } dirBad) return dirBad;
        if (!System.IO.File.Exists(fullPath)) return "备份文件已不存在";

        FileInfo fi;
        try
        {
            fi = new FileInfo(fullPath);
            if (PathGuard.IsReparsePoint(fi.Attributes)) return "备份文件是重解析点，拒绝使用";
        }
        catch (Exception ex)
        {
            return $"无法读取备份文件属性：{ex.Message}";
        }

        Meta? meta;
        try
        {
            meta = JsonSerializer.Deserialize<Meta>(System.IO.File.ReadAllText(fullPath + MetaSuffix));
        }
        catch (Exception ex)
        {
            return $"备份元数据缺失或损坏：{ex.Message}";
        }
        if (meta is null) return "备份元数据缺失";

        if (!string.Equals(meta.KeyPath, rec.KeyPath, StringComparison.OrdinalIgnoreCase))
            return "备份元数据与索引记录的键路径不一致，拒绝还原";
        if (meta.View != (rec.View == RegistryView.Registry32 ? 32 : 64))
            return "备份元数据与索引记录的注册表视图不一致，拒绝还原";
        if (rec.Sha256 is not null && !string.Equals(meta.Sha256, rec.Sha256, StringComparison.OrdinalIgnoreCase))
            return "备份元数据与索引记录的哈希不一致，拒绝还原";

        // 读一次、算一次哈希、用同一份字节导入
        try
        {
            using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var ms = new MemoryStream();
            fs.CopyTo(ms);
            content = ms.ToArray();
        }
        catch (Exception ex)
        {
            return $"无法读取备份文件：{ex.Message}";
        }

        var hash = Convert.ToHexString(SHA256.HashData(content));
        if (!string.Equals(hash, meta.Sha256, StringComparison.OrdinalIgnoreCase))
            return "备份文件内容与记录的哈希不一致（文件已被改动），拒绝还原";

        return null;
    }

    private static string DecodeRegText(byte[] content)
    {
        if (content.Length >= 2 && content[0] == 0xFF && content[1] == 0xFE) return Encoding.Unicode.GetString(content, 2, content.Length - 2);
        if (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF) return Encoding.UTF8.GetString(content, 3, content.Length - 3);
        // 无 BOM：reg.exe 导出一律带 BOM，本程序写出也带 BOM；无 BOM 只可能是 ANSI 手工文件
        return Encoding.Default.GetString(content);
    }

    // ---------- 查询 ----------

    public RegistryBackupRecord? Get(long id)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "SELECT id, ts, key_path, view, file, reason, restored_at, sha256, value_name FROM registry_backups WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        return Read(cmd).FirstOrDefault();
    }

    public IReadOnlyList<RegistryBackupRecord> List(int limit = 200)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "SELECT id, ts, key_path, view, file, reason, restored_at, sha256, value_name FROM registry_backups ORDER BY id DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        return Read(cmd);
    }

    // ---------- 迁移 ----------

    /// <summary>
    /// 数据目录整体搬迁后，把索引里仍指向旧备份目录的文件路径改成新目录（只改前缀为旧目录的记录，文件名不变）。返回修改的记录数。
    /// 路径校验（"备份目录 + 文件名"）在还原与淘汰时照常进行，所以这里改错也只会让记录失效，不会指向目录外的文件。
    /// </summary>
    public int RelocateFrom(string oldBackupDir)
    {
        var old = PathGuard.Normalize(oldBackupDir);
        if (string.Equals(old, BackupDir, StringComparison.OrdinalIgnoreCase)) return 0;
        int changed = 0;
        using var lease = _db.Open();
        foreach (var rec in List(int.MaxValue))
        {
            string full;
            try { full = PathGuard.Normalize(rec.File); } catch { continue; }
            if (!string.Equals(Path.GetDirectoryName(full), old, StringComparison.OrdinalIgnoreCase)) continue;
            using var cmd = lease.CreateCommand();
            cmd.CommandText = "UPDATE registry_backups SET file=$f WHERE id=$id";
            cmd.Parameters.AddWithValue("$f", Path.Combine(BackupDir, Path.GetFileName(full)));
            cmd.Parameters.AddWithValue("$id", rec.Id);
            changed += cmd.ExecuteNonQuery();
        }
        return changed;
    }

    // ---------- 淘汰 ----------

    /// <summary>
    /// 删除超过 days 天的备份，但至少保留最近 keepAtLeast 条。只删备份目录内的文件；文件删不掉就保留记录，下次再试。
    /// 返回成功移除的记录数。
    /// </summary>
    public int PurgeOlderThan(int days, int keepAtLeast = 20, DateTime? nowUtc = null)
    {
        // 备份目录或它的任何祖先被换成 Junction 时，"备份目录 + 文件名"会落到别处：什么都不删
        if (BackupDirProblem() is not null) return 0;
        var cutoff = (nowUtc ?? DateTime.UtcNow).AddDays(-days);
        var all = List(int.MaxValue);
        var victims = all.Skip(keepAtLeast).Where(r => r.TsUtc < cutoff).ToList();
        if (victims.Count == 0) return 0;

        int removed = 0;
        using var lease = _db.Open();
        foreach (var v in victims)
        {
            string name;
            string full;
            try
            {
                name = Path.GetFileName(v.File);
                full = Path.Combine(BackupDir, name);
                // 路径不是"备份目录 + 文件名"：这条记录被改过，不碰它指向的文件，只删记录
                if (string.IsNullOrEmpty(name) || !string.Equals(PathGuard.Normalize(v.File), full, StringComparison.OrdinalIgnoreCase))
                {
                    DeleteRecord(lease, v.Id);
                    removed++;
                    continue;
                }
            }
            catch
            {
                DeleteRecord(lease, v.Id);
                removed++;
                continue;
            }

            bool gone;
            try
            {
                if (System.IO.File.Exists(full))
                {
                    var fi = new FileInfo(full);
                    if (PathGuard.IsReparsePoint(fi.Attributes)) continue; // 不删链接目标，也不动记录
                    fi.Attributes = FileAttributes.Normal;
                    fi.Delete();
                }
                gone = !System.IO.File.Exists(full);
            }
            catch
            {
                gone = false;
            }

            if (!gone) continue; // 删不掉：保留记录，界面上仍可见

            try { System.IO.File.Delete(full + MetaSuffix); } catch { }
            DeleteRecord(lease, v.Id);
            removed++;
        }
        return removed;
    }

    /// <summary>备份目录及其到卷根的每一级祖先都不能是重解析点（构造时检查一次不够，目录可能之后被替换）。返回 null 表示可用。</summary>
    internal string? BackupDirProblem()
    {
        try
        {
            if (!Directory.Exists(BackupDir)) return "备份目录不存在";
            var current = BackupDir;
            while (current is not null)
            {
                if (PathGuard.IsReparsePoint(current)) return $"备份目录路径经过重解析点，拒绝使用：{current}";
                current = Path.GetDirectoryName(current);
            }
            return null;
        }
        catch (Exception ex)
        {
            return "无法核对备份目录：" + ex.Message;
        }
    }

    private static void DeleteRecord(CleanSweepDb.Lease lease, long id)
    {
        using var cmd = lease.CreateCommand();
        cmd.CommandText = "DELETE FROM registry_backups WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    private static List<RegistryBackupRecord> Read(Microsoft.Data.Sqlite.SqliteCommand cmd)
    {
        var list = new List<RegistryBackupRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new RegistryBackupRecord(
                r.GetInt64(0),
                DateTime.Parse(r.GetString(1), null, DateTimeStyles.RoundtripKind),
                r.GetString(2),
                r.GetInt64(3) == 32 ? RegistryView.Registry32 : RegistryView.Registry64,
                r.GetString(4),
                r.GetString(5),
                r.IsDBNull(6) ? null : DateTime.Parse(r.GetString(6), null, DateTimeStyles.RoundtripKind),
                r.IsDBNull(7) ? null : r.GetString(7),
                r.IsDBNull(8) ? null : r.GetString(8)));
        }
        return list;
    }

    private static string HashFile(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    private static string ViewFlag(RegistryView view) => view == RegistryView.Registry32 ? "/reg:32" : "/reg:64";

    private static readonly Dictionary<string, string> HiveLongNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["HKLM"] = "HKEY_LOCAL_MACHINE", ["HKEY_LOCAL_MACHINE"] = "HKEY_LOCAL_MACHINE",
        ["HKCU"] = "HKEY_CURRENT_USER", ["HKEY_CURRENT_USER"] = "HKEY_CURRENT_USER",
        ["HKU"] = "HKEY_USERS", ["HKEY_USERS"] = "HKEY_USERS",
        ["HKCR"] = "HKEY_CLASSES_ROOT", ["HKEY_CLASSES_ROOT"] = "HKEY_CLASSES_ROOT",
    };

    /// <summary>
    /// 校验 .reg 文件里的每个 [键] 段都位于 keyPath 之下。返回 null 表示通过，否则为拒绝原因。
    /// 段头形如 [HKEY_CURRENT_USER\Software\...]，删除键的写法为 [-HKEY_...]。
    /// </summary>
    internal static string? ValidateRegFileScope(string content, string keyPath)
    {
        if (!RegistryPath.TryParse(keyPath, out _, out var sub)) return "备份记录的键路径无效";
        var hiveShort = keyPath.Split('\\')[0];
        if (!HiveLongNames.TryGetValue(hiveShort, out var hive)) return "备份记录的键路径无效";
        var expected = sub.Length == 0 ? hive : hive + "\\" + sub;

        var lines = content.Split('\n');
        if (lines.Length == 0 || !lines[0].TrimStart('﻿').StartsWith("Windows Registry Editor", StringComparison.Ordinal))
            return "备份文件不是 reg.exe 导出的格式";

        int sections = 0;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (!line.StartsWith('[')) continue;
            var end = line.IndexOf(']');
            if (end < 0) return $"备份文件段头格式错误：{line}";
            var key = line[1..end].TrimStart('-');
            sections++;
            if (!string.Equals(key, expected, StringComparison.OrdinalIgnoreCase)
                && !key.StartsWith(expected + "\\", StringComparison.OrdinalIgnoreCase))
                return $"备份文件包含备份范围之外的键，拒绝导入：{key}";
        }
        return sections == 0 ? "备份文件不包含任何键" : null;
    }

    private static string Sanitize(string keyPath)
    {
        var name = keyPath.Replace('\\', '_');
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Length > 80 ? name[..80] : name;
    }

    private static void RunReg(string args)
    {
        var regExe = Path.Combine(System.Environment.SystemDirectory, "reg.exe");
        var psi = new ProcessStartInfo(regExe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("无法启动 reg.exe");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(60_000))
        {
            try { p.Kill(); } catch { }
            throw new TimeoutException("reg.exe 超时");
        }
        if (p.ExitCode != 0)
        {
            var msg = (stderr.Result + stdout.Result).Trim();
            throw new InvalidOperationException($"reg.exe {args.Split(' ')[0]} 失败（{p.ExitCode}）：{msg}");
        }
    }
}
