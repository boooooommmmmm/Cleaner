using CleanSweep.Core.Backup;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

public class RestorePointPolicyTests
{
    private static readonly DateTime Now = new(2026, 9, 28, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void No_previous_point_never_skips()
    {
        Assert.False(RestorePointService.ShouldSkip(null, 1440, Now));
    }

    [Fact]
    public void Recent_point_within_frequency_skips()
    {
        Assert.True(RestorePointService.ShouldSkip(Now.AddHours(-2), 1440, Now));
    }

    [Fact]
    public void Old_point_does_not_skip()
    {
        Assert.False(RestorePointService.ShouldSkip(Now.AddHours(-25), 1440, Now));
    }

    [Fact]
    public void Zero_frequency_means_unlimited()
    {
        Assert.False(RestorePointService.ShouldSkip(Now.AddMinutes(-1), 0, Now));
    }

    [Fact]
    public void Future_timestamp_does_not_skip()
    {
        Assert.False(RestorePointService.ShouldSkip(Now.AddHours(1), 1440, Now));
    }

    [Fact]
    public void Parses_wmi_datetime()
    {
        Assert.Equal(new DateTime(2026, 9, 28, 10, 15, 0, DateTimeKind.Utc), RestorePointService.ParseWmiDateTime("20260928101500.000000-000"));
        // +480 分钟 = 东八区，转为 UTC 要减 8 小时
        Assert.Equal(new DateTime(2026, 9, 28, 2, 15, 0, DateTimeKind.Utc), RestorePointService.ParseWmiDateTime("20260928101500.000000+480"));
        Assert.Equal(new DateTime(2026, 9, 28, 10, 15, 0, DateTimeKind.Utc), RestorePointService.ParseWmiDateTime("20260928101500.000000***"));
        Assert.Equal(new DateTime(2026, 9, 28, 10, 15, 0, 500, DateTimeKind.Utc), RestorePointService.ParseWmiDateTime("20260928101500.500000-000"));
        Assert.Null(RestorePointService.ParseWmiDateTime("garbage"));
        Assert.Null(RestorePointService.ParseWmiDateTime(null));
    }
}

public class RegistryPathTests
{
    [Fact]
    public void Parses_hive_prefixes()
    {
        Assert.True(RegistryPath.TryParse(@"HKCU\Software\Foo", out var hive, out var sub));
        Assert.Equal(RegistryHive.CurrentUser, hive);
        Assert.Equal(@"Software\Foo", sub);

        Assert.True(RegistryPath.TryParse(@"HKEY_LOCAL_MACHINE\SYSTEM", out hive, out sub));
        Assert.Equal(RegistryHive.LocalMachine, hive);
        Assert.Equal("SYSTEM", sub);
    }

    [Fact]
    public void Rejects_unknown_hive_and_dangerous_characters()
    {
        Assert.False(RegistryPath.IsValid(@"HKXX\Software"));
        Assert.False(RegistryPath.IsValid("HKCU\\Software\" /y \"C:\\evil"));
        Assert.False(RegistryPath.IsValid("HKCU\\Software\nHKLM"));
        Assert.False(RegistryPath.IsValid(""));
    }

    [Fact]
    public void Nearest_existing_walks_up()
    {
        var existing = RegistryPath.NearestExisting(@"HKCU\Software\Microsoft\Windows\CurrentVersion\DoesNotExist-" + Guid.NewGuid().ToString("N"), RegistryView.Registry64);
        Assert.Equal(@"HKCU\Software\Microsoft\Windows\CurrentVersion", existing);
    }
}

/// <summary>在 HKCU\Software\CleanSweepTests 下建临时键，用真实 reg.exe 验证导出与还原。</summary>
public class RegistryBackupTests : IDisposable
{
    private const string TestRoot = @"Software\CleanSweepTests";
    private readonly string _keyName = Guid.NewGuid().ToString("N");
    private readonly string _keyPath;
    private readonly string _dir;
    private readonly CleanSweepDb _db;
    private readonly RegistryBackup _backup;

    public RegistryBackupTests()
    {
        _keyPath = $@"HKCU\{TestRoot}\{_keyName}";
        _dir = Path.Combine(Path.GetTempPath(), "CleanSweepTests", "regbackup-" + _keyName);
        _db = CleanSweepDb.InMemory();
        _backup = new RegistryBackup(_db, _dir);

        using var k = Registry.CurrentUser.CreateSubKey($@"{TestRoot}\{_keyName}");
        k.SetValue("Alpha", "one");
        k.SetValue("Beta", 2, RegistryValueKind.DWord);
        k.SetValue("Gamma", new byte[] { 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree($@"{TestRoot}\{_keyName}", false); } catch { }
        try { using var r = Registry.CurrentUser.OpenSubKey(TestRoot); if (r is not null && r.SubKeyCount == 0) Registry.CurrentUser.DeleteSubKey(TestRoot, false); } catch { }
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Backup_exports_reg_file_and_indexes_it()
    {
        var rec = _backup.Backup(_keyPath, "单元测试");

        Assert.True(File.Exists(rec.File));
        Assert.StartsWith(_dir, rec.File, StringComparison.OrdinalIgnoreCase);
        var text = File.ReadAllText(rec.File);
        Assert.Contains("Windows Registry Editor", text);
        Assert.Contains("\"Alpha\"=\"one\"", text);

        var listed = _backup.List();
        Assert.Contains(listed, r => r.Id == rec.Id && r.KeyPath == _keyPath && r.Reason == "单元测试" && r.RestoredUtc is null);
    }

    [Fact]
    public void Restore_brings_back_modified_and_deleted_values()
    {
        var rec = _backup.Backup(_keyPath, "还原测试");

        using (var k = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}", writable: true)!)
        {
            k.SetValue("Alpha", "CHANGED");
            k.DeleteValue("Beta");
            k.SetValue("Delta", "new");
        }

        var restored = _backup.Restore(rec.Id);
        Assert.NotNull(restored.RestoredUtc);

        using var after = Registry.CurrentUser.OpenSubKey($@"{TestRoot}\{_keyName}")!;
        Assert.Equal("one", after.GetValue("Alpha"));
        Assert.Equal(2, after.GetValue("Beta"));
        Assert.Equal(new byte[] { 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, after.GetValue("Gamma"));
        // reg import 是合并语义：备份后新增的值保留
        Assert.Equal("new", after.GetValue("Delta"));

        Assert.NotNull(_backup.Get(rec.Id)!.RestoredUtc);
    }

    [Fact]
    public void Backup_of_missing_key_throws()
    {
        Assert.Throws<InvalidOperationException>(() => _backup.Backup(_keyPath + @"\Nope", "x"));
    }

    [Fact]
    public void Invalid_key_path_is_rejected_before_touching_reg_exe()
    {
        Assert.Throws<ArgumentException>(() => _backup.Backup("HKCU\\Software\" \"C:\\evil.reg", "x"));
        Assert.Throws<ArgumentException>(() => _backup.Backup(@"HKXX\Software", "x"));
    }

    [Fact]
    public void Nearest_existing_backs_up_parent_when_child_missing()
    {
        var rec = _backup.BackupNearestExisting(_keyPath + @"\Child\Grandchild", "祖先");
        Assert.NotNull(rec);
        Assert.Equal(_keyPath, rec!.KeyPath);
    }

    [Fact]
    public void Restore_refuses_tampered_file_targeting_other_keys()
    {
        var rec = _backup.Backup(_keyPath, "篡改");
        var text = File.ReadAllText(rec.File);
        // 攻击者把备份内容改成写 HKLM Run 键
        var tampered = text + "\r\n[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n\"evil\"=\"C:\\\\evil.exe\"\r\n";
        File.WriteAllText(rec.File, tampered, System.Text.Encoding.Unicode);

        // 文件被改动：先撞上哈希核对（内容与 sidecar / 索引不一致），即使绕过哈希也会被范围校验拦住
        var ex = Assert.Throws<InvalidOperationException>(() => _backup.Restore(rec.Id));
        Assert.Contains("拒绝", ex.Message);
    }

    [Fact]
    public void Reg_file_scope_validation()
    {
        const string ok = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Foo]\r\n\"a\"=\"1\"\r\n\r\n[HKEY_CURRENT_USER\\Software\\Foo\\Sub]\r\n";
        Assert.Null(RegistryBackup.ValidateRegFileScope(ok, @"HKCU\Software\Foo"));
        Assert.NotNull(RegistryBackup.ValidateRegFileScope(ok, @"HKCU\Software\Foo\Sub"));
        Assert.NotNull(RegistryBackup.ValidateRegFileScope(ok.Replace("HKEY_CURRENT_USER\\Software\\Foo\\Sub", "HKEY_LOCAL_MACHINE\\SYSTEM"), @"HKCU\Software\Foo"));
        Assert.NotNull(RegistryBackup.ValidateRegFileScope("[HKEY_CURRENT_USER\\Software\\Foo]", @"HKCU\Software\Foo"));
        Assert.NotNull(RegistryBackup.ValidateRegFileScope("Windows Registry Editor Version 5.00\r\n", @"HKCU\Software\Foo"));
        // 前缀相同但不是子键（Foo 与 Foobar）
        Assert.NotNull(RegistryBackup.ValidateRegFileScope(ok.Replace("Foo\\Sub", "Foobar"), @"HKCU\Software\Foo"));
    }

    [Fact]
    public void Restore_unknown_id_throws()
    {
        Assert.Throws<KeyNotFoundException>(() => _backup.Restore(999_999));
    }

    [Fact]
    public void Restore_refuses_file_outside_backup_dir()
    {
        var rec = _backup.Backup(_keyPath, "越界");
        var outside = Path.Combine(Path.GetTempPath(), "CleanSweepTests", "outside-" + _keyName + ".reg");
        File.Copy(rec.File, outside);
        try
        {
            using (var lease = _db.Open())
            using (var cmd = lease.CreateCommand())
            {
                cmd.CommandText = "UPDATE registry_backups SET file=$f WHERE id=$id";
                cmd.Parameters.AddWithValue("$f", outside);
                cmd.Parameters.AddWithValue("$id", rec.Id);
                cmd.ExecuteNonQuery();
            }
            Assert.Throws<InvalidOperationException>(() => _backup.Restore(rec.Id));
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public void Purge_keeps_recent_and_minimum_count()
    {
        var a = _backup.Backup(_keyPath, "1");
        var b = _backup.Backup(_keyPath, "2");
        var c = _backup.Backup(_keyPath, "3");

        // 全部都"很旧"，但至少保留 2 条 → 只删最老的 1 条
        var removed = _backup.PurgeOlderThan(days: 1, keepAtLeast: 2, nowUtc: DateTime.UtcNow.AddYears(1));
        Assert.Equal(1, removed);
        Assert.False(File.Exists(a.File));
        Assert.True(File.Exists(b.File));
        Assert.True(File.Exists(c.File));
        Assert.Null(_backup.Get(a.Id));

        // 没有过期的 → 不删
        Assert.Equal(0, _backup.PurgeOlderThan(days: 1, keepAtLeast: 0, nowUtc: DateTime.UtcNow));
    }
}
