using CleanSweep.Core.Backup;
using CleanSweep.Core.Drivers;
using CleanSweep.Core.Popup;
using CleanSweep.Core.Repair;
using CleanSweep.Core.Storage;
using CleanSweep.Core.SysInfo;

namespace CleanSweep.Core.Tests;

public sealed class DriverStoreTests
{
    private const string EnglishOutput = """
        Microsoft PnP Utility

        Published Name:     oem12.inf
        Original Name:      nvlddmkm.inf
        Provider Name:      NVIDIA
        Class Name:         Display adapters
        Class GUID:         {4d36e968-e325-11ce-bfc1-08002be10318}
        Driver Version:     05/12/2025 32.0.15.7602
        Signer Name:        Microsoft Windows Hardware Compatibility Publisher

        Published Name:     oem3.inf
        Original Name:      nvlddmkm.inf
        Provider Name:      NVIDIA
        Class Name:         Display adapters
        Class GUID:         {4d36e968-e325-11ce-bfc1-08002be10318}
        Driver Version:     01/02/2025 32.0.15.6109
        Signer Name:        Microsoft Windows Hardware Compatibility Publisher

        Published Name:     oem7.inf
        Original Name:      rtux64w10.inf
        Provider Name:      Realtek
        Class Name:         Network adapters
        Class GUID:         {4d36e972-e325-11ce-bfc1-08002be10318}
        Driver Version:     03/03/2024 1.0.0.5
        Signer Name:        Microsoft Windows Hardware Compatibility Publisher

        """;

    private const string ChineseOutput = """
        Microsoft PnP 实用程序

        发布名称:     oem5.inf
        原始名称:     hdaudio.inf
        提供程序名称:     Realtek Semiconductor Corp.
        类名:     声音、视频和游戏控制器
        类 GUID:     {4d36e96c-e325-11ce-bfc1-08002be10318}
        驱动程序版本:     2024/06/01 6.0.9700.1
        签名者姓名:     Microsoft Windows Hardware Compatibility Publisher

        """;

    [Fact]
    public void Parses_english_and_chinese_output_by_position()
    {
        var en = DriverStore.ParseEnumDrivers(EnglishOutput);
        Assert.Equal(3, en.Count);
        Assert.Equal("oem12.inf", en[0].PublishedName);
        Assert.Equal("nvlddmkm.inf", en[0].OriginalName);
        Assert.Equal("32.0.15.7602", en[0].DriverVersion);
        Assert.Equal("05/12/2025", en[0].DriverDate);
        Assert.Equal("{4d36e968-e325-11ce-bfc1-08002be10318}", en[0].ClassGuid);

        var zh = DriverStore.ParseEnumDrivers(ChineseOutput);
        var d = Assert.Single(zh);
        Assert.Equal("oem5.inf", d.PublishedName);
        Assert.Equal("6.0.9700.1", d.DriverVersion);
        Assert.Equal("声音、视频和游戏控制器", d.ClassName);
    }

    [Fact]
    public void Classifies_newest_and_in_use()
    {
        var packages = DriverStore.ParseEnumDrivers(EnglishOutput);
        var rows = DriverStore.Classify(packages, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "oem12.inf", "oem7.inf" });
        var newest = rows.Single(r => r.Package.PublishedName == "oem12.inf");
        var old = rows.Single(r => r.Package.PublishedName == "oem3.inf");
        Assert.True(newest.IsNewestInFamily);
        Assert.True(newest.InUse);
        Assert.False(old.IsNewestInFamily);
        Assert.False(old.InUse);
        Assert.Equal(2, old.FamilySize);
        Assert.True(rows.Single(r => r.Package.PublishedName == "oem7.inf").IsNewestInFamily);

        // 读不到设备使用情况：全部视为在用
        var unknown = DriverStore.Classify(packages, null);
        Assert.All(unknown, r => Assert.True(r.InUse));
    }

    [Fact]
    public async Task Refuses_deleting_newest_or_in_use_before_running_anything()
    {
        using var db = CleanSweepDb.InMemory();
        var store = new DriverStore(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "drv-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
        var packages = DriverStore.ParseEnumDrivers(EnglishOutput);
        var rows = DriverStore.Classify(packages, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "oem12.inf" });

        var (ok1, m1) = await store.DeleteOldPackageAsync(rows.Single(r => r.Package.PublishedName == "oem12.inf"));
        Assert.False(ok1);
        Assert.Contains("最新", m1);
        var (ok2, m2) = await store.DeleteOldPackageAsync(rows.Single(r => r.Package.PublishedName == "oem7.inf"));
        Assert.False(ok2);
        var inUseOld = rows.Single(r => r.Package.PublishedName == "oem3.inf") with { InUse = true };
        var (ok3, m3) = await store.DeleteOldPackageAsync(inUseOld);
        Assert.False(ok3);
        Assert.Contains("正在使用", m3);
    }

    [Fact]
    public void Kb_numbers_are_validated()
    {
        Assert.Equal(("wusa.exe", "/uninstall /kb:5031455"), DriverStore.BuildUninstallUpdate("KB5031455", out _));
        Assert.Equal(("wusa.exe", "/uninstall /kb:5031455"), DriverStore.BuildUninstallUpdate("5031455", out _));
        Assert.Null(DriverStore.BuildUninstallUpdate("KB5031455 /quiet", out var err));
        Assert.Contains("格式", err);
        Assert.Null(DriverStore.BuildUninstallUpdate("KB12", out _));
    }

    [Fact]
    public void Pause_range_is_enforced_without_touching_registry()
    {
        using var db = CleanSweepDb.InMemory();
        var store = new DriverStore(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "wu-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
        Assert.False(store.PauseUpdates(0).Success);
        Assert.False(store.PauseUpdates(36).Success);
        _ = DriverStore.GetPauseState();
        _ = DriverStore.GetInstalledUpdates();
    }
}

public sealed class PopupBlockerTests
{
    private static PopupBlocker Create()
    {
        var db = CleanSweepDb.InMemory();
        return new PopupBlocker(new RegistryBackup(db, Path.Combine(Path.GetTempPath(), "CleanSweepTests", "popup-" + Guid.NewGuid().ToString("N")[..6])), new OperationLog(db));
    }

    [Fact]
    public void Bundled_rules_load()
    {
        using var b = Create();
        b.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "popups"));
        Assert.Empty(b.Rejected);
        Assert.True(b.Rules.Count >= 2);
        Assert.NotEmpty(b.BlockableProcesses);
    }

    [Fact]
    public void Rejects_overbroad_rules_and_system_processes()
    {
        using var b = Create();
        b.LoadJson("""
            { "rules": [
                { "id": "onlyproc", "processPattern": "foo\\.exe" },
                { "id": "badregex", "processPattern": "(", "titlePattern": "x" },
                { "id": "ok", "processPattern": "^foo\\.exe$", "titlePattern": "广告" } ],
              "blockableProcesses": [ "explorer.exe", "C:\\x\\a.exe", "AdThing.exe" ] }
            """, "t.json");
        Assert.Single(b.Rules);
        Assert.Contains(b.Rejected, r => r.RuleId == "onlyproc");
        Assert.Contains(b.Rejected, r => r.RuleId == "badregex");
        Assert.Contains(b.Rejected, r => r.RuleId == "explorer.exe");
        Assert.Contains(b.Rejected, r => r.RuleId == @"C:\x\a.exe");
        Assert.Equal(new[] { "AdThing.exe" }, b.BlockableProcesses);
    }

    [Fact]
    public void Match_requires_all_given_patterns_and_never_matches_protected_processes()
    {
        using var b = Create();
        b.LoadJson("""
            { "rules": [ { "id": "ad", "processPattern": "tips\\.exe$", "classPattern": "AdWnd", "titlePattern": "热点" } ] }
            """, "t.json");
        Assert.NotNull(b.Match("SomeTips.exe", "AdWnd", "今日热点"));
        Assert.Null(b.Match("SomeTips.exe", "AdWnd", "设置"));
        Assert.Null(b.Match("SomeTips.exe", "MainWnd", "今日热点"));
        Assert.Null(b.Match("other.exe", "AdWnd", "今日热点"));
        // 即使规则写得很宽，系统 / 常用程序也永不匹配
        b.LoadJson("""{ "rules": [ { "id": "wide", "processPattern": ".*", "titlePattern": ".*" } ] }""", "w.json");
        Assert.Null(b.Match("explorer.exe", "CabinetWClass", "文件资源管理器"));
        Assert.Null(b.Match("chrome.exe", "Chrome_WidgetWin_1", "热点"));
    }

    [Fact]
    public void Block_only_listed_processes()
    {
        using var b = Create();
        b.LoadJson("""{ "rules": [], "blockableProcesses": [ "AdThing.exe" ] }""", "t.json");
        Assert.False(b.SetBlocked("notepad.exe", true).Success);
        Assert.False(b.SetBlocked("explorer.exe", true).Success);
        _ = PopupBlocker.ListBlocked();
    }
}

public sealed class SystemRepairTests
{
    [Fact]
    public void Commands_are_fixed()
    {
        Assert.Equal(("sfc.exe", "/scannow"), SystemRepair.BuildCommand(RepairOperation.SfcScan));
        Assert.Equal(("dism.exe", "/Online /Cleanup-Image /RestoreHealth"), SystemRepair.BuildCommand(RepairOperation.DismRestoreHealth));
        Assert.Null(SystemRepair.BuildCommand(RepairOperation.RestartExplorer));
        Assert.Equal(SystemRepair.Actions.Count, Enum.GetValues<RepairOperation>().Length);
    }

    [Fact]
    public void Hosts_validation()
    {
        Assert.Null(SystemRepair.ValidateHosts(SystemRepair.DefaultHosts));
        Assert.Null(SystemRepair.ValidateHosts("127.0.0.1 localhost\r\n::1 localhost # v6\r\n\r\n# comment\r\n10.0.0.5\tmy-host.example.com alias"));
        Assert.Contains("第 1 行", SystemRepair.ValidateHosts("notanip host"));
        Assert.Contains("第 2 行", SystemRepair.ValidateHosts("127.0.0.1 ok\r\n127.0.0.1 bad host!name"));
        Assert.NotNull(SystemRepair.ValidateHosts("127.0.0.1"));
    }

    [Fact]
    public void Write_hosts_rejects_invalid_content_before_touching_file()
    {
        using var db = CleanSweepDb.InMemory();
        var repair = new SystemRepair(new OperationLog(db), Path.Combine(Path.GetTempPath(), "CleanSweepTests", "hosts-" + Guid.NewGuid().ToString("N")[..6]));
        var (ok, msg) = repair.WriteHosts("garbage line here");
        Assert.False(ok);
        Assert.Contains("第 1 行", msg);
        Assert.True(File.Exists(SystemRepair.HostsPath));
    }
}

public sealed class SystemInfoTests
{
    [Fact]
    public void Collects_basic_facts()
    {
        var items = SystemInfo.Collect();
        Assert.Contains(items, i => i.Group == "系统" && i.Name == "Windows 版本");
        Assert.Contains(items, i => i.Group == "处理器");
        Assert.All(items, i => Assert.False(string.IsNullOrWhiteSpace(i.Value)));
    }
}
