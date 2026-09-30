using CleanSweep.Core.Startup;

namespace CleanSweep.Core.Tests;

public class StartupApprovedTests
{
    [Fact]
    public void Missing_or_empty_value_means_enabled()
    {
        Assert.True(StartupApproved.IsEnabled(null));
        Assert.True(StartupApproved.IsEnabled(Array.Empty<byte>()));
    }

    [Fact]
    public void Encode_enabled_writes_0x02_and_no_timestamp()
    {
        var b = StartupApproved.Encode(true);
        Assert.Equal(12, b.Length);
        Assert.Equal(0x02, b[0]);
        Assert.True(StartupApproved.IsEnabled(b));
        Assert.Null(StartupApproved.DisabledAtUtc(b));
        Assert.All(b.Skip(1), x => Assert.Equal(0, x));
    }

    [Fact]
    public void Encode_disabled_writes_0x03_and_filetime()
    {
        var now = new DateTime(2026, 9, 28, 12, 0, 0, DateTimeKind.Utc);
        var b = StartupApproved.Encode(false, null, now);
        Assert.Equal(0x03, b[0]);
        Assert.False(StartupApproved.IsEnabled(b));
        Assert.Equal(now, StartupApproved.DisabledAtUtc(b));
    }

    [Fact]
    public void Encode_preserves_high_flag_bits_of_existing_value()
    {
        var existingEnabled = new byte[] { 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        var disabled = StartupApproved.Encode(false, existingEnabled);
        Assert.Equal(0x07, disabled[0]);

        var reEnabled = StartupApproved.Encode(true, disabled);
        Assert.Equal(0x06, reEnabled[0]);
        Assert.True(StartupApproved.IsEnabled(reEnabled));
    }
}

public class CommandLineTests
{
    private static bool Never(string _) => false;

    [Fact]
    public void Quoted_path_with_arguments()
    {
        var (exe, args) = CommandLine.Split("\"C:\\Program Files\\Foo\\bar.exe\" --minimized /x", Never);
        Assert.Equal(@"C:\Program Files\Foo\bar.exe", exe);
        Assert.Equal("--minimized /x", args);
    }

    [Fact]
    public void Quoted_path_without_arguments()
    {
        var (exe, args) = CommandLine.Split("\"C:\\Tools\\a.exe\"", Never);
        Assert.Equal(@"C:\Tools\a.exe", exe);
        Assert.Null(args);
    }

    [Fact]
    public void Unquoted_path_with_spaces_prefers_existing_file()
    {
        var real = @"C:\Program Files\Foo\bar.exe";
        var (exe, args) = CommandLine.Split(@"C:\Program Files\Foo\bar.exe -tray", p => string.Equals(p, real, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(real, exe);
        Assert.Equal("-tray", args);
    }

    [Fact]
    public void Unquoted_path_falls_back_to_exe_extension()
    {
        var (exe, args) = CommandLine.Split(@"C:\Program Files\Foo\bar.exe -tray", Never);
        Assert.Equal(@"C:\Program Files\Foo\bar.exe", exe);
        Assert.Equal("-tray", args);
    }

    [Fact]
    public void Expands_environment_variables()
    {
        var (exe, args) = CommandLine.Split(@"%SystemRoot%\system32\svchost.exe -k netsvcs", Never);
        Assert.EndsWith(@"\system32\svchost.exe", exe, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("%", exe);
        Assert.Equal("-k netsvcs", args);
    }

    [Fact]
    public void Normalizes_nt_prefixes_used_by_service_image_paths()
    {
        Assert.Equal(@"C:\Windows\x.exe", CommandLine.NormalizeNtPrefix(@"\??\C:\Windows\x.exe", @"C:\Windows"));
        Assert.Equal(@"C:\Windows\System32\a.exe", CommandLine.NormalizeNtPrefix(@"\SystemRoot\System32\a.exe", @"C:\Windows"));
        Assert.Equal(@"C:\Windows\system32\b.exe", CommandLine.NormalizeNtPrefix(@"system32\b.exe", @"C:\Windows"));
        Assert.Equal("\"C:\\Windows\\c.exe\" /s", CommandLine.NormalizeNtPrefix("\"\\??\\C:\\Windows\\c.exe\" /s", @"C:\Windows"));
    }

    [Fact]
    public void Empty_command_yields_nulls()
    {
        Assert.Equal((null, null), CommandLine.Split("   ", Never));
        Assert.Equal((null, null), CommandLine.Split(null, Never));
    }

    [Fact]
    public void Host_processes_are_recognized()
    {
        Assert.True(CommandLine.IsHostProcess(@"C:\Windows\System32\rundll32.exe"));
        Assert.True(CommandLine.IsHostProcess(@"C:\Windows\System32\svchost.exe"));
        Assert.False(CommandLine.IsHostProcess(@"C:\Apps\foo.exe"));
        Assert.False(CommandLine.IsHostProcess(null));
    }

    [Fact]
    public void Rundll32_payload_is_the_dll()
    {
        var payload = StartupManager.PayloadPath(@"C:\Windows\System32\rundll32.exe", @"C:\Vendor\hook.dll,Start");
        Assert.Equal(@"C:\Vendor\hook.dll", payload);

        var relative = StartupManager.PayloadPath(@"C:\Windows\System32\rundll32.exe", "shell32.dll,Control_RunDLL");
        Assert.Equal(Path.Combine(System.Environment.SystemDirectory, "shell32.dll"), relative);

        Assert.Equal(@"C:\Apps\a.exe", StartupManager.PayloadPath(@"C:\Apps\a.exe", "-x"));
    }
}

public class StartupInfoParserTests
{
    private const string SampleXml = """
        <?xml version="1.0"?>
        <StartupData>
          <Process Name="OneDrive.exe" PID="9568" StartedInTraceSec="6.05">
            <StartTime>2026/09/28:07:20:53.2176345</StartTime>
            <CommandLine>"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background</CommandLine>
            <DiskUsage units="bytes">5291008</DiskUsage>
            <CpuUsage units="us">640625</CpuUsage>
          </Process>
          <Process Name="helper.exe" PID="1" StartedInTraceSec="1">
            <StartTime>x</StartTime>
            <CommandLine>C:\Apps\helper.exe</CommandLine>
            <DiskUsage units="bytes">1024</DiskUsage>
            <CpuUsage units="us">50000</CpuUsage>
          </Process>
          <Process Name="helper.exe" PID="2" StartedInTraceSec="1">
            <StartTime>x</StartTime>
            <CommandLine>C:\Apps\helper.exe</CommandLine>
            <DiskUsage units="bytes">1024</DiskUsage>
            <CpuUsage units="us">50000</CpuUsage>
          </Process>
        </StartupData>
        """;

    [Fact]
    public void Parses_units_into_ms_and_bytes()
    {
        var samples = StartupInfoParser.Parse(SampleXml);
        Assert.Equal(3, samples.Count);
        Assert.Equal("OneDrive.exe", samples[0].Name);
        Assert.Equal(640.625, samples[0].CpuMs, 3);
        Assert.Equal(5291008, samples[0].DiskBytes);
    }

    [Fact]
    public void Aggregate_sums_within_boot_and_averages_across_boots()
    {
        var boot1 = StartupInfoParser.Parse(SampleXml);
        var boot2 = new List<ProcessStartupSample>
        {
            new("OneDrive.exe", "\"C:\\Users\\me\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", 200, 1_000_000),
        };
        var agg = StartupInfoParser.Aggregate(new[] { boot1, boot2 }, _ => false);

        var onedrive = agg[@"c:\users\me\appdata\local\microsoft\onedrive\onedrive.exe"];
        Assert.Equal(2, onedrive.Boots);
        Assert.Equal((640.625 + 200) / 2, onedrive.CpuMs, 3);
        Assert.Equal((5291008 + 1_000_000) / 2, onedrive.DiskBytes);

        // 同一次开机的两个 helper.exe 进程先求和，再按 1 次开机平均
        var helper = agg[@"c:\apps\helper.exe"];
        Assert.Equal(1, helper.Boots);
        Assert.Equal(100, helper.CpuMs, 3);
        Assert.Equal(2048, helper.DiskBytes);
    }

    [Theory]
    [InlineData(0, 0, StartupImpact.Low)]
    [InlineData(300, 0, StartupImpact.Low)]
    [InlineData(301, 0, StartupImpact.Medium)]
    [InlineData(0, 300 * 1024 + 1, StartupImpact.Medium)]
    [InlineData(1001, 0, StartupImpact.High)]
    [InlineData(0, 3L * 1024 * 1024 + 1, StartupImpact.High)]
    public void Rating_thresholds_match_task_manager(double cpuMs, long disk, StartupImpact expected)
    {
        Assert.Equal(expected, StartupInfoParser.Rate(cpuMs, disk));
    }

    [Fact]
    public void Load_directory_skips_corrupt_files()
    {
        var dir = Path.Combine(Path.GetTempPath(), "CleanSweepTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "S-1-5-21_StartupInfo1.xml"), SampleXml);
            File.WriteAllText(Path.Combine(dir, "S-1-5-21_StartupInfo2.xml"), "<not xml");
            var boots = StartupInfoParser.LoadDirectory(dir);
            Assert.Single(boots);
            Assert.Equal(3, boots[0].Count);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}

public class StartupSuggestionTests
{
    [Fact]
    public void Microsoft_items_are_kept()
    {
        Assert.Equal(StartupSuggestion.Keep,
            StartupManager.Suggest(StartupKind.RegistryRun, true, SignatureState.SignedMicrosoft, StartupImpact.High, "SecurityHealth", @"C:\Windows\System32\SecurityHealthSystray.exe"));
    }

    [Fact]
    public void Security_software_is_kept_even_if_high_impact()
    {
        Assert.Equal(StartupSuggestion.Keep,
            StartupManager.Suggest(StartupKind.Service, false, SignatureState.Signed, StartupImpact.High, "Kaspersky Lab", @"C:\Program Files\Kaspersky\avp.exe"));
    }

    [Fact]
    public void Unsigned_is_recommended_to_disable()
    {
        Assert.Equal(StartupSuggestion.RecommendDisable,
            StartupManager.Suggest(StartupKind.RegistryRun, false, SignatureState.Unsigned, StartupImpact.Low, "Foo", @"C:\Apps\foo.exe"));
    }

    [Fact]
    public void Updaters_and_high_impact_are_recommended_to_disable()
    {
        Assert.Equal(StartupSuggestion.RecommendDisable,
            StartupManager.Suggest(StartupKind.ScheduledTask, false, SignatureState.Signed, StartupImpact.Low, "Adobe Update Scheduler", @"C:\Program Files\Adobe\AdobeUpdater.exe"));
        Assert.Equal(StartupSuggestion.RecommendDisable,
            StartupManager.Suggest(StartupKind.RegistryRun, false, SignatureState.Signed, StartupImpact.High, "Game Launcher", @"C:\Games\launcher.exe"));
    }

    [Fact]
    public void Signed_low_impact_third_party_can_be_disabled()
    {
        Assert.Equal(StartupSuggestion.CanDisable,
            StartupManager.Suggest(StartupKind.RegistryRun, false, SignatureState.Signed, StartupImpact.Low, "Slack", @"C:\Apps\slack.exe"));
        Assert.Equal(StartupSuggestion.CanDisable,
            StartupManager.Suggest(StartupKind.RegistryRun, false, SignatureState.Unknown, StartupImpact.NotMeasured, "Foo", null));
    }
}

public class StartupMiscTests
{
    [Fact]
    public void Package_full_name_to_family_name()
    {
        Assert.Equal("Microsoft.OneDrive_8wekyb3d8bbwe", StartupManager.ToFamilyName("Microsoft.OneDrive_24.1.0.0_x64__8wekyb3d8bbwe"));
        Assert.Equal("Foo.Bar_abc", StartupManager.ToFamilyName("Foo.Bar_1.0.0.0_neutral_~_abc"));
        Assert.Null(StartupManager.ToFamilyName("NoUnderscore"));
    }

    [Fact]
    public void Formats_iso8601_delays()
    {
        Assert.Equal("30 秒", StartupManager.FormatDelay("PT30S"));
        Assert.Equal("2 分钟", StartupManager.FormatDelay("PT2M"));
        Assert.Equal("1.5 小时", StartupManager.FormatDelay("PT1H30M"));
        Assert.Equal("garbage", StartupManager.FormatDelay("garbage"));
    }

    [Fact]
    public void Boot_event_xml_is_parsed()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <EventID>100</EventID>
                <TimeCreated SystemTime="2026-09-28T01:02:03.000Z"/>
              </System>
              <EventData>
                <Data Name="BootTsVersion">2</Data>
                <Data Name="BootTime">45123</Data>
                <Data Name="MainPathBootTime">20000</Data>
                <Data Name="BootPostBootTime">25123</Data>
              </EventData>
            </Event>
            """;
        var rec = BootHistory.ParseEvent(xml, null);
        Assert.NotNull(rec);
        Assert.Equal(45123, rec!.BootTimeMs);
        Assert.Equal(20000, rec.MainPathMs);
        Assert.Equal(25123, rec.PostBootMs);
        Assert.Equal(new DateTime(2026, 9, 28, 1, 2, 3, DateTimeKind.Utc), rec.TimeUtc);
    }

    [Fact]
    public void Boot_event_without_boot_time_is_ignored()
    {
        Assert.Null(BootHistory.ParseEvent("<Event><EventData><Data Name=\"Other\">1</Data></EventData></Event>", DateTime.UtcNow));
    }
}

public class FileSignatureTests
{
    [Fact]
    public void System_notepad_is_microsoft_signed_via_catalog_or_embedded()
    {
        var notepad = Path.Combine(System.Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(notepad)) notepad = Path.Combine(System.Environment.SystemDirectory, "cmd.exe");
        var info = FileSignature.Inspect(notepad);
        Assert.Equal(SignatureState.SignedMicrosoft, info.State);
        Assert.True(info.IsMicrosoft);
    }

    [Fact]
    public void Test_assembly_itself_is_unsigned()
    {
        var info = FileSignature.Inspect(typeof(FileSignatureTests).Assembly.Location);
        Assert.Equal(SignatureState.Unsigned, info.State);
        Assert.False(info.IsMicrosoft);
    }

    [Fact]
    public void Missing_file_is_unknown()
    {
        Assert.Equal(SignatureState.Unknown, FileSignature.Inspect(@"C:\definitely\missing\file.exe").State);
        Assert.Equal(SignatureState.Unknown, FileSignature.Inspect(null).State);
    }

    [Fact]
    public void Microsoft_publisher_detection()
    {
        Assert.True(FileSignature.IsMicrosoftPublisher("Microsoft Corporation"));
        Assert.True(FileSignature.IsMicrosoftPublisher("Microsoft Windows"));
        Assert.True(FileSignature.IsMicrosoftPublisher("Microsoft Windows Publisher"));
        Assert.False(FileSignature.IsMicrosoftPublisher("Microsofty Ltd"));
        Assert.False(FileSignature.IsMicrosoftPublisher(null));
        // WHQL 与第三方组件 CA 签的是第三方驱动，不是微软自带
        Assert.False(FileSignature.IsMicrosoftPublisher("Microsoft Windows Hardware Compatibility Publisher"));
        Assert.False(FileSignature.IsMicrosoftPublisher("Microsoft Windows Third Party Component CA 2012"));
    }
}
