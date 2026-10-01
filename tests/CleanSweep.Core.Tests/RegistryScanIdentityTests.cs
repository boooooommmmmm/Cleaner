using CleanSweep.Core.Model;
using CleanSweep.Core.RegistryCleaning;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

public sealed class RegistryScanIdentityTests
{
    [Theory]
    [InlineData(@"HKLM\Software\Classes\.wemta", true)]
    [InlineData(@"HKLM\Software\Classes\xmp", true)]
    [InlineData(@"HKLM\Software\Classes\Applications\xmp.exe", true)]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\XMP.exe", true)]
    [InlineData(@"HKCU\Software\CleanSweepTests\Vendor", true)]
    [InlineData(@"HKCU\Software\Classes\.wemta", true)]
    [InlineData(@"HKCR\xmp", true)]
    [InlineData(@"HKLM\Software\Classes\CLSID\{abc}", false)]
    [InlineData(@"HKCU\Software\Classes\CLSID\{abc}", false)]
    [InlineData(@"HKCR\Interface\{abc}", false)]
    [InlineData(@"HKLM\Software\Classes\DirectShow\x", false)]
    [InlineData(@"HKLM\Software\Classes\Media Type\x", false)]
    [InlineData(@"HKLM\Software\Classes\MediaFoundation\x", false)]
    [InlineData(@"HKLM\Software\Classes\Wow6432Node\x", false)]
    [InlineData(@"HKLM\Software\ClassesOther\x", false)]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\App PathsOther\x", false)]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\x", false)]
    [InlineData(@"HKLM\Software\Vendor", false)]
    public void Only_shared_targets_merge_across_views(string path, bool shared)
    {
        var item = Item(path);
        var other = item with { Id = "other", Registry = item.Registry! with { View = RegistryView.Registry32 } };
        Assert.Equal(shared, RegistryScanIdentity.ForItem(item) == RegistryScanIdentity.ForItem(other));
    }

    [Fact]
    public void Identity_handles_hive_aliases_case_and_distinct_value_names()
    {
        var item = Item(@"HKLM\Software\Classes\xmp");
        var alias = item with { Registry = new RegistryTarget(@"HKEY_LOCAL_MACHINE\SOFTWARE\CLASSES\XMP", RegistryView.Registry32, null) };
        Assert.Equal(RegistryScanIdentity.ForItem(item), RegistryScanIdentity.ForItem(alias));
        var value = item with { Kind = ItemKind.RegistryValue, Registry = item.Registry! with { ValueName = "" } };
        Assert.NotEqual(RegistryScanIdentity.ForItem(item), RegistryScanIdentity.ForItem(value));
        Assert.NotEqual(RegistryScanIdentity.ForItem(value), RegistryScanIdentity.ForItem(value with { Registry = value.Registry! with { ValueName = "other" } }));
    }

    private static ScanItem Item(string path) => new()
    {
        Id = "item", ModuleId = "registry", Group = "g", DisplayName = "item",
        Kind = ItemKind.RegistryKey, Registry = new RegistryTarget(path, RegistryView.Registry64, null),
    };
}
