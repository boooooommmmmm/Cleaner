using CleanSweep.Core.Inventory;

namespace CleanSweep.Core.Uninstall;

/// <summary>
/// 预装软件（Bloatware）识别：常见的 OEM / 微软预装应用商店包与试用软件。命中只是"建议看看"，不代表建议卸载；
/// 用户明确要求时才调用官方卸载。
/// </summary>
public static class Bloatware
{
    private static readonly string[] PackagePrefixes =
    {
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingFinance", "Microsoft.BingSports", "Microsoft.GetHelp", "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.People", "Microsoft.SkypeApp", "Microsoft.WindowsFeedbackHub",
        "Microsoft.XboxApp", "Microsoft.XboxGamingOverlay", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.Xbox.TCUI", "Microsoft.GamingApp", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.YourPhone", "Microsoft.MixedReality.Portal",
        "Microsoft.Todos", "Microsoft.PowerAutomateDesktop", "Microsoft.Wallet", "Microsoft.Messaging", "Microsoft.OneConnect", "Microsoft.Print3D",
        "Microsoft.3DBuilder", "Microsoft.Microsoft3DViewer", "Microsoft.WindowsMaps", "Microsoft.WindowsAlarms", "Microsoft.WindowsSoundRecorder",
        "Microsoft.WindowsCamera", "Microsoft.Office.OneNote", "Microsoft.MicrosoftStickyNotes", "Microsoft.549981C3F5F10", "MicrosoftTeams", "MSTeams",
        "Microsoft.OutlookForWindows", "Microsoft.Copilot", "Microsoft.Windows.DevHome", "Microsoft.Windows.Ai.Copilot.Provider", "MicrosoftCorporationII.QuickAssist",
        "MicrosoftCorporationII.MicrosoftFamily", "Clipchamp.Clipchamp", "king.com.", "SpotifyAB.SpotifyMusic", "Disney.", "Facebook.", "BytedancePte.Ltd.TikTok",
        "AmazonVideo.PrimeVideo", "Amazon.com.Amazon", "AdobeSystemsIncorporated.AdobePhotoshopExpress", "AdobeSystemsIncorporated.AdobeExpress",
        "DolbyLaboratories.DolbyAccess", "Netflix.", "PandoraMediaInc.", "Duolingo-LearnLanguagesforFree", "Twitter.", "LinkedIn", "7EE7776C.LinkedInforWindows",
        "flaregamesGmbH.", "GAMELOFTSA.", "ActiproSoftwareLLC", "46928bounde.EclipseManager", "A278AB0D.", "CAF9E577.Plex", "DB6EA5DB.CyberLinkMediaSuiteEssentials",
        "E046963F.LenovoCompanion", "LenovoCorporation.LenovoVantage", "4DF9E0F8.Netflix", "Fitbit.FitbitCoach", "HPInc.", "AD2F1837.HP", "DellInc.", "ASUSTeKCOMPUTERINC.",
        "McAfee.", "Evernote.Evernote", "Dropbox.Dropbox", "C27EB4BA.DropboxOEM", "WildTangent", "Nordcurrent", "ThumbmunkeysLtd.PhototasticCollage",
        "5A894077.McAfeeSecurity", "AppUp.IntelGraphicsExperience",
    };

    private static readonly string[] RegistryNameKeywords =
    {
        "McAfee", "Norton", "WildTangent", "Booking.com", "ExpressVPN", "Dropbox 20 GB", "Amazon Music", "CyberLink Power", "Candy Crush",
    };

    public static bool IsKnown(InstalledApp app)
    {
        if (app.Source == AppSource.Uwp && app.PackageFamilyName is not null)
        {
            var name = app.PackageFamilyName.Split('_')[0];
            return PackagePrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }
        return RegistryNameKeywords.Any(k => app.Name.Contains(k, StringComparison.OrdinalIgnoreCase));
    }
}
