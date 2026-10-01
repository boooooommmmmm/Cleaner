using CleanSweep.Core.Model;

namespace CleanSweep.App.ViewModels;

public enum CleanRiskFilter { All, Safe, Confirm, High, NotRecommended }
public enum CleanSortOrder { ScanOrder, SizeDescending, NameAscending, RiskAscending }
public sealed record CleanResultOption<T>(T Value, string Label);

internal static class CleanResultOptions
{
    internal static bool Matches(this CleanRiskFilter filter, RiskLevel risk) => filter switch
    {
        CleanRiskFilter.All => true,
        CleanRiskFilter.Safe => risk == RiskLevel.Safe,
        CleanRiskFilter.Confirm => risk == RiskLevel.Confirm,
        CleanRiskFilter.High => risk == RiskLevel.High,
        CleanRiskFilter.NotRecommended => risk == RiskLevel.NotRecommended,
        _ => false,
    };
}
