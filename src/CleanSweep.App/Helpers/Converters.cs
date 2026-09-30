using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Helpers;

public sealed class BytesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is long l ? Format.Bytes(l) : value is int i ? Format.Bytes(i) : "-";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class RiskToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            RiskLevel.Safe => "Brush.Risk.Safe",
            RiskLevel.Confirm => "Brush.Risk.Confirm",
            RiskLevel.High => "Brush.Risk.High",
            _ => "Brush.Risk.NotRecommended",
        };
        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class RiskToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        RiskLevel.Safe => "安全",
        RiskLevel.Confirm => "建议确认",
        RiskLevel.High => "高风险",
        RiskLevel.NotRecommended => "不建议",
        _ => "",
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>true → Visible；parameter 为 "invert" 时反转。</summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool invert = parameter is string s && s.Equals("invert", StringComparison.OrdinalIgnoreCase);
        bool b = value is bool v && v;
        if (invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>多值绑定：全部为 true 才为 true。</summary>
public sealed class AllTrueConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) => values.All(v => v is true);
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b && !b;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b && !b;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    /// <summary>parameter 为 "invert" 时：null → Visible。</summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool invert = parameter is string s && s.Equals("invert", StringComparison.OrdinalIgnoreCase);
        bool visible = value is not null;
        if (invert) visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>int 属性与 RadioButton 组的双向绑定：值等于 parameter → true；选中 → 写回 parameter。</summary>
public sealed class IntEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int v && int.TryParse(parameter?.ToString(), out var p) && v == p;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true && int.TryParse(parameter?.ToString(), out var p) ? p : Binding.DoNothing;
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    /// <summary>集合非空 → Visible；parameter 为 "invert" 时反转。</summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool invert = parameter is string s && s.Equals("invert", StringComparison.OrdinalIgnoreCase);
        int count = value switch
        {
            int i => i,
            ICollection c => c.Count,
            IEnumerable e => e.Cast<object>().Count(),
            _ => 0,
        };
        bool visible = count > 0;
        if (invert) visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
