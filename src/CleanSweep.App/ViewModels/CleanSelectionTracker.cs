using CleanSweep.App.Services;

namespace CleanSweep.App.ViewModels;

/// <summary>恢复并记录一组条目的选择；过滤和清理过程中的状态变化不改写用户偏好。</summary>
internal sealed class CleanSelectionTracker : IDisposable
{
    private readonly ScanGroupViewModel _group;
    private readonly AppSettings _settings;
    private readonly Func<bool> _canRemember;
    private readonly Action<string?> _reportError;
    private readonly Dictionary<ScanItemViewModel, bool> _previous = new();
    private bool _needsSave;

    public CleanSelectionTracker(ScanGroupViewModel group, AppSettings settings, Func<bool> canRemember, Action<string?> reportError)
    {
        _group = group;
        _settings = settings;
        _canRemember = canRemember;
        _reportError = reportError;
        foreach (var row in group.Items)
        {
            row.IsSelected = row.CanSelect && settings.CleaningSelectionFor(row.Item);
            _previous[row] = row.IsSelected;
        }
        group.SelectionChanged += OnSelectionChanged;
    }

    private void OnSelectionChanged(object? sender, EventArgs e)
    {
        foreach (var row in _group.Items)
        {
            var changed = !_previous.TryGetValue(row, out var previous) || previous != row.IsSelected;
            _previous[row] = row.IsSelected;
            if (!changed || !row.CanSelect || !_canRemember()) continue;
            _settings.RememberCleaningSelection(row.Item, row.IsSelected);
            _needsSave = true;
        }
        if (!_needsSave || !_canRemember()) return;
        try
        {
            _settings.Save();
            _needsSave = false;
            _reportError(null);
        }
        catch (Exception ex)
        {
            _reportError("勾选状态未能保存，重启后可能丢失：" + ex.Message);
        }
    }

    public void Dispose() => _group.SelectionChanged -= OnSelectionChanged;
}
