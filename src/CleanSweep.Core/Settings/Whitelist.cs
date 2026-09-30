using System.Text.Json;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Settings;

/// <summary>用户白名单：永久排除路径、规则、单个条目（设计文档 6.1 第 6 条）。</summary>
public sealed class Whitelist
{
    private sealed class Dto
    {
        public List<string> Paths { get; set; } = new();
        public List<string> RuleIds { get; set; } = new();
        public List<string> ItemIds { get; set; } = new();
    }

    private readonly object _lock = new();
    private readonly HashSet<string> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ruleIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _itemIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _file;

    public Whitelist() { }

    public Whitelist(string file)
    {
        _file = file;
        Load();
    }

    public IReadOnlyCollection<string> Paths { get { lock (_lock) return _paths.ToArray(); } }
    public IReadOnlyCollection<string> RuleIds { get { lock (_lock) return _ruleIds.ToArray(); } }
    public IReadOnlyCollection<string> ItemIds { get { lock (_lock) return _itemIds.ToArray(); } }

    public bool IsPathExcluded(string path)
    {
        lock (_lock)
        {
            foreach (var p in _paths)
            {
                if (PathGuard.IsSameOrUnder(path, p)) return true;
            }
        }
        return false;
    }

    public bool IsRuleExcluded(string ruleId) { lock (_lock) return _ruleIds.Contains(ruleId); }
    public bool IsItemExcluded(string itemId) { lock (_lock) return _itemIds.Contains(itemId); }

    public void AddPath(string path) { lock (_lock) { _paths.Add(PathGuard.Normalize(path)); } Save(); }
    public void RemovePath(string path) { lock (_lock) { _paths.Remove(PathGuard.Normalize(path)); } Save(); }
    public void AddRule(string ruleId) { lock (_lock) { _ruleIds.Add(ruleId); } Save(); }
    public void RemoveRule(string ruleId) { lock (_lock) { _ruleIds.Remove(ruleId); } Save(); }
    public void AddItem(string itemId) { lock (_lock) { _itemIds.Add(itemId); } Save(); }
    public void RemoveItem(string itemId) { lock (_lock) { _itemIds.Remove(itemId); } Save(); }

    private void Load()
    {
        if (_file is null || !File.Exists(_file)) return;
        try
        {
            var dto = JsonSerializer.Deserialize<Dto>(File.ReadAllText(_file));
            if (dto is null) return;
            lock (_lock)
            {
                foreach (var p in dto.Paths) _paths.Add(p);
                foreach (var r in dto.RuleIds) _ruleIds.Add(r);
                foreach (var i in dto.ItemIds) _itemIds.Add(i);
            }
        }
        catch
        {
            // 损坏的白名单文件按空处理，不影响启动
        }
    }

    private void Save()
    {
        if (_file is null) return;
        Dto dto;
        lock (_lock)
        {
            dto = new Dto { Paths = _paths.ToList(), RuleIds = _ruleIds.ToList(), ItemIds = _itemIds.ToList() };
        }
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllText(_file, JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
    }
}
