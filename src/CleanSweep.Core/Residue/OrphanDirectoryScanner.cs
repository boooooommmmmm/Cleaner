using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Uninstall;

namespace CleanSweep.Core.Residue;

/// <summary>有卸载记录的已知缓存，以及真正为空的应用目录。不按年龄或泛化目录名猜测用户数据。</summary>
public sealed class OrphanDirectoryScanner(
    Func<CancellationToken, InventorySnapshot> inventory,
    AppFingerprintDb fingerprints, UninstallHistory history, IReadOnlyCollection<string>? appNames = null) : IScanner
{
    private readonly HashSet<string>? _appKeys = appNames?.Select(NameKey.Normalize).Where(k => k.Length >= 3).ToHashSet(StringComparer.Ordinal);
    public const string ModuleId = "orphan-directories";
    public string Id => ModuleId;
    public string DisplayName => "僵尸目录（缓存与空目录）";

    private static readonly HashSet<string> CacheNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cache", "Caches", "Code Cache", "GPUCache", "DawnCache", "ShaderCache", "GrShaderCache",
        "DawnGraphiteCache", "DawnWebGPUCache", "Logs", "Log", "CrashDumps", "CachedData",
    };

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run(() => Scan(ctx, progress, ct), ct);

    private IReadOnlyList<ScanItem> Scan(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        // Always request a fresh inventory. This same scanner is used before cleanup.
        var inv = inventory(ct);
        if (!inv.RegistryReliable) return [];
        var records = history.List(1000).Where(r => _appKeys is null || _appKeys.Contains(NameKey.Normalize(r.Name))).ToArray();
        var items = new List<ScanItem>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        UninstallRecord? Evidence(string app) => records.FirstOrDefault(r =>
            ExactName(r.Name, app) && inv.FindByName(app) is null);

        foreach (var fp in fingerprints.Fingerprints)
        {
            ct.ThrowIfCancellationRequested();
            var record = Evidence(fp.App);
            if (record is null || AppFingerprintDb.IsInstalled(fp, inv, ctx.Env, out _, out var uwp) != false
                || (uwp && !inv.UwpReliable)) continue;
            var owners = fp.ExpandPaths(ctx.Env).Where(p => AllowedPath(p, ctx)).ToArray();
            if (owners.Any(p => Active(p, inv))) continue;
            foreach (var owner in owners) AddEmpty(owner, fp.App, record, "指纹 " + fp.Id);
            foreach (var cache in fp.ExpandCachePaths(ctx.Env))
            {
                // A cache may not be the owner root itself; that could include settings or program files.
                if (!owners.Any(o => Under(cache, o))) continue;
                AddCache(cache, fp.App, record, "指纹缓存 " + fp.Id, null);
            }
        }

        foreach (var rule in ctx.Rules.Where(r => r.Category is "app" or "browser" or "dev"))
        {
            ct.ThrowIfCancellationRequested();
            var record = Evidence(rule.App);
            if (record is null || ctx.Whitelist.IsRuleExcluded(rule.Id) || RegistryDetect.IsInstalled(rule.Detect, ctx.Env)) continue;
            foreach (var target in rule.Targets)
            {
                if (target.Risk != RiskLevel.Safe || target.When != RuleWhen.Installed
                    || target.Kind is not (TargetKind.Files or TargetKind.Directory)
                    || target.PreActions.Count > 0 || target.ExpandedPath is null || target.HasWildcard) continue;
                var path = target.ExpandedPath;
                if (!CacheNames.Contains(Path.GetFileName(path.TrimEnd('\\', '/')))) continue;
                AddCache(path, rule.App, record, "缓存规则 " + rule.Id, target);
            }
        }

        // Only the exact recorded installation directory is considered, and only when literally empty.
        foreach (var record in records)
        {
            ct.ThrowIfCancellationRequested();
            if (record.InstallLocation is not { } path || inv.FindByName(record.Name) is not null) continue;
            AddEmpty(path, record.Name, record, "卸载记录中的安装位置");
        }

        progress?.Report(new ScanProgress(Id, null, items.Count, items.Sum(i => i.SizeBytes)));
        return items;

        bool CanUse(string path) => AllowedPath(path, ctx) && !Active(path, inv)
            && !ctx.Whitelist.IsPathExcluded(path)
            && !ctx.Whitelist.Paths.Any(p => PathGuard.IsSameOrUnder(p, path))
            && ctx.Guard.VerifyPhysical(path).Allowed;

        void AddEmpty(string path, string app, UninstallRecord record, string basis)
        {
            try
            {
                path = PathGuard.Normalize(path);
                if (!CanUse(path) || !Directory.Exists(path)) return;
                // Unlike file-counting, this detects subdirectories and inaccessible/reparse children as nonempty.
                if (Directory.EnumerateFileSystemEntries(path).Any()) return;
                var measured = ctx.Guard.FingerprintDirectory(path, ct);
                Add(new ScanItem
                {
                    Id = RuleScanner.MakeId(Id, "empty", path), ModuleId = Id, Group = app + " · 空目录",
                    DisplayName = Path.GetFileName(path), Path = path, Kind = ItemKind.Directory,
                    Risk = RiskLevel.Confirm, DirectoryFingerprint = measured.Fingerprint,
                    Description = Reason(record, basis) + "目录中没有文件或子目录；移入隔离区，不直接永久删除。",
                });
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        }

        void AddCache(string path, string app, UninstallRecord record, string basis, RuleTarget? target)
        {
            try
            {
                path = PathGuard.Normalize(path);
                if (!CanUse(path) || !Directory.Exists(path)) return;
                if (Directory.EnumerateFileSystemEntries(path).Any() == false) { AddEmpty(path, app, record, basis); return; }
                var cutoff = target is { MinAgeDays: > 0 } ? DateTime.UtcNow.AddDays(-target.MinAgeDays) : (DateTime?)null;
                var files = ctx.Guard.EnumerateFiles(path, target?.Pattern, target?.Recurse ?? true, ct)
                    .Where(f => cutoff is null || f.LastWriteUtc < cutoff)
                    .Where(f => target is null || !PathGuard.MatchesAny(Path.GetFileName(f.Path), target.Exclude.ToArray()))
                    .Where(f => !ctx.Whitelist.IsPathExcluded(f.Path)).ToList();
                if (files.Count == 0) return;
                Add(new ScanItem
                {
                    Id = RuleScanner.MakeId(Id, "cache", path), ModuleId = Id, Group = app + " · 缓存残留",
                    DisplayName = Path.GetFileName(path), Path = path, Kind = ItemKind.FileSet,
                    Risk = RiskLevel.Confirm, Files = files, SizeBytes = files.Sum(f => f.Size),
                    LastWriteUtc = files.Max(f => f.LastWriteUtc),
                    Description = Reason(record, basis) + "只处理规则指定的缓存/日志文件，应用根目录与其他数据保留；移入隔离区。",
                });
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        }

        void Add(ScanItem item)
        {
            if (ctx.Whitelist.IsItemExcluded(item.Id) || !paths.Add(item.Path!)) return;
            items.Add(item);
            progress?.Report(new ScanProgress(Id, item.Path, items.Count, items.Sum(i => i.SizeBytes)));
        }
    }

    private static string Reason(UninstallRecord record, string basis) =>
        $"“{record.Name}”有 {record.TsUtc.ToLocalTime():yyyy-MM-dd} 的卸载记录，本次清单未检测到同名已安装应用；依据：{basis}。";

    private static bool ExactName(string a, string b)
    {
        var key = NameKey.Normalize(a);
        return key.Length >= 3 && key == NameKey.Normalize(b);
    }

    private static bool Active(string path, InventorySnapshot inv) => inv.FindByInstallLocation(path) is not null
        || inv.HasRunningProcessUnder(path)
        || inv.RunningExecutables.Any(p => Path.GetDirectoryName(p) is { } parent && PathGuard.IsSameOrUnder(path, parent));

    private static bool Under(string path, string parent) => !string.Equals(PathGuard.Normalize(path), PathGuard.Normalize(parent), StringComparison.OrdinalIgnoreCase)
        && PathGuard.IsSameOrUnder(path, parent);

    private static bool AllowedPath(string path, ScanContext ctx)
    {
        try { return Directory.Exists(path) && AllowedExistingPath(path, ctx); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    private static bool AllowedExistingPath(string path, ScanContext ctx)
    {
        if (!ctx.Guard.Check(path).Allowed || path.Split('\\', '/').Any(p => p.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase))) return false;
        // First version deliberately stays within current-user AppData; no Documents, arbitrary disks or Program Files.
        foreach (var key in new[] { "LocalAppData", "AppData", "LocalAppDataLow" })
        {
            if (!ctx.Env.Variables.TryGetValue(key, out var root) || !Under(path, root)) continue;
            var relative = Path.GetRelativePath(root, path);
            var first = relative.Split('\\', '/')[0];
            if (first.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) || first.Equals("Packages", StringComparison.OrdinalIgnoreCase)
                || first.Equals("Temp", StringComparison.OrdinalIgnoreCase) || first.Equals("Programs", StringComparison.OrdinalIgnoreCase) && relative == first) return false;
            return !PathGuard.AnyAncestorIsReparsePoint(path, root) && !PathGuard.IsCloudPlaceholder(File.GetAttributes(path));
        }
        return false;
    }
}
