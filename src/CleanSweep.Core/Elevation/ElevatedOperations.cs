using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Elevation;

/// <summary>
/// 服务侧的指令实现。隔离区操作只按 ID 从服务自己的索引解析路径，并核对对象标识与归属用户；
/// 规则清理按规则 ID 重新加载（每次请求重新定位、验签）规则库，用连接方 SID 对应的配置文件目录展开（设计文档 7.4 第 3 条），
/// 只执行"安全"级的文件 / 目录目标，且每个条目的内容必须与界面上用户确认时的快照一致。
/// </summary>
public sealed class ElevatedOperations : IElevatedOperations
{
    /// <summary>每个请求条目的处理结果。</summary>
    public const string StateDone = "done";
    public const string StateChanged = "changed";
    public const string StateSkipped = "skipped";
    public const string StateFailed = "failed";
    public const string StateNotFound = "notfound";
    public const string StateNoSnapshot = "nosnapshot";

    private readonly Quarantine _quarantine;
    private readonly OperationLog _log;
    private readonly Func<PathGuard, RuleLoadResult> _rules;
    private readonly Func<Whitelist> _whitelist;
    private readonly Func<IEnvironmentResolver, PathGuard> _guardFactory;
    private readonly IPreActionRunner _preActions;

    /// <param name="rulesProvider">
    /// 每次请求时按连接方的护栏重新加载规则（服务宿主传入"定位 + 签名校验 + 加载"）：规则文件在服务启动后可能被在线更新替换，
    /// 也可能被同一用户的普通权限进程改动，执行前必须重新校验，不能沿用启动时的副本或直接按路径读文件。
    /// </param>
    /// <param name="whitelistProvider">每次请求重新读白名单（界面加入的排除项要立即生效）。</param>
    /// <param name="preActions">真实的预动作执行器：规则要求先停服务的，服务侧同样要停，不能跳过。</param>
    public ElevatedOperations(Quarantine quarantine, OperationLog log, Func<PathGuard, RuleLoadResult> rulesProvider, Func<Whitelist> whitelistProvider,
        Func<IEnvironmentResolver, PathGuard>? guardFactory = null, IPreActionRunner? preActions = null)
    {
        _quarantine = quarantine;
        _log = log;
        _rules = rulesProvider;
        _whitelist = whitelistProvider;
        _guardFactory = guardFactory ?? (env => new PathGuard(env));
        _preActions = preActions ?? new ServicePreActionRunner();
    }

    /// <summary>用一组已加载的规则与固定白名单（测试用）：每次按其源文件重新加载，不做签名校验；预动作用真实执行器。</summary>
    public ElevatedOperations(Quarantine quarantine, OperationLog log, RuleLoadResult rules, Whitelist whitelist, Func<IEnvironmentResolver, PathGuard>? guardFactory = null, IPreActionRunner? preActions = null)
        : this(quarantine, log, guard => new RuleLoader(guard).LoadFiles(rules.Rules.Select(r => r.SourceFile).Distinct(StringComparer.OrdinalIgnoreCase)), () => whitelist, guardFactory, preActions)
    {
    }

    public string Version { get; init; } = typeof(ElevatedOperations).Assembly.GetName().Version?.ToString(3) ?? "?";

    public ElevationResponse Execute(ElevationRequest request, ElevationClientIdentity client, CancellationToken ct)
    {
        switch (request.Operation)
        {
            case ElevatedOperation.Ping:
                return new ElevationResponse(true, "pong");

            case ElevatedOperation.GetStatus:
                return new ElevationResponse(true, "ok", ElevationProtocol.ToJson(new
                {
                    version = Version,
                    elevated = ProtectedDirectory.IsElevated(),
                    dataDir = AppPaths.DataDir,
                    rules = _rules(_guardFactory(new CurrentUserEnvironmentResolver())).Rules.Count,
                    quarantineItems = _quarantine.ListActive().Count,
                }));

            case ElevatedOperation.PurgeQuarantineItem:
            {
                if (request.ItemId is not { } id) return new ElevationResponse(false, "缺少 itemId");
                var entry = _quarantine.Get(id);
                if (entry is null) return new ElevationResponse(false, "隔离项不存在或已处理");
                if (Authorize(entry, client, request.ItemKey) is { } denied) return new ElevationResponse(false, denied);
                _quarantine.Purge(id);
                _log.Write(null, "elevation", "purge", entry.OriginalPath, entry.SizeBytes, true, client.UserName);
                return new ElevationResponse(true, $"已永久删除隔离项 {id}");
            }

            case ElevatedOperation.RestoreQuarantineItem:
            {
                if (request.ItemId is not { } id) return new ElevationResponse(false, "缺少 itemId");
                var entry = _quarantine.Get(id);
                if (entry is null) return new ElevationResponse(false, "隔离项不存在或已处理");
                if (Authorize(entry, client, request.ItemKey) is { } denied) return new ElevationResponse(false, denied);
                var path = _quarantine.Restore(id);
                _log.Write(null, "elevation", "restore", path, 0, true, client.UserName);
                return new ElevationResponse(true, $"已恢复到 {path}");
            }

            case ElevatedOperation.PurgeExpiredQuarantine:
            {
                var n = _quarantine.PurgeExpired();
                return new ElevationResponse(true, $"淘汰 {n} 项");
            }

            case ElevatedOperation.RunRuleClean:
            {
                var profile = ProfileFor(client);
                IEnvironmentResolver env = profile is null ? new CurrentUserEnvironmentResolver() : new ProfileEnvironmentResolver(profile);
                // 本次移入隔离区的对象都归连接方所有
                var previous = Quarantine.CurrentOwner.Value;
                Quarantine.CurrentOwner.Value = client.Sid.Value;
                try
                {
                    return ExecuteRuleCleanWithEnvironment(request, env, _guardFactory(env), ct);
                }
                finally
                {
                    Quarantine.CurrentOwner.Value = previous;
                }
            }

            default:
                return new ElevationResponse(false, "不支持的指令");
        }
    }

    /// <summary>
    /// 对象级授权：界面给出的对象标识必须与服务索引里的这一条一致（两份索引的数字 ID 撞车时拒绝）；
    /// 记录了归属用户的隔离项只有该用户能恢复 / 删除；没有归属（旧记录）的只允许原位置在连接方自己的配置文件或机器级位置。返回 null 表示允许。
    /// </summary>
    internal static string? Authorize(QuarantineEntry entry, ElevationClientIdentity client, string? itemKey)
    {
        if (itemKey is not null && !string.Equals(Quarantine.ObjectKey(entry), itemKey, StringComparison.OrdinalIgnoreCase))
            return "隔离项标识与服务索引不一致（界面与服务用的不是同一份索引），拒绝操作";
        if (entry.OwnerSid is not null)
            return string.Equals(entry.OwnerSid, client.Sid.Value, StringComparison.OrdinalIgnoreCase) ? null : "隔离项属于其他用户，拒绝操作";
        var profile = ProfileFor(client);
        if (profile is null) return "无法确定连接方的配置文件目录，且隔离项没有归属记录，拒绝操作";
        if (IsUnderUsersButNotProfile(entry.OriginalPath, profile)) return "隔离项原位置属于其他用户的配置文件目录，拒绝操作";
        return null;
    }

    /// <summary>按给定用户环境执行规则清理：规则路径重新校验展开，只执行"安全"级的文件 / 目录目标，且条目内容须与请求里的快照一致。</summary>
    public ElevationResponse ExecuteRuleCleanWithEnvironment(ElevationRequest request, IEnvironmentResolver env, PathGuard guard, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RuleId)) return new ElevationResponse(false, "缺少 ruleId");
        if (request.Items is { Count: > ElevationRequest.MaxItems }) return new ElevationResponse(false, $"items 超过 {ElevationRequest.MaxItems} 个");
        if (request.ItemIds is { Count: > ElevationRequest.MaxItems }) return new ElevationResponse(false, $"itemIds 超过 {ElevationRequest.MaxItems} 个");

        // 规则按连接方的环境与护栏重新加载并重新校验签名：服务启动时用的是 SYSTEM 的环境，展开结果不同；文件也可能已被更新或改动
        var reloaded = _rules(guard);
        var target = reloaded.Rules.FirstOrDefault(r => r.Id.Equals(request.RuleId, StringComparison.OrdinalIgnoreCase));
        if (target is null) return new ElevationResponse(false, $"规则不存在或在连接方环境下校验失败：{request.RuleId}");
        var whitelist = _whitelist();

        // 请求的条目：ID → 用户确认时的内容快照（旧客户端只给 ID，没有快照的条目一律不执行）
        Dictionary<string, string?>? requested = null;
        if (request.Items is { Count: > 0 })
            requested = request.Items.GroupBy(i => i.Id, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Snapshot, StringComparer.OrdinalIgnoreCase);
        else if (request.ItemIds is { Count: > 0 })
            requested = request.ItemIds.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(id => id, _ => (string?)null, StringComparer.OrdinalIgnoreCase);

        var results = new Dictionary<string, ItemResult>(StringComparer.OrdinalIgnoreCase);
        var ctx = new ScanContext { Env = env, Guard = guard, Whitelist = whitelist, Rules = new[] { target } };
        var items = new List<ScanItem>();
        foreach (var scanner in ScannersFor(target.Category, requested is not null))
        {
            foreach (var item in scanner.ScanAsync(ctx, null, ct).GetAwaiter().GetResult().Where(ElevationNeed.ServiceCanRun))
            {
                if (requested is null)
                {
                    items.Add(item);
                    continue;
                }
                if (!requested.TryGetValue(item.Id, out var expected)) continue;
                if (expected is null)
                {
                    results[item.Id] = new ItemResult(item.Id, StateNoSnapshot, "请求没有携带用户确认时的内容快照");
                    continue;
                }
                var current = item.ContentSnapshot();
                if (current is null || !string.Equals(current, expected, StringComparison.OrdinalIgnoreCase))
                {
                    results[item.Id] = new ItemResult(item.Id, StateChanged, "内容与用户确认时不一致（扫描后有新增或变化的文件），请重新扫描");
                    continue;
                }
                items.Add(item);
            }
        }
        if (requested is not null)
            foreach (var id in requested.Keys.Where(id => !results.ContainsKey(id) && !items.Any(i => i.Id.Equals(id, StringComparison.OrdinalIgnoreCase))))
                results[id] = new ItemResult(id, StateNotFound, "服务重新扫描时没有这个条目");

        CleanReport report = new();
        if (items.Count > 0)
        {
            var engine = new CleanEngine(guard, _quarantine, _log, _preActions, whitelist);
            report = engine.CleanAsync(items, null, ct).GetAwaiter().GetResult();
            foreach (var item in items)
            {
                var outcome = report.Outcomes.GetValueOrDefault(item.Id);
                var state = outcome is null || outcome.Untouched ? StateSkipped : outcome.Failed > 0 ? StateFailed : outcome.Skipped > 0 ? StateSkipped : StateDone;
                var reason = state == StateDone ? null : report.Failures.FirstOrDefault(f => f.ItemId == item.Id)?.Reason
                    ?? report.InUseFiles.FirstOrDefault(f => f.ItemId == item.Id)?.Reason
                    ?? (state == StateSkipped ? "有文件被跳过（已变化或在白名单中）" : null);
                var issue = report.Failures.Concat(report.InUseFiles).Concat(report.SkippedDetails).FirstOrDefault(f => f.ItemId == item.Id);
                results[item.Id] = new ItemResult(item.Id, state, issue?.Reason ?? reason, issue?.Kind);
            }
        }

        var payload = ElevationProtocol.ToJson(new RuleCleanPayload(
            report.QuarantinedBytes, report.FilesQuarantined, report.DirectoriesQuarantined,
            results.Values.OrderBy(r => r.ItemId, StringComparer.OrdinalIgnoreCase).ToArray(),
            report.Failures.Select(f => new FailureDto(f.ItemId, f.Path, f.Reason)).Take(50).ToArray()));
        var ok = report.Failures.Count == 0 && results.Values.All(r => r.State == StateDone);
        var message = items.Count == 0 && results.Count == 0
            ? "没有可清理的内容"
            : $"{report.FilesQuarantined} 个文件、{report.DirectoriesQuarantined} 个目录移入隔离区，{results.Values.Count(r => r.State != StateDone)} 个条目未完成";
        return new ElevationResponse(ok, message, payload);
    }

    /// <summary>
    /// 与界面各页使用相同的扫描器 ID（system-junk / app-cache / residue-rules），保证条目 ID 一致。
    /// 指定了条目时应用类规则同时跑"应用缓存"与"残留"两个扫描器（ID 不同，按集合过滤不会重复）；未指定时只跑已安装语义。
    /// </summary>
    private static IEnumerable<RuleScanner> ScannersFor(string category, bool byItems)
    {
        if (category == "system")
        {
            yield return RuleScanner.SystemJunk();
            yield break;
        }
        yield return RuleScanner.AppCache();
        if (byItems) yield return RuleScanner.Residue();
    }

    /// <summary>每个请求条目的明确结果：done / changed / skipped / failed / notfound / nosnapshot。</summary>
    public sealed record ItemResult(string ItemId, string State, string? Reason, CleanIssueKind? Kind = null);

    /// <summary>提权服务执行结果的载荷。</summary>
    public sealed record RuleCleanPayload(long QuarantinedBytes, int Files, int Directories, ItemResult[] Results, FailureDto[] Failures)
    {
        /// <summary>没有明确完成的条目 ID。</summary>
        public string[] Incomplete => Results.Where(r => r.State != StateDone).Select(r => r.ItemId).ToArray();
    }

    public sealed record FailureDto(string ItemId, string? Path, string Reason);

    public static RuleCleanPayload? ParsePayload(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return null;
        try { return System.Text.Json.JsonSerializer.Deserialize<RuleCleanPayload>(payload, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true }); }
        catch { return null; }
    }

    private static string? ProfileFor(ElevationClientIdentity client) =>
        UserProfiles.List().FirstOrDefault(p => p.Sid.Equals(client.Sid.Value, StringComparison.OrdinalIgnoreCase))?.Path;

    private static bool IsUnderUsersButNotProfile(string path, string profile)
    {
        try
        {
            var full = PathGuard.Normalize(path);
            var users = Path.GetDirectoryName(PathGuard.Normalize(profile));
            if (users is null) return false;
            return PathGuard.IsSameOrUnder(full, users) && !PathGuard.IsSameOrUnder(full, PathGuard.Normalize(profile))
                   && !PathGuard.IsSameOrUnder(full, Path.Combine(users, "Public"));
        }
        catch
        {
            return true;
        }
    }
}
