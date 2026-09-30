using CleanSweep.Core.Environment;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Uninstall;

namespace CleanSweep.Core.Residue;

public sealed class ResidueOptions
{
    /// <summary>扫描本机全部用户账户的配置文件（需要管理员权限）。</summary>
    public bool ScanAllUsers { get; set; }

    /// <summary>无法归属的目录：超过此天数无修改 → 疑似残留。</summary>
    public int SuspectedAfterDays { get; set; } = 180;

    /// <summary>无法归属的目录：超过此天数无修改 → 未知（折叠显示，仅高级模式）。</summary>
    public int UnknownAfterDays { get; set; } = 90;

    /// <summary>空目录多少天未修改视为残留。</summary>
    public int EmptyDirectoryAfterDays { get; set; } = 30;

    /// <summary>只针对某个应用做定向扫描（卸载后即时扫描）。</summary>
    public string? OnlyAppName { get; set; }
}

/// <summary>
/// 用户目录残留清理（设计文档 3.3）：扫描 %LocalAppData%、%AppData%、%LocalAppDataLow%、Packages、Programs、
/// 用户目录点目录与指纹库指定的位置，用 App Inventory、指纹库、卸载历史、目录活跃度四类信号交叉判定，按应用聚合输出。
/// 硬性排除（系统目录、重解析点、凭据目录）在引擎层写死，规则库与用户都不能覆盖。
/// </summary>
public sealed class ResidueScanner : IScanner
{
    public const string ModuleId = "residue";

    private static readonly HashSet<string> ExcludedLocal = new(StringComparer.OrdinalIgnoreCase)
    {
        "Temp", "ConnectedDevicesPlatform", "Comms", "PlaceholderTileLogoFolder", "D3DSCache", "VirtualStore", "Publishers",
        "PeerDistRepub", "History", "Temporary Internet Files", "Application Data", "CrashDumps", "Microsoft Help", "IsolatedStorage",
        "Deployment", "Apps", "ElevatedDiagnostics", "Diagnostics", "OneDrive", "Microsoft Edge", "MicrosoftEdge", "PenWorkspace",
        "Packages", "Programs", "Microsoft",
    };

    private static readonly HashSet<string> ExcludedRoaming = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Identities", "Application Data", "Local Settings",
    };

    /// <summary>用户目录下的凭据 / 密钥目录：永不列出。</summary>
    private static readonly HashSet<string> ExcludedProfileDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ssh", ".aws", ".azure", ".kube", ".gnupg", ".config", "Contacts", "Links", "Searches", "OneDrive",
    };

    /// <summary>Packages 下的系统包家族（前缀）或系统包发布者。</summary>
    private static readonly string[] SystemPackagePrefixes =
    {
        "Microsoft.Windows.", "MicrosoftWindows.", "Microsoft.Windows", "windows.immersivecontrolpanel", "Microsoft.AAD", "Microsoft.Win32WebViewHost",
        "Microsoft.MicrosoftEdge", "Microsoft.LockApp", "Microsoft.XboxGameCallableUI", "Microsoft.AccountsControl", "Microsoft.AsyncTextService",
        "Microsoft.BioEnrollment", "Microsoft.CredDialogHost", "Microsoft.ECApp", "Microsoft.PPIProjection", "Microsoft.UI.Xaml", "Microsoft.VCLibs",
        "Microsoft.NET.", "Microsoft.WindowsAppRuntime", "Microsoft.DesktopAppInstaller", "Microsoft.WindowsStore", "Microsoft.StorePurchaseApp",
        "Microsoft.SecHealthUI", "Microsoft.Windows.SecHealthUI", "Microsoft.MicrosoftEdgeDevToolsClient", "Microsoft.549981C3F5F10", "MicrosoftWindows.Client",
        "Microsoft.Windows.ShellExperienceHost", "Microsoft.Windows.StartMenuExperienceHost", "Microsoft.Windows.Search", "Microsoft.Windows.CloudExperienceHost",
        "Microsoft.Windows.ContentDeliveryManager", "Microsoft.Windows.Photos", "Microsoft.WindowsCalculator", "Microsoft.WindowsNotepad", "Microsoft.Paint",
        "Microsoft.ScreenSketch", "Microsoft.WindowsTerminal", "Microsoft.WebMediaExtensions", "Microsoft.WebpImageExtension", "Microsoft.HEIFImageExtension",
        "Microsoft.VP9VideoExtensions", "Microsoft.RawImageExtension", "Microsoft.HEVCVideoExtension", "Microsoft.AV1VideoExtension", "Microsoft.MPEG2VideoExtension",
    };

    private static readonly HashSet<string> KnownVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Google", "Mozilla", "JetBrains", "Adobe", "Tencent", "Netease", "Baidu", "Autodesk", "Apple Computer", "Apple", "Sun", "Oracle", "Intel",
        "NVIDIA", "NVIDIA Corporation", "AMD", "Realtek", "Logitech", "Razer", "Corsair", "Samsung", "Huawei", "Xiaomi", "Kingsoft", "Sogou", "Alibaba",
        "ByteDance", "Epic Games", "Ubisoft", "Electronic Arts", "EA Games", "Blizzard", "Blizzard Entertainment", "Bethesda Softworks", "CD Projekt Red",
        "Rockstar Games", "Riot Games", "2K", "2K Games", "Bandai Namco", "Paradox Interactive", "Valve", "Wondershare", "Xunlei", "Thunder Network",
        "Youdao", "Kuaishou", "Bilibili", "iQIYI", "Youku", "Kugou", "QQMusic", "Meitu", "Foxit Software", "Foxit", "TechSmith", "Dell", "HP", "Lenovo", "ASUS", "MSI",
    };

    private readonly AppInventory _inventory;
    private readonly AppFingerprintDb _fingerprints;
    private readonly UninstallHistory? _history;
    private readonly ResidueOptions _options;
    private readonly Action<string, string>? _log;

    public ResidueScanner(AppInventory inventory, AppFingerprintDb fingerprints, UninstallHistory? history, ResidueOptions options, Action<string, string>? log = null)
    {
        _inventory = inventory;
        _fingerprints = fingerprints;
        _history = history;
        _options = options;
        _log = log;
    }

    public string Id => ModuleId;
    public string DisplayName => "用户目录残留清理";

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run(() => Scan(ctx, progress, ct), ct);

    private sealed class Profile
    {
        public required IEnvironmentResolver Env { get; init; }
        public required PathGuard Guard { get; init; }
        public required bool IsCurrent { get; init; }
        public required string Tag { get; init; }
        public required Dictionary<string, AppFingerprint> FingerprintIndex { get; init; }
        public required HashSet<string> RuleCovered { get; init; }
    }

    private sealed class State
    {
        public required ScanContext Ctx { get; init; }
        public required InventorySnapshot Inventory { get; init; }
        public required IReadOnlyList<UninstallRecord> History { get; init; }
        public required List<ScanItem> Items { get; init; }
        public required IProgress<ScanProgress>? Progress { get; init; }
        public long Bytes;
    }

    private IReadOnlyList<ScanItem> Scan(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var inv = _inventory.Last is { } last && (DateTime.UtcNow - last.TakenUtc) < TimeSpan.FromMinutes(2) ? last : _inventory.Scan(ct);
        var history = _history?.List(500) ?? Array.Empty<UninstallRecord>();
        var state = new State { Ctx = ctx, Inventory = inv, History = history, Items = new List<ScanItem>(), Progress = progress };

        if (!inv.RegistryReliable)
            _log?.Invoke("inventory", $"注册表卸载项只读到 {inv.RegistryCount} 条，本次不把“未找到卸载项”当作已卸载的证据");

        ScanProfile(MakeProfile(ctx.Env, ctx.Guard, isCurrent: true, tag: "me", ctx), state, ct);

        if (_options.ScanAllUsers && ProtectedDirectory.IsElevated())
        {
            var profiles = UserProfiles.List();
            foreach (var p in profiles.Where(p => !p.IsCurrentUser && !p.IsSystemAccount && Directory.Exists(p.Path)))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var env = new ProfileEnvironmentResolver(p.Path);
                    ScanProfile(MakeProfile(env, new PathGuard(env), isCurrent: false, tag: p.Sid, ctx), state, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { _log?.Invoke("profile " + p.Path, ex.Message); }
            }

            if (ctx.Env.Variables.TryGetValue("SystemDrive", out var sysDrive))
            {
                foreach (var orphan in UserProfiles.FindOrphans(Path.Combine(sysDrive + "\\", "Users"), profiles))
                {
                    ct.ThrowIfCancellationRequested();
                    Emit(state, ctx.Guard, orphan.Path, "已删除的用户账户", "profile",
                        "Users 目录下的这个配置文件目录不属于任何现有账户（ProfileList 中无记录），账户已删除但目录遗留", RiskLevel.High, ct, forceHigh: true);
                }
            }

            ScanProgramData(state, ctx, ct);
        }

        var items = state.Items;
        if (!string.IsNullOrWhiteSpace(_options.OnlyAppName))
        {
            items = items.Where(i => NameKey.Matches(i.Group.Replace(" 残留", ""), _options.OnlyAppName)
                                     || NameKey.Matches(Path.GetFileName(i.Path ?? ""), _options.OnlyAppName)).ToList();
        }

        progress?.Report(new ScanProgress(Id, null, items.Count, items.Sum(i => i.SizeBytes)));
        return items;
    }

    private Profile MakeProfile(IEnvironmentResolver env, PathGuard guard, bool isCurrent, string tag, ScanContext ctx)
    {
        var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in ctx.Rules)
        {
            foreach (var t in rule.Targets.Where(t => t.When == RuleWhen.Uninstalled && t.RawPath is not null))
            {
                if (env.TryExpand(t.RawPath!, out var full, out _))
                {
                    try { covered.Add(PathGuard.Normalize(full)); } catch { }
                }
            }
        }
        return new Profile { Env = env, Guard = guard, IsCurrent = isCurrent, Tag = tag, FingerprintIndex = _fingerprints.IndexByPath(env), RuleCovered = covered };
    }

    // ---------- 单个用户配置文件 ----------

    private void ScanProfile(Profile p, State s, CancellationToken ct)
    {
        var v = p.Env.Variables;
        var roots = new List<(string Path, HashSet<string> Excluded)>();
        if (v.TryGetValue("LocalAppData", out var local)) roots.Add((local, ExcludedLocal));
        if (v.TryGetValue("AppData", out var roaming)) roots.Add((roaming, ExcludedRoaming));
        if (v.TryGetValue("LocalAppDataLow", out var low)) roots.Add((low, ExcludedRoaming));

        foreach (var (root, excluded) in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var dir in p.Guard.EnumerateDirectories(root))
            {
                ct.ThrowIfCancellationRequested();
                s.Progress?.Report(new ScanProgress(Id, dir.FullName, s.Items.Count, s.Bytes));
                var name = dir.Name;

                if (name.Equals("Microsoft", StringComparison.OrdinalIgnoreCase))
                {
                    // 系统自身目录：只处理指纹库明确列出的子目录（Teams 之类），其余一律不碰
                    foreach (var child in p.Guard.EnumerateDirectories(dir.FullName))
                    {
                        if (p.FingerprintIndex.TryGetValue(PathGuard.Normalize(child.FullName), out var fp))
                            ClassifyFingerprint(p, s, child.FullName, fp, ct);
                    }
                    continue;
                }
                if (name.Equals("Packages", StringComparison.OrdinalIgnoreCase) && string.Equals(root, local, StringComparison.OrdinalIgnoreCase))
                {
                    if (p.IsCurrent) ScanPackages(p, s, dir.FullName, ct);
                    continue;
                }
                if (name.Equals("Programs", StringComparison.OrdinalIgnoreCase) && string.Equals(root, local, StringComparison.OrdinalIgnoreCase))
                {
                    ScanPrograms(p, s, dir.FullName, ct);
                    continue;
                }
                if (excluded.Contains(name)) continue;

                Classify(p, s, dir.FullName, allowVendorDescent: true, ct);
            }
        }

        // 指纹库指定但不在上述三个根之下的位置：用户目录点目录、Documents 下的存档目录等
        foreach (var (path, fp) in p.FingerprintIndex)
        {
            ct.ThrowIfCancellationRequested();
            if (roots.Any(r => PathGuard.IsSameOrUnder(path, PathGuard.Normalize(r.Path)))) continue;
            if (!Directory.Exists(path) && !File.Exists(path)) continue;
            if (ExcludedProfileDirs.Contains(Path.GetFileName(path))) continue;
            ClassifyFingerprint(p, s, path, fp, ct);
        }
    }

    // ---------- 判定 ----------

    private void Classify(Profile p, State s, string dir, bool allowVendorDescent, CancellationToken ct)
    {
        string full;
        try { full = PathGuard.Normalize(dir); } catch { return; }
        if (s.Ctx.Whitelist.IsPathExcluded(full)) return;
        if (PathGuard.IsReparsePoint(full)) return;
        var name = Path.GetFileName(full);
        if (ExcludedProfileDirs.Contains(name)) return;

        // 规则库里有 when=uninstalled 目标覆盖这里：交给规则（更精确，带风险等级与说明）
        if (p.RuleCovered.Contains(full) || p.RuleCovered.Any(c => PathGuard.IsSameOrUnder(c, full))) return;

        if (p.FingerprintIndex.TryGetValue(full, out var fp))
        {
            ClassifyFingerprint(p, s, full, fp, ct);
            return;
        }

        var inv = s.Inventory;

        // 厂商目录（Google\Chrome、JetBrains\IntelliJIdea2023.1）：按产品子目录分别判定
        if (allowVendorDescent && (KnownVendors.Contains(name) || inv.IsPublisher(name)))
        {
            foreach (var child in p.Guard.EnumerateDirectories(full))
            {
                ct.ThrowIfCancellationRequested();
                Classify(p, s, child.FullName, allowVendorDescent: false, ct);
            }
            return;
        }

        // 信号 A + B：目录名对应已安装应用 / 在安装位置内 / 有进程在跑 → 活跃
        if (inv.FindByName(name) is not null) return;
        if (inv.FindByInstallLocation(full) is not null) return;
        if (inv.HasRunningProcessUnder(full)) return;

        // 卸载记录：最强的"已卸载"证据，不受目录新旧影响
        if (_history?.FindByName(name, s.History) is { } rec)
        {
            Emit(s, p.Guard, full, rec.Name, p.Tag, $"该应用已于 {rec.TsUtc.ToLocalTime():yyyy-MM-dd} 卸载（卸载记录），目录为遗留数据", RiskLevel.Safe, ct);
            return;
        }

        // 目录内程序文件的版本信息
        var exe = AppInventory.FindMainExecutable(full);
        if (exe is not null)
        {
            var (product, company, _) = AppInventory.ReadVersionInfo(exe);
            if (product is not null && inv.FindByName(product) is not null) return;
            if (product is not null && inv.RegistryReliable)
            {
                Emit(s, p.Guard, full, product, p.Tag,
                    $"目录内程序文件的版本信息属于“{product}”{(company is null ? "" : $"（{company}）")}，系统中未找到该应用的安装记录", RiskLevel.Confirm, ct);
                return;
            }
        }

        // 信号 C：活跃度
        ClassifyByActivity(p, s, full, null, ct);
    }

    private void ClassifyByActivity(Profile p, State s, string full, string? appName, CancellationToken ct)
    {
        var (size, count, last, fingerprint) = p.Guard.FingerprintDirectory(full, ct);
        DateTime lastWrite;
        try { lastWrite = last ?? Directory.GetLastWriteTimeUtc(full); } catch { return; }
        var age = DateTime.UtcNow - lastWrite;

        if (count == 0)
        {
            if (age.TotalDays >= _options.EmptyDirectoryAfterDays)
                EmitMeasured(s, p.Guard, full, appName ?? "空目录", p.Tag, $"空目录，{(int)age.TotalDays} 天未修改", RiskLevel.Safe, size, count, lastWrite, fingerprint);
            return;
        }
        if (age.TotalDays >= _options.SuspectedAfterDays)
        {
            EmitMeasured(s, p.Guard, full, appName, p.Tag, $"无法识别归属，{(int)age.TotalDays} 天无任何写入，疑似残留", RiskLevel.Confirm, size, count, lastWrite, fingerprint);
        }
        else if (age.TotalDays >= _options.UnknownAfterDays)
        {
            EmitMeasured(s, p.Guard, full, appName, p.Tag, $"无法识别归属，{(int)age.TotalDays} 天无写入，归属未知", RiskLevel.NotRecommended, size, count, lastWrite, fingerprint);
        }
        // 90 天内有写入：活跃，不列出
    }

    private void ClassifyFingerprint(Profile p, State s, string path, AppFingerprint fp, CancellationToken ct)
    {
        string full;
        try { full = PathGuard.Normalize(path); } catch { return; }
        if (s.Ctx.Whitelist.IsPathExcluded(full)) return;
        if (PathGuard.IsReparsePoint(full)) return;
        if (!Directory.Exists(full)) return; // 指纹里的单个文件（.condarc、.npmrc）体积可忽略，不单独列

        var installed = AppFingerprintDb.IsInstalled(fp, s.Inventory, p.Env, out var usesRegistry, out var usesUwp);
        if (installed == true) return;

        // 清单读取不可靠时，"清单里没找到"不能当作已卸载的证据：降级为无法判定，只提示不默认勾选
        var inventoryUnreliable = installed == false && ((usesRegistry && !s.Inventory.RegistryReliable) || (usesUwp && !s.Inventory.UwpReliable));
        if (inventoryUnreliable) installed = null;

        var reason = installed is null
            ? (inventoryUnreliable ? $"已安装软件清单读取不完整，无法确认“{fp.App}”是否已卸载，仅提示" : "指纹库未定义检测方式，无法判定应用是否仍在使用，仅提示")
            : $"指纹库命中“{fp.App}”，检测为未安装";
        if (fp.Note is not null) reason += "。" + fp.Note.TrimEnd('。');

        var risk = installed is null ? RiskLevel.High : RiskLevel.Safe;
        if (fp.Has(FingerprintFlags.License)) { risk = Max(risk, RiskLevel.Confirm); reason += "；重装可能依赖此配置恢复许可证"; }
        if (fp.Has(FingerprintFlags.LoginState)) { risk = Max(risk, RiskLevel.Confirm); reason += "；含登录态或聊天记录"; }
        if (fp.Has(FingerprintFlags.ProgramBody)) { risk = Max(risk, RiskLevel.Confirm); reason += "；属于程序本体或 SDK，删除后需重新下载"; }
        if (fp.Has(FingerprintFlags.GameSaves)) { risk = RiskLevel.High; reason += "；可能含游戏存档"; }

        Emit(s, p.Guard, full, fp.App, p.Tag, reason, risk, ct);
    }

    private static RiskLevel Max(RiskLevel a, RiskLevel b) => a >= b ? a : b;

    // ---------- Packages / Programs ----------

    private void ScanPackages(Profile p, State s, string packagesDir, CancellationToken ct)
    {
        var inv = s.Inventory;
        if (!inv.UwpReliable)
        {
            _log?.Invoke("packages", "没有读到任何已安装的应用商店包，跳过 Packages 目录判定");
            return;
        }
        foreach (var dir in p.Guard.EnumerateDirectories(packagesDir))
        {
            ct.ThrowIfCancellationRequested();
            var pfn = dir.Name;
            if (SystemPackagePrefixes.Any(prefix => pfn.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))) continue;
            if (pfn.EndsWith("_cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase)) continue; // 系统应用发布者
            if (!pfn.Contains('_')) continue;
            if (inv.IsPackageFamilyInstalled(pfn)) continue;
            if (s.Ctx.Whitelist.IsPathExcluded(dir.FullName)) continue;

            var appName = pfn.Split('_')[0];
            Emit(s, p.Guard, dir.FullName, appName, p.Tag, "应用商店包已卸载，这是它遗留的应用数据目录", RiskLevel.Safe, ct);
        }
    }

    private void ScanPrograms(Profile p, State s, string programsDir, CancellationToken ct)
    {
        var inv = s.Inventory;
        foreach (var dir in p.Guard.EnumerateDirectories(programsDir))
        {
            ct.ThrowIfCancellationRequested();
            var full = PathGuard.Normalize(dir.FullName);
            if (s.Ctx.Whitelist.IsPathExcluded(full)) continue;
            if (p.RuleCovered.Contains(full)) continue;
            if (p.FingerprintIndex.TryGetValue(full, out var fp))
            {
                ClassifyFingerprint(p, s, full, fp, ct);
                continue;
            }
            if (inv.FindByInstallLocation(full) is not null) continue;
            if (inv.HasRunningProcessUnder(full)) continue;
            if (inv.FindByName(dir.Name) is { Source: not AppSource.Portable }) continue;

            if (_history?.FindByName(dir.Name, s.History) is { } rec)
            {
                Emit(s, p.Guard, full, rec.Name, p.Tag, $"该应用已于 {rec.TsUtc.ToLocalTime():yyyy-MM-dd} 卸载（卸载记录），程序目录遗留", RiskLevel.Confirm, ct);
                continue;
            }

            // 便携软件本体：只按活跃度判定，绝不因为"没有卸载项"就当成残留
            ClassifyByActivity(p, s, full, null, ct);
        }
    }

    // ---------- ProgramData ----------

    private static readonly HashSet<string> ExcludedProgramData = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Package Cache", "Packages", "USOShared", "USOPrivate", "SoftwareDistribution", "ssh", "Application Data", "Desktop", "Documents",
        "Start Menu", "Templates", "Favorites", "regid.1991-06.com.microsoft", "WindowsHolographicDevices", "Comms", "Oracle", "NVIDIA", "NVIDIA Corporation",
        "Intel", "AMD", "Realtek", "Dell", "HP", "Lenovo", "boot", "chocolatey", "scoop", "WinGet", "Docker", "DockerDesktop", "Miniconda3", "Anaconda3",
    };

    private void ScanProgramData(State s, ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Env.Variables.TryGetValue("ProgramData", out var pd) || !Directory.Exists(pd)) return;
        foreach (var dir in ctx.Guard.EnumerateDirectories(pd))
        {
            ct.ThrowIfCancellationRequested();
            if (ExcludedProgramData.Contains(dir.Name)) continue;
            var full = PathGuard.Normalize(dir.FullName);
            if (ctx.Whitelist.IsPathExcluded(full)) continue;
            var inv = s.Inventory;
            if (inv.FindByName(dir.Name) is not null || inv.IsPublisher(dir.Name)) continue;
            if (inv.FindByInstallLocation(full) is not null || inv.HasRunningProcessUnder(full)) continue;

            if (_history?.FindByName(dir.Name, s.History) is { } rec)
            {
                Emit(s, ctx.Guard, full, rec.Name, "programdata", $"该应用已于 {rec.TsUtc.ToLocalTime():yyyy-MM-dd} 卸载（卸载记录），ProgramData 下的全局数据遗留", RiskLevel.Confirm, ct);
                continue;
            }
            // ProgramData 下的目录常含许可证与全局配置：最多判为"疑似"
            var (size, count, last, fingerprint) = ctx.Guard.FingerprintDirectory(full, ct);
            DateTime lastWrite;
            try { lastWrite = last ?? Directory.GetLastWriteTimeUtc(full); } catch { continue; }
            var age = DateTime.UtcNow - lastWrite;
            if (count > 0 && age.TotalDays >= _options.SuspectedAfterDays)
                EmitMeasured(s, ctx.Guard, full, null, "programdata", $"ProgramData 下无法识别归属的目录，{(int)age.TotalDays} 天无写入，疑似残留（可能含许可证或全局配置）", RiskLevel.Confirm, size, count, lastWrite, fingerprint);
        }
    }

    // ---------- 输出 ----------

    private void Emit(State s, PathGuard guard, string full, string? appName, string tag, string reason, RiskLevel risk, CancellationToken ct, bool forceHigh = false)
    {
        var (size, count, last, fingerprint) = guard.FingerprintDirectory(full, ct);
        DateTime lastWrite;
        try { lastWrite = last ?? Directory.GetLastWriteTimeUtc(full); } catch { lastWrite = DateTime.UtcNow; }
        EmitMeasured(s, guard, full, appName, tag, reason, forceHigh ? RiskLevel.High : risk, size, count, lastWrite, fingerprint);
    }

    private void EmitMeasured(State s, PathGuard guard, string full, string? appName, string tag, string reason, RiskLevel risk,
        long size, int count, DateTime lastWrite, string fingerprint)
    {
        var verdict = guard.Check(full);
        if (!verdict.Allowed) return;

        // 已知用户文件夹（Documents、Saved Games…）与 OneDrive 接管目录：只提示，标红
        var v = guard.EnvVariables;
        if (v.TryGetValue("UserProfile", out var profile))
        {
            foreach (var known in new[] { "Documents", "Desktop", "Pictures", "Videos", "Music", "Downloads", "Saved Games", "OneDrive" })
            {
                if (PathGuard.IsSameOrUnder(full, Path.Combine(profile, known)))
                {
                    risk = RiskLevel.High;
                    reason += $"；位于“{known}”文件夹内，可能含用户文件";
                    break;
                }
            }
        }
        if (IsCloudManaged(full))
        {
            risk = RiskLevel.High;
            reason += "；目录由 OneDrive 等云盘接管，删除会同步到云端";
        }

        var profileNote = tag is "me" or "programdata" ? "" : tag == "profile" ? "" : $"（其他用户 {Path.GetFileName(Path.GetPathRoot(full) is { } r && full.Length > r.Length ? ProfileOf(full) : full)}）";
        var group = appName is null ? "疑似残留（未识别归属）" : appName + " 残留";
        var item = new ScanItem
        {
            Id = RuleScanner.MakeId(ModuleId, tag, full),
            ModuleId = ModuleId,
            Group = group,
            DisplayName = Path.GetFileName(full) + profileNote,
            Kind = ItemKind.Directory,
            Path = full,
            SizeBytes = size,
            Risk = risk,
            Description = $"{reason}。{count:N0} 个文件，最后修改 {lastWrite.ToLocalTime():yyyy-MM-dd}，整个目录移入隔离区",
            LastWriteUtc = lastWrite,
            DirectoryFingerprint = fingerprint,
            DirectoryFileCount = count,
        };
        s.Items.Add(item);
        s.Bytes += size;
    }

    /// <summary>C:\Users\name\... → name。</summary>
    private static string ProfileOf(string full)
    {
        var parts = full.Split('\\');
        var idx = Array.FindIndex(parts, p => p.Equals("Users", StringComparison.OrdinalIgnoreCase));
        return idx >= 0 && idx + 1 < parts.Length ? parts[idx + 1] : full;
    }

    private static bool IsCloudManaged(string full)
    {
        try
        {
            var attr = File.GetAttributes(full);
            if (PathGuard.IsCloudPlaceholder(attr)) return true;
            // 目录本身通常不带占位属性，看它的父链里是否有 OneDrive 目录
            return full.Split('\\').Any(seg => seg.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }
}
