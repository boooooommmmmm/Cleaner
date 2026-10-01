using CleanSweep.Core.Integrity;
using CommunityToolkit.Mvvm.ComponentModel;

namespace CleanSweep.App.Services;

/// <summary>启动检查与手动更新共用：先下载验签，准备好后才询问安装。</summary>
public sealed partial class AppUpdateCoordinator : ObservableObject
{
    private readonly Func<CancellationToken, Task<AppUpdateCheck>> _check;
    private readonly Func<ReleaseInfo, IProgress<(long Done, long Total)>, CancellationToken, Task<string>> _download;
    private readonly Func<ReleaseInfo, string, Task<bool>> _confirm;
    private readonly Func<string, string?> _launch;
    private readonly Action _shutdown;
    private readonly Func<ReleaseInfo, string, Task<bool>> _validate;
    private readonly HashSet<string> _prompted = new();
    private string? _zip;
    private int _generation;
    private CancellationTokenSource? _workCancellation;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private ReleaseInfo? _readyRelease;
    public bool InstallationStarted { get; private set; }

    public AppUpdateCoordinator(Func<CancellationToken, Task<AppUpdateCheck>> check,
        Func<ReleaseInfo, IProgress<(long Done, long Total)>, CancellationToken, Task<string>> download,
        Func<ReleaseInfo, string, Task<bool>> confirm, Func<string, string?> launch, Action shutdown,
        Func<ReleaseInfo, string, Task<bool>>? validate = null)
    {
        _check = check; _download = download; _confirm = confirm; _launch = launch; _shutdown = shutdown;
        _validate = validate ?? ((release, zip) => Task.Run(() =>
            ReleaseManifest.VerifyPreparedAsset(release, zip) is null));
    }

    public void ResetSource()
    {
        _generation++;
        _workCancellation?.Cancel();
        ReadyRelease = null;
        _zip = null;
        _prompted.Clear();
        Status = "更新来源已改变，请重新检查。";
    }

    public async Task CheckAndPrepareAsync(bool promptAgain = false, CancellationToken ct = default)
    {
        if (IsBusy || InstallationStarted) return;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _workCancellation = cancellation;
        ct = cancellation.Token;
        IsBusy = true;
        var generation = _generation;
        var downloading = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            Status = "正在检查程序更新…";
            var result = await _check(ct);
            ct.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            if (!result.Available || result.Release is not { } release)
            {
                // 没有通过验签的发布信息通常表示网络或来源失败，不能据此撤销已准备好的更新。
                if (result.Release is null && ReadyRelease is not null && _zip is not null)
                {
                    Status = result.Message + "；保留已下载更新，可在设置中安装。";
                    return;
                }
                ReadyRelease = null;
                _zip = null;
                Status = result.Message;
                return;
            }
            var cached = ReadyRelease is { } ready && Identity(ready) == Identity(release) && _zip is not null
                && await _validate(release, _zip);
            ct.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            if (!cached)
            {
                ReadyRelease = null;
                _zip = null;
                Status = $"正在后台下载 {release.Version.ToString(3)}…";
                downloading = true;
                var progress = new Progress<(long Done, long Total)>(p =>
                {
                    if (generation == _generation && downloading)
                        Status = $"正在后台下载… {p.Done / 1048576.0:0.#} / {p.Total / 1048576.0:0.#} MB";
                });
                var zip = await _download(release, progress, ct);
                downloading = false;
                ct.ThrowIfCancellationRequested();
                if (generation != _generation) return;
                _zip = zip;
            }
            ReadyRelease = release;
            Status = $"新版本 {release.Version.ToString(3)} 已下载并校验，可安装。";
            if (promptAgain || !_prompted.Contains(Identity(release))) await ConfirmAndInstallAsync(generation, ct);
        }
        catch (OperationCanceledException) { if (generation == _generation) Status = "更新下载已取消，可重新检查。"; }
        catch (Exception ex) { if (generation == _generation) Status = "更新检查或下载失败：" + ex.Message; }
        finally { downloading = false; _workCancellation = null; IsBusy = false; }
    }

    public async Task InstallPreparedAsync()
    {
        if (IsBusy || InstallationStarted || ReadyRelease is null || _zip is null) return;
        IsBusy = true;
        try { await ConfirmAndInstallAsync(_generation); }
        catch (Exception ex) { Status = "更新失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    private async Task ConfirmAndInstallAsync(int generation, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var release = ReadyRelease;
        var zip = _zip;
        if (release is null || zip is null) return;
        // A previously downloaded package may have disappeared or changed while the user deferred.
        var valid = await _validate(release, zip);
        ct.ThrowIfCancellationRequested();
        if (!valid)
        {
            if (generation != _generation) return;
            ReadyRelease = null;
            _zip = null;
            Status = "下载包已丢失或校验失败，请重新检查更新。";
            return;
        }
        if (generation != _generation) return;
        _prompted.Add(Identity(release));
        var accepted = await _confirm(release, zip);
        ct.ThrowIfCancellationRequested();
        if (generation != _generation) return;
        if (!accepted) { Status = $"新版本 {release.Version.ToString(3)} 已下载，稍后可在设置中安装。"; return; }
        Status = "正在启动更新安装…";
        var error = _launch(zip);
        if (error is not null) { Status = "安装未开始：" + error; return; }
        InstallationStarted = true;
        _shutdown();
    }

    private static string Identity(ReleaseInfo release) => $"{release.Version}|{release.Asset}|{release.Sha256}|{release.Url}";
}
