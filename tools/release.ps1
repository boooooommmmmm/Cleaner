# 打一个可自动更新的发布：publish → zip → 用数据签名密钥生成 release/latest.json。
# 用法：powershell -File tools/release.ps1 -Repo owner/CleanSweep [-Version 0.14.0] [-Notes "..."] [-Key <私钥.pem>] [-KeyId release-2026-09]
# 私钥默认读 %USERPROFILE%\.cleansweep\keys\release-signing-key.pem，不在仓库里。
# 之后：
#   1. git add release/latest.json && git commit && git push          （程序从 raw.githubusercontent.com/<repo>/main/release/latest.json 读发布信息）
#   2. 在 GitHub 上创建 tag v<版本> 的 Release，把 publish/CleanSweep-win-x64-<版本>.zip 作为附件上传（地址必须与 latest.json 里的 url 一致）
param(
    [Parameter(Mandatory = $true)][string]$Repo,
    [string]$Version = "",
    [string]$Notes = "",
    [string]$Key = (Join-Path $env:USERPROFILE ".cleansweep\keys\release-signing-key.pem"),
    [string]$KeyId = "release-2026-09",
    [string]$Rid = "win-x64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & (Join-Path $PSScriptRoot "publish.ps1") -Rid $Rid
    if ($LASTEXITCODE -ne 0) { throw "publish failed" }
    $exe = "publish/$Rid/CleanSweep.exe"
    if ($Version -eq "") { $Version = ((Get-Item $exe).VersionInfo.ProductVersion -split "\+")[0] }
    $asset = "CleanSweep-$Rid-$Version.zip"
    $zip = "publish/$asset"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path "publish/$Rid/*" -DestinationPath $zip -CompressionLevel Optimal
    $url = "https://github.com/$Repo/releases/download/v$Version/$asset"
    dotnet run --project tools/CleanSweep.SignData -c Release -- sign-release $Version $zip $url release/latest.json $Key $KeyId $Notes
    if ($LASTEXITCODE -ne 0) { throw "sign-release failed" }
    Write-Host ""
    Write-Host "已生成 $zip 与 release/latest.json。接下来："
    Write-Host "  git add release/latest.json; git commit -m 'release v$Version'; git push"
    Write-Host "  在 GitHub 创建 Release v$Version 并上传 $zip（下载地址须为 $url）"
}
finally {
    Pop-Location
}
