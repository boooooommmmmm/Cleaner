# 发布自包含版本（目标机不需要安装 .NET 运行时）。
# 用法：powershell -File tools/publish.ps1 [-Rid win-x64|win-arm64] [-Out publish/win-x64]
param(
    [string]$Rid = "win-x64",
    [string]$Out = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ($Out -eq "") { $Out = "publish/$Rid" }
Push-Location $root
try {
    foreach ($proj in "src/CleanSweep.App", "src/CleanSweep.Service") {
        dotnet publish $proj -c Release -r $Rid --self-contained true -p:PublishReadyToRun=true -o $Out --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "publish $proj failed" }
    }
    # 发布前自检：三个数据集的签名必须通过
    foreach ($kind in "rules", "fingerprints", "popups") {
        dotnet run --project tools/CleanSweep.SignData -c Release -- verify (Join-Path $Out $kind) $kind
        if ($LASTEXITCODE -ne 0) { throw "$kind manifest verification failed" }
    }
    Write-Host "已发布到 $Out"
}
finally {
    Pop-Location
}
