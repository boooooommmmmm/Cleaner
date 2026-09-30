# 为 rules / fingerprints / popups 重新生成签名清单。改过任何数据文件后必须运行，否则程序拒绝加载该数据集。
# 用法：powershell -File tools/sign-data.ps1 [-Version N] [-Key <私钥.pem>] [-KeyId release-2026-09]
# 私钥不在仓库里：默认读 %USERPROFILE%\.cleansweep\keys\release-signing-key.pem（用 CleanSweep.SignData keygen 生成，公钥写进 Integrity/TrustedKeys.cs）。
param(
    [int]$Version = 0,
    [string]$Key = (Join-Path $env:USERPROFILE ".cleansweep\keys\release-signing-key.pem"),
    [string]$KeyId = "release-2026-09"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    dotnet build tools/CleanSweep.SignData -c Debug --nologo -v q | Out-Null
    foreach ($kind in "rules", "fingerprints", "popups") {
        $v = $Version
        if ($v -le 0) {
            # 默认在现有版本号上加 1
            $manifest = Join-Path $kind "manifest.json"
            $v = 1
            if (Test-Path $manifest) { $v = (Get-Content $manifest -Raw | ConvertFrom-Json).version + 1 }
        }
        dotnet run --project tools/CleanSweep.SignData -c Debug --no-build -- sign $kind $kind $v $Key $KeyId
    }
}
finally {
    Pop-Location
}
