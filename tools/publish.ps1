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
    # 安装清单：自更新时只替换 / 删除这里列出的文件，安装目录里用户放的其他文件不动
    $outFull = (Resolve-Path $Out).Path.TrimEnd('\')
    $manifest = Join-Path $outFull "install-files.txt"
    $files = Get-ChildItem -Path $outFull -Recurse -File -Attributes !ReparsePoint |
        Where-Object { $_.Name -ne "install-files.txt" } |
        ForEach-Object { $_.FullName.Substring($outFull.Length + 1) } | Sort-Object
    $lines = @("# CleanSweep 安装清单：本程序拥有的文件。更新时只替换 / 删除这里列出的文件。") + $files
    [System.IO.File]::WriteAllLines($manifest, $lines, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "已发布到 $Out（$($files.Count) 个文件，安装清单 install-files.txt）"
}
finally {
    Pop-Location
}
