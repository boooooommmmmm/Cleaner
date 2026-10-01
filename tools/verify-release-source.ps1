# 发布必须能由指定提交重建；SDK 默认编译未跟踪的 .cs，因此也检查未跟踪文件。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $RepositoryRoot
try {
    $revision = git rev-parse --verify HEAD
    if ($LASTEXITCODE -ne 0) { throw '无法确定发布提交' }
    $status = @(git -c core.quotepath=false status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw '无法读取工作区状态' }
    # 只有本次生成的发布元数据可以未提交，其余源文件、配置和脚本必须属于该提交。
    $dirty = @($status | Where-Object { $_.Length -ge 3 -and $_.Substring(3) -ne 'release/latest.json' })
    if ($dirty.Count -gt 0) {
        throw "发布工作区含未提交或未跟踪文件，请先提交需要发布的内容：`n$($dirty -join "`n")"
    }
    $revision.Trim()
}
finally { Pop-Location }
