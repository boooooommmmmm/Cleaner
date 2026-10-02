# 更新代码复审的独立探针

日期：2026-09-29。对应报告：[更新代码复审](../../docs/archive/更新代码复审-2026-09-29.md)。

本项目不在 CleanSweep.slnx 中，不修改产品实现。它直接引用当前 Core，并链接原测试工程的 TestEnv。为访问已有 InternalsVisibleTo，程序集名使用 CleanSweep.Core.Tests；输出目录与原测试工程独立。

## 运行

在仓库根目录的 PowerShell 中：

```powershell
dotnet test tools/review-20260929-update/ReviewProbes.csproj --nologo --logger 'trx;LogFileName=review-probes.trx' --results-directory tools/review-20260929-update/results
```

本轮结果：12 通过 / 0 失败 / 0 跳过。**PASS 表示当前缺陷成功复现，修复后应反转对应断言。**

| 报告 | 用例后缀 |
|---|---|
| R01 | ShredHardLink_DestroysUnselectedProtectedFile |
| R02 | BackupPurge_FollowsBackupRootJunction |
| R03 | BackupRestore_AllThreeWritableCopiesCanBeForged |
| R04 | Residue_UnreliableInventoryStillDefaultsFingerprintToSafe |
| R05 | RegistryCleaning_DeletesRepairedEntryFromStaleScan |
| R06 | ElevationRuleClean_IgnoresRequiredServicePreAction |
| R07 | ElevationPurge_DoesNotCheckItemOwner |
| R09 | RegistryGuard_AllowsDeletingAncestorsOfProtectedKeys（两个输入） |
| R10 | TokenPrivileges_ManagedLayoutHasWrongLuidOffset |
| R11 | SystemCommand_UserCancellationDisablesTimeout |
| R12 | TargetedResidueScan_RuleScannerIncludesUnrelatedApplication |

文件写入使用临时 TestEnv；注册表写入使用随机 HKCU 测试子树并在 finally 清理。硬链接/Junction 创建必须成功，失败会令用例失败，不会直接 return 伪装通过。服务相关探针调用操作实现，不安装 Windows 服务，也不表示绕过了管道身份认证。命令探针运行有限次数的本机回环 ping，不执行系统修改。R10 只检查 Marshal 布局，不清理内存。

R08/R13/R14/R15 是报告中的静态审查结论，不运行真实卷擦除、任务删除或硬盘故障测试。

## 证据文件

- results/baseline.trx：原有正式测试，324 通过。
- results/review-probes.trx：本项目 12 个缺陷复现结果。
- source-hashes.json：本轮开始时 155 个源码/规则/原测试文件的 SHA-256；结束时比较一致。
