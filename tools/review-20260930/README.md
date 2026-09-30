# 2026-09-30 三轮复审证据

报告：[三轮代码复审-2026-09-30.md](../../docs/三轮代码复审-2026-09-30.md)。

本目录为独立审查工程，不在产品 solution 中。没有修改产品代码或正式测试。目标框架为 net10.0-windows，依赖 Windows 文件权限和注册表行为；使用已有 TestEnv。AssemblyName 沿用 Core 现有 InternalsVisibleTo 所允许的测试程序集名。

## 结果

| 文件 | 结果 | 解释 |
|---|---|---|
| results/baseline.trx | 353 通过 / 0 失败 / 0 跳过 | 正式测试 |
| results/baseline-final.trx | 360 通过 / 0 失败 / 0 跳过 | 自更新增量提交后的正式测试 |
| results/baseline-working.trx | 359 通过 / 1 失败 / 0 跳过 | 收尾时公钥已轮换、清单未轮换的工作区；正式验签测试失败，见报告 W01 |
| results/previous-probes.trx | 11 通过 / 1 失败 | 原有 12 个缺陷探针重跑；唯一失败说明取消后的超时缺陷已修复 |
| results/round3-probes.trx | 10 通过 / 0 失败 / 0 跳过 | 8 个新缺陷复现 + 2 个正向回归 |
| results/round3-final-probes.trx | 13 通过 / 0 失败 / 0 跳过 | 最终版本：11 个新缺陷复现 + 2 个正向回归 |
| source-hashes.json | 179 个文件 | 审查开始的绝对路径及 SHA-256；结束核对见 source-verification.json |
| source-hashes-final.json | 183 个文件 | 审查期间发现增量提交后固定的最终范围；结束核对见 source-verification.json |
| source-hashes-working.json | 182 个文件 | 收尾签名迁移工作区；gitignore 范围也变化；结束核对见 source-verification.json |

**Repro_ 通过代表缺陷被触发；Regression_ 通过代表预期正确行为成立。** 不要把独立探针全部通过解释为没有问题。

## 新探针映射

| 用例 | 报告 |
|---|---|
| Repro_ServiceRescan_MovesFilesCreatedAfterUserScan | N01 |
| Repro_SeparateIndexes_ForwardedNumericIdPurgesDifferentFile | N02 |
| Repro_ServiceUsesStaleWhitelist_AfterUiAddsPath | N03 |
| Repro_BulkScope_BlocksServiceIndexWriteAfterPayloadDeletion | N04 |
| Repro_RegistrySnapshot_TruncationHidesChangedValue | N05 |
| Repro_UnknownRequestedItem_IsAbsentFromIncompletePayload | N06 |
| Repro_MoveAccessDenied_IsNotTheExceptionCaughtByServiceFallback | N07 |
| Repro_DataUpdate_BodyReadOutlivesHttpTimeout | N08 |
| Repro_AppUpdate_MirrorDeletesFilesOutsideInstallThroughJunction | N11 |
| Repro_AppUpdate_LockedLaterFileLeavesEarlierFileReplaced | N12 |
| Repro_AppUpdate_StagedExecutableCanChangeAfterVerification | N13 |
| Regression_UserCancellation_PreservesCommandTimeout | R11 修复 |
| Regression_VerifiedRuleBytes_AreNotReopenedAfterTampering | 验签后内容不重新打开 |

N09、N10 是静态调用链确认，不在动态用例中。N02/N04/N07 验证实际底层行为，完整 UI/SYSTEM 场景的适用条件见报告，未安装真实服务。

## 命令（从仓库根执行）

```powershell
dotnet build CleanSweep.slnx -c Debug --no-restore --nologo
dotnet build CleanSweep.slnx -c Release --no-restore --nologo
dotnet test tests/CleanSweep.Core.Tests --no-build --no-restore --nologo --logger 'trx;LogFileName=baseline.trx' --results-directory tools/review-20260930/results
dotnet test tools/review-20260929-update/ReviewProbes.csproj --nologo --logger 'trx;LogFileName=previous-probes.trx' --results-directory tools/review-20260930/results
dotnet test tools/review-20260930/ReviewProbes.csproj --nologo --logger 'trx;LogFileName=round3-probes.trx' --results-directory tools/review-20260930/results
dotnet test tests/CleanSweep.Core.Tests --no-build --no-restore --nologo --logger 'trx;LogFileName=baseline-final.trx' --results-directory tools/review-20260930/results
dotnet test tests/CleanSweep.Core.Tests --no-restore --nologo --logger 'trx;LogFileName=baseline-working.trx' --results-directory tools/review-20260930/results
dotnet test tools/review-20260930/ReviewProbes.csproj --nologo --logger 'trx;LogFileName=round3-final-probes.trx' --results-directory tools/review-20260930/results
dotnet list CleanSweep.slnx package --vulnerable --include-transitive --format json
```

旧探针命令预期返回一个测试失败，具体用例为 Repro_SystemCommand_UserCancellationDisablesTimeout。其余复现断言也应在对应产品缺陷修复后改为正向回归；本轮保留旧工程不改动。

测试使用临时目录和随机 HKCU 测试键，结束后清理；ACL 探针恢复原权限。HTTP 测试使用模拟响应流，命令超时使用回环 ping。未运行真实安装/卸载、系统服务修改、计划任务修改、填盘或系统内存清理。
