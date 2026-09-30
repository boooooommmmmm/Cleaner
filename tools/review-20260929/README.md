# 2026-09-29 独立审查复现

此目录保留审查证据，不属于产品解决方案。

**13 个 `Repro_` 用例通过表示成功观察到当前缺陷。修复后应将其反转为安全回归断言，不能把这里的绿色结果当作安全验收通过。**

- 报告：[全量审查](../../docs/全量审查-2026-09-29.md)
- 原有测试结果：`results/baseline.trx`（167 通过）
- 复现结果：`results/review-probes.trx`（13 通过）
- 源码哈希：`source-hashes.json`（86 个源文件/配置，排除 bin/obj）

运行：

```powershell
dotnet test tools/review-20260929/ReviewProbes.csproj --nologo --logger 'trx;LogFileName=review-probes.trx' --results-directory tools/review-20260929/results
```

要求 Windows、.NET 10 SDK。用例使用临时 TestEnv 文件目录、内存数据库和专用随机 HKCU 测试键；不运行真实服务停止或计划任务变更。测试键在 finally 中删除。中断进程可能留下测试临时目录/测试键。

独立项目使用与原测试相同的程序集名称以访问现有 InternalsVisibleTo；它不修改正式项目，也未加入解决方案。AppSettings 以链接源文件方式检查；重复文件用例执行真实 Core 流程并核对界面使用的条件，没有进行 WPF 对话框自动化。延迟任务用例只验证名称冲突，未向系统注册任务。
