# Windows 系统清理软件 · 产品功能设计

- 版本：v0.18（M1 到 M6 全部实现，发布前横切工作与 GitHub 自更新完成并已真实跑通一次自更新；四份外部审查共 56 条发现全部处理；规则通配目录段与两轮数据覆盖扩展；两轮真机反馈修复：占用文件按跳过计、磁盘操作提权判定、更新来源默认官方仓库、卸载程序缺失时移除登记项；累计十四轮代码评审）
- 日期：2026-09-30
- 状态：功能与横切工作均已实现，数据集与发布信息已用正式密钥签名，v0.15.0 已发布到 GitHub Release；仍需 EV 代码签名证书，以及在虚拟机以管理员身份做端到端验收，见文末变更记录与 README“发布与安装”
- 变更记录见文末第 12 节

---

## 1. 产品定位

面向 Windows 10（1809 及以上）/ Windows 11 个人用户与开发者的一体化系统清理与优化工具。目标是覆盖 CCleaner、360 安全卫士、腾讯电脑管家、Wise Care 365、BleachBit 等主流产品的核心能力，并在以下三点形成差异：

1. **安全优先**：先扫描后清理，三级风险标注，所有操作可回滚。
2. **残留清理做深**：用户目录与注册表的已卸载应用残留识别，是市面产品普遍薄弱的环节。
3. **无捆绑、无弹窗、无广告、不上传用户数据**：托盘常驻可选，不强制。

**明确不做的事**：不做"一键加速"类伪优化（工作集压缩、Prefetch 清空、注册表"提速"），不做进程注入与系统钩子。这些功能收益存疑且是杀毒软件误报的主要来源。

---

## 2. 功能总览

优先级含义：P0 / P1 为 1.0 正式版必须包含，P2 为 1.x 迭代，P3 为储备。构建顺序见第 8 节，两者不一一对应。

| 分类 | 模块 | 优先级 | 构建阶段 |
|---|---|---|---|
| 清理 | 系统垃圾清理 | P0 | M1 |
| 清理 | 浏览器与应用缓存清理 | P0 | M1 |
| 清理 | 大文件、重复文件与空间分析 | P0 | M1 |
| 优化 | 开机加速 | P0 | M2 |
| 清理 | 用户目录残留清理 | P0 | M3 |
| 管理 | 软件卸载与残留追踪 | P0 | M3 |
| 清理 | 注册表与僵尸配置清理 | P1 | M4 |
| 清理 | 隐私清理与文件粉碎 | P1 | M4 |
| 优化 | 磁盘健康与优化 | P2 | M5 |
| 优化 | 内存与进程管理 | P2 | M5 |
| 优化 | 系统优化项 | P2 | M5 |
| 管理 | 驱动与更新管理 | P2 | M6 |
| 管理 | 弹窗与广告拦截 | P2 | M6 |
| 管理 | 系统修复 | P2 | M6 |
| 管理 | 其他实用工具 | P3 | M6 |

---

## 3. 清理类模块

### 3.1 系统垃圾清理

**扫描项**

| 项目 | 风险等级 | 说明 |
|---|---|---|
| Windows 临时目录、用户 Temp | 安全 | 跳过正在被占用的文件 |
| 缩略图缓存、图标缓存、字体缓存 | 安全 | 删除后系统会重建，收益小但无害 |
| 系统日志、错误报告（WER）、CBS 日志 | 安全 | |
| 内存转储（minidump、MEMORY.DMP） | 安全 | 用户若正在排查蓝屏应保留，说明中提示 |
| 回收站 | 安全 | 通过 Shell API 清空，不直接操作 `$Recycle.Bin` |
| Delivery Optimization 缓存、Defender 扫描历史 | 安全 | |
| `SoftwareDistribution\Download` | 安全 | 需先停止 wuauserv，清理后重启服务 |
| `$WinREAgent` | 建议确认 | 更新中途存在时删除会导致更新失败 |
| `Windows.old` | 建议确认 | 删除后**无法回退到上一个 Windows 版本**，说明中必须写明 |
| WinSxS 组件清理 | 建议确认 | 调用 `DISM /Online /Cleanup-Image /StartComponentCleanup`。执行后**已安装的更新不可卸载**。不使用 `/ResetBase` |
| Installer 孤立补丁包 | 高风险 | `C:\Windows\Installer` 中无对应产品的 .msp / .msi。误判会导致相关软件无法修复或卸载，默认不勾选 |
| Prefetch 预读取 | 不建议 | 清空后系统需重新学习，短期内启动更慢。仅在"高级"模式下可见，默认隐藏 |

**设计要点**

- 每项显示体积、说明、风险等级
- 扫描阶段只统计，不打开文件内容，保证秒级出结果

### 3.2 浏览器与应用缓存清理

**浏览器**：Chrome、Edge、Firefox、Brave、Opera 及其他 Chromium 内核浏览器

- 按项勾选：缓存、Cookie、历史、下载记录、表单数据、会话、Service Worker 缓存
- 多 Profile 支持
- 浏览器运行中时提示关闭，或跳过被锁定的文件并在结果中标注

**常见应用**：微信、QQ、钉钉、企业微信、Steam、Epic、Adobe 系列、Office、VS Code、JetBrains 系列，以及 Java / npm / pip / NuGet / Gradle / Maven 等开发工具缓存

**规则驱动**

- 清理规则以 JSON 规则库描述（借鉴 CCleaner 社区 winapp2.ini 思路），格式见 7.3
- 规则包含：应用检测条件、清理路径、文件通配、风险等级、说明
- 规则库可在线更新，更新包必须经签名校验（见 6.2）

### 3.3 用户目录残留清理

本产品的重点差异化模块，解决"应用已卸载，但配置、缓存、日志仍散落在用户目录中"的问题。

#### 3.3.1 扫描范围

| 位置 | 典型内容 | 特点 |
|---|---|---|
| `%LocalAppData%` | 缓存、日志、Electron 应用数据 | 体积最大，残留最多 |
| `%AppData%`（Roaming） | 配置、账号、插件 | 体积小，数量多 |
| `%LocalAppData%\Temp` | 安装器解包、崩溃转储 | 可直接清 |
| `%LocalAppData%\Packages` | UWP 应用数据 | 需比对已装 UWP 列表 |
| `%LocalAppData%\Programs` | 用户级安装的程序本体 | 卸载后常整目录遗留 |
| `%UserProfile%` 根目录下的点目录 | `.vscode` `.gradle` `.m2` `.nuget` `.android` `.docker` `.cache` | 开发者机器上可达几十 GB |
| `%UserProfile%\Documents` | 游戏存档、工程文件 | 高风险，只提示不默认勾选 |
| `Saved Games`、`Pictures`、`Videos` 下的应用子目录 | 截图、录屏、存档 | 只提示 |
| `%Public%` | 公共账户下的应用数据 | 少见但存在 |
| `%ProgramData%` | 全局配置、许可证、日志 | 严格说不属于用户目录，但性质相同，归入本模块。需管理员权限 |

**硬性排除**（引擎层内置，规则库不可覆盖）：

- 用户目录中的 Junction 与符号链接（如 `Application Data`、`Local Settings`、`My Documents` 等兼容性重解析点）**只识别，绝不进入，绝不删除**
- 系统自身目录：`Microsoft\Windows`、`Microsoft\Edge`（由 3.2 处理）、`Packages` 下 `Microsoft.Windows.*` / `MicrosoftWindows.*` 系统包、`ConnectedDevicesPlatform`、`Comms`、`PlaceholderTileLogoFolder`、`D3DSCache`
- 用户自定义白名单

#### 3.3.2 "已卸载"判定：多信号交叉

单靠目录名匹配误判率高，采用四类信号交叉判定。

**信号 A：已安装软件库（App Inventory，见 7.2）**

- 注册表 Uninstall 键（HKLM / HKCU，含 WOW6432Node）：DisplayName、Publisher、InstallLocation、UninstallString
- UWP：PackageManager API 取包全名与发布者
- 便携软件：扫描常见目录下的 exe，读取版本信息中的 CompanyName / ProductName
- 正在运行的进程与服务对应的可执行路径

**信号 B：目录归属识别**

- 目录名与 ProductName / Publisher 归一化匹配（大小写、空格、下划线、连字符）
- 目录内 exe / dll 的版本信息（残留程序本体的情况）
- 配置文件特征：Electron 的 `Preferences`、Java 的 `.properties`、`.ini` 中的产品名
- 内置**应用指纹库**：目录名 → 应用 → 卸载检测方式。例如 `.gradle` → 检查 PATH 中是否有 gradle，且 Android Studio / IntelliJ 是否已安装

**信号 C：活跃度（仅对信号 B 无法归属的目录生效）**

- 90 天内有写入：视为活跃，不列出
- 90 到 180 天无写入：未知，折叠显示
- 180 天以上无写入：疑似残留
- 有进程持有该目录下文件的句柄：无论时间，视为活跃

信号 C 不作用于已通过信号 A + B 确认归属的目录。例如昨天刚卸载的应用，其目录最近修改时间很新，但仍应判为"确认残留"。

**信号 D：排除规则**

- 3.3.1 中的硬性排除列表
- 用户自定义白名单
- 指纹库中标记为"重装依赖此配置"的应用（如许可证缓存），自动降为"建议确认"

**判定结果分三级**

| 等级 | 条件 | 默认状态 |
|---|---|---|
| 确认残留 | 信号 B 找到归属应用，且信号 A 判定已卸载；或指纹库命中且检测为未安装 | 勾选 |
| 疑似残留 | 信号 B 无法归属，且信号 C 判定 180 天以上无修改 | 不勾选，展示体积 |
| 活跃 / 未知 | 其他 | 折叠显示或不列出 |

#### 3.3.3 展示与操作

- **按应用聚合**而非按目录：一个"Adobe Photoshop 残留"条目下列出其在多个位置的目录与总体积
- 每条显示：应用名、厂商、判定依据（如"注册表中未找到卸载项"）、最后修改时间、体积
- "查看内容"按钮直接打开资源管理器供用户核实
- 清理动作默认**移入隔离区**（见 6.1），不直接删除
- "以后忽略此应用"加入白名单

#### 3.3.4 配套能力

- **卸载后即时残留扫描**：监听三类卸载事件，触发后对该应用定向扫描并提示
  - 注册表 Uninstall 键变更（`RegNotifyChangeKeyValue`，HKLM / HKCU / WOW6432Node）
  - Windows Installer 事件日志：MsiInstaller 事件 ID 1034（产品已移除）
  - UWP：PackageManager 卸载事件
  - 定向扫描准确率远高于全盘扫描，是最佳入口。**此功能要求后台进程常驻**，用户开启时需明确告知，默认关闭
- **开发者模式**：单独页面处理 `.gradle`、`.m2`、`.nuget`、`node_modules`、pip cache、Docker 镜像、conda 环境，支持"仅清缓存不清配置"。Docker Desktop 的 WSL 虚拟磁盘（`ext4.vhdx`）只显示体积，不提供删除
- **多用户支持**：管理员可扫描 `C:\Users` 下所有账户，以及已删除账户遗留的整个 Profile 目录（通过 ProfileList 注册表比对）
- **游戏存档保护**：匹配知名游戏目录，即使确认卸载也标红提醒"可能含存档"

#### 3.3.5 风险提示

- Electron 类应用（微信、钉钉、Discord）配置目录常含登录态与聊天记录，清理前明确提示
- 部分软件重装依赖残留配置恢复许可证，指纹库中标记此类应用
- OneDrive 接管的 Documents / Desktop / Pictures 目录，删除会同步到云端。检测 `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` 或 OneDrive 已知根目录并警示

### 3.4 注册表与僵尸配置清理

**定位**：注册表清理的目的是**移除已卸载软件的残留配置**，不是提速。微软官方立场是注册表清理对性能无可测量影响，产品文案中不得宣称"加速"。

**扫描项**

| 项目 | 风险等级 |
|---|---|
| 无效卸载项（UninstallString 指向不存在的文件） | 安全 |
| 失效的开始菜单与桌面 `.lnk`（目标不存在） | 安全 |
| MUI 缓存中不存在的可执行文件项 | 安全 |
| 已卸载软件遗留的 `HKCU\Software`、`HKLM\Software` 子键（复用 App Inventory 判定） | 建议确认 |
| 失效文件关联、失效的应用路径（App Paths） | 建议确认 |
| 指向不存在可执行文件的服务项与计划任务 | 建议确认 |
| 失效 COM / ActiveX 注册 | 高风险 |
| 失效的共享 DLL 计数 | 高风险，删除可能破坏 MSI 修复与卸载流程 |

**安全机制**

- 清理前自动导出 `.reg` 备份，支持一键还原
- 默认只勾选"安全"级
- 与 3.3 共用 App Inventory，同一应用的文件残留与注册表残留在界面上聚合展示

### 3.5 大文件、重复文件与空间分析

- **空间分析器**：TreeMap 可视化（参考 WizTree / SpaceSniffer）。管理员权限下 NTFS 卷直接读 MFT 加速，非管理员或非 NTFS 卷回退到常规枚举
- **重复文件查找**：先按大小分组，再按首尾 64KB 哈希初筛，最后全量哈希确认
  - 跳过带 `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` 的云端占位文件，否则会触发 OneDrive 全量下载
  - 比较文件 ID（`FILE_ID_INFO`）排除硬链接，同一文件的多个链接不算重复
  - 排除 `Windows`、`Program Files`、`System Volume Information`
- **大文件扫描**：可自定义阈值，按类型（视频、镜像、压缩包、虚拟机磁盘）分类
- **空文件夹清理**：排除重解析点与系统保留目录

### 3.6 隐私清理与文件粉碎

- 最近使用文件记录、跳转列表（Jump List）、运行历史、剪贴板历史
- Windows 活动历史、时间线、搜索历史、诊断数据
- 文件粉碎：多次覆写防恢复，支持右键菜单集成
  - **SSD 上覆写不保证擦除**（磨损均衡会保留旧块）。检测到 SSD 时明确提示，建议依赖 BitLocker 加密与 TRIM
- 空闲空间擦除：仅在机械盘上提供

---

## 4. 性能优化类模块

### 4.1 开机加速

**管理范围**

- 注册表 Run / RunOnce（HKLM / HKCU / WOW6432Node）
- 启动文件夹（用户与公共）
- 计划任务中的登录触发项
- 服务（自动启动 / 延迟自动启动）。**微软自带服务默认隐藏**，高级模式才显示
- Shell 扩展、浏览器助手对象
- UWP 应用的 StartupTask

**每项展示**

- 启动耗时与影响评级。数据来源：`%LocalAppData%\Microsoft\Windows\StartupInfo\*.xml`（任务管理器同源）与 Diagnostics-Performance 事件日志（事件 ID 100 到 110）
- 厂商、数字签名状态、可执行路径
- 建议：保留 / 可禁用 / 建议禁用

**操作**

- 禁用 / 启用：写入 `StartupApproved` 注册表键，与任务管理器状态保持同步，**不删除原 Run 值**
- 删除：仅在用户明确要求时，删除前备份
- **延迟启动**：转换为登录后延迟 N 秒的计划任务
- 开机时间统计与历史趋势图

### 4.2 磁盘健康与优化

**取舍说明**：Windows 8 起系统自带每周自动优化（机械盘整理、SSD TRIM），自研碎片整理引擎收益低。本模块定位为**健康监控 + 接管系统优化计划**，不自研整理算法。

- 介质识别：机械盘 / SSD / NVMe，展示系统优化计划状态与上次执行时间，可手动触发 `defrag.exe` 对应操作
- **禁止对 SSD 做碎片整理**，硬性约束
- S.M.A.R.T. 健康检测与预警（通过 WMI `MSStorageDriver_FailurePredictStatus` 或直接 IOCTL）
- `chkdsk` 调度（下次重启时执行）
- 启动时整理 MFT / 页面文件 / 注册表 hive：需要 BootExecute 原生应用，复杂度高、收益低，**不做**

### 4.3 内存与进程管理

**取舍说明**：清理工作集（`EmptyWorkingSet`）会导致后续页错误，实际拖慢系统，**不做**。

- 待机列表清理（Standby List purge）：对内存紧张的游戏场景有一定价值，作为可选工具提供，不宣传为"加速"
- 高占用进程识别与一键结束。系统关键进程与受保护进程不可结束
- UWP 后台应用权限管理

### 4.4 系统优化项

- 服务优化：每项附风险说明与恢复方式，**不提供"一键全关"**
- 视觉效果、电源计划、虚拟内存、`hiberfil.sys` 开关（关闭休眠会同时禁用快速启动，需提示）
- 网络：DNS 缓存刷新、Winsock 重置（需重启）、TCP 参数
- 右键菜单管理、Windows 搜索索引范围管理

---

## 5. 管理工具类模块

### 5.1 软件卸载与残留追踪

- **强力卸载**：调用官方卸载程序后，自动扫描文件与注册表残留（复用 3.3、3.4 引擎）
- 批量卸载、UWP 应用卸载、预装软件（Bloatware）移除
- **安装监控**：安装前快照文件系统与注册表，之后可精确回滚
- 与 3.3 是同一引擎的两个入口

### 5.2 驱动与更新管理

- 驱动备份 / 还原
- 旧版本驱动包清理：`pnputil /enum-drivers` 识别同一硬件的多个旧版本包，仅删除非当前使用版本
- Windows 更新：暂停、卸载补丁、清理更新缓存

### 5.3 弹窗与广告拦截

**实现约束**：不做进程注入、不做全局钩子。这两种手段会被杀毒软件误报，也会引发与被拦截方的对抗。

- 方式一：定时枚举顶层窗口，按规则库（进程名 + 窗口类名 + 标题特征）匹配后关闭
- 方式二：对已知的独立弹窗进程（如 `xxxPopup.exe`），通过 IFEO（Image File Execution Options）阻止其启动。用户可随时恢复
- 规则库在线更新，签名校验

### 5.4 系统修复

- 一键运行 `sfc /scannow`、`DISM /Online /Cleanup-Image /RestoreHealth`
- 修复文件关联、图标缓存、右键菜单、任务栏、Windows 商店（`wsreset`）等常见故障
- Hosts 文件管理

### 5.5 其他实用工具

- 文件恢复（误删除）
- 软件搬家：C 盘迁移到其他盘，用目录 Junction 保持兼容。**限制**：UWP 应用不适用（应引导用户使用系统设置中的"移动"功能）；部分软件的更新器会校验路径而失败，指纹库中标记已知不兼容软件
- 系统信息与硬件检测面板
- 桌面整理

---

## 6. 安全与体验设计原则

这一部分决定产品口碑，所有模块必须遵守。

### 6.1 用户可见的安全机制

1. **先扫描后清理**：任何模块都不允许"一键直接删"，必须先呈现结果
2. **三级风险标注**：安全 / 建议确认 / 高风险。默认只勾选"安全"级。另有"不建议"级仅在高级模式显示
3. **隔离区**：所有文件删除先移入隔离区
   - 默认保留 30 天，体积上限取卷容量 10% 与 20 GB 中的较小值，超限时按时间淘汰
   - 每个卷独立隔离目录，同卷内移动为重命名操作，零拷贝、瞬时完成
   - 隔离区索引存 SQLite，记录原路径、权限 ACL、时间戳，恢复时原样还原
4. **注册表自动备份**：每次注册表修改导出 `.reg`，保留历史
5. **系统还原点**：涉及服务、驱动、系统优化项的操作前创建。注意 Windows 默认 24 小时内只允许创建一个还原点（`SystemRestorePointCreationFrequency`），且系统保护可能被禁用。创建失败时降级为注册表备份 + 隔离区，并在界面提示
6. **白名单机制**：用户可永久排除文件、目录、注册表键、应用
7. **定时 / 开机自动清理可选**：自动模式只执行"安全"级项目
8. **操作日志**：所有清理与修改记录可查、可导出。操作按事务记录，进程崩溃后可识别半完成状态并提示用户恢复或继续
9. **无捆绑、无弹窗广告、托盘常驻可选、不上传任何用户数据**。规则库更新只下载不上传

### 6.2 引擎层硬性约束（规则库与用户均不可覆盖）

1. **永不跟随重解析点**：递归遍历与删除遇到 Junction、符号链接、挂载点时只处理链接本身，绝不进入目标。这是清理软件历史上最常见的毁盘事故来源
2. **系统保护路径列表**：`Windows`（除明确列出的缓存子目录）、`Program Files*` 根、`System Volume Information`、`$Recycle.Bin`（只经 Shell API 操作）、EFI 分区、所有卷根目录，任何规则不得以这些路径为删除目标
3. **规则路径校验**：规则中的路径必须以已知环境变量开头，经规范化后不得包含 `..`，不得解析到保护路径。不通过校验的规则整条拒绝加载
4. **规则库与指纹库签名**：更新包附带签名，公钥内置于程序。签名校验失败则拒绝更新并继续使用旧版。更新通道为 HTTPS 且固定证书
5. **SSD 禁止碎片整理**
6. **删除前二次核对**：执行删除时重新检查文件是否仍符合扫描时的判定（路径、大小、时间未变），防止扫描到执行之间的文件变化

---

## 7. 技术架构

### 7.1 技术选型

| 层 | 选型 | 理由 |
|---|---|---|
| 目标系统 | Windows 10 1809+ / Windows 11，x64 与 ARM64 | .NET 10 不支持 Windows 7 / 8.1，Win7 市占已低于 3%，不再兼容 |
| 核心引擎 | C# / .NET 10 LTS（关键路径可用 C++ 原生模块） | 需要 Win32 API、WMI、注册表、提权。开发机未安装 .NET 8 SDK，且 .NET 10 为当前 LTS |
| UI | WPF + CommunityToolkit.Mvvm | 已选定。WPF 成熟稳定、依赖少 |
| 规则库 | JSON 规则文件 + 签名 | 无需发版即可更新 |
| 权限模型 | 分阶段：M1 至 M2 单进程 UAC 提权；M3 起引入提权服务 | 见 7.4 |
| 本地数据 | SQLite | 存历史、隔离区索引、白名单、App Inventory 缓存 |
| 打包与签名 | MSIX 或 Inno Setup；**EV 代码签名证书** | 清理软件是杀毒软件误报重灾区，EV 签名可直接建立 SmartScreen 信誉 |

### 7.2 核心公共服务

以下服务被多个模块复用，需在架构层单独抽出：

| 服务 | 职责 | 使用方 |
|---|---|---|
| **App Inventory** | 维护已安装软件清单（注册表、UWP、便携软件、进程） | 残留清理、注册表清理、强力卸载、启动项识别 |
| **App Fingerprint DB** | 目录名 / 注册表键 → 应用的指纹库，含卸载检测方式与风险标记 | 残留清理、注册表清理、软件搬家 |
| **Rule Engine** | 加载、校验（6.2 第 3 条）、执行 JSON 清理规则 | 系统垃圾、应用缓存、弹窗拦截 |
| **Quarantine** | 隔离区管理：移入、恢复、过期清理、体积上限 | 所有删除操作 |
| **Backup & Restore** | 系统还原点、注册表备份、降级策略 | 注册表、服务、驱动相关模块 |
| **Scan Scheduler** | 并行扫描调度、进度汇报、取消 | 所有扫描模块 |
| **Path Guard** | 重解析点识别、保护路径校验、环境变量按目标用户解析 | 所有文件操作 |
| **Elevation Service** | 提权服务进程（M3 起） | 所有需要管理员权限的操作 |

### 7.3 规则库格式示意

```json
{
  "id": "vscode",
  "app": "Visual Studio Code",
  "publisher": "Microsoft",
  "detect": {
    "anyOf": [
      { "registry": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1" },
      { "file": "%LocalAppData%\\Programs\\Microsoft VS Code\\Code.exe" }
    ]
  },
  "targets": [
    {
      "path": "%AppData%\\Code\\Cache",
      "pattern": "*",
      "recurse": true,
      "risk": "safe",
      "when": "installed",
      "description": "编辑器缓存，可安全删除"
    },
    {
      "path": "%AppData%\\Code\\User",
      "pattern": "*",
      "recurse": true,
      "risk": "high",
      "when": "uninstalled",
      "description": "用户设置与快捷键，仅在应用已卸载时建议删除"
    }
  ]
}
```

**语义说明**

- `detect` 决定应用当前是否已安装
- `when: "installed"` 的 target 仅在 detect 成功时生效，归入 3.2 应用缓存清理
- `when: "uninstalled"` 的 target 仅在 detect 失败时生效，归入 3.3 用户目录残留清理
- `when: "always"` 两种情况均生效
- 所有 `path` 在加载时经 Path Guard 校验，失败则整条规则拒绝加载
- `path` 的目录段可含通配符 `*`（v0.16 起，如 `User Data\Profile *\Cache`、`Packages\*\TempState`、`JetBrains\*\caches`）：只匹配所在父目录的直接子目录，不递归，跳过重解析点，最多 200 个；通配符不能出现在环境变量段与最后一段，也不能紧跟环境变量（`%LocalAppData%\*\Cache` 拒绝）；加载时用占位名校验整条模板与静态前缀（前缀只豁免"范围过大"一条），扫描时每个展开出的具体路径再过一次护栏。每个匹配目录生成独立条目，条目名带匹配到的段（"网页缓存（Profile 1）"），条目 ID 按具体路径计算，提权服务重扫得到同样的 ID
- `exclude`（v0.17 起，可选）：按文件名排除的通配模式列表（如 `["TileCache_*"]`），只对 `files` 目标有效，模式不得含路径分隔符、不得为 `*`；用于目录里长期被进程独占、清了也只会报"正在使用"的文件，扫描时直接不列入
- 清理时被其他程序独占的文件按"跳过"计数（`CleanReport.InUse`），不算失败，条目保留在列表里，关闭占用程序后重新扫描即可

### 7.4 权限模型与提权服务

**分阶段策略**

- M1 至 M2：整个应用以管理员身份运行（UAC 提权一次）。实现简单，足以支撑垃圾清理、缓存清理、启动项管理
- M3 起：引入提权服务，UI 回到普通权限。原因是卸载事件监听、定时清理需要在无用户交互时运行

**提权服务安全要求**（服务以 SYSTEM 运行，任何缺陷都是本地提权漏洞）

1. 命名管道 ACL 限定为 Administrators 组与创建该服务的交互用户 SID；每次连接校验客户端进程的 SID 与可执行文件签名
2. 服务只接受**枚举型指令**（如"清理隔离区中 ID 为 X 的项"、"执行规则 Y"），不接受任意路径的删除请求
3. 用户目录路径由服务侧根据传入的用户 SID 解析（`%AppData%` 等环境变量在 SYSTEM 上下文中指向 SYSTEM 自己的 Profile，直接展开是错误的）
4. 服务的所有文件操作经 Path Guard 与 6.2 全部约束
5. 服务可执行文件与配置目录 ACL 仅允许 SYSTEM 与 Administrators 写入

---

## 8. 构建路线

| 阶段 | 范围 | 目标 |
|---|---|---|
| **M1** | 系统垃圾清理、浏览器与应用缓存清理、空间分析、隔离区、Path Guard、规则引擎 | 覆盖 80% 使用场景，同时把安全基础设施建好 |
| **M2** | 开机加速、白名单、还原点与注册表备份、操作日志 | 补齐可回滚能力 |
| **M3** | App Inventory、指纹库、用户目录残留清理、强力卸载、提权服务、卸载事件监听 | 建立差异化能力 |
| **M4** | 注册表清理、隐私清理 | 依赖 M3 的 App Inventory。**M4 完成即 1.0 发布** |
| **M5** | 磁盘健康、内存与进程管理、系统优化项 | 1.x 迭代 |
| **M6** | 驱动管理、弹窗拦截、系统修复、其他工具 | 1.x 迭代 |

---

## 9. 非功能需求与测试策略

### 9.1 非功能需求

| 项 | 目标 |
|---|---|
| 扫描性能 | 系统垃圾扫描 10 秒内出结果；用户目录残留全量扫描 60 秒内（500 GB 系统盘、10 万目录基准） |
| 内存 | 常驻后台进程小于 30 MB；扫描峰值小于 300 MB |
| 启动 | 主界面 2 秒内可交互 |
| 隐私 | 不采集任何用户数据。崩溃报告仅在用户主动提交时发送 |
| 误报率 | 每个发布版本在测试镜像集上"确认残留"误判率为零，"疑似残留"误判率低于 5% |
| 可恢复性 | 任何清理操作在隔离期内 100% 可恢复 |

### 9.2 测试策略

- **金样镜像集**：一组虚拟机快照，预装再卸载数十种常见软件（含 Electron、Java、游戏、Adobe、国产软件），作为残留识别的回归基准。每条指纹规则至少对应一个镜像样例
- **毁盘防护测试**：在用户目录中人工构造指向 `C:\Windows`、其他用户目录、网络位置的 Junction 与符号链接，验证任何模块均不进入
- **规则校验测试**：构造含 `..`、卷根、保护路径的恶意规则，验证全部被拒绝加载
- **提权服务安全测试**：以非管理员用户、其他会话用户尝试连接管理管道，验证拒绝
- **杀毒软件兼容测试**：每个发布版本在 Defender、火绒、360、卡巴斯基下验证无误报

---

## 10. 待决问题

- [ ] 是否做多语言，首发语言范围。建议首发简体中文 + 英文
- [ ] 商业模式：免费 / 免费加专业版 / 开源。影响是否需要账号体系
- [ ] ARM64 是否首发支持

已决定：

- 规则库、指纹库、弹窗规则与程序本身的更新渠道采用 GitHub（raw 数据文件 + Release 附件），签名清单与发布信息均由 release-2026-09 密钥签发（v0.14–v0.16）；不自建服务端
- UI 框架采用 WPF（v0.3）
- 运行时采用 .NET 10 LTS 而非 .NET 8（v0.3）

- 不支持 Windows 7 / 8.1（.NET 10 不兼容，见 7.1）
- 隔离区默认 30 天、卷容量 10% 与 20 GB 取小（见 6.1）

---

## 11. 术语

| 术语 | 含义 |
|---|---|
| 残留 | 应用卸载后遗留在文件系统或注册表中的数据 |
| 隔离区 | 本软件自建的可恢复删除暂存区，区别于系统回收站 |
| App Inventory | 已安装软件清单服务 |
| 指纹库 | 目录名 / 注册表键到应用的映射规则集 |
| 重解析点 | NTFS Junction、符号链接、挂载点的统称 |
| 高级模式 | 显示"不建议"级项目与微软自带服务的界面模式 |

---

## 12. 变更记录

### v0.18（2026-09-30）第二轮真机反馈：自动更新"不生效"、卸载程序不存在时的出路

**自动更新不生效的根因是设置项默认为空**（`AppSettings.UpdateSource` 此前默认 `""`，启动时后台检查与设置页都直接跳过，用户不手填仓库地址就永远不会检查）。修复与验证（回归 UpdateSourceAndRemoveEntryTests，共 428 测试；程序版本 0.16.1）：

- `UpdateSources.Default = "boooooommmmmm/Cleaner"`：设置为空按官方仓库解析，`AppSettings.Normalize` 清空即恢复默认；不想检查更新用"启动时在后台检查更新"开关。设置页说明文字同步。
- GitHub 仓库形式的来源带备用根 `cdn.jsdelivr.net/gh/<owner>/<repo>@<branch>`（`FallbackDataBaseUrl` / `FallbackReleaseInfoUrl`）：raw.githubusercontent.com 在部分网络里连不上，`AppServices` 在主地址"获取发布信息失败 / 超时、下载清单失败 / 更新超时"（`UpdateSources.IsNetworkFailure`，内容无效不算）时用镜像再试一次，两次都失败把两个原因一起显示。镜像只是搬运，签名清单与发布信息的校验不变。
- **真实跑通一次自更新**：把 v0.15.0 发布包解压到临时目录、设置来源后启动：启动提示"有新版本 0.16.0"且规则库自动更新到版本 5；点"下载并安装"→ 确认 → 约 15 秒内下载 60 MB、校验、安装目录里的旧程序复验并暂存、新程序替换后以 0.16.0 重启，目录里没有 `.update-stage` / `.update-backup` 残留。README 已知限制里"自更新真实下载安装待验证"取消（管理员 / 提权服务场景仍待虚拟机）。

**卸载程序不存在时的出路**（用户问"卸载程序不存在怎么办"）：此前卸载页只禁用按钮并提示去"应用和功能"，而注册表清理的"无效的卸载项"又对安装目录还在的条目保守放过，两边都不管。现在卸载页对这类行显示"移除卸载项"：

- `Uninstaller.UninstallerMissing(app, out exe)`：注册表来源、非 MSI、UninstallString 里的可执行文件是绝对路径且不存在。相对路径、便携软件、应用商店包都不算。
- `Uninstaller.RemoveEntry(app, RegistryOps)`：重读键里的 UninstallString 与清单一致（否则"已变化，请刷新"）、取快照、`RegistryOps.DeleteKey`（注册表护栏 + 快照核对 + 重探卸载程序仍不存在 + 先导出 .reg 备份）、写卸载历史（detectedBy = entry-removed）供残留清理定向扫描、记操作日志。不运行任何程序、不动安装目录（Program Files 全树保护不开例外）。
- 界面：确认框写明只删登记项、会备份、HKLM 条目普通权限下需要以管理员身份重新启动；完成后询问是否扫描残留。备注列改为可换行，不再截断到 120 像素。

**侧栏分组**（用户问"功能太多了，是否需要二级入口"；程序版本 0.16.2）：不做真正的二级菜单（最常用的系统清理会多一次点击），改为同一根侧栏内按类别分组、组可折叠、任何页面仍一次点击直达。分组沿用第 2 节的分类：清理（系统清理、应用缓存、残留清理、开发者缓存、注册表清理、隐私清理）、空间（空间分析、重复文件、文件粉碎）、优化（开机加速、磁盘健康、内存与进程、系统优化）、管理（软件卸载、驱动与更新、弹窗拦截、系统修复、系统信息）；隔离区与设置固定在侧栏底部、始终可见。清理与空间默认展开，优化与管理默认折叠；折叠的组标题右侧显示项数；折叠状态记进设置 `NavGroupExpanded`；程序内跳转（如"扫描残留"）到了折叠组里的页面时该组自动展开。实现：`NavItem.Group`、`NavGroup`、`ShellViewModel.Groups` / `PinnedItems`，App.xaml 的 `Nav.ItemTemplate` 与 `Nav.GroupHeader`。UI 自动化验证：默认折叠组的项不出现，展开后可点到，状态持久化，程序内跳转自动展开。**界面自动化脚本注意**：点折叠组里的页面前要先展开该组。

**左侧导航可滚动**（用户反馈"左侧导航没做滚动"）：17 个导航项在 600 像素高的窗口里放不下，底部的"设置"等项被裁掉。导航列表包进 ScrollViewer（顶部标题与底部权限状态区固定不动），键盘焦点移动到被裁掉的项时自动滚入视野。用 UI 自动化在 1000×600 窗口验证：导航区可滚动（可见 48%），"设置"项获得焦点后进入可见区域。

### v0.17（2026-09-30）首次真机反馈修复：占用文件、磁盘操作提权、发布脚本一键发布

用户在另一台机器上用 v0.15.0 做了第一次真实清理，反馈两件事，都已修（回归 InUseAndExcludeTests 7 用例，共 417 测试；程序版本 0.16.0）：

**"部分项目失败"弹出一整屏显卡着色器缓存与开始菜单磁贴缓存**（`NVIDIA\DXCache\*.nvph`、`Packages\...\TempState\TileCache_*.bin`，都是被驱动 / 开始菜单进程独占打开的文件）：

- 引擎把 ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION 单独归类（`Safety/FileInUse.cs`，句柄级移动的原生错误码与 .NET 的 0x8007 HRESULT 两种形式都认）：`CleanReport.InUse` / `InUseFiles` 计数与明细，条目按"跳过"留在列表、取消勾选，不进 `Failures`，操作日志记 skip 而不是 fail。摘要写"N 个文件正在被其他程序使用，这次跳过（关闭相关程序后重新扫描即可）"。
- 失败原因去掉重复的路径后缀（`CleanEngine.StripPathSuffix`：底层异常消息自带"（路径）"，明细里已单独列路径，此前每行出现两次）。
- 清理页不再弹模态框：失败与占用明细放在状态栏下方可展开的列表（`ProblemDetail` / `ProblemTitle`），失败最多列 50 条、占用最多 30 条，完整记录看操作日志。
- 规则目标新增 `exclude`（文件名通配列表，只对 files 目标，不得含路径分隔符、不得为 `*`；7.3 补充语义）：`Packages\*\TempState` 排除 `TileCache_*`（开始菜单常驻持有，清了只会报占用），DXCache 描述注明运行中程序占用的条目会跳过。数据集重签为版本 5。
- 有意不做扫描期逐文件试开（`FileShare.Delete` 探测）：大目录每文件多一次 CreateFile，且探测到清理之间占用状态仍会变；按跳过计数已经消除了"失败"误导。

**磁盘页"碎片整理"点了像没反应**：普通权限下 defrag.exe 什么都不做，只打印"权限不足 (0x89000024)"且退出码仍为 0，程序此前按退出码判成"完成（0 秒）"。修复：

- `DiskHealth.Normalize` 从输出里解析 `(0x89xxxxxx)` 存储优化器错误码并提升为失败退出码（`ParseDefragError`），`DescribeExitCode` 把 0x89000024 / 0x89000001 翻译成可读原因，状态栏写"碎片整理 未执行：权限不足：需要以管理员身份运行"。
- `DiskHealth.RequiresElevation`：除查询 chkntfs 状态外都需要管理员。磁盘页普通权限运行时在标题下显示提示，点击这些操作先询问"是否以管理员身份重新启动"，同意即走与左下角相同的 runas 重启。

**发布脚本**：`tools/release.ps1 -Publish` 用 `%USERPROFILE%\.cleansweep\github-token.txt` 里的细粒度令牌直接创建 Release（tag 打在已推送的 HEAD 上，脚本 fetch 核对 HEAD 与 origin/分支一致且工作树干净）、上传 zip、匿名重新下载核对 SHA-256；之后只剩提交并推送 release/latest.json。令牌只在用户目录，不进仓库、不回显。

### v0.16（2026-09-30）程序自更新的三项审查修复（N11–N13）、数据覆盖第一轮扩展

**自更新改为三阶段、执行者在可信位置**（docs/三轮代码复审-2026-09-30.md N11–N13，状态表已补齐；回归在 AppUpdateTests，共 13 用例）：

- **N13 暂存区信任**：界面只负责下载（流式核对大小与哈希）并把签名的发布信息原样存在压缩包旁（`<zip>.release.json`），然后启动**安装目录里已有的** CleanSweep.exe 执行 `--apply-update <zip> <界面 pid>`（安装目录不可写或装有提权服务时 runas）。旧程序以拒绝他人写入的方式打开压缩包，先哈希后解压用同一个流，独立复验发布信息签名、版本只升（拒绝用旧的真实发布包降级）、大小与哈希、压缩包条目路径（无绝对路径、`..`、盘符，解压总量上限）、解压后三个数据集的签名，解压到安装目录下的 `.update-stage`（Program Files 下普通用户不可写），再启动那里的新程序执行 `--apply-update-run <安装目录> <界面 pid> <本进程 pid>`。任何拒绝都清空暂存目录。新程序启动时核对自己确实位于安装目录的暂存区。
- **N12 服务协调与回滚**：新程序等两个旧进程退出、停止 CleanSweepElevation 服务（`IUpdateServiceControl`，真实实现用 ServiceController），把旧版本拥有的文件改名到 `.update-backup`，再复制新文件；任一步失败把已放入的新文件删除、备份原样搬回、服务按原状态重启，错误信息区分"已恢复原文件"与"恢复时又出错"。成功后重写安装清单、删除备份（旧进程仍占用时留给新版本启动时清理）、恢复服务、启动新版本。
- **N11 不跟随重解析点、只动自己的文件**：目录枚举用 `AttributesToSkip = ReparsePoint`（Junction / 符号链接既不进入也不列出），写入路径上的每一级已存在目录不能是重解析点；只替换 / 删除安装清单 `install-files.txt`（`tools/publish.ps1` 生成，每次更新重写）里的文件与新包重名的文件，安装目录里用户放的其他文件不动；没有清单的首次升级视整目录为旧版本所有。`--updated` / 每次启动清理残留目录。
- 版本升到 0.15.0（协议变化，0.14 从未发布过，无兼容负担）。

**规则路径通配目录段**（用户"再扩展清理范围"；`PathGuard.ValidateRuleTemplate` / `ExpandWildcards`，`RuleTarget.HasWildcard`，`RuleScanner.BuildItems`；语法与约束见 7.3；回归 RuleWildcardTests 6 用例：合法 / 非法模板、Profile * 展开与 Junction 跳过、directory 类目标、多段通配与上限）。以此覆盖此前规则语法够不到的目录：Chromium 系浏览器（Chrome / Edge / Brave / Vivaldi / Chromium / 360 极速 / QQ 浏览器）的全部 `Profile *` 配置文件缓存（README 原"只处理 Default"的已知限制取消）、JetBrains 各产品的 caches / index（建议确认）/ log / tmp、Android Studio 同类目录、Visual Studio 各实例的 ComponentModelCache、应用商店应用的 `Packages\*\TempState`、`AC\INetCache`、`AC\Temp`（≥1 天）、微信各账号的 `WeChat Files\*\FileStorage\Cache` 与 `Temp`（建议确认）。

**数据覆盖第二轮**（规则 63 → 74 条，数据集版本 4）：另加 GitHub Desktop、Signal、Bitwarden 的 Electron 缓存，Office 加载项与联机服务缓存，EA app / Ubisoft Connect 日志，Visual Studio 遥测日志，NVIDIA 旧位置着色器缓存与 GeForce Experience 网页缓存，Windows 安装 / 网络安装 / 更新编排器日志（≥7 天）。

**数据覆盖第一轮**（规则 30 → 63 条，指纹 49 → 69 条，弹窗规则 2 → 3 条，数据集版本 3）：

- 浏览器：Opera、Opera GX、Vivaldi、Chromium、360 极速 / 安全浏览器、QQ 浏览器的 Cache / Code Cache / GPUCache / ShaderCache（Service Worker 缓存为"建议确认"）。
- 应用（已有指纹的只加"已安装"缓存目标，残留由指纹库负责，避免残留页重复列出）：Slack、Zoom、Telegram（文件 / 媒体缓存"建议确认"）、Notion、Obsidian、Postman、Figma、Cursor、VS Code Insiders、Epic Games Launcher、OBS Studio、网易云音乐（歌曲缓存"建议确认"）、OneDrive 日志。
- 开发：Composer、Bun、Deno、uv、Poetry、Dart / Flutter pub、Electron / electron-builder、vcpkg（会导致重新编译 / 下载的为"建议确认"）。
- 系统：WinINet 缓存（INetCache，≥1 天）、远程桌面位图缓存、.NET Framework 使用日志、DirectX 着色器缓存、NVIDIA / AMD / Intel 驱动着色器缓存、用户程序崩溃转储（%LocalAppData%\CrashDumps）、ThumbCacheToDelete。
- 指纹（残留）：Opera、Vivaldi、Chromium、360 浏览器、QQ 浏览器、Cursor、企业微信、腾讯会议、迅雷、WPS、Google 云端硬盘、Dropbox、iTunes / iCloud、Logitech G HUB、Razer、Battle.net、EA app、Ubisoft Connect（gameSaves）、GOG GALAXY、Riot。
- 弹窗：营销词与广告类名扩充，新增"托盘气泡式营销弹窗"泛化规则（进程名带 bubble / tray / mini / assist 等且标题含营销词），仍不点名厂商。
- 有意未加：微信 / QQ / 钉钉 / 飞书的运行期缓存（缓存目录在账号子目录下，规则语法不支持通配目录；残留判定已由指纹覆盖）、Visual Studio 与 conda 的包缓存（删除会破坏环境）、Adobe 媒体缓存（在 Documents 下）。
- 新增 DataCoverageTests：规模下限与类别分布、新规则不与指纹路径重复、无检测条件的系统规则只指向本地缓存、弹窗规则必须带类名或标题。

### v0.15（2026-09-30）两份定时审查报告的 23 项修复、GitHub 发布与仓库安全

**审查修复**（docs/更新代码复审-2026-09-29.md R01–R15、docs/三轮代码复审-2026-09-30.md N01–N10，状态表在后者顶部）。要点：

- **提权服务的执行绑定用户确认**：请求携带每个条目的内容快照（`ScanItem.ContentSnapshot()`），服务重扫后只执行 ID 匹配且快照一致的条目，逐条回报 done / changed / skipped / failed / notfound；白名单每次请求重新读；预动作用真实执行器；隔离项记录归属用户 SID 并带对象标识，服务按归属与标识授权；界面只在与服务共用索引时委托隔离项操作，批量操作不在本地事务内等服务。
- **删除依据在执行前仍须成立**：注册表类条目记录扫描时判定缺失的程序路径（`MissingPath`），删除前重新探测；快照缺失、读不到或超过 5000 项一律拒绝删除；多动作计划任务只在全部可执行动作失效时才列出；清单不可靠时指纹残留降级为无法判定。
- **文件与备份边界**：粉碎拒绝多硬链接文件；备份目录及祖先经过重解析点时不淘汰也不还原；空闲空间擦除用随机新建目录且只清理自己创建的文件、区分磁盘已满与其他 I/O 错误；注册表护栏拒绝受保护子树的祖先并统一 WOW6432Node 判断。
- **正确性**：TOKEN_PRIVILEGES 按原生布局声明；SMART 预警按设备实例标识映射磁盘；更新下载的正文读取受总时限约束；服务安装后立即启动并设为延迟自动启动；卸载脚本按实际安装目录工作。
- **威胁模型明确化（R03）**：%ProgramData%\CleanSweep 的写入者视为可信（ACL 只给 SYSTEM / Administrators / 安装用户），不再宣称抵御同账户进程对索引与备份的一致篡改。

**GitHub 发布与仓库安全**：仓库推送到 GitHub 前，把最初提交里的开发签名私钥从历史中移除（重建提交），换成保存在发布者用户目录的正式密钥（公钥 release-2026-09）；测试结果 .trx（含机器名与账户名）、个人定时审查脚本、签名私钥目录加入 .gitignore；提交作者改用 GitHub noreply 邮箱。程序自更新以 GitHub 仓库为来源（`owner/repo`），见 README“自动更新”。

### v0.14（2026-09-30）发布前横切工作：普通权限运行、数据集签名与更新、自包含发布、安装

**界面切回普通权限（7.4 的目标形态）**：清单改为 asInvoker。`Elevation/ElevationNeed.cs` 静态判断每条扫描结果是否需要管理员（HKLM / 服务 / 任务 / 系统命令一律需要；文件类看路径是否在 Windows、Program Files、ProgramData 或其他用户目录之下，`PathGuard.RequiresElevation`）。非提权时需要管理员的条目在列表里禁用并标注；提权服务在线时，规则库产生的"安全"级文件 / 目录条目仍可勾选，清理时按规则 ID + 条目 ID 交给服务（`ElevationRequest.ItemIds`，条目 ID 是哈希而非路径，服务用与界面相同的扫描器 ID 重新扫描后只执行 ID 匹配的条目，结果按条目回传）。左下角"以管理员身份重新启动"（runas 重启，新实例等待旧实例释放单实例互斥体）。隔离区页恢复 / 删除遇权限失败且服务在线时按 ID 交给服务重做。数据目录：提权实例用 %ProgramData%\CleanSweep；普通权限实例若该目录已存在且自己能写（同一用户）就共用它，否则用 %LocalAppData%\CleanSweep；索引始终按不可信输入校验，所以共用不扩大提权实例的行为范围。

**数据集签名与在线更新（6.2 第 4 条）**：`Integrity/SignedManifest.cs` 定义 manifest.json（kind、version、generated、每个文件的 SHA-256、keyId、对前四项固定格式文本的 ECDSA P-256 签名）；`TrustedKeys.cs` 内置受信任公钥；`DataSets.Locate` 为每个数据集选目录（更新目录须签名通过且版本更高，否则内置；内置校验失败则一个文件都不加载），加载器改为 `LoadFiles(清单列出的文件)`，清单外的文件不加载。`DataUpdater` 从 https 地址取清单 → 验签、版本必须更高 → 逐文件下载并核哈希 → 落盘后再完整校验 → 目录级原子切换；只接受 https（回环地址的 http 供测试）。签名工具 `tools/CleanSweep.SignData`（keygen / sign / verify / sign-release），`tools/sign-data.ps1` 一键重签；私钥不进仓库（发布者的 %USERPROFILE%\.cleansweep\keys\），仓库公开前已把最初的开发密钥从历史中移除并换成正式密钥。提权服务加载规则走同一套定位与校验。

**发布与安装**：`tools/publish.ps1` 自包含 + ReadyToRun 发布 App 与 Service（目标机无需 .NET 运行时，约 140 MB），发布后校验三个数据集签名；`tools/install.ps1` / `uninstall.ps1`（复制到 Program Files、创建 ProgramData 数据目录、装 / 卸提权服务、快捷方式、"应用和功能"卸载项，卸载默认保留数据目录与各卷隔离区）；`installer/CleanSweep.iss` 为 Inno Setup 6 安装器脚本（同样的步骤，可选任务"安装提权服务"），本机未装 Inno，脚本未编译验证。

**程序自更新（以 GitHub 仓库为更新来源）**：设置 `UpdateSource` 统一解析为数据集根地址与 `release/latest.json` 地址（`Integrity/UpdateSources`）。`ReleaseManifest` 用数据签名密钥对"版本、压缩包名、下载地址、SHA-256、大小、生成时间"签名；`AppUpdater`：检查（版本只比前三段，更高才算新）→ 流式下载并核对大小与哈希（超出大小立即中止）→ 解压到数据目录暂存区（拒绝逃出目录的条目）并校验其中三个数据集的签名 → 用暂存区里的新 CleanSweep.exe 以 `--apply-update <安装目录> <旧进程 ID>` 启动（安装目录不可写时 runas），新进程等旧进程退出后镜像复制到安装目录（重试占用的文件、删除多余旧文件）再启动安装目录里的新版本。启动时可选后台检查，只在侧栏提示不自动安装。`tools/release.ps1` 一键生成压缩包与签名的 latest.json，压缩包作为 GitHub Release 附件上传。

**横切工作完成后的五轮 review**（明细在 docs/全量审查-2026-09-29.md 第三轮表 S01–S11）：提权服务每次请求重新定位、验签、加载规则，不保留启动副本；签名校验通过的文件内容直接交给加载器，不按路径重读；首次提权运行把普通权限时期的数据目录整体迁到 ProgramData 并修正备份索引；管道不存在时不等连接超时；分组三态只按可选条目计算；隔离区批量操作也有服务回退；安装脚本先停服务再覆盖文件。

**仍待完成（仓库外的事）**：EV 代码签名（未签名时 `--install` 会自动关闭 RequireSignedClient）；正式数据签名密钥；在虚拟机以管理员身份做端到端验证（提权服务真实执行、数据目录迁移、重启资源管理器的令牌路径、计划任务备份重新注册）；用 Inno Setup 编译安装器。

### v0.13（2026-09-29）全量审查第二轮复查：同类边界在 M3–M6 中的重现

审查报告的验收要求之一是"对同类边界覆盖所有模块"。本轮以报告的 16 项为模板逐一对照 M3–M6 新模块，报告的修复项没有回退；在新模块里找到 8 处同类重现并修复，明细在 docs/全量审查-2026-09-29.md 的"第二轮复查"表。要点：

- **注册表类条目的扫描时快照**（对应目录条目的逐文件指纹）：`RegistryCleaning/RegistrySnapshot.cs` 给值、键、服务、计划任务各定义一种内容哈希，`ScanItem.TargetSnapshot` 在扫描时记录，`RegistryOps` 删除前重算比对，变化即拒绝并让用户重新扫描。隐私页的 MRU 键不核对（内容随使用变化是常态）。
- **服务优化的"恢复"改为记录驱动**：只有本程序改过的服务（`service-tweaks.json` 里有原始启动类型）才显示"恢复"，且只改回记录的类型；不再因为"当前不是自动"就提供"恢复自动"（RemoteRegistry 等默认禁用的服务此前会被设成自动启动）。优化也只接受当前为自动启动的服务。
- **计划任务备份可恢复**：sidecar 带 SHA-256，设置页新增"计划任务备份"列表与恢复按钮，恢复走与注册表备份相同的完整性校验；Password 登录类型的任务不自动恢复。
- **弹窗 IFEO**：恢复不再依赖规则库仍列出该进程，只认本程序的标记；不覆盖别人已有的 Debugger 值。
- **重启资源管理器**：提权运行时用旧 explorer 的普通用户令牌启动新 explorer（`Safety/UnelevatedProcess.cs`），避免提权的 explorer；失败退回普通启动并明确告知。此路径尚未在真实提权环境验证。
- hosts 保存改为临时文件 + ReplaceFile 原子替换，备份名不再按秒冲突；系统命令用户取消后仍受总时限约束；弹窗拦截 PID 缓存定期淘汰。

### v0.12（2026-09-29）M6 实现：驱动与更新、弹窗拦截、系统修复、系统信息

**驱动与更新**（`Drivers/DriverStore.cs`，5.2）：`pnputil /enum-drivers` 按块内字段顺序解析（发布名、原始名、提供程序、类名、类 GUID、日期 版本、签名者），不依赖界面语言；按"原始 inf + 提供程序 + 类 GUID"分组，最新版本之外的是旧版本；`pnputil /enum-devices /drivers` 给出正在使用的包，读不到时全部视为在用。删除只针对"旧版本且无设备在用"，用 `pnputil /delete-driver oemNN.inf`（不带 /force，发布名严格正则）；导出备份 `pnputil /export-driver * <目录>`，目录须过 Path Guard。Windows 更新：暂停 1 到 35 天写 WindowsUpdate\UX\Settings 的六个时间值（写前值级备份），恢复即删除；已安装更新来自 Win32_QuickFixEngineering，卸载用 `wusa /uninstall /kb:N`（交互式，KB 号严格校验）；更新缓存清理沿用系统清理规则。

**弹窗拦截**（`Popup/PopupBlocker.cs`，规则 `popups/popup-rules.json`，5.3）：不注入、不钩子。每 2 秒 EnumWindows 枚举可见顶层窗口，进程名 + 窗口类名 / 标题都匹配规则才 PostMessage(WM_CLOSE)，不结束进程；规则加载时校验正则（带 50 ms 超时），只按进程名不带类名 / 标题的规则拒绝；内置永不匹配名单（explorer、浏览器、IM、IDE、系统进程）。IFEO 阻止：只接受规则文件 blockableProcesses 列出的 .exe 名，Debugger 指向 systray.exe（立即退出的系统程序）并带标记便于识别与恢复，写前值级备份。只在程序运行期间生效，默认关闭。内置规则是泛化的特征规则（进程名含 tips / popup / news / toast 等 + 营销词标题；广告类窗口类名），不点名具体厂商。

**系统修复**（`Repair/SystemRepair.cs`，5.4）：固定操作表 sfc /scannow、DISM /CheckHealth、/ScanHealth、/RestoreHealth、wsreset；重启资源管理器只结束当前会话的 explorer 并重新启动；文件关联修复跳转系统"默认应用"设置；图标 / 缩略图缓存复用系统清理规则（移入隔离区）后重启资源管理器。Hosts：读取、逐行校验（IP + 主机名 + 可选注释）、保存前备份到数据目录 backups\hosts、可恢复 Windows 默认内容。

**系统信息**（`SysInfo/SystemInfo.cs`，5.5）：Windows 版本（按内部版本号纠正 Windows 11 显示）、安装日期、运行时长、处理器、主板 / BIOS、内存条、显卡、物理磁盘、启用的物理网卡、声卡、电池，全部只读，可复制。

**5.5 中未做的项目与原因**：文件恢复需要解析 NTFS MFT 与已释放簇，与"安全优先、不写原盘"的定位冲突且工程量大，不做；软件搬家（Junction 迁移）会让部分更新器与 UWP 失效，设计文档已列为限制，1.x 视需求再评估；桌面整理属纯桌面体验功能，不在清理软件核心范围。

### v0.11（2026-09-29）M5 实现：磁盘健康、内存与进程、系统优化项

**共用**：`Safety/SystemCommand.cs` 统一执行 System32 下的系统命令（只接受裸文件名、参数由各模块固定操作表生成、OEM 代码页读输出、用户取消不强杀只等待、超时才终止）。

**磁盘健康**（`Disk/DiskHealth.cs`，4.2）：MSFT_PhysicalDisk 读介质（HDD / SSD / SCM）、总线（NVMe / SATA / USB…）、健康状态；MSFT_Partition 把卷映射到磁盘，映射不到时退回 IOCTL 寻道开销探测；S.M.A.R.T. 用 MSStorageDriver_FailurePredictStatus（预测故障）与 MSFT_StorageReliabilityCounter（温度、磨损、通电小时、读写错误），读不到的字段留空并说明可能需要管理员；系统"优化驱动器"计划任务（\Microsoft\Windows\Defrag\ScheduledDefrag）的启用状态与上次 / 下次运行时间。手动操作走固定操作表：defrag /A（只读分析）、/O（按介质优化）、/L（仅固态盘修剪）、/D（仅机械盘整理，**固态盘与介质未知一律拒绝，硬性约束**）、chkntfs /C（下次启动检查磁盘）、chkntfs X:（查询）。不自研整理算法，不做 BootExecute 级整理。

**内存与进程**（`Memory/MemoryManager.cs`，4.3）：GlobalMemoryStatusEx + GetPerformanceInfo + PerfOS 待机列表字节数；待机列表清理用 NtSetSystemInformation(SystemMemoryListInformation, MemoryPurgeStandbyList)，需要 SeProfileSingleProcessPrivilege，界面明确写"不是加速手段"；**不做工作集清理**。进程列表按内存排序、采样 CPU；受保护判定：PID 0 / 4、自身、内置关键进程名单（csrss、lsass、svchost、dwm、explorer…）、会话 0、IsProcessCritical、Windows 目录下的组件；结束进程前重新判定并核对进程名（防 PID 复用），只结束本进程不结束进程树。UWP 后台权限读写 HKCU\...\BackgroundAccessApplications\<PFN> 的 Disabled / DisabledByUser，写前值级备份。

**系统优化项**（`Optimize/*`，4.4）：`ServiceTweaks` 目录 24 项，每项带说明、风险等级、恢复方式与适用条件；"优化" = 改为手动启动（与开机加速一致，绝不设"已禁用"），修改前导出服务键并尝试还原点；目录外的服务拒绝；**没有"一键全关"**。`SystemTweaks`：视觉效果（VisualFXSetting 0 / 1 / 2，写前备份）、电源计划（powercfg /list 解析，/setactive 只接受本机存在的 GUID）、休眠开关（powercfg /hibernate，界面提示同时关闭快速启动）、虚拟内存只读展示并跳转系统性能选项、网络修复（ipconfig /flushdns、/renew，netsh winsock reset、int ip reset，需重启的明确标注）、TCP 全局参数只读、搜索索引跳转 control.exe srchadmin.dll。`ContextMenuManager`：枚举 *、Directory、Directory\Background、Folder、Drive、AllFilesystemObjects、DesktopBackground 的 ContextMenuHandlers，解析 CLSID → DLL → 签名 / 发布者，禁用通过系统的 Shell Extensions\Blocked 机制（非提权时写 HKCU 的 Blocked），不删除注册，写前值级备份，微软自带默认隐藏。

**设计决定与偏离**：搜索索引范围不在程序内改（跳转系统界面）；虚拟内存只展示不修改；TCP 参数只展示不修改；服务优化只改启动类型不停止正在运行的实例；SMART 预警按枚举顺序与磁盘对齐（数量不一致时不显示预警，避免张冠李戴）。

### v0.10（2026-09-29）M4 实现：注册表清理与隐私清理

**统一执行通道**：`ItemKind` 新增 RegistryValue、RegistryKey、Service、ScheduledTask 四种条目，`ScanItem` 带 `RegistryTarget` / `ServiceName` / `TaskPath`；清理引擎通过 `RegistryCleaning/RegistryOps.cs` 执行：先过注册表护栏，再备份（值级 .reg、整键导出、任务 XML 存到 backups\registry\tasks），再删除。界面沿用同一个清理页，确认框区分"移入隔离区"与"删除前备份、可在设置中还原"。引擎未配置 RegistryOps 时拒绝执行注册表类条目。

**注册表护栏**（`RegistryCleaning/RegistryGuard.cs`，即 v0.8 答复里预告的"注册表版 Path Guard"）：只允许在 HKCU\Software、HKLM\Software（含 WOW6432Node）、HKU\<SID>\Software 之下操作；六十余条永不触碰子树（Windows NT\CurrentVersion、Policies、Run / RunOnce / StartupApproved、Installer、Cryptography、SystemCertificates、Classes\Installer / Interface / AppID、AppModel 包仓库等）；不允许删除 Software 根、Classes 根、系统与硬件厂商的顶层键、Microsoft 下容器级（第 4 层及以内）的键。

**文件存在判定**（`RegistryProbe.cs`）：Exists / Missing / Unknown 三态，只有 Missing 才作为清理依据。处理环境变量展开、shell 占位符（%1、%L、%*）、引号与参数剥离、rundll32 载荷、\??\ 与 \SystemRoot\ 前缀、8.3 短名、System32 ↔ SysWOW64 与 Program Files ↔ Program Files (x86) 重定向；网络路径、未就绪 / 非固定驱动器一律 Unknown。无引号且含空格的路径只接受以可执行扩展名结尾的前缀，找不到即 Unknown（冒烟时发现 "C:\Program Files\x\a.dll" 会被截成 "C:\Program" 造成上百条误报，已修）；InstallLocation 之类纯路径值整体作为路径。Windows 目录下缺文件不算垃圾（可选功能未安装）。

**注册表清理**（`RegistryCleanerScanner.cs`）按 3.4 的三级：安全 = 无效卸载项（非 MSI、卸载程序缺失且安装目录也不存在）、失效快捷方式（开始菜单 / 桌面 .lnk，文件类走隔离区；Path Guard 为开始菜单下的单个 .lnk 文件开了例外，目录仍拒绝）、MUI 缓存孤儿；建议确认 = 已卸载软件遗留的 Software 键（需要证据：卸载记录，或键内路径值指向已不存在的位置且没有对应已安装应用；证据来自产品子键时只针对子键）、失效文件关联（扩展名指向不存在的 ProgID、ProgID 打开命令缺失、"打开方式"列表）、失效 App Paths、指向不存在程序的用户态服务（驱动与 Boot / System 级拒绝，删除用 DeleteService）与计划任务（Microsoft 的拒绝，删除前存 XML）；高风险 = 失效 COM 注册（CLSID 的 InprocServer32 / LocalServer32）、失效共享 DLL 计数。产品文案不宣称"加速"。

**隐私清理**（`Privacy/PrivacyScanner.cs`）：最近使用文件记录、跳转列表（自动 / 应用自定义）、活动历史数据库（服务占用时会失败并提示）为文件类走隔离区；RunMRU、TypedPaths、WordWheelQuery、RecentDocs、ComDlg32 对话框历史、UserAssist 为注册表键类，删除前整键备份。剪贴板历史、诊断数据、浏览器历史不纳入（页面说明去向）。

**文件粉碎与空闲空间擦除**（`Privacy/FileShredder.cs`）：1 到 7 遍覆写（0x00 / 0xFF / 随机）后随机改名删除，只接受通过 Path Guard 的普通文件；`Disk/DiskMedia.cs` 用 IOCTL_STORAGE_QUERY_PROPERTY（寻道开销 / TRIM）识别固态盘，界面对 SSD 上的文件明确提示"覆写不保证擦除"。空闲空间擦除只对确认为机械盘的固定卷提供，SSD 与介质未知一律拒绝。

**设计决定与偏离**：服务项的清理动作是 DeleteService（不是删注册表键），且只针对用户态、非 Boot / System 级服务；计划任务用任务计划程序 API 删除并留 XML 备份；文件关联删除的是 HKCU / HKLM Classes 下的物理键而不是 HKCR 合并视图；卸载项中 MSI 条目交给 Windows Installer 不碰；空目录 / 单层路径（D:\Games）不作为"路径已不存在"的证据。

### v0.9（2026-09-29）全量审查修复 + M3 实现

**全量审查修复**：依据 [全量审查-2026-09-29.md](全量审查-2026-09-29.md)，F01 到 F16 与五项观察全部修复，逐项状态见该文档顶部的"修复状态"表；13 个复现探针反转为回归测试（ReviewFixTests，27 个）。要点：注册表备份带 sidecar（键路径、视图、SHA-256）且导入的是校验过的字节副本；`RegistryBackup.BackupValue` 操作级备份，值原本不存在时记录删除标记，首次禁用启动项可完整撤销；隔离恢复目标必须与隔离项元数据一致并通过 `PathGuard.CheckRestoreTarget`；已存在的受保护目录核对 DACL 并收紧；整目录清理前比对逐文件指纹；引擎逐条返回成功 / 跳过 / 失败，界面只移除完全成功的条目；发现 kernel32 的 `SetFileInformationByHandle` 不接受 `RootDirectory`（此前一直走绝对路径回退分支），改为直接调用 `NtSetInformationFile`，删除回退。

**M3 实现（设计文档 3.3、5.1、7.2、7.4）**

- **App Inventory**（`Inventory/AppInventory.cs`）：注册表 Uninstall 键（HKLM 64 / 32 位、HKCU，跳过补丁条目）、应用商店包仓库（HKCU 与 AppxAllUserStore）、便携软件（`%LocalAppData%\Programs`、scoop、WinGet 目录里的 exe 版本信息）、正在运行的进程。快照带可靠性标志：注册表条目少于 5 条或读不到任何应用商店包时，"未找到"不作为已卸载的证据。
- **指纹库**（`Inventory/AppFingerprints.cs`，数据 `fingerprints/fingerprints.json`，v0.9 时 50 条，v0.16 起 69 条）：路径 → 应用 + 检测方式（注册表、文件、目录、PATH 命令、已安装名称 / 发布者、包家族）+ 标志（loginState、license、gameSaves、devCache、programBody）+ cachePaths。路径经 Path Guard 校验，cachePaths 必须位于 paths 之下，不合法整条拒绝。
- **用户目录残留清理**（`Residue/ResidueScanner.cs` + `RuleScanner.Residue()`）：扫描 LocalAppData / Roaming / LocalLow 一级目录、Packages（按包家族比对）、Programs（只按活跃度）、指纹库指定位置；`Microsoft` 目录只处理指纹库列出的子目录；厂商目录（已安装应用的发布者或已知厂商名）下钻到产品目录。判定顺序：规则库覆盖 → 指纹 → 已安装名称 / 安装位置 / 运行进程（活跃）→ 卸载记录（确认，不看新旧）→ 目录内 exe 版本信息（建议确认）→ 活跃度（180 天疑似 / 90 天未知 / 空目录 30 天）。硬性排除写死：Temp、ConnectedDevicesPlatform、Comms、D3DSCache、凭据目录、.ssh / .aws / .kube / .gnupg 等。Documents、Saved Games、OneDrive 接管目录一律标红只提示。管理员模式可扫描其他用户配置文件（`ProfileEnvironmentResolver` 按 profile 展开变量）、ProgramData 与已删除账户遗留的配置文件目录。
- **开发者缓存**（`Residue/DevCacheScanner.cs`）：指纹库 devCache 的缓存目录（只清缓存不清配置）、项目根目录下 30 天未动的项目的 node_modules、conda 环境（只列出，高风险）；Docker Desktop 的 WSL 虚拟磁盘只显示体积。
- **软件卸载**（`Uninstall/Uninstaller.cs`）：只运行官方卸载程序。MSI 一律改写为 `msiexec /x {ProductCode}`（不信任注册表里的其余参数）；exe 卸载程序必须存在；应用商店包用 `Remove-AppxPackage`，包全名严格正则校验；系统组件包拒绝。取消只停止等待不强杀。卸载后重扫清单确认并写入 `uninstall_history`。预装软件识别（`Bloatware.cs`）只是标记。**安装监控**（`InstallMonitor.cs`）：安装前快照（应用、关键目录一级子目录、服务、Run 项）与安装后比对，本阶段只识别不回滚。
- **卸载事件监听**（`Uninstall/UninstallWatcher.cs`）：`RegNotifyChangeKeyValue` 监视 Uninstall 键与包仓库 + MsiInstaller 1034 事件，去抖后重扫清单，消失的应用写入卸载历史并弹出提示，点"是"进入残留清理页做定向扫描。**只在程序运行期间生效**，默认关闭，设置页明确说明没有常驻后台进程。
- **提权服务**（`Elevation/*`，宿主 `src/CleanSweep.Service`）：命名管道 ACL 只给 Administrators、LocalSystem 与安装时登记的交互用户 SID，显式拒绝网络登录；每次连接读取客户端进程令牌核对 SID 与可执行文件路径（安装时登记），发布构建要求签名发布者一致；只接受枚举型指令（Ping、GetStatus、按 ID 清除 / 恢复隔离项、淘汰过期项、按规则 ID 执行"安全"级清理），用户目录按连接方 SID 的配置文件展开；恢复不得落到其他用户的配置文件目录。`--install` 用 sc.exe 注册为按需启动的 LocalSystem 服务并写入 `elevation.json`。

**设计决定与偏离**

- 界面以普通权限运行（v0.14 起）：需要管理员的条目在列表中标出，提权服务在线时按条目 ID 交给服务，否则由用户“以管理员身份重新启动”。提权服务由安装器安装，未签名的构建自动关闭客户端签名校验。
- 3.3.2 信号 C 的"有进程持有该目录下文件的句柄"以"正在运行的进程可执行文件位于该目录下"近似，不做系统句柄枚举。
- `%LocalAppData%\Programs` 下的目录绝不因为"没有卸载项"就判为残留（便携软件是合法用法），只有卸载记录或活跃度能把它列出来。
- 3.3.4 的"后台常驻"卸载监听不做常驻进程：监听只在程序运行期间生效；常驻能力将来由提权服务承担。
- 3.3.3 "以后忽略此应用"沿用白名单条目机制。

### v0.8（2026-09-28）安全审查修复 + 两轮评审

依据 [安全审查-2026-09-28.md](安全审查-2026-09-28.md)，13 条发现全部修复，审查附带的复现用例反转为回归测试（SecurityFixTests，22 个）。

**信任边界与隔离区（审查 1、2、4、5）**

- 隔离区索引视为不可信输入：删除 / 恢复前由"本卷隔离区根 + 批次 + 文件名"重新推导路径并要求与索引一致，隔离区根与批次目录不得是重解析点；被篡改的记录拒绝操作并保留
- 所有移动改为**句柄级操作**（新增 HandleMove）：先打开源对象与目标目录，向内核核对真实路径与逻辑路径一致，再用同一句柄按"目标目录句柄 + 相对名"重命名。校验与移动作用于同一对象，消除检查与移动之间的竞态；源以不跟随重解析点方式打开，即使被换成链接也只会移动链接本身
- 恢复前先检查原路径祖先是否有重解析点，再创建父目录（否则创建目录本身就会穿过链接）
- 隔离区根与程序数据目录统一由 ProtectedDirectory 管理：已存在的目录校验所有者（SYSTEM / Administrators / 当前用户），新建目录 ACL 设置失败即拒绝使用
- **提权运行时数据目录改为 %ProgramData%\CleanSweep**（受限 ACL），非提权运行退回 %LocalAppData%\CleanSweep。索引、注册表备份不再放在其他本地进程可写的位置
- 移入顺序改为：先写元数据文件（原路径等）→ 句柄级移动 → 写索引；索引写入失败把对象移回原位。启动时 Reconcile 核对文件系统与索引：有元数据无索引的重新登记，索引有文件无的标记清除（所在卷未挂载时不判定）
- 永久删除只在确认对象已不存在后才标记；失败保留记录并可重试。目录删除自行遍历，遇到 Junction 只删链接
- 注册表备份还原前校验 .reg 文件中每个 [键] 段都在当初备份的键之下，被篡改成其他键一律拒绝

**引擎约束（审查 3、6、7、9、10）**

- PathGuard 新增"目标包含受保护对象"检查：整目录目标不得包含保护根、用户关键对象、范围过大根或 Windows 目录（如 %UserProfile%\AppData）
- 整目录清理前重新度量目录，大小或最后修改时间与扫描快照不一致即拒绝，提示重新扫描
- 清理引擎接入最新白名单：执行前逐项、逐文件核对，包含白名单路径的目录不能整体移动；重复文件页同样受益
- Command 目标改为固定操作表：命令与参数必须与代码中的表精确匹配；Command 与回收站类目标风险等级下限为"建议确认"，规则不能标成"安全"
- 单文件目标同样应用 minAgeDays；NuGetScratch、dotnet 临时目录加 1 天年龄限制
- 前置动作失败时跳过依赖它的项目；停止服务超时视为失败但仍返回恢复句柄，服务稍后停下由本次操作重新启动

**其余（审查 8、11、12、13 与观察项）**

- 规则加载对 JSON null（规则、目标、detect 条件、字符串、preActions 元素）全部转为拒绝原因，minAgeDays 限定 0 到 3650
- 报告区分"移入隔离区字节数"（到期后释放）与"直接释放字节数"，界面不再把移动量说成已释放
- SQLitePCLRaw 升级到 3.0.5，NU1903 消除
- 空间分析根目录及每个递归入口拒绝重解析点
- 清理进行中的取消按钮真正取消清理；失败的项目保留在列表中并取消勾选；重复文件执行前核对每组拟保留副本仍存在

**两轮评审补充修复**

- 句柄级移动的 Win32 错误统一包装为 IOException，避免单个文件失败中断整批；UNC 路径使用 \\?\UNC\ 前缀
- 隔离区页面单项永久删除失败时提示并保留记录，不再触发未处理异常
- 开机加速页在扫描或修改进行中拒绝新的开关切换，避免并发写注册表
- 测试总数 167



**新增模块**

- **开机加速**（4.1）：枚举注册表 Run / RunOnce（HKCU、HKLM、WOW6432Node）、启动文件夹（用户与公共，解析 .lnk 目标）、计划任务中带登录 / 开机触发器的项、自动与手动启动的服务、UWP StartupTask（AppModel\SystemAppData\*\State）。每项展示发布者、Authenticode 签名状态（内嵌签名与系统 catalog 签名均通过 WinVerifyTrust 校验，不联网查吊销）、启动影响（StartupInfo XML，阈值与任务管理器一致）、建议（保留 / 可禁用 / 建议禁用）
- 禁用 / 启用只写 StartupApproved（保留原值高位标志，仅翻转最低位）、任务 Enabled、服务启动类型（自动 ↔ 手动，绝不设为“已禁用”）、UWP State，**不删除原始项**，与任务管理器同步
- 删除：注册表值先备份整键；启动文件夹的文件移入隔离区；计划任务只允许删除 CleanSweep 自建的延迟任务
- 延迟启动：在任务计划程序 `\CleanSweep` 文件夹创建登录后延迟 N 秒的任务，再禁用原项；删除任务并重新启用原项即可撤销
- 开机时间历史：Diagnostics-Performance 事件 100，按次展示并给出平均值；非管理员运行时明确提示需要权限
- **注册表自动备份**（6.1 第 4 条）：任何注册表写入前用 reg.exe 导出所改的键为 .reg，索引存 SQLite，设置页可查看、一键还原（reg import，合并语义：备份后新增的值保留）、按保留天数自动淘汰且至少保留最近 20 条。导入只接受备份目录内由本程序生成的文件
- **系统还原点**（6.1 第 5 条）：通过 WMI SystemRestore 创建，修改服务启动类型前调用；先检查系统保护是否启用与 `SystemRestorePointCreationFrequency`，频率限制内直接复用已有还原点；创建失败时降级为注册表备份 + 隔离区并在界面提示（本次会话只提示一次）
- 操作日志导出 CSV（6.1 第 8 条“可导出”），UTF-8 BOM 便于 Excel

**实现中确定的决定**

- 微软自带的服务与计划任务默认隐藏（4.1），但注册表 Run、启动文件夹、UWP 项始终显示，因为 OneDrive、Edge 自启之类正是用户想管的
- 服务的“禁用”实现为“改为手动启动”而非 Disabled：依赖该服务的程序仍可按需拉起它，避免功能损坏
- 一键“禁用全部建议禁用项”不包含服务，服务逐项确认
- WHQL（Microsoft Windows Hardware Compatibility Publisher）与第三方组件 CA 签名的文件不算微软自带
- 可执行文件已不存在的启动项标注“应用可能已卸载”并建议禁用，是 3.3 用户目录残留清理在启动项维度的先行版
- 扫描按来源与按项两级隔离错误：一个服务的注册表键无权读取只跳过该服务，整个来源失败才记入日志
- 4.1 中的 Shell 扩展 / 浏览器助手对象延后到 M6 系统修复一并做，与浏览器数据一起处理更合适

**验证**

- 新增 53 个测试（StartupApproved 编解码、命令行拆分、StartupInfo 解析与阈值、建议规则、事件 XML 解析、真实 reg.exe 备份与还原、注册表路径校验、还原点频率策略与 WMI 时间解析、真实机器只读扫描、notepad.exe catalog 签名），测试总数 132
- 非提权冒烟：开机加速页实测 57 项，签名、发布者、禁用时间、僵尸项标注均正确；设置页新增“备份与还原”区块

### v0.6（2026-09-28）M1 代码再评审两轮

**第一轮：核心文件完整重读**

- 隔离区 `Get(id)` 通过加载全部活动条目再查找，恢复全部 / 清空为平方级复杂度，数万条时界面冻结。修复：改为按主键直接查询；恢复全部、清空、删除过期改为后台线程 + 批量事务 + 进度提示
- 用户已知文件夹（Desktop、Documents、Downloads、Pictures、Music、Videos、OneDrive 等）整目录可被规则引用。修复：列为范围过大，仅子目录可引用（对应 3.3.1 只提示不清理）
- 命令类目标重定向了标准错误却不读取，DISM 输出较多时可能阻塞。修复：不再重定向标准错误
- 隔离区列表改为整体替换集合，避免数万次集合变更通知

**第二轮：真实运行核对**

- 回收站规则为“安全”并默认勾选，但它是唯一不经过隔离区、不可恢复的项目，且实测占扫描总量八成（69 GB / 85 GB）。修复：降为“建议确认”，默认不勾选
- 回收站与目录类条目说明文字重复显示。修复：说明只保留附加信息
- 侧栏导航按钮无自动化名称，读屏软件与自动化工具无法定位。修复：绑定 AutomationProperties.Name
- 应用缓存页实测正确识别 Chrome、Edge、Gradle、npm、NuGet 等已安装应用，风险分级符合预期
- 测试总数 79


### v0.5（2026-09-28）M1 代码再评审五轮

| 轮次 | 视角 | 发现与修复 |
|---|---|---|
| 1 | 引擎正确性 | 文件集清理后空子目录残留。修复：以非递归删除清掉变空的子目录，不含扫描根，跳过重解析点 |
| 2 | 规则库内容 | 临时目录规则无年龄过滤，会搬走正在运行的安装程序的临时文件。修复：三个临时目录目标加 `minAgeDays: 1`；JetBrains 下载目录降为“建议确认”。其余 60 余条路径逐一核对无误 |
| 3 | 界面与视图模型 | 分组复选框为三态，点击全选后显示为“部分选中”而项目实际全选。修复：改为两态，部分选中仅作显示 |
| 4 | 存储与恢复 | 隔离文件被外部删除后恢复失败且条目永久残留。修复：恢复时检测源文件缺失，标记已清除并给出明确错误。两个实例并行会争抢 SQLite。修复：单实例互斥量 |
| 5 | 测试与工程 | 补充空目录清理、外部删除后恢复两个测试；测试总数 74，Release 发布物已重新生成并启动验证 |


### v0.4（2026-09-27）M1 代码两轮评审

**第一轮：安全与正确性**

- 扫描根目录本身若为 Junction，枚举与清理均未拒绝，构成本地提权入口。修复：枚举跳过根重解析点；删除前通过 GetFinalPathNameByHandle 核对真实路径与逻辑路径一致（Path Guard 新增 VerifyPhysical，6.2 第 1 条落地）
- 隔离区根目录继承卷根默认 ACL，其他本地用户可篡改待恢复内容。修复：创建时重设 ACL，仅 SYSTEM、Administrators、当前用户
- `%Temp%` 直接取自环境变量，被改到 Documents 等位置时会引发误删。修复：最后一级目录名必须为 Temp / Tmp，否则回退到 `%LocalAppData%\Temp`；同时展开 8.3 短名
- 用户配置文件内的注册表 hive、凭据、DPAPI 密钥、开始菜单未受保护。修复：加入引擎硬性拒绝列表；`%LocalAppData%\Microsoft\Windows` 与 `%AppData%\Microsoft\Windows` 列为范围过大
- 空间分析递归使用默认线程栈，极深目录树可能溢出。修复：64 MB 专用线程
- 新增 8 个安全回归测试

**第二轮：性能与并发**

- 清理引擎对每个文件写两条 SQLite 记录且各自独立事务，7 万文件需十余分钟。修复：批量模式共享事务、每 500 次操作提交、WAL + synchronous=NORMAL
- 批量模式首版存在锁顺序反转导致的死锁，已修正并用并发读取测试覆盖
- 测试总数 72，连续多次运行稳定


### v0.3（2026-09-27）M1 实现

- 解决方案 `CleanSweep.slnx`：`CleanSweep.Core`（引擎）、`CleanSweep.App`（WPF）、`CleanSweep.Core.Tests`
- 已实现：系统垃圾清理、应用缓存清理、空间分析、重复文件、隔离区、Path Guard、规则引擎、白名单、操作日志
- 规则库 4 个文件 26 条规则，全部通过路径校验；`uninstalled` 目标已写入规则但由 M3 的残留模块消费
- 单元测试 59 个，覆盖 Junction 毁盘防护、恶意规则拒绝、隔离区往返、删除前二次核对
- 未实现：规则库签名校验（M1 只加载内置规则）、提权服务（M1 单进程 UAC 提权）
- 技术选型调整：.NET 8 → .NET 10 LTS；UI 选定 WPF


### v0.2（2026-09-27）两轮评审修订

**安全类修正**

- 新增 6.2 引擎层硬性约束：永不跟随重解析点、系统保护路径、规则路径校验、规则库签名、删除前二次核对
- 新增 7.4 提权服务安全要求：管道 ACL 与 SID 校验、枚举型指令、SYSTEM 上下文下的用户路径解析
- 系统还原点补充 24 小时频率限制与降级策略
- 重复文件查找补充云端占位文件与硬链接处理

**技术准确性修正**

- Prefetch 清理降为"不建议"级并默认隐藏；工作集压缩明确不做
- WinSxS 清理与 Windows.old 删除补充不可逆后果说明
- 文件粉碎补充 SSD 上不可靠的说明
- 磁盘整理重新定位为"健康监控 + 接管系统计划"，放弃启动时整理
- 注册表清理重新定位为残留清理，共享 DLL 计数与 COM 项升为高风险
- 弹窗拦截明确不做注入与钩子，改为窗口枚举 + IFEO
- 软件搬家补充 UWP 不适用的限制
- 开机加速补充 `StartupApproved` 同步机制与耗时数据来源
- 卸载事件监听补充 MsiInstaller 事件与"需常驻"的说明
- 明确 .NET 8 不支持 Win7，放弃 Win7 兼容

**一致性修正**

- 信号 C 与判定表的时间阈值矛盾：信号 C 改为仅对无法归属的目录生效，避免刚卸载应用被错误降级
- 优先级 P 与构建阶段 M 的关系明确化，总览表新增构建阶段列；磁盘整理由 P1 降为 P2
- 第 2 节对 MVP 的章节引用由"第 6 节"改为第 8 节
- 隔离区保留期在 3.3.3 与待决问题中重复且矛盾，统一到 6.1
- 规则示例的 `onlyWhenUninstalled` 改为三值 `when` 字段并补充语义说明

**新增内容**

- 第 1 节新增"明确不做的事"
- 第 9 节非功能需求与测试策略
- 第 11 节术语表
- 7.2 新增 Path Guard 公共服务
