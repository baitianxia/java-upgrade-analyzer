# 测试体系建设方案

本文定义本工程长期有效的测试分类、真值治理和准出原则。目标不是让测试绑定当前实现，而是建立一套允许内部架构、算法、缓存和执行方式持续演进的安全网。

## 1. 总体结构

测试集分为三套，职责不得混淆：

| 测试集 | 保护对象 | 是否允许依赖内部实现 | 主要失败含义 |
|---|---|---|---|
| 黑盒测试 | 对外输入、输出和用户可观察语义 | 不允许 | 对外契约或分析正确性发生回归 |
| 白盒测试 | 内部算法、模块协作、异常路径和实现约束 | 允许 | 当前实现存在逻辑缺陷或重构遗漏 |
| 性能测试 | 时间、内存、CPU、I/O、缓存和规模增长 | 允许读取测量证据，不允许放宽正确性 | 性能回退，或通过少算获得虚假性能收益 |

另设“测试可信度门禁”。它不是第四套产品测试，而是验证测试分类、Oracle、真值、skip 和 CI 执行本身可信。

所有重要改动的验收顺序固定为：

1. 测试可信度门禁先确认分类、Oracle 和真值可用；
2. 黑盒正确性通过；
3. 白盒逻辑与异常路径通过；
4. 性能测试在相同语义结果下通过。

准确性是底线。不得为了性能、兼容旧测试或缩短流水线而修改真值、减少结果或扩大不确定结论的适用范围。

测试体系提供的是“对已声明契约、已登记风险和已执行环境的可审计保证”，不是“以后不会再有 bug”的证明。测试数量、行覆盖率、能力标签或一次全绿都不能单独推出系统正确；质量保证必须同时回答：测了什么、expected 从哪里来、哪些反例能杀死错误实现、哪些门禁实际执行、哪些环境没有取得证据，以及真实缺陷为什么曾经逃逸。

### 1.1 充分性判定模型

一项能力只有同时满足下面五个条件才能写成 `covered`，任一条件缺失都必须标为 `partial` 或 `missing`：

1. **契约完整**：公开输入、输出、状态、错误和禁止结果均已声明；
2. **故障模型适用性已评审**：除正常路径外，逐项判断反例、边界、无效输入、部分失败、状态迁移、恢复、并发、资源上限和平台差异是否适用；不适用必须给出具体理由，不能留空；
3. **独立真值可判定**：actual 与 expected 来源隔离，关键结论至少由两个不同机制交叉确认；
4. **实际执行可证明**：精确测试被合入或发布 profile 选中，结构化证据中 selected、unique-selected 和 run 守恒；
5. **目标环境已取得证据**：涉及 Windows、JDK、文件系统、Git、构建工具或资源计量时，必须来自对应真实环境，模拟分支不能替代。

测试设计不得再以“先补一个成功案例，失败后再继续补”为默认方式。每个功能或修复在写实现前先形成测试设计表，至少列出受影响能力、公开契约、适用故障维度、独立 Oracle、正例、近邻反例、边界、状态序列/并发交错、执行 profile 和目标平台。测试数量只用于防止清单被静默删减，不参与充分性结论。

### 1.2 未声明但客观存在的范围

测试范围不能只来自需求、能力矩阵或开发者主动声明。代码中已经存在的入口、模块、条件分支、异常处理、调用关系、状态文件、子进程、脚本和平台分支都是客观测试对象，即使文档遗漏，也不能因此从分母消失。完整范围由两条独立路线取并集：

1. 自顶向下：公开 CLI、Step0～Step6、输出 schema、support manifest、用户事故和兼容性声明；
2. 自底向上：`scripts/` 实际文件清单、生产入口 import 闭包、函数/方法、可解析调用边、运行时动态调用边、字节码条件分支、shell 入口、持久化读写点和外部工具边界。

`tests/fixtures/internal_test_scope.json` 必须把每个 `scripts/*.py` 与 shell/PowerShell/batch 入口归入“分析运行时”或有具体测试 owner 的支持工具类别。新增文件没有分类、分析 import 闭包与登记清单不一致、支持工具没有可解析 selector，可信度门立即失败。分类只决定由哪套测试负责，不能成为免测清单。

白盒结构证据由 `whitebox_coverage_gate.py` 从当前源码自动重建，不使用手填数量作为分母：

- 每个生产函数/方法必须有实际调用证据；
- 每条静态可解析的内部 `caller -> callee` 关系必须被执行；运行时发现的额外动态边一并保留；
- 每个函数及其 lambda/comprehension 所属逻辑中的条件分支左右 alternative 必须被执行；
- 证据逐项绑定实际 test ID 和进程 ID，父进程与 Python 子进程合并；
- 原生 Windows、发布规模或其他当前环境不能执行的路径只能转交给对应平台证据，不能在本机记成已覆盖；
- 真正不可达的代码优先删除。确需保留时必须提供可复核的不可达/平台证明、责任环境和失效条件，不能用笼统 `exclude` 或百分比阈值放行。

结构覆盖执行会改变时序时，首先修复观测器或使用不改变语义的局部事件；不得放宽产品超时、资源预算或并发断言来迁就覆盖工具。性能正确性仍以未扰动执行为准。结构取证和普通执行任何一方失败都不能算通过。

因此，“完成”是一个机器可反驳的状态：源码清单无未归属项，公开能力无 blocking gap，黑盒 closed-set 无差异，白盒结构责任无未解释缺口，性能守恒，全部目标平台有当次证据，且已知逃逸缺陷均有独立回归。只满足其中一部分时必须报告具体缺口，不允许以 58 个方法、89 个标签、覆盖百分比或一次全绿宣布测试建设完成。

## 2. 黑盒测试集

### 2.1 边界

黑盒测试只能：

- 构造或读取版本化输入；
- 通过公开 CLI 启动系统；
- 读取 CLI 返回的公开结果位置和版本化公开输出；
- 将公开语义投影与独立真值比较。

黑盒测试禁止：

- 导入 `scripts/` 下的分析器、解析器、裁决器、图算法或输出聚合模块；
- mock、patch 或调用内部函数；
- 读取 SQLite、内部缓存或未声明为公开契约的中间状态来决定通过；
- 使用本系统上一次输出生成预期结果；
- 因缺少必需运行环境而静默 skip。

允许忽略时间戳、绝对路径、随机运行 ID、性能计数等非语义字段。比较对象必须是稳定的公开语义投影。

### 2.2 两类数据集

闭集小工程是主要正确性门：

- 输入规模小，能够穷举全部变化和全部合法结果；
- `result_set_policy=exact`；
- 同时检验假阳性、假阴性、状态、依赖归属和路径；
- 每个正例至少配一个语义相近的负例；
- 适合 PR 和跨平台矩阵执行。

固定真实项目是补充验收门：

- 固定 commit、制品 SHA、依赖坐标和运行画像；
- 覆盖真实框架语义、复杂打包结构和规模问题；
- 必须明确真值是完整闭集、某状态闭集还是关键结果子集；
- 子集通过不能被描述为“全部结果正确”。

真实大项目不能替代闭集小工程。大项目容易发现边界问题，但通常无法独立证明数千条结果的完整性。

### 2.3 黑盒比较维度

闭集案例至少比较：

- owner、member、JVM descriptor、member kind；
- dependency lineage、base/current coordinate；
- `reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed`；
- static linkage、impact conclusion、runtime verification；
- exact/possible path、路径文本和路径集合完整性；
- 结果总数、TP、FP、FN、状态偏差和路径偏差；
- 明确禁止出现的结果。

只比较“发现了几个 API”或“流程返回 0”不属于充分的黑盒测试。

### 2.4 场景强度合同

“某能力引用了一个测试方法”不等于该能力已经充分覆盖。每项公开能力还必须登记可执行的场景维度，并绑定到第三方真值中的具体 JSON Pointer：

- `nominal`：正常输入和预期成功语义；
- `counterexample`：与正例相近但不得命中、不得出现或必须保持不同状态的反例；
- `boundary`：descriptor、可见性、loader、条件、规模或集合完整性的边界；
- `failure_closed`：输入、工具、制品或证据不完整时不得给出虚假确定结论；
- `recovery`：中断、缓存损坏、重试或恢复后语义守恒；
- `metamorphic`：重打包、冷热缓存、重复/并发执行等不应改变公开语义的变形关系。
- `invalid_input`：缺失、畸形、类型错误、重复或不受支持的公开输入必须得到精确失败合同；
- `partial_failure`：结果写入、工具链、持久化或发布链中途失败时，主失败不能被覆盖，旧有效状态不能被污染；
- `state_transition`：首次运行、恢复、重试、回滚、重新激活和重复调用之间的状态机转换必须守恒；
- `concurrency`：多进程/多线程、相同 generation、并发读写和取消竞态必须验证允许的结果集合与禁止的部分状态；
- `resource_limit`：条目数、展开量、堆、时间、命令行、路径和数据规模达到或越过预算时，范围与正确性不得被静默缩减。

critical 能力至少覆盖三个不同维度，high 至少两个；所有能力必须包含 `nominal` 和至少一个逆向维度。系统级场景集合还必须显式出现 `invalid_input`、`partial_failure`、`state_transition`、`concurrency` 和 `resource_limit`，不能继续把这些故障都藏进宽泛的 `boundary` 或 `metamorphic` 标签。闭集源码案例从 expected、forbidden 和 baseline/repacked 双运行自动获得三维证据；其余能力必须在 `system_test_scenario_contracts.json` 中显式绑定真值。指针不存在、预期为空、测试未引用该真值、对应证据测试没有实际读取该指针字段，或风险维度不足，门禁都失败。仅在能力矩阵中挂一个无关测试名不能再制造“纸面覆盖”。

这套规则保护“已声明的公开能力”，不承诺穷尽所有未来功能或任意 Java 程序。新增公开能力、CLI 参数、Step 或 support-manifest 机制时，必须先扩充能力、真值和场景合同；不能靠提高无关用例数量维持覆盖声明。

### 2.5 案例设计完成条件

每次功能、重构或缺陷修复的测试设计必须先于实现评审，并满足：

- 从公开入口反推能力和结果集合，而不是从待修改函数反推断言；
- 每个正例至少有一个只改变单一关键条件的近邻反例；
- 对集合、长度、数量、路径、版本和状态枚举验证空值、单值、上限内、恰好上限和越界；
- 对有状态流程画出允许的状态迁移，至少验证中断点、重复执行、恢复、回滚和陈旧状态；
- 对共享文件、缓存、generation、进度和子进程列出至少一种可重复的并发交错；
- 对外部工具逐项覆盖 missing、permission、timeout、nonzero、empty、malformed 和重试耗尽；
- 对适用平台使用真实 OS/JDK/构建工具，明确哪些结论仍没有平台证据；
- 先用故意错误实现、变异或独立差分确认案例确实能失败，再接受其作为保护证据。

评审者必须逐项确认适用性。`N/A` 只允许附带可验证理由，例如纯无状态转换不存在并发共享对象；“暂未发现问题”“实现看起来简单”或“已有很多测试”不是理由。

## 3. 真值与第三方 Oracle

### 3.1 真值不能来自被测系统

正式黑盒真值必须满足 `system_generated=false`。被测系统输出只能作为待比较的 actual，不能复制、转换或筛选后成为 expected。

真值来源优先级如下：

1. JVM 实际加载或执行行为；
2. OpenJDK `javac`、`javap`、`jdeps` 等独立工具；
3. 与生产实现无共享代码的独立解析器或图求解器；
4. JLS、JVMS 和框架公开规范推导；
5. 有证据记录的人工复核。

单个第三方工具并不天然正确。关键结论应由两个不同机制交叉验证，例如 `javap` 的成员集合差异加 JVM 实际 `NoSuchMethodError`，或独立静态图加 Java Agent 运行轨迹。

### 3.2 每份真值必须记录

- case ID、schema 和数据集版本；
- `closed_set`、`status_closed_set` 或 `subset` 范围；
- Oracle producer、组织、工具类型和证据维度；
- 输入源码/制品及 case 配置（入口、坐标、探针）的内容身份；
- 完整性论证；
- 已验证维度和未验证边界；
- expected results 与 forbidden results；
- 是否经过人工复核；未经过时必须明确记录，不能伪造审核人。

### 3.3 冲突处理

当两个 Oracle、规范推导和人工复核不一致时：

1. 案例立即进入 quarantine；
2. 不得选择“更接近系统输出”的结论；
3. 查明工具边界、输入差异或规范解释；
4. 保存冲突证据；
5. 只有冲突被解决且真值重新审核后，案例才能恢复 Release 门控。

### 3.4 真值变更规则

系统实现和黄金真值可以在同一 PR 中变化，但真值变更必须：

- 有独立 Oracle 或规范证据；
- 在变更说明中单独列出；
- 解释旧真值为什么错误或产品契约为什么正式改变；
- 通过比较器负向测试和测试可信度门禁。

禁止为了让测试重新通过而静默更新 expected。

## 4. 白盒测试集

白盒测试保护当前实现，可以随架构调整而调整。它应覆盖：

- 纯函数、数据模型和状态机单元测试；
- artifact diff、runtime reconciliation、decision、trace、publication 集成测试；
- owner/descriptor/loader 精确身份；
- 正例与相近负例；
- 异常、损坏输入、超时、中断和恢复；
- 缓存一致性、并发、重复执行和原子发布；
- 属性测试、固定随机种子和变形测试；
- 核心逻辑变异测试。

白盒的设计单位不是测试文件或方法数量，而是“分析场景 × 调用关系 × 分支 alternative × 故障点”。能力矩阵中的 `whitebox_paths` 只是入口索引，不能证明内部路径实际执行。每次实现变化后必须重新生成生产 import/调用/分支图：新增路径自动成为缺口；删除或重构路径应同步更新白盒测试，但不得改动同一公开语义的黑盒真值。

静态解析只能证明一部分调用关系，因此准出同时保留运行时动态边。静态解析出现同一局部名称在条件分支中指向不同模块时必须标为未解析，不能随意选择一个目标制造假覆盖；构造器后立即调用、局部 import、嵌套函数、lambda/comprehension 和子进程晚加载模块必须由覆盖工具的自身回归保护。覆盖工具发生版本混用、spawn 重入、写证据失败或显著时序干扰时，该轮证据无效，不得归因于产品。

健康门对内容身份与正式状态合同中登记的全部分支 alternative 要求 100%（当前 70/70，无未覆盖行），而不是把低于完整覆盖的比例当作准出成功。这里的 100% 仅指门禁明确登记的关键函数，不冒充整个代码库的行/分支覆盖率；全系统充分性仍由能力矩阵、黑盒闭集、白盒与变异证据共同判断。

白盒测试可以读取内部结构，但不能作为最终结果正确性的唯一证明。内部模块重写后，可以删除或重写对应白盒测试；同一公开语义下黑盒真值不得随之变化。

变异测试至少保护：

- 忽略 JVM descriptor；
- 删除或错误增加图边；
- exact/possible 互换；
- reachable/uncertain/not-found 状态漂移；
- 依赖 lineage 或坐标交换；
- 路径截断但不报告；
- 假阳性、假阴性和 required path 被忽略。

## 5. 平台执行维度（非第四类测试）

操作系统是黑盒、白盒和性能三类测试的执行维度，不是用模拟分支即可替代的第四类测试。路径解析、进程句柄、控制台/GUI 父进程、文件共享、原子替换、命令行参数、可执行文件后缀和资源计量都具有真实 OS 语义；在 macOS/Linux 上 patch `os.name` 只能验证分支选择，不能证明 Windows 行为。

Windows 准出采用两层门禁：Ubuntu、macOS、Windows Server 2022/2025 × JDK 11/17/21 的 12-cell `quick` 矩阵继续验证共同合同；每个 Windows cell 额外执行 `python scripts/test_suite_runner.py --suite windows`。使用两个显式 Windows 版本，避免 `windows-latest` 漂移掩盖版本差异。Windows 套件是三类测试的受治理投影，由版本化 selector 清单与正数下限约束，实际选择数必须从当次 JSON 读取，文档数字不能充当执行证据。2026-08-23 的非执行静态投影为 142 项（60 黑盒、78 白盒、4 性能），唯一选择数同为 142、selector 缺口为 0，策略下限为 110；其中包含 2 JAR/6 class 性能守恒 smoke。它覆盖：

- `pythonw.exe` 无控制台父进程下 Git 与普通子进程的 stdout 捕获；
- 中文、空格和 shell 元字符路径/参数，以及真实 Git 必需输出的重复读取；
- Git worktree 创建、校验、回收、遗留目录恢复和受污染环境隔离；
- `CREATE_NO_WINDOW`、后台存活检测、超时后的 Windows 进程树清理；
- `java.exe`/`javac.exe`、独立 JDK 8/17、Maven/Gradle 8.10.2、真实 CRLF `.cmd`/`.bat` wrapper 和 Git longpaths 选择；
- 接近 240 字符安全预算的 Unicode 路径在真实 Git 和原子 JSON 读写中的保持；
- 多写者/并发读者下 JSON 原子发布不能出现部分文档；
- 完整黑盒独立真值在 Windows/JDK 组合上的结果集合与状态一致；
- 通过 Win32 `GetProcessTimes`/`GetProcessMemoryInfo` 取得 CPU、实际耗时和峰值内存，并验证小规模冷/热缓存与结果守恒。

该套件只能在原生 Windows 上运行；非 Windows 调用必须以 `WINDOWS_SUITE_REQUIRES_NATIVE_WINDOWS` 失败，不能把全部用例记为 skip。Windows 套件中任一 skip、selector 丢失、测试数低于版本化下限、公开能力矩阵不完整或证据 JSON 缺失都阻断平台 cell。CI 必须保存每个 Windows/JDK cell 的结构化结果；没有实际 Windows runner 证据时，只能声明跨平台静态合同通过，不能声明 Windows 已验证。

公开工具故障合同中有 1 项 POSIX 专用注入器依赖 shebang、mode bit 和脚本替换 `java`，不得伪装成 Windows 测试。策略显式排除该驱动，并要求由两项不可删证据共同替代：可移植公开黑盒验证 failure JSON/失败关闭，Windows 原生子进程验证 missing/nonzero/timeout/empty 的分类与重试性。排除项、原因和 replacement selectors 必须精确登记；缺少替代项会由可信度门阻断。若未来实现 Windows ACL/PE 级公开故障注入，应删除该排除并恢复完整端到端驱动。

## 6. 性能测试集

性能测试分三档：

| 档位 | 时机 | 目标 |
|---|---|---|
| performance smoke | PR/本地 | 小规模守恒、缓存和明显复杂度退化 |
| scheduled benchmark | 定时任务 | 稳定环境中的 P50/P95、趋势和阶段预算 |
| release scale gate | Release | 400 JAR/100000 class 完整流水线和内存上限 |

每次性能测量必须先验证正确性守恒：

- 输入 class/member/edge 数守恒；
- 变化事实和正式结果数量、身份、状态守恒；
- 独立 validation 无问题；
- 冷/热运行语义结果一致；
- 缓存命中不能跳过必要验证。

至少记录：wall time、按版本化 nearest-rank 方法计算的 P50/P95、峰值 RSS、进程及已完成子进程 CPU 时间、平均核数、磁盘字节、缓存命中率、解析调用数和输入规模。门禁会从原始 warm samples 重新计算 P50/P95，并校验 `average_cpu_cores = cpu_seconds / wall_seconds`，不能只信任结果文件里的汇总字段。不得通过抽样、少扫 JAR、减少路径或静默降级获得性能收益。

当前提交的 2026-08-23 规模证据通过“候选采集 → 独立完整复采 → 正式证据构建 → 当前实现回放”形成，保留三次 warm 原始 wall/CPU 样本、两条完整流水线的 CPU/RSS/阶段数据和总计派生值。复采 cold 为 122.336 秒，warm P50/P95 为 43.185/43.258 秒；相同两侧完整流水线为 183.227 秒且正式结果/validation issue 均为 0，单 JAR 中 250 class 变化流水线为 267.223 秒且变化事实/正式结果均精确为 250，最大记录 RSS 为 775749632 字节。所有 smoke、scheduled benchmark 和 release scale 都必须输出 CPU 秒与平均核数，缺失或派生关系错误即失败；历史记录没有 CPU 原始数据时只能明确标记缺口，禁止补造数字。

内容摘要与规范化 identity 的测试目标是证明同一执行链对同一份精确字节达成一致，并对陈旧、替换、读取竞态和结构伪装失败关闭；测试必须包含不同序列化字节、硬链接别名、重复键、非有限数、JSON 类型别名和读写期间变化。该机制不测试、也不得宣称证据来源的真实性或不可伪造性，因为具有工作区或执行环境写权限的主体能够重新生成自洽摘要。文件安全测试覆盖预置叶节点链接与临时文件替换，但同权限恶意并发者可在检查后替换祖先目录，属于必须由独占工作目录、文件权限和 CI 沙箱隔离的 TOCTOU 信任边界，不能由单次路径检查宣称解决。发布者认证属于外部供应链边界，应由受保护 CI、签名和 provenance/attestation 的独立验证承担；缺少这类外部信任根时，测试结论必须限定为内部完整性与一致性。

## 7. 测试可信度门禁

机器门禁必须检查：

- 黑盒目录没有生产模块 import、mock 或 skip；
- 黑盒案例只调用允许的公开入口；
- 真值 schema、case ID、范围和完整性论证有效；
- 闭集真值至少有两个独立机制，且 `system_generated=false`；
- expected identity 唯一且字段完整；
- closed-set 案例有 forbidden result；
- 黑盒案例数、expected 数和 forbidden 数不低于版本化策略中的硬门槛；
- 必需能力标签全部由至少一个闭集案例覆盖，删除案例或能力时门禁失败；
- 每项公开能力满足按风险分级的场景强度，并且每个场景指向非空的第三方真值；
- support manifest 中 13 项自动入口发现和 9 项运行时语义边类型逐条映射到已覆盖能力；
- 所有 6 个公开 CLI 的完整参数集合、帮助合同和非法参数失败合同保持精确一致；
- Oracle 文件通过生产实现依赖隔离审计；
- 黑盒、白盒、性能 selector 不重叠，所有测试都能被确定分类；
- CI 引用的测试模块存在；
- 强制黑盒和性能环境缺失时失败，不静默 skip；
- `quick`、`step5` 和白盒只允许策略中精确登记、由 Release-only 或原生平台门实际替代执行的 skip；任何新增、改名或未登记 skip 都阻断，黑盒、性能与 Windows profile 禁止任何 skip；
- 任何 `expectedFailure` 都按未修复缺陷阻断，不得算作通过；
- Windows selector 与强制清单完全一致，原生套件测试数不低于基线且任何 skip 失败；
- 每个已逃逸缺陷都有根因族、逃逸原因、系统性修复范围、独立真值、反例、精确黑盒/内部回归和至少一个合入前 profile；
- `quality_gate.py` 的结构化证据存在，实际 run 数大于零，failure/error/skip 明细与子进程状态一致；
- 比较器和可信度门自身接受变异/负向测试。
- `scripts/` 中每个 Python/shell 入口都被内部范围合同分类，分析 import 闭包没有未登记变化，所有支持工具 owner selector 可解析；
- 白盒结构报告分别列出函数、静态调用边和条件分支 alternative 的总数、已执行项、缺口及 test/process owner，不用单个综合百分比掩盖空洞。

### 7.1 所有缺陷的根因与系统性闭环

无论缺陷来自用户反馈、真实项目、自动化测试、代码评审还是内部观测，都必须先视为“某个机制可能失效的证据”，而不只是待修的报错位置。禁止“反馈什么问题就只修什么问题”：不得仅在当前分支、文件、项目、类名、错误码或 fixture 上增加特判，然后把当前复现消失写成问题已经解决。

根因未确认、问题类型未分类、影响范围和同类问题点未排查前，不得进入正式修复，不得把假设写成结论，也不得宣称缺陷已修复。每个缺陷必须按以下顺序完成并保存可复核证据：

1. **确认问题**：记录期望行为、实际行为、最小稳定复现、触发条件、未触发的近邻反例和证据来源；先排除错误输入、过期结果或使用方式误解。
2. **定位根本原因**：建立从输入、状态或环境到错误输出的因果链，明确最早发生偏差的责任边界；错误信息和最终异常只是现象，不能直接作为根因。
3. **分类问题性质**：至少在“架构/设计问题、实现/代码问题、配置/环境问题、需求/使用问题”中给出明确分类和依据。尤其必须回答它是“设计本身错误或缺失”，还是“设计正确但代码偏离”；证据不足时标为“根因未确认”，不能先改代码碰运气。
4. **判断问题范围**：明确是仅由唯一输入或外部状态触发的个例，还是同一机制可在其他输入、模块、步骤或平台复现的普遍问题。当前只有一个报告不构成“个例”的证据。
5. **全面排查同类点**：以根因机制而不是报错字符串为搜索条件，检查同一抽象、算法、状态迁移、校验规则、缓存键、解析/归一化路径和错误处理的全部实现与调用点；同时检查相关的上游输入、核心处理、下游报告、base/current 两侧、Step 变体、构建工具、JDK/操作系统和并发/恢复路径。只检查最初报错文件不算完成排查。
6. **记录横向排查结果**：列出搜索范围、方法、命中的同类位置、每个位置是否受影响及处置结论。没有发现其他命中时也必须保留可复核的搜索证据和边界，不能只写“未发现”。
7. **选择正确修复层级**：实现/代码问题应修复最早的公共错误点，并验证所有受影响调用方；架构/设计问题必须先修正唯一所有者文档中的模型、职责、数据流、不变量或失败语义，再调整实现和测试，禁止用局部条件分支掩盖设计缺陷。配置/环境或需求/使用问题应修正对应边界、诊断或说明，不能伪装成算法修复。
8. **按根因设计回归**：用黑盒测试保护外部语义，用白盒测试保护根因和公共修复点；至少包含原始复现、近邻反例，以及横向排查发现的其他同类位置。涉及并发、规模或平台时再加入性能、故障注入或原生平台回归。
9. **解释测试为何曾漏过**：说明上一轮未发现该问题的具体原因，例如场景维度缺失、Oracle 盲区、断言过弱、测试未进入 PR 门禁、skip、平台缺失或设计评审遗漏，并修复对应测试策略缺口。
10. **闭合逃逸缺陷登记**：真实项目或用户使用中逃逸的缺陷还必须在 `escaped_defect_regressions.json` 登记根因族、系统性修复范围、每个精确 selector 及其必跑 profile，并运行 `defect_regression_gate.py`。
11. **核实实际执行**：从质量 JSON 核对相应 profile 的实际 run、failure、error、skip，而不是只确认测试文件存在或单个复现已经通过。
12. **处理重复根因**：同一根因族再次出现时，必须重新打开模型或架构评审并扩大横向排查范围，不接受继续追加局部 `if`、硬编码或只针对当前项目的 fixture 补丁。

目前台账登记 26 个产品缺陷，共绑定 58 个精确测试 selector 和 27 条真值引用，落到 18 份唯一独立真值文档及相应控制值。前 18 个历史缺陷的逃逸原因按已有回归重建；随后登记的 8 个缺陷直接保存 incident 证据。基线门只防止已知教训被删除；未知缺陷发现能力仍依赖场景生成、变形关系、故障注入、变异测试、真实项目轮换和人工探索。

### 7.2 执行度与证据

每个 profile 的质量结果必须嵌入 `test_execution`，至少记录 selected、unique-selected、run、selector overlap、failure、error、skip、expected failure、loader failure、对应测试身份、skip 原因和耗时。重叠 selector 只能执行一次并使门禁失败，避免重复执行同一方法制造虚假数量；`expectedFailure` 不是成功。证据文件缺失、损坏、明细数量与计数不一致、schema/profile 不匹配、run 为零或证据状态与进程退出码矛盾时，`quality_gate.py` 自身失败。失败也必须写证据，不能因测试基础设施先失败而只留下空日志。

PR 工作流固定执行并汇总：三组 Python 版本的 `quick`、完整 Linux 黑盒、完整白盒、完整性能回归，以及分支/变异/重复有效性门；稳定检查名为 `pre-merge-quality`。三类完整分区的并集必须等于当次 discovery，且每条测试唯一归类，因此 Step5 子集仍可用于本地快速反馈，但不再代替 PR 的完整白盒/性能执行。平台工作流继续执行 12-cell quick，并在 6 个 Windows cell 运行严格 Windows 投影，由稳定检查 `platform-quality` 汇总全部 cell。分支保护必须在 GitHub 设置中把 `pre-merge-quality` 和 `platform-quality` 设为 required；仓库代码无法证明外部设置已经启用，所以未核实设置时不得宣称合入无法绕过门禁。定时/手工 Release 在此基础上继续执行固定真实项目和 400 JAR/10 万 class 规模门。

### 7.3 质量有效性指标

质量报告同时保留领先指标和结果指标，禁止只汇报“测试通过数”：

- 领先指标：能力 covered/partial/missing、各故障维度、独立 Oracle 数、selected/unique/run、重复选择、skip/loader failure、登记变异杀伤、关键分支、重复执行一致性、平台矩阵 cell 和证据对应 commit；
- 结果指标：实际使用逃逸缺陷数、严重度、根因族、首次应被哪条门发现、同根因复发次数、修复到回归入门耗时；
- 真实性规则：没有 incident telemetry 或平台执行证据时记为“未知/未执行”，不能记为 0；测试新增但未进入 required profile 时记为未落实；同一根因再次逃逸必须单独报告，不能被总测试数稀释。

准入要求是：所有已登记能力无 blocking gap，所有必跑 profile 有完整执行证据，登记变异全部被杀死，目标平台汇总通过，且本次真实缺陷完成逃逸闭环。趋势指标用于发现策略退化，不通过随意提高数量门槛制造好看的覆盖率。

## 8. 仓库内落地

测试治理的机器契约位于以下位置：

| 路径 | 职责 |
|---|---|
| `tests/fixtures/test_suite_policy.json` | 黑盒目录、必需案例/能力、公开入口白名单、白盒 skip 精确白名单，以及性能/Windows selector 和下限的版本化清单 |
| `tests/fixtures/system_test_capability_matrix.json` | 从公开入口、Step0~Step6 和 support manifest 反向建立的系统能力清单；逐项记录黑盒状态、Oracle、白盒/性能证据和缺口 |
| `tests/fixtures/system_test_scenario_contracts.json` | 每项能力的正常/反例/边界及无效输入、部分失败、状态迁移、恢复、并发、资源上限场景，以及第三方真值 JSON Pointer |
| `tests/fixtures/escaped_defect_regressions.json` | 已逃逸产品缺陷、根因族、逃逸原因、独立真值、控制值、精确回归与必跑 profile |
| `tests/fixtures/internal_test_scope.json` | 从实际 `scripts/` 文件和生产 import 闭包建立的内部测试责任清单；任何未分类文件或无测试 owner 的支持工具都会失败 |
| `scripts/test_trust_gate.py` | 静态审计黑盒隔离，校验源码树与 case 配置双重身份、真值来源、完整性和分类配置 |
| `scripts/defect_regression_gate.py` | 验证每个历史缺陷的测试仍存在且确实被声明的合入/发布 profile 选择 |
| `scripts/test_suite_runner.py` | 一次 discovery 后将每个测试唯一归入黑盒、白盒或性能集，并在原生 Windows 上执行三类测试的严格平台投影 |
| `scripts/unittest_evidence_runner.py` | 为 quick/step5 和定向模块执行保存 run/failure/error/skip/expected-failure/loader-failure 及测试身份，并为严格 profile 阻断 skip |
| `scripts/whitebox_call_coverage.py` | 从实际生产入口构建函数、静态调用边和字节码分支分母，并采集父/子进程运行时 owner 证据 |
| `scripts/whitebox_coverage_gate.py` | 在不替代普通正确性执行的前提下运行内部测试、合并结构证据，并对任何未覆盖责任失败 |
| `tests/windows_native_contract.py` | 仅由 Windows 门禁显式加载的 GUI 父进程、真实 Git/路径、进程树和并发文件发布合同；不在非 Windows 上制造 skip |
| `tests/blackbox/` | 只经公开 CLI 执行的黑盒驱动、标准库 harness 和外部 Oracle |
| `tests/fixtures/blackbox/` | 版本化源码输入、case 声明和非系统生成的闭集真值 |
| `scripts/binary_result_truth.py` | 精确比较结果身份、四维状态、归属和 required path 的通用比较器 |

当前二进制闭集由 16 个案例组成，合计 54 条 expected 和 16 条 forbidden；另有补充真值文档约束工作流、CLI、运行时语义、安全、性能和真实项目。工作流案例覆盖 Step0~Step6、统一输入确认、取消恢复、两侧制品抽取、Maven/Gradle checkout 构建、WAR、Step1 聚合歧义、范围选择和有界人读报告。成功案例逐项比较依赖 GAV 与版本变化、当前依赖清单、两侧制品 SHA-256、抽取后 JAR 的逐字节身份、正式输出和确认点状态；预期值来自版本化人工合同，输入事实由标准 ZIP 读取、SHA-256、OpenJDK 和独立图/查询 Oracle 复核，不调用系统内部分析模块。

测试清单持续变化，权威数量只来自当次 `test_suite_runner.py` JSON。2026-08-23 的本地静态 discovery 快照为 3382 项（黑盒 61、白盒 3158、性能 163），Windows selector 静态投影为 142 项（60/78/4）；这只是本次变更的审计快照，不是后续固定目标，也没有在当前主机上证明 Windows 原生通过。Windows 投影只精确选择可在原生 Windows 执行的方法，不得把明确的 Unix-only 测试带入后再用 skip 冒充通过。完整白盒只允许两项精确登记的替代执行：一个由 Release 真实项目门运行，一个由 Windows 原生矩阵运行；其他任何 skip 都失败。测试健康门另验证登记的关键分支、变异和稳定性复跑；具体命中数以当次门禁 JSON 为准。数字只用于发现测试被漏选或误分类，不作为覆盖充分性的替代指标。

同日的本地执行证据为：`quick` 的 1029 项全部被选择和裁决，门禁通过（1028 项实际通过、1 项 Windows 原生替代执行 skip）；`step5` 的 1618 项全部被选择和裁决，门禁通过（1616 项实际通过、2 项精确替代执行 skip）；完整黑盒 61/61 通过（使用官方元数据 SHA-256 校验的 macOS ARM64 JDK 8u504、JDK 17 和真实 Gradle）；性能分区 163/163 通过且零 skip。严格结构白盒执行 3320 个唯一内部/性能测试（2 项精确替代 skip、1 项由 profile-safe 等价边界替换），证明 2749/2749 个生产函数、5506/5506 条静态调用边、793/793 条登记动态调用边和 52572/52572 个分支 alternative，所有缺口与未登记动态边均为 0。以上证据均为 0 failure、0 error、0 expected failure、0 unexpected success、0 loader failure、0 非预期 skip；测试有效性门另得到 98/98 个登记分支替代、15/15 个登记变异被杀死，以及 84 项健康集连续两轮身份和时序稳定。最终汇总 `release` 随后从当前工作树完整执行并通过：3382 项唯一测试全部被选择和裁决，其中 3380 项实际通过、2 项精确替代执行 skip；Release 已实际执行其中的 MyBatis 真实项目替代项，Windows GUI 项仍等待原生矩阵。6/6 个固定真实项目通过，各项目 issue 列表为空；400 JAR/100000 class 的 source-bound 记录证据重放通过且 issue_count 为 0。当前结果仍不证明 Windows 六个原生 cell 或远端 GitHub required-check 配置已经通过/启用；这些结论必须等待对应 Windows CI 与仓库设置证据。

2026-08-13 的历史 `release` 实测完整通过：当时的 1112/1112 项测试为 0 failure、0 error，6/6 个固定版本真实项目通过；400 JAR/100000 class 的 cold 为 124.09 秒，三次 warm 的 P50/P95 为 42.61/44.66 秒，最大端到端 RSS 为 2714075136 字节。相同两侧完整流水线得到严格 0 条正式结果且 validation issue 为 0；仅改变 1 个 JAR 中 250 个 class 后，独立变化事实和正式结果都精确为 250，validation issue 仍为 0。首次 Release 还暴露了本机 Python CA 链导致真实项目下载失败的环境问题及恢复能力缺口；下载器现仅在标准 HTTPS 校验失败时使用系统 `curl` 的 HTTPS-only、证书校验备用路径，最终文件仍必须匹配 manifest 固定 SHA-256 才能发布到缓存，完整 Release 随后从头重跑并通过。该历史结果只保留为趋势基线，不替代上文当前工作树的 Release 证据，也不替代 Windows 原生套件的执行证据。

| 案例 | expected | forbidden | 主要外部语义 |
|---|---:|---:|---|
| `removed-methods-v1` | 3 | 1 | 方法删除、重载 descriptor、可达/不可达 |
| `removed-fields-v1` | 2 | 1 | 字段删除、可达/不可达 |
| `method-shapes-v1` | 5 | 1 | 构造器、静态方法、primitive/array descriptor、跨类三跳路径 |
| `interface-dispatch-v1` | 2 | 1 | `invokeinterface` 与默认方法删除 |
| `access-restriction-v1` | 3 | 1 | 方法/字段从 public 收窄为 private、`IllegalAccessError` |
| `removed-class-v1` | 7 | 1 | 整类删除、构造器/方法/字段、provider 与 class-definition 公开结果 |
| `descriptor-change-v1` | 8 | 1 | 方法返回值/参数和字段 descriptor 变化；旧符号链接失败、新符号完整出现 |
| `static-instance-change-v1` | 4 | 1 | 方法/字段 static 与 instance 互换、`IncompatibleClassChangeError` |
| `implementation-change-v1` | 2 | 1 | 契约不变但实现变化、可达/不可达及 JVM 可观察行为差异 |
| `virtual-inherited-dispatch-v1` | 2 | 1 | 子类符号引用解析到父类声明、继承方法删除及可达/不可达 |
| `abstract-method-change-v1` | 1 | 1 | 具体方法变为抽象方法、`AbstractMethodError` |
| `final-class-change-v1` | 2 | 1 | 类变为 final、旧子类定义失败与公开类级结论 |
| `final-method-change-v1` | 2 | 1 | 方法变为 final、旧子类覆盖导致 `IncompatibleClassChangeError` 及类定义失败 |
| `nestmate-private-path-v1` | 1 | 1 | Java 11+ nest host/member 私有调用、实现变化及目标 JVM 可观察行为 |
| `added-members-v1` | 3 | 1 | 方法/字段新增，以及字段初始化引起的隐式构造器实现变化 |
| `access-level-matrix-v1` | 6 | 1 | private/package/protected 收窄、同运行包和合法子类正例、protected 接收者约束与 `VerifyError` 类定义结果 |

每个二进制案例都在 ZIP 时间戳和 entry 顺序不同的两种打包下运行。真值由 OpenJDK `javap` 的完整成员、flags、规范化指令和调用图，JAR entry 清单，以及目标 JVM 的实际链接、类定义或返回值行为交叉确认；Oracle runner 使用单独 JAR，不进入被分析业务制品。策略文件将当前 16/54/16 固化为防退化线，并要求全部 16 个案例和 36 个闭集能力标签持续存在；删除任意一个已登记案例或能力会直接失败。数量门槛不能替代能力矩阵，新增能力必须增加相应证据而不能复用无关计数。

数量门槛只是防退化底线，不是“覆盖充分”的证明。2026-08-23 当次可信度门盘点 90 项公开能力，状态为 **90 covered / 0 partial / 0 missing**；90 项全部具有场景合同，共 279 个风险维度，逐条约束 support manifest 的 22 个框架机制声明。除原有正常、反例、边界、失败关闭、恢复和变形外，门禁现在强制系统级场景集合显式覆盖无效输入、部分失败、状态迁移、并发和资源上限；删除唯一对应维度会直接失败。门禁还固化黑盒断言位置和补充真值预期叶值，并校验每个场景指针中的非数字路径字段都由该能力登记的具体测试函数（含其本地 helper）实际读取，防止测试内容被静默掏空或用无关真值冒充覆盖。覆盖包括 Step0~Step6、所有公开 CLI、Maven/Gradle/WAR、二进制变化与路径状态、框架入口/资源/loader/MR-JAR、source overlay、查询与报告、缓存/并发/原子发布、工具故障、损坏制品和全部安全预算、目标 JVM、固定版本真实项目，以及小规模和 400 JAR/10 万 class 性能门。后续权威数量仍只取当次 `test_trust_gate.py` JSON，不把本段快照当成永久充分性证明。

90/90 只表示当前文档、公开入口、Step manifest 和 support manifest 所声明的能力均有登记且达到其 Oracle 与场景强度标准，不表示所有未来功能或任意输入都已被数学证明。新增或改变公开能力时必须先扩展矩阵和场景合同；`test_trust_gate.py` 会校验每个 Step、公开入口、support manifest section/细粒度机制和已声明黑盒标签都进入矩阵，不能通过删除测试、降低状态、删除场景或把白盒测试改名为黑盒来维持 90/90。

`blackbox`/`whitebox`/`performance` profile 仍可用于局部开发反馈，但只有能力矩阵全部为 `covered` 才允许系统级质量准出。`test_suite_runner.py --suite all` 在矩阵存在 `partial` 或 `missing` 时返回 `PUBLIC_CAPABILITY_MATRIX_INCOMPLETE`，即使当时执行的测试全部通过，也不得宣称“系统功能已全面验证”。

本轮扩展证明了“不报 bug 往往意味着场景还不够强”：独立场景先后暴露并修复了访问收窄状态错误、合法 protected 子类路径误报不兼容、非法 protected 外部接收者路径误报兼容、确定缺类被降级、继承声明归因缺失、abstract/final 变化误判、Java 11+ nestmate 私有调用被误判为非法访问、Step3 资源漏扫、Step4 零变化范围误选、报告事实丢失、运行时 provider 假变化、公开 CLI 泄漏 traceback、进度临时文件并发碰撞、相同不可变 generation 并发发布失败、重复 class 条目被错误放行、Spring 目录下 XML 被误当作行式注册表、Gradle 真正失败原因被通用帮助链接覆盖、合法 JDK 8 供应商归档因没有非必需的 `release` 文件而被拒绝，以及同一物理 provider 因 loader realm 被错误拆成多个公开身份等产品缺陷。JDK 场景由官方 SHA-256 校验的真实 JDK 8 归档触发；端到端黑盒随后固定使用真实 JDK 字节的无 `release` 硬链接变形，并要求 Step0~Step6 与独立 Oracle 全部通过，不能通过给 fixture 补写文件绕过。真实 MyBatis annotation 制品还暴露了 validation Oracle 对物理存在但已被 classpath 遮蔽的 caller 强制要求 dispatch 记录，造成 728 条错误问题并阻断正确结果；修复后完整性只对运行时实际选中的 caller 定义生效，同时保留已选中 caller 缺记录必须失败的近邻控制。新增成员真值设计时，独立 Oracle还发现并纠正了一条被遗漏的隐式构造器实现变化；这属于测试真值缺陷，不冒充产品 bug。另有若干 OpenJDK Oracle 对本地化错误文本、静态调用格式、构造器/flags/实现字节码、继承解析和 descriptor 对称集合的缺口被单独修复；本轮还修复了 `javap` `NestHost` 属性被误解析成 class declaration 的 Oracle 缺陷。Spring/MyBatis 真实项目原先把实际可链接方法写成不兼容，经固定制品上的 `javap` 与由旧版本编译、在两侧 JVM 执行的 linkage probe 交叉验证后纠正。测试 Oracle 的缺陷与产品缺陷必须分别记录，不能把前者算成产品质量通过，也不能因后者而反向修改真值。

安全测试通过真实 ZIP 和子进程故障覆盖条目数、总展开量、膨胀比、嵌套深度/大小、class/frame/record、helper heap/timeout，以及缺失、权限、非零退出、空/畸形输出和重试耗尽。性能 smoke 使用固定 2 JAR/6 class 检查外部耗时、RSS、冷/热缓存与 changed/unchanged 完整结果守恒；发布门重新计算已记录的 400 JAR/10 万 class 指标和正确性不变量，并在定时 Release 中实际重跑。固定真实项目门覆盖 Spring transaction、RabbitMQ listener、scheduled task 和 MyBatis annotation/XML；每份 manifest 固定 revision 与制品 SHA。MyBatis XML no-op 案例独立逐项比较 33 个 base/current 运行时制品的完整字节和 ZIP 清单，并要求完整四状态结果集严格为空。其余非空子集由固定 `javap` 成员/flags 合同和 JVM linkage probe 在产品流水线执行前复核，仍只按声明的目标 API 子集解释，不能推导未列出结果的完整性。

新增黑盒案例时：

1. 先定义公开输入、边界和待证明结论，再编写最小源码制品；
2. 在运行被测系统前，由外部工具、规范推导或人工复核形成真值；
3. 保存源码树、case 配置和独立 Oracle 实现的内容身份，以及 Oracle 机制、完整性论证、已验证维度和已知限制；
4. 正例旁放置相近负例，并对闭集进行 exact 结果集比较；
5. 运行 `test_trust_gate.py` 和黑盒 profile；输入确实变化时才根据新输入证据更新内容 SHA，不能借机重录语义 expected。

## 9. 执行入口

按测试类型运行：

```bash
python3 scripts/quality_gate.py --profile blackbox
python3 scripts/quality_gate.py --profile whitebox
python3 scripts/quality_gate.py --profile performance
```

按开发阶段运行：

```bash
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
python scripts/test_suite_runner.py --suite windows  # 仅原生 Windows
```

- `quick` 必须包含测试可信度门、闭集黑盒核心案例和跨平台进程合同；平台 CI 在 Ubuntu、macOS、Windows Server 2022/2025 × JDK 11/17/21 的 12 个 cell 上执行，并在每个 Windows cell 预置独立 JDK 8/17 与 Gradle 8.10.2，再追加严格 Windows 原生套件；
- `step5` 在 quick 基础上运行关键白盒集成与公开工作流，供本地快速反馈；PR 仍执行完整三类分区，不能用 step5 子集代替；
- `release` 运行全部测试、真实项目、测试健康门和大规模性能门。

直接审计历史缺陷回归绑定：

```bash
python3 scripts/defect_regression_gate.py
```

PR 必须由 `pre-merge-quality` 同时汇总 quick、完整 blackbox、完整 whitebox、完整 performance 和测试有效性门，并由 `platform-quality` 汇总全部平台 cell；任一 job 被跳过、取消或失败都不能得到汇总成功。每个 job 的 JSON artifact 是“实际执行”的证据，工作流日志或测试文件数量不能替代它。

也可直接审计测试可信度：

```bash
python3 scripts/test_trust_gate.py
```

`blackbox`、`performance` 和 `windows` 所需的 JDK、工具或 fixture 缺失时必须失败；黑盒、性能和 Windows 套件禁止任何 skip，`quick`、`step5` 与完整白盒仅接受版本化的精确替代执行白名单，任何 `expectedFailure` 都阻断，不能将“已知失败”或未执行当作通过。

## 10. 准出标准

重要优化或重构至少满足：

- 闭集黑盒：FP=0、FN=0、状态偏差=0、路径偏差=0；
- 对外 schema 与人读语义无未批准变化；
- 关键白盒测试和变异测试通过；
- 性能结果在准确性守恒后满足预算；
- 无非预期 skip；
- Oracle 和真值变更有独立证据；
- 实际执行过的命令、测试数量和限制如实记录。
- 实际使用缺陷已经登记根因/逃逸原因，并由独立真值、公开回归和内部根因回归共同保护；
- PR 汇总门与平台 required checks 成功，结构化执行证据存在且与返回码一致。

“没有发现问题”只表示当前数据集未触发问题；只有明确列出的能力和真值范围可以声明已验证。
