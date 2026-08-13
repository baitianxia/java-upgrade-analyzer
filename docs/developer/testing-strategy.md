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

critical 能力至少覆盖三个不同维度，high 至少两个；所有能力必须包含 `nominal` 和至少一个逆向维度。闭集源码案例从 expected、forbidden 和 baseline/repacked 双运行自动获得三维证据；其余能力必须在 `system_test_scenario_contracts.json` 中显式绑定真值。指针不存在、预期为空、测试未引用该真值、对应证据测试没有实际读取该指针字段，或风险维度不足，门禁都失败。仅在能力矩阵中挂一个无关测试名不能再制造“纸面覆盖”。

这套规则保护“已声明的公开能力”，不承诺穷尽所有未来功能或任意 Java 程序。新增公开能力、CLI 参数、Step 或 support-manifest 机制时，必须先扩充能力、真值和场景合同；不能靠提高无关用例数量维持覆盖声明。

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

## 5. 性能测试集

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

当前提交的 2026-08-13 规模证据来自一次完整实测，保留三次 warm 原始 wall/CPU 样本、两条完整流水线的 CPU/RSS/阶段数据和总计派生值。所有 smoke、scheduled benchmark 和 release scale 都必须输出 CPU 秒与平均核数，缺失或派生关系错误即失败；历史记录没有 CPU 原始数据时只能明确标记缺口，禁止补造数字。

## 6. 测试可信度门禁

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
- 比较器和可信度门自身接受变异/负向测试。

## 7. 仓库内落地

测试治理的机器契约位于以下位置：

| 路径 | 职责 |
|---|---|
| `tests/fixtures/test_suite_policy.json` | 黑盒目录、必需案例/能力、公开入口白名单和性能 selector 的版本化清单 |
| `tests/fixtures/system_test_capability_matrix.json` | 从公开入口、Step0~Step6 和 support manifest 反向建立的系统能力清单；逐项记录黑盒状态、Oracle、白盒/性能证据和缺口 |
| `tests/fixtures/system_test_scenario_contracts.json` | 每项能力的 nominal/反例/边界/失败关闭/恢复/变形场景，以及第三方真值 JSON Pointer |
| `scripts/test_trust_gate.py` | 静态审计黑盒隔离，校验源码树与 case 配置双重身份、真值来源、完整性和分类配置 |
| `scripts/test_suite_runner.py` | 一次 discovery 后将每个测试唯一归入黑盒、白盒或性能集 |
| `tests/blackbox/` | 只经公开 CLI 执行的黑盒驱动、标准库 harness 和外部 Oracle |
| `tests/fixtures/blackbox/` | 版本化源码输入、case 声明和非系统生成的闭集真值 |
| `scripts/binary_result_truth.py` | 精确比较结果身份、四维状态、归属和 required path 的通用比较器 |

当前二进制闭集由 16 个案例组成，合计 53 条 expected 和 16 条 forbidden；公开黑盒驱动包含 52 个测试方法，并由 20 份补充真值文档约束工作流、CLI、运行时语义、安全、性能和真实项目。工作流案例覆盖 Step0~Step6、统一输入确认、取消恢复、两侧制品抽取、Maven/Gradle checkout 构建、WAR、Step1 聚合歧义、范围选择和有界人读报告。成功案例逐项比较依赖 GAV 与版本变化、当前依赖清单、两侧制品 SHA-256、抽取后 JAR 的逐字节身份、正式输出和确认点状态；预期值来自版本化人工合同，输入事实由标准 ZIP 读取、SHA-256、OpenJDK 和独立图/查询 Oracle 复核，不调用系统内部分析模块。

本轮受治理 discovery 的当前基线为 1112 项：黑盒 52、白盒 1020、性能 40，三类唯一归属且无重叠；测试健康门另要求 70/70 个登记的关键分支 alternative 命中、14/14 个关键变异被杀死，并执行两轮稳定性复跑。该数字只用于发现测试被漏选或误分类，不作为覆盖充分性的替代指标。

2026-08-13 的最终 `release` 实测完整通过：1112/1112 项测试为 0 failure、0 error，6/6 个固定版本真实项目通过；400 JAR/100000 class 的 cold 为 124.09 秒，三次 warm 的 P50/P95 为 42.61/44.66 秒，最大端到端 RSS 为 2714075136 字节。相同两侧完整流水线得到严格 0 条正式结果且 validation issue 为 0；仅改变 1 个 JAR 中 250 个 class 后，独立变化事实和正式结果都精确为 250，validation issue 仍为 0。首次 Release 还暴露了本机 Python CA 链导致真实项目下载失败的环境问题及恢复能力缺口；下载器现仅在标准 HTTPS 校验失败时使用系统 `curl` 的 HTTPS-only、证书校验备用路径，最终文件仍必须匹配 manifest 固定 SHA-256 才能发布到缓存，完整 Release 随后从头重跑并通过。

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

每个二进制案例都在 ZIP 时间戳和 entry 顺序不同的两种打包下运行。真值由 OpenJDK `javap` 的完整成员、flags、规范化指令和调用图，JAR entry 清单，以及目标 JVM 的实际链接、类定义或返回值行为交叉确认；Oracle runner 使用单独 JAR，不进入被分析业务制品。策略文件将当前 16/53/16 固化为防退化线，并要求全部 16 个案例和 35 个闭集能力标签持续存在；删除任意一个已登记案例或能力会直接失败。数量门槛不能替代能力矩阵，新增能力必须增加相应证据而不能复用无关计数。

数量门槛只是防退化底线，不是“覆盖充分”的证明。机器能力矩阵当前盘点 89 项公开能力，状态为 **89 covered / 0 partial / 0 missing**；89 项全部具有场景合同，共 260 个风险维度，逐条约束 support manifest 的 22 个框架机制声明。门禁还固化 621 个黑盒断言位置和 1063 个补充真值预期叶值，并校验每个场景指针中的非数字路径字段都由该能力登记的具体测试函数（含其本地 helper）实际读取，防止测试内容被静默掏空或用无关真值冒充覆盖。覆盖包括 Step0~Step6、所有公开 CLI、Maven/Gradle/WAR、二进制变化与路径状态、框架入口/资源/loader/MR-JAR、source overlay、查询与报告、缓存/并发/原子发布、工具故障、损坏制品和全部安全预算、目标 JVM、固定版本真实项目，以及小规模和 400 JAR/10 万 class 性能门。

89/89 只表示当前文档、公开入口、Step manifest 和 support manifest 所声明的能力均有登记且达到其 Oracle 与场景强度标准，不表示所有未来功能或任意输入都已被数学证明。新增或改变公开能力时必须先扩展矩阵和场景合同；`test_trust_gate.py` 会校验每个 Step、公开入口、support manifest section/细粒度机制和已声明黑盒标签都进入矩阵，不能通过删除测试、降低状态、删除场景或把白盒测试改名为黑盒来维持 89/89。

`blackbox`/`whitebox`/`performance` profile 仍可用于局部开发反馈，但只有能力矩阵全部为 `covered` 才允许系统级质量准出。`test_suite_runner.py --suite all` 在矩阵存在 `partial` 或 `missing` 时返回 `PUBLIC_CAPABILITY_MATRIX_INCOMPLETE`，即使当时执行的测试全部通过，也不得宣称“系统功能已全面验证”。

本轮扩展证明了“不报 bug 往往意味着场景还不够强”：独立场景先后暴露并修复了访问收窄状态错误、合法 protected 子类路径误报不兼容、非法 protected 外部接收者路径误报兼容、确定缺类被降级、继承声明归因缺失、abstract/final 变化误判、Java 11+ nestmate 私有调用被误判为非法访问、Step3 资源漏扫、Step4 零变化范围误选、报告事实丢失、运行时 provider 假变化、公开 CLI 泄漏 traceback、进度临时文件并发碰撞、相同不可变 generation 并发发布失败、重复 class 条目被错误放行，以及 Spring 目录下 XML 被误当作行式注册表等产品缺陷。新增成员真值设计时，独立 Oracle 还发现并纠正了一条被遗漏的隐式构造器实现变化；这属于测试真值缺陷，不冒充产品 bug。另有若干 OpenJDK Oracle 对本地化错误文本、静态调用格式、构造器/flags/实现字节码、继承解析和 descriptor 对称集合的缺口被单独修复；Spring/MyBatis 真实项目原先把实际可链接方法写成不兼容，经固定制品上的 `javap` 与由旧版本编译、在两侧 JVM 执行的 linkage probe 交叉验证后纠正。测试 Oracle 的缺陷与产品缺陷必须分别记录，不能把前者算成产品质量通过，也不能因后者而反向修改真值。

安全测试通过真实 ZIP 和子进程故障覆盖条目数、总展开量、膨胀比、嵌套深度/大小、class/frame/record、helper heap/timeout，以及缺失、权限、非零退出、空/畸形输出和重试耗尽。性能 smoke 使用固定 2 JAR/6 class 检查外部耗时、RSS、冷/热缓存与 changed/unchanged 完整结果守恒；发布门重新计算已记录的 400 JAR/10 万 class 指标和正确性不变量，并在定时 Release 中实际重跑。固定真实项目门覆盖 Spring transaction、RabbitMQ listener、scheduled task 和 MyBatis annotation/XML；每份 manifest 固定 revision 与制品 SHA。MyBatis XML no-op 案例独立逐项比较 33 个 base/current 运行时制品的完整字节和 ZIP 清单，并要求完整四状态结果集严格为空。其余非空子集由固定 `javap` 成员/flags 合同和 JVM linkage probe 在产品流水线执行前复核，仍只按声明的目标 API 子集解释，不能推导未列出结果的完整性。

新增黑盒案例时：

1. 先定义公开输入、边界和待证明结论，再编写最小源码制品；
2. 在运行被测系统前，由外部工具、规范推导或人工复核形成真值；
3. 保存源码树、case 配置和独立 Oracle 实现的内容身份，以及 Oracle 机制、完整性论证、已验证维度和已知限制；
4. 正例旁放置相近负例，并对闭集进行 exact 结果集比较；
5. 运行 `test_trust_gate.py` 和黑盒 profile；输入确实变化时才根据新输入证据更新内容 SHA，不能借机重录语义 expected。

## 8. 执行入口

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
```

- `quick` 必须包含测试可信度门、闭集黑盒核心案例和跨平台进程合同；平台 CI 在 Ubuntu/macOS/Windows × JDK 11/17/21 上执行，其中 Windows 专用 `pythonw` 用例不得只在非 Windows 环境中以 skip 存在；
- `step5` 在 quick 基础上运行关键白盒集成与公开工作流；
- `release` 运行全部测试、真实项目、测试健康门和大规模性能门。

也可直接审计测试可信度：

```bash
python3 scripts/test_trust_gate.py
```

`blackbox` 和 `performance` 所需的 JDK、工具或 fixture 缺失时必须失败；结果中的 `skipped` 数量必须显式复核，不能将 skip 当作通过。

## 9. 准出标准

重要优化或重构至少满足：

- 闭集黑盒：FP=0、FN=0、状态偏差=0、路径偏差=0；
- 对外 schema 与人读语义无未批准变化；
- 关键白盒测试和变异测试通过；
- 性能结果在准确性守恒后满足预算；
- 无非预期 skip；
- Oracle 和真值变更有独立证据；
- 实际执行过的命令、测试数量和限制如实记录。

“没有发现问题”只表示当前数据集未触发问题；只有明确列出的能力和真值范围可以声明已验证。
