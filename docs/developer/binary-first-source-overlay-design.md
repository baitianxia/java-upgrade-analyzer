# Binary-first / Source-overlay 最终设计

## 1. 状态与目标

本文是 Step4–Step6 当前实现的最终设计合同，不是迁移方案。

当前能力迁移是否满足合并门，以
[`binary-first-capability-migration-audit.md`](binary-first-capability-migration-audit.md)
及其可执行台账为准；设计合同不能替代缺失的生产路径、测试或真实项目证据。

目标是以升级前后最终制品及其真实运行时闭包为唯一事实主线，回答三类问题：

1. 哪个依赖包发生了什么运行时有效变化；
2. 当前业务制品是否存在到该变化的静态触达路径；
3. 证据能支持到什么结论，哪些事实仍需要人工或运行时复核。

Step4–Step6 只存在一个 binary-first 引擎。不存在 legacy、shadow、灰度、兼容模式或 fallback。引擎失败时失败关闭并保留上一份已经独立验证的完整 generation，不调用旧逻辑补算，也不允许逐 API、逐事实或逐边降级。

这次变更只替换分析引擎，不改变产品原则：准确性优先，用户只在必须作实质选择时介入，过程可观察，结果对人可读，依赖包身份和证据边界不能丢失。

## 2. 不可变原则

### 2.1 最终制品是事实源

- 依赖、版本、类、方法、字段、资源、运行路径和调用边均以 base/current 最终制品为准。
- 源码不能把最终制品中不存在的依赖、类或边提升为正式事实。
- 本地 Maven/Gradle 缓存中的同坐标文件不能替代被分析制品。
- 容器内路径、物理 SHA-256、逻辑 lineage 和 Maven 坐标必须同时保留，不能只用文件名或 artifactId 识别制品。

### 2.2 源码只做覆盖层

源码覆盖由实际可用输入决定，不是授权开关。源码模式和 Artifact 模式都在 Step0 必须提供并确认应用源码；当前 Git 仓库可以自动识别，但不能跳过这次统一确认。依赖包源码可在同一张 Step0 表格中提供，也可以留空。两类源码的每一个输入都可以是 Git 地址或本地 Git 仓库目录。Step1 得到依赖坐标后才匹配已提供的依赖包源码及其 Base/Current 版本；仓库或不同 commit 存在真实歧义时汇总请用户选择，否则自动继续。Step2 只消费已固定输入并建立升级上下文，不再收集、分类或确认源码。

源码覆盖层可以补充名称、声明位置、注释、源码片段和行为解释，但不得：

- 决定一个二进制变化是否存在；
- 生成或删除 executable edge；
- 覆盖 class provider、member resolution 或 dispatch 结果；
- 在二进制证据不完整时伪造确定性结论。

源码不可用时，二进制主线仍按已有证据工作；需要源码才能解释的内容明确记录为覆盖缺口，不转化为用户必须修复的内部流程问题。

### 2.3 依赖包维度是正式主键

每条变化、projection、触达结果和人工报告必须携带：

- `coord`；
- base/current 版本与完整坐标；
- base/current artifact reference；
- logical lineage；
- container entry 或 runtime path origin；
- physical SHA-256。

无法绑定依赖的事实不能使用虚构的运行时坐标。确实无法绑定时使用显式未绑定状态并失败关闭相应完整性门；不得写成普通依赖变化。

### 2.4 人工阅读是正式输出，不是兼容投影

机器权威数据和人类阅读视图职责不同，但二者都属于正式产品合同：

- 权威数据用于守恒、查询、重放和独立验证；
- Markdown/CSV 用于人工复核、筛选、沟通和归档；
- 人类视图必须从同一 validated generation 确定性生成；
- 人类视图不能省略依赖坐标、版本变化、API 身份、调用路径或结论边界。

`all_changed_apis.csv` 是稳定的用户/API 变化视图，不是旧版兼容文件。不可投影为 API 的资源、安全或 topology 事实进入 `review.md` 和权威 decision，不制造占位 API。

## 3. 目录边界

新引擎文件按使用者和生命周期分区：

| 目录 | 使用者 | 内容 | 约束 |
|---|---|---|---|
| `.runtime/binary_authority/` | 引擎、验证器、深度审计 | immutable generations、SQLite、phase manifest、validation、失败记录和 active pointer | 不作为普通人工入口；不得与 evidence 混放 |
| `.runtime/state/` | 调度器 | 主状态、恢复状态和交互状态 | 只存流程状态，不存用户报告 |
| `.runtime/indexes/` | 查询工具 | Step5 查询索引 | 可重建，不是结论权威 |
| `evidence/api_changes/` | Step4 人工复核 | 依赖包清单、API 明细、非 API 事实复核页、按依赖分组的摘要 | 必须可直接阅读并保留依赖维度 |
| `evidence/call_chain/` | Step5 人工复核 | 四态摘要、逐 API 结果和路径明细 | 只发布本轮选择范围，同 generation |
| `deliverables/` | 最终用户 | 主报告、全部依赖、全部 API/调用关系、范围说明及 CSV | 先依赖后 API，Markdown 与 CSV 同源 |

不得把 SQLite、raw IR、缓存、内部 generation manifest 复制到 `evidence/` 冒充人工产物；也不得只发布 raw JSON 而删除人工阅读视图。

## 4. 输入合同

Binary pipeline 在进入 Step4A 前必须持有完整、持久化的 `binary_pipeline_config`，但正常用户流程不要求用户手写：Step1 从 base/current 最终制品自动物化两侧完整有序运行闭包、依赖身份和运行时 profile，Step4 直接消费该结果。仓库根目录 `binary_pipeline_config.example.json` 仅用于高级集成、离线重放或显式覆盖；自动物化失败时系统先给出具体缺失事实，不把内部配置格式转嫁给普通用户。

配置必须固定：

- base/current 最终制品；
- 每个运行时条目的 side、coord、lineage、物理路径和容器内逻辑路径；
- 有序 classpath/module path；
- loader realm 及父子委派策略；
- base/current 完整目标 JDK home；
- resource/security policy；
- 业务入口及其方法 descriptor；
- `source_inputs` 记录业务源码和依赖源码各自的实际可用状态与来源，不记录授权或全局启停决定；
- 存在源码时，`source_overlay.source_sets` 必须按业务系统或依赖包分别记录 `owner_type`、`owner_coord`、`module`、稳定 `source_root` 和源码目录；不存在某类源码时只记录该类覆盖缺口，不能删除另一类已经可用的 source set。

这些事实决定运行时有效性，不能从当前开发机 classpath 或未固定的构建目录猜测。缺失会改变结论的外部事实时，系统明确指出缺口；身份冲突、重复 provider、JDK 不完整、entrypoint 无法绑定或配置与制品 SHA 不一致时直接失败关闭。

## 5. 身份模型

### 5.1 Generation 身份

每次分析生成：

- `result_generation_identity`：绑定全部二进制输入、RuntimeProfile、policy 和输出；
- `analysis_context_identity`：绑定业务入口、选择范围和环境上下文；
- `validation_run_identity`：独立验证执行身份，不与生产 generation 复用。

Step4A、Step5A、Step4B、Step5B、Step6 必须属于同一 result generation。任一阶段读取到不同 identity 都停止发布。

### 5.2 Artifact 身份

Artifact identity 由逻辑和物理两部分组成：

- 逻辑：side、coord、version、lineage、runtime path kind、loader realm、container entry；
- 物理：normalized path、SHA-256、size 和 archive entry digest。

平台类使用明确的 JDK platform identity，不伪装成 Maven 依赖。

### 5.3 API 身份

方法/构造器使用 owner、member name、JVM descriptor 和 member kind；字段使用 owner、field name、descriptor 和 kind。展示签名从 JVM descriptor 无损转换为 Java 参数签名，机器关联仍使用 descriptor，避免重载混淆。

## 6. 单向处理流水线

### 6.1 Step4A：Artifact-local facts

对 base/current artifact pair 进行一次性采集和差异比较：

- archive inventory；
- classfile contract；
- method IR；
- runtime-consumed metadata；
- resources/services；
- security/topology facts；
- parser、selection 和 pairing completeness。

ZIP 时间戳、条目顺序、签名重打包等只有在版本化安全规则证明不影响已声明分析范围时才能排除。未知 attribute、解析失败、pairing 歧义或无法证明安全的差异不能被归为“无变化”。

### 6.2 Step5A：Runtime-effective reconciliation

按 RuntimeProfile 建立：

- class provider selection；
- class definition；
- member resolution；
- resource winner/merge；
- dispatch 和 class-init/linkage 语义；
- effective graph membership。

Artifact-local 变化只有在当前 realm/profile 下生效，或它本身属于当前分析范围可观察事实时，才能进入正式裁决。被其他 provider 遮蔽的变化保留审计证据，但不能生成正式 API 目标。

### 6.3 Step4B：Decision 与 projection freeze

所有变化事实进入三套互斥裁决：

1. `authoritative`：在支持边界内、证据完整、可进入正式结论；
2. `diagnostic_candidate`：可能相关但不足以进入正式总数，只用于诊断计划；
3. `excluded`：有独立证据证明在当前 scope 内不应进入正式结果。

Authoritative facts 再分为：

- 可投影 API facts：生成稳定 `reported_api_identity`；
- confirmed-unprojectable facts：资源、安全、topology 等真实变化，保留依赖身份并进入人工 `review.md`，但不制造 API 行。

同一 fact 不能同时属于多套裁决。fact、assessment、projection、reported API 和 contributing fact IDs 必须守恒。

### 6.4 Step5B：Batch binary trace

调用图直接来自业务制品、运行时依赖和目标 JDK 的字节码。按 entrypoint 批量遍历，不为每个 API 重新扫描制品。

每条展示路径必须保留逐边信息：

- caller class、member、descriptor 和 artifact；
- edge kind 与 bytecode offset；
- resolved target；
- exact/possible certainty；
- 最终变化 API 所属依赖坐标。

用户路径文本使用可读 Java 签名，例如：

```text
app.OrderJob.run() → client.PaymentClient.pay(Order) → sdk.PaymentApi.execute(Request)
```

机器结果同时保留结构化 edge 数组，不能只存字符串。

### 6.5 Step6：同 generation 报告

Step6 只读取已经激活且通过验证的 generation，以及 Step5 同 generation 的本轮范围。禁止重新分析、重新选择 provider 或拼接其他 generation 的结果。

## 7. 正式结果语义

二进制静态分析使用四个正交维度：

| 维度 | 值 | 说明 |
|---|---|---|
| `reachability_status` | `reachable` / `uncertain` / `not_found_in_static_analysis` / `not_analyzed` | 静态路径存在性及完成度 |
| `static_linkage_status` | `compatible_or_not_applicable` / `incompatible_if_executed` / `undetermined` | 若执行时的链接兼容性 |
| `impact_conclusion` | `probable_impact` / `inconclusive` | 当前证据可支持的影响判断 |
| `runtime_verification_status` | `required_not_executed` / `undetermined` | 系统未执行用户业务运行测试 |

四种 reachability 状态互斥：

- `reachable`：存在支持范围内的入口到目标 exact path；
- `uncertain`：存在 possible path 或已识别的语义/覆盖边界；
- `not_found_in_static_analysis`：已声明静态范围完成，但未发现路径；这不表示安全；
- `not_analyzed`：相关输入、解析或图范围未完成，不能给静态未命中结论。

静态分析不输出 `confirmed_impact`、`confirmed_no_impact` 或“已完成运行验证”。旧五态中的 `not_impacted` 不属于新引擎合同，也不在 JSON、终端卡片或最终报告中保留空字段。

## 8. 用户交互合同

### 8.1 只询问实质选择

Step4 产生至少两个含正式 API projection 的依赖时，用户可以选择：

- 全量分析；
- 部分依赖分析。

选择卡必须展示总依赖数、API 数、Top 10 依赖、业务字节码直接引用证据和完整清单路径。用户按完整坐标或依赖名选择，系统必须验证选择确实命中 Step4 清单。未选择对象必须记录在范围报告中，不能混入“未完成分析”。

内部网络、源码、parser 或缓存故障不转化为范围选择。系统先自动重试、修复或安全停止；只有缺少系统无法获得的外部运行事实，或不同选择会实质改变结论时才请求用户。

### 8.2 非阻塞结果卡

Step5 成功后生成非阻塞四态卡片，包含：

- 四态计数；
- probable/inconclusive 计数；
- 所选依赖范围；
- 依赖坐标、API 和路径样例；
- `not_found_in_static_analysis` 的边界说明；
- 人工复核入口。

卡片不要求用户点击继续，Step6 自动生成最终报告。

### 8.3 人工复核顺序

Step4：

1. `evidence/api_changes/changed_dependencies.md`：先确认哪个依赖包、哪个版本发生变化；
2. `evidence/api_changes/s4_per_dependency/<coord>/summary.md`：按依赖查看变化 API；
3. `evidence/api_changes/all_changed_apis.csv`：批量筛选和逐行复核；
4. `evidence/api_changes/review.md`：复核资源、安全、topology 和不可投影事实；
5. 深度审计才进入 `.runtime/binary_authority/.../binary_decisions.json`。

Step5：

1. `evidence/call_chain/summary.md`；
2. `evidence/call_chain/alerts.csv`；
3. `evidence/call_chain/by_api/*.json`；
4. 方法查询使用 `.runtime/indexes/s5_query_index.json`，普通用户不直接编辑索引。

Step6：

1. `deliverables/report.md`；
2. `deliverables/all-affected-dependencies.md/.csv`；
3. `deliverables/all-impact-details.md/.csv`；
4. `deliverables/analysis-scope.md`。

## 9. 人类报告最低字段

依赖级 Markdown/CSV 至少包含：

- `coord`；
- base/current 完整依赖坐标和版本；
- 变化 API 数；
- reachable/uncertain/not-found/not-analyzed 数；
- probable impact 数；
- 分析完成度和范围边界。

API/路径级 Markdown/CSV 至少包含：

- 依赖坐标及 base/current 版本；
- API 全名、Java 参数签名和 member kind；
- 变化类型；
- 四维结果；
- 主路径文本和路径 certainty；
- contributing fact identity 或权威 generation 证据路径。

Markdown 与 CSV 必须从同一排序后的数据集合生成；二者行数、范围和依赖归属必须可对账。

## 10. 失败关闭与原子发布

新 generation 写入 staging 目录，完成以下检查后才能激活：

- support manifest；
- identity/pairing 完整性；
- decision/projection/API 守恒；
- trace path 与 dependency binding 守恒；
- sidecar SHA；
- SQLite schema/integrity；
- 独立 Oracle；
- performance gate；
- 人工输出与权威数据的确定性对账。

任何检查失败：

1. 记录到 `.runtime/binary_authority/binary_failures/`；
2. 不切换 `active_binary_generation.json`；
3. 不覆盖已有 `evidence/`、`deliverables/` 和查询索引；
4. 不执行旧引擎；
5. 向用户说明当前任务未完成、原因和上一份结果是否仍可用。

发布时先验证全部临时目录，再原子替换 Step4/Step5/Step6 对应人工目录。人工发布任一阶段失败时恢复本轮发布前的 active pointer 和用户输出，避免出现“权威 generation 已切换但人类报告仍是旧结果”的撕裂状态。

## 11. 查询合同

Step5 查询索引只从本轮 validated generation 生成。查询条件支持：

- 完整方法及 Java 参数签名；
- 完整依赖坐标；
- artifactId；
- Java 包前缀。

响应必须返回依赖坐标、base/current 版本、API、四维结果和可读路径。JVM descriptor 只作为结构化身份字段，不能代替人类签名。查询不到时说明查询范围和 generation，不把“索引未命中”解释为无影响。

## 12. 正确性验证

### 12.1 独立 Oracle

Oracle 与生产实现只能共享最终制品、RuntimeProfile 和身份协议，不得复用生产 parser、normalizer、pairer、resolver、trace 或 decision 代码生成期望值。

在支持范围内逐项对账：

- artifact/class/member/resource inventory；
- provider 与 member resolution；
- change facts；
- decision 与 projection；
- exact/possible paths；
- 四维结果；
- 依赖坐标和版本绑定；
- 人工视图的行数和关键字段。

缺失、额外、重复、冲突或无法绑定本次制品的 Oracle 结果都使 generation 无法激活。

### 12.2 必备 fixture

测试至少覆盖：

- removed/signature/access/behavior change；
- 构造器、重载、字段和数组/object/primitive descriptor；
- direct/type/class-init/dynamic/linkage/dispatch edge；
- 同坐标多实例、同名不同坐标和 class shadowing；
- fat JAR/WAR container entry；
- JDK platform class；
- service/resource/security/topology confirmed-unprojectable facts；
- 纯重打包和安全噪声；
- parser/identity/pairing/entrypoint/JDK 不完整失败关闭；
- 全量/部分范围；
- 中文 Markdown 和 UTF-8 BOM CSV；
- Step4/5/6 发布失败后旧结果保持不变；
- 查询结果的依赖身份、Java 签名和完整路径。

### 12.3 数据库契约变化旁路检查

数据库契约变化检查属于 Step3 的双侧制品检查，不改变 Step4/Step5 的 API 事实与调用可达性语义。输入只能来自 Step1 保留的 base/current 业务制品和完整运行时依赖 JAR，并保留产生契约变化的依赖坐标。

首版支持 MyBatis Mapper XML、MyBatis 注解 SQL、JPA/Jakarta Persistence 和 MyBatis-Plus 持久化映射。普通 DTO 字段不构成数据库契约事实；只有进入 SQL、ResultMap 或 ORM 持久化映射的表/列要求才进入结果。MyBatis-Plus 无注解约定式实体只通过同一制品内的 `BaseMapper<Entity>` 泛型绑定激活；跨制品实体无法绑定时必须形成覆盖缺口。显式表/列标识可形成“确认”证据，动态 SQL、默认命名和 Provider 间接 SQL 只能形成“需复核”证据。

该检查不得扫描 DDL/迁移文件，也不得推断数据库变更已存在、已发布或已在目标环境执行。输出必须包含人类可读 Markdown、结构化 CSV、覆盖汇总 JSON；制品缺失、摘要与明细不一致或解析不完整必须形成覆盖缺口，不能写成“确认没有变化”。主报告仅限量展示，并在该展示位置直接链接完整明细。

## 13. 性能合同

性能优化不能改变正式事实集合或降低覆盖：

- 每个 archive/classfile 在同一 generation 内只采集一次；
- graph 和 SCC 批量构建，多目标共享遍历；
- 缓存键包含 artifact SHA、RuntimeProfile、policy 和 parser version；
- 缓存完整性失败直接重建，不能读取近似结果；
- 记录端到端耗时、各 phase 耗时、峰值 RSS、archive/class/edge 数和缓存命中率；
- 性能回归门和准确性 Oracle 同时通过后才能发布。

## 14. Main 与当前分支的同输入对比

替换验收不能只比较“输出文件更多”或总数变化。每个对比 fixture 必须先独立写出真值，再让 main 和当前分支消费同一组 base/current 最终制品。

对比表至少包含：

- 真值中的依赖坐标和版本；
- 真值变化类型及 API/resource 身份；
- 真值业务入口和预期路径；
- main 实际结论及证据文件；
- 当前分支实际四维结论、依赖绑定和证据文件；
- 漏报、误报、身份丢失、路径错误和不可判定项；
- 冷启动耗时与峰值内存，环境和命令一致性说明。

当前分支需要额外显式 RuntimeProfile，这不是更换输入制品；它是把原先隐含或猜测的运行事实写入可审计合同。对比报告必须明确这一差异，不能把更多运行时信息带来的结果改善伪装成单纯算法优势。

## 15. 完成标准

只有同时满足以下条件，才算引擎替换完成：

- 生产 Step4–Step6 不存在旧引擎入口、选择参数、fallback 或混合 generation 路径；
- 正式 schema 不保留旧五态、P0/P1/P2 或 confirmed impact/no-impact 空壳；
- 依赖坐标和 base/current artifact identity 贯穿全部正式结果；
- Step4、Step5、Step6 的 Markdown/CSV 人工输出完整可读；
- 新旧目录边界符合第 3 节；
- failure/atomic publication 测试通过；
- 独立 Oracle、端到端、查询、交互和全量回归测试通过；
- main/当前分支同输入对比基于预先声明真值，并保存可复核证据；
- 代码、配置、README、Skill、用户文档和架构文档使用同一单引擎语义。
