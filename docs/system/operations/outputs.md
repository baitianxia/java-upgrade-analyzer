# 输出文件与人工复核指南

本文说明 `.upgrade-report/` 中当前真实存在的人工交付、复核证据和程序文件。Step4～Step6 只发布同一个已经独立验证并激活的 binary generation；源码只增加位置、声明和解释，不能创建二进制事实或可执行边。

所有 CSV 使用 UTF-8 BOM，便于 Excel 直接打开；JSON 和 Markdown 使用 UTF-8。

## 阅读原则

`.upgrade-report/` 分为三层：

| 目录 | 主要读者 | 用途 |
|---|---|---|
| `deliverables/` | 使用者、评审人 | 最终交付、完整依赖/API 明细和范围说明 |
| `evidence/` | 人工复核人 | 依赖、上下文、兼容线索、变化事实和系统触达证据 |
| `.runtime/` | 程序、深度审计人 | 状态、generation、索引、恢复和观测信息 |

普通复核从 `deliverables/report.md` 开始，不需要打开 SQLite、generation manifest 或内部索引。机器权威与人类视图职责不同，但人类视图必须由同一 validated generation 确定性生成。

主报告的内容顺序：

1. 依赖层面结论：本轮纳入的依赖、完成度、可能影响和仍不确定的边界；
2. API 及调用关系：变化 API、静态触达状态、链接状态、影响结论、运行验证状态和关键路径；
3. 用户可见文件说明：完整明细、原始记录、范围和诊断入口。

顶部目录只承担章节导航。目录只链接实际生成的章节，并使用 Markdown 标题锚点，不在人工报告中插入 HTML 标签。依赖、API 和运行时资源的主报告明细都必须设置展示上限，标明展示数、总数和未展示数；对应位置必须直接给出完整 Markdown、CSV 或证据文件入口。完整表格保留所有本轮对象，主报告不以节选替代全量交付。

每个用户可见文件应直接说明它回答的问题、结论的证据边界、对应依赖和版本、关键路径、未完成事实及复核入口。主报告使用读者语言，不展示分析引擎内部状态或原因码。

## 结论语义

正式结果使用四个互相独立的维度：

| 维度 | 程序值 | 人工含义 |
|---|---|---|
| 静态触达 | `reachable` | 支持范围内存在入口到目标的精确路径 |
| 静态触达 | `uncertain` | 存在可能路径、语义边界或覆盖限制 |
| 静态触达 | `not_found_in_static_analysis` | 声明的静态范围已完成但未找到路径；不表示安全 |
| 静态触达 | `not_analyzed` | 输入、解析、能力或预算使本次未完成分析 |
| 静态链接 | `compatible_or_not_applicable` / `incompatible_if_executed` / `undetermined` | 如果执行该路径，静态链接是否兼容 |
| 影响结论 | `probable_impact` / `inconclusive` | 当前静态证据支持“可能影响”或“仍不确定” |
| 运行验证 | `required_not_executed` / `undetermined` | 本工具没有替用户执行真实业务运行验证 |

静态路径存在不等于运行时事故，静态未找到路径也不等于系统安全。源码、候选关系、配置线索和性能观测都不能把四维结果提升为已经执行的运行验证。

## 推荐复核顺序

| 顺序 | 文件 | 回答的问题 |
|---:|---|---|
| 1 | `deliverables/report.md` | 本轮范围、主要结果和限制是什么 |
| 2 | `deliverables/all-affected-dependencies.md` | 每个纳入依赖的完整结果是什么 |
| 3 | `deliverables/all-affected-dependencies.csv` | 如何按依赖筛选同一结果 |
| 4 | `deliverables/all-impact-details.md` | 每个变化 API 的四维状态和完整调用关系是什么 |
| 5 | `deliverables/all-impact-details.csv` | 如何按 API、依赖或状态筛选同一结果 |
| 6 | `evidence/call_chain/alerts.csv` | 形成 Step5 视图的逐 API 原始记录是什么 |

若范围或输入存在限制，再读 `deliverables/analysis-scope.md` 和条件生成的 `deliverables/analysis-diagnostics.md`。若需核对变化事实，回到 `evidence/api_changes/`；若需深度审计 generation，进入 `.runtime/binary_authority/`。

## Step1：分析对象与依赖范围

Step1 以用户提供或真实构建的 base/current 最终制品为事实源。制品内 Maven 元数据优先；构建工具模型只能补齐实际存在的条目，不能扩展运行闭包。正式流程不读取 `~/.m2` 中的同坐标文件，也不下载替代依赖。

| 文件 | 用途 |
|---|---|
| `evidence/dependencies/dep_changes.csv` | base/current 依赖差异明细 |
| `evidence/dependencies/dep_summary.txt` | 构建制品、模块和变化规模摘要 |
| `evidence/dependencies/dep_alerts.csv` | 降级、删除、未解析等优先复核项 |
| `evidence/dependencies/build_provenance.json` | 制品来源、固定 ref/commit 和摘要 |
| `evidence/dependencies/s1_artifacts/` | 留存的 base/current 最终制品 |
| `evidence/dependencies/dependency_jars.json` | 后续分析使用的运行时依赖清单与 SHA-256 |
| `evidence/dependencies/s1_dependency_jars/` | 从最终制品固定的依赖 JAR |

`dep_changes.csv` 只在完整比较成功后发布；进度和耗时不是部分依赖事实。

## 运行监控与性能诊断

观测信息位于 `.runtime/observability/`，不参与 generation 内容身份，也不证明依赖、API 或路径结论。

| 文件 | 用途 |
|---|---|
| `.runtime/observability/progress.jsonl` | 当前有界进度段，记录步骤、阶段、进度、耗时、当前对象和心跳 |
| `.runtime/observability/progress.previous.jsonl` | 上一个有界进度段；轮转时最多保留一个 |
| `.runtime/observability/step1_progress.jsonl` | Step1 ref、构建和依赖解析进度 |
| `.runtime/observability/step1_timing.csv` | Step1 阶段耗时 |
| `.runtime/observability/step4_timing.csv` | fact、reconciliation、decision、trace、Oracle 和发布耗时 |
| `.runtime/observability/step5_timing.csv` | 选择范围、索引和 Step5 人工视图发布耗时 |

统一进度文件的当前段和上一段各自有 8 MiB 上限；单事件有 256 KiB 上限。超长事件只截断观测字段并留下截断标记，不能导致正式分析失败或改变结论。

## Step2：升级上下文

| 文件 | 用途 |
|---|---|
| `evidence/context/review.md` | 人工核对模块、版本、JDK、Spring Boot 和源码覆盖 |
| `evidence/context/context.json` | 程序使用的完整升级上下文 |
| `evidence/context/dep_graph.json` | 程序使用的依赖关系 |

## Step3：背景兼容线索

Step3 线索不能直接证明当前系统受影响，也不能创建 Step4 正式变化事实。

| 文件 | 用途 |
|---|---|
| `evidence/static_scan/s3_jdk_removed_api.csv` | JDK 已移除 API 线索 |
| `evidence/static_scan/s3_jdk_javax_refs.csv` | Jakarta 迁移线索；JDK 自带 `javax` 包不计为迁移项 |
| `evidence/static_scan/s3_jdk_internal_api.csv` | JDK 内部 API 和强反射线索 |
| `evidence/static_scan/s3_springboot_config.csv` | Spring Boot 配置线索与扫描完成度 |
| `evidence/static_scan/s3_dependency_compat.csv` | current 最终制品内依赖兼容规则命中 |
| `evidence/static_scan/s3_dependency_classfile.csv` | 实际打包依赖的 classfile 版本台账 |
| `evidence/static_scan/s3_database_contract_changes.md/.csv` | MyBatis/ORM 数据访问契约的 Step3 原始证据；每个契约位置一行，同一表列可出现多行 |
| `evidence/static_scan/s3_database_contract_summary.json` | 数据库契约覆盖和缺口摘要 |

数据库契约扫描不证明 DDL 已存在或执行；无法绑定跨制品实体时记录覆盖缺口，不猜测关系。
最终报告在同一依赖来源范围内按“表 + 列/整表 + 变化方向”去重展示，并把上述每个契约位置
保留为证据。由于扫描结果没有物理数据源身份，相同表列不会跨依赖合并；多表语句、动态 SQL、
只有 ResultMap 列而无法确定表名，或表列集合未发生明确增删的映射变化，单独进入“待复核线索”。

## Step4：依赖与变化事实

人工优先看的文件：

| 文件 | 用途 |
|---|---|
| `evidence/api_changes/changed_dependencies.md` | 依赖包维度的范围选择和人工复核入口 |
| `evidence/api_changes/s4_per_dependency/<coord>/summary.md` | 单依赖变化摘要和证据 |
| `evidence/api_changes/review.md` | 不可投影为 API 的资源、安全或 topology 事实 |
| `evidence/api_changes/all_changed_apis.csv` | validated generation 的完整 API 变化视图 |
| `evidence/api_changes/business_bytecode_changed_api_refs.csv` | 业务最终制品对变化 API 的逐指令精确直接引用证据 |
| `evidence/api_changes/business_bytecode_priority_evidence.json` | Top 10 排序所用扫描覆盖与引用计数 |

`changed_dependencies.md` 和 `changed_dependencies.csv` 是依赖包维度入口；`all_changed_apis.csv` 是完整 API 明细，不是范围选择入口。至少两个候选依赖时才存在全量/部分选择；0 个或 1 个候选自动继续。Top 10 仅在用户已经选择缩小范围时帮助排序，不代表系统建议缩小范围，也不代表已发现运行时影响。

源码解释位于 `evidence/source_analysis/`：

| 文件 | 用途 |
|---|---|
| `review.md` | 源码归属、制品、方法、文件/行号、声明、注解和覆盖边界 |
| `method_mappings.csv` | 二进制成员到源码位置的映射 |
| `candidate_relationships.csv` | 源码候选关系；不是可执行边或正式触达结论 |

## Binary generation 深度审计

深度排查或程序使用的文件位于 `.runtime/binary_authority/`：

```text
active_binary_generation.json
binary_generations/<result_generation_identity>/
  base_binary_facts.sqlite
  current_binary_facts.sqlite
  binary_decisions.json
  binary_projections.json
  binary_formal_results.json
  binary_candidate_results.json
  binary_entrypoints.json
  binary_coverage.json
  binary_summary.json
  binary_formal_results.csv
  validation/<validation_run_identity>.json
binary_failures/
```

`active_binary_generation.json` 只指向已经完成身份、守恒、sidecar、SQLite 和独立 Oracle 校验的 generation。验证失败的 staging generation 不激活，也不覆盖现有人工结果。

可执行直接边保存在 generation 的事实库中，并由独立 Oracle 从原始最终制品复核。系统不额外发布一份可脱离 generation 身份的边 CSV 台账；需要程序核对时读取绑定该 generation 的 SQLite、正式 sidecar 和 validation 结果。

## Step5：系统触达证据

人工优先入口：

| 文件 | 用途 |
|---|---|
| `evidence/call_chain/summary.md` | 本轮选择范围、四维计数、样例和边界 |
| `evidence/call_chain/alerts.csv` | 逐 API 结果、依赖、版本、状态和路径 |
| `evidence/call_chain/by_api/*.json` | 单 API 的结构化路径和证据 |

深度排查或程序使用的文件：

| 文件 | 用途 |
|---|---|
| `evidence/call_chain/summary.json` | Step5 结构化摘要 |
| `.runtime/indexes/s5_query_index.json` | 方法、坐标、artifactId 和包前缀查询索引 |
| `.runtime/observability/step5_timing.csv` | Step5 发布性能拆解 |

`alerts.csv` 每行保留 API 所属依赖、base/current 版本、四维状态、路径完整性和结构化路径字段。路径或候选数因预算截断时必须进入 coverage/`not_analyzed` 或相应限制字段，不能写成静态未命中。

## Step6：最终报告

| 文件 | 用途 |
|---|---|
| `deliverables/report.md` | 依赖层、API/调用关系层和文件说明 |
| `deliverables/all-affected-dependencies.md/.csv` | 本轮全部纳入依赖的同源明细 |
| `deliverables/all-impact-details.md/.csv` | 本轮全部变化 API、四维结果和路径的同源明细 |
| `deliverables/analysis-scope.md` | 选择前总数、纳入/未纳入对象和原因 |
| `deliverables/analysis-diagnostics.md` | 条件生成；输入或结构异常及其影响范围 |

`.runtime/findings/s6_findings.json` 是程序使用的结构化结果，不属于主报告阅读路径。部分范围只统计用户选择的对象；未选择对象记录在 `analysis-scope.md`，不能归入“本次未完成分析”，也不能据部分范围给出全局结论。

主报告先展示可能影响和仍不确定的结果，再展示静态未命中与未完成统计；完整 Markdown 和 CSV 保留所有对象及同一排序。任何行动建议都必须受证据边界约束，不能把静态分析结果写成已经完成的发布判断、代码修改或业务运行验证。
数据库访问契约章节额外展示涉及表数、唯一表/列变化数、需复核线索数和 Step3 原始证据数；
正文只展示有界的聚合结果，并就近链接 Step3 完整 Markdown/CSV 证据。表格中的“已确认”只表示
base/current 制品中的契约变化有明确证据，不表示数据库 DDL 已经部署。
