# 分析结果与人工复核指南

本页说明 `.upgrade-report/` 中哪些文件给人读、哪些文件用于复核、哪些文件只供程序恢复和深度审计。

所有 CSV 使用 UTF-8 BOM，可直接用 Excel 打开；JSON 使用 UTF-8 无 BOM。

## 三层目录

```text
.upgrade-report/
  README.md
  deliverables/
  evidence/
  .runtime/
```

| 目录 | 定位 | 普通使用方式 |
|---|---|---|
| `deliverables/` | 最终交付 | 先读这里，获得依赖层结论、API/调用关系和范围边界 |
| `evidence/` | 人工复核 | 核对依赖、API、路径和上下文证据 |
| `.runtime/` | 程序状态与权威内部数据 | 普通用户不进入；用于恢复、索引、不可变 generation 和深度审计 |

`.upgrade-report/README.md` 是落地阅读入口，只链接本轮实际生成的文件，并在等待确认时说明当前问题、选择和可直接回复的示例。

## 完成后的阅读顺序

1. `deliverables/report.md`：主报告；
2. `deliverables/all-affected-dependencies.md`：全部依赖包结论；
3. `deliverables/all-impact-details.md`：全部 API 和调用关系；
4. `deliverables/analysis-scope.md`：本轮纳入/未纳入范围；
5. 需要筛选时使用对应 `.csv`；
6. 需要核实原始人工证据时进入 `evidence/`；
7. 只有排查 generation、验证或程序状态时进入 `.runtime/`。

## Binary-first 权威与目录边界

Step4–Step6 只有一个 binary-first 引擎。必须通过 `binary_pipeline_config` 固定 base/current 最终制品、完整目标 JDK、有序运行路径、loader/resource policy 和业务入口。没有 legacy、shadow、灰度或 fallback。

正式内部结果先写入：

```text
.runtime/binary_authority/binary_generations/<result_generation_identity>/
```

通过 support、身份、守恒、sidecar、数据库、performance gate 和独立 Oracle 校验后，才切换：

```text
.runtime/binary_authority/active_binary_generation.json
```

校验或发布失败时不覆盖上一份完整 generation、人工 evidence、deliverables 或查询索引，也不调用旧引擎补算。

人工复核不需要先读 raw JSON。权威内部文件包括：

| 文件 | 深度审计用途 |
|---|---|
| `binary_decisions.json` | authoritative、diagnostic candidate、excluded 互斥裁决及 confirmed-unprojectable 事实 |
| `binary_projections.json` | 正式 API projection、assessment、candidate plan 和 contributing fact |
| `binary_formal_results.json/.csv` | 四维正式 API 结果和 exact/possible 路径 |
| `binary_candidate_results.json` | 候选事实的独立诊断结果，不进入正式 API 总数 |
| `binary_coverage.json` | decision、trace、source-overlay 覆盖和图统计 |
| `binary_summary.json` | fact、projection、API 和四态守恒汇总 |
| `binary_pairings.json` / `binary_build_identities.json` | 制品 pairing、逻辑 lineage 和物理身份 |
| `binary_phase_manifest.json` | 同一 generation 的单向 phase 身份 |
| `validation/*.json` | 与生产 identity 独立的 Oracle 对账结果 |

这些文件是深度排查或程序使用的文件，不属于主报告阅读路径。

## 分析对象与依赖范围

目录：`evidence/dependencies/`

人工优先看的文件：

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `dep_summary.txt` | Step1 摘要 | 目标模块、两侧最终制品和依赖变化规模 |
| `dep_changes.csv` | base/current 依赖差异 | 完整坐标、版本、scope 和变化类型 |
| `dep_alerts.csv` | 需要优先复核的依赖事实 | 删除、降级、坐标或制品异常 |
| `build_provenance.json` | 两侧构建/直接产物来源与 SHA-256 | 是否绑定正确 commit 和最终制品 |

深度排查或程序使用的文件：

| 文件 | 说明 |
|---|---|
| `dependency_jars.json` | Step1 固化的 runtime artifact、coord、container entry、SHA 和 retained path |
| `s1_dependency_jars/` | 从最终制品一次性留存的依赖 JAR |
| `s1_artifacts/` | 留存的 base/current 最终制品 |

Step1 以最终制品为依赖事实源。工程依赖树只在容器内元数据无法确定坐标时补齐实际条目，不能覆盖制品或扩展运行时闭包。后续步骤不读取本地 Maven 仓库中的替代 JAR。

## 升级上下文

目录：`evidence/context/`

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `review.md` | 人工升级范围确认页 | 目标模块、分支/commit、JDK、Spring Boot、源码是用户提交/选择使用还是明确不提供，以及对应覆盖是否正确 |
| `context.json` | 程序使用的完整上下文 | 深入排障时查看 |
| `dep_graph.json` | 依赖关系 | 仅用于上下文传播排查 |

## 兼容性线索

目录：`evidence/static_scan/`

Step3 识别 JDK、Jakarta、Spring、配置和 classfile 等背景风险。这些线索不能直接证明当前业务受影响，也不能追加成 Step4 的正式变化 API。

常见文件：

| 文件 | 说明 |
|---|---|
| `s3_jdk_removed_api.csv` | JDK 移除 API 线索 |
| `s3_jdk_javax_refs.csv` | `javax.*` 引用 |
| `s3_jdk_internal_api.csv` | JDK 内部 API |
| `s3_springboot_config.csv` | Spring Boot 配置线索和扫描完成度 |
| `s3_dependency_compat.csv` | current 最终制品内依赖兼容线索 |
| `s3_dependency_classfile.csv` | 依赖 classfile 版本扫描台账 |

## 依赖 API 变化

目录：`evidence/api_changes/`

### 人工复核顺序

1. `changed_dependencies.md`：先看是哪个依赖包、base/current 什么版本；
2. `s4_per_dependency/<coord>/summary.md`：按依赖查看变化 API；
3. `all_changed_apis.csv`：完整 API 行级筛选；
4. `review.md`：资源、安全、topology 和其他 confirmed-unprojectable 事实；
5. 只有深度审计才打开 `.runtime/binary_authority/.../binary_decisions.json`。

人工优先看的文件：

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `changed_dependencies.md` | 给人看的依赖包维度完整清单 | 完整坐标、base/current 版本、变化 API 数、精确/候选引用和排序理由 |
| `changed_dependencies.csv` | 同一依赖集合的结构化视图 | 批量筛选和范围选择 |
| `s4_per_dependency/<coord>/summary.md` | 单依赖可读摘要 | 该依赖的版本、API、变化类型和证据 |
| `all_changed_apis.csv` | 正式 API projection 的稳定用户视图 | coord、版本、API、Java 参数签名、member kind 和 change type |
| `review.md` | 不可安全投影为 API 的真实变化 | 资源、SPI、安全、topology、候选和证据边界，仍保留依赖坐标 |
| `business_bytecode_changed_api_refs.csv` | 业务最终制品的逐指令引用证据 | caller class/member、descriptor、offset、target API 和 coord |
| `business_bytecode_priority_evidence.json` | 依赖排序证据摘要 | 扫描完整性与精确/候选引用数 |
| `source_overlay.md` | 给人看的源码辅助证据 | 按源码归属依赖包展示二进制制品、方法、源码文件/行号、声明、注解和源码候选关系；同时说明用户选择与二进制权威边界 |
| `source_overlay.csv` | 同一源码映射的结构化视图 | 按依赖包、制品、方法、源码位置、声明和注解筛选；用户不提供源码时保留表头且不制造映射行 |
| `source_candidate_relationships.csv` | 源码调用候选视图 | 展示带依赖归属、调用方位置和置信度的候选关系；明确不作为可执行调用边或正式触达结论 |
| `summary.md` | Step4 人工摘要 | generation、依赖/API 规模、覆盖和后续阅读路径 |

`all_changed_apis.csv` 不是旧格式兼容投影，而是从 validated generation 确定生成的正式人工/API 视图。无法投影为 API 的真实资源或 topology 变化进入 `review.md` 和权威 decision；系统不会制造虚构 API 行。

### 依赖包维度选择入口

当至少有两个含正式 API projection 的依赖时，系统让用户选择全量或部分分析。0 或 1 个候选不存在实质范围取舍，会自动继续。

- 范围卡展示依赖数、API 数和按业务最终制品精确直接引用排序的 Top 10；
- 完整选择清单是 `changed_dependencies.md`；
- 用户回复依赖名称或完整坐标即可，不需要逐行选择 API；
- 部分范围只适用于所选依赖，未选对象进入 `analysis-scope.md`，不计入“未完成分析”；
- 删除、签名变化等类型不人为加权；源码覆盖是否存在只作为解释条件。

## 系统触达证据

目录：`evidence/call_chain/`

人工优先看的文件：

| 文件 | 定位 | 用途 |
|---|---|---|
| `summary.md` | 人工摘要 | 四态计数、选择范围、关键依赖和阅读边界 |
| `alerts.csv` | 人工优先入口 | 每个 API 的依赖坐标、版本、四维结果、主路径和路径 certainty |
| `by_api/*.json` | 逐 API 深入复核 | 结构化 paths、contributing facts 和完整 identity |

深度排查或程序使用的文件：

| 文件 | 定位 | 用途 |
|---|---|---|
| `summary.json` | 程序使用 | Step5 范围、四态、四维和 generation identity |
| `.runtime/indexes/s5_query_index.json` | 程序使用 | 按方法、坐标、artifactId 或包前缀即时查询调用链 |

查询结果必须返回依赖坐标、base/current 版本、可读 Java 参数签名和调用路径。查询索引未命中不表示没有影响。

## 系统触达证据结论

### 四态

| `reachability_status` | 含义 | 用户行动边界 |
|---|---|---|
| `reachable` | 当前声明入口存在到变化 API 的 exact 静态路径 | 作为可能影响优先执行针对性运行测试；不冒充运行确认 |
| `uncertain` | 存在 possible path、候选证据或已知语义边界 | 按依赖和路径优先级人工复核/运行验证 |
| `not_found_in_static_analysis` | 已声明静态范围完成但没有发现路径 | 不表示安全；结合动态机制和运行测试判断 |
| `not_analyzed` | 相关输入、解析或图范围未完成 | 只能说明本次未完成分析，不能给负面结论 |

### 四维

| 维度 | 值 |
|---|---|
| `reachability_status` | `reachable` / `uncertain` / `not_found_in_static_analysis` / `not_analyzed` |
| `static_linkage_status` | `compatible_or_not_applicable` / `incompatible_if_executed` / `undetermined` |
| `impact_conclusion` | `probable_impact` / `inconclusive` |
| `runtime_verification_status` | `required_not_executed` / `undetermined` |

静态分析不输出“确认有影响”“确认不受影响”或“运行验证已完成”。`not_found_in_static_analysis` 和 `not_analyzed` 都不能解释为安全。

## 最终报告

目录：`deliverables/`

| 文件 | 说明 |
|---|---|
| `report.md` | 主报告，先依赖后 API/调用关系，包含关键路径和结论限制 |
| `all-affected-dependencies.md` | 本轮范围内全部依赖级结果 |
| `all-affected-dependencies.csv` | 与依赖 Markdown 同源的结构化结果 |
| `all-impact-details.md` | 本轮范围内全部 API、版本和调用路径 |
| `all-impact-details.csv` | 与 API Markdown 同源的结构化结果 |
| `analysis-scope.md` | 全量/部分范围、纳入和未纳入依赖/API 数 |

`.runtime/findings/s6_findings.json` 是程序使用的结构化结果，不属于主报告阅读路径。

主报告的内容顺序：

1. **依赖层面结论**：依赖坐标、base/current 版本、变化/已完成/未完成数量和可能影响数量；
2. **API 及调用关系**：API、Java 参数签名、变化类型、四维结果、当前系统路径和结论说明；
3. **用户可见文件说明**：主报告未展开的依赖/API、CSV、范围文件和人工 evidence 在哪里。

“已完成分析”只表示该 API 获得正式四维静态结果；“未完成分析”表示 `not_analyzed`。可能影响是静态证据支持的优先级，不是已经完成运行验证。

每个用户可见文件必须保留依赖坐标和版本变化。Markdown 与 CSV 从同一排序后的数据生成，范围、依赖归属和 API 数量必须可以对账。

## 运行监控

运行监控不是结论证据，统一放在 `.runtime/observability/`：

| 文件 | 用途 |
|---|---|
| `.runtime/observability/progress.jsonl` | 全流程进度、阶段、已用时间和可用时的预计剩余时间 |
| `.runtime/observability/step1_progress.jsonl` | Step1 构建、ref 和制品固化进度 |
| `.runtime/observability/step4_timing.csv` | binary generation 各 phase 耗时、规模和发布状态 |
| `.runtime/observability/step5_timing.csv` | Step5 选择范围发布、索引和报告耗时 |

这些文件只用于确认进程是否仍在运行、定位性能瓶颈和排查失败，不证明某个依赖或 API 的结论。

## 完成状态

- `completed`：流程完成，范围和覆盖没有记录限制；
- `completed_with_limits`：交付物已生成，但存在部分范围、覆盖缺口、可能影响、uncertain、not_analyzed 或诊断候选。

两种状态都必须告诉用户报告路径。`completed_with_limits` 还必须列出限制和适用范围，不能包装成无限制结论。
