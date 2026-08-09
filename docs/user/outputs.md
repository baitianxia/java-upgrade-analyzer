# 输出文件与人工复核指南

本文面向使用者和人工复核人，说明 `.upgrade-report/` 中哪些文件应该优先阅读，以及每类结果代表什么。

所有 CSV 文件统一采用 UTF-8 BOM，可直接用 Excel 打开；程序仍可读取历史无 BOM 的 UTF-8 CSV。

使用统一入口的 `--step auto` 时，流程会自动运行到下一个必要确认点。分析对象与实际依赖范围需要确认；升级上下文仅在 JDK、业务源码范围等关键事实无法可靠确定，或用户提供的源码线索产生待采用映射建议时暂停；明确拒绝建议后不会重复询问。依赖 API 变化识别出至少两个候选依赖时保留全量/部分范围选择；0 个或 1 个候选不存在实际范围取舍，系统直接继续。确认范围后，系统触达分析和最终报告连续完成。

步骤内部的网络、fetch、依赖源码缺失、工具超时等故障不会制造额外确认点；系统会重试、使用最终制品证据或记录覆盖缺口。只有必须由用户提供的事实或会改变结论范围的选择才暂停。

## 阅读原则

这些文件的目标是帮助你快速判断，而不是展示内部实现细节。

阅读时请始终把所有输出当成一条连续链路，而不是一堆孤立文件：

```text
依赖发生了什么变化
  → 哪些 API 发生了变化
  → 哪些调用链触达业务或依赖入口
  → 最终结论是什么、为什么
```

`.upgrade-report/` 按阅读对象分成三层：

| 目录 | 谁主要阅读 | 用途 |
|---|---|---|
| `deliverables/` | 普通使用者、评审人 | 交付报告和分类清单 |
| `evidence/` | 需要深入复核的人 | 依赖、上下文、API 变化和系统触达证据 |
| `.runtime/` | 程序和 Agent | 状态、索引、恢复信息、运行进度和耗时诊断；普通阅读不需要进入 |

binary-first 引擎的 generation、事实库、独立验证和内部四维结果统一位于 `.runtime/binary_authority/`。它们是内部权威事实，不替代 `deliverables/` 和 `evidence/` 的既有人工阅读契约。

主报告的内容顺序：

1. 依赖层面结论：变化依赖总数、已完成分析、未完成分析、确认有影响、确认不受影响、尚未确认影响，以及每个依赖的结论依据。
2. API 及调用关系：变化 API 总数、已完成分析、未完成分析、确认有影响、确认不受影响、尚未确认影响，以及 API 对应的当前系统调用关系。
3. 用户可见文件说明：每个主阅读文件包含什么、覆盖全量还是节选、对应主报告哪一部分。

表中的“变化总数”以本轮分析范围为边界。全量分析时等于选择前识别出的全部变化对象；部分分析时只等于用户选中的依赖及其变化 API。未选择对象属于范围外对象，不计入“未完成分析”。已完成分析与未完成分析之和等于本轮范围内的变化总数。API 层的“确认有影响”“确认不受影响”“尚未确认影响”是已完成分析结果的三种分类。依赖层只要已有 API 确认有影响，就计入“确认有影响”；如果同一依赖仍有其他 API 未完成分析，该依赖也同时计入“未完成分析”，并在明细中直接写明原因。已执行分析但未发现当前系统调用关系的 API 仍属于已完成分析。只有本轮范围内因为输入缺失、文件无法读取或分析结果没有产生而无法完成的项，才进入“未完成分析”。

每个用户可见文件都应直接记录：

- 这个文件回答什么问题；
- 当前结论是什么；
- 结论来自哪个依赖版本变化、哪个业务模块或入口、哪个变更 API 和哪条关键链路；
- 哪些事实仍未确认，以及这些事实如何限制结论；
- 与当前结论直接关联的证据文件。

如果某个文件只有大量数字、内部字段或文件名，而不能直接说明问题和结果，应视为输出可读性缺陷。

## 复核入口

一次完整分析通常按以下顺序阅读：

| 顺序 | 文件 | 作用 |
|---:|---|---|
| 1 | `deliverables/report.md` | 先读依赖结论，再读 API 和调用关系 |
| 2 | `deliverables/all-affected-dependencies.md` | 本轮分析范围内全部变化依赖的分析状态、结论依据和对应 API 链接 |
| 3 | `deliverables/all-affected-dependencies.csv` | 与完整依赖 Markdown 相同的数据和排序，便于表格筛选 |
| 4 | `deliverables/all-impact-details.md` | 本轮分析范围内全部变化 API、分析状态和完整调用关系 |
| 5 | `deliverables/all-impact-details.csv` | 与完整 API Markdown 相同的数据和排序，包含完整调用关系 |
| 6 | `evidence/call_chain/alerts.csv` | 一行一条的原始分析记录，用于核对调用关系和证据文件 |

如果结果存在疑问，再回到对应步骤的原始证据文件继续追溯。

这些入口之间的关系是：

- `changed_dependencies.md` 回答“哪些依赖包发生 API 变化”；
- `all_changed_apis.csv` 回答“完整 API 变化事实是什么”；
- `deliverables/report.md` 回答“依赖层面和 API 层面的结论是什么”；
- `all-affected-dependencies.md` 回答“主报告未展开的依赖结果在哪里”；
- `all-affected-dependencies.csv` 是相同依赖结果的表格版本；
- `all-impact-details.md` 回答“主报告未展开的 API 和完整调用关系在哪里”；
- `all-impact-details.csv` 是相同 API 及调用关系的表格版本；
- `alerts.csv` 保留形成上述调用关系的原始分析记录。

## 分析对象与依赖范围

Step1 的职责是确定本次分析实际采用的 base/current 构建产物和依赖变化范围。

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `evidence/dependencies/dep_changes.csv` | base/current 依赖差异明细 | 依赖坐标、版本、scope、变化类型是否符合预期 |
| `evidence/dependencies/dep_summary.txt` | Step1 摘要 | 目标模块、构建产物、依赖变化规模 |
| `evidence/dependencies/dep_alerts.csv` | 需要优先复核的依赖变化 | 降级、删除、无法解析或高风险依赖 |
| `evidence/dependencies/build_provenance.json` | base/current 构建产物来源和摘要 | 后续字节码分析是否基于正确制品 |
| `evidence/dependencies/s1_artifacts/` | 留存的 base/current 产物 | Step5 业务字节码和运行时依赖 JAR 的来源 |
| `evidence/dependencies/dependency_jars.json` | Step1 固化的变化依赖 JAR 清单与 SHA-256 | Step4 是否直接消费正确的 base/current JAR |
| `evidence/dependencies/s1_dependency_jars/` | 从最终制品一次性提取的变化依赖 JAR | Step4 的唯一依赖 JAR 输入 |

注意：Step1 当前以真实构建结果或用户提供的构建产物为准，不把手工 dependency tree 当作正式事实源。
base/current 即使使用同一个源码目录，也会按各自确认后的 commit 分别建立临时 worktree；源码目录本身不代表制品版本。
`dep_changes.csv` 仍只在完整比较成功后写入；过程日志和耗时文件仅用于监控与诊断，不是未完成分析的部分结果。

从 Step1 开始，最终制品是依赖事实的唯一来源。Step1 先从 fat JAR 读取条目和坐标；内嵌 Maven 元数据无法确定坐标时，工程依赖树只补齐该条目，不替换制品事实。变化依赖 JAR 会在 Step1 固化，正式 Step4 直接读取，不会重新展开 fat JAR。源码只用于解释 Step1 已有 GAV 的源码变化，不会再次发现依赖或制造同 GAV 重复。所有步骤都不使用本地 Maven 仓库中的同坐标文件，也不下载其他版本代替。JApiCmp 自身是分析工具，首次缺失时可以自动安装；这不等于允许下载被分析依赖。最终制品内缺少目标 JAR 时，Step1 门控会明确报错，不会把异常拖到 Step4。

## 运行监控与性能诊断

运行过程和耗时不是分析结论证据，统一放在 `.runtime/observability/`：

| 文件 | 用途 |
|---|---|
| `.runtime/observability/progress.jsonl` | 全流程统一进度事件；保留任务、阶段、当前/总量、已用时间、粗略预计剩余时间和当前对象，长任务还会记录定期心跳，供中断排障与运行审计使用 |
| `.runtime/observability/step1_progress.jsonl` | Agent 在 Step1 运行中查看当前侧、当前阶段、命令和状态；`ref_resolution.details` 可核对实际采用的 ref 与 commit |
| `.runtime/observability/step1_timing.csv` | Step1 当前执行阶段及耗时；阶段开始即出现 `status=running`，可看到当前侧、模块/文件、命令和任务说明，完成后同一行更新为最终状态 |
| `.runtime/observability/step4_timing.csv` | Step4 当前执行阶段及耗时；按依赖并行记录源码 diff、JApiCmp、数据契约、行为字节码兜底和结果写入等 start/end 事件。以相同 `phase + coord + old_version + new_version` 的最后一条状态判断任务是否仍在运行 |
| `.runtime/observability/step5_timing.csv` | Step5 当前执行阶段及耗时；`activity` 段实时显示输入解析、建图、字节码扫描、框架适配、间接引用、证据合并、调用链追踪和报告写入，最终追加性能指标；`memory` 段同时记录主进程与完整子进程树的当前/峰值内存、CPU、外部命令次数/并发/墙钟时间、临时文件高水位及图规模 |
| `.runtime/observability/step5_diagnostics.jsonl` | Step5 实时诊断台账；制品、字节码、框架和逐 API 追踪一旦发现失败就追加原因码、阻断属性、作用域、计数与样例，不必等待最终 `summary.json` |
| `.runtime/observability/step5_progress.json` | Step5 当前追踪进度快照；`completed/total` 只在单个 API 完成后推进，供心跳显示可靠完成比例。该文件是运行观测状态，不是分析结论证据 |

Step5 的 stderr 会由正式调度器实时转发，因此诊断事件也会立即出现在终端。核心制品身份、安全性或全局业务字节码证据失效时，Step5 会写入 `artifact_preflight_failure.json` 并立即停止；路径级歧义只限制相关路径，其他 API 继续分析。

终端中的进度使用“任务名称 + 当前阶段 + 当前/总量 + 已用时间 + 可用时的预计剩余时间”的用户语言，不要求使用者理解 `step4` 等内部编号；完整内部标识仍保存在 `progress.jsonl`。这些文件用于运行监控和性能排查，不用于证明依赖、API 或调用链结论。

## 升级上下文

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `evidence/context/review.md` | 给人看的升级范围和版本确认页 | 目标模块、比较版本、JDK、Spring Boot 和依赖源码覆盖是否正确 |
| `evidence/context/context.json` | 程序使用的完整升级上下文 | 只有深入排查时查看 |
| `evidence/context/dep_graph.json` | 程序使用的依赖关系 | 只有深入排查依赖传播时查看 |

## 兼容性线索

Step3 用于识别 JDK、Jakarta、Spring 等框架升级带来的背景风险。

这些结果不能直接证明业务受影响；是否影响当前系统，需要结合 Step5。

如果 Step6 的 `findings` 中存在 `diagnostics`，说明某个前序 JSON 或 CSV 无法读取或格式损坏。该文件对应的数据不会被当作“没有风险”；诊断记录包含 `artifact`、`path` 和 `error_type`，相关结论的适用范围受到限制。

常见文件：

| 文件 | 说明 |
|---|---|
| `evidence/static_scan/s3_jdk_removed_api.csv` | JDK 移除 API 命中 |
| `evidence/static_scan/s3_jdk_javax_refs.csv` | `javax.*` 引用 |
| `evidence/static_scan/s3_jdk_internal_api.csv` | JDK 内部 API 引用 |
| `evidence/static_scan/s3_springboot_config.csv` | Spring Boot 配置相关线索；优先查看 `配置键`。若 `扫描状态` 为“未完成”，说明配置使用了当前行级扫描无法可靠展开的 YAML 形态，不能将未命中视为无风险。|
| `evidence/static_scan/s3_springboot_autoconfig.txt` | 自动装配相关线索 |
| `evidence/static_scan/s3_dependency_compat.csv` | current 最终制品内依赖 JAR 的兼容性规则命中；每条记录都通过“最终制品内路径”定位到实际打包条目，不读取本地 Maven 仓库 |
| `evidence/static_scan/s3_dependency_classfile.csv` | current 最终制品内全部依赖 JAR 的字节码版本扫描台账；每个实际打包条目一行，“扫描结论”明确区分完成、风险和未完成 |

## 依赖 API 变化事实

Step4 的核心输出目录：

```text
evidence/api_changes/
```

本分支改用 binary-first 引擎生成变化事实，但继续发布原有的人读字段、依赖维度和复核入口。报告是 validated generation 的单向投影，不会反向参与二进制裁决。

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `changed_dependencies.md` | 给人看的依赖包维度清单 | Step4 完成后选择全量或部分依赖范围 |
| `changed_dependencies.csv` | 结构化依赖包清单 | 影响排序、精确/候选字节码引用数、引用指令数、变化 API 数、源码分析条件 |
| `business_bytecode_changed_api_refs.csv` | 业务最终制品对变更 API 的逐指令引用证据 | 调用方类/方法/签名/字节码偏移到被调用 owner/member 的映射 |
| `business_bytecode_priority_evidence.json` | Step4 影响排序所用字节码扫描摘要 | 扫描状态、业务制品、精确引用与候选引用覆盖情况 |
| `all_changed_apis.csv` | 完整 API 变化事实集合，每行一个变更 API 或候选目标 | 变化 API 是否真实、符号类型是否正确 |
| `all_changed_apis_alerts.csv` | 高风险 API 变化子集 | P0/P1、删除、行为变化等 |
| `summary.txt` | Step4 覆盖率和执行摘要 | jar 是否缺失、JApiCmp 是否失败、git diff 是否跳过 |
| `*_binary.txt` / `*_binary.xml` | JApiCmp 原始证据 | 二进制兼容性变化来源 |
| `*_gitdiff_api_changes.txt` | 依赖源码 git diff 证据 | 行为变化、源码级 API 变化 |
| `*_removed_symbols.txt` | removed jar 的旧版 public/protected 符号导出 | 删除依赖场景目标池是否完整 |

Step4 还会从 old/current 最终 JAR 识别 DTO/数据对象的实例字段新增、删除和类型变化。`all_changed_apis.csv` 中对应的 `change_type` 为 `DATA_FIELD_ADDED`、`DATA_FIELD_REMOVED` 或 `DATA_FIELD_TYPE_CHANGED`，`old_value` / `new_value` 展示字段类型变化，`data_contract_evidence` 展示为何把该类识别为数据对象。该事实不代表数据库字段已经同步或不匹配。

### 依赖包维度选择入口

依赖 API 变化分析完成且存在至少两个候选依赖时，需要选择系统触达分析的全量或部分范围；0 个或 1 个候选没有不同范围可选，系统直接继续。优先看：

| 文件 | 用途 |
|---|---|
| `evidence/api_changes/changed_dependencies.md` | 给人看的依赖包维度清单 |
| `evidence/api_changes/changed_dependencies.csv` | 结构化依赖包清单 |
| `evidence/api_changes/all_changed_apis.csv` | 完整 API 变化事实集合 |

范围选择分为三层：

1. **全量分析**：覆盖全部候选依赖包。
2. **部分分析（仅在明确控制耗时时）**：先复核 Top 10 依赖。排序依次比较业务最终制品精确直接引用的变更 API 数、签名不完整候选引用数、引用指令数和变更 API 总数，最后按完整依赖坐标稳定排序。删除、签名变化等变更类型不额外加权，源码是否可用只作为分析条件展示。
3. **从全部候选中选择部分范围**：打开 `changed_dependencies.md`，从完整清单复制“依赖包”列中的坐标，可同时复制多个，例如：`只分析 com.foo:bar、com.foo:baz`。

`all_changed_apis.csv` 用于核对 API 级明细，不作为依赖包选择入口。Top 10 只用于用户已经决定缩小范围后的排序，不表示系统建议缩小范围，也不表示已经确认对当前系统有影响；未观察到业务字节码直接引用同样不表示安全，跨依赖、框架和运行时路径仍由 Step5 分析。

确认结果会写入 `.runtime/cache/step5_selection.json`。最终报告会据此标明全量或部分范围；如果是部分分析，主报告与依赖/API 两类完整分析明细（Markdown 和 CSV）只统计选中的依赖及其变化 API，未选择对象不会被归类为“未完成分析”。未选择依赖及原因记录在 `deliverables/analysis-scope.md`，选择前的依赖/API 全集仍保留在原始变化清单中。部分范围不能支持全局无影响结论。

最终会同时生成 `deliverables/analysis-scope.md`，把运行时范围快照转换为可直接核对的纳入/排除依赖清单和 API 数量。根目录 `README.md` 只展示本轮实际存在的文件，并使用可点击的相对链接；若流程正在等待确认，确认问题、选项和回复示例也会保留在该入口中。

完成状态分为“分析已完成”和“分析已完成，但存在结论限制”。部分范围、关键证据覆盖不完整、可能影响、结论未确定、本次未完成或证据读取异常均属于后者。结论未确定会进一步区分“存在候选证据”和“静态分析能力边界”，后者表示当前没有候选调用证据，不能误读为已经找到调用线索。

### per-dependency 视图

目录：

```text
evidence/api_changes/s4_per_dependency/<coord>/
```

常见文件：

| 文件 | 说明 |
|---|---|
| `removed_jar_symbols.csv` | 删除依赖旧版符号明细 |
| `resolved_targets.csv` | 单依赖最终进入 Step5 的目标 |
| `summary.json` | 单依赖 Step4/Step5 摘要 |

### 源码辅助证据

源码辅助文件单独位于 `evidence/source_analysis/`，不混入 `api_changes/`，避免把源码解释误读为二进制变化事实。

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `review.md` | 给人看的源码辅助证据 | 用户选择、源码归属依赖、实际二进制制品、方法、文件/行号、声明、注解和权威边界 |
| `method_mappings.csv` | 源码方法映射表 | 按依赖包、制品、方法和源码位置筛选；未提供源码时保留表头但不制造映射行 |
| `candidate_relationships.csv` | 源码候选关系 | 带依赖归属、调用方位置和置信度；不能当作可执行调用边或正式触达结论 |

用户已提交源码时系统直接使用；未提交时先说明源码用于补充位置、声明、注解、可读上下文及受支持的常量内联证明，再由用户选择补充或明确不提供。无论是否提供，最终依赖身份、变化事实和可执行边仍以最终二进制制品为准。

## 系统触达证据

Step5 的核心输出目录：

```text
evidence/call_chain/
```

### 人工优先看的文件

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `alerts.csv` | 人工优先入口，完整链路台账 | 每个 API、每条终止链路、状态和原因 |
| `alerts_<status>.csv` | 按结论状态拆分的链路台账 | 分别记录已确认影响、结论未确定、未发现路径和未完成分析；`uncertain` 行通过 `uncertainty_kind` 区分候选证据与分析能力边界 |
| `alerts_<status>_NNN.csv` | 大文件分片 | 单个状态文件太大时分段打开 |
| `by_api/*.json` | 单 API 详细证据 | 已经锁定某个 API，需要看逐跳链路、证据路径、终止原因 |

### 深度排查或程序使用的文件

这些文件不作为普通阅读入口。只有当主报告、`alerts.csv` 或 Agent 明确指向它们时再打开。

| 文件 | 类型 | 说明 |
|---|---|---|
| `summary.json` | 程序使用 | Step6 读取的结构化汇总，包含 `analysis_status`、`reason_code` 和能力覆盖 |
| `analyzer_edges.csv` | 程序和深度复核使用 | 分析器从当前最终制品中确认的可执行边台账，用于和独立边真值核对 |
| `.runtime/observability/step5_timing.csv` | 深度排查 | Step5 耗时拆解，用于性能问题定位 |
| `dependency_source_alignment.json` | 依赖源码版本对齐证据 | 使用了哪个 current ref/commit、用户工作区是否保持不变、多少源码类被 current JAR 保留或排除 |
| `.runtime/indexes/s5_query_index.json` | 程序使用 | Agent 按方法即时查询调用链；不作为人工阅读文件 |
| `by_module/*_impacts.json` | 按模块聚合视图 | 核对各模块的影响范围 |

`dependency_source_alignment.json` 是结果与预期不一致时才需要查看的辅助证据。依赖源码未能与 Step4 确认的当前版本或 current JAR 对齐时，Step5 会拒绝这份源码并继续使用 JAR 字节码分析，不会静默使用本地仓库当前分支。

### analyzer_edges.csv 的语义

`analyzer_edges.csv` 每行是一条在 SHA-256 已验证的 current 最终制品中发现的可执行字节码指令边。台账在字节码匹配形成边时直接记录，不会从 `alerts.csv` 的展示字符串或人工调用链文本反向重建。

固定表头如下：

```text
artifact_sha256,artifact_entry,caller_owner,caller_member,caller_descriptor,callee_owner,callee_member,callee_descriptor,opcode_family,instruction_offset,api_identity,edge_role,evidence_path,authority,authority_version,procedure,procedure_version
```

字段含义：

| 字段 | 含义 |
|---|---|
| `artifact_sha256`、`artifact_entry` | 已验证 current 最终制品的 SHA-256，以及外层 class 或嵌套运行时 JAR 内 class 的精确 entry |
| `caller_owner`、`caller_member`、`caller_descriptor` | 调用方类、成员名和原始 JVM descriptor；嵌套类保留 JVM binary name 中的 `$` |
| `callee_owner`、`callee_member`、`callee_descriptor` | 被调用方类、成员名和原始 JVM descriptor；嵌套类保留 `$`，构造器保留 `<init>` |
| `opcode_family`、`instruction_offset` | 产生边的 JVM opcode 和方法内指令偏移；偏移是必填的非负整数，真实偏移 `0` 会保留，缺失或非法值会拒绝该行 |
| `api_identity` | 该边匹配的 Step4 API 身份键 |
| `edge_role` | `internal_bridge` 或 `external_consumer` 等边角色 |
| `evidence_path` | 分析器读取的 JAR/class 证据路径 |
| `authority`、`authority_version` | 产生该行的分析器及其版本 |
| `procedure`、`procedure_version` | 可复现的边提取过程及过程版本 |

Step5 结构化统计同时给出 `analyzer_edge_count`、`duplicate_edge_count`、`edge_ledger_failure_count` 和 `edge_ledger_complete`。同一 canonical identity 在不同 class entry 或不同 `instruction_offset` 出现时保留为多条物理指令；只有对同一制品 entry、调用方和指令偏移的重复发现才折叠并计入 `duplicate_edge_count`。业务 class 使用 `BOOT-INF/classes`、`WEB-INF/classes` 或根 class entry，嵌套依赖使用扫描命中时携带的精确容器 entry，不按依赖坐标反查。

每条记录还会做字节 SHA-256 绑定：嵌套依赖要求扫描 JAR 与最终制品中的精确容器 entry 字节一致，并要求扫描 class 与该容器内的精确 class entry 一致；业务 class 的外层最终制品 SHA 和提取出的 `business-classes.jar` SHA 是两个独立身份，前者按 provenance 验证，后者按 catalog 和业务图边验证，再将扫描 class 字节与 `BOOT-INF/classes`、`WEB-INF/classes` 或根 class entry 的精确字节核对，不会把提取 JAR 的 SHA 当作外层制品 SHA。缺失、陈旧、被篡改或无关的扫描路径不能写入台账。

最终制品缺失、SHA-256 不匹配、entry 无法验证、任一身份字段缺失，或相关 catalog、JAR、class 解析、`javap` 扫描失败时，`edge_ledger_failure_count` 大于 `0` 且 `edge_ledger_complete` 为 `false`。所有 `unavailable` 状态同样失败关闭，包括运行时 catalog 缺失和 `MULTI_RELEASE_TARGET_JDK_UNKNOWN`。

### alerts.csv 的语义

`alerts.csv` 是完整主文件，不是样例文件。

报告中的“系统运行路径”包含普通业务代码，也包含有明确激活证据的定时任务、消息/事件监听、生命周期入口、Runner/Lifecycle、SPI 和框架回调。对于 DTO 字段变化，`reachable` 表示该 DTO/数据对象已经进入上述运行路径；它不表示工具检查过数据库表结构。只有条件声明但缺少当前制品激活证据的入口，不会被写成已确认影响。

它的设计目标是方便人工复核完整分析过程：

- 每个进入 Step5 的 API 至少一行；
- 每条终止链路独立一行；
- 不同业务入口、不同消费依赖、不同完整链路不会被合并；
- 如果一条长链路已经包含短后缀链路，可抑制同一命中的纯后缀重复行；
- 同一消费方法内的重复命中会合并，并通过 `path_occurrence_count` 标记次数。

当 `stop_reason=DEPTH_LIMIT_REACHED` 时，`coverage_details` 会明确列出本次实际使用的
预算、被截断的目标 key 和深度截断候选总数。该行属于覆盖未完成信号，不能解读为
“静态分析未发现使用”或“确认不受影响”。完整结构化值同时保留在 `summary.json` 和
`by_api` JSON 的 `path_details` 中。

### alerts 拆分文件

当 `alerts.csv` 太大时，Step5 会生成按状态拆分的阅读文件：

```text
alerts_reachable.csv
alerts_uncertain.csv
alerts_not_found_in_static_analysis.csv
alerts_not_analyzed.csv
```

如果单个分类仍然过大，会继续分片：

```text
alerts_reachable_001.csv
alerts_reachable_002.csv
```

拆分文件只是人工阅读视图，不是索引、抽样或替代结论。

## 系统触达证据结论

| 人工结论 | 含义 | 程序状态（排查时使用） |
|---|---|---|
| 已确认影响 | 已找到业务代码或当前制品中已激活入口到变更 API 的完整路径 | `reachable` |
| 已确认不受影响 | 当前制品中的其他依赖以完全相同的类字节码保留该 API；不覆盖资源、SPI 等非 API 内容 | `not_impacted` |
| 存在候选证据但结论未确定 | 已有调用或引用候选证据，但尚不能形成确定链路 | `uncertain` + `candidate_evidence` |
| 静态分析能力边界，结论未确定 | 没有候选调用证据，但当前场景无法通过静态未命中证明未使用 | `uncertain` + `analysis_limitation` |
| 静态分析未找到路径 | 已完成静态分析，但没有找到路径；不能解释为确定不影响 | `not_found_in_static_analysis` |
| 本次未完成分析 | 输入或工具能力不足，无法完成本项分析 | `not_analyzed` |

## 最终报告

### 文件分层

面向使用者的交付文件：

| 文件 | 说明 |
|---|---|
| `deliverables/report.md` | 主报告；依次展示依赖结论、API 及调用关系、用户可见文件说明 |
| `deliverables/all-affected-dependencies.md` | 本轮分析范围内全部变化依赖的已完成/未完成状态、分析结论、结论依据和对应 API 链接 |
| `deliverables/all-affected-dependencies.csv` | 与完整依赖 Markdown 相同的数据和排序 |
| `deliverables/all-impact-details.md` | 本轮分析范围内全部变化 API 的分析结果；确认有影响项包含完整调用关系，未完成项包含具体原因 |
| `deliverables/all-impact-details.csv` | 与完整 API Markdown 相同的数据和排序，包含完整调用关系 |
| `deliverables/analysis-scope.md` | 选择前总数、本轮纳入数量、未纳入数量、未纳入依赖及具体原因 |
| `deliverables/analysis-diagnostics.md` | 仅在存在输入读取或结构异常时生成，记录异常及其影响范围 |

`.runtime/findings/s6_findings.json` 是程序使用的结构化结果，不属于主报告阅读路径。内部原因码、步骤编号、状态枚举、查询索引和 `.runtime/` 文件目录保留在机器证据或深度排障材料中，不应出现在主报告正文或主报告的文件索引中。

Step6 在主报告中按依赖坐标分组，逐项展示本轮范围内全部“已确认影响”和“结论未确定”API；依赖之间按整体影响程度排序，同一依赖内再按结论状态、优先级分数和调用证据排序。“已确认不受影响”和“静态分析未找到路径”只在主报告给出统计数量，不能据此推断安全；所有状态的逐项记录仍进入完整 Markdown 和同数据、同排序的 CSV。只有本次未完成分析的 API 可以限量展示，此时必须标明展示数、总数和未展示数。部分分析时，选择前全集只保留在原始变化清单和范围记录中。

### 主报告固定内容顺序

`deliverables/report.md` 必须按以下顺序组织，不能先用目录、免责声明、运行统计或产物清单占据第一屏：

1. **依赖层面结论**：展示变化依赖总数、已完成分析、未完成分析、确认有影响、确认不受影响、尚未确认影响。已完成依赖合并在一张表中；未完成依赖单独列出具体原因。
2. **API 及调用关系**：使用与依赖层相同的六列统计口径。已完成 API 合并在一张表中，调用起点直接作为完整调用关系的第一个节点；未完成 API 单独列出具体原因。
3. **用户可见文件说明**：区分主报告、完整依赖明细、完整 API 与调用关系明细、原始分析记录及范围/异常记录，逐项说明内容和数据范围。

主报告先回答“发生了什么、证据证明到哪里、哪些事实仍未确认”，并提供五态语义对照和每种状态对应的用户行动。行动说明必须受当前证据边界约束，不得把静态未命中表述为安全，也不得生成发布判断、修改判断、具体实现方案或验证完成结论。

依赖明细按“确认有影响 → 未确认影响 → 确认不受影响”排列，同类结果按调用链数量从多到少排列。主报告中的 API 先按完整依赖坐标分组：依赖之间按确认有影响、结论未确定的整体影响程度排序；同一依赖内按结论状态、优先级分数和调用证据排序。完整 Markdown 和对应 CSV 保留全部状态并使用一致的分组与排序口径；未完成分析仍在独立列表中展示。

依赖结果表至少包含：

```text
依赖 | 版本变化 | API 分析（已完成/总数） | 当前系统调用关系 | 分析结果 | 结果说明
```

API 结果表至少包含：

```text
依赖 | API | 新版本中的变化 | 当前系统调用关系 | 分析结果 | 结果说明
```

已完成分析和未完成分析使用相同表头及列顺序。未完成项在“当前系统调用关系”中显示“调用关系分析未完成”，具体原因写入“结果说明”；已完成项在相同位置展示调用关系、分析结果及其客观依据。

主报告不要求普通读者理解或筛选 `api_id`、`path_status`、内部原因码等字段。完整 API 和调用关系直接进入 `deliverables/all-impact-details.md` 和对应的 `all-impact-details.csv`；`alerts.csv` 仅保留原始记录。静态分析已经完成但没有找到路径时，结果显示为“已完成分析、未确认影响”，不能写成“未完成分析”。

## 性能排查入口

Step5 慢时优先查看：

```text
.runtime/observability/step5_timing.csv
```

重点指标：

| 指标 | 含义 |
|---|---|
| `bytecode_scan.elapsed_sec` | 运行时依赖字节码扫描耗时 |
| `bytecode_expand.elapsed_sec` | 运行时依赖调用者扩展耗时 |
| `trace.elapsed_sec` | 反向追踪总耗时 |
| `trace.incoming_edges_scanned` | 实际扫描的反向边数量 |
| `trace.declared_signature_index_*` | 方法签名索引构建状态 |
| `main.indirect_usage_*` | 反射/MethodHandle/表达式等间接引用扫描耗时 |
