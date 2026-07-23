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

建议按这个顺序阅读：

1. 先看结论：已确认影响、可能影响、已确认不受影响、需人工复核、缺少依赖源码/构建产物；风险等级 P0/P1/P2 与结论确定性分开阅读。
2. 再看原因：为什么确定，或为什么还不能形成确定结论。
3. 再看链路：哪个依赖、哪个变更 API、哪条调用链触达业务代码。
4. 最后看明细：只有当结论和预期不一致，才进入 `by_api/`、原始 JApiCmp 或耗时统计文件排查。

每个用户可见文件都应让你第一时间知道：

- 这个文件回答什么问题；
- 当前结论是什么；
- 结论来自哪个依赖、哪个变更 API、哪条链路或哪类证据；
- 如果需要继续复核，下一个应该看的文件是什么。

如果某个文件只有大量数字、内部字段或文件名，而不能直接说明问题和结果，应视为输出可读性缺陷。

## 复核入口

一次完整分析通常只需要先看三个文件：

| 顺序 | 文件 | 作用 |
|---:|---|---|
| 1 | `deliverables/report.md` | 面向评审和交付的最终摘要、结论边界和下一步复核顺序 |
| 2 | `evidence/api_changes/changed_dependencies.md` | 依赖包维度的 API 变化摘要 |
| 3 | `evidence/call_chain/alerts.csv` | 完整系统触达证据台账 |

如果结果存在疑问，再回到对应步骤的原始证据文件继续追溯。

这三个入口之间的关系是：

- `changed_dependencies.md` 回答“哪些依赖包发生 API 变化”；
- `all_changed_apis.csv` 回答“完整 API 变化事实是什么”；
- `alerts.csv` 回答“这些变更 API 有没有调用链影响”；
- `deliverables/report.md` 回答“最终应该如何理解本次分析结果”。

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
| `.runtime/observability/step1_timing.csv` | Step1 分支工作区、Maven 构建、坐标补全、制品解析、差异计算和结果写入耗时 |
| `.runtime/observability/step4_timing.csv` | Step4 jar 解析、git diff、JApiCmp、removed jar 导出、changed classes 和汇总写入耗时 |
| `.runtime/observability/step5_timing.csv` | Step5 建图、字节码扫描、框架适配、间接引用和调用链追踪耗时；`memory` 段同时记录主进程与完整子进程树的当前/峰值内存、CPU、外部命令次数/并发/墙钟时间、临时文件高水位及图规模 |

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

如果 Step6 的 `findings` 中存在 `diagnostics`，说明某个前序 JSON 或 CSV 无法读取或格式损坏。该文件对应的数据不会被当作“没有风险”；请先按 `artifact`、`path` 和 `error_type` 排查输入。

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

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `changed_dependencies.md` | 给人看的依赖包维度清单 | Step4 完成后选择全量或部分依赖范围 |
| `changed_dependencies.csv` | 结构化依赖包清单 | 推荐标记、变化 API 数、高风险 API 数 |
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
2. **部分分析（仅在明确控制耗时时）**：可选择“部分分析优先项”为“是”的依赖包。排序依据是含高风险 API、删除或签名变化，或变化 API 数不少于 20 个。
3. **从全部候选中选择部分范围**：打开 `changed_dependencies.md`，从完整清单复制“依赖包”列中的坐标，可同时复制多个，例如：`只分析 com.foo:bar、com.foo:baz`。

`all_changed_apis.csv` 用于核对 API 级明细，不作为依赖包选择入口。“部分分析优先项”只用于用户已经决定缩小范围后的排序，不表示系统建议缩小范围，也不表示已经确认影响当前系统。

确认结果会写入 `.runtime/cache/step5_selection.json`。最终报告会据此标明全量或部分范围；如果是部分分析，未选择依赖不会被纳入系统触达结论，也不能据此得出全局无影响结论。

最终会同时生成 `deliverables/analysis-scope.md`，把运行时范围快照转换为可直接核对的纳入/排除依赖清单和 API 数量。根目录 `README.md` 只展示本轮实际存在的文件，并使用可点击的相对链接；若流程正在等待确认，确认问题、选项和回复示例也会保留在该入口中。

完成状态分为“分析已完成”和“分析已完成，但存在结论限制”。部分范围、关键证据覆盖不完整、可能影响、需人工复核、本次未完成或证据读取异常均属于后者。

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

## 系统触达证据

Step5 的核心输出目录：

```text
evidence/call_chain/
```

### 人工优先看的文件

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `alerts.csv` | 人工优先入口，完整链路台账 | 每个 API、每条终止链路、状态和原因 |
| `alerts_<status>.csv` | 按结论状态拆分的链路台账 | 只看已确认影响、需人工复核、未发现路径或未完成分析时使用 |
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
| `by_module/*_impacts.json` | 按模块聚合视图 | 分派处理责任 |

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
| 需人工复核 | 有候选证据，但尚不能形成确定链路 | `uncertain` |
| 静态分析未找到路径 | 已完成静态分析，但没有找到路径；不能解释为确定不影响 | `not_found_in_static_analysis` |
| 本次未完成分析 | 输入或工具能力不足，无法完成本项分析 | `not_analyzed` |

## 最终报告

| 文件 | 说明 |
|---|---|
| `deliverables/report.md` | 面向人类评审的最终报告 |
| `deliverables/s6_probable_impact_apis.csv/md` | 可能影响清单 |
| `deliverables/s6_uncertain_apis.csv/md` | 需人工复核清单 |
| `deliverables/s6_not_impacted_apis.csv/md` | 有直接制品证据确认 API 未实际消失的清单 |
| `deliverables/s6_needs_input_apis.csv/md` | 缺少依赖源码/构建产物清单 |
| `deliverables/s6_not_analyzed_apis.csv/md` | 本次未完成分析清单 |
| `deliverables/s6_not_found_apis.csv/md` | 未发现调用路径清单 |
| `.runtime/findings/s6_findings.json` | 程序使用；Step6 结构化结果，不作为人工阅读入口 |

Step6 会避免把大量未命中 API 全部塞进主报告；主报告用于传达结论，附属明细用于展开复核。

Step6 主结果表固定使用以下五列：

```text
依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因
```

存在调用证据时，“证据摘要 / 未确认原因”会同时给出证据数量和可点击链接。阅读顺序是：

1. 在五列表格中查看变更事实和结论。
2. 点击“证据摘要 / 未确认原因”中的链接，跳到同一报告内的具体调用链证据。
3. 需要检查全部路径时，按照证据说明给出的 `api_id` 和 `path_status` 筛选 `evidence/call_chain/alerts.csv`。

报告内会把 `path_status = reachable` 的已确认链路与 `path_status = uncertain` 的未回溯依赖引用分开显示，避免把不同可信度的证据混为一类。静态分析未找到路径时不存在可展示的调用链，因此该行只说明已检查范围和未找到原因，不生成空链接。

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
