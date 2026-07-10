# 输出文件与人工复核指南

本文面向使用者和人工复核人，说明 `.upgrade-report/` 中哪些文件应该优先阅读，以及每类结果代表什么。

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
| `evidence/` | 需要深入复核的人 | Step1-Step5 的事实证据 |
| `.runtime/` | 程序和 Agent | 状态、索引、恢复信息；普通阅读不需要进入 |

建议按这个顺序阅读：

1. 先看结论：已确认影响、可能影响、已确认不受影响、当前无法确认、需要补充输入。
2. 再看原因：为什么确定，或为什么不能确认。
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
| 1 | `deliverables/report.md` | 面向评审和交付的最终摘要 |
| 2 | `evidence/api_changes/changed_dependencies.md` | 依赖包维度的 API 变化摘要 |
| 3 | `evidence/call_chain/alerts.csv` | Step5 完整链路台账 |

如果结果存在疑问，再回到对应步骤的原始证据文件继续追溯。

这三个入口之间的关系是：

- `changed_dependencies.md` 回答“哪些依赖包发生 API 变化”；
- `all_changed_apis.csv` 回答“完整 API 变化事实是什么”；
- `alerts.csv` 回答“这些变更 API 有没有调用链影响”；
- `deliverables/report.md` 回答“最终应该如何理解本次分析结果”。

## Step1：依赖变化范围

Step1 的职责是确定本次分析实际采用的 base/current 构建产物和依赖变化范围。

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `evidence/dependencies/dep_changes.csv` | base/current 依赖差异明细 | 依赖坐标、版本、scope、变化类型是否符合预期 |
| `evidence/dependencies/dep_summary.txt` | Step1 摘要 | 目标模块、构建产物、依赖变化规模 |
| `evidence/dependencies/dep_alerts.csv` | 需要优先复核的依赖变化 | 降级、删除、无法解析或高风险依赖 |
| `evidence/dependencies/build_provenance.json` | base/current 构建产物来源和摘要 | 后续字节码分析是否基于正确制品 |
| `evidence/dependencies/s1_artifacts/` | 留存的 base/current 产物 | Step5 业务字节码和运行时依赖 JAR 的来源 |

注意：Step1 当前以真实构建结果或用户提供的构建产物为准，不把手工 dependency tree 当作正式事实源。

## Step2：上下文

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `evidence/context/context.json` | 升级上下文，如 JDK、Spring、依赖变化等 | 后续规则为什么启用或跳过 |
| `evidence/context/dep_graph.json` | 依赖关系和分析顺序 | 依赖升级传播关系 |

## Step3：背景风险扫描

Step3 用于识别 JDK、Jakarta、Spring 等框架升级带来的背景风险。

这些结果不能直接证明业务受影响；是否影响当前系统，需要结合 Step5。

常见文件：

| 文件 | 说明 |
|---|---|
| `evidence/static_scan/s3_jdk_removed_api.csv` | JDK 移除 API 命中 |
| `evidence/static_scan/s3_jdk_javax_refs.csv` | `javax.*` 引用 |
| `evidence/static_scan/s3_jdk_internal_api.csv` | JDK 内部 API 引用 |
| `evidence/static_scan/s3_springboot_config.csv` | Spring Boot 配置相关线索 |
| `evidence/static_scan/s3_springboot_autoconfig.txt` | 自动装配相关线索 |
| `evidence/static_scan/s3_dependency_compat.csv` | 依赖兼容性规则命中 |
| `evidence/static_scan/s3_dependency_classfile.csv` | classfile 版本等字节码线索 |

## Step4：依赖 API 变化事实

Step4 的核心输出目录：

```text
evidence/api_changes/
```

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `changed_dependencies.md` | 给人看的依赖包维度清单 | Step5 全量分析还是选择部分依赖包 |
| `changed_dependencies.csv` | 结构化依赖包清单 | `selection_key`、变化 API 数、高风险 API 数 |
| `all_changed_apis.csv` | 完整 API 变化事实集合，每行一个变更 API 或候选目标 | 变化 API 是否真实、符号类型是否正确 |
| `all_changed_apis_alerts.csv` | 高风险 API 变化子集 | P0/P1、删除、行为变化等 |
| `summary.txt` | Step4 覆盖率和执行摘要 | jar 是否缺失、JApiCmp 是否失败、git diff 是否跳过 |
| `*_binary.txt` / `*_binary.xml` | JApiCmp 原始证据 | 二进制兼容性变化来源 |
| `*_gitdiff_api_changes.txt` | 依赖源码 git diff 证据 | 行为变化、源码级 API 变化 |
| `*_removed_symbols.txt` | removed jar 的旧版 public/protected 符号导出 | 删除依赖场景目标池是否完整 |
| `step4_timing.csv` | Step4 耗时拆解 | 定位 jar 解析、git diff、JApiCmp、removed jar 导出、changed_classes 或汇总写文件等耗时点 |

### 依赖包维度选择入口

Step4 完成后，如果要决定 Step5 是全量分析还是只分析部分依赖包，优先看：

| 文件 | 用途 |
|---|---|
| `evidence/api_changes/changed_dependencies.md` | 给人看的依赖包维度清单 |
| `evidence/api_changes/changed_dependencies.csv` | 结构化依赖包清单 |
| `evidence/api_changes/all_changed_apis.csv` | 完整 API 变化事实集合 |

普通选择应使用 `changed_dependencies.md` 中的 `selection_key`，例如 `coord:com.foo:bar`。
`all_changed_apis.csv` 可能很大，它用于核对完整 API 明细，不作为普通选择入口。

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

## Step5：调用链影响证明

Step5 的核心输出目录：

```text
evidence/call_chain/
```

| 文件 | 说明 | 复核重点 |
|---|---|---|
| `alerts.csv` | 完整链路台账 | 每个 API、每条终止链路、状态和原因 |
| `summary.json` | 结构化汇总 | `analysis_status`、`reason_code`、能力覆盖 |
| `summary.md` | 人类可读复核摘要 | 状态含义、数量和阅读入口 |
| `summary.txt` | 执行摘要 | reachable、uncertain、not_found、not_analyzed 分布 |
| `step5_timing.csv` | Step5 耗时拆解 | 性能问题定位 |
| `dependency_source_alignment.json` | 依赖源码版本对齐证据 | 使用了哪个 current ref/commit、用户工作区是否保持不变、多少源码类被 current JAR 保留或排除 |
| `.runtime/indexes/s5_query_index.json` | 内部调用链查询索引 | Claude Code 按方法即时查询调用链；默认精确匹配全限定名，不作为人工阅读文件 |
| `by_api/*.json` | 单 API 详细证据 | 逐跳链路、证据路径、终止原因 |
| `by_module/*_impacts.json` | 按模块聚合视图 | 分派处理责任 |

`dependency_source_alignment.json` 是结果与预期不一致时才需要查看的辅助证据。依赖源码未能与 Step4 确认的当前版本或 current JAR 对齐时，Step5 会拒绝这份源码并继续使用 JAR 字节码分析，不会静默使用本地仓库当前分支。

### alerts.csv 的语义

`alerts.csv` 是完整主文件，不是样例文件。

它的设计目标是方便人工复核完整分析过程：

- 每个进入 Step5 的 API 至少一行；
- 每条终止链路独立一行；
- 不同业务入口、不同消费依赖、不同完整链路不会被合并；
- 如果一条长链路已经包含短后缀链路，可抑制同一命中的纯后缀重复行；
- 同一消费方法内的重复命中会合并，并通过 `path_occurrence_count` 标记次数。

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

## Step5 五态结论

| 人工结论 | 含义 | 程序状态（排查时使用） |
|---|---|---|
| 已确认影响 | 已找到业务代码或当前制品中已激活入口到变更 API 的完整路径 | `reachable` |
| 已确认不受影响 | 当前制品中的其他依赖以完全相同的类字节码保留该 API；不覆盖资源、SPI 等非 API 内容 | `not_impacted` |
| 需要人工复核 | 有候选证据，但尚不能形成确定链路 | `uncertain` |
| 静态分析未找到路径 | 已完成静态分析，但没有找到路径；不能解释为确定不影响 | `not_found_in_static_analysis` |
| 当前未完成有效分析 | 输入或工具能力不足，无法完成本项分析 | `not_analyzed` |

## Step6：最终报告

| 文件 | 说明 |
|---|---|
| `deliverables/report.md` | 面向人类评审的最终报告 |
| `deliverables/s6_probable_impact_apis.csv/md` | 可能影响清单 |
| `deliverables/s6_uncertain_apis.csv/md` | 需人工复核清单 |
| `deliverables/s6_not_impacted_apis.csv/md` | 有直接制品证据确认 API 未实际消失的清单 |
| `deliverables/s6_needs_input_apis.csv/md` | 缺少依赖源码/构建产物，无法回溯调用链清单 |
| `deliverables/s6_not_analyzed_apis.csv/md` | 本次未完成分析清单 |
| `deliverables/s6_not_found_apis.csv/md` | 未发现调用路径清单 |
| `.runtime/findings/s6_findings.json` | Step6 结构化结果；主要供程序读取 |

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
evidence/call_chain/step5_timing.csv
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
