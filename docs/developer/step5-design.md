# Step5 调用链分析设计

本文面向维护者，说明当前 Step5 的实际分析模型、结果语义和关键边界。

## Step5 的目标

Step5 消费 Step4 产生的 API 变化集合，判断这些变化是否可能影响当前业务系统。

它关注的问题是：

1. 变化 API 是否被业务源码直接调用；
2. 变化 API 是否被当前最终制品中的业务 class 引用；
3. 变化 API 是否被运行时依赖 JAR 引用；
4. 跨依赖调用链能否继续回溯到业务代码；
5. 反射、MethodHandle、表达式语言、资源配置和框架隐式边是否提供候选证据。

## 输入

主要输入：

| 输入 | 来源 | 用途 |
|---|---|---|
| `evidence/api_changes/all_changed_apis.csv` | Step4 | API 变化目标集合 |
| `evidence/api_changes/git_ref_matches.json` | Step4 | 确认依赖当前版本对应的源码 ref 和模块路径 |
| `evidence/dependencies/build_provenance.json` | Step1 | 确认业务制品来源 |
| `evidence/dependencies/s1_artifacts/` | Step1 | 提取业务 class 和运行时依赖 JAR |
| 系统源码目录 | `project_dir` / `project_scope` | 构建业务源码调用图 |
| `dependency_source_dirs` | 用户可选输入 | 提供依赖源码仓库位置；Step5 会固定到 Step4 已确认的当前版本，不直接使用工作区当前分支 |

## 证据层

Step5 当前不是单一源码扫描，而是多证据融合。

| 证据 | 作用 |
|---|---|
| 业务源码 AST/增强正则 | 构建业务方法、调用边、类型和 import 信息 |
| 业务字节码 | 证明最终制品中的业务 class 是否真实引用目标 |
| 运行时依赖 JAR 字节码 | 发现依赖包之间对变化 API 的引用 |
| 依赖源码映射 | 补足跨依赖源码链路；只允许与当前运行时 JAR 同坐标、同版本且实际打包的类进入图 |
| framework adapters | 补充 SPI、Spring、MyBatis、动态代理、运行时主动入口等隐式边 |
| indirect usage analyzer | 识别反射、MethodHandle、资源、表达式语言等候选 |

Java 类级使用优先读取 AST 与类型元数据中的结构化事实：返回值/参数/字段/局部变量声明、
泛型参数、方法和类注解、extends/implements、throws、方法引用、构造器和静态限定调用。
简单类型名必须能由显式 import、唯一已知 FQCN、同包或唯一通配包解析到目标；同名候选、
其他 import 以及遮蔽类型名的局部值不会升级为确定命中。正文模式只保留给解析器降级路径，
最终制品中的类引用仍由独立字节码证据确认。

## 分析流程

简化流程：

```text
Step4 all_changed_apis
  -> 构建系统源码图
  -> 提取 current 最终制品业务 class
  -> 扫描 current 运行时依赖 JAR
  -> 将依赖源码固定到 Step4 确认的 current ref，并按同坐标 JAR 类清单过滤
  -> 合并反射/框架/字节码证据
  -> 对每个 API 做反向追踪
  -> 输出 evidence/call_chain/alerts.csv / summary.json / by_api
```

## 依赖源码版本对齐

依赖源码只是运行时 JAR 的辅助证据，不能扩大当前制品的实际范围。Step5 使用 Step4 已确认的 `current ref` 创建只读的 detached worktree 快照，不切换、不修改用户仓库的当前分支、HEAD 或未提交内容。

对齐后还会按相同依赖坐标的 current JAR 类清单过滤源码：源码仓库中存在、但没有打进该 JAR 的类和方法不会进入调用图。这能防止错误分支、其他 profile、未打包模块或仓库附带源码形成虚假链路。

以下任一情况都会拒绝该源码映射：

- Step4 没有唯一确认 current ref；
- 源码映射与 Step4 记录的 Git 仓库不一致；
- ref、模块路径或快照无效；
- current 最终制品中没有同坐标 JAR，无法校验源码范围。

拒绝后 Step5 继续使用 current JAR 字节码证据，不会退回本地工作区当前分支。对齐明细写入 `evidence/call_chain/dependency_source_alignment.json`，包括选定 ref、commit、JAR 类数量以及被保留和排除的源码类数量。

## 目标键与反向图

Step5 会为每个变更 API 构建目标 key，例如：

- 精确方法签名；
- 无签名方法名回退；
- 构造器 key；
- 字段 key；
- 类级使用 key；
- 多态或兼容签名候选。

源码图和字节码图会写入 `reverse_edges`，即：

```text
callee_key -> caller edges
```

目标匹配必须遵守两个准确性边界：

- 不会把任意类的同名方法隐式合并到 `java.lang.Object`；继承边只能来自已证明的类型元数据。
- 源码图只命中其他重载、但当前最终制品已完整扫描且未命中目标精确描述符时，结论是 `not_found_in_static_analysis`，不是 `not_analyzed`。

依赖接口中已有方法体的 `static` / `default` / `private` 方法不属于动态代理边界，不得因“无实现类”提前停止回溯。

反向追踪从目标 API 出发，沿调用者方向回溯，直到：

- 触达业务代码；
- 达到最大累计 cost；
- 触达框架边界；
- 找不到更多调用者；
- 由于输入或能力不足停止。

## 置信度和深度

`max_depth` 表示最大累计 cost，不是简单 hop 数。

高置信边 cost 较低，可以走更深；低置信边 cost 较高，会更早停止。

当一条路径的目标匹配来源始终属于 `exact`，且沿途全部是高置信物理边时，追踪器会按
当前图的物理边数自适应放宽 cost 预算。放宽后的上限不超过调用方显式预算的 3 倍，
默认预算下最多为 15，且系统绝对自适应上限为 20；调用方显式给出的更大预算不会被
该上限反向缩小。只要出现 medium/low、polymorphic 或 fallback 证据，整条路径立即恢复
使用原始预算。

深度停止仍然失败关闭。`path_details` 会记录 `budget_limit`、`truncated_target` 和
`truncated_candidate_count`，`alerts.csv` 的 `coverage_details` 同步给出这三个值，
不得把截断解释为没有影响。

这样做的目的：

- 保留高置信多跳链路；
- 避免低置信候选无限扩散；
- 让 `uncertain` 明确保留为人工复核对象。

## 五态结果

| 状态 | 语义 |
|---|---|
| `reachable` | 已找到确认链路并触达业务代码 |
| `not_impacted` | removed API 的旧类与当前其他运行时依赖中的同名类字节码完全一致，证明该 API 未从当前制品消失 |
| `uncertain` | 有候选证据，但链路或证据不足以确认 |
| `not_found_in_static_analysis` | 分析已执行，但当前静态证据未找到路径 |
| `not_analyzed` | 输入缺失、工具能力不足或覆盖不完整，无法有效分析 |

重要边界：

- `not_found_in_static_analysis` 不是“确定不影响”。
- `not_analyzed` 不能被当成无风险。
- `not_impacted` 只证明目标 API 符号仍被相同字节码提供，不证明被删除 jar 的资源、SPI、清单或其他非 API 内容没有影响。
- Kotlin/KTS 使用部分能力分析；相关源码仅由正则解析且可能引用目标 API 时，负向裁决与制品保留捷径都必须失败关闭为 `PARTIAL_LANGUAGE_ANALYSIS`。
- 字节码命中运行时依赖使用目标 API，但无法回溯到业务入口时，通常应进入 `uncertain`，并保留消费依赖、消费类和消费方法。

## 删除依赖 jar 的语义

删除依赖时，Step4 会从旧版 JAR 导出 public/protected 符号作为目标池。

Step5 需要检查：

1. 业务源码是否直接引用已删除符号；
2. 业务字节码是否引用已删除符号；
3. current 最终制品中的其他运行时依赖 JAR 是否仍引用已删除符号；
4. 如果运行时依赖命中，能否继续回溯到业务入口。

因此，删除依赖不是只看业务源码 import。运行时依赖仍使用被删 API 时，也必须进入证据链。

## 反射和间接调用

Step5 负责处理与 API 变化相关的反射风险，例如：

```java
Class.forName("org.apache.commons.lang.StringUtils")
    .getMethod("isBlank", String.class)
    .invoke(null, value);
```

当前支持的间接证据包括：

- `Class.forName`;
- `getMethod` / `getDeclaredMethod`;
- `getField` / `getDeclaredField`;
- `getConstructor` / `getDeclaredConstructor`;
- `MethodHandles`;
- 资源文件中的类名或方法线索；
- 表达式语言中的类型引用。

精确匹配能形成边时，进入调用链；动态 member 或不完整证据会进入 `uncertain` 或覆盖矩阵。

## 运行时主动入口

并非所有影响链路都必须从业务源码显式调用开始。若依赖源码中存在容器或框架会主动触发的入口，例如 `@Scheduled`、`@PostConstruct`、Spring Runner/Lifecycle 或 Quartz `Job.execute`，Step5 会把该方法作为框架主动入口。只要该入口链路触达变更 API，就可以形成影响链路。

## 最终制品中的同名 class

框架适配器必须按最终制品的实际 classloader 可见性处理同名类，不能仅因多个物理条目归一到同一 FQCN 就全局阻断：

- 业务制品使用 `BOOT-INF/classes` / `WEB-INF/classes` 对应的应用 classpath 根；作为依赖挂载的 JAR 只使用自身归档根，不能把其内部的第二层可执行 JAR 布局当成新的 classpath 根。
- 多个运行时可见候选的 class 字节码完全一致时，合并为一个等价候选并保留副本来源。
- 字节码不同时，只有最终制品提供了可验证的加载顺序（例如 `BOOT-INF/classpath.idx`），或业务 classes 对依赖 JAR 的优先级可确定时，才能选择 effective class；其他候选作为 shadowed 证据保留。
- 字节码不同且加载顺序无法证明时，输出带候选 JAR、物理 entry、class 名称和字节码摘要的路径级歧义。该失败只约束涉及相应 class 的框架候选路径，不得传播成所有变化 API 的 `not_analyzed`。
- ZIP 中完全相同的物理 entry 名仍属于制品身份异常，应在事实库存阶段失败关闭，而不是按普通 classpath shadowing 处理。

## 原因码自助决策契约

`summary.json` 不能只输出 `not_analyzed_reason_summary` 的原因码计数。每个进入
`uncertain` / `not_analyzed` 的主原因，以及 failure ledger 中未成为主原因的阻塞失败，
都必须进入 `diagnostic_guidance[]`。该数组使用
`java-upgrade-analyzer.reason-guidance.v3`，至少包含：

- 稳定 `reason_code`、可读标题和触发条件；
- 该原因的语义影响，以及本轮实际观察到的 `api` / `path` / `global` 传播范围；旧结果缺少
  typed failure 时必须标为 `unknown`，不能猜测；
- 以该原因为主原因的 API 数、按 failure 作用域反推的潜在受影响 API 数、状态分布和少量 API 样例；`affected_api_count` 表示两者并集，不再把 failure 记录数冒充 API 数；
- failure 记录数与聚合后的物理 occurrence 数；`blocking` 表示该诊断是否实际限制本轮目标 API 结论，API 级 failure 未关联到本轮目标时只保留为覆盖遥测；
- 采集器、类、JAR、物理 entry、候选 class 哈希和错误摘要；
- 是否阻断、建议决策、可忽略条件、修复动作和完成标准。

Step6 继续兼容读取 v2：缺少新计数字段时，分别用旧 `affected_api_count` 和 `observed_failure_count` 补齐，不能把旧报告静默显示为 0。

Step6 必须直接消费 `diagnostic_guidance[]` 的诊断事实，不得维护另一套相互冲突的解释。
主报告只呈现可读标题、观察范围和对结论的客观限制；原因码与物理证据进入诊断明细，
`recommended_decision`、`repair_actions` 和 `verification_steps` 不进入 Step6 用户报告。
旧版或合成 `summary.json` 没有该字段时，Step6 可以用同一原因目录基于 API 列表和
`meta.graph_stats.evidence_ingestion.failures` 补建。

跨步骤原因码、字段命名和旧码兼容规则统一遵循
[`diagnostic-contract.md`](diagnostic-contract.md)，Step5 不再定义自己的命名风格。

`SPRING_RUNTIME_CLASS_AMBIGUOUS` 是路径级失败，只能影响经过歧义类的 Spring 路径。
旧原因码 `SPRING_PACKAGED_CLASS_AMBIGUOUS` 仅作为兼容别名读取，新结果不再输出该名称。
`MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED` 同样是路径级失败，作用对象为
`org.apache.ibatis.binding.MapperProxy` 代理路径；它不得再作为全局失败传播给所有变化
API。报告仍需如实展示历史输入中已经记录的 `global` 作用域，便于识别旧结果的过度传播。

## alerts.csv 设计原则

`alerts.csv` 是完整链路台账，不是抽样。

保留规则：

- A → B → C 已包含 B → C 时，同一命中的纯后缀可以不单独保留；
- E → B → C 与 A → B → C 是不同入口，需要保留；
- F → C 是不同消费方或不同链路，也需要保留；
- 每个进入 Step5 的 API 至少有一行，避免无声遗漏。

## 性能优化原则

Step5 的性能优化必须保持分析语义不变。

允许：

- 缓存重复排序结果；
- 构建等价索引；
- 按坐标与 owner 对多个目标执行多源反向传播，复用与目标无关的前驱转换；
- 复用字节码扫描结果；
- 对业务 class 使用 classfile 直接解析作为快路径，但解析失败、遇到反射/MethodHandle 线索或格式不确定时必须回退 `javap`；
- 记录耗时指标；
- 减少重复扫描。

不允许：

- 缩短搜索深度来换速度；
- 跳过低置信但有意义的候选；
- 把 `uncertain` 降级成 `not_found_in_static_analysis`；
- 用采样替代完整 alerts 台账；
- 为单一测试场景硬编码规则。

## 当前性能诊断点

Step5 会输出：

```text
.runtime/observability/step5_timing.csv
.runtime/observability/step5_diagnostics.jsonl
```

`step5_diagnostics.jsonl` 是追加式过程台账。collector 完成后立即按
`reason_code + blocking + scope` 聚合写入；逐 API 追踪第一次出现某个
`uncertain` / `not_analyzed` 原因时也立即写入，随后只在计数达到受控检查点时更新，
避免为数千个同原因 API 写数千条重复事件。正式调度器实时转发 Step5 stderr，不能等子进程
结束后再一次性打印。

核心制品身份、安全性和全局业务字节码证据失败必须写
`artifact_preflight_failure.json` 并在构图或逐 API 追踪前尽早停止。路径级和 API 级失败
不得扩大成全局短路；例如 `SPRING_RUNTIME_CLASS_AMBIGUOUS` 立即出现在实时台账中，但只
限制经过歧义类的路径。

重点看：

- `main.indirect_usage_*`;
- `main.business_bytecode_elapsed_sec`;
- `main.business_bytecode_classes_scanned`;
- `main.business_bytecode_classfile_fast_path_classes`;
- `main.business_bytecode_javap_fallback_classes`;
- `bytecode_scan.*`;
- `bytecode_expand.*`;
- `trace.incoming_edges_scanned`;
- `trace.incoming_edges_cache_*`;
- `trace.declared_signature_index_*`;
- `trace.direct_class_usage_*`;
- `trace.direct_field_usage_*`;
- `trace.direct_source_fact_index_*`（类型/字段源码事实的一次扫描构建成本、复用命中、正文读取与缓存释放、索引 key 数）；
- `trace.multi_target_group_count` / `multi_target_target_count` / `multi_target_shared_key_count`；
- `trace.reverse_transition_cache_builds` / `reverse_transition_cache_hits`；
- `trace.reverse_transition_edges_materialized` / `reverse_transition_edges_reused`；
- `memory.*_current_rss_mb` 与 `memory.*_peak_rss_mb`（Python 主进程）；
- `memory.*_process_tree_peak_rss_mb` 与 `memory.*_child_process_peak_rss_mb`（Python 与全部后代进程）；
- `memory.*_self_cpu_sec`、`memory.*_child_cpu_sec`、`memory.*_external_process_wall_sec`；
- `memory.*_external_process_count`、`memory.*_external_process_peak_concurrency` 与按工具拆分的 `memory.*_external_process_count_<tool>`；
- `memory.*_temporary_file_current_bytes` 与 `memory.*_temporary_file_peak_bytes`（报告 `.runtime` 临时/缓存目录）；
- `memory.*_method_count`、`memory.*_reverse_edge_key_count` 与 `memory.*_reverse_edge_count`。

进程树采样只保留标量和工具计数，不保留图、批次或进程对象的引用。Linux 读取 `/proc`，
macOS 优先使用 `libproc`（仅在系统库不可用时回退 `ps`）；其他平台显式记录
`process_tree_observer_supported=false`。采样失败会增加
`process_tree_sample_failures`，不会把缺失样本当作零内存证明。

可通过 `JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB` 设置软阈值：超过后保留完整结果并写入
`STEP5_PROCESS_TREE_RSS_SOFT_LIMIT_EXCEEDED` 告警。通过
`JUA_STEP5_PROCESS_TREE_HARD_RSS_MB` 设置硬阈值：在下一个阶段观测边界以
`STEP5_PROCESS_TREE_RSS_HARD_LIMIT_EXCEEDED` 失败关闭，避免继续扩大内存压力直至 OOM。
触发软阈值后，后续 `javap` 自动收敛为单 worker，并释放可从源码重新加载的方法正文字符串缓存；
不会删除图边、证据或缩小分析范围。阈值默认不启用，必须填写正数 MiB。
- `report.*`。

类型与字段直接使用共享 `direct_source_fact_index`：首次查询时遍历业务方法一次，收集声明类型、
AST 类型引用、正文类型 token、字段访问与静态导入，后续目标只做索引查询。索引物化后会释放可从
源文件重新加载的 `_body_text_cached`，不释放内嵌 `body_text`，也不改变证据排序和结论语义。

## 模块与失败边界

Step5 使用以下单向边界：`enhanced_source_analyzer` 提取事实，`signature_utils` 规范身份，
`step5_graph` 承载图，`step5_trace_policy` 承载纯追踪策略，
`confidence_weighted_tracer` 编排图查询，`step5_evidence_model` 收敛五态，
`enhanced_output_formatter` 只渲染结果。最外层 `s5_call_chain_engine_integrated` 可以依赖这些
模块，底层模块不能反向导入编排器。

运行时字节码与 JAR 元数据的 `javap` 失败都通过 `tool_execution` 形成结构化失败。
失败必须进入 analyzer ledger 或 `step5_evidence_failures`，同时产生 parser fallback；
collector 合并不得覆盖这类非 collector 失败。退出码为 0 但缺少要求的 stdout 也属于阻塞失败，
不能解释为“扫描完成且未命中”。

## 维护检查清单

修改 Step5 时至少检查：

1. 是否改变五态语义；
2. 是否影响 overload 安全过滤；
3. 是否影响删除依赖 jar 场景；
4. 是否影响运行时依赖多跳链路；
5. 是否影响反射/MethodHandle/资源证据；
6. 是否影响 `alerts.csv` 完整性；
7. 是否补充正例和负例测试；
8. 是否运行 Step5 质量门。
