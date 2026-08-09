# 最终制品二进制主线与源码覆盖层设计

## 文档状态

| 项目 | 内容 |
|---|---|
| 状态 | 已完成（binary 权威已在显式受支持范围内可用；legacy 仅作显式整代回退） |
| 优先级 | P1 |
| 代码复核基线 | `main@8cc40d2` |
| 复核日期 | 2026-08-09 |
| 适用范围 | Step4 依赖变化事实、Step5 业务触达分析、Step6 结果投影 |
| 不适用范围 | 在 Step4/Step5 新增下游重编译、执行被分析业务的运行测试、用源码扩大最终制品范围 |

本文定义并记录 `java-upgrade-analyzer` 已实现的“最终制品二进制事实主线、源码语义覆盖层”架构。显式 `binary_strict` 与 `binary_with_legacy_fallback` 在 [`binary_first_support_manifest.json`](../../scripts/binary_first_support_manifest.json) 的受支持范围内可作为权威；默认模式是否从 `legacy` 改为 binary 仍是独立的发布/运营决定，不改变能力已交付这一事实。

截至 2026-08-09，本分支已完成阶段 0～5 的开发和自动验证，并完成阶段 6 的代码路径隔离：

- 版本锁定 ASM 9.9.1 framed helper 同时驱动 artifact diff、SQLite JVM 事实和 effective graph；缺源码不会删除 executable edge。
- base/current RuntimeProfile、platform image、ArtifactInstance、显式 lineage pairing、provider/resource selection、非初始化 class-definition、member/type/class-init/linkage/dispatch resolution 已绑定同一 analysis context。
- authoritative / diagnostic-only / excluded 三通道、四层 immutable active snapshot、projection obligation 守恒、exact/possible 批量图与 SCC 元数据、正式四维状态和整代原子激活已经贯通 Step4～6。
- Java 源码仅作为 alias/解释 overlay；编译期常量只有在精确 owner+field 源码引用和 base/current 字节码值转换同时成立时才为 proven。Kotlin/Scala、未知 transformer、安全或语义机制按 support manifest 降级/阻断，不猜测闭集结论。
- 独立 Oracle 不进入 AnalysisScope/生产 identity，并独立校验 archive/MR、pairing、direct/type/class-init/dynamic、目标 JVM provider/definition、member/dispatch、resource selection 和 sidecar 防篡改。
- 固定 400 JAR / 100,000 class / 10,000 API 档位已实测；暖运行 400/400 cache hit、parser invocation 为 0，版本化性能门见 [`performance_gate.json`](../../tests/fixtures/binary_first/performance_gate.json)。
- binary 模式不再调用 source-first ingestion 或逐目标制品重扫。旧实现只在显式 `legacy`、`shadow` 或预授权 whole-generation fallback 中保留，不能逐事实/逐边混入 binary generation。

术语约定：本文中的 `old` 与 `base` 指同一基线侧，`current` 指升级后侧；持久化 schema 统一使用 `base/current`，仅在兼容现有工具字段时保留 `old`。

精确支持边界以版本化 support manifest 为准；超出范围不自动扩权，必须形成 candidate、coverage gap 或 generation failure。

## 1. 最终决策

目标架构采用：

> **Step1 分别固化 SHA 绑定的 base/current 最终制品、RuntimeProfileIdentity 及 RuntimeComparisonIdentity，Step4 以 old/current 依赖 JAR 和 effective runtime view 识别变化，Step5 以 current 最终制品构建 JVM 事实主图，源码只提供位置、可读性和语义覆盖，Step6 分别表达变化事实、业务触达和影响确定性。**

该方案不是“只分析二进制”，也不是“源码存在时继续以源码图为主”。它要求：

1. 最终制品中的类、成员和 JVM 直接边只能由最终制品事实决定。
2. 源码缺失、源码无法映射或源码映射歧义，不得删除已经解析出的二进制节点和边。
3. 源码可以补充文件、行号、模块、可读签名、source-only 注解/生成原因以及框架/反射/配置候选，但不能覆盖或扩大最终制品范围；运行时 annotation/metadata 仍由 classfile 决定，SOURCE-retention annotation 本身不能作为运行时 activation。
4. “变化事实已确认”“业务触达已确认”“实际行为影响仍需验证”必须能够同时成立，不能再被压缩成 `not_analyzed`。

### 1.1 必须保留的复合结论

当 base/current 的 effective runtime view 已确认同一 JVM 方法的实际发布实现发生变化，且 current 业务最终制品已确认存在到 current effective provider 中该方法的完整调用链，并且路径上的 class provider、class definition、member resolution 唯一有效（或在目标 scope 内已证明 runtime-equivalent）、虚调用分派和 semantic activation 均为 exact/proven 时，目标结果必须是：

```text
change_fact_status          = confirmed
reachability_status         = reachable
impact_conclusion           = probable_impact
runtime_verification_status = required_not_executed
best_path_certainty         = exact_or_proven
```

兼容字段和派生字段必须同时保持一致：

```text
analysis_status                          = reachable
is_reachable                             = true
path_detail.path_status                  = reachable
envelope_path.complete                   = true
decision_bucket                          = probable_impact
runtime_verification_executed_by_system  = false
runtime_verification_evidence            = []
```

用户可见结论固定为：

> **已确认触达变化实现，可能受影响，需运行时验证。**

该状态的边界是：

- 不是 `not_analyzed`：变化识别和调用链分析都已经完成。
- 不是 `confirmed_impact`：当前系统没有运行测试，不能声称实际业务行为后果已经确认。
- 不是“调用链不确定”：`reachability_status=reachable` 明确保留已确认的静态精确触达事实。只有结构上可能分派到变化实现、但接收者类型尚未证明的路径必须使用 `uncertain`，不能套用本结论。
- `required_not_executed` 表示运行时验证尚未执行，是后续验证要求，不是假设已经存在测试结果。
- `dispatch_certainty` 在该路径包含虚调用时为 `exact_or_proven`，没有虚调用时为 `not_applicable`；两种情况的 `best_path_certainty` 都是 `exact_or_proven`，不得为了填充字段伪造 dispatch edge。
- `envelope_path.complete=true` 只表示这条路径已从 proven 业务根连续到达 target；全部路径是否枚举完整只看 `path_set_complete`，两者不得互相覆盖。

### 1.2 对准确性的最终判断

在本设计完整实施并满足覆盖门槛后，分析结果准确性预期净提升：

- 真实调用链召回率提高，主要减少无源码、生成代码、重载、内部类、lambda、bridge/synthetic 等场景的假阴性。
- 精确 descriptor 和 provider 绑定减少源码模糊匹配、同名类和错误重载造成的假阳性。
- `not_found_in_static_analysis` 只有在目标相关 entrypoint/root/direct/class-provider/class-definition/member-resolution/dispatch/dynamic/class-init/linkage/inline 与适用语义覆盖完整时才能成立，负向结论更可信。
- 发布实现变化与实际行为后果分开表达，避免把字节码差异误写成已确认业务异常。

具体提升比例必须通过同一批真实工程的新旧引擎双跑计算，实施前不得虚构百分比。

“不漏真变化、不误识别变化”的硬保证只在已声明 `RuntimeComparisonIdentity + AnalysisScopeIdentity` 的完整交集内成立。对任意自定义 classloader、原始 ZIP 字节读取、未建模 agent/反射/本地代码等开放世界行为，不存在无条件的静态二值判定；本方案的闭环是将超出交集的相关 scope 显式留在 candidate/confirmed-unprojectable/partial，而不猜成变化或无变化。

### 1.3 开发准入结论

本方案在设计层面可有条件进入开发：先执行阶段 0 合同/fixture/门槛固化，再开发阶段 1～4 的 shadow 能力。该结论不等于允许直接切换生产权威；阶段 5 必须等单向 phase 编排、artifact pairing、runtime-effective gate、class-provider/class-definition/member-resolution/dispatch、entrypoint、authoritative projection complete/partial/unsupported、candidate diagnostic-plan coverage、obligation/projection/API 守恒和第 14 节独立质量门全部通过后才能开始 canary。任何实现若省略三通道/审计分流、把 artifact-local diff 直接提升，或继续让 source mapping 决定 executable edge，都不属于本文方案的合格实现。

## 2. 范围与非目标

### 2.1 Step1 构建是既有前置门槛

本设计不增加“下游重新编译分析”。

在 `checkout_build` 模式下，Step1 已经分别构建 base/current 目标模块：

- Maven 执行 `package`，失败立即阻断 Step1：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4456)、[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4479)。
- Gradle 执行 `build -x test`，失败立即阻断 Step1：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4608)、[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4635)。

当前命令本身没有 `clean`。虽然每侧在新 detached worktree 中构建，已经隔离普通历史输出，但目标设计仍必须落实第 6.12 节 clean-output invariant：校验/清理临时 worktree 内预存在的 tracked/ignored 输出，记录 Gradle/Maven build-cache 状态，并在无法证明输出对应固定 revision 时于 Step1 阻断。不能把 stale/generated residue 留给 Step4 当作编译环境噪声猜测。

在直接产物模式下，Step1 不为生成正式 base/current 制品而重新构建，而是消费用户已经提供的编译产物：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L5674)。仅当包内元数据不足以唯一补齐嵌套依赖坐标时，Step1 才可能基于固定源码 revision 调用 Maven/Gradle 运行时清单；Maven reactor 清单命令在多模块工程中可能包含 `package`：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L5707)、[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4097)。该动作只补坐标，不得替换用户提供的正式制品，也不得扩大从该制品解析出的依赖事实。

因此：

- 可信最终制品输入是下游前置门禁，但两种模式的门禁不同：`checkout_build` 必须构建成功并定位到产物；`provided_artifact` 必须同时提供两侧产物，并通过格式、嵌套依赖、完整归档扫描、SHA 以及坐标解析/显式 unresolved 策略校验。
- checkout build 的构建或制品定位失败是整次运行的 Step1 门禁失败，状态为 `blocked_by_system`；不生成下游逐 API `not_analyzed` 结果，也不继续执行 Step4/Step5/Step6。
- provided-artifact 校验失败同样在 Step1 阻断。两种输入模式是本轮运行开始前的二选一，不得在 checkout build 失败后自动改吃另一组直接产物。
- 直接产物模式的当前 `build_provenance.build_succeeded` 仅表示对应产物路径已成立，不表示分析器执行过构建：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L6259)。目标 schema 应将其拆为 `artifact_available` 与实际 build execution provenance，避免误读。
- 两种模式都必须分别建立第 6.0 节 base/current `RuntimeProfileIdentity`、field coverage 和 `RuntimeComparisonIdentity`；checkout build 的宿主 JDK/OS 只属于 BuildEnvironmentIdentity，不自动成为目标 runtime。profile 中影响 platform/MR/provider/native/resource/entrypoint 选择的字段未知时，相关下游 scope 为 candidate/incomplete，而不是猜用构建机值。
- Step4/Step5 不再增加独立的 `recompile_impact` 结论。

当前另有一个必须区分的窄例外：当固定 commit 中缺少配置的生成源码目录，且该侧来自 Step1 `checkout_build` 时，Step5 可能在 detached worktree 执行 `mvn -DskipTests compile` 重新生成源码：[`s5_call_chain_engine_integrated.py`](../../scripts/s5_call_chain_engine_integrated.py#L558)、[`s5_call_chain_engine_integrated.py`](../../scripts/s5_call_chain_engine_integrated.py#L799)。它只服务 source overlay，不重新生成或替换 Step1 正式制品。目标方案中该动作失败只能按作用域降低源码展示或适用 semantic coverage；不得删除已建立的 JVM direct edge、重新判定 Step1 构建失败，或产生“下游编译影响”结论。

还必须区分“Step1 已接受直接产物”和“当前全流程已不需要源码”。现有 Step2 仍硬性要求 base/current branch 及固定 commit，直接产物只完成 Step1 并不会绕过该门槛：[`run_step.py`](../../scripts/run_step.py#L11185)。目标 binary 模式应允许从 Step1 制品事实继续建立 Step4/Step5 二进制主线；缺少固定源码时，Step2 源码上下文和 source/semantic overlay 按明确 coverage 降级，不能阻断已经具备完整二进制输入的主线。该解耦本身属于待实现项。

### 2.2 当前系统不执行运行测试

Step1 的构建命令跳过测试；Step4/Step5/Step6 也不执行单元测试、集成测试或运行流量回放。本设计不新增测试执行器，也不允许报告暗示已经取得运行测试结果。

本工程自身的单元/集成回归测试只验证分析器实现和输出合同，不是对被分析业务应用的运行时验证，不能据此填充某个变化 API 的 `runtime_verification_evidence`。

“需运行时验证”只能表达：

- 静态分析已确认发布实现变化及业务触达；
- 实际业务行为后果不在当前静态证据能力内；
- 后续验证尚未执行。

### 2.3 其他非目标

- 不使用依赖源码重新发现 Step1 最终制品中不存在的依赖、版本、类或模块。
- 不把 old/base 制品混入 Step5 current 运行时图；old/base 只用于 Step4 建立变化事实。
- 不把 Spring、MyBatis、反射、配置、代理等语义关系伪装成 JVM 直接调用指令。
- 不把“静态证据未找到路径”表述为绝对无影响。
- 不因性能优化减少扫描 class、删除真实边或缩短可达性闭包；路径枚举达到确定性预算时可以停止，但不得静默抽样或把已物化路径冒充理论全集。
- 不在一次 Step5 运行中混用一部分 legacy 图和一部分 binary 图作为共同权威来源。

最终制品权威以“Step1 固化字节是目标 runtime profile 实际加载/消费的静态输入”为前提。若检测到 Java agent、runtime weaving、JVMTI redefine、动态下载插件、hidden class 或其他未建模运行时字节码变换，且没有 SHA 绑定的变换后 class 与版本化 transformer model，则相关 graph/effective-fact coverage 必须为 incomplete。只有路径上全部 class/edge 均被证明不在 transformer 匹配与可动态增删范围内的正向路径才能保留正式 `reachable`。任一路径节点/边可能被未建模变换时，变换前路径只作诊断证据：有受支持模型证明其仍是合法可能性时才能形成 `uncertain`，否则正式结果为 scoped `not_analyzed`。负向闭集和 affected/no-change 完整性均不能成立。不得把变换前 class 冒充实际运行 class，也不得为了保持结果数量而静默忽略 agent。

## 3. 当前实现基线

### 3.1 Step1 已具备最终制品事实入口

Step1 已支持两种输入模式：

1. 固定 base/current revision 后在隔离 worktree 构建最终制品；
2. 直接消费用户提供且包含可比较嵌套依赖的 base/current packaged JAR/WAR；当前 thin JAR / 无嵌套依赖场景会在 Step1 阻断，不会伪造正式依赖结果：[`s1_dep_diff.py`](../../scripts/s1_dep_diff.py#L4783)。

随后 Step1 留存最终制品、变化依赖 JAR、全部 current 运行时 JAR和 current 业务 classes，并记录制品 SHA-256 与构建来源。Step5 的运行时 catalog 会再次校验这些留存制品：[`s5_call_chain_engine_integrated.py`](../../scripts/s5_call_chain_engine_integrated.py#L3095)。

这条现状输入尚不足以支持目标方案的 base/current provider、resource-selection 和 inline 对账：只留变化依赖的 base JAR 不能证明 base loader 闭包完整。实施时 Step1 必须对两侧都固化完整业务最终制品、全部受支持运行时依赖/容器提供库、有序 classpath/module-path/nested slot 和 loader/resource 声明快照；任一侧只有局部闭包时，只允许对独立完整的 scope 做正向裁决，不得输出 provider/resource 未变或完整静态未命中。

本设计直接复用这条事实入口，不从 Maven 本地仓库、重新下载的 JAR 或未绑定本次运行的产物补证。

### 3.2 Step4 结构变化已经以二进制为主

当前 Step4 的结构 API 变化主要由 JApiCmp、old JAR 导出和 classfile contract 产生。源码结构变化不会替代 JAR 主证据进入 Step5：[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L3127)。

主要缺口在实现变化：

- 已有同签名方法字节码比较能力：[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L2543)。
- 但当前只有源码 diff 不可用时才运行 JAR 方法体比较：[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L8777)。
- 单纯“没有依赖源码映射”不会必然设置 `source_skip_for_behavior`，因此并不保证触发上述 JAR 方法体比较：[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L8209)、[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L8222)。
- 源码 diff 成功时，源码方法体变化可以被正式提升，但当前所谓 JAR 核验主要确认成员在两侧存在，不等同于确认发布方法体也发生变化。
- 当前 behavior coverage 的 planned 集合以 `coord in dependency_paths` 为前提，无源码映射的适用依赖可能不进入分母：[`s4_jar_compare.py`](../../scripts/s4_jar_compare.py#L9320)。因此现有 coverage 不能证明所有具备 old/current JAR 的依赖均已完成实现比较。

### 3.3 Step5 仍存在两套节点建立规则

当前 Step5 先建立 `SourceGraph`，随后合并业务最终制品字节码证据。普通字节码批次仍要求调用方映射到已有源码 `MethodDef`；无法映射时记录 `BYTECODE_CALLER_UNRESOLVED` 并拒绝原始边：[`step5_evidence_ingestion.py`](../../scripts/step5_evidence_ingestion.py#L1922)。

同时，目标驱动的运行时扩展已经可以创建 `language="bytecode"` 的 synthetic `MethodDef` 并补边：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L5900)。这能补偿部分目标相关路径，但没有统一初始主图身份，也不保证完整枚举全部 JVM 直接边。

全量运行时边采集函数已经存在，但尚未进入生产主流程：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L4379)。当前逐 API 追踪完成后才补充 analyzer edge ledger，不能用事后新增边回算已经生成的 `TraceResult`。

现有 classfile parser 能读取 `Dynamic/InvokeDynamic` 常量池项并处理部分 LambdaMetafactory handle，但没有把 `CONSTANT_Dynamic`、bootstrap linkage、lambda SAM binding 或 class initialization 建成目标模型要求的独立事实：[`business_bytecode_graph.py`](../../scripts/business_bytecode_graph.py#L292)、[`business_bytecode_graph.py`](../../scripts/business_bytecode_graph.py#L500)。现有全量 ledger 也只收集 method/field reference：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L4441)。因此这些能力是新增设计范围，不能按“当前 parser 已支持 invokedynamic”视为完成。

当前 `Step5ArtifactFactStore.from_catalog()` 仍以 coordinate 为唯一 map key，遇到同坐标不同物理 identity 会标记冲突：[`step5_artifact_fact_store.py`](../../scripts/step5_artifact_fact_store.py#L165)。这与目标 `ArtifactInstance` 模型中“coord 只是标签”不兼容，阶段 2 必须先重构，不能原样复用。

### 3.4 当前结果模型混合了不同维度

当前 `TraceResult.analysis_status` 同时承担可达性、证据完整性和用户影响结论：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L1288)。输出层又将 `reachable` 直接映射成“已确认影响”：[`enhanced_output_formatter.py`](../../scripts/enhanced_output_formatter.py#L1027)。

对于 `BEHAVIOR_CHANGED`，当前至少有两条路径会把已经完整的可达路径降为 `not_analyzed`，再通过原因码映射成“可能影响”：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L7866)、[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L12074)。这保留了“不能确认实际运行后果”的保守边界，但错误丢失了“调用链已经确认”的状态。

当前 Step6 先把 `reachable_apis` 放入确认影响分组，而“可能影响”只从 `not_analyzed_apis` 二次派生：[`s6_report.py`](../../scripts/s6_report.py#L3953)、[`s6_report.py`](../../scripts/s6_report.py#L4032)。因此不能只改 tracer；Step5 schema、formatter、Step6 和查询消费方必须原子迁移，否则同一 API 会被重复计数或落入冲突分组。

## 4. 架构不变量

实施过程中以下不变量不可破坏：

1. **最终制品权威**：源码不能覆盖最终制品中的依赖、类、成员、descriptor、指令或 provider 事实；Lombok、annotation processor、Schema/IDL/ERM 生成器或编译期增强器产生并进入最终制品的代码同样属于权威二进制事实。
2. **真实边保留**：可解析的 JVM 方法、字段和可执行类型边不得因源码缺失、源码歧义或展示信息不足而丢弃。
3. **身份唯一**：同一 `(ArtifactInstance, ClassVariant, member kind, owner, name, descriptor)` 只能有一个物理节点；同 owner/member 由不同 defining loader 定义时必须是不同 JVM 类型/成员。源码 alias、runtime synthetic 节点和已有源码节点不得在同一物理 identity 内形成重复。
4. **物理与语义分离**：JVM direct edge 与 framework/reflection/resource semantic edge 分表、分类型、分 authority。
5. **JVM 解析链可审计**：保留 raw symbolic target；完整闭包中确认 provider 缺失与解析覆盖不足必须分别记录 `missing` 和 `unresolved`，多个候选记录 ambiguous，不得猜测；provider selection、class definition/linkage、member resolution 和 dispatch 分层守恒，前一层成功不能冒充后一层成功。
6. **存在性、分派确定性与闭集分离**：一条 edge-local exact/proven 可信路径可以证明静态精确触达；possible dispatch 只能证明可能触达；`path_set_complete` 单独表达是否完整枚举全部路径。
7. **失败作用域明确**：global、artifact、class、API、path 失败分别传播，不因一个 class 失败污染无关 API。
8. **负向失败关闭**：解析失败、目标 JDK 未知、provider 歧义、查询截断或适用语义覆盖不完整时，不得输出完整静态未命中。
9. **身份稳定且分层**：BuildEnvironmentIdentity、BuildInputManifestIdentity、ArtifactBuildProvenance、RuntimeProfileIdentity、RuntimeComparisonIdentity 和 AnalysisScopeIdentity 互不代填；binary blob、loader/effective provider graph、source overlay、inline overlay、semantic overlay、change targets 和 trace/report 分层绑定各自完整 identity。任一层输入变化只失效该层及下游，禁止用二进制 SHA 命中冒充整个事实库可复用。
10. **当前能力诚实**：系统没有执行运行测试时，正式 `by_api` 只能使用 `required_not_executed` 或 `undetermined`，不得出现 passed/failed，也不得输出 `confirmed_impact/confirmed_no_impact`；`not_required` 仅允许用于不表达业务影响的审计事实。
11. **运行时有效变化保留、非运行时差异排除**：源码、生成源码或 Schema/ERM/IDL 改动只要造成最终制品中运行时可执行、可链接或当前 AnalysisScope 内可消费事实变化，就必须认定为变化，不得因映射失败或 generated 标签被过滤；只有经完整规范化与 scope-local verifier 证明不改变当前运行时/可观察事实、仅属于容器、构建元数据或安全白名单属性的差异，才能从 Step4 变化目标和最终影响结果中排除。原始 archive/classfile 可观察性在 scope 内或存在可信消费者时，同一物理差异不得复用其他 scope 的排除结论。
12. **物理差异不等于 effective runtime 差异**：某个 JAR/class/resource 内部的规范化差异必须先通过 base/current 声明运行路径、loader/provider 或资源选择语义投影；只有已证明不在任何适用 runtime path、被遮蔽、MR/资源 variant 未被选择或其他 selection-non-effective 实例中的差异，才不得生成正式影响目标，选择语义不完整时只能进入 candidate。系统没有实际 class-load 观测，禁止用“尚未找到调用链/推测运行时不会加载”反向排除变化；selected effective fact 即使最终静态未触达，仍保留 confirmed change，由 reachability 单独给出 `not_found_in_static_analysis`。

## 5. 目标数据流

```text
Step1 base/current 最终制品、RuntimeProfileIdentity/RuntimeComparisonIdentity、物理实例与 loader/path 快照
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
       artifact-local 规范化差异          base/current effective runtime view
       + 完整比较/环境等价证据             + current JVM 事实主图
                 └────────────────┬────────────────┘
                                  ▼
                    runtime-effective 差异裁决
                  ┌───────────────┼───────────────┐
                  ▼               ▼               ▼
            authoritative      candidate        excluded
              └ projection assessment                 │
                 ├ targetable   │                 │
                 │  ├ complete  │                 │
                 │  └ partial   │                 │
                 └ unsupported  │                 └ exclusion evidence
                     │          └ diagnostic trace（独立 namespace）
                     └ confirmed-unprojectable report

authoritative-targetable projections ────┐
current JVM 主图 + source/semantic overlay ┤
                                         ▼
                               正式多目标反向传播
                                         ▼
               已确认变化 × 精确/可能触达 × 影响确定性 × 覆盖
                                         ▼
            alerts / by_api / Step6（仅 authoritative-targetable）

candidate / confirmed-unprojectable / exclusion 分别独立闭合，不进入正式影响计数
```

这里的 Step4/Step5 是事实所有权，不等于仍可用一次线性“Step4 全完成后才启动 Step5”的进程边界。目标 orchestrator 必须显式拆成单向阶段：

```text
Step4A artifact-local raw/normalized diff
  -> Step5A target-independent inventory + combined reconciliation fixed point
  -> Step4B runtime-effective disposition/decision + assessment/plan/projection freeze
  -> Step5B formal/candidate trace
  -> Step6 aggregation/report
```

Step5A 不读取 authoritative change fact/projection，Step4B 不反向改变已经冻结的 raw inventory；若新 evidence 使较早层失效，由 orchestrator 新建 generation 并从最早受影响阶段重算，不允许 Step4/Step5 递归调用、在同一 snapshot 内回写已消费输入，或先发布 Step4B 再异步补 Step5A。现有用户可见 Step 编号可以保留，但 staging manifest 必须记录上述 phase identity、输入/输出 digest 和完成状态；Step4B 未原子完成前不得向 Step5B 暴露正式 target。

## 6. 统一 JVM 事实模型

### 6.0 RuntimeProfileIdentity

所有 effective、entrypoint 和 reachability 结论都必须绑定目标运行 profile，不能默认等于 Step1 构建宿主环境：

```text
runtime_profile_schema_version
target_jvm_vendor/full_version/major
runtime_platform_image_identity（实际 modules/jmods/boot image 摘要或版本化等价平台模型）
target_os/arch
container_and_launcher_kind
ordered_runtime_path_entry_descriptors
loader_topology/delegation policy descriptors
runtime_code_source_origin_mapping_identity
runtime_security_and_package_sealing_policy_identity
active_application/framework profile identities
external_config_snapshot identities（可缺失但必须记 coverage）
agent/transformer/plugin profile identities
business_entrypoint_profile
field_coverage
runtime_profile_policy_digest（不含制品 payload SHA，只含平台/启动器/路径角色/加载与选择策略）
runtime_profile_digest（包含有序实际 payload/slot 的完整单侧快照）
```

Step1 只能从用户显式输入、最终制品布局、可验证 launcher/manifest/module facts 和版本化默认策略构造该身份，不能把 build host 的 JDK/OS 自动冒充生产 runtime。仅有 vendor/major 不足以唯一确定 boot/module class、默认 provider 和平台资源；涉及 class definition、JDK 类继承、member resolution、bootstrap 或 module 可读性时，必须绑定实际平台镜像或经独立验证的等价平台模型。影响 platform/native/resource/provider/entrypoint/CodeSource/security selection 的字段未知时，相关 scope 为 candidate/incomplete；不影响该缺口的已证明正向事实仍可保留。

为避免 identity 循环，`ordered_runtime_path_entry_descriptors` 使用 profile 绑定前的 outer/container logical location、content SHA、path kind 和有序 slot，loader topology 也使用声明描述符；它们不能引用已经包含 `runtime_profile_id` 的 ArtifactInstance/loader-realm 主键。logical location 必须是相对于制品/launcher manifest 的可重算位置，禁止将 detached worktree、临时目录或报告目录的绝对路径写入稳定 identity。若目标部署的 CodeSource URL/域/路径具有语义，必须由显式、规范化 deployment-origin descriptor 进入 `runtime_code_source_origin_mapping_identity`；不得用分析机临时绝对路径冒充。未知字段的显式 sentinel 与 `field_coverage` 必须参与 policy/snapshot digest，防止“未知”与“默认值”命中同一缓存。先计算两侧 `runtime_profile_policy_digest/runtime_profile_digest`，再派生 ArtifactInstance/loader realm，最后计算 `runtime_comparison_digest`。

#### 6.0.1 RuntimeComparisonIdentity

base/current 对账还必须有独立的 `RuntimeComparisonIdentity`，不能用一个 current profile 覆盖两侧：

```text
base_runtime_profile_identity
current_runtime_profile_identity
comparison_intent = same_deployment_profile | release_snapshot
profile_correspondence_policy_version
controlled_profile_fields
declared_upgrade_payload_scope
changed_or_unknown_profile_fields
runtime_comparison_digest
```

`same_deployment_profile` 不要求两侧完整 `runtime_profile_digest` 相同，因为被升级制品的 content SHA/版本本就应当不同。它只能在两侧 `runtime_profile_policy_digest`、受控字段一致，path-role/loader-scope correspondence（包括声明升级范围内的 base-only/current-only 依赖 slot）已完整建立，且所有允许的 payload/依赖增删差异均落在 `declared_upgrade_payload_scope` 时使用。未声明的 JVM/OS/launcher/config/path-role/loader 策略差异不能被制品 SHA 变化掩盖；必须使用 `release_snapshot` 并把 profile 变化本身作为可审计 delta。后者可以确认“两个发布快照的 effective 事实不同”，但不得把变化原因单独归因于源码或依赖升级。一次运行分析多个 profile pair 时，每个 `RuntimeComparisonIdentity` 使用独立 loader/effective graph、decision/projection/trace scope，不得把其中一个 pair 的 provider、入口或 API 状态合并成另一个 pair 的结论。

#### 6.0.2 AnalysisScopeIdentity

分析能力/可观察范围使用独立 `AnalysisScopeIdentity`，禁止塞入 RuntimeProfile 后伪装成运行环境变化：

```text
analysis_scope_schema_version
analysis_observability_scope（stack-trace/debug/profiling、任意 resource 读取、原始 archive/classfile 等）
artifact_diff_support_manifest_identity
runtime_loader_support_manifest_identity
class_definition_support_manifest_identity
runtime_fact_semantic_capability_identity
runtime_fact_dynamic_capability_identity
runtime_fact_transformer_capability_identity
environment_equivalence_capability_identity
analysis_scope_field_coverage
analysis_scope_digest
```

这里的 `runtime_fact_*_capability_identity` 只描述会改变 raw fact 解释、runtime effectiveness 或三通道变化裁决的提取/等价能力，不包含仅负责把已确认 change fact 绑定到分析 target 的 projection registry/rule，也不包含只验证实现质量的 Oracle。inline-consumption verifier、entrypoint、semantic-path eligibility 等只影响 target/path 的能力分别进入 assessment、overlay/trace identity；若同一 semantic/dynamic 模块还负责 runtime-fact 提取，必须暴露彼此独立的 fact、projection-planning 和 projection-implementation/trace capability identity。`oracle_support_manifest_identity` 只进入第 14.3 节 validation-run metadata。否则扩展一个 inline/投影规则或 Oracle fixture 就会伪造新的 runtime-effective decision。

改变 AnalysisScopeIdentity 只失效 normalization decision/projection/trace/report 等受影响层，不改写 base/current RuntimeProfileIdentity、ArtifactInstance 或 raw binary facts。AnalysisScope 不允许使用未记录的隐式默认；CLI/系统可选择一个版本化 named default，但其完整字段与 digest 必须写入 run manifest。同一 RuntimeComparisonIdentity 在不同 AnalysisScopeIdentity 下的结果不得直接聚合或比较计数；必须明示“分析范围发生变化”。

每个可聚合/守恒的运行上下文使用 `analysis_context_identity = hash(runtime_comparison_identity + analysis_scope_identity + context_schema_version)`。它是派生身份，不替代前两者；相同 pair 在两个 scope 下是两个 context，多 pair/多 scope 运行也不得假定为笛卡尔积。

### 6.1 ArtifactBlob

原始制品内容身份首先固定为 parser-independent 的 `artifact_content_identity = hash(content_sha256 + byte_length + content_identity_schema_version)`。构建 provenance、runtime path descriptor 和跨版本物理对账只引用该身份，不得因解析器升级改写“制品字节或来源已变”。

`ArtifactBlob` 是基于该原始内容的解析缓存身份：

```text
artifact_content_identity
+ archive_scanner_version
+ classfile_parser_version
+ binary_fact_schema_version
```

该层解析并保留归档内全部 physical/MR entry 和 raw classfile facts，不选择 target-JDK variant，也不做环境归因或 analysis-scope 排除。同一字节内容可以跨 target JDK/profile 复用解析事实，但不能因此丢失它在不同容器或 classpath 位置的物理实例。MR variant 选择及依赖 target JVM 的规范化/链接裁决属于 effective runtime graph/decision 层。

### 6.2 ArtifactInstance

运行时物理实例身份至少包含：

```text
outer_artifact_sha256
container_entry
content_sha256
runtime_profile_id
path_owner_loader_realm_id（持有该 runtime path slot 的候选定义 loader）
runtime_path_kind = business_classes | classpath | module_path | nested_runtime
runtime_classpath_index/provider_slot
container_loader_policy_version
runtime_code_source_origin_identity
coord（标签，不是唯一主键）
```

相同 JAR 出现在不同位置或被多个 loader realm 分别暴露时保留全部 origin/path binding。`path_owner_loader_realm_id` 只表示哪个 loader 搜索该 slot，不提前声称 class 已由它定义；父优先/子优先委派后的实际 `selected_defining_loader_realm_id` 只能由 `ClassProviderBinding` 给出。一个物理 payload 若可被两个 loader 各自定义，使用两个 profile-scoped ArtifactInstance/path binding 共享同一 ArtifactBlob，不能因 SHA 相同合并 JVM 类型身份。只有运行时加载规则证明它们等价时，effective view 才允许在明确 scope 内合并。

#### 6.2.1 CrossVersionArtifactPairing

old/current 制品比较不能以 coordinate 或文件名直接做一对一配对。coordinate 只是标签，同坐标可以存在多个物理实例；版本、classifier、嵌套位置、shading 或依赖解析路径也可能发生变化。Step1/Step4 必须保存版本化的跨版本配对事实：

```text
base_artifact_instance_id
current_artifact_instance_id
logical_dependency_lineage
base_runtime_scope_identity
current_runtime_scope_identity
pairing_status = exact | base_only | current_only | ambiguous
pairing_evidence
pairing_policy_version
```

配对规则固定为：

- `exact` 只能来自唯一的解析依赖 lineage、稳定的容器语义位置、明确的 upgrade mapping 或其他版本化强证据；logical lineage 通常保留 group/artifact/type/classifier 和解析来源，把 version 作为被比较值，而不是仅凭“简单文件名相同”去掉版本号；
- SHA 相同只能证明 payload 相同，不能单独证明跨版本 lineage 或 runtime origin 相同；owner/member 重合率、文件名相似度或源码映射只能产生候选证据，不能把 ambiguous 升级为 exact；
- 多个实例无法唯一对应时使用 `ambiguous`，禁止笛卡尔积比较后制造大量 member 变化，也禁止任取第一个；
- `base_only/current_only` 在两侧 inventory 完整时建立 artifact/class/resource 新增或删除的物理事实；它们是否形成正式运行时变化仍必须通过第 7.1.1 节 effective runtime gate；
- exact artifact pair 内，effective class 按 JVM internal owner 配对，member 按 owner + kind + name + descriptor 配对，resource 按机制声明的 logical key 配对；descriptor 改变必须表示为 old member removal + current member addition/contract delta，不得按简单名强配成实现变化；
- synthetic/lambda/匿名类跨编译版本发生重编号时，不允许靠名称相似度猜测“同一成员”。无法建立 exact lineage 时保留新增/删除事实或 candidate，由 source alias 解释，不得删除最终制品差异；
- base/current loader realm 无法建立可信 scope correspondence 时，artifact-local diff 可以完成，但 runtime effectiveness 只能为 unknown，不能生成正式 target。

`pairing_policy_version`、两侧完整 artifact inventory digest 和显式 mapping digest 必须进入 pairing attachment identity；配对决策变化必须使附着到 lineage/runtime scope 的 artifact-local facts 以及下游 effective-fact decision、projection 和 trace 全部失效。纯 ArtifactBlob 对的 raw/规范化比较缓存只由两侧 content、entry-alignment/parser/normalization schema 决定，不得因 target JDK、loader scope 或 pairing policy 改变而重复解析；该缓存结果只有重新通过 active pairing attachment 后才能进入裁决，不能靠旧缓存自行证明配对正确。

ArtifactPairing 用于解释 artifact-local lineage，不能成为 runtime-effective delta 的唯一入口。即使 physical pairing ambiguous，若 base/current runtime scope、symbolic owner/member、class provider/class-definition/member resolution 和 effective fingerprints 已由独立证据唯一对账，仍可建立 provider/topology 或 effective member change；反之，只有 artifact 文件配对成功而 runtime selection 未知，仍不能提升。每个 decision 必须声明自己是否依赖 pairing，禁止让无关 pairing 失败删除已证明的 effective delta。

### 6.3 ClassVariant

```text
artifact_instance_id
jvm_internal_owner
logical_entry
selected_physical_entry
multi_release_version
class_sha256
```

JVM owner 保留 `$`；展示层才转换为更易读形式。MR-JAR 只选择 target JDK 对应的 effective variant。

`module-info.class` 和 `package-info.class` 不能因没有普通业务方法而从 inventory/coverage 静默跳过：前者产生 module readability/export/open/service facts，后者产生 package annotation/metadata facts。它们不伪造普通 Member/DirectEdge，但解析失败会影响相应 loader/linkage/semantic coverage。

### 6.4 Member

```text
class_variant_id
member_kind = method | field
jvm_member_name
descriptor
flags
```

`<init>`、`<clinit>`、bridge、synthetic、lambda body、匿名/内部类成员均作为普通 JVM 成员保存，以 flags 标注，不归并、不删除。

### 6.5 SymbolicTarget 与 provider resolution

字节码指令首先产生 symbolic target：

```text
target_kind + owner + member + descriptor
```

class provider binding identity 至少是：

```text
runtime_profile_id
initiating_loader_realm_id
initiating_module_or_unnamed_identity
resolution_context_kind = bytecode_symbolic | type_linkage | launcher
                        | reflection | service_resource | mechanism_specific
initiating_class_or_runtime_origin_identity
symbolic_owner
selected_defining_loader_realm_id
selected_defining_module_or_unnamed_identity
selected_artifact_instance_id（`resolved` 时单值）
selected_class_variant_id（`resolved` 时单值）
provider_equivalence_set_identity（`runtime_equivalent` 时必填）
class_provider_status = resolved | equivalent_code_only | runtime_equivalent
                      | ambiguous | missing | unresolved
resolution_policy_version
```

`selected_*` 字段只在状态语义允许唯一选择时填写；`ambiguous/missing/unresolved/equivalent_code_only` 不得为满足非空约束而任取第一个 provider。`runtime_equivalent` 使用 equivalence set，不伪造单一 physical provider。

再根据最终制品容器、loader realm、classpath/module-path 顺序、业务 classes 优先级、父子委派规则和 MR-JAR 选择解析 provider，结果为：

- `resolved`：loader policy 与顺序已确认，唯一 effective provider 已选定；允许同时记录未生效 duplicate；
- `equivalent_code_only`：顺序未知的多个候选 class/member 代码事实相同，但物理 origin、CodeSource、签名、package sealing、resource 或 ProtectionDomain 等运行时可观察事实尚未证明等价；不能当作 exact provider；
- `runtime_equivalent`：独立 verifier 已证明 support manifest 内全部 provider-origin/loader/security/resource 可观察事实等价；只有该状态才允许在对应 scope 忽略候选顺序；
- `ambiguous`：多个不同候选且加载顺序无法证明；
- `missing`：相关 loader/module/classpath 闭包与 policy 已完整验证，但没有可绑定 class provider；这是可建立 `no_class_definition` 的精确负向事实；
- `unresolved`：loader 拓扑、闭包、policy 或解析过程不完整，当前无法判断 provider；不能用作精确缺失或链接失败证据。

raw symbolic target 始终保留。removed API 的 current provider 不存在时，仍可查询 caller 中保留的旧 symbolic reference。

provider resolution 必须从具体 `initiating_loader_realm_id + initiating_module_or_unnamed_identity + resolution_context_kind` 出发完成。相同 loader 内来自不同 named/unnamed module 的 caller、普通 constant-pool resolution、launcher/module lookup、反射和 service/resource mechanism 不得无条件共用 binding。若运行时 loader/module-layer 拓扑、委派方向、module readability 或 mechanism policy 无法证明，状态只能是 `equivalent_code_only/ambiguous/unresolved`；不得套用普通扁平 classpath 的 first-wins 结果。坐标相同不代表同一物理实例，坐标不同也不代表不能提供同一 JVM owner。相同 class bytes 只允许复用解析 blob，不能自动合并 ArtifactInstance/provider origin。

`initiating_loader_realm_id/module` 从 caller 的 defining loader/module 及 JVM/容器规则派生；launcher、reflection、service 等没有普通 caller 的机制必须由对应 runtime-origin fact 提供，不能从 callee 坐标猜测。解析结果必须保留实际 defining loader/module。JVM 类型身份核心是 `(binary name, defining loader)`，但 module identity 仍参与 readability/access/security facts；同 owner 由不同 defining loader 定义时是不同类型，hierarchy、member resolution 和 dispatch 均不得跨 loader 合并。跨 realm/module 委派或桥接只有 runtime loader support manifest 明确建模时才建立。

`runtime_equivalent` 只在 verifier 明确覆盖的 fact/trace scope 内具有 exact 资格：target 必须绑定版本化 provider-equivalence-set，并证明集合内每个候选对该 change fact、class definition 和 member resolution 都等价。用于 type/member/dispatch 路径的候选必须具有同一 defining loader realm，并对当前 initiating/defining module context 具有相同 readability/access 结果；同名同字节但 defining loader 不同仍是不同 JVM 类型，不能声明 runtime-equivalent。该状态不能被改写成任意一个物理 ArtifactInstance，也不能用于 origin/signing/resource 等未被 verifier 覆盖的结论。`equivalent_code_only` 始终不具备该资格。

这里的 provider resolution 只回答“哪个 classfile payload 会被该 loader realm 尝试定义”，不证明该 payload 能在目标 JVM 成功定义，也不回答最终解析到了哪个字段/方法。class provider selection、class definition/linkage、symbolic member resolution 和 virtual/interface runtime selection 是四个连续但独立的事实层，任何实现都不得把它们压成一个 `resolved_provider` 布尔值。

raw binary core 可以保存所有 ArtifactInstance 的 class/member/edge，但正式 `EffectiveGraphView` 必须同时约束 caller 与 callee：只有 caller class 在该 loader realm effective（或属于 scope-local runtime-equivalent set），且第 6.5.1 节 class definition 状态具备 traversal eligibility，其 outgoing edge 才能进入正式路径；callee 再按 class provider → class definition → member resolution → dispatch 解析。被遮蔽或无法定义 class 的真实字节码边保留审计；前者不得进入该 realm 的正式路径，后者只能通过独立 class-definition/linkage failure projection 表达，不能假装其方法已经可执行。一个实例在 realm A effective、realm B non-effective 时分别裁决，禁止在落库时用全局布尔值删除或启用。

`EffectiveGraphMembership` 至少保存 `runtime_profile/loader_realm/class_variant_or_equivalence_set/provider_binding/class_definition_resolution` 以及 `membership_status=traversal_eligible | shadowed | definition_failed | ambiguous | unsupported`。只有 `traversal_eligible` 的 caller outgoing edge 可进入普通传播；`definition_failed` 只允许进入对应 failure-trigger projection，`ambiguous/unsupported` 降低 coverage，`shadowed` 只留 raw audit。membership 必须逐 realm 生成且与 provider/definition 记录守恒，不能用 class-level 全局标志复用。

#### 6.5.1 ClassDefinitionResolution

选中 classfile 之后必须独立判断其在目标 JVM/platform/module/security 模型中是否具备定义与后续解析资格：

```text
class_provider_binding_id
class_definition_target_identity（单一 ClassVariant 或 provider-equivalence-set）
class_definition_status = definition_ready
                        | runtime_equivalent
                        | unsupported_class_version
                        | class_format_error
                        | verification_failed
                        | dependency_linkage_failed
                        | security_or_sealing_failure
                        | ambiguous
                        | unsupported
class_definition_policy_version
class_definition_evidence
coverage_status
```

规则固定为：

- `class_provider_status=resolved|runtime_equivalent` 的 binding 必须恰有一条 ClassDefinitionResolution；provider 为 `missing/ambiguous/unresolved/equivalent_code_only` 时不得伪造 definition-ready 记录；
- `definition_ready` 只表示 support manifest 内的 classfile version/format、必要 verification、super/interface/module dependency 和 signer/sealing 检查已通过，不表示 class 已初始化，也不证明业务运行实际加载过它；`<clinit>` 仍只由第 6.7.2 节处理；
- `runtime_equivalent` 只允许用于 provider-equivalence-set 中每个候选均独立达到 definition-ready，且定义结果在当前 fact/trace scope 等价的情况；必须引用完整集合，不能任取一个 ClassVariant；
- `unsupported_class_version/class_format_error/verification_failed/dependency_linkage_failed/security_or_sealing_failure` 只有独立 verifier 在完整输入上按目标 JVM 规则证明时才是精确失败，并可形成独立 class-definition/linkage fact；工具不支持、platform/module/security 输入不完整或验证未收敛时必须是 `ambiguous/unsupported`，不得猜成成功或精确失败；
- provider 已选中但 class definition 失败时，raw class/member/edge 仍保留，caller 不具备普通 traversal eligibility，callee 也不能继续做成功 member resolution。只有从业务根到“尝试定义/链接该类”的受支持触发路径已证明时，相关 failure projection 才能形成正式 `reachable + incompatible_if_executed`；单有坏 class 躺在 JAR 内不等于业务可触达；
- class definition status 发生 base/current 变化本身是 runtime-effective linkage delta，不能因方法 IR 相同而忽略；反之仅 physical class 存在但从未被任一适用 loader/resource mechanism 选择，仍按第 7.1.1 节 non-effective 规则处理。

### 6.6 DirectEdge

```text
caller_member_id
opcode_family
instruction_offset
symbolic_target_id
class_provider_binding_id
member_resolution_id
dispatch_requirement = none | virtual | interface
```

`invokedynamic` 不写入普通 DirectEdge，使用第 6.7.1 节 DynamicCallSite。`invokevirtual` / `invokeinterface` 的声明目标属于物理事实。可能分派到哪些实现应使用独立 dispatch edge，不能改写原始 direct edge：

```text
direct_edge_id
declared_member_target_identity（单一 member 或已验证的 member-equivalence-set）
implementation_target_identity（单一 member 或已验证的 member-equivalence-set）
dispatch_edge_certainty = exact | proven_receiver | possible | ambiguous
receiver_evidence_identity
hierarchy/provider_policy_version
```

有 implementation edge 不能反过来表示“分派已完成”；否则无具体实现、不完整或空集会被都误写成“没有边”。每个适用 virtual/interface direct edge 必须另有一条守恒的 `DispatchResolution`：

```text
direct_edge_id
declared_member_target_identity（单一 member 或已验证的 member-equivalence-set）
dispatch_resolution_status = unique_implementation
                           | proven_receiver_set
                           | possible_implementation_set
                           | mixed_receiver_set
                           | partial_possible_set
                           | no_concrete_implementation
                           | ambiguous
                           | unresolved
implementation_target_identities
implementation_set_digest
dispatch_coverage_status = complete | partial | failed
resolution_policy_version
```

`no_concrete_implementation` 只能在 provider、hierarchy、动态子类/插件边界和 JVM selection 规则均完整时成立。它只确认当前闭集中的 concrete implementation 集为空，不自动等价于“执行必然发生链接错误”：例如没有可实例化 receiver 与已证明某个 concrete receiver 在方法选择时失败是两个不同事实。该状态不物化 implementation edge；只有独立 linkage/invocation-selection verifier 已绑定具体 receiver/调用条件并按 JVM 规则证明失败时，才能另建 `static_linkage_status=incompatible_if_executed`。`ambiguous` 只在声明 member 已解析、所有相互排斥的 receiver/activation outcome 都有证据且可穷举时才可物化为多条 ambiguous/possible edge。provider/member resolution 自身 ambiguous 时不得越层生成 dispatch edge。

hierarchy/plugin/receiver 闭包不完整时不能把所有已知候选一起丢成空 `unresolved`：若已经有一个或多个 provider/member 均已绑定的合法 implementation target，使用 `partial_possible_set + dispatch_coverage_status=partial` 并物化这些 evidence-backed possible/proven_receiver edge，同时记录 unknown remainder scope；只有没有任何可安全绑定的 concrete target 时才使用空集 `unresolved`。这样正向 possible/proven 证据仍可形成 uncertain/reachable，负向闭集和 path-set completeness 保持失败关闭。

dispatch edge 必须区分：

- `exact`：final method、final class 等使 virtual/interface implementation 由 JVM contract 唯一决定；
- `proven_receiver`：该 implementation edge 具有独立、edge-local receiver/activation 证据，证明对应 concrete receiver 在该 callsite 可行并按 JVM 规则选择此实现；或者全部已证明可行 receiver 虽有多个类型但都选择同一 implementation target。仅证明候选集合有限/闭合、只做 points-to/CHA 过近似，不能把集合内每条边升级为 proven；
- `possible`：仅由 class hierarchy、接口实现集合或开放世界中的已知合法候选得到的可能实现；开放世界未知余量由 `partial_possible_set` 的 coverage 表达；
- `ambiguous`：声明 member 已解析，但存在多个相互排斥、均有 receiver/activation 证据且可穷举的 dispatch outcome；每条边仍只是 possible/ambiguous。provider 或 member 尚未唯一解析时不建 dispatch edge；hierarchy/动态边界不完整但已有合法 target 时使用 `partial_possible_set`，完全没有可绑定 target 时才是 `unresolved`。

`invokestatic`、适用的 `invokespecial` 和 private call 不需要 dispatch edge；只有 class provider、class definition 与 member resolution 均唯一成功，或各层满足 scope-local runtime-equivalent 合同时，其路径 certainty 才能直接为 exact。只有 `exact/proven_receiver` dispatch edge 可以组成正式 `reachable` 路径。包含已穷举 `possible/ambiguous` 边的路径只能证明结构上可能触达，必须投影为 `uncertain`；`unresolved` 不物化猜测路径。Oracle 验证“它是合法可能实现”不能把它升级成已确认执行实现。

`DispatchResolution=proven_receiver_set` 要求每个 materialized implementation target 都能反查上述逐边证据，且证据集合与 implementation set 守恒；只证明“集合之外没有其他类型”但不能证明集合成员可行时，使用 `possible_implementation_set`。同一完整 callsite 中一部分 target 有逐边 receiver proof、另一部分只有 possible evidence 时使用 `mixed_receiver_set`；闭包另有未知余量时统一使用 `partial_possible_set`，但每条已物化 edge 仍保存自身 certainty。一个 callsite 因而可以同时拥有 exact/proven 路径与其他 possible 路径，结果聚合按第 9.4 节保留两类证据，不因 possible 分支降低已证明的 reachable；coverage partial 仍使对应 path set 与总体 completeness 为 partial。

#### 6.6.1 SymbolicMemberResolution

字段/方法的 JVM resolution 必须按 opcode、caller class、resolved owner、继承/接口规则、访问控制、static/instance kind 和目标 classfile/JVM policy 独立建模：

```text
symbolic_target_id
caller_class_variant_id
class_provider_binding_id
target_class_definition_resolution_id
resolved_member_id（`resolved` 时单值）
resolved_member_equivalence_set_identity（`runtime_equivalent` 时必填）
resolved_member_target_identity（以上二者恰取其一）
member_resolution_status = resolved
                         | runtime_equivalent
                         | no_class_definition
                         | class_definition_failed
                         | no_such_member
                         | illegal_access
                         | incompatible_class_change
                         | ambiguous
                         | unsupported
resolution_policy_version
resolution_evidence
```

规则固定为：

- raw DirectEdge 始终对应真实字节码指令，即使 current member resolution 失败也不能删除；
- 只有 `class_provider_status=missing` 才能生成 `member_resolution_status=no_class_definition`；provider `unresolved/ambiguous` 必须传播为 member `unsupported/ambiguous`，不得伪造精确缺失；
- provider 已选中但 `ClassDefinitionResolution` 是精确失败时使用 `member_resolution_status=class_definition_failed` 并引用该失败，不再执行普通 member lookup；definition 为 `ambiguous/unsupported` 时 member 只能为 `unsupported`。不得把 selected classfile 的存在等同于 class definition 成功；
- `member_resolution_status=resolved` 只允许建立在 `class_provider_status=resolved + class_definition_status=definition_ready` 上；caller、resolved owner 及查找过程中实际依赖的 superclass/interface definition 都必须满足对应 coverage，不能只校验目标 class 一项；
- `member_resolution_status=runtime_equivalent` 只能建立在 class provider 与 ClassDefinitionResolution 均为 `runtime_equivalent` 上，且 verifier 必须证明 equivalence set 内每个候选都按同一 opcode/caller/access/hierarchy 规则解析成功、解析结果对当前 fact/trace scope 等价，并生成版本化 member-equivalence-set；不得任取一个 physical member 填入 `resolved_member_id`。`equivalent_code_only` 不满足该条件，只能传播为 `ambiguous/unsupported`；
- 字段可以在 superclass/interface 中解析，方法解析和 interface/default method selection 必须遵守对应 opcode 语义，不能只在 symbolic owner 的本地 member table 查找；
- `invokespecial`、构造器、private method、interface default method、static/instance kind mismatch 和访问失败必须分别保留，不能统一猜成“调用同名方法”；
- 在 class provider/definition/member resolution 输入完整时，`no_*`、`class_definition_failed`、`illegal_access`、`incompatible_class_change` 可以引用对应精确 linkage fact 并建立 `static_linkage_status=incompatible_if_executed`；输入或 policy 覆盖不完整时只能是 `ambiguous/unsupported`，不得声称执行必然失败；
- virtual/interface dispatch 只能从 `member_resolution_status=resolved|runtime_equivalent` 的 `resolved_member_target_identity` 继续计算。member resolution 尚未完成时不得生成 implementation edge；后者的 dispatch/result identity 必须继续引用 equivalence set，不能在下游退化成任意 physical member。

该层的 identity、coverage、错误种类和独立 Oracle 必须与 class provider、class definition、dispatch 分开统计；否则无法区分“没有 provider”“class 无法定义”“符号解析失败”和“运行时接收者未收敛”四种准确性边界。

### 6.7 TypeEdge

可执行类型指令单独保存：

```text
caller_member_id
opcode_family = new | anewarray | multianewarray | checkcast | instanceof | ldc_class
instruction_offset
target_type_descriptor
class_provider_binding_id/status
```

TypeEdge 只可证明 type/class-level 使用，不能单独证明某个 method/field API 被调用。注解、签名或常量池中没有对应可执行指令的类型名必须存为 `MetadataReferenceFact`，不能冒充 TypeEdge。这里的 metadata reference 是否可消费、能否投影及 certainty 由独立机制裁决，不复用 `diagnostic_candidate_fact` 的通道字段。若 TypeEdge 参与正式类型级 `reachable`，必须通过第 14.3 节独立 type-edge Oracle；未实现该质量门前只能作为非正式辅助事实。

#### 6.7.1 DynamicCallSite 与 BootstrapFact

`invokedynamic`、`CONSTANT_Dynamic`、通过 `ldc/ldc_w` 装载的 `MethodHandle` 和 `MethodType` 必须保留为独立动态链接事实，不能把常量池中的任意 handle 直接改写为普通方法调用：

```text
caller_member_id
instruction_offset
constant_kind = invokedynamic | constant_dynamic | method_handle | method_type
callsite_name_and_descriptor
bootstrap_method_handle
bootstrap_arguments
bootstrap_provider_binding_id
bootstrap_provider_status
bootstrap_member_resolution_id
bootstrap_member_resolution_status
dynamic_mechanism = lambda_metafactory | string_concat | method_handle
                  | var_handle | custom | unknown
dynamic_binding_status = proven | possible | unresolved
coverage_status
```

处理规则固定为：

- 执行 `invokedynamic` 或解析 `CONSTANT_Dynamic` 时，bootstrap method 属于链接期可能执行的目标，使用独立 `BootstrapLinkageEdge`，不得伪装成普通源码调用；
- LambdaMetafactory 的 implementation handle 只建立 `LambdaBinding`。创建 lambda 对象不等于调用 lambda body；只有后续 SAM 调用与该 binding 通过 receiver/dispatch 证据关联后，才能到达实现方法；
- `ldc` 装载 MethodHandle/MethodType 只建立常量/绑定候选，不等于调用 handle 指向的方法。`MethodHandle.invoke/invokeExact` 及 `VarHandle` access-mode 方法都具有 signature-polymorphic 规则；通过 Lookup/condy/字段传递的 handle 只有经独立数据流、access-mode 和 activation verifier 绑定到具体方法/字段后，才能建立 `MethodHandleInvocationBinding` 或 `VarHandleAccessBinding`。proven/possible/unresolved 规则与本节 dynamic binding 一致；未实现 VarHandle verifier 时必须显式降低相关 coverage，不得把它当作普通同 descriptor 调用；
- custom bootstrap、嵌套 dynamic argument 或未知 mechanism 无法完整解释时，保留原始事实并降低对应 dynamic coverage，不能生成猜测的 direct edge，也不能输出完整静态未命中；
- bootstrap、handle、参数或 resolved provider 的变化属于规范化 method IR/linkage 变化，不能因源码没有显式调用而忽略。

只有 mechanism-specific verifier、bootstrap provider/class-definition/member resolution 和端点 binding 均完成时，dynamic edge 才能使用 `proven` 并进入 exact/proven path；结构合法但接收者、SAM binding 或自定义 bootstrap 结果未唯一收敛时为 `possible`，只能贡献 `uncertain`；无法解释时为 `unresolved`，只降低 coverage，不能物化猜测目标。

#### 6.7.2 ClassInitEdge 与 LinkageEdge

`<clinit>` 不能只作为普通 member 保存，还必须通过 JVM 主动使用规则建立初始化触发事实：

```text
trigger_member_id
instruction_offset
trigger_kind = new | getstatic | putstatic | invokestatic | reflection | method_handle | runtime_entry
initialized_class_variant_id
selected_clinit_member_id
initialization_chain
resolution_status
```

`new`、`getstatic`、`putstatic`、`invokestatic` 等主动使用可以触发类初始化；`ldc_class`、`checkcast`、`instanceof` 和仅声明 descriptor 通常只涉及加载/解析，不能误当初始化触发。父类以及 JVM 规则要求初始化的接口顺序必须由版本化 class-init policy 计算。反射和 MethodHandle 只有 mechanism verifier 证明对应主动使用后才能建立初始化边。

方法/字段 descriptor、super/interface、exception catch type、bootstrap 参数、module/nest 等可能影响类加载、验证或链接的引用使用独立 `LinkageEdge` 和 support manifest 分类。普通调用可达、类型可达、类加载可达和类初始化可达是不同事实；任何一种都不得冒充另一种。若 `<clinit>` 实现变化，只有从业务入口到主动使用触发点、再到该初始化链的可信路径才能确认静态触达。

#### 6.7.3 编译期内联消费事实

Java 编译期常量、Kotlin/Scala inline 等内容进入 consumer 字节码后，通常不再保留对原字段或方法的 JVM symbolic reference。不能通过“字面量相同”“consumer 常量池包含该值”或源码单边命中伪造 direct edge。

目标模型增加：

```text
inline_source_target_identity
consumer_member_identity
consumer_base_current_ir_evidence
source_alias_evidence
compiler_or_language_metadata
inline_binding_status = proven | possible | unavailable
consumption_effect = changed_with_source | retained_base | removed | introduced | unchanged | ambiguous
coverage_status
```

首版规则为：

- 只有版本化 compiler/language verifier 能够把 exact source symbol、base/current consumer IR 位置和最终制品 member 唯一绑定，并证明 current consumer 中的嵌入实现/常量确实随 source target 发生对应变化时，才能建立 `proven + changed_with_source` 的 `InlineConsumptionEdge`；
- 仅有源码引用、old/new 常量值、字面量或 consumer IR 差异时只能形成 `possible` inline binding；
- current consumer 仍保留 base 值/实现，或 base/current consumer IR 在该绑定位置未变化时，必须记录 `retained_base/unchanged`，不得把“依赖侧常量或 inline body 已变”直接当成 current consumer 已受影响；该结论只覆盖已唯一绑定的 consumer，不能替代全局 consumer coverage；
- `introduced/removed` 只表示消费关系本身在两侧变化，仍需结合 current consumer 的实际嵌入事实决定 current target；`ambiguous` 只能贡献 possible evidence；
- changed compile-time constant/inline body 没有普通 JVM 引用时，必须记录 inline coverage。适用 consumer 范围无法证明完整时，不得输出针对该变化的完整静态未命中；
- 对 authoritative change，只有 `proven + changed_with_source` binding 可以组成 exact/proven 路径；`possible/ambiguous` binding 只能贡献 `possible_path_exists/uncertain`。对 diagnostic candidate fact，同样只进入 candidate 专属状态。两者都不得靠字面量或 source-only reference 升级为正式 `reachable`。

### 6.8 SourceAlias

```text
binary_member_id
repo + source_revision_identity + module + file + line/range + language
mapping_status = exact | ambiguous | unmapped | generated | conflict
```

`source_revision_identity` 优先使用固定 commit；允许的本地源码场景必须使用可复算的 source-state hash，不能以可移动 branch 名或工作区路径充当 revision identity。

一个二进制成员可以没有源码 alias，也可以有多个候选 alias。alias 歧义只限制源码展示和依赖源码语义，不限制 JVM direct edge。

编译期生成成员有可验证生成源码或生成清单时使用 `mapping_status=generated` 并记录 generator/schema provenance；没有可用生成源码时使用 `unmapped`。两种状态都只影响展示和溯源，不能降低该成员的 binary authority。

### 6.9 SemanticEdge

Spring、MyBatis、SPI、反射、MethodHandle、配置、表达式语言、代理和运行时主动入口继续使用独立语义边，并保留：

- authority；
- match quality；
- activation evidence；
- activation condition；
- capability coverage；
- artifact/source provenance。

authority、match quality、activation 和 coverage 是正交维度，不能压缩成单一 confidence 后丢失原始含义。

#### 6.9.1 BusinessEntryPoint 与 RootEdge

反向传播的业务根也不能继续隐含依赖源码 `MethodDef`。目标模型必须将入口建成独立事实：

```text
entrypoint_identity
entrypoint_kind = jvm_main | servlet | framework_route | listener
                | scheduler | messaging | rpc | agent | test_or_tooling | other
target_member_identity
loader_realm_identity
activation_status = proven | possible | inactive | unresolved
activation_evidence
entrypoint_policy_version
coverage_status
```

JVM manifest/module/agent 入口、classfile runtime annotation、已解析 framework/resource registration 和外部入口清单是主要证据；源码 annotation/方法声明只能补 alias 或产生候选，不能因源码缺失删除已经从最终制品确认的入口。外部请求、消息或调度器到入口 member 的关系使用 `RootEdge`，不得伪装成某个 JVM caller 的 DirectEdge。

只有 `activation_status=proven` 且 member/provider/class-definition/loader binding 完整、入口 class 具备 traversal eligibility 时，入口才能作为 exact/proven 路径根；`possible` 根只能形成 `uncertain`。这里的 `proven` 只确认入口在目标 profile 中已启用/注册且静态可被外部事件调用，不确认生产流量已经调用它；后者仍是第 9 节运行时验证边界。某类入口 discovery coverage 不完整时，已经证明且不受该缺口破坏的正向路径仍保留，但针对依赖该入口机制的负向闭包不能输出完整静态未命中。`test_or_tooling` 默认不属于生产业务根，只有运行 profile 明确包含时才启用，避免测试代码把正式影响范围扩大。

### 6.10 CoverageLedger

至少记录：

- 两侧 runtime-path candidate class entry 的 inventoried / fully-parsed / explicitly-deferred / failed 数，以及 effective class 子集的 parsed/failed 数；`explicitly_deferred` 只允许用于已证明不参与当前 base compact 对账的 scope，current 正式路径图不得用它跳过 class；
- 声明 method/field 数；
- raw 与 effective-traversal-eligible direct/type/dispatch/class-init/linkage/bootstrap/inline edge 数，按 opcode、kind、artifact/provider/loader realm 和 certainty 分组；class-provider、class-definition、caller eligibility、member-resolution、DispatchResolution 和 dispatch edge 结果必须分别守恒；
- dynamic callsite/constant 的 total、recognized、unknown、failed 数，以及 lambda binding 与 SAM invocation 的绑定状态；
- provider resolved/equivalent_code_only/runtime_equivalent/ambiguous/missing/unresolved 数；
- class definition 的 definition-ready/runtime-equivalent/各精确失败/ambiguous/unsupported 数，以及每个 resolved/runtime-equivalent provider binding 的一对一覆盖；
- loader realm、module layer/readability、classpath/module-path slot、parent delegation、initiating module/resolution-context binding 和 base/current provider-binding delta 的 complete/ambiguous/failed 数；
- initiating-resolution-context/class-owner/symbolic-member/resource-key 四类 reconciliation universe 的 total/discovered/failed 数，context→key 适用关系的 total/resolved/ambiguous/failed 数，以及各自 identity/digest/coverage；
- source alias exact/ambiguous/unmapped/generated/conflict 数；
- business entrypoint/root edge 的 proven/possible/inactive/unresolved 数，按 mechanism 与 runtime profile 分组；
- JAR effective entry 的 total/compared/failed 数，以及 packaging-noise/payload-changed 数；
- classfile 已识别属性、安全白名单属性、未知属性和 verifier 失败数；
- 已识别 generated class/member 数及其 compared/changed/failed 数；`generated` 只能作为 provenance 标签，不能从 class 比较分母扣除；
- base/current BuildEnvironment/BuildInputManifest/ArtifactBuildProvenance identity 的 complete/equal/different/unknown 数，以及 environment-change/nondeterministic-output attribution 的 proven/suspected/rejected 数；
- FactBuildInputSlice 的 complete/partial/failed 及 equal/different/unknown 数；任何使用 environment/nondeterminism suspected/proven-noise 的 fact 都必须能反查完整且相同的全局 input manifest 或 fact slice；
- changed resource entry 的 runtime-semantic/runtime-topology/operational-security/runtime-native/build-metadata/distribution-metadata/mixed/unknown 主分类数，以及每个 mixed entry 的全部 child fact；每个 changed physical entry 必须恰有一个主分类，不能因 parser 不支持而从分母删除；
- artifact diff 被提升、排除和保持 candidate 的事实数，以及实际使用的容器/classfile/resource 规范化策略版本；
- 每个 analysis context 的 active decision/assessment/formal-projection/candidate-plan+projection snapshot identity、成员数、target/obligation/projection 数、成员 digest 与 supersession 链；四层成员必须按第 7.1 节外键关系守恒，禁止查询时临时选择 `latest` 行；
- parser fallback、截断、edge cap、缓存失效和稳定失败原因；
- runtime transformer/agent/plugin profile 的 detected/modeled/unmodeled 数及受影响 loader/class scope；
- compile-time constant/inline target 的 proven/possible/unavailable consumer binding 与 coverage；
- 每个失败影响的 artifact、class、API 或 path 范围。

基本守恒式：

```text
runtime_candidate_class_entry_count
  = fully_parsed_class_entry_count
  + explicitly_deferred_class_entry_count
  + explicit_failed_class_entry_count
effective_class_count
  = effective_parsed_class_count + effective_failed_class_count
effective_entry_count = compared_entry_count + explicit_failed_entry_count
changed_resource_entry_count
  = runtime_semantic_resource_entry_count
  + runtime_topology_resource_entry_count
  + operational_security_resource_entry_count
  + runtime_native_resource_entry_count
  + build_metadata_resource_entry_count
  + distribution_metadata_resource_entry_count
  + mixed_resource_entry_count
  + unknown_resource_entry_count
```

上式必须分别在 base/current 和 runtime profile/loader realm scope 内成立；不能用“已解析了 non-effective class”抵消某个 effective class 的失败。任何静默跳过均视为验证失败。

除上述总量守恒外，每个 `resolved|runtime_equivalent` provider binding 必须恰有一条 ClassDefinitionResolution，其他 provider 状态不得伪造 definition-ready；每个适用 virtual/interface direct edge 必须恰有一个 `DispatchResolution`，各非空 resolution 的 implementation target 数与 dispatch edge 数必须一致。`partial_possible_set` 的 target 数必须大于 0 且 coverage=partial；`unresolved/no_concrete_implementation` 的 target/edge 数必须为 0，前者 coverage=partial|failed，后者 coverage=complete。edge certainty 还满足 `exact + proven_receiver + possible + ambiguous = materialized_dispatch_edge_count`；member resolution 满足 `resolved + runtime_equivalent + no_class_definition + class_definition_failed + no_such_member + illegal_access + incompatible_class_change + ambiguous + unsupported = applicable_symbolic_member_resolution_count`。`possible/ambiguous` dispatch 只能贡献诊断或正式 `uncertain`，不得混入 exact reachable 计数；`no_concrete_implementation/unresolved` 均不物化猜测 implementation path，前者只在完整闭包内确认 implementation 集为空，后者表示没有任何可安全物化 target。二者都不能单独生成 `incompatible_if_executed`；该结论必须来自独立的 linkage/invocation-selection 事实。

### 6.11 分层缓存与失效

“事实库”不是一个只由 JAR SHA 决定的单体缓存。即使物理表保存在同一 SQLite，也必须使用独立 namespace/version 和以下分层 identity：

| 层 | 必须进入 identity 的输入 | 允许复用的边界 |
|---|---|---|
| binary blob | content SHA、archive scanner、classfile parser/helper identity、raw binary fact schema | 只复用该字节内容的全部 physical/MR entry、class/member/raw edge/attribute inventory；不缓存 target-JDK selection、环境归因或 scope-specific 排除 |
| effective runtime graph | RuntimeProfileIdentity、有序 ArtifactInstance、outer/container entry、loader realm/delegation、classpath/module-path、raw inventory/reference/registration、target-independent source/resource-consumer/entrypoint/semantic discovery digest/coverage 与 resolution-origin seed 构成的 pre-resolution discovery snapshot、provider/class-definition/member-resolution/dispatch/discovery policy、fixed-point/resolution schema | 复用 combined fixed-point 输出的 final reconciliation snapshot、consumer/entrypoint/semantic discovery closure、class provider、class definition、symbolic member resolution 和 dispatch 绑定；final universe/适用关系 digest 是本层输出而不是自身缓存输入。profile、platform/module/security model、realm、discovery seed/candidate、顺序或规则变化必须重算 |
| source overlay | physical binary member-inventory identity（不含 provider/trace 结果）、repo、fixed commit 或 source-state hash、module/source 清单、source parser/mapping version | 只复用 alias 和源码展示事实；runtime profile/provider 改变不应迫使相同 physical member 重做源码映射，但该 alias 在新 effective graph 中的可用性必须重新绑定 |
| inline consumption | base/current business binary identities、source overlay identity、old/current inline target facts、compiler/language verifier 与 policy version | 只复用 proven/possible inline binding 与 coverage；任一 consumer/target/source/verifier 变化必须重算 |
| business entrypoints | binary graph identity、RuntimeProfileIdentity、manifest/module/resource snapshot、entrypoint adapter/activation policy | 只复用 entrypoint/RootEdge 与 mechanism coverage；profile 或 activation evidence 变化必须重算 |
| semantic overlay | binary graph identity、artifact/resource/config snapshot、adapter/version/config、activation-policy version | 只复用该机制的 semantic facts 与 coverage |
| cross-version pairing | base/current 完整 ArtifactInstance inventory、resolved dependency lineage、runtime-scope correspondence、显式 mapping、pairing policy/schema | 只复用 exact/base-only/current-only/ambiguous 配对；任一 inventory、scope mapping 或 policy 变化必须重算 |
| artifact-local diff | base/current raw content identity（各侧为 parser-independent `artifact_content_identity` 或显式 `ABSENT` sentinel）、entry-alignment schema、archive scanner/parser identity、容器/classfile/resource raw-normalization policy、Step4 physical-diff schema | 只复用内容对的 raw/结构化规范化差异模板；不包含 target-JDK/MR selection、ArtifactInstance/runtime pairing、BuildEnvironment 归因或 AnalysisScope 排除。模板必须经当前 pairing attachment 后才能参与 decision |
| environment/build-variation attribution | artifact-local diff identity、base/current BuildEnvironmentIdentity、BuildInputManifestIdentity、ArtifactBuildProvenance identity、FactBuildInputSlice identity/coverage、determinism-control/attestation identity、environment/nondeterminism candidate 与 equivalence verifier version | 只复用 proven-noise/suspected/rejected 归因证据；不能单独创建 runtime decision |
| scope audit classification | RuntimeComparisonIdentity、AnalysisScopeIdentity、raw/规范化 delta identity、target-independent consumer-discovery closure、audit/exclusion policy | 只复用 packaging/classfile/build/distribution/resource-encoding 等 audit-only scope exclusion；不得当作 active excluded decision cache |
| provider topology diff | base/current effective runtime graph identity、initiating-context/key universe 及适用关系 digest、loader/module/classpath snapshots、resolution policy、provider-delta schema | 只复用 base/current provider binding delta；任一侧 realm、universe/适用关系、顺序或 policy 变化必须重算 |
| runtime-effective decision | RuntimeComparisonIdentity、AnalysisScopeIdentity、artifact-local fact digest、该原子 fact 的 base/current decision-relevant provider/class-definition/member/resource-selection closure、class-definition/member-resolution/selection policy、environment/equivalence evidence、decision schema | 只复用该 profile-pair + analysis-scope + fact evidence closure 的 authoritative/candidate/excluded 裁决；单侧 profile、不同 analysis scope、无关全图 digest 变化或物理 diff 命中不能冒充 effective decision 命中 |
| projection assessment | authoritative change-fact identity、final reconciliation/provider-topology/resource-selection digest、projection planning registry/rule-contract/applicability policy、applicable target-scope 与 target-discovery evidence digest | 只复用 target/obligation set 与 targetable-complete/targetable-partial/unsupported 评估；planning 能力变化只 supersede assessment，不改写 runtime-effective decision |
| change projection | active projection-assessment identity、projection-obligation key、projection implementation/schema version | 只复用本次 obligation 的变化目标投影；`change_events` 不属于 immutable binary core |
| candidate diagnostic plan/projection | candidate decision identity、diagnostic planning registry/rule-contract/applicability policy、applicable target scope/target-discovery evidence、canonical bound-target/obligation/coverage/unbound-scope payload；projection 另加 plan identity、obligation key 与 implementation/schema version | 复用候选诊断 target plan 及其 projection；零/部分 target 也有 plan 记账，planning/implementation 能力分别 supersede plan 或 projection，不改写 candidate decision |
| projection trace | formal/candidate projection identity、graph/source/inline/entrypoint/semantic identities、遍历/certainty/SCC/path-canonicalization 策略、path budget、trace-result schema | 只复用同一原子 target 的路径结果；不因无关 active projection 集变化而重跑 |
| report/aggregation | 每个 analysis context 的四层 active snapshot identity、引用的 trace-result set digest、reported-API grouping/primary/聚合策略、output budget 和 result schema | 只复用同一 active generation 的聚合/报告；禁止从数据库当前行临时拼接新旧 snapshot |

源码、配置或 Step4 目标变化时，binary blob fragment 可以继续复用，但受影响的 discovery/overlay、authoritative assessment/candidate plan、projection 和结果必须按分层 identity 重建。缓存损坏、identity 字段缺失或版本未知时失败关闭并重建，不能把“binary fragment 命中”报告成“完整事实库命中”。

### 6.12 BuildEnvironmentIdentity、BuildInputManifestIdentity 与 ArtifactBuildProvenance

`BuildEnvironmentIdentity`、`BuildInputManifestIdentity` 和 `ArtifactBuildProvenance` 是三个独立、版本化的事实对象，不能互相代填。前者只描述执行环境/工具链，不包含 source revision，否则 base/current 正常源码变化会被误判成“环境不同”：

```text
build_environment_schema_version
jdk_vendor/version
compiler_family/version
build_tool/wrapper-distribution/plugin executable identities
processor/generator/enhancer executable identities
locale/timezone/encoding/os/arch
ambient_environment_variable_digest（不含已声明的语义构建输入）
available clock/SOURCE_DATE_EPOCH/random-seed/filesystem-order/parallelism controls
field_coverage
build_environment_identity_digest
```

实际构建输入另建：

```text
build_input_schema_version
source content manifest identity
resource content manifest identity
source/target/release/compiler_flags
build files/profiles/declared task identity
processor/generator/enhancer config/input digests（含 ERM/Schema/IDL 等外部输入）
ordered_compile_classpath_digest
resolved dependency/plugin payload snapshot identity
declared VCS/environment/property/path semantic-input digest
field_coverage
build_input_manifest_identity_digest
```

最后由 provenance 绑定制品、输入与一次构建/接收事件：

```text
artifact_build_provenance_schema_version
artifact_content_identity_or_outer_artifact_content_identity（parser-independent）
input_mode = checkout_build | provided_artifact
artifact_available
build_executed_by_system
build_execution_status = succeeded | failed | not_executed | unknown
source_revision_or_state_identity（provenance；不单独作为语义输入）
build_environment_identity（可缺失但必须记 coverage）
build_input_manifest_identity（可缺失但必须记 coverage）
build_command/task identity
actual clock/SOURCE_DATE_EPOCH/random-seed/order/parallelism controls
daemon/incremental-compilation state identity
build_cache_policy/status/key/attestation identity
output_cleanliness_status
external_reproducibility_attestation identity
field_coverage
artifact_build_provenance_identity_digest
```

固定 commit 是制品来源证据，不是必然会被编译器消费的语义输入，因此只放入 ArtifactBuildProvenance。若构建脚本会把 commit/tag/dirty state 写入 Manifest、字段、注解或生成代码，被实际读取的 VCS 值还必须进入 `declared VCS/... semantic-input digest`；此时它是明确输入，不得被当作仅 provenance 差异。同理，被 build/generator 读取的环境变量值属于 BuildInputManifestIdentity；BuildEnvironmentIdentity 中只保留宿主/工具执行环境及未声明 ambient 事实，禁止同一字段在两个 identity 中以不同值重复归类。

为了在全局 BuildInputManifestIdentity 因无关源码变化而不同时，仍能安全判断某个具体差异是否具备 same-input 前提，可另建版本化 `FactBuildInputSlice` 证据：

```text
artifact_local_fact_identity
fact_scope = member | class | resource
base/current build_input_manifest_identity
source/resource content dependency closure
compiler flags/build profile/task closure
ordered compile-classpath payload/member dependency closure
processor/generator/enhancer config and external-input closure
declared VCS/environment/property/path input closure
slice_construction_policy/support_manifest_identity
slice_coverage_status = complete | partial | failed
base_fact_build_input_slice_digest
current_fact_build_input_slice_digest
fact_build_input_slice_comparison = equal | different | unknown
```

`equal` 只能在保守影响闭包完整、两侧全部适用输入相同时写出。不能因某个源文件未变就猜测 classpath、processor、generator、plugin、外部 Schema 或构建配置不会影响该 fact；无法构建完整切片时必须为 `unknown`。processor/generator/weaver/obfuscator 若可扫描全部 source/classpath、产生全局 registry 或受于未建模顺序，必须把整个适用输入域纳入切片；只有对应 plugin support manifest 与独立 fixture 证明局部性时才能缩小。该证据只放宽“全局 manifest 不同但差异作用域输入已证明相同”的安全场景，不能证明输出语义等价；后者仍需第 7.3.2 节独立 verifier。

`artifact_local_fact_identity` 必须是环境归因之前已冻结的 raw/规范化 observed fact identity；FactBuildInputSlice 只能作为后续 attribution/decision evidence，不得反向进入该 fact identity，否则会形成“先知道是噪声才定义差异”的循环身份。

三者只用于构建可复现性与 build-variation 归因，不得替代第 6.0 节 `RuntimeProfileIdentity`。`build_environment_comparison_status` 只比较 BuildEnvironmentIdentity；源码/资源内容、构建参数、generator 输入或 compile classpath 的差异只进入 `build_input_comparison_status`，不得污染“环境是否相同”。source revision 本身只是 provenance；只有它被构建实际读取时，对应值才作为明确语义输入参与 `build_input_comparison_status`。例如 build host 为 macOS/JDK 21 不能证明目标 runtime 也是该 OS/JVM；反过来，目标 runtime profile 变化也不能被自动解释为编译噪声。

`checkout_build` 必须在新 detached worktree 中建立 clean-output invariant：构建前目标输出目录不存在或已在该临时 worktree 内安全清空，仓库若跟踪 `target/build` 输出则必须显式阻断或纳入 BuildInputManifestIdentity；Gradle/Maven 远程或本地 build cache 的启用、命中和 identity 必须记录在 ArtifactBuildProvenance。checkout-build 默认在首次且唯一一次正式构建中禁用未受信 build cache；只有工具可验证的完整 input key/attestation 覆盖固定 revision/content manifest、toolchain、processor/generator、配置和有序 compile-classpath payload 时才允许 cache hit。compiler daemon、incremental compilation 或共享 worker 的可变状态按同类未受信缓存处理：必须每侧隔离/禁用，或有完整 state identity 与 input attestation。项目无法隔离或禁用这些未受信状态、且不能提供上述证据时在 Step1 阻断。无法证明输出干净时，不得声称产物只对应固定 revision，也不得留给 Step4 猜测。

`provided_artifact` 的最终字节仍是运行时事实权威，且 `build_executed_by_system=false`；缺少 build provenance 时不能声称它由某个源码 revision、输入 manifest 或环境唯一产生，也不能使用 environment/nondeterminism noise 排除规则。此时 source overlay 只记录 mapping/conflict，build input/environment comparison 与归因保持 unknown。

### 6.13 生产 classfile 解析器合同

生产 binary core 首版使用版本锁定的 ASM 提取器（独立 Java helper）读取 classfile，并以“4-byte big-endian 长度 + UTF-8 JSON payload”的版本化 frame 协议通过 stdout 向 Python 主流程流式输出 raw facts。首帧必须是 schema/parser/helper identity，随后按 ArtifactInstance/class 输出事实帧，尾帧包含 record count、输入/输出 digest 和 coverage totals；stdout 出现非 frame 字节、缺少尾帧、长度越界、digest/count 不守恒或 helper 非零退出都视为 scoped parse failure，日志只能写 stderr 并单独留存。ASM 版本、支持的 classfile major、visitor policy、helper SHA 和输出 schema 都进入 parser identity。

当前 `javap` 文本摘要和 Python 手写 parser 可以用于迁移期 shadow、fallback 诊断或独立交叉验证，但不得作为切换 binary 权威后的唯一生产解析依据。任何高于 support manifest、ASM 不支持或 helper 输出不完整的 class 必须形成 scoped parse failure；禁止静默改用低保真文本结果后继续输出闭集结论。解析失败传播必须绑定 runtime selection：已证明对当前 profile non-effective 的 MR/class entry 失败不污染无关 effective graph，但仍使 raw-artifact comparison/包含 raw classfile 可观察性的 AnalysisScope 不完整，且不能被其他 profile 复用为成功。target JDK/selection 未知时也不得声称该失败 non-effective。解析器只负责无损提取，噪声规范化和变化裁决由独立、版本化 policy 完成，不能把两者合成不可审计的黑盒。

ASM visitor “没有回调”不能被解释成“该 attribute 不存在”。helper 必须通过受限 raw classfile attribute inventory 或等价的通用 Attribute capture，逐 class 列出 class/field/method/code/record/module 各层 attribute name、length 和 digest，再与 support manifest 的 recognized/safe/unknown 集合守恒对账。任何未列入 inventory、同名重复语义未定义或 visitor 静默跳过的 attribute 都使相应 comparison scope incomplete；不得仅因 ASM 没暴露字段就输出 normalized equal。

helper 只读取 Step1 SHA 绑定的字节，不得加载、验证执行或初始化被分析 class。归档解压上限、单 class/frame 大小、总记录数、进程超时和内存上限必须来自版本化 artifact-safety policy；超限形成明确 artifact/class failure，不能崩溃后返回部分成功。

## 7. Step4 变化事实设计

### 7.1 原始制品差异不是代码变化结论

old/current JAR SHA-256 不同只确认“发布制品字节不同”，用于 provenance、缓存失效和审计，不能直接生成 API 变化、`BEHAVIOR_CHANGED` 或 Step5 目标。

Step4 必须逐层产生结构化差异事实，而不是一个布尔 `jar_changed`：

```text
artifact_content_changed
container_diff_status
class_diff_status
resource_diff_status
comparison_coverage_status
runtime_effective_diff_summary
build_environment_comparison_status
build_input_comparison_status
environment_attribution_status
build_variation_kind
analysis_eligibility_summary
analysis_projection_summary
projection_coverage_summary
normalization_policy_version
promotion_status
```

建议的正式状态：

- `container_diff_status = identical | packaging_noise_only | runtime_observable_metadata_changed | payload_changed | incomplete`
- `class_diff_status = none | classfile_noise_only | runtime_diagnostic_metadata_changed | contract_changed | implementation_changed | runtime_metadata_changed | mixed | incomplete`
- `resource_diff_status = none | build_metadata_only | distribution_metadata_only | operational_security_changed | runtime_native_changed | runtime_semantic_changed | runtime_topology_changed | mixed | unknown`
- `comparison_coverage_status = complete | partial | failed`
- `runtime_effective_diff_summary = unchanged | changed | changed_with_unknown | unknown`
- `build_environment_comparison_status = equal | different | unknown`
- `build_input_comparison_status = equal | different | unknown`
- `environment_attribution_status = not_applicable | proven_noise | suspected | rejected`
- `build_variation_kind = none | environment_change | nondeterministic_build_output | unknown`
- `analysis_eligibility_summary = none | authoritative_only | diagnostic_only | excluded_decision_only | audit_only | mixed`
- `analysis_projection_summary = none | targetable_only | unsupported_only | mixed`
- `projection_coverage_summary = none | complete_only | partial_only | unsupported_only | mixed`
- `promotion_status = audit_only | excluded | api_change | resource_semantic_change | runtime_topology_change | operational_security_change | runtime_native_change | confirmed_unprojectable | mixed | candidate`

`build_environment_comparison_status=equal` 只允许两侧 BuildEnvironmentIdentity 的全部适用字段覆盖完整且相等；`build_input_comparison_status=equal` 同理只比较 BuildInputManifestIdentity。任一适用字段缺失时对应状态必须为 unknown，不得按已知字段相等猜成 equal；source revision 不同或 BuildInputManifest 不同都不得反向把 environment 写成 different，source revision 本身也不得改写 input comparison。

同一个 JAR 可以同时包含多类事实。上述 `*_summary` 和 `promotion_status` 只做 artifact-level 摘要，不能作为单条 fact 的裁决字段：`changed` 只允许在至少一个 effective fact 已确认且其余适用 scope 均已完成时使用；同时存在已确认变化和 unresolved scope 时必须使用 `changed_with_unknown`。`unchanged` 只允许在相关 scope 全部比较、runtime selection 和等价验证完整时使用。任何 `mixed` 都必须能由明细重算，不能覆盖 `partial/failed` coverage。

confirmed 变化账本保存 `analysis_eligibility=authoritative` 的 runtime-effective facts，其中只有 targetable 子集生成正式影响目标；尚未满足 authoritative 或 excluded 证据条件的候选，包括编译环境/非确定构建疑似噪声、runtime selection 不确定和未知 resource/attribute，单独保存到 `diagnostic_candidate_facts[]`；被排除的差异保存到 `excluded_diff_evidence[]`，但每条 evidence 必须明确 `exclusion_owner_kind=runtime_decision | audit_only`。前者引用 excluded decision 并计入三通道，后者只引用 raw/audit delta 和 scope-exclusion 证据，不伪造 decision。candidate、两类 exclusion evidence 都不得进入正式 Step5 目标、`alerts.csv`、影响计数或 Step6，但每个具有可绑定运行时目标的 candidate 必须进入独立诊断触达分析，不能隐藏或丢弃。candidate 会阻止在自身 scope 上声称完整无变化。每个 fact 必须携带自己的 comparison/runtime scope 和 coverage：某个 exact member/resource 的正向变化可以在该 scope 比较完整时独立确认，不能被无关 scope 的失败删除；但要排除某个 scope 或输出完整无变化，相关 scope 必须全部覆盖完整。

三条通道在同一 `active decision snapshot + disposition_obligation_identity` 上必须互斥：

| 通道 | fact 状态 | 后续处理 |
|---|---|---|
| authoritative | `change_fact_status=confirmed` | 不改写变化 decision；通过独立 active `AuthoritativeProjectionAssessment` 按 `analysis_projection_status=targetable\|unsupported` 与 projection coverage 分流，targetable 生成正式 target，部分覆盖另记 unprojected scope，unsupported 进入 confirmed-unprojectable report |
| diagnostic | `candidate_fact_status=candidate\|incomplete` | 只进入 candidate trace/report 和诊断计数 |
| excluded | `exclusion_status=excluded` | 只保存 exclusion evidence；原因明确区分安全等价、超出当前运行 profile 和 non-effective，不把所有排除项统称为“噪声” |

该互斥/完备性约束针对“已经进入当前 analysis context 裁决域的 runtime decision”，不要求把每条 raw ZIP/classfile/build provenance 都伪造成 active decision。所有物理/runtime-profile/topology 差异先形成 scope-independent `observed_delta_identity`，再与 `analysis_context_identity` 组成 `disposition_obligation_identity` 进入 immutable disposition ledger：若能映射到当前 AnalysisScope 内的 runtime/可观察 fact，必须恰好进入上述一条 decision 通道；若已证明只落在 AnalysisScope 外且没有可信 in-scope consumer，则只生成 `audit_only_record + exclusion_owner_kind=audit_only + audit_status=scope_excluded`，保留 obligation identity，但不生成 `decision_identity/exclusion_status`，也不计入 `active_runtime_decision_total/excluded_decision_count`。每个 disposition obligation 必须恰有一个 active decision 或一个 audit-only record，不能两者皆有或两者皆无。audit record 可以被 excluded/authoritative/candidate decision 作为上游 evidence 引用，但不能替代其通道状态；同一 observed delta 在两个 AnalysisScope 下共享 observed identity、使用不同 obligation identity，同一 raw delta 在不同 loader/mechanism fact scope 则先派生不同 observed identity。

仅 BuildEnvironment/BuildInput/Provenance 改变而没有 artifact-local 或 runtime-profile/topology observed delta 时，只进入独立 build-audit ledger，不进入上述 disposition 分母；否则会用“构建环境变了”伪造运行时变化 obligation。

`analysis_projection_status` 只属于 authoritative fact 的版本化 active `AuthoritativeProjectionAssessment`，不是 immutable change decision 的内在字段。正式枚举只有 `targetable | unsupported`，并必须配套 `projection_coverage_status=complete | partial | unsupported`。`targetable` 表示 assessment 已绑定至少一个 exact analysis-target identity，并已为每个 `(target identity, projection rule contract identity, required edge family)` 建立 canonical projection-obligation key；紧随其后的兼容 formal-projection snapshot 必须为 obligation set 中每一项恰好物化一个 projection，其 coverage 可 complete 或 partial。`unsupported` 表示 target/obligation set 都为空，并要求 projection 数为 0 且 coverage=unsupported。assessment 的 target-set/obligation-set digest 不引用下游 projection identity，避免身份循环。targetable+partial 必须列出尚未发现/绑定的 mechanism/consumer/target scope，不能因已有一个 target 就伪装全覆盖；所有已知 obligation 仍须完整物化并保留正式 trace，但总体完整性被阻止。candidate/excluded 不建立该 assessment；纯构建、安全或运维审计使用独立 audit schema，也不得用 `not_applicable` 混入 authoritative runtime fact。

身份必须分为“观测 → 变化裁决 → 投影能力评估”三层：

```text
observed_delta_identity = delta_source_kind + comparison/runtime/fact/mechanism scope
                        + base/current observed fingerprints
disposition_obligation_identity
                        = observed_delta_identity + analysis_context_identity
decision_identity       = disposition_obligation_identity
                        + decision-relevant effective-runtime-view digest
                        + decision-relevant evidence-set digest
                        + canonical decision outcome/reason/coverage digest
                        + decision-policy/schema version
projection_assessment_identity
                        = change_fact_identity + final_reconciliation_snapshot_identity
                        + projection_planning_registry_identity
                        + applicable-target-scope/target-discovery evidence digest
                        + canonical target-set/projection-obligation-set
                          /status/coverage/partial-scope digest
                        + projection-assessment-policy/schema version
```

两个 `decision-relevant` digest 都必须按该原子 decision scope 构造，只包含裁决此 fact 所必需的 base/current binding、selection 与 evidence closure，不能用包含全部 target-discovery/unrelated owner 的全局图 digest 代填。`evidence-set digest` 只能包含 decision 生成前已经冻结的 artifact-local、environment/equivalence、provider/class-definition/member/resource-selection 和 coverage 证据。二者都不得包含 decision/change-fact 自身、projection capability、assessment、projection、trace 或 report identity；否则会形成自引用，或让无关图扩展、下游能力升级反向制造新的变化裁决。若新 reconciliation 结果改变该 fact 的 provider/effectiveness 证据，则生成 superseding decision；若只扩大下游 target discovery 而 decision-relevant closure 未变，则只更新 assessment/projection snapshot。

assessment 至少保存 `change_fact_identity`、适用 target/mechanism 分母、已绑定 target-set digest、canonical projection-obligation keys/digest/count、未投影 scopes、`analysis_projection_status`、`projection_coverage_status`、evidence/policy identity 和 supersession 关系。每个 active authoritative change fact 在 active projection-assessment snapshot 中必须恰有一个 active assessment；升级 projection registry、target discovery 或绑定证据时，只新建/supersede assessment 及下游 projection/trace，不得原地改写“runtime fact 已确认变化”的 decision。

`projection_planning_registry_identity` 指决定 rule contract/applicability 与 obligation 分母的 planning registry，故意只进入 assessment，不得又被塞入产生 `decision_identity` 的能力 digest；projection implementation/schema version 只进入具体 projection。若同一个实现模块既负责 runtime-fact 提取/裁决，又负责 target projection，必须暴露 fact、projection-planning、projection-implementation 三类可独立失效的 identity：第一类变化可以生成新 decision，第二类生成新 assessment/plan，第三类只生成新 projection/trace。不能用一个粗粒度“semantic capability version”让纯投影升级伪装成变化事实证据已变。

active runtime decision 的 `delta_source_kind` 至少区分 `artifact_local | runtime_profile | provider_topology | class_definition | resource_selection`；因此即使两侧 artifact payload 相同，runtime profile、classpath/loader、class-definition outcome 或 resource selection 变化仍有独立 identity，不依赖伪造 raw JAR diff。`build_environment` 不是运行时 delta source：它只能作为已存在 artifact-local delta 的归因/等价证据；两侧构建环境不同但最终 effective 制品事实相同时，只产生独立 build audit，不得创建 runtime candidate/decision。

`fact/mechanism scope` 至少绑定 exact class/member/resource/provider fact、loader/resource-selection scope 和适用 consumer mechanism。同一 raw entry delta 若在两个 loader realm 或两种资源消费机制中的 effectiveness 不同，必须派生两个独立 observed-delta scope；反之，一个 ordered-all resource set 或 provider binding 由多个 raw entry 共同决定时，以该规范化 effective-set fingerprint 作为一个原子 observed delta，并保留全部 contributing raw-delta identities。不能用单个 raw ZIP entry identity 同时覆盖多个互相矛盾的 effective 裁决。AnalysisScope 不进入 observed identity，只通过 disposition obligation 隔离，避免相同事实因分析范围不同被伪造成制品本身不同。

同一 active decision snapshot 中，一个 `disposition_obligation_identity` 恰好只能有一个 active decision，且只能进入 authoritative、diagnostic 或 excluded 其中一条通道。candidate 出现在正式 `by_api`、excluded fact 生成 trace target，或同一 active decision 同时出现在多条通道都属于合同失败。证据或策略更新时必须追加新的 immutable decision 并以 `supersedes_decision_identity` 关联旧记录；旧 candidate trace 只能标记 superseded、从当前视图排除，不能物理删除或改写历史证据。`change_fact_status` 是 authoritative 正式/未投影事实字段；candidate/excluded 使用各自 schema，不能为了复用一个枚举重新制造跨通道非法组合。

active 集合必须用四层独立快照原子冻结，禁止由查询时的 `is_active` 布尔值临时拼装：

```text
active_decision_snapshot_identity
  = analysis_context_identity + ordered active decision identities + snapshot schema
active_projection_assessment_snapshot_identity
  = active_decision_snapshot_identity + ordered active assessment identities + snapshot schema
active_formal_projection_snapshot_identity
  = active_projection_assessment_snapshot_identity + ordered active formal projection identities + snapshot schema
active_candidate_projection_snapshot_identity
  = active_decision_snapshot_identity
  + ordered active candidate diagnostic-plan identities
  + ordered active candidate projection identities + snapshot schema
result_generation_identity
  = run-input manifest identity + engine mode
  + canonical active_snapshot_sets[] + graph/overlay identity sets
  + active audit/exclusion/incompleteness record-set identities
  + trace-result set/trace-policy identities
  + report/aggregation/output policy and schema identities
```

每层必须保存完整成员清单、canonical order、digest、上一代 snapshot 和 supersession 原因；某层没有成员时也必须保存 canonical empty-list snapshot，不能用“缺失 snapshot”代表空集。纯 projection implementation/schema 变化可以保持 assessment identity 不变，但必须产生新的 formal-projection snapshot；diagnostic target discovery/planning-contract 变化更新 candidate plan，纯 diagnostic projection implementation/schema 变化只更新其 projections，二者都只产生新的 candidate-projection snapshot，其中 plan 负责保存零/部分 target 的 discovery coverage。任何 trace/report generation 必须绑定一组彼此兼容的四层 snapshot identity，不能把新 assessment、旧 projection 或旧 candidate trace 混入同一 active view。`result_generation_identity` 不包含 staging/临时绝对路径；每个已发布 SQLite active view/summary/by_api/alerts/Step6 报告必须声明该 identity，generation manifest 还必须按 content identity 引用本代使用的低层 sidecar。可复用 sidecar 的核心内容不得反向包含 result-generation identity；需要独立分发时由不可变 publication envelope 绑定，避免报告变化使 Step4/graph 缓存失效。完整校验后才可原子发布。

decision scope 必须细化到一个可独立裁决的 class/member/resource/provider-selection fact。artifact/class 摘要可以引用多个 child decisions，但不能作为另一个互斥 decision 覆盖它们；否则同一 JAR 中“一个方法 confirmed、另一个 attribute unknown”的情况无法同时表达，也无法满足后续计数守恒。

`decision_identity` 是三通道共用的裁决身份。只当该 decision 进入 authoritative 通道时才派生一个且仅一个 `change_fact_identity = hash(decision_identity + canonical authoritative-fact payload digest + authoritative_fact_schema_version)`；payload 至少包含 exact fact kind、base/current effective fingerprints、scope 与 change reason。candidate/excluded 不得伪造 change-fact ID。因 decision scope 已是原子 fact，一个 authoritative decision 派生多个 change fact、或多个 active decision 共享同一 change-fact ID 都是守恒失败。decision/assessment/change-fact identity 对应的 canonical payload 必须落库并在读取时重算；同一 identity 出现两个 payload 视为数据库损坏，不允许按最后写入覆盖。

active assessment 中的 `analysis_projection_status=unsupported` 不表示变化不确定：运行时事实仍为 confirmed，只是当前没有任何可信 target/consumer/edge 模型。它不得进入正式 API 影响计数，也不得降级成 candidate 或伪造 `not_analyzed` API；必须进入独立 confirmed-unprojectable 清单，并阻止在相应 scope 声称“影响分析已完整”。若已经存在至少一个可信 target 但其余适用 target 发现/机制 coverage 不完整，必须使用 `targetable + projection_coverage_status=partial`，保留已有 projection 并写入 partial-projection/incompleteness report，不能错误改成 unsupported 或 complete。

#### 7.1.1 物理制品差异到 runtime-effective 事实的裁决

artifact-local 规范化差异只是中间证据。最终三通道裁决必须按以下顺序执行，禁止跳步：

1. **完整比较**：按第 6.2.1 节建立 `exact | base_only | current_only | ambiguous` pairing；只有前三类可产生具有完整证据的 class/member/resource artifact-local `changed | equivalent`，`ambiguous` 及任一比较失败只能得到 `unknown`。raw SHA 只用于进入这一层。
2. **安全等价与环境归因**：命中版本化安全等价 verifier 才能排除；严格环境疑似但未证明等价时保持 candidate。
3. **运行时选择与定义**：在对应 base/current loader realm 中比较实际 class provider、ClassDefinitionResolution、symbolic member resolution、MR variant 和 resource/native selection；provider 被选中不等于 class 可定义，资源也可能采用 first、ordered-all 或 mechanism-specific 聚合，不能套用 class first-wins。
4. **effective fact 对账**：对实际生效的 class/member/resource/provider 事实计算 base/current fingerprint；只有该 fingerprint 已确认改变，才形成 authoritative runtime fact。
5. **目标投影评估**：为 authoritative fact 按第 7.9 节新建 active AuthoritativeProjectionAssessment，分为 targetable/unsupported；assessment 及其 supersession 不反向改变前四步的变化裁决。

每个 artifact-local fact 至少保存：

```text
artifact_local_diff_status          = changed | equivalent | unknown
base_selection_mechanism            = class_provider | first_resource | ordered_resources
                                    | mechanism_specific | native_selector | unknown
current_selection_mechanism         = class_provider | first_resource | ordered_resources
                                    | mechanism_specific | native_selector | unknown
base_runtime_selection_status       = selected_one | selected_many | not_selected
                                    | absent | ambiguous | unsupported
current_runtime_selection_status    = selected_one | selected_many | not_selected
                                    | absent | ambiguous | unsupported
base_effective_fact_identities
base_effective_fact_set_digest
current_effective_fact_identities
current_effective_fact_set_digest
effective_fact_diff_status          = changed | unchanged | unknown
runtime_selection_policy_version
```

两侧 selection 必须分字段保存，禁止压成一个 `runtime_selection_status`：否则 `base selected -> current absent`、`base absent -> current selected`、provider 切换与两侧均被遮蔽无法区分。`selected_many` 的有序 identity 列表和 digest 都必须保存，不得用无序 set 消除 SPI/`getResources`/配置合并顺序变化。`absent` 只能在该侧完整 inventory/loader/resource policy 中确认不存在时使用；闭包不完整必须是 `unsupported/ambiguous`，不能伪造精确新增/删除。

selection 组合还必须满足：`class_provider/first_resource` 不能写 `selected_many`；`selected_many` 只允许用于明确支持多结果的 `ordered_resources/mechanism_specific`，且列表非空并保留消费顺序；`not_selected` 表示当前 physical occurrence 存在但被同一 logical key 的其他 effective occurrence 遮蔽，`absent` 表示完整闭包中该 logical key 根本不存在，二者不得互换。mechanism 未识别时必须写 `unknown + unsupported`。base/current mechanism 不同时先建立 resource/topology mechanism delta；除非独立 verifier 证明两种机制在该 fact scope 等价，否则不能只比较两个 set digest 后写 `unchanged`。

闭环规则为：

- 对普通 executable/linkable class/member fact，`selected_*` 只是必要条件；base/current 对应 ClassDefinitionResolution 还必须为 `definition_ready|runtime_equivalent` 才能比较并提升 method/field/contract runtime fact。精确 definition failure 生成自己的 class-definition/linkage fact，不能把失败 class 内的 method IR 差异继续包装成可执行实现变化；definition `ambiguous/unsupported` 时相关 method/member decision 为 candidate。若 AnalysisScope 包含 raw classfile 可观察性，失败 class 的原始字节差异另按 resource/semantic fact 裁决，不能反向赋予普通调用 traversal eligibility；
- `effective_fact_diff_status=changed` 且两侧比较/选择证据完整：进入 authoritative；这同时覆盖 selected content 改变、有序 selected-many 集合改变、`selected <-> absent` 和 provider/origin 改变，即使 artifact SHA、coordinate 或 physical provider 没变也不能漏掉；
- artifact-local changed，但变化实例在所有受支持 realm/mechanism 中均被证明 `not_selected`，且 base/current effective fact 列表及有序 digest（包括 provider origin 可观察事实）相同：进入 excluded，reason=`RUNTIME_SELECTION_NON_EFFECTIVE_ONLY`；保留物理差异审计；
- artifact-local changed 且 class bytes 相同但 effective provider/origin 变化：不能使用上一条排除，必须按 provider/runtime-topology fact 裁决；只有第 6.5 节 `runtime_equivalent` 完整证明才可判 effective unchanged；
- 某个 decision 所必需的 pairing、loader realm correspondence、provider/class-definition/member resolution、resource selection 或任一侧 effective inventory 不完整：相应侧必须写 `ambiguous/unsupported`，`effective_fact_diff_status=unknown`，该 decision 进入 diagnostic candidate；不能生成正式 target，也不能写 effective unchanged/absent。但独立且完整的 provider/topology/effective-symbol delta 不得被无关 artifact pairing 失败污染；
- 上游 artifact-local 的环境/语义等价仍未知时，只有“该实例在全部适用 runtime scope 均确定不被选择，且 effective view 自身完整不依赖该差异”的独立证明才能消除该 scope 的 candidate；不得用局部 non-effective 证据掩盖其他 realm 或 `getResources`/SPI 等 ordered-all 资源机制仍可能消费该实例；
- 一个 scope 的 effective change 已确认时可以独立进入 authoritative；同一 artifact 其他 scope unknown 必须并存为 candidate，并使 artifact summary 使用 `changed_with_unknown`；
- 纯 build audit 与不属于已声明 runtime scope 的 operational audit 使用独立 audit schema，不伪造 `effective_fact_diff_status` 或 API target。签名/signer、ProtectionDomain、package sealing 等 JVM/provider 固有可观察安全事实不能因没有普通 method consumer 而降为 build audit，必须按第 7.6 节裁决为 targetable 或 confirmed-unprojectable。

这层门禁保证“最终制品事实为裁决依据”指的是实际运行时视图中的 effective 事实，而不是任意被打进包但永远不会被 loader/resource mechanism 选中的物理字节。

#### 7.1.2 源码变化是否形成运行时有效变化的裁决

本设计中的“运行时变化”是指静态证据已确认最终制品中的运行时可执行、可链接或可消费事实发生变化，不表示系统已经运行测试并确认业务行为后果。对 old/current effective class/resource，先比较 contract、method IR、运行时可消费 metadata、resource semantic 和 runtime topology，再按以下规则裁决：

本文所有噪声/审计分流中的“没有可信消费者”都是闭集结论：必须针对该 exact archive/class/resource/metadata key 完成已声明 consumer mechanism 发现，coverage=complete 且命中数为 0。它不能被实现成“当前没找到”；consumer discovery partial/failed 或存在无法界定的动态读取时，相应差异必须为 candidate/incomplete，不得命中 packaging/classfile/build/distribution 排除规则。

- 手写源码、生成源码、Lombok/annotation processor 展开结果，以及 ERM/Schema/IDL 等生成输入只要造成 runtime-effective contract、规范化 method IR、运行时可消费 metadata、resource semantic 或 runtime topology 变化，就设置对应 fact 为 authoritative confirmed；是否生成正式影响 target 再由第 7.9 节决定；
- source diff 失败、源码未提交、源码无法映射或源码显示未变化，不得成为排除上述运行时有效变化的理由；
- entry payload 相同而只有 ZIP 容器元数据不同，且当前 AnalysisScope 不包含原始 archive 可观察性、也没有可信运行时消费者时，才判为 `packaging_noise_only` 并排除；否则记录 `runtime_observable_metadata_changed`，按 consumer/projection coverage 裁决为 targetable、confirmed-unprojectable 或 candidate；
- class payload 不同，但 contract、method IR、runtime metadata 均相同且差异完全落在第 7.3 节 scope-local 安全白名单内，并且当前 AnalysisScope 不包含原始 classfile 可观察性、也没有可信消费者时，才判为 `classfile_noise_only` 并排除；否则必须从 raw inventory 重新分类；
- 只改变版本化白名单内 build metadata 时进入构建审计，不进入代码/API 影响分析；运行诊断 metadata 按第 7.3 节的 AnalysisScope 分流。仅重新签名不得当作通用噪声排除，因为 class signer、ProtectionDomain、package sealing 和安全策略可以观察签名身份；必须按第 7.6 节进入 effective security fact 或 non-effective/audit 裁决；
- 无法完成安全等价或 runtime-effectiveness 裁决的 changed class/resource 必须进入 `incomplete/candidate`，不能默认排除或直接提升。

因此，裁决关系固定为：

```text
源码/生成输入变化 + runtime-effective 制品事实变化 -> confirmed change
源码/生成输入变化 + 当前 context 内仅非运行时差异 -> audit_only 或 excluded decision（按 owner 规则）
原始 JAR 字节变化 + 当前 context 的运行时/可观察事实未变化 -> audit_only 或 excluded decision（按 owner 规则）
runtime-effective 制品事实变化 + 源码无法映射 -> confirmed change
比较、等价或 runtime selection 不完整         -> candidate/incomplete
```

这里的 `confirmed change` 只确认 Step4 的运行时有效制品事实发生变化，不确认实际业务行为后果。若 Step5 又确认完整业务调用链，最终结论仍是第 1.1 节的“已确认触达变化实现，可能受影响，需运行时验证”。

“非代码变化”按最终制品是否存在 runtime-effective 变化定义，不能仅按 Git 文件类型或提交原因推断。即使只修改编译器、插件、插桩或构建配置，只要 effective contract、method IR 或运行时可消费 metadata 发生变化，仍属于有效发布变化，不能排除；反之，源码文本发生变化但最终二进制只剩已证明的非运行时噪声或只改变 non-effective 实例时，不生成代码/API 目标。排除项只保留最小审计证据、规则版本和 `exclusion_reason`，不得流入 Step5 目标及最终影响计数。

允许的 `exclusion_reason` 必须是版本化封闭集合，首版至少包括：

```text
PACKAGING_METADATA_ONLY
CLASSFILE_SAFE_ATTRIBUTE_ONLY
BUILD_METADATA_ONLY
DISTRIBUTION_METADATA_ONLY
TARGET_JDK_NON_EFFECTIVE_VARIANT_ONLY
RUNTIME_SELECTION_NON_EFFECTIVE_ONLY
RESOURCE_ENCODING_ONLY_PARSER_PROVEN
BUILD_ENVIRONMENT_REPRODUCED_NOISE_ONLY
BUILD_NONDETERMINISM_REPRODUCED_NOISE_ONLY
```

新增排除原因必须同时提供正例、反例和独立 verifier；无法命中封闭集合的差异一律不得排除。

首版原因与 owner 的边界固定为：

- `PACKAGING_METADATA_ONLY`、`CLASSFILE_SAFE_ATTRIBUTE_ONLY`、`BUILD_METADATA_ONLY`、`DISTRIBUTION_METADATA_ONLY` 在满足“对应 raw 可观察性位于 AnalysisScope 外且无 in-scope consumer”时只生成 `audit_only` scope exclusion；若 raw/semantic 事实在 scope 内，就不得使用这些原因绕过变化/candidate 裁决。
- `RESOURCE_ENCODING_ONLY_PARSER_PROVEN` 在无 in-scope consumer 时可以作为 `audit_only`；存在已注册 semantic consumer 时，只有 selection 完整且 mechanism-specific parser/equivalence verifier 覆盖全部适用消费语义、证明 base/current effective parsed fact 相等，才可以作为 `runtime_decision` exclusion。仅证明文本格式通常可忽略、或 consumer coverage 不完整时仍为 candidate。
- `TARGET_JDK_NON_EFFECTIVE_VARIANT_ONLY`、`RUNTIME_SELECTION_NON_EFFECTIVE_ONLY`、`BUILD_ENVIRONMENT_REPRODUCED_NOISE_ONLY`、`BUILD_NONDETERMINISM_REPRODUCED_NOISE_ONLY` 可以生成 `runtime_decision` exclusion，但必须分别具有完整 selection 或第 7.3.2 节等价证明，并引用 decision identity。
- 同一 raw delta 在不同 loader/mechanism scope 可以分别形成 audit-only、excluded、candidate 或 authoritative 记录；这些记录必须具有不同 observed scope，并全部反查同一 raw delta，不能用 artifact-level `promotion_status` 抹平成一个 owner。

### 7.2 JAR 容器规范化

比较顺序固定为：完整安全扫描 → physical/effective entry inventory → entry 解压内容摘要 → class/resource 分类。只有两侧归档都扫描完整、当前 AnalysisScope 不包含原始 archive 可观察性且没有可信消费者时，才能给出 `packaging_noise_only`。原始 archive 可观察性在 scope 内或存在可信消费者时，同样的时间戳/顺序/压缩字段差异必须记录为 `runtime_observable_metadata_changed`，再按 semantic consumer 与 coverage 裁决，不能先排除后丢失证据。

artifact-local 层始终保留具体 `ZIP_METADATA_CHANGED` 字段、old/new 摘要和 raw inventory，不把它们物理删除。`packaging_noise_only` 是绑定 RuntimeComparisonIdentity、AnalysisScopeIdentity、consumer-discovery closure 和安全 policy 后的 audit classification/summary，不是可跨 profile/scope 复用的原始制品事实，也不是 active runtime decision。因此 artifact-local cache 命中只能复用 raw/规范化证据，最终 scope exclusion 必须重走当前 analysis context 的 audit-classification gate。

在 entry 名称和解压后 payload 完全一致，archive scanner 已证明对应字段不改变 entry 类型、权限、symlink、加密、签名或运行时布局，且满足上一段 AnalysisScope/consumer 门禁时，才可以忽略以下 ZIP 容器差异：

- entry 时间戳；
- entry 排列顺序和目录占位项；
- 压缩算法、压缩级别和压缩后字节；
- ZIP comment；
- 版本化安全白名单内只表达时间戳或压缩布局的 extra field/中央目录编码差异。

下列情况不得当作容器噪声：

- entry 新增、删除、重名或路径变化；
- 解压后 payload 不同；
- nested JAR 的物理 entry、内容或运行时拓扑变化；
- thin/fat JAR、BOOT-INF/WEB-INF 或 shaded 布局变化；
- 加密、损坏、重复 entry、归档扫描不完整或不支持的压缩格式。
- Unix mode、external attribute、symlink/硬链接语义或未知 extra field 变化；这些至少进入 operational/topology candidate，不能按普通 ZIP 元数据排除。

MR-JAR 必须按 target JDK 比较 effective variant。只有非 effective variant 变化时，记录 `non_effective_variant_changed`，不提升为本 target JDK 的代码影响；target JDK 未知时不得据此排除。

这里的“容器噪声”只表示在已建模的 JVM 装载语义与 AnalysisScopeIdentity 内不产生代码/API 目标，不等于证明任意程序都不会观察 ZIP 原始元数据。analysis scope 明确包含原始归档可观察性，或存在业务/框架读取自身 JAR 时间戳、entry 顺序、压缩方式、comment、extra field 等可信证据时，semantic adapter 必须将对应事实重新分类；相关动态读取覆盖不完整时不得给出无影响或 `impact_analysis_completeness=complete` 结论。

### 7.3 classfile 规范化

class 原始 SHA 不同不能直接确认实现变化。每个 effective class 必须分别生成 contract fingerprint、method IR fingerprint 和 runtime metadata facts。

允许判定为“表示等价且不生成 method implementation target”的内容只能来自版本化安全白名单；这些内容按第 7.1.2 节排除，只在 `excluded_diff_evidence[]` 保存最小审计证据：

- 常量池槽位重新编号；
- branch/exception table 的原始 BCI 在规范化 label 后仅发生编号变化；
- class 已通过独立 verifier 时，仅 `StackMapTable` 编码不同。

上述差异归入 `classfile_noise_only`，不得进入 Step4 变化目标、Step5 调用链分析或最终影响计数。

该结论同样只对当前 AnalysisScopeIdentity 有效。如果 analysis scope 包含原始 `.class` 资源可观察性，或存在业务/agent/框架读取自身 classfile 字节的可信证据，常量池编号、attribute 编码等 raw 差异仍必须从 artifact-local inventory 重新分类为 resource/semantic 事实；不得因通用 JVM 执行语义等价就宣称原始字节也相同。

`SourceFile`、`SourceDebugExtension`、`LineNumberTable`、`LocalVariableTable` 和 `LocalVariableTypeTable` 不属于上述“字节表示等价”白名单：它们可被 JVM 堆栈、debugger、profiler 或字节码工具观察。单独变化时必须记录 `runtime_diagnostic_metadata_changed`，禁止误报为 `classfile_noise_only`。当 AnalysisScopeIdentity 不包含诊断可观察性且没有可信业务消费者时，它们进入独立 audit-only 计数，不伪装成 API 影响或“完全没有二进制变化”；analysis scope 明确要求该观测范围或存在 stack-trace/debug metadata 消费证据时，再经 runtime-effective gate 形成 targetable 或 confirmed-unprojectable fact。这一分流是分析范围裁剪，不是宣称该字节差异不存在。

规范化时必须保留：

- classfile major/minor version；
- class、method、field flags，包括 bridge/synthetic；
- field/method table 的物理顺序；
- superclass、interfaces、nest、record、sealed、module 等结构；
- owner/member/descriptor、字段常量值；
- opcode、字面量、符号引用、控制流、switch 和异常表；
- `invokedynamic`、`CONSTANT_Dynamic`、bootstrap、MethodHandle/MethodType 和参数；
- runtime-visible/invisible annotations、parameter annotations、`AnnotationDefault`；
- `Signature`、`MethodParameters`、Kotlin metadata 等可能被框架或反射消费的元数据。

“规范化时保留”不等于这些属性一有字节差异就全部成为同一种 authoritative runtime fact。每类 attribute 必须声明 JVM/反射/框架/raw-classfile 消费机制：例如 runtime-visible annotation 可按受支持反射/框架语义裁决，runtime-invisible annotation 通常只有 classfile 工具/agent 等机制可见。消费机制不在 AnalysisScope 时只留 audit，机制适用但运行时相关性或 consumer/selection 无法裁决时为 candidate，事实已确认但缺少可信 target 时才是 confirmed-unprojectable；禁止用统一的 `runtime_metadata_changed` 布尔值绕过该分流。

未知 attribute、解析 fallback、verifier 失败或无法证明安全的差异必须产生 `class_diff_status=incomplete`，不得自动归为噪声或无变化。安全白名单必须带 `normalization_policy_version`，新增忽略规则必须有独立正反例。

field/method table 物理顺序虽然通常不改变 JVM 执行 contract，但可被原始 classfile 读取器观察，因此先建立 artifact-local raw-metadata fact，不进入通用安全噪声白名单。只有 raw classfile 可观察性位于当前 AnalysisScope，或目标 JVM/框架专用 verifier 已证明某个 consumer 会观察该顺序，并且该 class 在对应 runtime scope effective 时，才形成 authoritative 可观察事实；有可信 consumer projection 时 targetable，否则 confirmed-unprojectable。Java reflection API 的返回顺序没有通用稳定合同，不能仅因 `getDeclaredMethods/Fields` 存在就假定 classfile 顺序变化可见。被遮蔽实例、非 effective variant、scope 外的顺序差异分别按第 7.1.1/7.3 节进入 non-effective exclusion 或 audit；运行时相关性、selection 或 verifier 不完整时为 candidate。

下列常见差异不得仅凭“通常由编译器产生”自动排除：

- lambda、匿名/局部类、Kotlin coroutine/state-machine 的 synthetic 名称或编号变化；类名可能被反射、序列化、日志、配置和框架观察；
- coverage、APM、agent、weaver、obfuscator 或 shading 工具引入的指令、成员、常量、注解和控制流变化；
- `@Generated(date=...)`、processor build id、绝对路径、compiler id 等进入 runtime-visible/invisible annotation、Kotlin metadata、字段常量或自定义 attribute 的变化；
- native library、nested binary、Graal/native-image 配置、Unix permission、symlink/external attribute 等制品差异。

这些差异若已经改变 contract、规范化 IR 或明确运行时可消费事实，先按事实类型确认 artifact-local 变化，再经第 7.1.1 节 runtime-effective gate 裁决和 targetable/unsupported 投影；若只命中版本化、独立验证的安全等价规则才允许排除；无法确认是否属于运行时事实、runtime selection 不完整或比较不完整时进入 diagnostic candidate。禁止通过跨版本猜测 synthetic 名称对应、删除 instrumentation opcode 或笼统清理“generated metadata”来降低噪声。

#### 7.3.1 编译期生成代码不得排除

只要生成结果进入 Step1 固化的 old/current 最终制品，就必须和手写代码使用完全相同的 class/member/descriptor/contract/IR/runtime-metadata 比较规则。适用范围至少包括：

- Lombok 生成的构造器、getter/setter、builder、`equals/hashCode/toString`、日志字段等成员；
- Java annotation processor 生成或改写的类和成员；
- 根据 ERM/ER 模型、数据库 Schema、OpenAPI、Protobuf/IDL 等生成并编译进 JAR 的 DTO、实体、客户端和序列化代码；
- 编译期 weaving、字节码增强、插桩或其他 build plugin 产生的最终 class。

以下事实不得因 `generated`、源码目录未提交、源码 diff 未变化或 generator 输入属于“非 Java 文件”而被过滤：

- generated class/member 新增、删除或 contract 变化；
- generated method 的规范化 IR 变化；
- generated annotation、Signature、字段常量、序列化或其他 runtime metadata 变化；
- 手写源码未变，但 generator 版本、配置、Schema/ERM/IDL 输入变化导致的上述最终制品差异。

只有 base/current effective class facts 在第 7.3 节规范化支持范围内相等，或 artifact-local 差异已证明在全部适用 runtime scope non-effective 时，才不生成代码变化 target。generator、Schema 或生成源码发生变化但 effective 二进制相等时，只保留 provenance/config 冲突或审计事实；反之，只有中间生成源码变化但没有进入 effective 最终制品的内容，也不得扩大正式制品范围。`generation_provenance` 可用于解释差异，不能作为提升或排除变化的前置条件。

#### 7.3.2 编译环境与非确定构建噪声隔离

仅凭“base/current 编译环境不同”或“构建工具可能不稳定”不能证明某个 method IR 差异是噪声，也不能把所有这类差异提升为正式变化。目标方案必须先控制输入/确定性、再做归因：

1. Step1 `checkout_build` 应尽可能让 base/current 使用同一受控宿主环境；项目声明的 wrapper、toolchain、compiler plugin 或 processor 版本属于构建输入，不能被宿主环境静默覆盖。
2. 两侧分别保存版本化 `BuildEnvironmentIdentity`（工具链/宿主）、`BuildInputManifestIdentity`（内容、参数、generator 输入、compile classpath）和 `ArtifactBuildProvenance`（source revision、制品与一次执行/接收事件）；环境、语义输入与来源必须分别比较/审计，不能因 source revision 不同就写 environment 或 input different，也不能因 environment equal 就声称输入相同。若构建实际读取 VCS 值，该值必须同时作为明确语义输入记账。
3. `provided_artifact` 不重新构建正式制品；只能消费制品携带或用户提供的 build provenance。相应身份缺失时分别记 `build_environment_comparison_status/build_input_comparison_status=unknown`，不能伪造环境/输入一致或 build-variation noise 证明。

差异裁决固定为：

下表只裁决当前 artifact-local member/metadata scope 的“是否可归因于编译环境或已知非确定构建变体”，不覆盖独立的 runtime-profile/provider/resource/topology delta；即使 member IR 相同，effective provider/origin 或资源选择变化仍按第 7.1.1 节另行裁决。

| 条件 | 裁决 | 是否影响正式分析 |
|---|---|---|
| contract、runtime metadata、规范化 IR 及该 scope 全部适用 attribute 均相同或命中安全白名单 | 已由第 7.3 节证明为安全差异 | 排除 |
| 环境不同，且输入同一性满足以下之一：完整 BuildInputManifest 相同；或全局 manifest 不同但当前 fact 的 `FactBuildInputSlice=equal + coverage=complete`。独立 verifier 再联合版本化 same-input golden 或可信 reproducibility attestation 证明当前运行时事实等价 | `build_variation_kind=environment_change`、`environment_attribution_status=proven_noise`、`exclusion_reason=BUILD_ENVIRONMENT_REPRODUCED_NOISE_ONLY` | 排除 |
| 环境 identity 确认不同，且输入同一性满足上一行两条之一；contract/runtime metadata 与其他适用 facts 均相同或安全，IR 差异又精确命中版本化“环境敏感变换”候选规则，但独立等价证明尚不完整 | `build_variation_kind=environment_change`、`environment_attribution_status=suspected`、`analysis_eligibility=diagnostic_only`、promotion=`candidate` | 不进入正式目标和影响计数；只进入诊断 sidecar |
| BuildEnvironmentIdentity 相同，且输入同一性满足上述两条之一；输出差异精确命中版本化 clock/random/filesystem-order/parallelism 等非确定变换候选规则，但独立等价证明尚不完整 | `build_variation_kind=nondeterministic_build_output`、`environment_attribution_status=suspected`、promotion=`candidate` | 不进入正式目标和影响计数；只进入诊断 sidecar，不因“相同环境”直接提升 |
| 上一行场景由独立 verifier + same-input golden/reproducibility attestation 证明当前 runtime fact 等价 | `build_variation_kind=nondeterministic_build_output`、`environment_attribution_status=proven_noise`、`exclusion_reason=BUILD_NONDETERMINISM_REPRODUCED_NOISE_ONLY` | 排除 |
| 当前 fact 的语义输入切片不完整/已变化，或 IR 差异不满足上述任一严格疑似条件 | `build_variation_kind=none/unknown`、`environment_attribution_status=rejected/not_applicable` | 不能借“可能是环境/非确定构建”降级；先确认 artifact-local 结构/IR/semantic fact，再经第 7.1.1 节 runtime-effective gate 裁决，只有 effective changed 才进入 authoritative 及 targetable/unsupported 投影 |

same-source/same-input 复现证据只能来自离线版本化 goldens 或外部提供且可校验的 reproducibility attestation；生产分析不得为归因新增构建流程，也不得在 Step4/Step5 下游临时重编译。一般字节码语义等价不可判定，因此 verifier 只能覆盖版本化安全变换白名单；不能因为 opcode 看起来相似、源码相同、两次输出不同或环境版本不同就声明 `proven_noise`。所谓“非确定变换候选规则”也必须精确到 generator/compiler/version、输入位置和差异形态，不能用“构建偶尔不稳定”作为通配规则。

ordered compile classpath、声明的 processor/generator/plugin、其配置以及项目 toolchain/wrapper 的声明部分都是 `BuildInputManifestIdentity` 中的语义构建输入，不是普通“宿主环境噪声”。这些输入任一变化且无法以完整 `FactBuildInputSlice` 证明与当前 fact 无关时，不能仅凭 source text 相同进入通用 `suspected` 规则。若独立 fact-specific verifier 已完整证明当前 runtime fact 等价，可使用对应的安全规范化/语义等价排除理由，但不得伪造 `BUILD_ENVIRONMENT_*` 或 `BUILD_NONDETERMINISM_*` 归因；否则 effective IR/contract/metadata 差异按真实发布变化处理。禁止用 candidate 规则吸收依赖升级触发的重载选择、代码生成或 weaving 变化。

这里必须区分两个事实：规范化 IR 不同可以确认“artifact-local 发布实现表示不同”，但不能确认业务语义不同，也不能跳过 runtime-effective gate。环境 identity unknown 且 IR 确认不同的 provided artifact 不能因 provenance 缺失降级成“未变化”；若该 member 在 runtime scope effective，则属于真实发布实现差异，报告通过 `impact_conclusion` 保留行为不确定性；若 selection 未知则保持 candidate。只有差异满足严格环境变化或非确定构建疑似条件时才隔离为 candidate，只有独立等价证据完整时才据此排除。任意编译器/生成器输出不存在同时保证零误报和零漏报的通用语义等价算法，三值裁决和显式证据边界是本方案的准确性合同，不得被实现为启发式二值猜测。

`diagnostic_only` candidate 不得生成用户可见的“已确认/可能受影响”API，不得增加 `reachable/probable/not_analyzed` 等正式计数，也不得污染其他已确认目标。它只阻止在自身 scope 上声称“已确认无运行时变化”。只要 candidate 能绑定 exact member/resource/runtime target，系统就必须使用同一二进制事实图执行独立诊断触达分析，输出“未裁决差异是否触达业务”；该结果进入独立不确定性清单，不能合并进正式影响报告。无法绑定目标时必须记录 scoped failure，不能静默跳过。

### 7.4 结构变化

迁移期 legacy 生产结果可以继续使用 JApiCmp XML 和现有 old JAR 导出；但在 `binary_strict` 目标合同中，第 6.13 节 ASM raw facts 派生的版本化 classfile contract 是唯一结构变化权威事实。JApiCmp 仅作为 shadow/独立交叉检查和兼容输出来源，不能与 ASM contract 并列裁决或覆盖它；两者在 support manifest 交集中冲突时，相应 scope 必须失败关闭/candidate 并留存 delta，不得任取其一。源码结构差异只能作为解释或冲突证据，不得在二进制证据失败时冒充正式发布事实。

class version、字段/方法 contract、继承、module/nest/record/sealed 以及运行时注解/元数据变化必须先按其作用域建立 artifact-local 结构或 metadata fact，再经 runtime-effective gate 裁决；不能因“方法指令未变”而忽略，也不能因 class 被遮蔽而直接生成正式 target。

### 7.5 方法实现变化

对所有具备可信 old/current 留存 JAR 的适用变化依赖，常态执行方法实现比较，不再以源码 diff 是否成功作为执行条件。

阶段 1 的 shadow 对账可以复用当前规范化 `javap` 方法体摘要，但不得据此切换 authoritative 变化目标；进入正式 binary 模式前必须使用第 6.13 节 ASM raw facts 生成版本化 classfile IR fingerprint：

- 使用 JVM owner/member/descriptor 绑定同一成员；
- 将常量池索引解析成真实 owner/name/descriptor/value；
- 将 branch、switch 和异常处理目标规范化为稳定 label；
- 保留 opcode、字面量、控制流、异常表和 bootstrap 参数；
- 覆盖 public/protected/private、构造器、`<clinit>`、bridge/synthetic 和 lambda body。

artifact-local 中间事实建议使用：

```text
artifact_local_change_kind = METHOD_IR_CHANGED
artifact_local_diff_status = changed
change_basis              = final_artifact_method_ir_fingerprint
```

只有第 7.1.1 节确认 current/base effective method fact 已变化后，才能建立正式 `METHOD_IMPLEMENTATION_CHANGED + change_fact_status=confirmed`。binary 权威切换时的兼容输出适配层可以继续投影：

```text
change_type = BEHAVIOR_CHANGED
source      = jar_bytecode
confirmed   = true
```

但该兼容字段的 `confirmed=true` 只确认 runtime-effective 发布实现变化，不表示实际业务语义或运行后果已经变化。规范化 IR 不同时，先确认 artifact-local difference；只有通过第 7.1.1 节 effective gate 后才能正式提升，满足第 7.3.2 节 `proven_noise` 时排除，满足严格 `suspected` 条件时进入 `diagnostic_only`。annotation processor、生成器、插桩或混淆器造成的 runtime-effective 差异不能仅因“手写源码未变”或“构建工具变化”被排除。

### 7.6 最终制品资源分类

非 `.class` payload 不能统一忽略。资源必须按 entry 和解析能力分类：

| 类型 | 示例 | 正式处理 |
|---|---|---|
| runtime semantic | `META-INF/services/*`、Spring metadata、MyBatis XML、properties/YAML、SQL、模板 | 建立独立 resource/semantic change fact；适用 adapter coverage 完整时进入 semantic target |
| runtime topology | Manifest 的 `Main-Class`、`Class-Path`、`Multi-Release`、`Automatic-Module-Name`、agent 入口 | 建立 topology/linkage fact；重新计算 effective runtime graph |
| operational/security | `META-INF/*.SF`、`*.RSA`、`*.DSA`、`*.EC`、签名 digest | 记录签名/完整性变化；对 effective provider 先建立 signer/ProtectionDomain/package-sealing security fact，有受支持安全消费机制时 targetable，否则 confirmed-unprojectable。只有变化签名未被任一受支持 runtime scope 选中，或独立 verifier 证明两侧 signer/security 事实等价时才排除；不得伪装成普通 method API 调用链 |
| runtime/native binary | `.so`、`.dll`、`.dylib`、WASM、脚本引擎产物、nested executable | raw payload 不同只建立 artifact-local fact；受支持 parser 已确认 effective ABI/code/data/runtime-metadata 变化时才进入 authoritative，并按 projection 能力分为 targetable/confirmed-unprojectable；只有规范化等价 verifier 完整时才排除，格式、选择或比较不完整时为 candidate |
| build metadata | `Built-By`、`Build-Time`、构建机器/JDK/commit 展示字段 | 先由版本化 key/entry 白名单分类；只有当前 AnalysisScope 不包含任意 resource/raw 观测、exact key 无可信 consumer 且 consumer-discovery coverage 完整时，才记 `build_metadata_only` 并只留 audit/exclusion。否则按实际 consumer 重分类或 candidate；这一类不包含第 7.3 节的 runtime diagnostic classfile attribute |
| distribution/audit metadata | 版本化 matcher 命中的 LICENSE/NOTICE/随包文档、SBOM/provenance 附件、不参与 launcher/module/resource index 的构建描述 | 只有 parser/registry 已证明它不属于任何已注册 runtime semantic/topology/security/native 机制，当前 AnalysisScope 不包含任意资源/原始制品观测，且没有该 exact resource key 的可信 consumer 时，才记 `distribution_metadata_only` 并进入 audit/exclusion；任一门禁不满足时按实际机制重分类或 candidate |
| unknown | 未注册 entry、解析失败、重复 key、语义未知格式 | `resource_diff_status=unknown`、promotion=`candidate`、`analysis_eligibility=diagnostic_only`、coverage=`partial/failed`；禁止当作无变化或进入正式影响统计 |

表中的示例不是“首版全部支持”的承诺。每个 runtime semantic/native mechanism 必须在 `artifact_diff_support_manifest` 中分别声明 entry matcher、parser、消费/选择语义、顺序/重复 key 规则、target identity、edge-local verifier 和 coverage 算法。未声明、无法证明运行时语义、runtime selection 或解析不完整时为 candidate；parser 与 selection view 已确认 runtime-effective 事实变化但尚无可信 consumer/projection verifier 时为 authoritative + unsupported，进入 confirmed-unprojectable report；只有事实和 projection 都完整时才生成正式 target。不得为了扩大首版范围把所有 XML/YAML、模板、SQL 或 native payload 统一提升为正式目标，也不得把 native 原始 SHA 不同当成已确认运行时变化。

Manifest 必须按 key 解析，忽略行折叠、key 排列等编码噪声，但不能忽略运行时 key 的值变化。properties/XML/YAML 等只有对应 parser 能证明注释、格式或 key 顺序不影响消费语义时才能规范化；重复 key、顺序敏感格式和未知 parser 一律失败关闭。

`META-INF/services/*` 必须保留 provider 内容和对消费语义有意义的顺序，配置中的 list/array 顺序也不得被 map-key 规范化意外抹平。

Manifest 的 `Implementation-Version`、`Specification-Version`、package sealing、module/agent/launcher 等可被运行时直接消费的 key 不得进入通用 build-metadata 白名单：值变化先建立 artifact-local metadata/topology fact；对应 package/module/artifact 在 runtime scope effective 时才成为 confirmed runtime fact，有 consumer projection 时 targetable，否则 confirmed-unprojectable。selection 未知时为 candidate。自定义 metadata key 只有独立证明属于诊断字段时才能排除；连运行时相关性都无法确定时按 candidate 处理。

LICENSE/NOTICE/SBOM/`META-INF/maven/**` 等名称只是 matcher 候选，不是无条件忽略清单。`pom.properties`、SBOM、provenance、`INDEX.LIST` 或任意文档都可能被业务、框架、安全扫描器或 ClassLoader API 读取；命中已注册 consumer/索引/安全机制、原始 resource 观测在 AnalysisScope 内，或 consumer discovery coverage 不完整时，不得使用 `DISTRIBUTION_METADATA_ONLY`。

即使某个 build metadata 通常无业务影响，也只能在上述三重门禁完整时排除其 Step4 API/行为目标，不能删除制品审计记录，也不能据此单独给出“已确认无业务影响”。若当前业务或框架存在读取该资源/Manifest key 的可信证据，应由 semantic adapter 将其重新分类为 runtime semantic change；若动态读取覆盖无法证明完整，必须进入 candidate/incompleteness，不得先写 `BUILD_METADATA_ONLY` 再只降低负向路径 coverage。

### 7.7 差异提升矩阵

| 原始现象 | 规范化事实 | Step4 裁决 |
|---|---|---|
| JAR SHA 不同 | entry payload 全同，仅 ZIP 元数据不同，且 raw archive 不在 AnalysisScope、无可信消费者 | `packaging_noise_only`；不进入 Step5。否则为 `runtime_observable_metadata_changed`，按 projection/coverage 裁决 |
| class SHA 不同 | contract、IR、runtime metadata 均相同，仅 scope-local 安全白名单属性不同，且 raw classfile 不在 AnalysisScope、无可信消费者 | `classfile_noise_only`；不提升为 API/实现变化，但保留 raw/noise fact。否则重新分类为 resource/semantic fact |
| method 原始 Code 不同 | 规范化 IR 相同 | 不生成实现变化；保留 noise fact |
| method 规范化 IR 不同 | exact artifact-local member 比较完整 | 先建立 `METHOD_IR_CHANGED`；仅在 effective method fact 不同时提升 `METHOD_IMPLEMENTATION_CHANGED` 并进入 Step5 |
| compile-time constant/inline body 变化 | consumer 不再保留 symbolic reference | source target 变化事实按 effective dependency class 裁决；consumer binding 按第 6.7.3 节 consumption effect 与 proven/possible 裁决，禁止字面量猜边或完整静态未命中 |
| Lombok/annotation processor/ERM/Schema 等生成 class 不同 | contract、IR 或 runtime metadata artifact-local 差异已确认 | 与手写 class 一样经过 runtime-effective gate；禁止按 generated/non-code 排除，也禁止把被遮蔽实例直接提升 |
| class contract/runtime metadata 不同 | 比较和 runtime selection 完整 | effective fact 不同时生成结构或 semantic change fact |
| runtime resource 不同 | adapter 分类、selection 和 coverage 完整 | effective resource fact 不同时生成 resource/semantic target |
| LICENSE/NOTICE/SBOM/随包文档等 distribution metadata 不同 | 命中版本化 matcher，不属于已注册运行机制，raw/resource 观测在 scope 外，且 exact key 无可信 consumer | `distribution_metadata_only`；只进入 audit/exclusion。任一门禁不完整时重分类或 candidate |
| 仅重新签名且其他 payload 相同 | signer/ProtectionDomain/security artifact-local change | effective security fact 改变时为 targetable 或 confirmed-unprojectable；不伪造普通 API 调用链，也不按通用噪声排除 |
| 仅非 effective MR variant 不同 | target JDK 已确认 | 记录 target-not-effective，不生成本 target JDK 影响 |
| 编译环境不同，独立证据证明输出运行时等价 | environment proven noise | 排除；不生成正式目标或影响计数 |
| 满足第 7.3.2 节严格环境疑似条件但尚未证明等价 | environment suspected | `diagnostic_only/candidate`；只进入诊断 sidecar |
| same-input 构建输出不同，命中精确非确定变换规则且独立证明运行时等价 | nondeterministic build proven noise | 排除；无等价证明时为 `diagnostic_only/candidate`，不得因环境相同直接提升或排除 |
| nested JAR、runtime topology 不同 | payload/topology 已确认 | 不是 packaging noise；先重建两侧 runtime view，effective provider/resource selection 变化时提升 runtime-topology fact，不变时只留物理审计 |
| artifact payload 相同但 loader/classpath/module-path 顺序变化 | base/current provider binding 不同 | 生成 provider/runtime-topology fact；任一侧 loader coverage 不完整则为 candidate |
| synthetic 名称、插桩、混淆或 runtime metadata 变化 | 未命中独立安全等价规则 | 先确认 artifact-local contract/IR/metadata 差异，再经 runtime-effective gate 与 targetable/unsupported 投影；解析/选择/运行时相关性未知时为 candidate，不得按“编译器生成”排除 |
| 未知 attribute/resource 或比较不完整 | 无法安全规范化 | `diagnostic_only/incomplete/candidate`；禁止进入正式影响统计或输出完整无变化 |

### 7.8 二进制与源码裁决矩阵

| runtime-effective 二进制裁决 | 固定源码差异 | 正式裁决 |
|---|---|---|
| 变化 | 同一成员也变化 | 发布实现变化已确认；源码补原因、文件和行号 |
| 变化 | 无源码、生成源码未保留或无法映射 | 仍进入 Step5；按证据记录 `source_mapping_status=generated/unmapped` |
| 变化 | 源码显示未变化 | 以制品为准；记录 `SOURCE_ARTIFACT_CONFLICT` |
| effective view 完整且未变化 | 源码显示变化 | 不提升为发布变化；只保留 source/artifact implementation conflict |
| 比较/pairing/runtime selection partial/failed | 源码显示变化 | 只能形成 candidate；不得写 `confirmed=true` 或完整无变化 |
| effective view 完整且未变化 | 源码也未变化 | 仅说明规范化与 runtime selection 支持范围内未发现发布实现变化 |

源码冲突可能来自生成代码、构建 profile、编译器、插桩、错误 ref 或未进入发布制品的修改。报告必须记录冲突，不能静默选择源码或二进制一侧。

### 7.9 变化事实到 Step5 target 的类型化投影

“运行时事实发生变化”不表示所有变化都能以同一种 member 调用链分析。projection 必须按 change kind 建立，禁止为了复用 tracer 把 metadata/resource/topology 变化都伪装成方法实现变化：

| change fact | 正式 target/projection | 禁止推断 |
|---|---|---|
| method implementation changed | current exact member；构造器、`<clinit>`、lambda body 分别走 direct/class-init/lambda-binding 关系 | 源码同名方法、possible dispatch 不得冒充 exact target |
| current effective method/field removed 或 descriptor/contract incompatible | current caller 中保留的 exact symbolic reference、linkage target 和已确认 missing/incompatible resolution | 某个 physical JAR 内删除不等于 effective removal；current 其他 provider 仍提供等价成员时必须在 effective gate 排除该 removal，provider/origin 变化则投影为 topology fact |
| field `ConstantValue` changed | 真实 getstatic/putstatic access；已内联 consumer 走第 6.7.3 节 | 字面量匹配不能生成 field edge |
| hierarchy/default method/bridge/flag changed | 受变化影响的 provider/dispatch/linkage delta | 任意引用该 class 都不能自动算受影响 |
| classfile version/module/nest/record/sealed 变化 | 对应 ClassDefinitionResolution/loader/linkage compatibility fact | provider 被选中不等于目标 JVM 可定义；普通 method reachability 不能替代 definition/linkage 证明 |
| runtime annotation/Signature/Kotlin metadata changed | fact confirmed；具有已验证 consumer 时 targetable，consumer 未知时 confirmed-unprojectable | 直接调用被注解方法不能证明 metadata 被消费 |
| resource semantic changed | mechanism adapter 建立的 resource consumer target | 同包/同模块关系不能证明读取 |
| runtime topology/provider changed | 第 8.2.1 节 current callsite/symbolic target 与 provider delta | 只比较 JAR 坐标或 current provider 不能证明发生变化 |
| effective signer/ProtectionDomain/package-sealing/security fact changed | 受支持安全机制 target；无可信 consumer 模型时 confirmed-unprojectable | 不得伪造普通 API 调用链，也不得得出无影响结论 |

每个 projection 记录 active `projection_assessment_identity`、`projection_obligation_key`、planning-contract identity、`projection_rule_implementation_version`、change fact/decision identity、target identity、所需 edge family 和 coverage requirement。没有注册 projection 的 authoritative runtime-effective fact 不能静默丢弃：若运行时事实已确认但当前不具备可信 target 模型，必须在 active assessment 中写入“confirmed fact / analysis unsupported”，不得伪造 API target；该状态会阻止对相应 scope 声称影响分析完整。

projection target-set completeness 必须由第 8.2.1 节对应 initiating-context/key universe、context→key 适用关系和 mechanism coverage 共同证明，不能由“已经找到一个 target”推断。例如 removed member/provider delta 需要覆盖全部 current symbolic-member context，resource/metadata change 需要覆盖全部适用 consumer mechanism，class-definition/topology change 需要覆盖全部触发 context/key。找到部分 exact target 但 universe/适用关系/adapter coverage 不完整时就是 targetable+partial；一个 target 都无法可信绑定且 fact 本身已确认时才是 unsupported。

projection 是显式多对多关系，不是把 fact 字段直接复制到 API：

```text
projection_obligation_key = projection_rule_contract_identity
                          + analysis_target_identity + required_edge_family
projection_identity = projection_assessment_identity + projection_obligation_key
                    + projection_rule_implementation_version
                    + canonical projection payload digest
                    + projection_schema_version
reported_api_identity
```

canonical projection payload 至少包含 change-fact/target/obligation/coverage requirement 与 provider/resource scope，但不包含 projection identity 自身、trace 或 report 字段；candidate payload 同理，防止下游结果反向进入投影身份。

- 一个 authoritative fact 可以投影到零个、一个或多个 runtime target；零个可信 target 时必须是 `unsupported + projection_coverage_status=unsupported`；一个或多个 target 且全部适用 target/mechanism discovery 已闭合时为 `targetable + complete`，已有 target 但仍有未覆盖 consumer/mechanism/target scope 时为 `targetable + partial`；
- 多个 authoritative facts 可以汇入同一个 `reported_api_identity`，但每个 `projection_identity` 都必须独立保留 change kind、runtime scope、provider、trace 和 coverage；
- formal trace 的原子单位是 authoritative-targetable projection，不是去重后的展示 API。`by_api` 只是第 9.4 节定义的确定性聚合视图，不能因去重丢失未分析 projection 或结构/linkage 子结果；
- partial targetable fact 的已建立 projection 与 complete fact 使用相同正式状态模型，但每个未投影 scope 必须引用 `incompleteness_scope_identity`；不得为未知 target 伪造 `not_analyzed` projection，也不得因已有 reachable projection 删除 partial coverage；
- 同一 active assessment/projection-obligation key 只能有一个 active projection，且 assessment 中每个 obligation 必须恰有一个；target dedup 不能跨 loader realm、ArtifactInstance 或不同 resource selection scope；
- `analysis_target_identity` 通常是 exact physical runtime target；只有第 6.5/6.5.1/6.6.1 节的 provider/class-definition/member equivalence set 对当前 change fact、projection 与 trace scope 全部通过 verifier 时，才可使用版本化 equivalence-set target。不得选集合中任一 physical member 充当稳定 target，也不得跨 defining loader/module context 合并；
- projection planning registry、rule contract/applicability、target-discovery 或 obligation-set 变化时先生成新 assessment；仅 projection implementation/schema、active assessment 或 target identity 变化时生成新 projection identity/formal snapshot。旧 assessment/projection/trace 按 immutable supersession 规则退出 active view，其 change decision 保持不变；若变化的是 runtime-fact 提取/裁决能力，则按第 7.1 节另建 decision，不冒充纯 projection 更新。

`reported_api_identity` 必须由版本化 grouping rule 生成，至少保留 RuntimeComparisonIdentity、AnalysisScopeIdentity、current RuntimeProfileIdentity、dependency/member lineage、owner、member kind、name 和 exact descriptor lineage；不能用人类可读简单签名、源码行号或坐标字符串直接去重。实现与 contract 同时变化的同一 exact member 可以聚合；descriptor change 只有 CrossVersionArtifactPairing/member-lineage 证据明确时才能把 removal/addition 放入同一展示组；同一 runtime profile-pair + analysis-scope 下不同 loader realm/physical target 即使展示 API 相同也只允许在 `by_api` 聚合，底层 projection 永不合并。跨 RuntimeComparisonIdentity 或 AnalysisScopeIdentity 只能做另一个明确标记的 presentation 汇总，不能进入 `unique_reported_api_total` 或四维状态聚合。

candidate 不建立 `AuthoritativeProjectionAssessment`，但每个 active candidate decision 必须恰有一个版本化 `CandidateDiagnosticProjectionPlan`，否则零 target/部分 target 会被静默隐藏：

```text
candidate_projection_plan_identity
  = candidate_decision_identity
  + diagnostic_projection_registry/policy identity
  + applicable-target-scope/target-discovery evidence digest
  + canonical bound-target-set/projection-obligation-set
    /status/coverage/unbound-scope digest
  + candidate-plan schema version
diagnostic_target_status = targetable | unbound
diagnostic_projection_coverage_status = complete | partial | failed
candidate_projection_obligation_key
  = diagnostic projection-rule contract identity
  + candidate_target_identity + required_edge_family
candidate_projection_identity
  = candidate_projection_plan_identity + candidate_projection_obligation_key
  + diagnostic projection-rule implementation/schema version
  + canonical candidate-projection payload digest
```

`targetable` plan 至少绑定一个 exact candidate target，并要求 active candidate-projection snapshot 为 plan 中每个 projection obligation 恰好物化一个 projection；coverage 可 complete/partial。`unbound` plan 的 target/obligation/projection 数均为 0，但仍必须明确 discovery 是 complete、partial 还是 failed，并保存 unbound scopes/reason；complete 只表示当前诊断投影能力确实没有 target，不能据此把 candidate 排除。plan 的 target/obligation-set digest 不引用下游 projection identity。诊断 target discovery、planning registry/rule contract 或 obligation-set 变化时 supersede plan；仅 projection implementation/schema、active plan 或 target identity 变化时 supersede candidate projection/trace；两者都不改写 candidate decision。只有变化裁决证据更新时才按第 8.3.1 节升级/降级该 decision。candidate plan/projection 使用独立 namespace 和多对多基数规则，不得复用正式 assessment/`projection_identity`。

## 8. Step5 二进制主图设计

### 8.1 构图顺序

目标顺序固定为：

1. 从 Step1 留存清单建立 loader realms、module/classpath slots 和 artifact instances。
2. 按第 6.2.1 节建立 base/current artifact/runtime-scope pairing，并选择每个 artifact 的 effective class variant。
3. 先完成两侧 runtime-path entry/resource inventory，流式解析所有 current runtime-path candidate class，并解析构造 base reconciliation universe/provider/class-definition/resource delta/effective diff/inline verifier 所需的全部 base raw classfile facts。base 侧可不物化业务路径和展示对象，但不能按“当前已知变化 target”抽样原始 reference/registration 发现分母，也不能混入 current 路径图。任何 deferred base entry 都必须先有独立证据证明它不参与上述任一 scope；不得用尚未冻结的 universe 反向证明可 deferred。
4. 写入两侧 pre-discovery 所需 class/member/direct/type/dynamic/bootstrap/class-init/linkage/type-hierarchy 原始事实；current 额外保留正式路径图所需全部事实。
5. 从上述已完成的 raw inventory/facts、manifest/module/classfile annotation/resource registration、全量 source-alias/consumer candidate 扫描和版本化 adapter matcher 做 **target-independent** binding pre-discovery，再冻结 `pre_resolution_discovery_snapshot`。它包含物理 owner/member/resource key 候选、raw caller/path-owner 候选、exact-key/raw-resource consumer obligation 及 launcher/reflection/service/semantic runtime-origin seed，但不读取 authoritative change fact/projection，也不声称 caller defining loader 或 final context→key 适用关系已知。源码 direct call 仍不能进入 JVM 主图；此处源码只提供可能影响 consumer 闭集或 semantic binding 的候选分母，单独的 source-only consumer candidate 既不是可信 consumer 命中，也不能扩大最终制品范围。
6. 以该 discovery snapshot 和有限 runtime inventory 为输入做版本化单调 fixed point：先对 request-origin + owner 解析 class provider/ClassDefinitionResolution，由已选 caller 的实际 defining loader/module 派生 bytecode initiating context 及其 member/type/linkage/bootstrap key；再以当前 round 的 binding 运行 target-independent business-entrypoint、resource-consumer 和 semantic activation verifier，解析 symbolic member/resource selection/dispatch，并把新发现的受支持上下文/key/适用关系单调加入下一 round。source candidate 只有绑定 current final-artifact 端点并取得独立 activation/consumer evidence 后才成为可信命中；端点不存在时只记 source/artifact conflict，验证或覆盖未完成时保留对应 frontier。resolver 与这些 discovery/verifier 必须共同达到“无新增 obligation”的收敛点；不得先冻结 provider 再在 decision 后补消费者。超过版本化有限上限、出现动态无界 key/context 或任一 round coverage 失败时，只能保留 scoped partial evidence/candidate，不得用截断集冒充闭包。
7. 只有 combined fixed point 收敛后，才冻结四类 final reconciliation universe、`context_key_applicability`、全部 binding/resource-consumer/entrypoint/semantic-discovery digest，并物化 current business entrypoint/RootEdge 与已验证 semantic edges。source alias 可在此完成展示绑定，但不改变 physical fact。若物化阶段出现 pre-discovery support manifest 未声明的新 initiating context、runtime binding key 或适用关系，视为 discovery 合同失败：当前 final snapshot 作废并从第 5 步重建，禁止在 trace 中就地补图。
8. 建立 base/current provider/class-definition/resource-selection view 与版本化 delta，完成第 7.1.1 节 runtime-effective decision；build/distribution metadata 的“无可信消费者”排除只能使用上述已收敛 consumer-discovery 证据。base 节点不得混入 current 路径图。
9. 完成 binary facts、pre-resolution discovery snapshot、fixed-point rounds、四个 final reconciliation universe、context→key 适用关系、runtime-effective decisions、certainty 和 coverage 守恒校验；再为已确认/候选 fact 建立 target-dependent proven/possible inline binding 与其他 projection evidence。该阶段若暴露新的 runtime binding obligation，说明 capability 分层或 pre-discovery 不完整，必须失效并从第 5 步重建，不能把它只当成 projection 更新。
10. 按第 7.1 节依次冻结 active decision、active projection-assessment、active formal-projection 和 active candidate-projection 四层 snapshot；冻结后新增 inline/semantic/target-discovery evidence 不能在 trace 中就地加 target，必须从其最早受影响层生成 superseding snapshot。
11. 对 authoritative-targetable projections 执行批量多源反向传播；candidate projections 使用独立 namespace 执行诊断传播；confirmed-unprojectable facts 只进入 scoped report，直到存在版本化 projection rule 才能转为 targetable。
12. 先逐 projection 裁决，再按第 9.4 节聚合每个 reported API 的变化、精确/可能触达、影响和覆盖。
13. 生成全部已物化唯一终止路径台账、projection/API 聚合守恒元数据和兼容查询索引。

不能再在逐 API 结果生成之后补图并期待结果自动修正。

这里不存在 Step4/Step5 循环依赖：Step4 先产生 artifact-local diff 和“需要 runtime-effectiveness 对账”的信号；Step5 的 target-independent 阶段在不读取 authoritative change fact/projection 的前提下冻结 pre-resolution discovery input，再以 combined finite fixed point 建立 final reconciliation snapshot、current graph、consumer/entrypoint/semantic discovery closure 与 base/current compact provider/class-definition/resource-selection views。effective decision 与 provider delta 随后回写版本化 Step4 fact sidecar，并依次冻结 active decision、projection-assessment、formal-projection 和 candidate-projection snapshot；只有四层兼容快照冻结后才开始目标反向传播。pre-discovery 后出现未声明 seed，或 final snapshot 后发现新解析上下文、binding key/适用关系，都不能就地修改 binding/target set，必须从最早受影响的 discovery/reconciliation/decision/assessment/projection 冻结点重建；只有 decision-relevant effective-runtime 证据改变时才 supersede decision，仅 target-discovery/projection 能力改变时不得改写 decision。

### 8.2 持久化与查询

建议在报告目录使用版本化 SQLite，例如：

```text
.runtime/indexes/s5_binary_graph_v1.sqlite
```

至少包含：

- `artifact_blobs`
- `artifact_instances`
- `cross_version_artifact_pairs`
- `class_variants`
- `members`
- `symbolic_targets`
- `direct_edges`
- `type_edges`
- `metadata_reference_facts`
- `dynamic_call_sites`
- `bootstrap_linkage_edges`
- `class_init_edges`
- `linkage_edges`
- `dispatch_resolutions`
- `dispatch_edges`
- `loader_realms`
- `module_layers`
- `module_readability_bindings`
- `runtime_profiles`
- `runtime_comparisons`
- `analysis_scopes`
- `analysis_contexts`
- `build_environments`
- `build_input_manifests`
- `artifact_build_provenance`
- `build_audit_records`
- `fact_build_input_slices`
- `pre_resolution_discovery_snapshots`
- `resolution_fixed_point_rounds`
- `reconciliation_snapshots`
- `initiating_resolution_contexts`
- `class_owner_universes`
- `symbolic_member_universes`
- `resource_key_universes`
- `context_key_applicability`
- `provider_bindings`
- `provider_equivalence_sets`
- `provider_equivalence_memberships`
- `class_definition_resolutions`
- `effective_graph_memberships`
- `symbolic_member_resolutions`
- `member_equivalence_sets`
- `member_equivalence_memberships`
- `provider_binding_deltas`
- `resource_selection_views`
- `resource_selection_deltas`
- `inline_consumption_facts`
- `business_entrypoints`
- `root_edges`
- `semantic_edges`
- `source_aliases`
- `graph_sccs`
- `graph_scc_memberships`
- `canonical_path_routes`
- `coverage_ledger`
- `incompleteness_scopes`
- `artifact_local_diff_facts`
- `analysis_disposition_ledger`
- `runtime_effective_decisions`
- `decision_snapshots`
- `authoritative_change_facts`
- `diagnostic_candidate_facts`
- `excluded_diff_evidence`
- `audit_only_records`
- `authoritative_projection_assessments`
- `projection_assessment_snapshots`
- `change_projections`
- `formal_projection_snapshots`
- `projection_trace_results`
- `change_events`（正式 projection 的兼容 active view）
- `confirmed_unprojectable_facts`（只供 completeness/report，不参加图遍历）
- `partial_projection_scopes`（fact 已有正式 projection，但仍有未覆盖 target/mechanism）
- `candidate_diagnostic_projection_plans`
- `candidate_projections`
- `candidate_projection_snapshots`
- `candidate_trace_results`（独立 namespace，不与正式 `change_events` 联表投影）

至少建立以下索引：

- symbolic target → incoming edges；
- resolved callee member → incoming edges；
- caller member → outgoing edges；
- artifact/container/class；
- base/current artifact pair、runtime scope → effective decision；
- reconciliation universe/context-key applicability → provider/member/resource binding；
- decision snapshot → active authoritative projection assessments，assessment snapshot → formal-projection snapshot，decision snapshot → candidate-projection snapshot；
- source alias → binary member。

完整图应流式写入 SQLite，不在内存中同时保留完整 `CollectorBatch`、全图对象和全部展示副本。

`change_events` 只暴露同一 active formal-projection snapshot 中、且引用同一 active assessment snapshot 的 authoritative-targetable projection；confirmed-unprojectable 引用 active unsupported assessment，candidate tables 只暴露 active candidate-projection snapshot 中的独立 decision/diagnostic-plan/projection namespace，三者不得通过 view、foreign-key cascade 或查询默认 join 混入正式目标集合。assessment/plan/projection 均可反查 immutable decision identity，但不能代替它。superseded decision/assessment/plan/projection/trace 只供审计，默认查询必须按 generation manifest 中的四层 snapshot identity 显式过滤，禁止物理删除后失去裁决历史。

#### 8.2.1 base/current provider 与 runtime topology 对账

最终制品内容相同不代表 effective provider 相同。classpath/module-path 顺序、nested layout、loader realm、parent delegation、MR target 或 module readability 变化时，必须使用同版本 resolver/schema、分别读取两侧真实 loader policy 与有序快照建立 compact runtime binding views。对账域不能只取普通 invoke/field 的 symbolic target，必须闭合四类 universe 及它们的适用关系：

1. **initiating-resolution-context universe**：由两类记录组成：a) launcher、reflection、service/resource 与受支持 semantic mechanism 中没有普通 caller 的 request/runtime-origin seed；b) raw caller 经 provider/ClassDefinitionResolution 后派生的 effective bytecode initiating context。seed 只保留 `requesting_loader_realm + requesting_module_or_unnamed + resolution_context_kind + runtime_origin`，不预写 defining loader；effective caller context 必须额外引用 caller provider/definition binding，并保留真实 `initiating_loader_realm(=caller defining loader) + initiating_module_or_unnamed + initiating_class`。无法派生唯一 effective context 的 seed/caller 也必须以 ambiguous/failed coverage 记账，不得从分母删除；
2. **class-owner universe**：base/current 完整 runtime-path inventory 中所有可暴露 owner，加上 pre-resolution 阶段已经冻结的 business-entrypoint/TypeEdge/LinkageEdge/bootstrap/class-init seed、pre-decision artifact-local raw/normalized delta obligation owner 和受支持 semantic adapter 声明的 target-independent owner；用于 provider 与 ClassDefinitionResolution 对账；不得引用后续才生成的 runtime-effective observed delta、authoritative change fact 或 projection；
3. **symbolic-member universe**：两侧 raw direct/dynamic/linkage facts 中的 exact symbolic member target，加上 pre-decision artifact-local member lineage/removal/compatibility obligation 与受支持 adapter 预声明的 target-independent member key；用于 member resolution 对账；不得引用正式 projection 或 trace 反向扩充分母；
4. **resource-key universe**：两侧完整 resource inventory 与已注册 runtime mechanism 的 logical key；用于 first/ordered-all/mechanism-specific selection 对账。

四类 universe 都必须保存构成清单、去重 identity、coverage 与 digest，并另存版本化 `context_key_applicability`，明确哪个 initiating context 适用哪个 owner/member/resource key、依据和 coverage。它们是第 8.1 节 fixed point 的最终输出：pre-resolution seed 不得伪装成 effective caller context，已解析 caller 派生的新上下文/key 必须在下一 round 全量纳入，直到收敛后才可给出 final digest。适用关系来自实际 symbolic reference、类型/链接依赖、入口/资源注册和受支持 mechanism，不允许在全部 context 与全部 key 之间做无证据笛卡尔积，也不允许只保留已知 change target 的关系。仅在 current 普通调用图中未引用的 class/resource 仍可能由 launcher、SPI、反射、配置、序列化或 agent 消费，不能从 key universe 中删除；但没有任何受支持适用 context 的物理 key 只属于 inventory/audit，不得伪造 effective binding。动态上下文或 key 发现不完整时必须降低对应 mechanism coverage；无法投影时按 confirmed-unprojectable/candidate 裁决，而不是静默遗漏。decision/projection/trace 都只能消费冻结后的 universe；如果它们发现遗漏 obligation，只能使当前 snapshot 失效并回到 pre-resolution discovery 重建，禁止把自身输出追加回输入形成闭环。每个最终适用 binding 使用以下类型化 identity 对账：

final snapshot 至少保存：

```text
pre_resolution_discovery_snapshot_identity
runtime_profile/loader/platform/support_manifest identities
target_independent_consumer/entrypoint/semantic discovery identity and coverage
fixed_point_policy/schema_version
completed_round_count
per_round_added_context/key/applicability counts and digests
initiating_context/class_owner/symbolic_member/resource_key universe identities
context_key_applicability_identity
binding/consumer/entrypoint/semantic result coverage digest
fixed_point_status = converged | limit_exceeded | incomplete | failed
final_reconciliation_snapshot_identity
```

`final_reconciliation_snapshot_identity` 只在 `converged` 且所有适用计数守恒时具有闭集资格；其他状态仍保留部分正向证据，但必须以 scoped incompleteness 阻止负向和 projection-complete 结论。该 final identity 引用 discovery input 与 resolver outputs，不得反向参与产生它的 effective-runtime-graph cache key。每个最终适用 binding 再使用以下类型化 identity 对账：

```text
initiating_loader_realm + initiating_module_or_unnamed + resolution_context_kind
             + binding_key_kind(class_owner | symbolic_member | resource_key)
             + binding_key_identity
             + base/current provider/member/resource-selection identity
             + base/current class-definition resolution（class/member 时）
             + base/current loader/resource policy identity + resolver_schema_version
```

这里的 `compact` 只表示 base 侧不物化业务路径和展示对象，不表示抽样或只解析 current 已知目标。两侧 effective class/resource inventory、loader slots 以及构造上述四个 universe/context-key 适用关系所需的 class/member/reference/entrypoint/semantic-registration facts 必须满足 support manifest 守恒；目标 JDK platform image 和容器提供库若参与 superclass/member/bootstrap/module resolution，也必须作为已绑定平台事实或经验证模型进入对应 universe。否则 provider/class-definition/resource/platform delta coverage 为 incomplete，只能进入 candidate。

结果至少区分 `unchanged | provider_changed | definition_changed | became_missing | became_resolved | ambiguous | incomplete`。`provider_changed/definition_changed/became_missing/became_resolved` 且两侧 provider/class-definition resolution coverage 完整时生成 authoritative runtime-topology/linkage fact；loader、platform/module/security policy 或任一侧闭包不完整时只能生成 `incomplete` diagnostic candidate，不能借用 `became_missing/definition_changed`。

base/current provider class bytes 相同只能证明 code fact 相同，不能把 provider delta 改成 unchanged。只有第 6.5 节 `runtime_equivalent` 证据覆盖 origin、CodeSource、签名、package/module/resource 与 loader 可观察事实时，才可在该 scope 排除 provider-origin 变化；否则至少保留 topology fact 或 candidate。

正式业务路径始终在 current 图上计算：provider delta 用于说明“本次升级改变了哪个运行时绑定”，不能把 base provider 节点作为 current 调用链的一段。对于 `provider_changed`，目标应锚定 current callsite/symbolic target 和 current provider；对于 `became_missing`，锚定仍存在该 symbolic reference 的 current caller。只重新构建 current 图而不做 base/current binding 对账，不足以裁决 runtime-topology 变化。

### 8.3 多目标反向传播

将所有 Step4 目标作为一次批量任务：

- 共享与目标无关的 predecessor transition；
- 每个 API 独立保留 descriptor、provider、match quality 和 coverage；
- predecessor transition 必须保留 edge kind 与 certainty，不能在遍历前把 exact/proven/possible 合并；
- 每条物化路径保存 `path_certainty=exact_or_proven | possible`：业务 entrypoint/RootEdge 已 proven，所有适用 caller membership、class provider、class definition 与 member resolution 均已唯一成功或满足第 6.5/6.5.1 节 scope-local `runtime_equivalent`，dispatch/dynamic/bootstrap/class-init/linkage/inline/semantic 边均为 exact/proven，且路径不经过未建模 transformer 可改写 scope 时才是前者。业务根或任一边只是已穷举 possible/ambiguous 时是后者；不可穷举 unresolved 只降低 coverage，不物化猜测路径。`possible` path 的 `path_status` 必须为 `uncertain`，不能与 exact reachable 路径去重合并；
- 路径枚举与“是否至少存在一条路径”分开；
- 先按完整物理 node/typed-edge identity 和 certainty 分层计算 strongly connected components，再在 SCC-condensed DAG 上枚举 canonical root→target route。路径 identity 由 root、有序 SCC/node/edge identity、target 和 trace policy 组成；每个非平凡 SCC 保存成员、内部边、入/出口和至少一条可复核 witness，不把递归循环展开成无限 walk。`*_path_set_complete=true` 表示该 certainty 分层下所有 canonical condensed routes 已处理且每个 SCC 的适用成员/边 coverage 完整，不表示枚举了运行时循环次数的所有组合；
- exact layer 只包含 exact/proven 边；possible layer 允许 exact/proven 边作为前后缀，但每条 possible route 必须至少包含一条 possible/ambiguous 边或 possible root。纯 exact route 不在 possible layer 重复计数，两层各自建 SCC/digest，禁止先混合 certainty 再压缩而把 possible cycle 污染为 exact；
- possible layer 的“适用”不以当前是否已经物化 possible edge 为唯一条件：任一 `partial_possible_set`、可能新增 route 的 unresolved dispatch/semantic/entrypoint frontier 或 possible root 都使该层适用。已知 target 为空但存在 unknown remainder 时，必须写 `possible_path_set_complete=false`，不能按空集合真值声称完整。某个缺口只有在证据语义上可能补充 exact/proven route 时才同时令 `exact_path_set_complete=false`；例如仅未知 receiver 余量不会把未证明 receiver 自动变成 exact，但未完成的 proven-entrypoint/receiver verifier 可能影响两层。每个 completeness=false 都必须引用具体 frontier/evidence scope；
- 达到确定性的高扇出/输出 cap 后允许停止路径物化，但必须分别记录 `exact_path_set_complete`、`possible_path_set_complete`、`path_enumeration_limit`、`exact_materialized_path_count`、`possible_materialized_path_count`、兼容 `materialized_path_count` 和 `truncation_frontier`。总数必须等于两个 certainty 分层计数之和。兼容 `path_set_complete` 是两个适用 certainty 分层完整性的逻辑与，任一层被截断都必须为 false；不得丢失已经证明存在的路径，也不得静默删路径后仍宣称完整。

正式 projection 的 exact layer 恒为适用；possible layer 必须显式保存 `possible_path_layer_applicable` 和 `possible_layer_applicability_scopes[]`。只有已证明没有 possible root/edge/frontier，且相关 dispatch/entrypoint/semantic/dynamic/inline 能力对该 target 覆盖完整时才能写 false；不得由 `possible_path_exists=false` 反推不适用。兼容字段的唯一派生式为：

```text
path_set_complete
  = exact_path_set_complete
  AND (NOT possible_path_layer_applicable OR possible_path_set_complete)
```

`possible_path_layer_applicable=false` 时 applicability scopes 必须为空、possible path 数必须为 0，并统一将 `possible_path_set_complete=true` 作为序列化规范值；该 true 不是“已搜索 possible 闭包”的证据，且该层不参与 completeness 分母。值为 true 时至少有一个可重算适用理由，且 `possible_path_set_complete=false` 必须引用对应 frontier/incompleteness scope。

#### 8.3.1 未裁决差异的独立触达分析

`diagnostic_candidate_facts[]` 与 authoritative-targetable projections 共享同一 immutable binary graph 和 provider/class-definition/member-resolution/dispatch 事实，但必须使用独立 projection/task namespace、结果 schema 和统计口径。每个 candidate 先有 plan record，即使 target 数为 0 也存在：

```text
candidate_fact_id
candidate_reason
candidate_projection_plan_identity
diagnostic_projection_planning_registry_identity
diagnostic_target_status
diagnostic_projection_coverage_status
candidate_bound_target_count
candidate_projection_obligation_count
candidate_projection_obligation_set_digest
candidate_unbound_target_scopes
```

plan 核心记录不反向包含 generation；进入 active candidate report 时，publication attachment 另行记录 `result_generation_identity + active_decision_snapshot_identity + active_candidate_projection_snapshot_identity`。

只有 targetable plan 才生成一条或多条 projection result：

```text
candidate_projection_plan_identity
candidate_projection_obligation_key
diagnostic_projection_rule_contract_identity
diagnostic_projection_rule_implementation_version
candidate_projection_identity
candidate_target_identity
result_generation_identity
active_decision_snapshot_identity
active_candidate_projection_snapshot_identity
candidate_reachability_status = reachable | uncertain | not_found_in_static_analysis | not_analyzed
candidate_best_path_certainty = exact_or_proven | possible | none
candidate_exact_path_exists
candidate_possible_path_exists
candidate_exact_path_set_complete
candidate_possible_path_set_complete
candidate_possible_path_layer_applicable
candidate_possible_layer_applicability_scopes
candidate_path_set_complete
candidate_exact_materialized_path_count
candidate_possible_materialized_path_count
candidate_materialized_path_count
candidate_failure_scope
candidate_paths
```

plan-level target discovery 与 projection-level path completeness 必须分开：前者说明候选 target 是否全量绑定，后者说明某个已绑定 target 的路径是否全量枚举。candidate 的三个 path completeness 字段与正式 projection 使用同一适用性公式，只是 namespace 不同；`candidate_materialized_path_count` 也必须等于 exact/possible 两个分层计数之和。不得因 candidate 不进入正式影响统计就省略 unbound target scope、possible-layer frontier 或伪造完整。

处理规则：

- 每个 active candidate decision 必须先生成且只生成一个 active diagnostic plan；targetable plan 的每个 exact target 必须批量执行诊断反向传播，不能因为不是正式变化目标而跳过；unbound plan 必须保留完整/部分/失败 coverage 和 scoped reason；
- candidate reachable 只说明“未裁决二进制差异可触达业务”，不得投影为 `probable_impact`、`confirmed_impact` 或正式 `reachable`；
- candidate uncertain 表示只存在从业务根到 target 的完整 possible dispatch/receiver/semantic path，不得与 candidate reachable 合并；依赖内部片段只记诊断证据；
- candidate 静态未命中只有在相关 entrypoint/root/direct/class-provider/class-definition/member-resolution/dispatch/dynamic/class-init/linkage/inline/semantic coverage 完整时才能记录，但不能据此把差异裁决为噪声；
- target 无法绑定、图覆盖失败，或在找到任一完整 exact/possible 路径前闭包就截断时，使用 candidate 专属 `not_analyzed`/coverage 字段，不得增加正式 `not_analyzed_count`。若截断前已存在完整路径，必须保留 candidate reachable/uncertain 并将对应 path-set completeness 置 false；
- 后续证据将 diagnostic candidate decision 升级为 authoritative 或降级为 excluded 时，必须生成新的 decision digest；若升级后 targetable，再生成新的正式 assessment/projection identity。旧 candidate decision/diagnostic-plan/projection/trace 标记 `superseded_by` 并退出 active view，但必须保留审计，禁止删除或原地改写。禁止同一 active decision 同时出现在两个事实通道。
- candidate trace 结果只能使用 `candidate_reachability_status`；任何 formatter 或兼容适配器都不得把该字段复制到正式 `reachability_status/analysis_status`。

这样既不会把噪声误报为变化，也不会让尚未识别出的真正变化从分析系统中消失。

### 8.4 源码覆盖层

Tree-sitter/现有源码解析器继续运行，并非“没有用了”；它从 direct-call authority 降为 source/semantic overlay 引擎。其输出不能覆盖 ASM/JVM 事实，但仍承担以下职责：

- 为二进制 member 补充 repo、commit、module、file、line 和可读签名；
- 提供注解、泛型和源码专属语义；
- 为 framework/reflection/resource adapter 提供候选；
- 记录源码与制品冲突。

源码中存在但最终制品中不存在的 JVM 直接调用，不得写入 authoritative direct graph，也不得改名为 semantic edge“救活”；它只能作为 `source_artifact_conflict` 或人工提示保留。

SOURCE-retention annotation、源码泛型或其他 source-only 元数据只能解释生成 provenance 或产生 semantic candidate；只有最终 class/resource/registration 中存在独立运行时激活证据时才可能进入可信 semantic path。编译期处理器若据此生成代码，其影响按生成后的 effective 二进制事实裁决，不把原 annotation 伪装成运行时消费者。

源码解析器可以为框架、反射或配置机制提供候选，但 semantic path 只有同时满足以下条件才能参与 authoritative `reachable` 裁决：

1. 候选属于明确的 framework/reflection/resource 机制，不是把 source-only direct call 重新分类；
2. 激活证据独立于产生候选的源码文本；
3. 两端均绑定 current artifact member、resource 或明确 runtime instance；
4. 完整路径能够回到业务入口；
5. 路径上的每条 semantic edge 都有 edge-local verifier 证明候选、激活、端点、provider 与 class-definition eligibility；若依赖 receiver/dispatch，则其 certainty 也必须为 exact/proven。

单条 semantic edge 或单个激活事实本身不能证明业务触达；它只能作为完整证据路径的一部分。

这里的 semantic candidate 是“边/激活尚未证明”，不是第 7.1 节 `diagnostic_candidate_fact`。对于 authoritative change，它最多贡献 `possible_path_exists/uncertain`；对于 diagnostic candidate fact，它进入 candidate 专属追踪。字段、表和统计必须使用 `semantic_edge_status` 与 `candidate_fact_status` 分名，禁止把两类 candidate 混成一个通道。

正向存在性与覆盖闭集必须分离：一条 edge-local 已验证的完整路径即使同一 mechanism 的全局枚举 coverage 不完整，也可以证明该路径存在，但必须设置 `path_set_complete=false`。全局或目标相关 capability coverage 完整只用于输出 `not_found_in_static_analysis`、声明路径集合完整或排除未知 semantic path；不得用无关区域的 coverage 缺口删除已经验证的正向路径，也不得用一条正向路径反推该 mechanism 已完整覆盖。

候选证据和激活证据不得是同一条源码断言；`SOURCE_AST` / `SOURCE_INDIRECT_INFERENCE` 单独不能设置 reachability-eligible activation。当前 `_collected_indirect_edge()` 会同时用 `SOURCE_INDIRECT_INFERENCE` 生成 semantic candidate 和 `activation_verified=true`，这是待修正的自证缺口：[`indirect_usage_analyzer.py`](../../scripts/indirect_usage_analyzer.py#L913)。

当前最终制品门禁还把所有 semantic edge 交给 framework 专用 `_verified_composite_framework_projection()`，普通 reflection/resource edge 没有通用机制级校验路径：[`confidence_weighted_tracer.py`](../../scripts/confidence_weighted_tracer.py#L9826)。目标实现必须引入 mechanism-specific eligibility verifier；每类 verifier 分别校验候选/激活独立性、current artifact 端点、provider、activation condition 和 coverage，不能只把 collector 输出落库就视为可达。

### 8.5 无源码路径展示

没有 exact source alias 时，路径仍必须可复核：

```text
artifact-or-container!/class-entry :: owner.member(descriptor) @ bci
```

有 exact alias 时，再附加源码文件和行号。可读性缺失不等于证据缺失。

## 9. 结果状态模型

### 9.1 正式结果的四个正交维度

三值变化裁决发生在第 7.1 节的三条互斥数据通道中；本节四维状态只适用于 `authoritative + active projection assessment.analysis_projection_status=targetable` 的正式目标。assessment 的 `projection_coverage_status=partial` 不删除已经建立的正式 projection/`by_api` 状态，但必须降低总体完整性并保留未投影 scope；candidate、excluded 和 confirmed-unprojectable 都没有正式 `by_api` 结果，因此不存在它们的正式 reachability/impact 组合。

#### `change_fact_status`

正式结果固定为：

- `confirmed`

变化种类由独立 `change_kind` 表达。`excluded` 只存在于 `excluded_diff_evidence.exclusion_status`；`candidate/incomplete` 只存在于 `diagnostic_candidate_facts.candidate_fact_status`。若正式 `by_api.change_fact_status` 不是 `confirmed`，写出端必须合同失败。

#### `reachability_status`

- `reachable`
- `uncertain`
- `not_found_in_static_analysis`
- `not_analyzed`

状态语义固定为：

- `reachable`：至少存在一条从业务入口到目标的完整静态证据路径，路径上的 class provider、class definition 与 member resolution 唯一成功或满足 scope-local `runtime_equivalent`，dispatch、dynamic/inline binding 和 semantic activation 均为 exact/proven；
- `uncertain`：至少存在一条从 proven/possible 业务根连续到目标的完整可能路径，但包含 `possible` dispatch、未收敛 receiver 或其他不能升级为 exact/proven 的边；仅有依赖内部边片段而没有回到业务根，不是 possible path；
- `not_found_in_static_analysis`：支持范围内未找到 exact 或 possible path，且目标相关 entrypoint/root/direct/class-provider/class-definition/member-resolution/dispatch/dynamic/class-init/linkage/inline/semantic coverage 完整；
- `not_analyzed`：authoritative target 已建立，但完成有效路径分析所需的目标绑定、解析或覆盖失败。

本节的 `reachable` 是“从已启用业务根到变化目标的静态结构路径存在性已证明”，不是路径条件可满足性、某次请求实际执行或业务输出已变的证明。这正是其与 `impact_conclusion=probable_impact` 及 `runtime_verification_status=required_not_executed` 分开的原因。

没有调用/链接路径语义的 confirmed fact 必须是 `analysis_projection_status=unsupported` 或进入独立审计 schema，不得用正式 `reachability_status=not_applicable` 回避本应执行的追踪。

#### `impact_conclusion`

- `probable_impact`
- `inconclusive`

`confirmed_impact` 和 `confirmed_no_impact` 在当前静态分析 v2 中均为禁止写出值。系统没有执行被分析业务的运行测试或取得等价运行证据，静态可达不能证明业务分支实际执行，静态未命中或符号保留也不能证明业务绝对无影响。未来若接入可信运行证据，必须升级结果 schema 后再引入这两个值。

结构/链接事实使用独立字段表达，不挤入业务影响结论：

```text
static_linkage_status = not_applicable
                      | compatible_in_supported_scope
                      | incompatible_if_executed
                      | ambiguous
provider_transition_status = not_applicable
                           | unchanged
                           | changed_compatible
                           | changed_incompatible
                           | ambiguous
dispatch_certainty   = exact_or_proven | possible | unresolved | not_applicable
best_path_certainty  = exact_or_proven | possible | none
```

这里的 `dispatch_certainty` 是正式 projection/API 的最佳路径汇总字段，不是第 6.6 节的 edge 枚举：最佳路径不含 virtual/interface dispatch 时为 `not_applicable`；其全部 dispatch edge 均为 `exact/proven_receiver` 时为 `exact_or_proven`；至少一条已物化最佳可能路径含 `possible/ambiguous` dispatch 时为 `possible`；适用 virtual/interface dispatch 因 hierarchy/receiver 失败而无法裁决时为 `unresolved`。class provider、class definition 或 member resolution 失败由各自字段表达，不能误写成 dispatch failure。`best_path_certainty` 对 reachable/uncertain/no materialized path 分别为 `exact_or_proven/possible/none`。其他可能路径是否存在由 `possible_path_exists` 单独记录，不能把存在 exact path 且另有 possible path 的结果降级。

`provider_transition_status` 只汇总 base/current provider/topology 对账：非 topology projection 为 `not_applicable`；两侧 binding 相同为 `unchanged`；provider/origin 改变但 current class-definition/member linkage 成功为 `changed_compatible`；改变并由独立解析事实证明 current 失败为 `changed_incompatible`；任一侧选择/定义/对账未收敛为 `ambiguous`。若完整 `runtime_equivalent` 已证明所有 provider 可观察事实相同，则该 delta 在上游 excluded，不生成带 `unchanged` 的形式化占位 projection。`changed_incompatible` 必须与 `static_linkage_status=incompatible_if_executed` 一致，`changed_compatible` 必须与 `compatible_in_supported_scope` 一致；非法组合写出时合同失败。

#### `runtime_verification_status`

- `required_not_executed`
- `undetermined`

当前系统不执行运行测试，因此不得生成表示测试已通过或失败的 verification 状态。

- `required_not_executed`：authoritative 变化与 exact/proven 业务触达均已确认，但实际业务后果尚未验证；实现变化和“执行时必然发生链接错误”的结构变化都使用该值；
- `undetermined`：触达为 uncertain/not-found/not-analyzed，或当前无法安全决定如何进行运行验证；

历史 `not_required` 不属于 v2 正式 `by_api` 枚举；只允许旧结果读取器保留在 `legacy_runtime_verification_status`，或由不表达业务影响的独立审计 schema 使用。v2 写出端不得用它暗示“无需测试”或“已无影响”。

v2 组合不变量：

- `required_not_executed` 当且仅当正式 `change_fact_status=confirmed`、`reachability_status=reachable`、路径 certainty 为 exact/proven 且 `impact_conclusion=probable_impact`；
- `impact_conclusion=probable_impact` 当且仅当 `reachability_status=reachable`；`uncertain/not_found_in_static_analysis/not_analyzed` 必须为 `inconclusive`；
- `uncertain/not_found_in_static_analysis/not_analyzed` 对应的 verification 必须为 `undetermined`；
- candidate/incomplete 没有本四维状态，只能使用 candidate 专属 schema；
- `static_linkage_status=incompatible_if_executed` 只确认“若执行则发生静态链接后果”，不能生成 `confirmed_impact`；存在 exact/proven 业务路径时仍为 `probable_impact + required_not_executed`；
- `confirmed_impact`、`confirmed_no_impact` 或正式 `by_api.runtime_verification_status=not_required` 出现时必须合同失败；
- 当前两个正式状态的 `runtime_verification_executed_by_system` 均为 `false`、evidence 均为空；未来若接入真正的运行验证，必须升级 schema，不能复用 v2 值伪装 passed/failed。

附加完整性字段：

```text
existence_proven
exact_path_exists
possible_path_exists
exact_path_set_complete
possible_path_set_complete
possible_path_layer_applicable
possible_layer_applicability_scopes
path_set_complete
entrypoint_coverage
direct_graph_coverage
semantic_coverage
provider_resolution_status
class_definition_status
class_definition_coverage
loader_resolution_coverage
member_resolution_coverage
dispatch_certainty
static_linkage_status
dynamic_linkage_coverage
class_init_coverage
inline_consumption_coverage
source_mapping_status
```

`existence_proven` 是 `exact_path_exists` 的兼容别名，只能在存在 exact/proven 完整路径时为 true；possible dispatch path 使用 `possible_path_exists=true`，不得把兼容字段设为 true。完整性分别由 `exact_path_set_complete/possible_path_set_complete` 表达；possible 层是否进入分母必须由 `possible_path_layer_applicable` 和可重算 scopes 明示，兼容 `path_set_complete` 只能按第 8.3 节公式派生，不改变单条路径的 certainty 或已证明的存在性。

candidate 的 `incomplete` 表示建立 authoritative 变化事实所需的适用二进制证据失败或覆盖不完整；不能用源码候选把它升级为 `confirmed`，也不能因此创建一个正式 `by_api` 占位结果。

### 9.2 裁决矩阵

| 变化事实 | 业务触达 | 覆盖 | 目标结论 |
|---|---|---|---|
| `checkout_build` 构建或制品定位失败 | 不适用 | 运行级阻塞 | Step1 失败；不切换输入模式，不进入 Step4/Step5/Step6 |
| `provided_artifact` 成对产物校验失败 | 不适用 | 运行级阻塞 | Step1 失败；不进入 Step4/Step5/Step6 |
| 结构/链接不兼容已确认 | exact/proven `reachable` | 路径可信 | `static_linkage_status=incompatible_if_executed`、`probable_impact`、`required_not_executed`；不得写 confirmed impact |
| 发布实现变化已确认 | exact/proven `reachable` | 路径可信 | `probable_impact`，`required_not_executed`；显示“已确认触达变化实现，可能受影响，需运行时验证” |
| 发布实现或结构变化已确认 | 仅存在 possible dispatch/receiver 路径 | 路径结构合法但实现未证明 | `reachability_status=uncertain`、`dispatch_certainty=possible`、`impact_conclusion=inconclusive`、verification=`undetermined` |
| authoritative 变化与 exact target 已建立 | 目标绑定、class/provider definition、member resolution 或图构建失败 | 部分/失败 | `reachability_status=not_analyzed`、`impact_conclusion=inconclusive`、verification=`undetermined` |
| 变化已确认 | 仅命中依赖内部边片段、未回到业务根 | 目标相关闭包完整 | `not_found_in_static_analysis + inconclusive + undetermined`；另保留 `dependency_local_evidence` 诊断，不伪造 possible path |
| 变化已确认 | 仅命中依赖内部边片段、未回到业务根 | 入口/图/语义闭包部分或失败 | `not_analyzed + inconclusive + undetermined`；保留 failure scope 和局部证据 |
| 变化已确认 | 未找到 exact 或 possible 路径 | 目标相关 entrypoint/root/direct/class-provider/class-definition/member-resolution/dispatch/dynamic/class-init/linkage/inline/semantic coverage 完整 | `not_found_in_static_analysis` + `impact_conclusion=inconclusive` + verification=`undetermined`；只表示支持范围内静态未命中 |
| 变化已确认 | 未找到 exact 路径，但存在 possible/未证明路径 | exact coverage 不完整或 certainty 未收敛 | `uncertain`；若连 possible evidence 也不存在且 coverage 失败则为 `not_analyzed` |
| artifact-local removed 符号在 current effective view 仍有兼容 provider | 不得作为正式 removal 进入本矩阵 | 这是 runtime-effective gate 的上游裁决 | base/current effective member 与 provider 可观察事实全等价时 exclusion；provider/origin 改变时建 provider/topology fact，并按证据写 `provider_transition_status=changed_compatible\|changed_incompatible`，选择证据不完整时 candidate。兼容替换的 `static_linkage_status=compatible_in_supported_scope`，不能与 effective removal fact 共存 |
| 至少一条 exact/proven 可信路径存在 | `reachable` | 其他路径区域不完整 | 保持触达结论，`path_set_complete=false`；不能声称完整枚举所有入口 |

candidate 使用独立裁决矩阵，不生成上述正式字段：

| candidate 条件 | 诊断结论 | 正式结果影响 |
|---|---|---|
| exact target 可绑定且存在 exact/proven 路径 | `candidate_reachability_status=reachable` | 无正式 API、无正式 reachable/probable 计数 |
| 仅存在 possible path | `candidate_reachability_status=uncertain` | 无正式结果 |
| 未找到路径且目标相关 coverage 完整 | `candidate_reachability_status=not_found_in_static_analysis` | 不能据此排除 candidate |
| target 无法绑定或 coverage 失败 | `candidate_reachability_status=not_analyzed` + scoped reason | 无正式 not_analyzed 计数 |

### 9.3 `not_analyzed` 的唯一语义

`not_analyzed` 仅表示完成有效分析所需的关键证据不可用或覆盖不完整，例如：

- Step4 authoritative 变化事实已经建立，但其 exact target 无法绑定到 current graph instance，导致有效可达性分析不能执行；
- 目标相关 artifact/class 解析失败，且尚无可信存在性路径；
- target JDK 缺失，导致目标相关 MR-JAR variant 无法选择；
- provider 或 class definition 无法解析且影响目标裁决；
- 负向闭包查询在找到可信路径前被截断；
- 适用于该 API 的关键语义能力失败，且没有其他可信路径完成存在性证明。
- dynamic callsite、class-init、inline consumption 或 loader/class-provider/class-definition/member-resolution coverage 失败，且没有其他 exact/proven 路径完成存在性证明。
- 目标或路径可能被未建模 runtime transformer/agent/plugin 增删改，且既没有 SHA 绑定的变换后 class，也没有受支持模型证明 pre-transform 路径仍是合法可能性。

不得因为“已经确认触达，但实际行为后果尚未验证”使用 `not_analyzed`。

Step4 差异本身仍为 candidate/incomplete 时不适用本状态：它进入 candidate report，而不是创建正式 `not_analyzed` API。正式分析失败和变化裁决未完成必须保持两个独立通道。

### 9.4 Projection 到 `by_api` 的聚合与兼容规则

正式状态先在每个 `projection_identity` 上裁决，再聚合到 `reported_api_identity`。一个 API 的多个 change fact、loader realm、provider 或 consumer target 不得先去重再追踪。`by_api` 至少保留 `contributing_projection_ids[]`、每个 projection 的 change kind/状态、failure scope 和路径引用。

聚合优先级固定为：

1. 任一 active projection 存在 exact/proven 完整路径：API 为 `reachable`，`exact_path_exists=true`；其他 projection 的 possible path 或失败继续保留，且只要任一相关路径集合/coverage 不完整，聚合 `path_set_complete=false`。
2. 没有 exact/proven 路径，但任一 projection 存在 possible 路径：API 为 `uncertain`，`possible_path_exists=true`；其他失败仍保留，不能用 possible evidence 掩盖 coverage 缺口。
3. 没有 exact/possible 路径，且任一 active projection 绑定、解析或覆盖失败：API 为 `not_analyzed`。
4. 只有所有 active projections 均完成目标相关负向闭包且都未找到路径时，API 才能为 `not_found_in_static_analysis`。

因此，正向存在性优先于其他区域的失败，但不会把 path set 或 coverage 伪装成完整。聚合后的 `impact_conclusion/runtime_verification_status` 仍严格由第 9.1 节 truth table 派生。`static_linkage_status`、provider delta 和不同 change kind 的细节必须保留 per-projection；API 层若提供摘要，只能使用版本化严重度规则，并不得删除未选为主摘要的子结果。

聚合 `best_path_certainty` 按 `exact_or_proven > possible > none` 选择。API 级 `dispatch_certainty` 只描述被选中的 best/primary path：该路径没有 virtual/interface edge 时为 `not_applicable`；其他 projection 的 unresolved/possible dispatch 必须留在子结果，不能覆盖一条已经 exact 的无 dispatch 路径，也不能被它隐藏。

API 级路径完整性不能只取 primary projection，必须按 contributing projections 守恒聚合：

```text
by_api.exact_path_set_complete
  = AND(all contributing projection exact_path_set_complete)
by_api.possible_path_layer_applicable
  = OR(all contributing projection possible_path_layer_applicable)
by_api.possible_layer_applicability_scopes
  = canonical union(all applicable projection scopes)
by_api.possible_path_set_complete
  = AND(projection.possible_path_set_complete
        for every projection where possible_path_layer_applicable=true)
by_api.path_set_complete
  = by_api.exact_path_set_complete
    AND (NOT by_api.possible_path_layer_applicable
         OR by_api.possible_path_set_complete)
```

空的 applicable-projection 集只使 `by_api.possible_path_layer_applicable=false`，不得用空集合的 AND 结果伪造“possible 闭包已验证”证据。

primary projection/path 的排序必须由版本化 `trace_policy_identity` 固定：先按 certainty，再按声明的 linkage/severity 规则、canonical SCC-condensed route 边数和 canonical identity 稳定排序；不得用某个任意 SCC witness 的展开长度改变 primary。并列时禁止依赖 SQLite row id、线程完成顺序或 hash-map 遍历顺序。primary 只服务摘要，不影响计数或保留哪些 projection/path。

candidate 采用同样的存在性/失败聚合顺序，但只在 `candidate_projection_identity` 范围内生成 candidate 专属状态，绝不参与正式 API 聚合。

迁移期间保留现有 `analysis_status`，但其职责收敛为 `reachability_status` 的兼容投影。对于“已确认触达变化实现”场景：

```text
analysis_status                         = reachable
is_reachable                            = true
reachability_status                     = reachable
impact_conclusion                       = probable_impact
decision_bucket                         = probable_impact
runtime_verification_status             = required_not_executed
runtime_verification_executed_by_system = false
runtime_verification_evidence           = []
best_path_certainty                     = exact_or_proven
```

该兼容组合中的 `dispatch_certainty` 仍按路径适用性写 `exact_or_proven` 或 `not_applicable`，不影响 `best_path_certainty=exact_or_proven`。

所有已确认的调用路径继续保持 `path_status=reachable`、`complete=true`，不得把验证要求写成路径 `stop_reason`，也不得生成 blocking `EvidenceFailure`。

Step6 和所有内置消费者必须在同一变更中改为：

- 使用 `reachability_status` 展示调用链事实；
- 使用 `impact_conclusion` 生成“可能影响/当前无法确认”等用户结论；当前静态 v2 不生成“已确认影响/已确认无影响”；
- 使用 `runtime_verification_status` 展示尚未执行的后续验证要求；
- 不再从 `analysis_status=reachable` 单独推导 `confirmed_impact`。

三组 API 聚合汇总必须分别闭合，不能跨轴相加：

- `reachability_summary`：每个正式 API 恰好进入一个 reachability 状态；
- `impact_summary`：每个正式 API 恰好进入一个 impact conclusion；
- `runtime_verification_summary`：每个正式 API 恰好进入一个 verification 状态。

因此同一 API 可以同时贡献 `reachable=1` 和 `probable_impact=1`，但它不会进入 `not_analyzed`。每一轴的计数之和分别等于 `unique_reported_api_total`；不同轴的计数禁止相加为总数。另设 `formal_projection_total` 与 per-projection 状态守恒，不能把 projection 总数和 API 总数混用。兼容输出若暂时保留 `confirmed_impact_count/confirmed_no_impact_count`，v2 值必须恒为 0，并标记 deprecated，不能从静态结构或可达性派生。

Step6 的主明细先按 `impact_conclusion` 唯一分区，再在分区内按 P0/P1/P2 展示 severity，并把 `reachability_status` 作为调用链事实列。`by_module` 和依赖汇总在每一轴内按 API identity 去重；禁止因同一 API 同时具有 reachable 和 probable 两个正交属性而复制到 confirmed-impact 或 not-analyzed 明细。

兼容读取旧 v1 结果时，可以将历史组合

```text
change_type=BEHAVIOR_CHANGED
analysis_status=not_analyzed
reason_code=BEHAVIOR_CHANGED_RUNTIME_VERIFICATION
```

不能仅凭这三个旧字段自动升级。只读迁移器只有在旧证据中还能同时恢复以下事实时，才允许生成本节的新复合状态：

1. old/current 最终制品证据能够确认同一 JVM member 的实现变化；
2. current 最终制品路径具有 proven business entrypoint/RootEdge、精确 descriptor、artifact SHA/entry/class-provider/class-definition/member-resolution 绑定；
3. 路径上的 dispatch、dynamic/inline binding 和 semantic activation 均可恢复为 exact/proven；
4. 对应 `ReachabilityPath.complete=true`，且没有把 verification reason 当作 blocking failure。

否则保留原 `legacy_source_status`，输出 `impact_conclusion=inconclusive`，不得伪造 `reachable` 或 `probable_impact`。v2 写出端不得继续输出旧矛盾组合；v2 缺少必填字段或出现非法组合时必须合同失败，不能猜测。

其他兼容投影固定为：`uncertain -> uncertain`、`not_found_in_static_analysis -> not_found_in_static_analysis`、`not_analyzed -> not_analyzed`。现有 `analysis_status=not_impacted` 只能保留为 `legacy_source_status`，v2 读取器将业务影响投影为 `inconclusive`；不得自动迁移成 `confirmed_no_impact` 或解释成业务不可达。迁移窗口结束后应由消费者直接读取正交字段。

`summary.json`、`by_api` 和查询索引应增加 schema/version 标识。新增字段优先进入 JSON；`alerts.csv` 只在全部内置消费者完成兼容测试后尾部追加字段，不删除或重排已有列。`analysis_status` 收敛为可达性投影是必须由 v2 schema 明示的语义变化，不能伪装成无兼容影响。

这是一次有意的语义纠正，不可能让“只看 `analysis_status=reachable` 就认定已确认影响”的旧第三方消费者同时保持原判断。切换前必须完成消费者清单和契约测试；兼容窗口内如需旧输出，只能由整次 `legacy` 运行单独生成，不能在同一份 v2 结果中写入矛盾状态。

## 10. 对最终分析结果准确性的影响

### 10.1 明确结论

本设计的准确性收益不是“产生更多确定结果”，而是让每种确定性与证据能力一致：

- 真实制品边不再受源码节点约束，降低实际受影响却未发现的假阴性。
- 仅有源码直接调用、但 current 最终制品没有对应 JVM 指令的关系不再冒充发布制品事实，降低错误影响路径的假阳性。
- 经当前 AnalysisScope 证明不可观察的 JAR 容器噪声和安全白名单 classfile 表示差异不再冒充实现变化，降低由重打包或编码布局造成的假阳性；调试属性变化始终单独记账，并按诊断可观察 scope 裁决，不能混入该白名单。
- LICENSE/NOTICE/SBOM/随包文档等只在版本化分类、AnalysisScope 与 exact-key consumer 三重门禁都完整时作为 distribution audit metadata 排除，避免它们统一落入 unknown candidate；可被运行时读取的 `pom.properties`/索引/自定义资源不会被文件名白名单误排除。
- 运行时资源、拓扑和反射/框架可消费元数据不会被“非代码改动”统一过滤，避免漏掉真实发布语义变化。
- Lombok、annotation processor 和 ERM/Schema/IDL 等编译期生成代码按最终 class 与手写代码等价比较，避免源码未变或生成源码缺失造成的漏报。
- 经证明不改变运行时事实的容器、classfile 和 build/diagnostic 噪声不会进入 Step4 目标及最终影响计数；runtime-effective contract、IR、运行时可消费 metadata/resource/topology 变化的错误排除数必须为 0。
- artifact-local 差异必须先与 base/current effective provider/resource view 对账：被遮蔽或未选择实例的变化只留审计，实际 effective 事实变化不能因坐标、文件名或错误配对被漏掉。
- 编译环境差异只有在独立证明为运行时等价时才排除；严格疑似但未证明的差异隔离在诊断 sidecar，不生成受影响 API 或正式计数。
- 三值变化裁决避免在证据不足时猜测：candidate 不冒充变化或噪声，但必须完成独立触达分析并显式暴露，兼顾 confirmed 结果精度与潜在变化召回。
- confirmed-unprojectable 将“变化已确认”和“当前没有可信影响 target”分开，避免把真实 metadata/native/topology 变化误降成 candidate，也避免为追踪而伪造 API 调用链。
- 完整 provider/descriptor 身份减少同名类和重载串线。
- exact/proven 与 possible dispatch 分开，避免把所有接口/虚调用实现都误写成已确认触达。
- class-init、dynamic/condy/bootstrap、inline consumption 和 base/current provider delta 独立建模，避免普通 invoke 图之外的运行时事实被静默漏掉。
- 负向结论受 coverage ledger 约束，降低把分析缺口误写成静态未命中的风险。
- 实现变化、静态触达、静态链接状态与业务后果分开，避免把 `not_analyzed`、`reachable` 和业务影响混成单一状态。

### 10.2 预期状态迁移

| 当前结果 | 新结果可能变化 | 准确性含义 |
|---|---|---|
| `BYTECODE_CALLER_UNRESOLVED / not_analyzed` | exact/proven path 为 `reachable`；possible dispatch 为 `uncertain` | 补回真实路径且不夸大分派确定性 |
| 因缺源码无法判断 | `reachable`、`uncertain` 或可信 `not_found_in_static_analysis` | 源码不再是二进制事实前提，certainty 仍由二进制路径决定 |
| 运行时依赖命中但业务回路缺失 | 找到 exact/proven 业务入口后为 `reachable`；找到完整 possible 业务路径才为 `uncertain` | 只有依赖内部片段不是路径；闭包完整时为静态未命中，不完整时为 not-analyzed |
| 仅靠源码 direct call 形成的 `reachable` | 删除该假路径并记 conflict；若无其他路径，闭包完整为 `not_found_in_static_analysis`，不完整为 `not_analyzed` | 只有独立证据建成的 possible semantic/runtime path 才能为 `uncertain`；source direct call 自身不能转换成 semantic edge |
| 已验证的 framework/reflection/resource semantic path | 保持或升级为 `reachable` | 必须满足第 8.4 节全部条件，不能由单条候选边单独证明 |
| 图不完整但当前输出静态未命中 | `not_analyzed` | 暴露证据缺口，纠正假阴性风险 |
| `BEHAVIOR_CHANGED + exact/proven 完整路径 -> not_analyzed` | `reachable + probable_impact + required_not_executed` | 同时保留触达事实和行为不确定性 |
| virtual/interface possible implementation 被当成 reachable | `uncertain + dispatch_certainty=possible` | 删除分派过度确认造成的假阳性 |
| `<clinit>`、condy/bootstrap 变化但普通 invoke 图无边 | 通过 class-init/bootstrap linkage path 裁决 | 补回 JVM 隐式运行关系；coverage 不完整时不输出静态未命中 |
| 编译期常量/inline consumer 无 symbolic reference | proven inline edge 或 possible inline path | 不用字面量猜边；possible 只形成 uncertain，也不静默漏掉内联风险 |
| JAR 内容相同但 loader/classpath 顺序改变 provider | provider/runtime-topology change 或 candidate | 识别最终运行时绑定变化 |
| 仅 JAR SHA、时间戳、顺序或压缩结果不同，且当前 scope 不观察 raw archive、无可信消费者 | `excluded + packaging_noise_only` | 删除该分析 context 内非运行时容器差异造成的假实现变化；其他 scope 重新裁决 |
| 仅 scope-local 安全白名单 classfile 属性不同，且当前 scope 不观察 raw classfile、无可信消费者 | `excluded + classfile_noise_only` | 从本 context 的 Step4 目标和影响结果排除，保留 raw 审计证据；其他 scope 重新裁决 |
| 受控复现证明仅由编译环境产生且运行时事实等价 | `excluded + BUILD_ENVIRONMENT_REPRODUCED_NOISE_ONLY` | 消除编译环境噪声，不进入正式分析 |
| same-input 输出不同但独立证明属于等价非确定构建变体 | `excluded + BUILD_NONDETERMINISM_REPRODUCED_NOISE_ONLY` | 消除 clock/random/order/parallelism 构建噪声；无独立证明时只能 candidate |
| 满足严格环境疑似条件但尚未证明等价 | `diagnostic_only + candidate` | 仅进入诊断 sidecar，不产生受影响 API 或正式统计 |
| 手写源码未变或无生成源码，但 Lombok/annotation processor/ERM/Schema/IDL 最终 effective class 变化 | 按 contract/IR/runtime metadata 生成正式变化事实；再由 Step5 判断触达 | 补回编译期生成代码变化的假阴性；被遮蔽生成 class 不误报，触达后仍输出“可能受影响，需运行时验证”而非确认行为影响 |
| 非 `.class` 运行时资源发生变化 | targetable semantic/topology fact、confirmed-unprojectable 或 `candidate` | 区分“事实已变但不能追踪”和“变化尚未裁决”，不再因“非代码文件”静默漏报 |

当前目标驱动扫描已经能补偿一部分 direct business 命中，所以并非所有 API 都会改变。收益主要集中在无源码多跳链、完整路径枚举、统一成员身份、字段/构造器/生成方法和 provider 精度。

### 10.3 不会自动解决的准确性边界

- 反射目标动态拼接；
- 运行时生成代理；
- 未建模 Java agent/JVMTI/runtime weaving 或动态下载插件改写/增加的 class；
- 外部配置和环境条件；
- JNI、脚本和远程服务行为；
- 相同字节码在不同外部状态下产生不同结果；
- 字节码变化但语义等价的重构、编译器或插桩差异。

这些场景继续通过 semantic/inline/dynamic/loader coverage 和候选证据表达：前置事实不完整时 verification=`undetermined`；仅在 authoritative 变化与 exact/proven 业务触达均已确认时使用 `required_not_executed`。不能因二进制主图建立而静默升级为确定行为影响。

### 10.4 迁移自身可能引入的回退

新架构仍可能因实现错误产生假阳性或假阴性，重点风险包括跨版本 pairing 错误、descriptor 归一化错误、错误 loader/class-provider/class-definition/member-resolution 绑定、MR-JAR variant 误选、source/binary 重复节点、把 possible dispatch 当 exact、把 lambda binding 当直接调用、漏掉 class-init/condy/inline relation，以及把 semantic edge 错当 direct edge。容器/classfile/resource/environment/nondeterminism 忽略白名单过宽会制造假阴性，过窄会保留重打包或构建变体噪声造成的假阳性；仅凭环境版本不同或 same-input 输出不同就降级会漏掉真实生成代码变化，environment/determinism provenance 未进入缓存 identity 则可能复用错误裁决。未知格式若被默认排除也会产生不可见漏报。全图路径数量增长还可能触发查询或报告截断，使 `path_set_complete` 降低。

这些风险必须由双引擎逐边对账、独立 Oracle、mutation 和 coverage ledger 阻断后才能切换权威。source alias 成功率只衡量可读性和交互体验，不能代替物理图 precision/recall 指标。

## 11. 性能与存储影响

### 11.1 预期影响

- 冷运行需要全量解析 current 业务 class 和运行时 JAR，构图耗时、磁盘占用和写入 I/O 会增加。
- 多 API 分析可以复用同一事实图和多目标反向传播，减少逐 API 重扫。
- candidate 诊断追踪复用同一 binary graph 和 predecessor transition，不得重复解析 artifact；其耗时、路径数和存储单独计量。
- 第 6.11 节对应层的完整 cache key 命中且缓存完整时，暖运行只复用该层事实；不得把 binary blob 命中扩大为 source/semantic/change/trace 全库命中。
- 使用 SQLite 流式写入和索引查询，避免全图、全部路径和全部展示对象同时常驻内存。

### 11.2 不允许的性能优化

- 少扫描 class 或 artifact；
- 丢弃低频但真实的 opcode/edge family；
- 为了更快而降低 max depth 或提前停止闭包；
- 静默把 `alerts.csv` 改成样例路径，或达到 cap 后不记录截断元数据；
- 缓存身份不完整时复用旧图或旧 overlay；
- 解析失败后静默返回空集合。

## 12. 输出与兼容策略

### 12.1 保持的合同

- 每个 active authoritative-targetable `projection_identity` 必须有且只有一个 projection trace result；每个 `reported_api_identity` 必须有且只有一个按第 9.4 节生成的正式聚合主结果。
- `alerts.csv` 每个 reported API 至少一行，并通过 projection identity 覆盖全部已物化的唯一 canonical SCC-condensed 终止路由；非平凡 SCC 必须可链接到环内成员/边/witness 明细。达到确定性 cap 时允许理论路由未全部物化，但必须可审计 cap、截断位置和 `path_set_complete=false`。
- `summary.json.formal_projection_total` 必须与 Step4 active authoritative-targetable projection 闭合，`unique_reported_api_total` 必须与 `by_api` 聚合键闭合；两者不得混为一个“目标总数”。targetable-partial scope、confirmed-unprojectable、candidate、excluded 和 superseded audit 各自独立闭合。
- `by_api`、`by_module`、Step6 和只读查询继续可用。
- 内部 SQLite node id 不得泄漏为用户稳定身份。
- 当前 `.runtime/indexes/s5_query_index.json` 的 v1 严格 schema 在兼容窗口内继续由输出适配层生成；SQLite/v2 不能覆盖同一路径。若新增 query v2，必须使用并行路径和显式版本选择。

### 12.2 Step4 制品差异与 runtime decision sidecar

Step4 应新增版本化 artifact-local-diff sidecar 与 runtime-scope-decision sidecar；具体物理路径由实现阶段与现有 Step4 evidence 目录合同统一确定，不能只把结果写入日志，也不能把 loader-realm 级事实复制到任意一个 artifact pair 名下。每个 exact/base-only/current-only/ambiguous artifact pairing record 至少保存或引用：

```text
base_artifact_identity
current_artifact_identity
artifact_pairing_identity
artifact_pairing_status
base_runtime_profile_identity
current_runtime_profile_identity
runtime_comparison_identity
analysis_scope_identity
analysis_context_identity
base_build_environment_identity
current_build_environment_identity
base_build_input_manifest_identity
current_build_input_manifest_identity
base_artifact_build_provenance_identity
current_artifact_build_provenance_identity
base_runtime_loader_graph_identity
current_runtime_loader_graph_identity
base_pre_resolution_discovery_snapshot_identity
current_pre_resolution_discovery_snapshot_identity
base_final_reconciliation_snapshot_identity
current_final_reconciliation_snapshot_identity
base_context_key_applicability_identity
current_context_key_applicability_identity
base_resource_selection_view_identity
current_resource_selection_view_identity
provider_binding_delta_digest
active_decision_snapshot_identity
active_projection_assessment_snapshot_identity
active_formal_projection_snapshot_identity
active_candidate_projection_snapshot_identity
artifact_content_changed
container_diff_status
class_diff_status
resource_diff_status
comparison_coverage_status
runtime_effective_diff_summary
build_environment_comparison_status
build_input_comparison_status
environment_attribution_status
build_variation_kind
analysis_eligibility_summary
analysis_projection_summary
projection_coverage_summary
container_normalization_policy_version
classfile_normalization_policy_version
resource_classification_policy_version
artifact_local_diff_facts
fact_build_input_slice_identities
disposition_obligation_identities
runtime_effective_decision_identities
authoritative_projection_assessment_identities
confirmed_unprojectable_fact_identities
diagnostic_candidate_fact_identities
candidate_projection_plan_identities
excluded_evidence_identities
audit_only_record_identities
promotion_status
projection_identities
candidate_projection_identities
exclusion_reason_codes
```

每个 base/current runtime-scope correspondence 另行保存完整 loader/classpath/module-path/resource-selection inventory identity、class-provider/class-definition/member-resolution/resource/provider delta、observed-delta decisions、四层 active snapshot identity 和 coverage。classpath 顺序变化、provider/class-definition delta 或 resource selection delta 即使没有任何 artifact payload 变化，也必须能在该 sidecar 独立闭合。artifact sidecar 只通过 identity 引用这些 scope facts，禁止复制后产生多个事实 owner 或计数重复。

每个 runtime-effective confirmed fact 必须包含 observed-delta/disposition-obligation/decision/change-fact identity、pairing/runtime scope、entry/class/member/resource identity、artifact-local 与 base/current effective fingerprints、事实类型、提升原因、selection/comparison coverage 和 provenance；其 active projection assessment 另行包含 `projection_assessment_identity`、`analysis_projection_status`、`projection_coverage_status`、applicable/selected target-set digest、projection-obligation keys/digest/count 与 partial scopes。可获得时在 change fact 额外记录 generator、generator version/config digest、Schema/ERM/IDL identity，但这些字段缺失不能阻断已经由有效二进制证据确认的变化。targetable assessment 通过独立 `change_projections[]` 记录第 7.9 节的 `projection_assessment_identity/projection_obligation_key/projection_rule_contract_identity/projection_rule_implementation_version/projection_identity/target_identity`；targetable+partial 还必须记录 `partial_projection_scopes`，unsupported assessment 进入 `confirmed_unprojectable_facts`，不得伪造成 API target。`promotion_status=audit_only|excluded` 不能只给出布尔值，必须在 `excluded_diff_evidence` 中记录 `exclusion_owner_kind`、最小 old/new 摘要、明确 `exclusion_reason`、comparison/runtime-selection/consumer coverage 和第 7.7 节规则/策略版本；`runtime_decision` owner 必须引用 decision identity，`audit_only` owner 必须引用 audit record 且不得伪造 decision。两类排除证据都不得被投影为 API 目标。`diagnostic_candidate_facts/candidate_diagnostic_projection_plans/candidate_projections` 必须使用独立 schema/path；零/部分 target 和全部 projection obligation 也必须由 plan 记录 target-discovery coverage，任何 formatter、Step6 或 query consumer 都不得把它们并入正式目标或影响统计。

`summary.json` 必须同时保存正式基数和不参与影响分桶的各通道诊断/审计基数：

```text
result_generation_identity
has_unresolved_change_facts
has_confirmed_unprojectable_facts
runtime_comparison_identities
runtime_comparison_count
analysis_scope_identities
analysis_scope_count
analysis_context_identities
analysis_context_count
active_snapshot_sets[] = {
  analysis_context_identity,
  active_decision_snapshot_identity,
  active_projection_assessment_snapshot_identity,
  active_formal_projection_snapshot_identity,
  active_candidate_projection_snapshot_identity
}
impact_analysis_completeness = complete | partial
path_inventory_completeness = complete | partial
path_incomplete_projection_count
incomplete_scope_count
incomplete_scope_report_path
active_runtime_decision_total
analysis_disposition_total
authoritative_fact_count
active_authoritative_projection_assessment_count
authoritative_targetable_fact_count
authoritative_targetable_complete_fact_count
authoritative_targetable_partial_fact_count
partial_projection_scope_count
partial_projection_report_path
formal_projection_total
formal_projection_reachable_count
formal_projection_uncertain_count
formal_projection_not_found_count
formal_projection_not_analyzed_count
unique_reported_api_total
confirmed_unprojectable_fact_count
confirmed_unprojectable_report_path
diagnostic_candidate_fact_count
active_candidate_projection_plan_count
candidate_targetable_plan_count
candidate_unbound_plan_count
candidate_plan_incomplete_count
diagnostic_candidate_projection_count
diagnostic_candidate_projection_reachable_count
diagnostic_candidate_projection_uncertain_count
diagnostic_candidate_projection_not_found_count
diagnostic_candidate_projection_not_analyzed_count
diagnostic_candidate_report_path
excluded_decision_count
audit_only_record_count
build_audit_record_count
superseded_audit_only_record_count
superseded_decision_count
superseded_projection_assessment_count
superseded_formal_projection_count
superseded_candidate_projection_plan_count
superseded_candidate_projection_count
```

这些字段用于防止未裁决的真正变化被隐藏，不能与正式 `reachable/probable/not_analyzed` 数相加。candidate fact、diagnostic plan、candidate projection 和 candidate 状态计数分别闭合：一 fact 恰好一 plan，plan 可零/多 target，禁止把“一 fact 多 target”误算为重复 fact，也禁止因零 target 而漏掉 fact。详细候选、target-discovery coverage、诊断路径和失败范围只写独立 candidate report。

`authoritative_targetable_*_fact_count` 和 `confirmed_unprojectable_fact_count` 都是按 authoritative change-fact identity 去重，分类依据是其唯一 active assessment；它们不是 assessment 历史记录数。active/superseded assessment 另行计数，禁止因能力升级把同一 change fact 重复计入 targetable 和 unprojectable。

计数守恒至少满足：

```text
active_runtime_decision_total
  = authoritative_fact_count + diagnostic_candidate_fact_count + excluded_decision_count
analysis_disposition_total
  = active_runtime_decision_total + audit_only_record_count
  = count(distinct disposition_obligation_identity in active disposition ledger)
runtime_comparison_count = count(distinct runtime_comparison_identities)
analysis_scope_count = count(distinct analysis_scope_identities)
analysis_context_count = count(distinct analysis_context_identities)
authoritative_fact_count
  = authoritative_targetable_fact_count + confirmed_unprojectable_fact_count
active_authoritative_projection_assessment_count
  = authoritative_fact_count
authoritative_targetable_fact_count
  = authoritative_targetable_complete_fact_count
  + authoritative_targetable_partial_fact_count
formal_projection_total
  = count(active projections referenced by authoritative_targetable facts)
  = sum(projection_obligation_count of active targetable assessments)
  = formal projection reachable + uncertain + not_found + not_analyzed counts
unique_reported_api_total
  = count(distinct reported_api_identity in active formal projections)
diagnostic_candidate_projection_count
  = count(active projections referenced by candidate targetable plans)
  = sum(candidate_projection_obligation_count of active targetable plans)
  = reachable + uncertain + not_found + not_analyzed candidate projection counts
active_candidate_projection_plan_count
  = diagnostic_candidate_fact_count
  = candidate_targetable_plan_count + candidate_unbound_plan_count
candidate_plan_incomplete_count
  = count(active candidate plans where diagnostic_projection_coverage_status=partial|failed)
path_incomplete_projection_count
  = count(active formal projections where exact_path_set_complete=false
          OR (possible_path_layer_applicable=true AND possible_path_set_complete=false))
path_inventory_completeness = complete iff path_incomplete_projection_count = 0
has_unresolved_change_facts = (diagnostic_candidate_fact_count > 0)
has_confirmed_unprojectable_facts = (confirmed_unprojectable_fact_count > 0)
partial_projection_scope_count
  = count(distinct active incompleteness_scope_identity whose category=projection_partial)
incomplete_scope_count
  = count(distinct active incompleteness_scope_identity referenced by candidate,
          confirmed-unprojectable, partial-projection, formal not-analyzed, coverage/transformer,
          or path-incomplete records)
```

每个 active authoritative fact 恰有一个 active projection assessment。每个 targetable assessment 至少有一个 projection obligation，formal snapshot 必须为每个 obligation 恰好保存一个 active projection；每个 formal projection 恰好引用一个 active targetable assessment、其 authoritative fact 和一个存在于 assessment obligation set 的 key。targetable+complete 不得引用 partial-projection scope，targetable+partial 必须至少引用一个且与 `partial_projection_scope_count/report` 守恒；unsupported assessment 的 target/obligation/projection 数必须均为 0，并恰好进入 confirmed-unprojectable report。audit-only 和 superseded decision/assessment/projection records 不进入 active runtime decision 等式，分别计数。任何无法满足守恒的 sidecar/summary 都不得发布。

`excluded_decision_count` 只计算 active excluded decision，且每个都必须至少有一条 `exclusion_owner_kind=runtime_decision` evidence；`audit_only_record_count` 只计算 scope/packaged-build-metadata/distribution audit record，且其 evidence 必须为 `exclusion_owner_kind=audit_only`。audit-only record 不得拥有 decision/change-fact/projection identity，runtime-decision exclusion 不得借 audit owner 逃出三通道守恒；两类 owner 的 identity 集必须不相交。

audit-only record 也必须 immutable。consumer/observability/equivalence evidence 更新使同一 obligation 改为 decision 或改变 audit reason 时，生成新 record/disposition generation 并以 `supersedes_audit_record_identity` 保留历史；旧 record 退出 active ledger但不得删除或原地改写。`superseded_audit_only_record_count` 不进入 active disposition 等式。

`build_audit_record_count` 单独计算没有 artifact/runtime observed delta 的 BuildEnvironment/BuildInput/Provenance 差异；它既不加到 `analysis_disposition_total`，也不阻止已有 runtime scope 的影响分析完整性。若同一构建差异同时为某个 artifact-local delta 提供 environment attribution evidence，该 build-audit record 可被 decision 引用，但仍只计一次 build audit。

每个实际运行的 `analysis_context_identity` 在 generation manifest 中必须恰有一个四层 `active_snapshot_sets[]` 记录。assessment snapshot 中的每个 assessment 必须引用该 decision snapshot 内的 authoritative decision；formal snapshot 中的每个 projection 必须引用该 assessment snapshot 内 targetable assessment 的一个 obligation。candidate snapshot 必须为该 decision snapshot 内每个 candidate decision 恰好保存一个 active diagnostic plan，且必须为 targetable plan 的每个 obligation 恰好保存一个 candidate projection；unbound plan 的 target/obligation/projection 数均为 0，partial/failed coverage 必须有 unbound scope/reason。四条 snapshot supersession 链及 decision/assessment/plan/projection 记录自身的 supersession 链都必须无环且每层至多一个 active head；跨 snapshot 引用、缺失成员、重复 active head 或运行时按最大时间戳猜 active 均使 generation 不可发布。

上述等式先按 `analysis_context_identity` 分别成立，run-level 数值只允许对实际声明的 context 计数求和；不得跨 profile pair 或 analysis scope 对同名 API、provider 或 decision 去重，也不得从两个独立 ID 列表猜测未实际运行的笛卡尔积 context。

`incompleteness_scope_identity` 是统一的报告身份，不等同于“异常失败”。每个阻止 `impact_analysis_completeness=complete` 的 active 原因都必须恰好引用一个可重算记录，至少包含 `analysis_context_identity + category(candidate|unprojectable|projection_partial|formal_failure|coverage|transformer|path_inventory) + subject_identity + reason_code + evidence_digest`；同一根因影响多个 subject 时可共享 scope identity，但引用关系必须全量保存。candidate 已完成诊断路径仍因变化裁决未完成而引用 candidate scope；confirmed-unprojectable 引用 projection-capability scope；targetable+partial 引用 projection-partial scope；路径截断引用 path-inventory scope。没有对应记录却把总体 completeness 写成 partial，或存在阻断原因却没有进入 `incomplete_scope_count/report`，都属于合同失败。

当 `has_unresolved_change_facts=true` 时，Step6 首页/主摘要必须显示“不参与正式影响计数的未裁决制品差异”提示、数量、最高 failure scope 和 candidate report 路径；不得只在调试日志或深层 sidecar 中出现。该提示不把 candidate 改名为“可能受影响”，也不改变 `formal_projection_total/unique_reported_api_total`。

当 `has_confirmed_unprojectable_facts=true` 时，主摘要必须单独显示“已确认 runtime-effective 事实变化，但当前缺少可信影响投影”的数量、scope 和 report path。它与 candidate 的区别必须对用户可见：前者确认 effective 变化、未知如何追踪；后者尚未完成比较、安全等价或 runtime selection/effectiveness 裁决。两者都不进入正式 API 影响计数，但都会阻止相应 scope 的完整性声明。

当 `authoritative_targetable_partial_fact_count>0` 时，主摘要必须显示“部分已确认变化已有正式影响路径分析，但仍存在未覆盖投影范围”的 fact/scope 数和 report path。已有 projection 继续进入正式 API 计数，未覆盖 scope 不伪造占位 API；该提示不得与 confirmed-unprojectable（零 target）或 candidate（变化未裁决）合并。

`impact_analysis_completeness=complete` 只允许在所有适用 runtime scope 中均不存在 active candidate、confirmed-unprojectable、targetable+partial、formal `not_analyzed`、未建模 runtime transformer、违反 support manifest 的 coverage 缺口或未完整路径分层时写出；否则为 `partial` 并列出 scope/reason。`path_inventory_completeness=complete` 当且仅当所有 active formal projection 的 exact layer 完整，且每个 `possible_path_layer_applicable=true` 的 possible layer 完整；`path_incomplete_projection_count` 必须按上述公式与明细闭合。已经证明的 exact/possible 正向存在性不因其他 scope partial 而删除。`path_set_complete=false` 会使总体 completeness 为 partial，但若 impact 状态已由 exact path 证明，它不把该 projection 的存在性裁决改成失败。Step1 运行级阻断不发布一份伪装成 `partial` 的 Step6 summary，而是发布失败 manifest。

### 12.3 目标结果字段

优先建立正式 `projection_results[]`，再在 `by_api` 和 `summary.json` 增加或收敛聚合字段。`decision_bucket` 当前已由 formatter 派生，但在目标 schema 中必须由四维裁决统一生成并由所有消费者按同一语义读取：

```text
change_fact_status
analysis_projection_status
projection_coverage_status
change_basis
observed_delta_identity
disposition_obligation_identity
decision_identity
change_fact_identity
projection_assessment_identity
projection_obligation_key
projection_rule_contract_identity
projection_rule_implementation_version
projection_identity
reported_api_identity
contributing_projection_assessment_ids
contributing_projection_ids
target_jvm_identity
runtime_profile_identity
runtime_comparison_identity
analysis_scope_identity
analysis_context_identity
result_generation_identity
active_decision_snapshot_identity
active_projection_assessment_snapshot_identity
active_formal_projection_snapshot_identity
binary_graph_identity
source_overlay_identity
inline_overlay_identity
entrypoint_overlay_identity
semantic_overlay_identity
change_target_digest
trace_policy_identity
reachability_status
impact_conclusion
decision_bucket
runtime_verification_status
runtime_verification_executed_by_system
runtime_verification_evidence
verification_reason_code
provider_resolution_status
provider_transition_status
class_definition_status
class_definition_coverage
loader_resolution_coverage
member_resolution_coverage
dispatch_certainty
static_linkage_status
dynamic_linkage_coverage
class_init_coverage
inline_consumption_coverage
loader_realm_identity
existence_proven
exact_path_exists
possible_path_exists
exact_path_set_complete
possible_path_set_complete
possible_path_layer_applicable
possible_layer_applicability_scopes
path_set_complete
best_path_certainty
path_enumeration_limit
exact_materialized_path_count
possible_materialized_path_count
materialized_path_count
truncation_frontier
entrypoint_coverage
direct_graph_coverage
semantic_coverage
source_mapping_status
artifact_origins
```

`change_fact_identity/projection_assessment_identity/projection_identity/target_jvm_identity` 的单数形式属于 projection result。正式 projection result 必须绑定生成它的 decision/assessment/formal-projection snapshot 与 `result_generation_identity`；candidate result 则绑定 decision/candidate-projection snapshot。可复用的底层 trace result 可独立于 active 集合缓存，但序列化进某代输出时必须经 generation manifest attachment 明确绑定，不能把缓存命中冒充当前 active membership。`by_api` 必须使用 `contributing_projection_ids[]/contributing_projection_assessment_ids[]/contributing_change_fact_ids[]/target_jvm_identities[]` 保存完整集合，并保存 contributing assessments 的 `projection_coverage_status` 与 partial-scope 引用；只对 reachability/impact/verification/path completeness 等字段应用第 9.4 节聚合。不能任取一个 projection 的 provider、class-definition、linkage 或 failure 字段冒充整个 API；需要主摘要时必须同时保留 `primary_projection_id` 和版本化选择理由。

正式 `by_api` 中每个 contributing projection 必须反查 `change_fact_status=confirmed` 和 active `analysis_projection_status=targetable` assessment，该 assessment 的 `projection_coverage_status` 只能是 complete/partial；任一 partial 必须引用对应 incompleteness scope。candidate report 使用 `candidate_fact_status/candidate_reachability_status`；exclusion sidecar 对 active excluded decision 使用 `exclusion_status + exclusion_owner_kind=runtime_decision`，对 scope audit 使用 `audit_status=scope_excluded + exclusion_owner_kind=audit_only`；confirmed-unprojectable report 使用 `change_fact_status=confirmed + active assessment.analysis_projection_status=unsupported + projection_coverage_status=unsupported`。这些 schema 不得互相复用。`summary.json.formal_projection_total` 只等于 active authoritative-targetable projection 数，`unique_reported_api_total` 只等于聚合 API 数，其余通道分别使用诊断/审计总数闭合。

行为变化且触达业务的建议字段：

```text
reason_code                             = IMPLEMENTATION_CHANGED_BUSINESS_REACHABLE
verification_reason_code                = IMPLEMENTATION_CHANGED_RUNTIME_VERIFICATION_REQUIRED
runtime_verification_executed_by_system = false
runtime_verification_evidence           = []
user_conclusion                         = 已确认触达变化实现，可能受影响，需运行时验证。
```

主原因码描述已经完成的分析事实；verification reason 只描述尚未执行的后续验证要求，不再把它伪装成 blocking analysis failure。

结构/链接不兼容且 exact/proven 触达时固定为：

```text
reason_code                             = STATIC_LINKAGE_INCOMPATIBLE_IF_EXECUTED_BUSINESS_REACHABLE
static_linkage_status                   = incompatible_if_executed
reachability_status                     = reachable
impact_conclusion                       = probable_impact
runtime_verification_status             = required_not_executed
user_conclusion                         = 已确认存在可触达的结构或链接不兼容，执行相关路径时会失败，业务是否实际触发仍需运行时验证。
```

该文案确认的是“执行相关路径时”的确定性，不确认生产运行已经执行。若路径只含 possible dispatch，必须改为 `uncertain + inconclusive + undetermined`，不得使用上述文案。

旧 `BEHAVIOR_CHANGED_RUNTIME_VERIFICATION` 仅作为 v1 读取别名保留；v2 正式结果使用上面的两个独立原因码，避免把“已完成触达分析”和“尚需验证”压回同一阻塞原因。

## 13. 分阶段迁移

### 阶段 0：冻结合同和基线

- 固定 authoritative/candidate/excluded 三套互斥事实 schema、immutable decision 与可 supersede AuthoritativeProjectionAssessment/CandidateDiagnosticProjectionPlan 的边界、authoritative targetable complete/partial/unsupported 与 candidate targetable/unbound discovery coverage、正式四维状态 truth table 和全部非法组合测试。
- 固定 `base/current RuntimeProfileIdentity/RuntimeComparisonIdentity/AnalysisScopeIdentity/analysis_context_identity/platform-image/ArtifactBlob/ArtifactInstance/CrossVersionArtifactPairing/loader realm/BuildEnvironmentIdentity/BuildInputManifestIdentity/ArtifactBuildProvenance/FactBuildInputSlice` 完整 identity，四类 reconciliation universe 与 context→key 适用关系，以及 artifact-local → runtime-effective decision、base/current provider/resource-selection delta schema；构建环境、构建输入、制品 provenance、运行 profile 和分析范围禁止互相代填，派生 context 必须可唯一反查实际 pair + scope。
- 固定 `(target, projection rule, required edge family)` obligation 分母、projection 多对多基数、projection → reported API 聚合优先级、各层计数守恒和 immutable supersession 合同。
- 固定 decision → assessment → formal projection 与 decision → candidate projection 的四层 active snapshot schema、成员外键、无环 supersession 和 generation 原子发布合同。
- 固定 Step4A → Step5A → Step4B → Step5B → Step6 单向 phase manifest、输入/输出 digest、失败传播和从最早失效点重算合同。
- 固定 ASM helper 协议、parser identity、受支持 classfile major 和 `artifact_diff_support_manifest/runtime_loader_support_manifest/class_definition_support_manifest/oracle_support_manifest` 首版范围。
- 固定 exact/proven/possible dispatch、dynamic callsite、class-init/linkage、inline consumption 的事实和降级规则。
- 固定代表性真实工程的 Step4 目标集、Step5 规范化结果和 Step6 输出指纹。
- 固定并保存 base/current `BuildEnvironmentIdentity`/determinism controls、环境差异与非确定输出候选规则和独立等价 verifier 版本。
- 保存独立 Oracle 的 direct edges 与目标反向闭包。
- 记录 cold/warm 耗时、峰值 RSS、磁盘占用和查询延迟。
- 产出版本化 `performance_gate.json`：固定机器/CPU/内存/OS/JDK/工具版本、数据集及 artifact identity、warmup 与采样次数、cold/warm 清理规则、统计口径，以及端到端/阶段 p95、峰值 RSS、磁盘和相对 legacy 基线阈值。
- 增加固定执行策略：`legacy | shadow | binary_strict | binary_with_legacy_fallback`；每个 generation 的 engine 仍不可混用。

退出条件：上述 schema、truth table、support manifest、解析协议、Oracle fixture 和 clean-output/build-provenance 合同均已评审并能由自动命令重复验证；现有输出、查询可重复，且准确性门和 `performance_gate.json` 已固定。阶段 0 完成前不得改变生产裁决或声称存在已验证的性能门槛；可以开发 shadow/基础组件，但不得切换权威。

### 阶段 1：Step4 影子常态二进制实现比较

- 在 shadow pipeline 中，即使源码 diff 成功也执行 JAR 方法实现比较；生产目标集仍保持 legacy。
- Step1 影子固化 base/current 完整业务制品、受支持运行依赖闭包、有序 path/loader/resource 声明、RuntimeProfileIdentity/RuntimeComparisonIdentity 和完整 inventory digest；缺失范围必须显式记 coverage。
- 按第 7 节影子执行 JAR 容器、classfile 和 resource 三层 **artifact-local** 比较，输出原始 SHA 差异、规范化事实、安全等价/环境归因证据和策略版本，不改变生产目标集。本阶段尚未建成 loader/provider/resource effective view，不得写 `authoritative-targetable`、`RUNTIME_SELECTION_NON_EFFECTIVE_ONLY` 或完整 runtime-effective unchanged。
- 影子采集并分别比较 base/current BuildEnvironment/BuildInputManifest/ArtifactBuildProvenance/determinism identity，只在 artifact-local scope 输出 environment/nondeterministic-output proven-noise、diagnostic-only suspected 或不可归因的已确认表示差异；这些都不能越过阶段 2 的 effective gate 进入生产目标集。
- 在 checkout-build 影子记录 clean-output/build-cache provenance；不满足第 6.12 节时产生 `binary_would_block` 证据，验证 binary strict 合同将阻断而不是产生差异候选。阶段 1 不因 shadow would-block 擅自改变 legacy 生产运行；真正硬阻断随 binary 执行策略切换或另行批准的 Step1 安全加固生效。
- 先影子输出 binary/source 一致性矩阵，以及 raw-JAR-diff/normalized-fact 一致性矩阵。
- 安全忽略项只允许来自版本化白名单；未知 attribute、resource、重复 entry、解析失败或比较不完整必须失败关闭。
- 修正 behavior coverage 分母：所有具备可信 old/current JAR 的适用依赖都进入 planned。

退出条件：同一对 JAR 在有源码和无源码时产生相同的 artifact-local contract/IR/runtime-metadata/resource 差异集合；该阶段生产正式目标集变化数为 0。payload 完全相同但 ZIP 时间戳/顺序/压缩方式不同时 artifact-local 代码差异数为 0；安全白名单 classfile 表示变化和独立证明的编译环境等价输出不生成 artifact-local 实现变化；运行诊断 metadata 和 signer/security 差异被正确单独分类而不得当作安全白名单噪声。未知 attribute/resource、不完整比较或 ambiguous pairing 只能为 artifact-local unknown/candidate；本阶段产生任何 runtime-effective authoritative/excluded-non-effective/projection 均为质量门失败。

### 阶段 2：影子二进制事实库

- 先将当前按 coordinate 唯一键工作的 `Step5ArtifactFactStore` 重构/替换为按 `ArtifactInstance` 工作；禁止原样复用后把同坐标多实例视为冲突。
- 使用第 6.13 节 ASM helper 先 inventory 并流式解析全部 current runtime-path candidate class entry，再由 EffectiveGraphView 过滤 caller/callee；禁止先猜 effective 后只解析被猜中的 class。base 侧至少对 provider/resource/inline 对账所需的完整 scope 建立 compact facts，任何 deferred scope 都必须有可验证边界。
- 写入 direct/type/dynamic/bootstrap/class-init/linkage/hierarchy facts、`DispatchResolution` 和 edge certainty；先冻结 pre-resolution discovery snapshot，再通过版本化有限 fixed point 冻结四类 final reconciliation universe/context→key 适用关系，建立 loader realms、current class-provider/class-definition/member-resolution/dispatch view，对 topology 变化建立 base/current compact provider/class-definition/resource-selection delta，并首次运行 runtime-effective gate。
- 建立 target-independent consumer/entrypoint/semantic discovery 接口并纳入 fixed-point round；本阶段尚未实现的 source/framework mechanism 必须把对应 consumer/projection coverage 标为 partial/unsupported，使相关 resource/raw-metadata 差异保持 candidate，禁止为了让影子 decision 闭合而假定“无消费者”。
- 让同一 ASM raw facts 同时驱动 shadow Step4 IR/contract/metadata normalization 与 Step5 图，替换阶段 1 的 `javap` 影子摘要；两类派生 policy 仍保持独立版本。
- 先只写入版本化 binary-core SQLite namespace 和 coverage ledger；不把本轮 source/semantic/change facts 固化为同一缓存 identity。
- 生产 tracer 仍使用 legacy 图。

退出条件：shadow binary fact collector 中因源码缺失导致的 executable edge rejection 为 0；legacy 生产 ingestion 在该阶段仍可能保留已知拒绝行为，必须记入 delta，但不得误算为 shadow collector 失败。两侧 candidate/effective inventory、ClassDefinitionResolution 和 DispatchResolution 守恒；独立 Oracle 支持范围内没有漏边、额外边、错 descriptor、错 class-definition/class-init/bootstrap/linkage、错 class provider/class definition/member resolution/dispatch certainty、错 pairing/effective decision 或错 provider/resource delta。源码 diff 显示变化但 effective runtime fact 未变化的 shadow 正式提升数为 0；已证明 non-effective 的 artifact-local 差异不生成 projection；runtime-effective contract、method IR、可消费 metadata/resource/topology/security 变化的错误排除数为 0；Lombok、annotation processor、ERM/Schema/IDL 生成代码的 runtime-effective class/member 变化与等价手写变化产生相同 projection。diagnostic-only candidate 进入生产 Step5/alerts/summary/Step6 的数量为 0；confirmed-unprojectable 缺失独立记账或混入正式 projection、已有 target 但未覆盖 scope 被误写为 projection complete/unsupported 的数量均为 0。任何仍可能被当前 scope 选择/观察的未知或不完整比较、配对、platform image 或 runtime selection 都不能产生“已排除”或“完整无变化”，独立证明全 scope non-effective 的例外必须保留原始 failure/audit 且不得伪装成比较成功。各层使用第 14.3 节要求的独立校验器。

### 阶段 3：源码降为 overlay

- 建立 binary member ↔ source alias。
- 将 business entrypoint/RootEdge 改为 runtime-profile + final-artifact/registration 事实；源码入口只作为 alias/candidate。
- 建立 inline consumption 的 proven/possible 证据；首版不支持的 compiler/language 必须降低 inline coverage，不能按字面量提升。
- framework/reflection/resource collector 只写 semantic edge。
- 为 framework、reflection、resource 等机制实现各自的 eligibility verifier，替换当前所有 semantic edge 共用 framework 专用校验器的限制。
- 将 target-independent source/resource consumer candidate、entrypoint 与 semantic activation discovery 接入第 8.1 节 combined fixed point；能力扩展后从 pre-resolution snapshot 重建 final reconciliation 与受影响 decision/assessment/projection snapshot，不允许在旧 decision 后只补 semantic edge。
- 仅有源码 direct call、且无 current 制品指令的边永久改为 conflict/hint，不得转换成 semantic edge。

退出条件：同一 JVM member 的 source/bytecode 重复节点为 0；alias 歧义不删除物理边；source-only direct edge 和未证明 inline binding 进入 authoritative graph 的数量为 0；无源码时丢失 proven runtime entrypoint 的数量为 0，possible/test-only root 被当成生产 exact root 的数量为 0。

### 阶段 4：双引擎结果对账

- 先校验每个 analysis context 的四层 active snapshot 成员、外键、supersession 与 generation manifest 一致，再启动追踪；禁止从数据库当前行临时拼 active 集合。
- 对全部 active authoritative-targetable projections 批量追踪。
- 为全部 diagnostic candidate 建立一 fact 一 plan；对 plan 中全部可绑定 target 使用独立 namespace 批量追踪，零/部分 target 也输出 discovery coverage，不并入正式影响结果。
- 先逐 projection，再逐 reported API 比较 direct/dynamic/class-init/linkage/dispatch edges、edge certainty、provider delta、反向闭包、状态四维、原因码、全部已物化唯一终止路径、路径集合完整性和聚合守恒元数据。
- 输出内部 `analysis_delta`，不改变用户正式报告。

退出条件：所有旧 `reachable -> 新非 reachable` 都有证据证明旧路径仅靠源码 direct call、绑定了错误 class provider/class definition/member、把 possible dispatch 当 exact，或新图存在明确失败；所有新增 JVM path 均由第 14.3 节 support manifest 覆盖的 symbolic/class-provider/class-definition/member-resolution/dispatch/type/dynamic/class-init/linkage 独立验证层证明，新增 semantic/inline path 均满足各自 verifier；所有可绑定 candidate 都有独立诊断结果且与正式 projection/API 计数完全互斥。

### 阶段 5：切换 binary 权威

- binary graph 成为 direct edge 唯一权威来源。
- Step4 同时切换为 ASM/规范化 artifact-local diff → runtime-effective decision → typed projection 主线；源码 diff 只保留解释/冲突，不再决定正式变化目标。禁止只切 Step5 图而继续消费 source-first Step4 target。
- 仅对 support manifest 和 loader policy 覆盖的运行形态启用 binary 正式模式；超出范围时显式降级/阻断，不能冒充完整覆盖。
- 通过同一 generation manifest 原子切换四层 active snapshot、Step5 状态模型、formatter、Step6 和 query consumer；任一消费者未绑定同一 snapshot set 时整代不可发布。
- 先在固定真实工程/受控范围 canary，对账通过后再设为默认模式。
- legacy 仅保留为预授权 whole-generation fallback；binary generation 失败后必须从头建立纯 legacy generation，不允许逐边混用。

退出条件：完整质量门连续通过，真实工程不存在未经解释的准确性回退。

### 阶段 6：删除双轨成本

- 删除“业务字节码先映射源码再补边”的权威路径。
- 删除 binary 模式下的逐目标重复 artifact 扫描。
- `SourceGraph` 收缩为源码/语义 overlay。
- 兼容窗口结束后再评估 query index v2。

## 14. 验收标准

### 14.1 准确性硬门槛

- base/current 分 scope 的 `runtime_candidate_class_entry_count = fully_parsed + explicitly_deferred + explicit_failed`，且 `effective_class_count = effective_parsed + effective_failed`；`explicitly_deferred` 只允许出现在边界已证明的 base compact scope，current 正式图 scope 必须为 0。
- `effective_entry_count = compared_entry_count + explicit_failed_entry_count`。
- checkout-build 不满足 clean-output/build-cache provenance 合同时进入 Step4 的运行次数必须为 0；provided-artifact 缺失 environment/input/determinism identity 时使用环境或非确定构建噪声排除的数量必须为 0。
- BuildEnvironmentIdentity 的 JDK/OS 被自动复制为 RuntimeProfileIdentity、source revision/BuildInputManifest 差异被计入 `build_environment_comparison_status`、单用 vendor/major 冒充实际 platform image、用分析临时路径冒充目标 CodeSource、profile 关键字段 unknown 时猜测 MR/platform/native/provider/resource/entrypoint/CodeSource/security selection，或两侧 profile 未建 RuntimeComparisonIdentity 即聚合结果的数量必须为 0。
- AnalysisScopeIdentity 被写入 RuntimeProfileIdentity/伪装成运行环境 delta，不同 analysis scope 共享 decision/report cache、`reported_api_identity` 和计数聚合，projection-only/Oracle capability 被塞入 runtime-fact AnalysisScope/decision identity，或 `analysis_context_identity` 不能唯一反查实际 pair+scope 的数量必须为 0。
- Step1 未固化任一侧完整业务制品、受支持 runtime closure 和有序 path/loader/resource 快照，却输出该 scope provider/resource unchanged 或完整静态未命中的数量必须为 0。
- Step5A 读取 authoritative change fact/projection 作为 discovery 分母、Step4B 在 Step5A/fixed point 未完成时发布 target、Step5B 在四层 snapshot 未冻结时启动，或 Step4/Step5 对同一 snapshot 递归回写的运行次数必须为 0。
- 只有 JAR 原始 SHA 不同、没有规范化事实支撑时，提升为 API/实现变化的数量必须为 0。
- 独立 goldens 中不改变 runtime-effective 事实的 packaging-only、安全白名单 classfile-only、build-metadata-only、三重门禁完整的 distribution-metadata-only、已明确超出 `AnalysisScopeIdentity.analysis_observability_scope` 的诊断 metadata 和 non-effective artifact-local 差异的错误提升数必须为 0；runtime-effective contract、规范化 method IR、运行时可消费 metadata/resource/security 和 runtime topology 变化的错误排除数及漏检数必须为 0。
- `SourceFile`/行号/局部变量等诊断 attribute 被误写为表示等价 `classfile_noise_only`、未记录 `runtime_diagnostic_metadata_changed`，或在 AnalysisScope 明确包含诊断可观察性时被直接排除的数量必须为 0。
- effective JAR 重签名后 signer/ProtectionDomain/package-sealing 变化被当作通用噪声排除、或被伪造成普通 method API 调用目标的数量必须为 0；必须按安全机制 targetable/confirmed-unprojectable 闭合。
- exact artifact pair 的错配数、ambiguous pair 被强行一对一或笛卡尔积比较数必须为 0；base-only/current-only 和 loader-realm correspondence 不完整时输出 effective unchanged 的数量必须为 0。
- artifact-local changed 但所有受支持 runtime scope 均证明 non-effective、effective facts 不变时生成正式 projection 的数量必须为 0；反之 effective fact 已变却仅因 coordinate/SHA/physical pair 未变而漏掉的数量必须为 0。
- selected/effective fact 已确认变化却因 Step5 未找到调用链、推测 class 不会实际加载或业务未触发而被改成 non-effective/audit/excluded 的数量必须为 0；可达性结果只能改变 reachability/impact 轴，不能反向改写变化 decision。
- class/first-resource selection 写出 `selected_many`、多结果 selection 丢失顺序或允许空列表、physical occurrence 存在却把 `not_selected` 写成 `absent`、mechanism unknown 却写出 selected/unchanged，或 base/current mechanism 不同但无等价证明仍只按 set digest 判 unchanged 的数量必须为 0。
- 被遮蔽 caller class 的 raw outgoing edge 进入该 realm 正式路径的数量必须为 0；effective caller edge 因另一个 realm/实例被遮蔽而全局删除的数量必须为 0。
- `BUILD_ENVIRONMENT_REPRODUCED_NOISE_ONLY` 必须同时具有完整 environment identity、全局 BuildInputManifest 相同或 `FactBuildInputSlice=equal + coverage=complete`、以及独立等价证据；`BUILD_NONDETERMINISM_REPRODUCED_NOISE_ONLY` 必须额外具有完整 same-input/determinism-control identity、精确版本化候选规则和独立等价证据。全局 BuildInputManifest 不同时仍使用 partial/failed/unknown 切片，或只凭单个源文件未变、JDK/compiler/OS 版本不同、两次输出不同、“工具可能不稳定”而 suspected/排除的数量必须为 0。
- 两侧 BuildEnvironmentIdentity 或 BuildInputManifestIdentity 不同但不存在 artifact-local/effective 制品差异时，因环境/输入变化单独创建 active runtime decision/candidate/projection 的数量必须为 0；只能进入 build audit。
- `analysis_eligibility=diagnostic_only` 进入正式 Step5 目标、`alerts.csv`、summary 影响计数、Step6 或 query 正式结果的数量必须为 0；其失败作用域不得污染其他 authoritative fact。
- 正式 `by_api` contributing projection 的 `change_fact_status` 非 `confirmed`、`analysis_projection_status!=targetable` 或 `projection_coverage_status` 非 complete/partial 的数量必须为 0；targetable assessment 的 obligation 缺失/重复 projection、projection 引用 obligation-set 外 key、targetable+partial 缺少 incompleteness scope、targetable+complete 仍有未覆盖 scope，或 unsupported 仍持有 target/obligation/projection 的数量必须为 0；candidate/excluded/confirmed-unprojectable 与正式 projection identity 交集必须为空。
- 每个 active authoritative-targetable projection 必须有且只有一个 projection trace result；每个有 exact runtime target 的 `candidate_projection_identity` 必须有且只有一个 candidate diagnostic trace result。无 target 或追踪失败必须有显式 scoped reason，静默漏项数为 0。
- active candidate decision 缺失/重复 `CandidateDiagnosticProjectionPlan`、targetable plan 使用 failed coverage、其 obligation 缺失/重复 projection 或 projection 引用 plan 外 key、unbound plan 仍有 target/obligation/projection、partial/failed plan 缺少 unbound scope/reason，或 plan/projection registry 变化时原地改写 candidate decision 的数量必须为 0；candidate fact/plan/obligation/projection/status 计数必须分别守恒。
- 多 fact→同 API、单 fact→多 target、跨 loader realm 场景中，projection 丢失、错误跨 realm 去重或 `formal_projection_total/unique_reported_api_total` 任一不守恒的数量必须为 0；聚合后仍须保留每个 projection 的失败与 coverage。
- `by_api` 只取 primary projection 的 path completeness/applicability，或其 `exact_path_set_complete/possible_path_layer_applicable/possible_path_set_complete/path_set_complete` 不等于第 9.4 节 AND/OR/适用分母公式的数量必须为 0。
- `diagnostic_candidate_fact_count > 0` 但 Step6 主摘要没有 unresolved-change 提示和 report path 的数量必须为 0；提示不得增加正式 projection/API/impact 计数。
- confirmed-unprojectable fact 被静默丢弃、改成 candidate/`not_analyzed` API、混入正式影响计数，或主摘要缺少独立提示/report path 的数量必须为 0；targetable+partial fact 的已有正式结果不得被删除，其未投影 scope 也不得被 confirmed-unprojectable/candidate 掩盖。
- 存在 candidate、confirmed-unprojectable、targetable+partial、formal not-analyzed、未建模 transformer、适用 coverage 缺口或任一 active projection 的适用 path certainty 分层未完整，却输出 `impact_analysis_completeness=complete` 的数量必须为 0；每个阻断原因与 `incompleteness_scope_identity` 的引用及 `incomplete_scope_count/report` 必须守恒；`path_set_complete=false` 必须使 `path_inventory_completeness=partial` 且不得反向删除已证明的正向状态。
- active decision 同时存在于多个事实通道、superseded candidate 仍进入当前统计、或旧 decision/trace 被物理删除/原地改写的数量必须为 0。
- decision/change-fact/assessment/formal-or-candidate projection identity 重算后与 canonical payload 不一致、同一 identity 对应多个 outcome/reason/coverage/target/obligation/projection payload，或读取时以最后写入覆盖 immutable record 的数量必须为 0。
- audit-only 排除被计入 `excluded_decision_count/active_runtime_decision_total`、伪造 decision/change-fact/projection identity、在证据变化后被原地改写/物理删除，或 active excluded decision 没有 `runtime_decision` owner evidence、借 `audit_only` 逃出三通道计数的数量必须为 0。
- active disposition ledger 中 disposition obligation 同时/均未落入一个 runtime decision 或一个 audit-only record，`analysis_disposition_total != active_runtime_decision_total + audit_only_record_count`，AnalysisScope 被写入 observed-delta identity 而不是 obligation，或只有 BuildEnvironment/Input/Provenance 差异却伪造 runtime disposition obligation 的数量必须为 0。
- active authoritative fact 缺失/重复 active AuthoritativeProjectionAssessment，candidate/excluded 伪造该 assessment，assessment 与 fact/target/obligation-set/coverage 不守恒，或只因 projection planning/implementation/target-discovery 变化就原地改写/supersede runtime-effective decision 的数量必须为 0；同一模块的 runtime-fact、projection-planning 与 projection-implementation/trace 能力使用同一粗粒度 identity 的数量必须为 0。superseded assessment/projection/trace 不得进入 active 统计。
- 每个 analysis context 缺失/重复四层 active snapshot set、snapshot supersession 成环/多 active head、assessment/formal/candidate projection 跨层引用不兼容成员、trace/report 混用不同 snapshot generation，或用 `is_active/latest timestamp` 临时拼装 active view 的数量必须为 0。
- 同一已发布结果的 SQLite active view、summary、by_api、alerts 与 Step6 报告缺失或使用不同 `result_generation_identity`，generation manifest 未按 content identity 固定本代 sidecar，publication envelope 指向其他 generation，或 generation identity 含临时路径/不可复算字段的数量必须为 0；低层可复用 sidecar 核心反向包含 generation identity 的数量也必须为 0。
- 独立 truth set 必须绑定同一 RuntimeComparisonIdentity + AnalysisScopeIdentity，并以独立 Oracle 标注“runtime-effective/可观察事实是否变化”，不得把未执行的业务语义后果当标签；其中 `confirmed` 的假事实变化数、`excluded` 的真正 runtime-effective/可观察变化数均为 0。未被证明确认或排除的样本必须保持 candidate，不允许为追求二值覆盖率猜测。
- generated provenance 不得改变变化裁决：支持清单内 Lombok、annotation processor、ERM/Schema/IDL 生成 class/member 的 runtime-effective 新增、删除、contract、IR 和 runtime metadata 变化漏检数必须为 0；已证明 non-effective 的生成实例也不得因 generated 标签反向提升。
- 对仍可能被当前 scope 选择/观察的事实，未知 attribute/resource、重复 entry、解析失败、ambiguous runtime selection 或比较不完整不得输出 `packaging_noise_only`、`classfile_noise_only`、effective unchanged 或完整无变化。只有独立且完整的证据证明该 physical 差异在全部适用机制中 non-effective 时，才能按第 7.1.1 节排除该 scope，并保留原始 failure/audit；不得把 non-effective 结论伪装成解析成功或 artifact-local equivalent。
- `BUILD_METADATA_ONLY` 或 `DISTRIBUTION_METADATA_ONLY` 缺少版本化 key/entry/parser 分类、AnalysisScope 排除任意 resource/raw observability、exact-key consumer 无命中及 consumer-discovery coverage 完整中的任一项时，仍被写出的数量必须为 0；`pom.properties`/SBOM/索引/文档/构建字段已有可信 runtime consumer 却因文件名/key 被排除的数量必须为 0。
- 检测到未建模 runtime transformer/agent/plugin 时，受影响 scope 输出完整 graph/effective/no-path 结论，或把经过可变换 class/edge 的 pre-transform 路径保留为正式 `reachable` 的数量必须为 0。
- binary 模式因源码无法映射而拒绝的 executable edge 数必须为 0。
- binary 模式因源码缺失而丢失已由 final artifact/runtime registration 证明的 business entrypoint 数必须为 0；possible/unresolved entrypoint 生成正式 reachable 的数量必须为 0。
- `oracle_support_manifest` 支持范围内的 direct method/field、TypeEdge、dynamic/bootstrap、class-init/linkage 和 dispatch edge，按各自完整 identity 与 certainty 计算的 precision 和 recall 均为 100%。
- wrong descriptor、wrong ArtifactInstance/initiating-or-defining-loader/class provider、wrong initiating/defining module 或 resolution context、wrong class definition、wrong member resolution、wrong dispatch certainty、wrong class-init/bootstrap/linkage、source/bytecode duplicate member 数均为 0；同 owner 不同 defining loader 的错误合并数，以及同 loader 不同 caller module/mechanism 的错误 binding 复用数均为 0；`runtime_equivalent` provider/class-definition/member 集被任取 physical member、集合成员或 scope 不守恒的数量为 0；provider/class-definition/member-resolution/dispatch 必须由第 14.3 节新增的独立验证层证明，不能引用现有 symbolic Oracle 代替。
- selected provider 未建立唯一 ClassDefinitionResolution、unsupported classfile major/精确 format/verification/dependency/security failure 被写成 definition-ready、definition ambiguous/unsupported 的 caller raw edge 进入正式路径，或仅因 parser 能读 class 就宣称目标 JVM 可定义的数量必须为 0；精确 class-definition failure 没有业务触发路径却被写成 reachable 的数量也必须为 0。
- selected 但 definition-failed/unsupported class 内的 method IR 差异被提升为普通 executable implementation projection 的数量必须为 0；精确 definition status delta 必须独立记为 linkage fact，raw-classfile scope 的字节可观察性也不得反向启用该 class 的普通调用边。
- 仅由 hierarchy 得到的 possible implementation 输出正式 `reachable` 的数量必须为 0；exact/proven path 被降为 uncertain 的数量也必须为 0。
- possible-only path 设置 `existence_proven/exact_path_exists=true` 的数量必须为 0；exact/proven reachable 未设置二者为 true 的数量必须为 0。
- 每个适用 virtual/interface direct edge 缺失或重复 `DispatchResolution`、`no_concrete_implementation/unresolved` 物化猜测 implementation edge、已有合法 target 且闭包不完整却写成空 unresolved、`partial_possible_set` 为空或 coverage=complete、`no_concrete_implementation` 未经独立 invocation-selection/linkage 证明就生成 `incompatible_if_executed`、edge `dispatch_edge_certainty`、path `path_certainty` 和结果 `dispatch_certainty/best_path_certainty` 发生跨层非法枚举复制的数量必须为 0；provider/member resolution ambiguous 时越层生成 dispatch edge 的数量必须为 0；无 virtual/interface edge 的 exact path 必须使用 `dispatch_certainty=not_applicable` 而非伪造 dispatch。
- LambdaMetafactory implementation handle 被直接连接为“创建 lambda 的 caller 调用 lambda body”的数量必须为 0；SAM binding、custom bootstrap 和 condy 分别按 support manifest 裁决。
- `<clinit>` 变化在存在受支持主动使用路径时的漏检数必须为 0；`ldc_class/checkcast/instanceof` 被错误当成类初始化触发的数量必须为 0。
- compile-time constant/inline 场景中仅凭字面量或 source-only reference 生成 authoritative edge 的数量必须为 0；current consumer `retained_base/unchanged` 却生成 `changed_with_source` exact edge 的数量必须为 0；适用 inline coverage 不完整却输出完整静态未命中的数量必须为 0。
- base/current loader/provider binding 已变化却只因 artifact payload 相同而输出无变化的数量必须为 0；loader policy 不完整时猜测 first-wins provider 的数量必须为 0。
- pre-resolution seed 被直接当作 caller defining-loader context、fixed point 未收敛/截断却冻结 final digest，或 initiating-resolution-context/class-owner/symbolic-member/resource-key 任一 final universe/context→key 适用关系不守恒却输出 provider/resource delta 完整、projection complete 或完整静态未命中的数量必须为 0；全量 context×key 无证据笛卡尔积、只按 change target 抽样适用关系、把 authoritative change fact/projection/trace 反向作为 reconciliation 输入，或 consumer/entrypoint/semantic discovery 尚未收敛就先做 noise/effective decision 的数量也必须为 0。
- `provider_transition_status` 与 projection kind、base/current binding、ClassDefinitionResolution/member linkage 或 `static_linkage_status` 不一致的数量必须为 0；完整 runtime-equivalent delta 被错误保留为形式化 `unchanged` topology projection 的数量必须为 0。
- 独立验证图已确认可达但产品输出闭集静态未命中的数量为 0。
- 一条 exact/proven 可信路径存在时，其他区域失败不得删除该存在性证明；必须使用 `path_set_complete=false` 表达枚举不完整。possible path 只能得到 uncertain。
- 存在 `partial_possible_set` 或其他可能新增 route 的 unresolved frontier 时，即使当前没有物化 possible edge，`possible_path_set_complete` 也不得为 true；缺口是否同时影响 exact layer 必须按证据类型显式裁决并引用 frontier，禁止把“当前空集合”冒充闭集。
- `possible_path_layer_applicable=false` 但仍有 possible root/edge/frontier、applicability scopes 非空、`possible_materialized_path_count!=0`、`possible_path_set_complete!=true`，或相关 capability coverage 不完整的数量必须为 0；`materialized_path_count != exact_materialized_path_count + possible_materialized_path_count`、`path_set_complete` 不等于 `exact_path_set_complete AND (!possible_path_layer_applicable OR possible_path_set_complete)`、`path_incomplete_projection_count` 与该公式不守恒的数量必须为 0。
- 存在递归/环时必须在 exact/possible 分层 SCC-condensed DAG 上产生有限、稳定 canonical route；将环展开为无限/重复 path、把 possible SCC 混入 exact 层、或 SCC member/edge coverage 不完整仍写 `*_path_set_complete=true` 的数量必须为 0。
- 仅有源码 direct call、且 current 最终制品没有对应 JVM 指令的路径不得成为 authoritative `reachable`，也不得转换成 semantic edge。
- 无源码和有源码场景对同一 effective runtime scope 的正式实现变化 projection 集一致。
- `change_fact_status=confirmed + BEHAVIOR_CHANGED + current-final-artifact exact/proven reachable` 必须输出本设计第 1.1 节定义的四维状态和固定用户结论。
- `not_analyzed` 不得用于表示“已确认触达但尚未运行验证”。
- 当前静态 v2 正式输出中的 `confirmed_impact`、`confirmed_no_impact` 和 `runtime_verification_status=not_required` 数量必须均为 0。

### 14.2 必测场景

| 维度 | 场景 |
|---|---|
| Step1/2 | base/current checkout build 成功/失败、clean-output 成功/失败、tracked/ignored stale output、Gradle/Maven cache 命中/未知、直接产物模式、SHA 变化、direct artifact 无源码时 binary 主线继续且 overlay coverage 降级 |
| RuntimeProfile | target JVM 与 build JDK 相同/不同/未知、OS/arch、launcher/container、active profile/config、classpath/module path、规范化 deployment CodeSource/security/sealing policy、agent/plugin；多 profile 结果隔离 |
| AnalysisScope | 标准 JVM 执行语义、stack-trace/debug/profiling、任意 resource 读取、raw archive/classfile 可观察性开/关，support manifest 版本变化；不同 scope 结果禁止直接聚合 |
| JAR 容器规范化 | 时间戳、entry 顺序、目录占位、压缩算法/级别、ZIP comment/安全 extra field 变化但解压 payload 相同；entry 增删/重名、损坏、加密、不支持压缩、unknown extra field、Unix mode/symlink/external attribute、nested/layout 变化 |
| classfile 规范化 | 常量池重新编号、稳定 label 后 BCI 变化、调试表、通过验证的 StackMap 编码差异；class version、flag、descriptor、常量、opcode、字面量、控制流、异常表、invokedynamic/condy/bootstrap、注解/Signature/Kotlin metadata 变化 |
| 编译环境 | JDK vendor/version、javac/ECJ/Kotlin compiler、target/release/flags、Maven/Gradle wrapper、processor/plugin/generator、classpath、locale/timezone/encoding/OS/arch、clock/SOURCE_DATE_EPOCH/random/filesystem-order/parallelism 相同/不同/缺失；environment/nondeterministic-output proven noise、strict suspected、真实生成代码变化和 candidate 隔离 |
| 跨版本配对 | 同 GA 版本升级、同坐标多实例、classifier/type、文件改名、base-only/current-only、显式 lineage、shaded/relocated、synthetic 重编号、ambiguous pairing 禁止猜配 |
| 源码/运行时裁决 | 手写/生成源码分别造成 effective contract、IR、运行时可消费 metadata/resource/topology 变化；artifact-local 变化被 shadow、源码文本变化但只产生安全白名单属性；纯重打包、构建元数据和重新签名；source diff 成功/失败、可映射/不可映射不得改变 runtime-effective 裁决 |
| 资源差异 | 仅重新签名、Manifest 构建字段与运行时字段、LICENSE/NOTICE/SBOM/随包文档的 distribution-metadata 三重门禁正反例、SPI、Spring/MyBatis metadata、properties/XML/YAML、native/nested executable、Graal 配置、重复 key、未知格式、动态读取覆盖不完整 |
| 源码关系 | 无源码、错误 ref、源码与制品冲突、生成代码、一个成员多个 alias |
| 业务入口 | main/manifest、servlet、framework route、listener/scheduler/messaging/RPC/agent、外部入口清单、possible activation、测试入口默认排除、源码缺失 |
| JVM 方法 | 重载、同简单名不同 owner、static/virtual/interface/special、构造器、`<clinit>` 主动使用/父类初始化、lambda SAM binding、custom bootstrap、condy |
| 生成结构 | lambda、方法引用、bridge、synthetic、匿名/内部类；Lombok 成员；annotation processor；ERM/ER/数据库 Schema、OpenAPI、Protobuf/IDL 生成 DTO/实体/客户端；generator 版本、配置或输入变化但手写源码未变；生成源码不存在或无法映射 |
| 字段/内联 | get/put static/instance、descriptor、编译期常量、Kotlin/Scala inline；changed-with-source、retained-base/unchanged、introduced/removed、proven/possible binding、uncertain 传播和禁止字面量猜边 |
| 类型 | new、cast、instanceof、数组、class literal 与纯常量池候选区分 |
| 制品拓扑 | thin JAR 阻断、BOOT-INF、WEB-INF、nested JAR、shaded JAR、classpath/module-path 顺序、loader realm/父子委派变化 |
| 运行时变换 | Java agent/JVMTI/redefine/runtime weaving/hidden class/动态插件的已建模、变换后 class 已提供、未建模 coverage 降级 |
| MR-JAR | target JDK 8/11/17、target JDK 未知、错误 variant 不得混入 |
| provider | initiating/defining loader 与 module、同 loader 不同 caller module/resolution mechanism、realm 内 first-wins、跨 realm 委派、module readability、equivalent-code-only 与 runtime-equivalent 区分、同 owner 不同 loader、CodeSource/签名/package sealing、base/current provider delta、顺序/loader policy 未知 |
| class definition | target JVM classfile major、format/verification、super/interface/module dependency、signer/sealing；definition-ready、精确失败、ambiguous/unsupported 与 `<clinit>` 分离 |
| member resolution | inherited field/method、interface/default method、构造器、private/special、static/instance mismatch、访问失败、no-class/no-such-member、runtime-equivalent member set、unsupported policy |
| dispatch | 继承、接口、default method、bridge、final/private/special、多实现、receiver proven/unknown、exact/proven/possible certainty、mixed receiver、开放世界 partial-known set、provider/member ambiguity 阻断 dispatch、MR-JAR |
| 图查询 | 直连、多跳、递归/互递归 SCC、exact/possible 分层压缩、possible-layer 适用/不适用与空集合反例、canonical route 稳定性、多入口、高扇出、确定性 cap、截断元数据、无路径 |
| 语义机制 | Spring、MyBatis、SPI、反射、MethodHandle/VarHandle signature-polymorphic 绑定、资源配置、源码候选不得自证激活、mechanism verifier 失败 |
| 缓存 | 各层单独命中/失效、source/config/target 变化、identity 缺失、缓存损坏 |
| 快照生命周期 | decision/assessment/formal-projection/candidate-projection 四层分别升级、纯 projection/Oracle 能力变化、跨 snapshot 污染、supersession 分叉/成环、generation 原子发布与回滚 |
| 故障 | 漏 class、解析失败、错 descriptor、删边、缓存污染、SQLite 中断 |
| 确定性 | 线程数变化、cold/warm、多次运行结果一致 |
| 结果语义 | confirmed change + exact/proven reachable + probable impact + required_not_executed；结构不兼容只写 incompatible-if-executed；静态 v2 禁止 confirmed impact/no-impact/not-required |
| 未裁决差异 | candidate diagnostic plan 的 targetable-complete/partial 与 unbound-complete/partial/failed、零 target 不漏 fact；candidate reachable/uncertain/not-found/not-analyzed 独立输出、summary fact/plan/projection 诊断计数、正式影响计数为 0、candidate 升降级后三通道互斥 |
| 投影/聚合 | 一 fact 多 target、单 target 多 projection rule/required-edge-family obligation、多 fact 同 API、跨 loader realm 禁止误去重、exact/possible/failure 聚合优先级、obligation/projection/API 多层计数守恒、superseded audit |
| 兼容性 | alerts、summary、by_api、Step6、query exact/fuzzy |

### 14.3 独立验证

现有 [`final_artifact_edge_oracle.py`](../../scripts/final_artifact_edge_oracle.py) 可以作为 symbolic invoke/field edge 的独立起点，但不能被写成已经验证完整目标图。当前 [`edge_truth.py`](../../scripts/edge_truth.py#L10) 的比较 identity 只有 artifact SHA、caller/callee owner/member/descriptor 和 opcode family，不包含 ArtifactInstance/classpath slot、resolved provider、BCI、bootstrap/handle、dispatch 或 TypeEdge。

切换 binary 权威前必须建立并版本化 `artifact_diff_support_manifest`、`runtime_loader_support_manifest`、`class_definition_support_manifest` 和 `oracle_support_manifest`，分别明确规范化/分类、provider/resource selection、目标 JVM class-definition/linkage 及独立验证范围，以及 classfile major、opcode/attribute/dynamic family、target JDK/MR policy、loader/module/security policy、inline language/compiler、identity 字段和已知排除项。未列入 manifest 的能力不能以“尽力解析”进入正式闭集结论。必须补齐以下彼此独立的验证层：

每次独立验证另建 `validation_run_identity = analyzed result-generation/snapshot-set identities + oracle_support_manifest_identity + truth-set identity + validation-policy/schema version`。Oracle 只读取待验证输出并产生 validation result，不得进入 `AnalysisScopeIdentity`、生产 decision/assessment/projection identity，也不得调用生产实现生成 truth；升级 Oracle 只使 validation run 失效，不得改变被验证的分析结果。

1. **artifact-normalization/pairing goldens**：使用独立 archive inventory/classfile parser 或手工 fixture，分别构造 payload 相同的容器/classfile 噪声和 payload、contract、IR、runtime metadata、resource、topology 真实变化；覆盖 exact/base-only/current-only/ambiguous pairing、同坐标多实例、shadowed artifact、distribution-metadata 三重门禁、Lombok/processor/ERM/Schema 生成 class，以及同一源码在不同受支持编译环境下的已知等价/非等价输出；独立标注全局 BuildInputManifest 相同、fact slice 完整相同和 slice 缺失/差异场景，验证 artifact-local、environment attribution 与 runtime-effective decision 分层正确；不得调用生产规范化器、pairer、slice builder 或 resolver 生成期望值；
2. **symbolic direct-edge Oracle**：扩展现有 Oracle 或增加手工 classfile goldens，覆盖 caller ArtifactInstance/entry、BCI 和 invoke/field symbolic target；dynamic facts 不得压扁进该 Oracle；
3. **dynamic/bootstrap Oracle**：独立验证 invokedynamic、LambdaMetafactory binding、custom bootstrap、`CONSTANT_Dynamic`、MethodHandle/MethodType、VarHandle access mode 及 signature-polymorphic invocation/access binding，确保 lambda/handle 创建或装载不等于目标方法/字段访问；
4. **binding-discovery/provider/resource-selection/topology Oracle**：输入 base/current raw inventory/reference/registration、request/runtime-origin seeds、有序 ArtifactInstance、实际 platform-image/容器提供事实、container/classpath/module slot、delegation/readability policy、resource mechanism 和 RuntimeProfileIdentity/RuntimeComparisonIdentity，独立建立 pre-resolution discovery set，再输出已收敛的 initiating/defining loader/module context、四类 final universe、context→key 适用关系、effective class/resource/platform selection、status 及 delta；覆盖 parent delegation 使 caller defining loader 与 request/path-owner loader 不同、多 round 才发现 bootstrap/hierarchy key、无界动态 context 降级和 fixed-point limit failure。不得把 production 已算好的 final context/universe 当 Oracle 输入，也不得调用生产 discovery/provider/resource resolver；
5. **class-definition/linkage Oracle**：在 provider selection 之后，按实际目标 JVM/platform/module/security 输入独立验证 classfile major、format/verification、必要 super/interface/module dependency、signer/sealing，并输出 definition-ready、scope-local runtime-equivalent 或精确失败；不得用“ASM 能解析”或“provider 已选中”替代 JVM definition 资格，也不得把初始化结果混入本层；
6. **symbolic-member-resolution Oracle**：在已知且 definition-ready 的 class provider 上按 opcode、caller、owner、hierarchy/interface、access 和 static/instance kind 独立验证 resolved member、scope-local runtime-equivalent member set 或精确 linkage failure；验证 equivalence set 时必须逐候选产生期望结果，禁止选取任一 physical member 代表集合；不得用生产 dispatch resolver 代替；
7. **dispatch/hierarchy Oracle**：逐适用 direct edge 验证唯一 `DispatchResolution`、virtual/interface 声明 target 到 implementation target 的结构候选和 `exact/proven_receiver/possible` certainty，覆盖继承、接口、default method、bridge、final/private/special、逐边 receiver proof、mixed receiver set、开放世界 partial-known set、抽象无具体实现、不完整子类闭包、provider/member ambiguity 阻断和 MR-JAR；仅验证 CHA 候选合法性不能把 possible 标成 exact，已知合法 target 不得因未知余量被清空，`no_concrete_implementation/unresolved` 不得产生猜测 implementation edge，空 concrete set 也不得在没有独立 invocation-selection/linkage 证据时自动变成 `incompatible_if_executed`；
8. **type/class-init/linkage Oracle**：独立枚举 `new`、array、cast、`instanceof`、class literal 等受支持 TypeEdge，并验证主动使用到 `<clinit>`、父类/接口初始化顺序、descriptor/catch/bootstrap 等受支持 LinkageEdge；区分 type load、link 和 init；
9. **inline-consumption goldens**：按受支持 compiler/language 独立构造常量/inline consumer，验证 changed-with-source、retained-base/unchanged、proven/possible binding、uncertain/coverage 传播和禁止字面量猜边；
10. **semantic goldens**：按 mechanism 验证候选/激活独立性、端点、完整业务路径和 edge-local proof；全局 coverage 只约束负向闭集，不能用 bytecode Oracle 代替。
11. **business-entrypoint goldens**：按 runtime profile 独立验证 manifest/module/classfile annotation/resource registration 到 RootEdge 的 proven/possible/inactive/unresolved 裁决；源码缺失不删除制品入口，测试/工具入口不默认进入生产根。

只有 support manifest 声明的 JVM direct/type/dynamic/class-init/linkage/dispatch edge 才要求按各自 identity 和 certainty 达到 precision/recall 100%；不得把该指标泛化到任意反射、代理或其他动态行为。目标反向闭包对账必须基于已经通过 pairing/runtime-effectiveness、loader/class-provider/class-definition、symbolic-member-resolution、dispatch 与相关 mechanism 校验的图，而不是只比较 raw symbolic edge。

必须加入 mutation：

- 随机修改 ZIP 时间戳、entry 顺序、压缩方式和 comment，payload 不变；
- 修改 Unix mode、symlink/external attribute 或未知 extra field，并错误按普通容器元数据排除；
- 修改解压 payload、nested/runtime topology 或 effective MR variant；
- 把 ambiguous artifact pair 强配为 exact、按文件名/坐标错配，或对多实例做笛卡尔积 member diff；
- 修改被 shadow 的 artifact-local class 后错误生成正式 target，或改变 effective provider/resource 后仍因 local pair/SHA 相同输出无变化；
- 对 selected/effective changed member 构造静态未命中，然后错误用“不会加载/没有调用链”反向排除变化 decision；
- 将 shadowed caller 的 raw edge 混入 EffectiveGraphView，或用全局 effective 布尔值删除另一个 loader realm 的真实边；
- 配置未建模 runtime transformer/agent 后仍把变换前图标记为 coverage complete、输出完整静态未命中，或把经过可变换 class/edge 的 pre-transform 路径当作正式 reachable；
- 只增删调试属性，或修改 opcode、字面量、bootstrap、runtime metadata；
- 将 packaging/classfile/build-metadata-only 噪声错误提升为代码变化，或让 source mapping 失败导致有效 contract/IR/runtime metadata 变化被排除；
- 仅修改 build-environment identity、仅观察到 same-input 输出不同或笼统声称构建不稳定就错误声明 `proven_noise`，或将严格 nondeterministic-output/environment `diagnostic_only` candidate 混入正式目标/影响计数；
- 全局 BuildInputManifest 不同时用 partial/failed/unknown FactBuildInputSlice 伪造 same-input，或在 classpath/processor/generator/plugin/Schema 已影响当前 fact 时仍把真实生成代码变化降为 environment candidate；
- 向 checkout worktree 注入 tracked/ignored stale output，或污染 build-cache provenance 后仍接受为 clean fixed-revision artifact；
- 只改 source revision 或 ASM/parser 版本就改写 BuildInputManifest/artifact-content/build provenance identity，或复用未隔离 compiler daemon/incremental state 仍声称 clean build；
- 隐藏 candidate、跳过可绑定 candidate 的诊断追踪、把 candidate reachable 错写为 `probable_impact`，或把 candidate not-found 错写为 `excluded`；
- 删除零 target candidate 的 diagnostic plan、把 partial/failed target discovery 写成 complete，或让 unbound plan 持有 projection/targetable plan 没有 projection；
- 将 superseded candidate 继续计入 active summary，或物理删除/改写旧 decision 和 trace；
- 只升级 projection registry/rule、target-discovery 或 Oracle fixture 就错误 supersede runtime-effective decision，或将新 assessment/projection 与旧 snapshot 的 trace/report 混成一个 active generation；
- 破坏四层 snapshot 成员清单/外键、制造 supersession 分叉或环，或让查询按最大时间戳挑选彼此不兼容的 active 行；
- 在不改变 identity 的情况下篡改 decision outcome/reason/coverage、authoritative fact payload、assessment target/obligation-set/status 或 formal/candidate projection payload，并让读取器接受最后写入值；
- 污染/删除 environment identity 或复用旧 environment-attribution cache，使真实生成代码变化被误判为环境噪声；
- 将生成 class/member 标记为 `generated` 后从比较或目标集中错误删除；
- 修改 generator 版本、配置或 ERM/Schema/IDL 输入，使最终 DTO/class contract 或 IR 改变而手写源码保持不变；
- 把未知 attribute/resource、重复 entry 或解析失败错误归为无变化；
- 仅凭 LICENSE/NOTICE/SBOM/`META-INF/maven/**` 文件名排除资源变化，或 exact key 已有运行 consumer/raw-resource scope 内可观察时仍写 `DISTRIBUTION_METADATA_ONLY`；
- 修改 Manifest runtime key、SPI provider 或框架/配置资源；
- 在其他 payload 不变时重新签名，并错误排除 signer/security 变化，或错误伪造为普通 API 调用链目标；
- 删除真实边；
- 删除 final artifact 已证明但没有源码 alias 的 business RootEdge，或把 possible/test-only entrypoint 提升为生产 exact root；
- 修改 descriptor；
- 把 class provider binding 直接当作 definition-ready/member resolution，或将 ASM 可解析误当成目标 JVM 可定义，漏掉 unsupported major、format/verification、super/interface/module dependency、signer/sealing failure；
- 将 definition 失败/unsupported caller 的 raw edge 混入正式路径，或没有业务类定义触发路径就把坏 class 报成 reachable linkage impact；
- 漏掉 inherited/default member、access 或 static/instance linkage failure；
- 将 `runtime_equivalent` provider/class-definition/member set 任取一个 physical member、丢失集合成员/scope，或让 `equivalent_code_only` 获得 exact 路径资格；
- 修改 BCI 或 invokedynamic bootstrap/handle；
- 将 LambdaMetafactory implementation handle 直接连成 caller 对 lambda body 的普通调用，或漏掉 custom bootstrap/condy；
- 将 `ldc MethodHandle` 直接连成目标调用，或未证明 handle 数据流就把 `invokeExact/invoke` 标为 exact；
- 把 VarHandle access-mode 当作普通 descriptor 方法调用，或未绑定具体 field/access mode 就伪造 exact field edge；
- 删除/伪造 class-init 主动使用边，或把 class literal/cast 错当初始化触发；
- 仅凭相同字面量/source-only reference 生成 inline edge，把 `retained_base/unchanged` consumer 写成 changed-with-source，或 inline coverage 失败后输出静态未命中；
- 绑定错误 ArtifactInstance/loader realm/provider，或漏掉 base/current provider delta；
- 把 initiating loader 与 defining loader 混用，或将同 owner 不同 defining loader 的类型/hierarchy/member 合并；
- 把 pre-resolution request/path-owner seed 直接当作 caller defining-loader context，或 fixed point 未收敛/超限时用当前 context/key 截断集冒充 final reconciliation snapshot；
- 把 authoritative change fact/projection 反向加入 class-owner/member universe，或在 exact-key resource consumer/entrypoint/semantic discovery 完成前先写 `BUILD_METADATA_ONLY`/`DISTRIBUTION_METADATA_ONLY`/effective decision；
- 在同一 loader 下跨 caller module 或 bytecode/launcher/reflection/service resolution context 复用 provider binding，掩盖 readability/access/selection 差异；
- 生成错误 dispatch implementation，或把 possible dispatch 标为 exact/reachable；
- 删除/重复某个 virtual/interface direct edge 的 `DispatchResolution`，把完整闭包中的无具体实现与不完整 hierarchy 都写成同一种空 dispatch-edge 集合，丢弃开放世界中已知合法 target，或仅因 closed-world concrete set 为空就伪造 `incompatible_if_executed`；
- 把 `MetadataReferenceFact` 伪造成 executable TypeEdge；
- 漏 class；
- 伪造额外边；
- 污染缓存身份；
- 截断路径；
- 将递归 SCC 无限展开、删除环内证据，或先混合 exact/possible edge 再压缩导致 certainty 污染；
- 在一 fact 多 target、单 target 多 rule/required-edge-family obligation、多 fact 同 API 或多 loader realm 时丢/重复 projection、引用 obligation set 外 key、跨 realm 去重，或把 obligation/projection 总数当 API 总数；
- 在 exact/proven 行为触达结果中错误写入 `not_analyzed`，或在当前静态 v2 中写入 `confirmed_impact`、`confirmed_no_impact`、正式 `runtime_verification_status=not_required`。

每项 mutation 必须由对应独立验证层发现；现有 symbolic Oracle 未扩展前，不能据其结果声称 pairing/runtime-effectiveness、loader/class-provider/class-definition/member-resolution、dispatch certainty、TypeEdge、dynamic/bootstrap、class-init/linkage 或 inline binding 已验证。

### 14.4 现有回归测试迁移

以下测试当前固化了旧语义，实施状态模型时必须同步反转，不能通过新增一套旁路测试掩盖旧断言：

- 精确源码调用链的行为变化测试当前只使用 `ast_method_invocation`，并断言 `not_analyzed`：[`test_step5_key_matching.py`](../../tests/test_step5_key_matching.py#L5411)。不能直接把断言反转为 authoritative `reachable`；必须把 fixture 重写为带 current-final-artifact 身份的二进制 direct path，再断言新复合状态。若仍只有源码 direct call，则继续作为 conflict/hint，不能进入该状态。
- 业务最终制品字节码直接命中的行为变化测试也断言 `not_analyzed`，但当前 fixture 的 change `confirmed=false`，mock hit 也缺少 SHA、物理 entry、class-provider/class-definition/member-resolution 和 runtime scope：[`test_step5_key_matching.py`](../../tests/test_step5_key_matching.py#L23125)。必须先补齐“runtime-effective 二进制变化已确认”和完整物理路径事实，才能断言第 1.1 节状态；若不补齐，预期应保持 `inconclusive`。外部依赖命中但未回到业务入口的相邻用例不得继续用 `uncertain` 伪造完整 possible path：补齐闭包后无根路径则断言 `not_found_in_static_analysis`，闭包不完整则断言 `not_analyzed`，并单独保留 dependency-local evidence：[`test_step5_key_matching.py`](../../tests/test_step5_key_matching.py#L23176)。
- formatter 汇总测试当前用“没有调用链、`is_reachable=false`”的 fixture 产生 `probable_impact`：[`test_step5_key_matching.py`](../../tests/test_step5_key_matching.py#L10590)。该 fixture 必须补成真实 reachable 路径后才能进入 probable 分组；没有触达证据时不得仅凭 verification reason 产生“可能影响”。
- Step6 当前测试把“可能影响”放在 `not_analyzed_apis`：[`test_step5_key_matching.py`](../../tests/test_step5_key_matching.py#L14807)。应改为独立 probable bucket，并断言同一 API 不进入 confirmed-impact 或 not-analyzed 明细。

必须新增组合不变量测试：

```text
confirmed implementation change + exact/proven business reachability
=> reachable_count=1
=> probable_impact_count=1
=> confirmed_impact_count=0
=> confirmed_no_impact_count=0
=> not_analyzed_count=0
=> required_not_executed_count=1
=> not_required_count=0
=> formal_projection_total=1
=> unique_reported_api_total=1
=> reachability_total=impact_total=runtime_verification_total=unique_reported_api_total
=> projection_state_total=formal_projection_total
```

任何 `*_RUNTIME_VERIFICATION_REQUIRED` 被写成 blocking failure、`not_analyzed`、不完整路径或已执行测试证据时，质量门必须失败。本工程回归测试只证明产品实现符合上述合同，不得写入被分析 API 的运行时验证状态。

### 14.5 性能门槛

- 本节定义必须测量的维度；具体数值由阶段 0 的版本化 `performance_gate.json` 固定，不在尚无基线时虚构。
- 记录 cold/warm inventory、parse、DB write/index、overlay、trace、report 耗时。
- 记录 peak RSS、SQLite/cache/temp 峰值和 bytes/class、bytes/edge。
- 仅当 binary blob 层的全部 cache key 命中、缓存完整且校验通过时，warm run 的 classfile parser invocation 必须为 0；其他层按第 6.11 节独立失效。
- 单 artifact 变化只允许对应 fragment 重解析。
- target JDK 或 classpath 顺序变化必须重新做 provider binding。
- 至少在固定 artifact identity 的 400 JAR、10 万 class 和大批量 API 档位验证冷/暖性能；采样次数、warmup、p95 算法与异常值策略由 gate artifact 固定。
- gate 同时包含相对 legacy 基线和绝对资源上限；变更硬件、数据集或测量协议时必须生成新 gate 版本，禁止沿用旧阈值。
- 更快但少边、少 class、少路径或更宽松负向结论一律判为准确性回退。

## 15. 回滚策略

- 一次用户操作开始前固定 `legacy | shadow | binary_strict | binary_with_legacy_fallback` 策略。单个 analysis generation 的 engine 不得切换；fallback 策略只能在 binary generation 整体失败并丢弃后，新建一个纯 legacy generation。
- SQLite 和全部报告使用 run-generation staging 目录；完整校验后只原子切换 generation manifest/current pointer，不能逐文件覆盖当前完整结果。
- 构建失败不得覆盖上一份完整事实库。
- binary 模式发生身份、解析或 DB 完整性失败时，只有预先固定为 `binary_with_legacy_fallback` 才可另起完整 legacy generation；输出必须标记 `engine_mode=legacy_fallback`、关联原 binary failure generation/scope 和已知准确性边界，不能把 fallback 结果声明为满足 binary support manifest。`binary_strict` 直接失败，禁止逐 API/逐边混用。
- 回滚只丢弃本轮未发布的 staging generation；不得清理或覆盖上一份完整 `summary.json`、`alerts.csv` 和 query index。fallback 结果使用新的完整 generation 原子发布，禁止混合新旧输出。
- 已证明的存在性路径可以保留并标记 `path_set_complete=false`；无路径不得在覆盖失败时静默回落为无影响。

## 16. 实现清单（2026-08-09 已完成）

- [x] Step4 新增版本化 artifact-local-diff 与 runtime-scope-decision sidecar，分别保存配对范围物理差异及 loader/provider/resource effective 裁决、coverage、provenance 和提升/排除理由。
- [x] 将 orchestrator 拆为 Step4A artifact-local diff、Step5A target-independent reconciliation、Step4B decision/projection freeze、Step5B trace、Step6 report 的单向 phase manifest；禁止 Step4/Step5 递归回写同一 snapshot。
- [x] 冻结 scope-independent observed-delta、per-analysis-context disposition-obligation 与 immutable decision identity，authoritative/candidate/excluded 三套 active 互斥事实 schema、与 decision 分离且可 immutable supersession 的 AuthoritativeProjectionAssessment、targetable complete/partial 与 unsupported projection coverage、正式四维状态 truth table、非法组合和原子消费者迁移合同。
- [x] 实现 per-analysis-context 的 decision/assessment/formal-projection/candidate-projection 四层 active snapshot、完整成员 digest、无环 supersession、跨层外键验证和 generation manifest 原子发布；禁止 `is_active/latest` 临时拼装。
- [x] 实现 CrossVersionArtifactPairing、base/current runtime-scope correspondence 和 exact/base-only/current-only/ambiguous 裁决，禁止 coordinate/文件名猜配与多实例笛卡尔积。
- [x] 实现 artifact-local diff → class/resource selection → runtime-effective fact gate；被遮蔽/non-effective 差异只留审计，selection 不完整进入 candidate。
- [x] 实现完整归档安全扫描、effective entry inventory、解压 payload 比较和 MR-JAR target 选择。
- [x] 实现版本化 classfile 安全规范化白名单、独立 verifier、未知 attribute 失败关闭和 noise facts。
- [x] 在 Step1 落实 clean-output/build-cache provenance，分别固化 base/current `BuildEnvironmentIdentity`、`BuildInputManifestIdentity`、`ArtifactBuildProvenance` 与 determinism controls；实现环境/输入/provenance 分层、保守 `FactBuildInputSlice`、版本化环境敏感/非确定输出候选规则和独立等价 verifier。
- [x] 实现独立 base/current `RuntimeProfileIdentity`、实际 platform-image/等价模型身份、`RuntimeComparisonIdentity`、`AnalysisScopeIdentity`、field coverage 与多 profile-pair/scope，禁止从 BuildEnvironmentIdentity 猜生产 JDK/OS/launcher，也禁止把分析策略写成运行环境变化。
- [x] 实现 `authoritative | diagnostic_only | excluded` 三类分析资格，确保编译环境/非确定构建疑似 candidate 只进入独立诊断 sidecar，不进入正式影响分析或统计。
- [x] 为每个 candidate 实现独立 `CandidateDiagnosticProjectionPlan`，零/部分 target 全量记 discovery coverage；对所有可绑定 target 实施独立批量反向传播，产出 candidate reachability/report 和 summary fact/plan/projection 非影响诊断计数，保证候选既不误报变化也不被隐藏。
- [x] 实现 confirmed-unprojectable 与 targetable-partial report、summary 主提示和 completeness 传播：零 target 与“已有 target 但仍有未覆盖 scope”分别闭合，禁止已确认变化被静默丢弃、伪造 API 占位或用一个已知 target 掩盖其余范围。
- [x] 将 Lombok、annotation processor、ERM/Schema/IDL 和编译期增强产生的最终 class/member 纳入与手写代码相同的差异提取、目标提升和 coverage 分母。
- [x] 实现 runtime-effective 变化/非运行时噪声分类器：安全表示等价和已证明 non-effective 的物理差异只写最小排除证据且不进入目标，effective contract/IR/运行时可消费 metadata/resource/security/topology 变化不得误排除；运行诊断 attribute 按 `AnalysisScopeIdentity.analysis_observability_scope` 单独记账，重签名不按通用噪声排除，未知项失败关闭为 candidate。
- [x] 实现 resource/runtime-topology 分类注册表与 semantic adapter coverage；禁止把非 `.class` payload 统一忽略。
- [x] 将 Java agent/runtime transformer/plugin profile 纳入 runtime support manifest；无变换后 class 或 verifier 时降低受影响 scope coverage，且经过可变换 class/edge 的 pre-transform 路径不得作为正式 reachable。
- [x] Step4 对所有适用 old/current JAR 常态执行方法实现比较。
- [x] 增加 exact JVM change fact sidecar，不只依赖人类签名 CSV。
- [x] 解耦 direct-artifact binary 主线与 Step2 固定源码门槛；缺源码只降低 overlay/semantic coverage。
- [x] Step1 分别固化 base/current 完整业务最终制品、受支持运行依赖/容器提供闭包、有序 classpath/module-path/nested slot 及 loader/resource 快照；局部闭包必须按 scope 降级。
- [x] 实现版本锁定 ASM helper、流式 raw-fact 协议、parser/support manifest 和不支持 classfile 的 scoped failure。
- [x] 将 `Step5ArtifactFactStore` 从 coordinate-keyed 重构为 ArtifactInstance-keyed，建立统一 loader/artifact/class/member/edge/provider 身份。
- [x] 建立 method/field/type/dynamic/bootstrap/class-init/linkage/class-provider/provider-equivalence-set/ClassDefinitionResolution/symbolic-member-resolution/member-equivalence-set/`DispatchResolution`/dispatch-edge 事实、certainty 及版本化 SQLite binary core 和 raw/effective 守恒 coverage ledger；禁止把 provider/parser success 冒充 class definition success，禁止用任意 physical member 代表 equivalence set，也禁止从空 dispatch 集合直接推导链接失败。
- [x] 实现 base/current pre-resolution discovery snapshot 和包含 target-independent consumer/entrypoint/semantic discovery 的版本化有限 fixed point，在 combined closure 收敛后冻结 initiating-resolution-context/class-owner/symbolic-member/resource-key 四类 final reconciliation universe 及 context→key 适用关系，建立 loader/provider/resource-selection compact view 和 provider/runtime-topology delta；不得读取 authoritative change fact/projection 反向裁剪分母，base 节点不得混入 current path。
- [x] 建立 per-runtime-profile/per-loader-realm EffectiveGraphView，caller 与 callee 均按 effective membership 过滤，raw shadowed edges 只留审计。
- [x] 实现 compile-time constant/Kotlin/Scala inline 的 changed-with-source/retained-base/unchanged 与 proven/possible binding、coverage；禁止字面量猜边。
- [x] 按 binary/provider/source/semantic/change/trace 分层实现缓存 identity 与精确失效。
- [x] 将源码图降为 source alias 与 semantic overlay。
- [x] 将 business entrypoint/RootEdge 从源码节点解耦，按 runtime profile 建立 proven/possible activation 和独立 coverage。
- [x] 实现 mechanism-specific semantic eligibility verifier，禁止源码候选自证激活。
- [x] 将 virtual/interface dispatch 分成 exact/proven_receiver/possible，只有 exact/proven path 可输出正式 reachable。
- [x] 实现 fact↔target 多对多、target×rule×required-edge-family obligation 分母、formal/candidate projection、逐 projection 多目标反向传播和 projection→reported API 无损聚合/obligation-projection-API 多层计数守恒；分别构建 exact/possible SCC-condensed DAG 与 canonical routes，分层记录 path-set completeness，枚举截断使总体 completeness=partial 但不删除已证明存在性。
- [x] 引入正式四维结果状态、`static_linkage_status/dispatch_certainty`，修正 `BEHAVIOR_CHANGED` 触达结论并禁止静态 v2 输出 confirmed impact/no-impact/not-required。
- [x] 更新 formatter、Step6、alerts、summary、by_api 和 query consumer。
- [x] 建立 legacy/shadow/binary strict-or-whole-generation-fallback 双跑与逐 projection/逐 API 对账。
- [x] 扩展 symbolic Oracle，并新增独立 pairing/runtime-effectiveness、loader/provider/resource-selection、class-definition/linkage、member-resolution、dispatch-certainty、type/class-init/linkage、dynamic/bootstrap、inline 验证层和 semantic goldens。
- [x] 产出并通过版本化 performance gate、独立 Oracle mutation、真实 `javac`/JAR 端到端工程 fixture 和 400 JAR / 10 万 class / 1 万 API 规模门槛；外部真实生产工程仍属于每次发布/灰度的输入验收，不伪装成本分支已经执行的证据。
- [x] 从 binary generation 删除 source-first ingestion 和 target-driven 重扫补偿路径；旧实现仅隔离保留给显式 `legacy`、`shadow` 与 whole-generation fallback。物理删除 legacy 代码须等待运营灰度完成，不属于 binary 权威实现的发布前置条件。

## 17. 完成定义

以下完成定义已由合同测试、独立 Oracle、兼容输出测试和规模门禁共同覆盖；能力范围以 support manifest 为边界：

1. binary core 已成为生产 direct/type/dynamic/class-init/linkage/dispatch 事实的唯一权威来源，business entrypoint/RootEdge 不再隐含依赖源码节点，source-only direct edge 不进入正式图；
2. 源码缺失或映射失败不再导致真实 executable edge 被拒绝；
3. Step1 已固化 base/current 完整受支持 runtime closure 和有序运行快照；Step4 已按跨版本 pairing、容器、classfile、resource 和两侧 runtime-effective selection 产生版本化差异/裁决事实，原始 JAR SHA 和任意 non-effective 物理差异不再直接提升为代码变化；
4. 不改变当前 analysis context 中 runtime-effective/可观察事实的 packaging/classfile/build-metadata、已证明 non-effective 的差异和已独立证明的编译环境/非确定构建噪声不产生正式 projection 或影响计数；运行诊断 metadata 按 AnalysisScope 单独记账，effective signer/security 变化不被当作通用噪声。active authoritative/candidate/excluded decision 完全互斥且历史 immutable，每个 authoritative fact 恰有一个独立、可 supersede 但不改写 decision 的 active projection assessment，每个 candidate 恰有一个独立 diagnostic plan 且零/部分 target 不漏记，decision/assessment/formal-projection/candidate-plan+projection 四层 snapshot 外键守恒并按 generation 原子发布，targetable-complete/targetable-partial/unsupported projection coverage 完整记账，所有可绑定 candidate 都完成独立触达分析并进入不确定性清单；effective contract/IR/运行时可消费 metadata/resource/security/topology 变化不被错误排除；Lombok、annotation processor、ERM/Schema/IDL 等编译期生成代码与手写代码使用相同裁决且无漏变更；仍可能被当前 scope 选择/观察的未知或不完整比较/pairing/selection 不能产生“已排除”或完整无变化，独立全 scope non-effective 证明只能排除 runtime decision，不能抹掉上游 unknown/failure；
5. Step4 正式实现变化目标不依赖源码是否存在；
6. 正式四维状态已经贯通 Step5、所有输出和 Step6；fact↔target、target×rule×required-edge-family obligation、projection→reported API 聚合、多层计数及 exact/possible path-set completeness 全部守恒，candidate/excluded 使用独立 schema，静态 v2 不产生 confirmed impact/no-impact 或正式 not-required；
7. “已确认触达变化实现，可能受影响，需运行时验证。”只在 authoritative 变化与 exact/proven 路径组合中稳定输出；possible dispatch 始终为 uncertain；
8. `not_analyzed` 只用于 authoritative target 的真实分析失败或覆盖不完整，变化尚未裁决使用 candidate report；
9. artifact normalization/pairing/runtime-effectiveness 与 symbolic/loader-provider-resource-selection/class-definition/member-resolution/DispatchResolution/dispatch-certainty/type-class-init-linkage/dynamic-bootstrap/inline 独立验证层、semantic goldens 和真实工程对账没有漏变更、漏边、错 certainty、错绑定、错 projection 聚合或错误闭集结论；
10. 输出兼容、冷暖性能、峰值 RSS 和磁盘预算通过阶段 0 版本化 `performance_gate.json` 的固定门槛；
11. Step4A→Step5A→Step4B→Step5B→Step6 单向 phase manifest、clean-output、相互独立的 BuildEnvironmentIdentity/BuildInputManifestIdentity/ArtifactBuildProvenance 与保守 FactBuildInputSlice、base-current RuntimeProfileIdentity/RuntimeComparisonIdentity/AnalysisScopeIdentity、pre-resolution discovery + consumer/entrypoint/semantic combined closure 已收敛的有限 fixed point + 四类 final reconciliation universe/context→key 适用关系、platform image、ASM parser identity、runtime loader/class-definition/transformer support manifest 和分层缓存失效均已生效；
12. 当前架构文档、用户输出文档、SKILL 规则和 TODO 已同步更新。
