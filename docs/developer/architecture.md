# 系统架构

## 1. 总体边界

`java-upgrade-analyzer` 是一个以最终制品为事实源、按状态机执行的 Java 升级影响分析器。

系统分为三层：

1. Step0–Step3：统一确认输入，固定分析对象、依赖闭包与升级背景；
2. Step4–Step6：单一 binary-first 引擎生成变化事实、静态触达结果和最终报告；
3. 调度与交互：保存主状态、门控、原子发布、恢复、进度和用户确认。

Step4–Step6 不存在旧引擎选择、shadow、灰度、兼容模式或 fallback。详细引擎合同见 [Binary-first / Source-overlay 最终设计](binary-first-source-overlay-design.md)。

## 2. 架构目标

系统持续同时满足：

- 准确性：最终制品与运行时事实决定结论，失败关闭，证据可追溯；
- 用户体验：只询问会实质改变结果的外部事实/范围，所有正式结果有 Markdown/CSV 人工入口；
- 性能：制品一次采集、批量建图/遍历、内容寻址缓存，并记录耗时和内存。

准确性是底线；源码覆盖、性能优化和人工展示均不能改变权威事实集合。

## 3. 状态机与调度器

统一入口是 `scripts/run_step.py`，步骤定义在 `scripts/step_manifest.json`。

```text
step0 → step1 → step2 → step3 → step4 → step5 → step6 → done
```

主状态：

```text
.upgrade-report/.runtime/state/main_state.json
```

辅助恢复状态：

- `last_step_summary.json`：轻量机器摘要；
- `resume_context.md`：可直接向用户说明的恢复摘要；
- `interaction.json`：待交互决策卡或 Step5 非阻塞信息卡。

状态语义：

- `ready`：上一阶段完成，`current_step` 指向下一阶段；
- `awaiting_*`：必须等待真实用户答复；
- `running`：当前有实际任务执行；
- `completed`：Step6 完成且无记录限制；
- `completed_with_limits`：Step6 完成但范围或证据存在明确限制；
- `failed`：当前阶段失败关闭，之前正式产物保留。

重跑某一步会清理该步及后续本轮产物，但保留之前步骤。binary generation 与人类报告另有原子发布保护，失败时恢复 active pointer 和发布前用户文件。

旧状态和旧交互协议不兼容当前状态 schema：加载到旧 schema 时直接建立新的 Step0，不复用旧 Step1/Step2 确认记录。

## 4. 目录架构

```text
.upgrade-report/
  README.md
  deliverables/
  evidence/
    dependencies/
    context/
    static_scan/
    api_changes/
    call_chain/
  .runtime/
    state/
    observability/
    cache/
    indexes/
    findings/
    binary_authority/
```

| 分区 | 职责 |
|---|---|
| `deliverables/` | 最终用户报告；依赖、API/路径、范围及 CSV |
| `evidence/` | 人工复核证据；按分析阶段分目录 |
| `.runtime/state/` | 状态机与恢复 |
| `.runtime/observability/` | 进度、耗时、内存与失败观测 |
| `.runtime/cache/` | 可验证、可失效重建的缓存 |
| `.runtime/indexes/` | 查询索引 |
| `.runtime/findings/` | 最终结构化程序结果 |
| `.runtime/binary_authority/` | immutable binary generations、SQLite、validation、failures 与 active pointer |

内部原始数据不复制到 evidence 冒充人工文件；人工报告也不放进 runtime。

## 5. Step0：正式分析输入确认

Step0 在任何 Maven/Gradle 构建和依赖解析前完成一次统一交互：

1. 自动识别 Base/Current 最终制品或源码构建模式；
2. 固定应用源码 Base/Current ref 到不可变 commit；
3. 分别识别目标模块、Maven/Gradle 与 JDK 目录；
4. 用相同表格展示 Artifact/源码模式；应用源码必填、依赖包源码可选；
5. 自动识别值也由这一次交互统一确认，缺失值在同一回复补齐。

确认后立即执行内容绑定的静态前置检查：两侧所选 JDK 以绝对路径实际完成
`javac -> javap -> java` 探针并验证目标平台镜像；固定源码 commit 的 worktree、对应
构建工具项目加载、ASM、直接制品和输出存储也在此处验证。确认记录位于
`.runtime/state/step0_confirmation.json`，前置检查及其身份位于
`.runtime/state/step0_preflight.json`。后续组件只能消费该身份对应的 JDK；不得再从进程
`PATH` 重新选择 `java`、`javac` 或 `javap`。只有 Step1 才物化的运行时闭包在产出后立即
进行摘要和完整归档校验，这是其最早可验证时点。

## 6. Step1：最终制品与依赖闭包

Step1 支持两类输入：

- 分支/tag/commit：固定远程 SHA，在隔离 worktree 中构建；
- 直接制品：用户提供 base/current JAR/WAR。

核心职责：

1. 使用 Step0 已确认的模块、工具链和应用源码 commit 产生或验证两侧最终制品；
2. 从 fat JAR/WAR 读取实际运行时依赖；
3. 建立 container entry、Maven coord、logical lineage 和 physical SHA；
4. 一次性留存后续需要的依赖 JAR 与业务内容；
5. 记录 build provenance；
6. 无歧义时自动继续；依赖身份或已提供依赖源码的仓库/版本存在歧义时一次汇总确认。

制品内 Maven 元数据优先；构建工具 resolved artifact 清单或项目模型只能补齐实际存在的条目，不能扩展闭包或覆盖已确定坐标。Thin JAR 不能证明完整运行时闭包，正式分析失败关闭。

人工输出位于 `evidence/dependencies/`。

## 7. Step2：升级上下文

Step2 读取 Step1 已固定事实，生成：

- `evidence/context/context.json`；
- `evidence/context/dep_graph.json`；
- `evidence/context/review.md`。

项目源码结构用于补充 Spring 和解释上下文。Step2 是内部步骤，不设置固定用户确认点。

## 8. Step3：背景兼容线索

Step3 扫描：

- JDK removed/internal API；
- `javax`/`jakarta` 迁移；
- Spring Boot 配置与自动装配；
- runtime flag、serialization、reflection；
- current 最终制品依赖兼容和 classfile 版本。

输出位于 `evidence/static_scan/`。Step3 是背景风险层，不得制造 Step4 正式 API projection，不覆盖 binary decision。

## 9. Step4：Binary generation 与 API 变化视图

生产入口：

- `scripts/binary_pipeline.py`：构建、验证、激活 immutable generation；
- `scripts/binary_report.py --phase step4`：发布人工 Step4 视图；
- `scripts/gate.py step4`：验证 generation 与人工视图守恒。

必需输入 `binary_pipeline_config` 固定：

- base/current artifacts；
- coord、lineage、container entry 和 runtime path；
- 完整目标 JDK；
- loader realms、ordered classpath 和 resource policy；
- entrypoints；
- 可选 source overlay。

内部单向 phase：

```text
Step4A artifact-local diff
  → Step5A runtime-effective reconciliation
  → Step4B decision/projection freeze
  → Step5B batch trace
  → Step6 snapshot
```

### 8.1 Binary components

- `binary_first_model.py`：schema 和 immutable identity；
- `binary_artifact_diff.py`：archive/classfile/IR/resource facts；
- `binary_runtime_resolver.py`：provider、definition、member/resource resolution；
- `binary_decision_engine.py`：authoritative/candidate/excluded；
- `binary_trace_engine.py`：entrypoint 到目标的 batch trace；
- `binary_output.py`：SQLite、sidecar、formal/candidate/coverage/summary；
- `binary_validation_oracle.py`：独立 Oracle；
- `binary_first_contract.py`：支持边界和守恒；
- `binary_report.py`：Step4–Step6 人工/程序发布视图。

### 8.2 人工输出

`evidence/api_changes/` 中：

- `changed_dependencies.md/.csv`；
- `s4_per_dependency/<coord>/summary.md`；
- `all_changed_apis.csv`；
- `business_bytecode_changed_api_refs.csv`；
- `business_bytecode_priority_evidence.json`；
- `summary.md/.json`；
- `review.md`。

`all_changed_apis.csv` 是 validated generation 的稳定用户视图，不是兼容投影。confirmed-unprojectable resource/security/topology facts 进入 `review.md` 和权威 decision，不创建占位 API。

## 10. Step4 范围交互

只有至少两个含正式 API projection 的依赖时才产生范围选择：

- 全量：分析所有目标依赖；
- 部分：用户按完整坐标或依赖名选择。

范围卡按依赖展示 Top 10，并提供 `changed_dependencies.md` 完整列表。排序使用业务最终制品精确直接引用、候选引用、指令数和 API 数；不因为删除/签名变化人为加权。

选择结果先写入主状态。Step5 验证坐标/名称确实命中 Step4 `all_changed_apis.csv`；协议冲突或空匹配停止，不能静默扩大为全量。

## 11. Step5：同 generation 触达发布

Step5 不重新扫描制品，而是从 active validated generation 发布用户选择范围：

- `evidence/call_chain/summary.md/.json`；
- `evidence/call_chain/alerts.csv`；
- `evidence/call_chain/by_api/*.json`；
- `.runtime/indexes/s5_query_index.json`。

### 10.1 正式四维

| 维度 | 值 |
|---|---|
| reachability | reachable / uncertain / not_found_in_static_analysis / not_analyzed |
| static linkage | compatible_or_not_applicable / incompatible_if_executed / undetermined |
| impact conclusion | probable_impact / inconclusive |
| runtime verification | required_not_executed / undetermined |

静态分析不输出 runtime-confirmed impact/no-impact。Step5 生成非阻塞四态信息卡后自动进入 Step6。

### 10.2 路径数据

每条路径同时保存结构化 edge 和可读文本：

- caller class/member/Java signature/artifact；
- edge kind 和 bytecode offset；
- resolved target；
- exact/possible certainty；
- 最终 API 所属 coord 和 base/current 版本。

查询工具读取内部索引，支持完整方法、coord、artifactId 和包前缀；查询未命中不解释为安全。

## 12. Step6：最终报告

Step6 只读取同 generation 的 Step5 范围，发布：

- `deliverables/report.md`；
- `deliverables/all-affected-dependencies.md/.csv`；
- `deliverables/all-impact-details.md/.csv`；
- `deliverables/analysis-scope.md`；
- `.runtime/findings/s6_findings.json`。

报告顺序固定为依赖层 → API/调用关系 → 文件说明。Markdown/CSV 从同一排序数据生成，并保留 coord、base/current 版本、四维状态和关键路径。

完成摘要使用“可能影响/仍不确定”，不保留旧 severity bucket、`not_impacted` 或 confirmed impact/no-impact 空字段。

## 13. 失败关闭和原子发布

一个 binary generation 只有在以下检查都通过后才能激活：

- artifact/runtime identity；
- support manifest；
- fact/decision/projection/API 守恒；
- trace/dependency binding；
- sidecar SHA；
- SQLite integrity；
- 独立 Oracle；
- performance gate。

失败记录在 `.runtime/binary_authority/binary_failures/`。active pointer 不切换，已有用户输出不覆盖，不创建旧引擎 generation。

人类发布也使用 staging + atomic replace。Step4/5/6 发布失败时恢复本轮前 active pointer 和用户文件，避免内部权威与人工报告撕裂。

## 14. Source overlay

Source overlay 是可选解释层：

- 绑定已经由 artifact identity 确定的类和成员；
- 提供源码位置、声明、注释和解释；
- 不参与 class provider、member resolution、dispatch 或 executable edge 裁决；
- 缺失或解析不完整时形成明确 coverage gap；
- 不要求用户批准二进制降级，因为不存在降级路径。

## 15. 观测与性能

统一进度位于 `.runtime/observability/progress.jsonl`。各阶段 timing 保存 phase、对象、状态、耗时、规模和可用时的进度分母。

Binary 性能策略：

- 每个 archive/classfile 每 generation 采集一次；
- Spring Boot 等容器中多个逻辑制品共享同一个外层 JAR 时，按稳定文件身份复用外层摘要，并在输入画像结束前再次完整校验；
- 内容寻址缓存绑定 artifact SHA、RuntimeProfile、parser 和 policy；
- 冷缓存解析复用 snapshot 自带的前后摘要校验；相邻 base/current 内容相同时只在内存保留一个解码模板，仍分别校验实际文件并重建 ArtifactInstance 身份；
- 独立 Oracle 仍对每个 base/current 制品实例分别绑定并比对生产数据库；只有 artifact SHA、目标 `javap` 与 class inventory 都相同的不可变规范化真值才跨侧复用，并在两侧 structural 校验完成后立即释放扫描缓存；
- target JVM 观测不会抽样或跳过；两侧完成观测和 declared-member 补全后，仅共享 JSON 类型及值都完全相同的只读字段，保持 canonical truth bytes 不变；
- 批量建图、SCC 和多目标遍历；
- 缓存完整性失败重建；
- 记录端到端耗时、phase 耗时、主/子进程 CPU、平均核数、主进程与已完成子进程峰值 RSS、archive/class/edge 数、摘要读盘量和缓存层级命中。

任何性能优化必须同时通过独立 Oracle 和性能门。

## 16. 测试分层

- 单元：schema、descriptor、identity、pairing、decision、projection、trace、report；
- 守恒：fact/decision/projection/API、dependency binding、generation identity；
- 故障：parse、JDK、entrypoint、Oracle、sidecar、SQLite、publication；
- 端到端：Step4→Step5→Step6、全量/部分范围、查询和恢复；
- 人工输出：Markdown/CSV 同源、依赖维度、Java 签名、关键路径、UTF-8 BOM；
- 性能：固定数据集冷/热执行、峰值内存和缓存；
- A/B：main 与当前分支消费同一 base/current 制品，先写独立真值，再比较漏报、误报、身份和路径。

全量测试结果只能证明实际执行的当前提交和环境，不得沿用旧运行结果。
