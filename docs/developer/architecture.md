# Architecture

## 文档定位

本文档用于描述 `java-upgrade-analyzer` 的当前实现。本文档回答三个核心问题：

1. 这套分析链路如何组织与运行
2. 它依赖哪些技术与内部契约
3. 它如何在当前静态分析边界内保证结果的准确性、可追溯性和可恢复性

本文于 2026-07-21 以 `main@69b60af` 为代码复核基线。五态裁决以
`scripts/step5_evidence_model.py` 为准，发布裁决以 `scripts/quality_gate.py`
为准；后续 HEAD 若发生变化，应以对应代码和当前提交上的测试结果更新本文，
不能把本页的复核日期当成新鲜验证证据。

本文档面向维护者、新工程师和其他需要理解或复现当前逻辑的模型。本文档描述的是当前实现，不承担运行期交互规则，也不替代：

- `SKILL.md`
- `RUNBOOK.md`
- `docs/developer/quality.md`
- `docs/archive/DESIGN_PRINCIPLES.md`

## 系统目标

`java-upgrade-analyzer` 是一个供 Claude Code 使用的升级兼容性分析 Skill。系统将升级问题拆成三层事实，并以正式流程串联：

1. 升级前后究竟变了什么
2. 这些变化是否触达当前业务系统
3. 哪些结果可以证明，哪些结果只能保守表达

因此，当前实现的正式链路由六个步骤组成：

- Step1：识别依赖变化范围
- Step2：收敛升级上下文
- Step3：扫描背景兼容性风险
- Step4：构建 API 变化证据池
- Step5：证明变化是否触达业务系统
- Step6：汇总最终 findings 和报告

## 阅读地图

本文档按以下顺序组织：

1. 先说明系统为什么采用 `jar + 源码` 的双证据模式
2. 再说明正式运行模型、主状态模型和调度职责
3. 然后逐步解释 Step1 到 Step6 的职责与契约
4. 最后集中说明 Step5 的实现机制、准确性保障、验证方式和已知边界

## 设计摘要

当前实现的关键判断如下：

- 升级变化识别依赖 `jar` 与产物层证据
- 影响证明依赖业务源码与依赖源码构成的静态图
- 正式流程只有一个调度入口：`scripts/run_step.py`
- 正式流程只有一个业务参数与状态真相源：`.upgrade-report/.runtime/state/main_state.json`
- `interaction.json` 只负责展示待交互信息，不参与求值
- Step5 的目标是高精度影响证明，不是最大召回
- 证据不足时系统进入保守状态，不将“未覆盖”误写成“未影响”

## 为什么必须是 `jar + 源码`

### 三种分析模式的能力边界

当前实现采用 `jar + 源码` 的组合模式。三种模式的能力边界如下：

| 模式 | 擅长回答的问题 | 主要短板 |
| --- | --- | --- |
| `只用 jar` | 哪些依赖 API 变了 | 很难证明业务是否实际触达这些 API |
| `只用源码` | 业务代码调用了哪些依赖符号 | 很难准确界定升级前后究竟发生了哪些正式变化 |
| `jar + 源码` | 依赖里变了什么，以及这些变化是否真正影响业务 | 仍受静态分析边界限制，但能力最完整 |

### `jar` 在当前实现中的角色

`jar` 相关能力主要落在 Step1 和 Step4，也会在 Step5 中提供类型补充信息。

当前 `jar` 承担四类职责：

- 作为 Step1 的正式输入之一，支持直接产物模式
- 作为 Step4 的二进制变化证据源，识别删除、签名变化、访问级别变化和类层次变化
- 作为 Step5 的类型补丁层，为依赖源码图补齐类层次和方法返回类型元数据
- 作为 Step6 最终交付的可追溯事实来源之一

### 源码在当前实现中的角色

源码能力主要落在 Step5。当前实现依赖源码完成以下工作：

- 构建 AST
- 提取方法定义和调用点
- 推断局部变量、receiver 和调用签名
- 构建 `reverse_edges`
- 对变更 API 执行反向可达性证明

### 只用 `jar` 为什么不足以形成当前效果

仅依赖 `jar` 可以识别“变了什么”，但难以稳定形成源码级调用链证据。原因在于：

- 字节码提供的是编译结果，不是源码中的调用上下文
- 局部变量、receiver、实参表达式和链式调用语义会明显弱化
- lambda、方法引用、泛型传播和部分多态信息在编译后退化
- 仅靠 `jar` 更容易得到结构层候选，较难得到可解释的业务调用证据

当前实现据此形成明确分工：

- Step4 负责证明变化存在
- Step5 负责证明变化触达业务

## 顶层架构

### 总体分层

当前实现可分为六层：

1. 调度与状态层
2. 步骤执行层
3. 契约与门控层
4. 分析引擎层
5. 报告交付层
6. 验证与回归层

```text
                 +-----------------------------+
                 |       run_step.py           |
                 | 调度 / 主状态 / 恢复 / 门控 |
                 +-------------+---------------+
                               |
        +----------------------+----------------------+
        |                      |                      |
        v                      v                      v
 +-------------+       +--------------+      +---------------+
 | Step1~Step3 |       |    Step4     |      |     Step5     |
 | 发现与上下文 |       | 变化证据池构建 |      | 调用链影响证明  |
 +-------------+       +--------------+      +---------------+
        |                      |                      |
        +----------------------+-----------+----------+
                                           |
                                           v
                                 +-------------------+
                                 |      Step6        |
                                 | findings / report |
                                 +-------------------+
                                           |
                                           v
                                 +-------------------+
                                 | gate / smoke / CI |
                                 +-------------------+
```

### 主要文件职责

#### 调度与状态层

- `scripts/run_step.py`
  - 唯一正式入口
  - 负责步骤解析、主状态维护、结构化恢复、统一落盘和重跑协调

#### 步骤执行层

- `scripts/s1_dep_diff.py`
- `scripts/s2_context_from_deps.py`
- `scripts/s3_scan.py`
- `scripts/s4_jar_compare.py`
- `scripts/s5_call_chain_engine_integrated.py`
- `scripts/s6_report.py`

这些脚本只负责本步骤事实生成与产物落盘，不承担跨步骤状态机职责。

#### 共享能力层

- `scripts/enhanced_source_analyzer.py`
  - AST、正则补充、调用边提取和类型推测
- `scripts/confidence_weighted_tracer.py`
  - 反向回溯、签名过滤、多态扩展和候选收敛
- `scripts/auto_discover_bridge_sources.py`
  - 依赖源码桥接发现
- `scripts/progress_logging.py`
  - 进度事件落盘与汇总
- `scripts/error_handler.py`
  - 统一错误承载
- `scripts/compat.py`
  - 运行兼容与命令封装

#### 契约与辅助层

- `scripts/step_manifest.json`
  - 固定步骤顺序和交互配置
- `scripts/pipeline_constants.py`
  - 共享常量
- `scripts/s4_contract.py`
  - 固定 `all_changed_apis.csv` 字段契约
- `CHECKPOINT_RULES.md`
  - 固定待交互最小规则

## 正式运行模型

### 唯一入口

当前正式流程只有一个入口：`scripts/run_step.py`。

任何正式执行都通过该入口完成以下动作：

- 解析 CLI 与当前执行意图
- 读取与更新主状态
- 应用结构化用户答复
- 解析当前步骤输入
- 执行前置交互或正式步骤
- 统一持久化成功、待交互和失败状态

### 唯一主状态

`.upgrade-report/.runtime/state/main_state.json` 是正式流程的唯一主状态文件，也是唯一业务参数真相源。

它承载：

- `state.*`
- 每一步的 `input`
- 每一步的 `derived`
- 每一步的 `output`
- 当前待交互元数据
- 已归一化且已确认的业务参数

一旦某个业务参数被写入 `main_state.json`，后续步骤必须只从这里读取，不再从 CLI、展示文件或历史产物重新决定真值。

### 主状态字段语义

当前 `state.*` 字段至少包含以下正式语义：

- `current_step`
  - 当前应执行或应恢复的步骤
- `completed_step`
  - 最近一个已完成并已写回主状态的步骤
- `status`
  - 当前运行态，如 `idle`、`ready`、`completed`、`awaiting_user_input`、`blocked_by_system`
- `blocking_reason`
  - 当前阻塞原因
- `pending_interaction`
  - 当前待恢复的 checkpoint 描述
- `last_user_response`
  - 最近一次已归一化并写回主状态的结构化用户答复

这些字段由调度层维护。步骤脚本不直接实现状态机迁移。

### 展示文件与证据文件

当前实现严格区分三类文件：

- `main_state.json`
  - 运行真相
- `interaction.json`
  - 当前待交互展示
- 各类 CSV、JSON、报告和摘要
  - 证据文件和汇总产物

当前正式流程明确禁止：

- 把 `interaction.json` 当作状态文件
- 把报告或摘要文件当作求值输入
- 让历史产物反向篡改主状态
- 显式重跑某一步时漏清该步骤正式输出，导致旧轮次证据混入本轮结果

### 正式执行与调试执行

当前实现支持两种运行形态：

1. 正式编排形态
   - 入口为 `run_step.py`
   - 真相源为 `main_state.json`
2. 单脚本调试形态
   - 入口为各步骤脚本 CLI
   - 仅服务局部调试，不改写正式主状态模型

这两种形态共享大部分实现，但正式语义只由正式编排形态定义。

## 调度器职责

### `run_step.py` 的职责分组

当前 `run_step.py` 的职责分为四组：

#### 输入与上下文准备

- `build_step_input_context()`
- `build_run_context()`
- `store_step_input()`

#### 恢复与重跑管理

- `clear_steps_from()`
- `reset_step_state_for_restart()`
- `prepare_main_state_for_step_execution()`

#### 结构化恢复协议

- `resolve_user_response()`
- `build_canonical_user_response()`
- `normalize_intent_patch()`
- `apply_structured_user_response_if_present()`
- `handle_step2_resume_followups()`

#### 执行结果持久化

- `persist_step_interaction()`
- `persist_completed_step()`
- `persist_interaction_required_error()`
- `persist_step_error()`

### 正式主路径

当前正式主路径稳定为：

1. 解析 CLI
2. 读取主状态
3. 应用结构化用户答复
4. 处理仍未消费的 pending interaction
5. 执行恢复后补充逻辑
6. 构建当前步骤 `run_context`
7. 执行前置交互或正式步骤
8. 统一持久化结果

### 主状态写回与下游播种

步骤之间的正式参数传递通过主状态写回与下游播种完成，不通过临时 CLI 透传。

关键函数包括：

- `store_step_output()`
  - 将当前步骤产出写回 `<step>.output`
- `seed_next_step_input()`
  - 将当前步骤对下游有效的正式输入播种到下一步 `input`
- `persist_completed_step()`
  - 在步骤完成后统一写回主状态并清理 `interaction.json`
- `persist_step_interaction()`
  - 在步骤进入 checkpoint 时统一写回主状态并落盘 `interaction.json`

## 步骤级设计

### Step1：依赖范围发现

Step1 负责识别依赖变化范围，并建立后续分析所需的最小可信输入。

当前实现的关键点：

- 支持 `artifact_inputs` 与 `checkout_build` 两种入口
- 输入不足时优先进入前置交互，而不是直接失败
- base/current 可共享同一个源码仓库路径；revision 才是两侧身份，解析后持久化 requested ref、resolved ref 与 immutable commit
- `artifact_inputs` 先解析最终 JAR，只有坐标缺失的一侧才按需解析 ref 并运行 Maven 补全；`checkout_build` 在构建前解析两侧 ref
- ref 解析只读取本地及现有远端跟踪 refs，不隐式 fetch；候选按 commit 去重，唯一 commit 自动采用，歧义在 Maven 前形成硬 checkpoint
- 坐标补全同时拿到 source directory 与 ref 时始终优先 ref；source-only 输入必须确认 HEAD 对应的 commit，不能直接分析可变工作区
- 所有分支构建和坐标补全使用 detached worktree，不改变用户仓库当前 HEAD 与未提交内容
- 首轮确认的模块范围必须尽早写入主状态
- 依赖坐标无法安全补齐时不伪装成功
- Maven 输出通过编排层实时转发，避免长时间构建期间完全无反馈
- `.runtime/observability/step1_progress.jsonl` 记录可增量读取的阶段事件；`ref_resolution` 事件保存 requested ref、resolved ref、commit、解析方式与候选数量
- `.runtime/observability/step1_timing.csv`、`step4_timing.csv`、`step5_timing.csv` 统一记录各阶段耗时与状态
- 进度与耗时属于诊断证据；正式依赖差异仍只在 base/current 两侧均成功后生成

### Step2：升级上下文收敛

Step2 负责把后续步骤真正依赖的上下文收敛回主状态，并产出 `evidence/context/context.json`。

当前实现的关键点：

- 确认 `base_branch/current_branch`
- 接受 `source_repo_hints`
- 处理依赖源码目录入口
- 固化确认后的映射
- 恢复时优先使用最新确认输入

### Step3：背景风险扫描

Step3 负责扫描升级背景中的兼容性风险信号，不负责最终影响判定。

当前实现主要扫描：

- JDK API 变化
- `javax.*` / Jakarta 相关变化
- 内部 API、反射和 Spring Boot 配置风险

Step3 的职责是暴露风险面，Step5 才负责证明这些变化是否触达业务系统。

### Step4：变化证据池构建

Step4 的职责是构建 Step5 可稳定消费的变化证据池。

当前实现的核心工作：

- 生成 JApiCmp 二进制兼容变化
- 生成依赖源码 `git diff` 变化
- 直接比较 old/current 最终 JAR 的实例字段，识别 DTO/数据对象字段新增、删除和类型变化
- 对 `removed jar` 场景导出旧版 jar 的 public/protected 符号集合
- 自动识别依赖源码目录与仓库映射
- 聚合生成 `all_changed_apis.csv`
- 按单个 `coord` 落盘 `s4_per_dependency/<coord>/` 目录，作为 Step4/Step5 的桥接视图

#### Step4 的正式语义

Step4 是变化识别层，不负责调用链分析。它定义“变更 API 池”，并把后续 Step5 所需的结构化证据统一到一个契约文件中。

当前关键语义如下：

- `dependency_source_dirs` 是推荐入口
- `dependency_repo_mappings` 是内部派生结果
- `s4_contract.py` 固定 `all_changed_apis.csv` 字段契约
- `removed jar` 不走旁路逻辑；正式语义是把旧版 jar 的 `class / method / constructor` 符号集导出为 Step5 目标池
- Step4 在报告根目录下为每个依赖写出 `s4_per_dependency/<coord>/removed_jar_symbols.csv`、`resolved_targets.csv`、`summary.json`
- 依赖源码仓库的 git ref 只从远端分支 `remotes` 中匹配，不直接沿用主项目分支名
- 版本匹配会先去掉末尾 `-SNAPSHOT`，再按“严格边界命中”筛选候选；像 `3.0.2` 不会命中 `3.0.2.1`
- `DEV/dev` 分支在同等条件下低于非 `DEV/dev` 分支
- old/new 两侧同时存在多个候选时，先要求候选各自命中规范化版本，再优先选择能够复现 `old_version -> new_version` 非核心 token 差分、且 remote 一致、版本前缀家族一致的 ref pair；若仍无法拉开差距，则进入人工确认

#### Step4 到 Step5 的正式契约

`all_changed_apis.csv` 是 Step4 的核心输出，也是 Step5 的正式输入。字段顺序和字段语义由 `s4_contract.py` 唯一定义。

当前最关键的字段包括：

- `coord`
  - 变更 API 所属依赖坐标
- `change_type`
  - `REMOVED` / `SIGNATURE_CHANGED` / `BEHAVIOR_CHANGED` / `ACCESS_REDUCED`
- `api_name`
  - Step5 主目标键来源
- `api_simple`
  - Step5 回退匹配来源
- `symbol_kind`
  - `method` / `field` / `class` / `constructor`
- `api_signature`
  - 方法和构造器的精确签名来源
- `confirmed`
  - 区分二进制确认结论与推断结论
- `severity`
  - Step6 汇总风险等级的基础字段
- `source`
  - 变更来源，如 `japicmp` / `gitdiff` / `changelog`
- `old_value` / `new_value`
  - `DATA_FIELD_*` 行中的字段旧类型和新类型
- `data_contract_evidence`
  - DTO/数据对象识别依据，例如命名/包结构、JavaBean/record 访问器或 `Serializable` 状态

`DATA_FIELD_ADDED`、`DATA_FIELD_REMOVED`、`DATA_FIELD_TYPE_CHANGED` 来自最终 JAR 的 classfile 成员表，包含 private 实例字段，排除 static、synthetic 和内部类 `this$` 字段。它们描述的是 DTO/数据对象结构变化，不等于数据库字段已经不匹配。

#### Step4 的 per-dependency 中间产物

Step4 现在会在报告根目录下为每个依赖额外生成 `s4_per_dependency/<coord>/` 目录，用于承接“单个依赖包为集合”的正式语义。

当前最小闭环中，这个目录包含三类文件：

- `removed_jar_symbols.csv`
  - 仅在 `change_type=removed` 时有实际内容
  - 保存旧版 jar 导出的 `class / method / constructor` 符号集合
- `resolved_targets.csv`
  - 保存该依赖最终归一化后的 Step5 输入视图
  - 已按 `coord + api_name + api_signature + symbol_kind + change_type` 去重
- `summary.json`
  - 保存该依赖当前阶段的最小摘要
  - Step4 先写入目标池规模、source 分布和 removed jar 导出元数据
  - Step5 再补写该依赖是否触达系统源码的结果

#### `jar` 元数据在 Step4 与 Step5 之间的桥接作用

Step4 不仅产出变化 API 池，也为 Step5 提供依赖坐标、版本和桥接线索。Step5 会据此定位依赖 `jar`，进一步抽取 `jar_metadata`，作为依赖源码图的类型补丁层。

这条桥接链路的目标不是让 `jar` 直接生成调用图，而是让 `jar` 补齐：

- 依赖类的 `extends / implements`
- 依赖类的方法签名与返回类型
- `coord -> jar -> class` 的归属关系

### Step5：调用链影响证明

Step5 负责证明 Step4 发现的 API 变化是否已经触达当前业务系统。

这里的“触达当前业务系统”不是狭义的 Controller 或普通业务方法。正式语义是触达任何有证据证明会影响系统运行的入口，包括业务制品代码、定时任务、消息/事件监听、生命周期入口、Runner/Lifecycle、SPI 与已激活的框架回调。只有条件声明、但当前制品尚未证明会激活的框架入口仍保留为 `uncertain` 或 `not_analyzed`。

当前正式输入：

- `all_changed_apis.csv`
- 业务源码目录 `source_dirs`
- 自动推断或用户补齐的依赖源码映射
- 必要时由 Step4 checkpoint 指定的目标 API 子集

当 `Step5` 作为独立 CLI 运行且未显式传 `--report-dir` 时，当前实现会优先从 `all_changed_apis.csv` 所在的 `evidence/api_changes/` 目录推导报告目录；若该输入也未提供，则再回退到 `output_dir` 的父目录。

当前正式输出：

- `evidence/call_chain/alerts.csv`
- `evidence/call_chain/summary.json`
- `evidence/call_chain/by_api/*.json`
- `evidence/call_chain/by_module/*_impacts.json`
- `evidence/api_changes/s4_per_dependency/<coord>/candidate_hits.csv`
- `reachable`
- `not_impacted`
- `uncertain`
- `not_analyzed`
- `not_found_in_static_analysis`
- `evidence/api_changes/s4_per_dependency/<coord>/summary.json` 中的单依赖结果视图

五态属于正式语义，不是展示标签。`not_impacted` 仅在当前制品中的其他运行时依赖以完全相同的类字节码保留目标 API 时成立；它不等于宽泛的“没有风险”。

#### Step5 的 per-dependency 汇总

Step5 在保留原有 `summary.json`、`by_api/*.json`、`by_module/*.json` 的同时，现在会把 API 级 `TraceResult` 再按 `coord` 汇总回 `s4_per_dependency/<coord>/summary.json`。

同时，Step5 现在会把 Step4 的正式 API 目标与 Step3 的 `s3_risk_candidates.csv` 做并集桥接：

- Step4 负责提供“已确认 API 变化事实”
- Step3 负责提供 `class_usage / resource / reflection / SPI` 等候选信号
- 若在 Step4 checkpoint 指定了 `step5_selected_coords` / `step5_selected_names`，筛选会同时作用于这两类输入，而不是只过滤 Step4

#### Step5 的直接证据增强

对于传统方法反向图不擅长的符号，Step5 现在先尝试直接业务证据：

- `class_usage` / `symbol_kind=class`
  - 直接检查业务方法中的声明类型、导入类型与 FQCN body 引用
  - simple name 形式的 `new` / `instanceof` / `Type.class` 仅在当前 import（含 wildcard import）精确解析到目标 FQCN 时才可升级为 `DIRECT_CLASS_USAGE`
  - 若命中，则输出 `DIRECT_CLASS_USAGE`
- `symbol_kind=field`
  - 直接检查 `static import` 与限定名字段访问
  - 若命中，则输出 `DIRECT_STATIC_IMPORT_USAGE` 或 `DIRECT_FIELD_USAGE`
- `change_type=DATA_FIELD_*`
  - 不把 DTO 字段变化伪装成普通字段读写；先按全限定类型名查找方法参数、返回值、局部变量和最终制品 class 引用
  - 再复用标准反向图，证明 DTO/数据对象是否进入业务制品或已激活运行入口
  - current 最终制品字节码是正式证据，源码类型解析是辅助证据；不使用简单类名跨包匹配
  - 结论只表示“数据契约变化进入系统运行路径”，不判断数据库 DDL、迁移脚本或真实表结构是否同步

只有在这些直接证据也未命中时，`class_usage` 才继续回落到 `CLASS_USAGE_ONLY`，`field` 才继续回落到 `CALL_GRAPH_LIMITATION_SYMBOL_KIND`。

当前最小输出字段包括：

- `reaches_system_source`
  - 该依赖是否已有任一目标 API 被证明触达业务源码
- `blocked_at`
  - 若未触达系统源码，当前证据链主要止步层级
- `blocked_reason`
  - 当前代表性阻塞原因，来自代表性 API 的 `reason_code`
- `evidence_level`
  - 当前单依赖结论的最小证据强度摘要

#### Step5 的设计原则

当前 Step5 显式遵循以下原则：

- 精度优先于召回
- 业务直达优先
- 跨依赖回溯必须有证据门槛
- 图不完整时优先保守
- 证据字段属于正式契约
- 调试与正式严格隔离

#### Step5 的内部架构

Step5 按“目标键生成 -> 源码图构建 -> 过滤与门控 -> 反向回溯 -> 候选收敛”的顺序组织。

```text
all_changed_apis.csv
        |
        v
+------------------------------+
| build_api_target_key_groups |
| 目标键生成 / 分层退化        |
+------------------------------+
        |
        v
+------------------------------+        +---------------------------+
| build_enhanced_source_graph  |<-------| source_dirs / dep sources |
| 方法索引 / reverse_edges     |        | source roots              |
| type_metadata                |        +---------------------------+
+------------------------------+
        |
        +----------------------+
        |                      |
        v                      v
+----------------------+  +-------------------------------+
| overload safety      |  | bridge / graph completeness   |
| 精确签名保护          |  | 缺映射 / 图不完整保守处理      |
+----------------------+  +-------------------------------+
        |                      |
        +----------+-----------+
                   |
                   v
+--------------------------------------------+
| trace_api_with_confidence_weighting         |
| 反向 BFS / cost / confidence / polymorphic |
+--------------------------------------------+
                   |
                   v
+--------------------------------------------+
| TraceResult                                |
| analysis_status / reason_code / paths      |
+--------------------------------------------+
```

#### Step5 的关键数据结构

以下数据结构构成 Step5 的正式实现骨架：

##### `MethodDef`

`MethodDef` 是 AST 层向建图层传递的方法级结构化表示。核心字段包括：

- 标识字段：`symbol_id`、`qualified_key`、`simple_key`
- 类型字段：`class_fqcn`、`class_name`、`package_name`、`is_interface`
- 源码定位字段：`file`、`line`、`end_line`
- 归属字段：`owner_type`、`owner_coord`、`module`、`source_root`、`is_test`
- 签名字段：`return_type`、`param_types`、`param_declared_types`
- 推断辅助字段：`imports`、`field_types`、`local_var_types`
- 运行辅助字段：`local_method_return_types`、`known_method_return_types`、`known_method_return_types_by_signature`
- AST 提取字段：`ast_local_var_sites`、`ast_call_sites`

后续建图层只消费 `MethodDef`，不直接操作原始 AST 节点。

##### `CallEdge`

`CallEdge` 是调用边的正式表示。核心字段包括：

- `caller_symbol_id`
- `caller_qualified_key`
- `callee_key`
- `callee_simple_key`
- `confidence`
- `file`
- `line`
- `content`
- `owner_type`
- `owner_coord`
- `module`
- `is_test`
- `callee_param_types`

`CallEdge` 同时保留精确匹配键、回退匹配键、追踪裁剪信息和证据定位信息。

##### `SourceGraph`

`SourceGraph` 是围绕 Step5 回溯需求构建的最小图模型。核心字段包括：

- `methods_by_id`
- `methods_by_qualified`
- `methods_by_simple`
- `reverse_edges`
- `lookup_keys_by_symbol`
- `type_metadata`

其中：

- `reverse_edges` 是正式回溯主索引
- `type_metadata` 是继承、多态和签名兼容分析的正式依赖

##### `TraceResult`

`TraceResult` 是 Step5 的正式输出载体。核心字段包括：

- API 信息：`api_name`、`api_simple`、`api_signature`、`symbol_kind`、`change_type`、`coord`、`source`
- 正式结论：`analysis_status`、`is_reachable`、`reason_code`、`reachable_note`
- 路径证据：`call_paths`、`evidence_paths`、`hops`
- 追踪状态：`direct_callers`、`business_reach_depth`、`dependency_chain_coords`、`confidence_score`
- 人工复核：`verification_commands`

五态、`reason_code` 和路径证据字段共同构成正式结论。

#### AST 构建与类型推测

当前 Java 主路径优先使用 `tree-sitter` 构建 AST，核心入口为 `TreeSitterAnalyzer.analyze()`。

实现分工如下：

- `tree-sitter`
  - 负责主结构定位
- 增强正则
  - 补充包名、imports、字段、嵌套类和类型推断辅助信息

当前类型推测直接决定 `callee_key`、调用签名和调用边质量。系统显式推测以下类型：

- 方法返回类型
- 参数类型
- 局部变量类型
- receiver 类型
- 方法调用表达式返回类型
- lambda 参数类型

当前主要顺序如下：

1. 解析方法声明中的 `return_type`、`param_types` 和 `param_declared_types`
2. 收集字段类型、imports 和包级类型信息
3. 收集局部变量声明，对 `var` / `val` 等推断型声明按初始化表达式反推类型
4. 在调用点推断 `receiver_type`
5. 对实参表达式推断参数类型
6. 根据 `receiver_type + method_name + invocation_signature` 推断调用返回类型

这套机制不是完整编译器语义，也不做全局数据流求解。当前实现采用局部高置信度推断和有限返回类型传播，以获得更高的建图精度。

#### `callee_key` 形成链路

`callee_key` 的形成依赖完整的调用点解释链：

1. 从 AST 或正则提取调用点
2. 提取 `receiver_expr`、`method_name`、`arg_exprs`
3. 推断 `receiver_type`
4. 推断实参类型
5. 参数类型完整时构建 `invocation_signature`
6. 生成 `callee_key`
7. 同时生成 `callee_simple_key`

当前关键规则如下：

- `receiver_type` 可确认时，`callee_key` 使用 `receiver_type.method_name`
- `receiver_type` 无法确认时，退回 `method:{method_name}`
- 参数类型完整时才追加签名
- 参数类型不完整时不强行生成不可靠的带签名键
- 方法引用场景单独处理，不把空参数列表误判为零参数重载

#### 调用边提取

调用边提取入口为 `extract_ast_call_edges()`。当前重点处理：

- 普通方法调用
- 构造器调用
- 方法引用

对每个调用点，系统依次完成：

1. 解析 `receiver_expr`、`method_name`、`arg_exprs`
2. 推断 `receiver_type`
3. 推断参数类型
4. 生成 `callee_key` 和 `callee_simple_key`
5. 在签名足够完整时拼接调用签名

#### 源码图构建

源码图由 `build_enhanced_source_graph()` 统一构建。建图过程分两段：

1. 先建立类型信息
   - 收集 `class_info`
   - 解析 `extends` / `implements`
   - 建立接口实现关系
2. 再写入方法和边索引
   - 归档 `MethodDef`
   - 建立方法级查找表
   - 把调用边写入 `reverse_edges`

#### `jar` 元数据如何辅助源码图构建

Step5 并不使用 `jar` 直接构建调用图，而是使用 `jar_metadata` 补齐依赖源码图缺失的类型信息。

当前链路如下：

1. 根据 `dependency_source_mappings` 建立 `source_roots`
2. 依据 Step1 的 `build_provenance.json` 与依赖 `lib_entry`，从 current 最终制品提取目标 `jar`；无法提取时记录证据缺失，不使用本地 Maven 仓库替代
3. 通过 `javap -s -p` 解析类层和方法层元数据
4. 生成 `jar_metadata`
5. 将 `jar_metadata` 合并进 `class_info`、`type_metadata` 和全局方法返回类型索引

`jar_metadata` 当前主要补齐：

- 依赖类的 `extends / implements`
- 依赖类的方法签名与返回类型
- `coord -> jar -> class` 的归属关系

其直接收益包括：

- 提升 `resolve_type_name()` 的稳定性
- 为多态目标扩展提供更完整的 `type_metadata`
- 为返回类型推断提供依赖方法签名索引

因此，当前系统的调用图仍是源码图，但其类型语义由源码信息和 `jar` 元数据共同支撑。

#### `reverse_edges` 与目标键

当前回溯依赖 `reverse_edges` 执行反向查询。

`reverse_edges` 的 key 设计遵循以下规则：

- 同时索引 `callee_key` 和 `callee_simple_key`
- 若 key 带签名，则补一份无签名基键
- 对方法引用场景，若源码中只有唯一声明签名，则额外补该唯一签名键

目标键生成入口为 `build_api_target_key_groups()`。当前正式顺序如下：

1. `exact_signature`
2. `exact_name`
3. `fallback_simple`
4. `polymorphic`

系统先生成分层键组，再命中 `reverse_edges`。`tier_index`、`provenance` 和 `provenance_family` 都属于正式求值的一部分。

#### overload 安全过滤

系统在命中无签名键后先应用 overload 安全过滤，再决定是否进入正式回溯。

核心规则如下：

- 方法或构造器缺少 `api_signature` 时，直接进入 `not_analyzed`
- 存在精确签名命中时，只保留精确签名组
- 只有兼容签名且兼容结果唯一时，允许退化到 `compatible_signature`
- 只有无签名键或存在兄弟重载但无法唯一确认时，进入 `OVERLOAD_AMBIGUOUS_TARGET`

overload 安全过滤发生在 BFS 之前，而不是回溯之后补救。

#### bridge-check 与图完整性判定

Step5 在正式回溯前执行 `bridge-check`，判断是否必须跨依赖边界继续分析。

判定依据包括：

- 业务源码图是否已经直接命中目标 API
- `dependency_source_mappings` 是否可用
- `business_graph_precheck_incomplete()` 是否认为业务图不完整
- `critical_parser_fallback_reasons()` 是否暴露关键解析降级

当前正式语义如下：

- 业务图已直接命中时，不要求额外 bridge source
- 需要跨依赖继续回溯时，先尝试依赖源码映射；若缺映射，则继续尝试当前 packaged runtime jar 的字节码稳定符号匹配
- 只有依赖源码与无源码字节码两条正式路径都不可用时，才进入待交互或 `not_analyzed`
- 图明显不完整时，不将“未命中”解释为“未影响”

#### 回溯与候选收敛

正式回溯入口为 `trace_api_with_confidence_weighting()`。当前采用“从变更 API 反向寻找调用者”的求值模型，而不是从业务入口正向枚举下游调用。

正式顺序为：

1. 校验最小追踪条件
2. 构建目标键组
3. 选择可命中的目标组
4. 应用 overload 安全过滤
5. 以 BFS 方式扩展回溯前沿
6. 用 `cost`、`confidence` 和关键节点控制搜索边界
7. 基于 `type_metadata` 处理多态扩展
8. 将候选收敛成正式五态结果

当前评分与停止条件固定为：

- `calculate_depth_cost()`
  - `high -> 1`
  - `medium -> 2`
  - `low -> 5`
- `calculate_confidence_decay()`
  - `high -> ×0.95`
  - `medium -> ×0.8`
  - `low -> ×0.5`
- `should_stop_tracing()`
  - `current_cost >= max_cost`
  - `confidence_score < 0.3`
  - 命中 `system_code_touched`
  - 命中 `framework_boundary`

系统不会在命中第一条路径后立即返回，而是先收集候选，再通过 `select_confirmable_reachable_candidate()` 和 `select_best_candidate()` 做收敛与稳定排序。

#### Step5 的正式结果语义

Step5 最终收敛到以下五态：

- `reachable`
- `not_impacted`
- `uncertain`
- `not_analyzed`
- `not_found_in_static_analysis`

结果不仅包含状态，还必须输出：

- `reason_code`
- `call_paths`
- `evidence_paths`

当前高频决策如下：

| 场景 | 当前处理 | 结果语义 |
| --- | --- | --- |
| 缺少 `symbol_kind` | 不进入正式回溯 | `not_analyzed` |
| 方法或构造器缺少 `api_signature` | 不进入正式回溯 | `not_analyzed` |
| 目标键无法生成 | 直接终止 | `not_analyzed` |
| 只有无签名命中且重载无法唯一确认 | overload 安全阻断 | `not_analyzed` |
| 需要跨依赖回溯但缺 `dependency_source_mappings`，但 packaged runtime jar 可扫描 | 走无源码依赖字节码路径 | `uncertain` / `not_found_in_static_analysis` |
| 需要跨依赖回溯且源码映射、无码字节码路径都不可用 | 默认阻塞或待交互 | `not_analyzed` / 阻塞 |
| 图明显不完整 | 不把未命中解释为无影响 | 保守语义 |
| 命中业务代码 | 停止继续扩展 | `reachable` |
| removed API 的旧类与当前其他运行时依赖中的同名类字节码完全一致 | 记录制品保留证据，不再把该 API 当作已消失符号 | `not_impacted` |
| 命中框架边界且无法再静态证明 | 收敛为不确定候选 | `uncertain` |
| 没有任何静态路径 | 不伪装成影响 | `not_found_in_static_analysis` |

### Step6：最终交付

Step6 负责把 Step1 到 Step5 的结构化产物收敛成最终交付结果。

核心产物包括：

- `.runtime/findings/s6_findings.json`
- `deliverables/report.md`

Step6 的职责是读取和重组前序结构化产物，回填 `reason_code` 与 `evidence_paths`，并按用户可理解的视角组织 findings。

#### Step5 到 Step6 的结果消费链

当前 Step6 主要消费以下产物：

- `evidence/call_chain/summary.json`
  - 五态统计、`user_conclusion_summary`、`quality_gate`
- `evidence/call_chain/by_api/*.json`
  - 单条 API 的 `reason_code`、`call_paths`、`evidence_paths`
- `evidence/api_changes/all_changed_apis.csv`
  - Step4 输入变更集，用于反向核对 Step6 汇总项

Step6 不是新的分析层，而是对 Step4 和 Step5 的正式证据做收敛、分组和可读化表达。

## 门控、恢复与重跑

### 门控层

`gate.py` 统一负责完整性判断，主要覆盖：

- `step1_scope`
- `context`
- `scan`
- `jar_compare`
- `call_chain`

门控层的职责是判断是否足够继续，不负责改写主状态。

### 恢复协议

当前恢复协议的正式入口在 `run_step.py`。核心顺序为：

1. 读取 pending interaction
2. 接收 `--response-json` 或 `--response-file`
3. 构建规范化答复
4. 校验 `response_schema`
5. 将 `intent_patch` 合并入主状态
6. 再由调度器决定 `continue`、`rerun_current_step` 或 `restart_from_step`

当前恢复是受结构化协议约束的状态机操作，而不是裸动作跳转。

### checkpoint 恢复、自愈与重跑边界

当前调度层区分三类恢复路径：

- `continue`
  - 在当前 checkpoint 上继续执行
- `rerun_current_step`
  - 保留当前步输入，清理当前步及下游状态与产物后重跑
- `restart_from_step`
  - 回跳到指定上游步骤，并重新建立后续状态

系统同时支持完整性自愈：

- `detect_integrity_repair_step()`
  - 检查目标步骤依赖的关键产物是否缺失
- 若关键产物缺失
  - 自动回退到最早缺口步骤并重建

## 准确性保障模型

当前实现对准确性的要求是：在正式边界内给出可信结论。当前主要控制以下风险：

- 多源状态不一致
- 证据缺失被误解释为无影响
- 签名和调用图的模糊匹配导致串链
- 同输入重复运行时结果漂移
- 调试逻辑渗透进正式语义

当前主要依赖以下机制：

- 单一真相源
  - 正式流程只从 `main_state.json` 读取业务上下文
- 契约优先
  - 步骤顺序、CSV 字段和恢复答复都由显式契约约束
- 保守求值
  - 证据不足时进入保守状态，不用乐观假设填平结论
- 精度优先匹配
  - 先精确键，后退化键，并辅以 overload 安全过滤
- 图质量前置检查
  - 图不完整时不把“没找到”直接写成“没影响”
- 证据可回溯
  - 最终结论必须能回溯到 Step4 与 Step5 证据字段
- 调试隔离
  - `JUA_STEP5_DEBUG`、`--debug-analysis` 等开关只服务观察，不改变正式结论语义

## 验证与正式语义

### 回归验证面

当前回归验证按正式架构拆成三个验证面：

- `core`
  - 验证 Step1 到 Step4 的基础分析链路
- `step5`
  - 验证调用链、bridge source、五态语义和门控行为
- `orchestrator`
  - 验证 `run_step.py` 的主状态机、checkpoint 恢复、结构化答复和状态落盘

### gate 与 smoke 的正式语义

`gate.py` 和 `smoke_regression.py` 共同约束正式行为。

`gate.py` 当前负责：

- 判断每一步必要产物是否齐备
- 阻止“证据缺失但流程继续”这类错误前进
- 在严格模式下，对 `uncertain`、`not_analyzed`、`not_found_in_static_analysis` 保持阻断语义

`smoke_regression.py` 当前负责：

- 固定 `summary.json`、`main_state.json`、`interaction.json` 等核心产物口径
- 固定 Step5 的 `reason_code`、五态语义和旧字段迁移行为
- 固定 orchestrator 的 checkpoint 恢复、自愈和重跑边界

因此，当前正式行为不仅由实现定义，也由 gate 和 smoke 共同约束。

## 已知边界

以下边界属于当前实现明确承认的能力边界，不是偶发错误：

- `api_signature` 的原始文本不保证完全统一
- 签名归一化会带来一定精度损失
- `reachable` 表示已触达业务代码，不保证一定展示到最外层入口
- 动态行为、反射和运行时代理会削弱静态图完整性
- 源码图缺失、桥接信息缺失和参数类型缺失都会限制 Step5 的稳定结论能力

排查 Step5 miss 场景时，按以下顺序检查：

1. `api_name` 与 `symbol_kind` 是否正确
2. `api_signature` 是否只是文本风格差异
3. `reverse_edges` 中是否存在该目标的带签名键或无签名键
4. 是否被 overload 安全过滤拦截
5. 是否属于多态扩展或跨依赖桥接场景

## 维护要求

当以下内容发生变化时，本文档必须同步更新：

- 主状态模型
- 恢复协议
- Step1 到 Step6 的职责边界
- Step4 / Step5 的正式输入输出契约
- Step5 的 AST 构建、建图、`jar_metadata` 补图或回溯口径
- Step6 的交付语义

## 代码评审检查项

每次改动以下区域时，必须逐项检查：

- 是否引入了第二业务参数源
- 是否引入了第二主状态源
- 是否让 `interaction.json` 或报告产物重新参与求值
- 是否让 CLI 重新成为步骤之间透传业务参数的主路径
- 是否破坏了结构化恢复协议
- 是否破坏了 Step5 的五态语义
- 是否破坏了 Step5 的精度优先、overload 保护或 bridge-check 规则
- 是否修改程序行为但未同步更新本文档和相关测试
