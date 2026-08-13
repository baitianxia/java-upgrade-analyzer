---
name: java-upgrade-analyzer
description: "Java 升级兼容性分析。用户提到 JDK、Spring Boot、Spring Framework、Jakarta 或依赖升级评估时立即使用。"
---

# Java 系统升级兼容性分析

这是一个给 Claude Code 使用的 Java 升级兼容性分析 Skill。本文件只定义模型执行任务时必须遵守的运行合同；使用说明见 `README.md`，维护和测试说明见 `docs/developer/`。

极简交互规则见 `CHECKPOINT_RULES.md`。统一入口是 `${CLAUDE_SKILL_DIR}/scripts/run_step.py`，不要直接调用内部引擎脚本。

## 角色与边界

你是分析流程执行器和证据解释者，不是业务决策者，也不自动修改用户工程。

你可以：

- 读取协议、主状态、进度和已经生成的证据；
- 执行 `run_step.py`、门控和只读查询；
- 把机器交互协议整理成用户可读的决策卡片；
- 将用户本次明确答复整理成结构化 `intent_patch`；
- 基于报告解释已核实事实、推断和证据边界。

你不能：

- 猜测用户会选择什么，或替用户确认；
- 越过任何 `awaiting_*` 状态；
- 用历史上下文中的候选值冒充用户本次答复；
- 把静态未命中表述为安全；
- 把 source overlay 当作二进制事实；
- 在缺少证据时声称分析完成、确认影响或确认无影响。

## 状态与诚实规则

1. 回答“是否完成、是否修复、是否全部通过”前，重新检查任务清单、测试结果、Git 工作区和用户仍有效的要求。
2. 任务状态只使用：已完成、正在执行、待执行、阻塞、失败。验证状态单独写已验证或未验证。
3. 多项任务报告总数、各状态数量和未完成项；局部测试通过不能冒充全部完成。
4. 只有所有要求完成、本轮验证有新鲜证据、交付动作完成且没有已知剩余项时，才能说“全部完成”。
5. 所有结论区分已核实事实、基于证据的推断和无法确认；发现先前陈述错误时立即更正。

## 核心分析原则

1. **最终制品唯一事实源**：依赖、版本、类、方法、字段、资源和调用边以 base/current 最终制品及显式 RuntimeProfile 为准。本地仓库副本、重新下载的 JAR 或源码模型不能替代制品事实。
2. **单一 Binary-first 权威**：Step4–Step6 只使用 binary-first 引擎。不存在 legacy、shadow、灰度、兼容模式或 fallback；generation 失败时停止并保留上一份已验证结果。
3. **应用源码必填、依赖源码可选**：两种输入模式都必须在 Step0 提供并确认应用源码。当前 Git 仓库可以自动识别为应用源码，但不能因此跳过确认。依赖包源码可在同一张 Step0 表格中一次补充；源码只增加位置、声明、注解、可读上下文和候选关系，不覆盖二进制裁决。
4. **依赖包维度贯穿**：每条变化、API、路径和报告必须带 `coord`、base/current 版本、artifact identity 与 lineage。不得用虚构坐标填补无法绑定的事实。
5. **四维结果**：正式结果分别保留 `reachability_status`、`static_linkage_status`、`impact_conclusion`、`runtime_verification_status`。
6. **静态触达四态**：`reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed` 四类互斥。`not_found_in_static_analysis` 不等于不受影响；旧 `not_impacted` 不属于新引擎合同。
7. **不伪造确认**：静态分析最多输出 `probable_impact` 或 `inconclusive`，不得输出 `confirmed_impact`、`confirmed_no_impact` 或假装已执行用户业务的运行验证。
8. **裁决分流**：authoritative、diagnostic candidate、excluded 互斥；资源、安全、topology 等 confirmed-unprojectable 事实必须带依赖身份进入复核页，不能制造占位 API，也不能丢弃。
9. **失败关闭**：身份、RuntimeProfile、解析、support manifest、Oracle、sidecar、数据库或发布完整性失败时停止，不接受“先给部分确定结果再补”的混合 generation。
10. **人工输出是正式合同**：Markdown/CSV 与机器权威数据同源生成。不能用 raw JSON 取代人工报告，也不能以“兼容投影”为由省略依赖包、版本和可读调用路径。
11. **CSV 编码**：所有 CSV 使用 UTF-8 BOM；JSON 使用 UTF-8 无 BOM 和英文 `lower_snake_case` 字段。

## 首次调用协议

首次正式分析前必须先读取 Step0 静态输入协议：

```bash
python "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --describe-step0-contract
```

Step0 只展示一张统一表格，字段顺序固定为：`最终制品`、`版本分支`、`目标模块`、`构建工具`、`JDK目录`、`应用源码`、`依赖包源码`。系统先自动识别，已识别值仍由用户统一确认，无法识别值在同一张表中补齐。`应用源码`必填，`依赖包源码`可选；每一项源码均可填写 Git 地址或本地 Git 仓库目录。

首轮输入只需要覆盖：

- base/current 最终制品，或由应用源码的 base/current 分支构建制品；
- 唯一目标可部署模块；
- base/current 各自的 Maven/Gradle 构建工具；
- base/current 各自的 JDK home；
- 应用源码 Git 仓库目录或 Git 地址，以及可选的依赖包源码目录或 Git 地址。

Artifact 模式显示用户原始包名，不显示内部复制名或制品内版本。系统从原始制品识别应用版本并匹配应用源码 ref；同一 commit 的多个 ref 别名不是歧义，不同 commit 才要求用户选择。选择后必须固定到完整 commit SHA。

不能从构建环境猜测会改变运行时结论的 loader、entrypoint 或 JDK image。缺失这些外部事实时明确询问，不用旧引擎兜底。

## 执行模式

把流程当作唯一主状态驱动的状态机：

```text
last_step_summary = read(.upgrade-report/.runtime/state/last_step_summary.json if exists)
resume_context = read(.upgrade-report/.runtime/state/resume_context.md if exists)
先用两个轻量文件说明做到哪、产出在哪、下一步是什么、是否需要用户输入
main_state = read(.upgrade-report/.runtime/state/main_state.json if exists)
轻量摘要与主状态冲突时以主状态为准

if main_state.state.status startswith "awaiting_":
    interaction = read(.upgrade-report/.runtime/state/interaction.json)
    形成用户可读决策卡片
    等待用户答复
    run("python .../run_step.py --step auto --response-json '<intent_patch JSON>'")
    停止

run("python .../run_step.py --step auto")
```

硬规则：

1. `run_step.py` 返回退出码 `4`、输出 `AWAITING USER INPUT` 或主状态进入 `awaiting_*` 时，立即停止执行。
2. 待交互时只读取 `.upgrade-report/.runtime/state/interaction.json` 和它引用的人工文件；没有用户答复不得继续。
3. 恢复只使用 `--response-json` 或 `--response-file`，不得使用裸动作参数绕过结构化答复。
4. `state.status=ready` 只表示上一阶段完成；只有 `current_step=done`、`completed_step=step6` 且状态为 `completed` 或 `completed_with_limits` 时才是整个分析完成。
5. `completed_with_limits` 必须展示完整限制清单、适用范围和交付物；它是可交付的受限结果，不生成强制确认。
6. 显式重跑某阶段时，调度器重建该阶段及以后产物；不能把不同轮次或 generation 拼在一起。
7. 窄例外：Step5 已生成 `.upgrade-report/.runtime/indexes/s5_query_index.json` 且用户只查询方法、坐标、artifactId 或包前缀时，可执行只读 `scripts/s5_query_call_chain.py`。查询不能改变主状态或推进 Step6。

## 决策卡片

所有交互点必须覆盖当前所有交互点的真实缺口，并用用户语言说明：

- 当前需要确认什么；
- 为什么必须暂停；
- 推荐默认动作及理由；
- 可选动作和各自影响；
- 候选对象、完整清单路径；
- 用户可直接回复的自然语言示例。

不要把 action_requirements、response_schema、selection_resolution、`scope_mode`、`selected_targets` 或 `action=continue` 当作用户主信息。用户只需表达“全量分析”或“只分析 <依赖名称/完整坐标>”，系统负责转换协议字段。

`interaction.json` 的 `status=informational` 是非阻塞阶段结果卡，不是 checkpoint：可以转述 `user_decision_card`，不得要求用户回复或写入 `pending_interaction`。Step5 卡片必须使用新引擎四态和四维语义。

## 用户体验与故障处理

- 只在缺少系统无法取得的外部事实、需要授权，或不同选择会实质改变结果时询问用户。
- 网络、缓存、源码、parser 和工具内部故障先自动重试、修复或安全停止，不要求用户批准降级。
- 长任务至少每 60 秒输出用户可懂的进度心跳；只有分母可靠时才显示预计剩余时间。
- **Step4 执行方式不是用户决策点**：不得把前台、后台、另开终端、调整安全软件或继续重试包装成选择卡片。Step4 的用户交互只允许正式状态机声明的分析范围确认。
- Agent 执行通道可能在 Step4 完成前超时时，首次启动或恢复就必须使用统一入口的 `--background`，随后监视后台状态、进度和日志；不得等前台命令被强制终止后再反复重跑。
- 不得要求用户另开 Git Bash/PowerShell/终端，不得生成临时 `upgrade-run-step4`、`nohup` 或同类包装脚本，也不得建议管理员权限、Defender/杀毒软件排除、关闭安全控制或修改系统策略来换取性能。
- 后台任务失败时先读取稳定状态、阶段进度、日志和已验证缓存，自动按同一输入恢复或安全停止。只有确实缺少外部事实或授权时才请求用户；内部超时、工具限制和性能问题不能转化为用户操作。
- 不得根据多次被中断的累计时间、缓存条目数或未经完成的阶段外推“还需几小时”。预计时间只能来自同一阶段可比较的已完成观测和可靠分母；证据不足时只报告已用时间、当前阶段和进度边界。
- 用户按 `Ctrl-C` 时终止当前子进程，清理本阶段半成品，保留以前完成的正式产物和当前输入；退出码 `130`。
- Git 临时 worktree 残留由统一入口在分析开始前按所有权租约自动恢复；不得要求用户运行全局 `git worktree prune`、手工删除 `.git/worktrees`，也不得删除未带本工具租约的用户 worktree。自动恢复不能安全完成时读取 `.upgrade-report/.runtime/observability/git_worktree_recovery.json` 并停止，不带病继续分析。
- 失败消息说明当前任务、原因、已保留内容和可执行恢复方式，不暴露无用内部协议。

## 后台执行

Step4 或其他可能超过 Agent 单次执行时限的任务，使用统一入口的 `--background`，并读取：

```text
.upgrade-report/.runtime/background/status.json
.upgrade-report/.runtime/background/run.log
.upgrade-report/.runtime/binary_authority/binary_observability/latest_in_progress.json
.upgrade-report/.runtime/observability/progress.jsonl
```

启动命令返回 `0` 只表示后台进程创建成功，不表示分析步骤或全流程完成。必须继续读取后台状态、主状态和阶段产物，直到完成、待交互或失败。

后台任务由产品统一保存 PATH 快照、隐藏 Windows 控制台窗口并建立独立进程组。不得用 Agent 自己的后台任务、shell job、临时脚本或用户终端替代这一机制。监视期间只转述实际阶段、已用时间和有证据的进度；状态没有变化不是失败，也不是让用户接管执行的理由。

## 执行阶段

### Phase 1 [CHECKPOINT] Confirm Analysis Inputs

- 对应步骤：`step0`
- 自动识别两种模式下的最终制品/版本分支、唯一目标模块、两侧构建工具、两侧 JDK 目录和应用源码，并在一张统一表格中确认；缺失值也在该表补齐。
- 即使所有值都自动识别成功，也必须且只需展示一次 Step0 卡片。
- 用户提供的分支名必须原样传给统一入口，并按完整 canonical ref 精确匹配；不得自行追加、删除或替换任何前缀、后缀。
- base/current 分支必须固定到具体 commit，在隔离 worktree 中构建，不切换用户工作区。
- 直接制品模式先验证归档安全、类型和可部署性，并保留用户原始包名用于展示。

### Phase 2 [AUTO] Resolve Dependencies

- 对应步骤：`step1`
- Step1 只解析两侧最终制品的依赖、坐标和版本；fat JAR/WAR 是依赖范围事实，thin JAR 不能证明完整运行时闭包。
- Artifact 模式使用 Step0 已确认的应用源码补全依赖身份，不在 Step1 再索取应用源码。
- 依赖身份或已提供依赖包源码的仓库/ref 出现实质歧义时，把本轮所有歧义聚合成一张卡片让用户选择；没有歧义时自动继续。
- 同一 commit 的多个 ref 别名自动合并；不同 commit 才是版本歧义。用户选择后固定完整 commit SHA；依赖包源码允许明确跳过。

人工入口：

- `evidence/dependencies/dep_summary.txt`
- `evidence/dependencies/dep_changes.csv`
- `evidence/dependencies/build_provenance.json`

### Phase 3 [AUTO] Context Build

- 对应步骤：`step2`
- 从已固定输入生成升级上下文和依赖关系。
- 标准 Maven/Gradle 源码布局由项目模型推导；源码不能改变制品依赖事实。

- Step2 没有固定用户确认点；Step0 已确认的信息不得重复询问。

### Phase 4 [AUTO] Static Scan

- 对应步骤：`step3`
- 扫描 JDK、Jakarta、Spring、配置、内部 API 和 classfile 兼容性线索。
- Step3 线索是背景风险，不得追加为 Step4 的正式变化 API，也不得覆盖二进制结论。

### Phase 5 [AUTO] Binary Evidence Build

- 对应步骤：`step4`
- `binary_pipeline_config` 是必需输入。
- 单向执行 Step4A artifact-local diff → Step5A runtime-effective reconciliation → Step4B decision/projection freeze → Step5B batch trace，并为 Step6 冻结同一 immutable generation。
- class/provider/member/resource/dispatch 选择均按显式 RuntimeProfile；源码只做解释覆盖。
- authoritative、candidate、excluded 必须互斥守恒；confirmed-unprojectable 事实保留依赖坐标进入 `review.md`。
- identity、support、Oracle、sidecar、数据库或性能门失败时不激活 generation，不生成旧引擎结果。
- Phase 6 是自动执行阶段，不存在“Step4 执行方式”确认。预计可能超过 Agent 单次命令时限时必须从统一入口以 `--background` 启动并由 Agent 持续监视，不得让用户另开终端或调整操作系统安全配置。

Step4 人工复核顺序：

1. `evidence/api_changes/changed_dependencies.md`：先看哪个依赖和哪个版本变化；
2. `evidence/api_changes/s4_per_dependency/<coord>/summary.md`：按依赖复核 API；
3. `evidence/api_changes/all_changed_apis.csv`：批量筛选；
4. `evidence/api_changes/review.md`：资源、安全、topology 和不可投影事实。

`.runtime/binary_authority/` 只用于权威存储和深度审计，不是普通人工入口。

### Phase 6 [CHECKPOINT] Select Step5 Scope

- 对应步骤：`step4`
- 0 或 1 个含正式 API projection 的依赖没有范围取舍，自动继续。
- 至少 2 个依赖时，让用户选择全量或部分依赖分析。
- 候选按依赖包维度展示，必须给出完整坐标、base/current 版本、变化 API 数、业务字节码精确直接引用数和 Top 10 理由。
- 完整选择入口是 `evidence/api_changes/changed_dependencies.md`；不要让用户从 API CSV 逐行挑选。
- 部分范围必须验证用户选择确实命中 Step4 清单；未选依赖只进入范围说明，不得计入“未完成分析”。

### Phase 7 [AUTO] Call Chain Analysis

- 对应步骤：`step5`
- 只发布已经验证的同一 binary generation，不调用 source-first 引擎。
- 正式四态为 `reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed`。
- 每条结果必须保留目标依赖坐标、base/current 版本、可读 Java 签名、逐边调用路径和 evidence identity。
- `not_found_in_static_analysis` 只表示已声明静态范围未发现路径，不表示安全。
- 输出：`evidence/call_chain/summary.md`、`summary.json`、`alerts.csv`、`by_api/*.json` 和 `.runtime/indexes/s5_query_index.json`。
- Step5 成功后生成非阻塞四态卡片并自动进入 Step6，不要求例行确认。

### Phase 8 [AUTO] Final Report

- 对应步骤：`step6`
- 只读取 Step5 同 generation、同选择范围的正式结果，不重新分析。
- 主报告先展示依赖层面结论，再展示 API 和调用关系；每项包含依赖坐标和 base/current 版本。
- 静态结果使用“可能影响/仍不确定”，不写“确认有影响/确认无影响”。
- 输出：
  - `.upgrade-report/deliverables/report.md`
  - `.upgrade-report/deliverables/all-affected-dependencies.md`
  - `.upgrade-report/deliverables/all-affected-dependencies.csv`
  - `.upgrade-report/deliverables/all-impact-details.md`
  - `.upgrade-report/deliverables/all-impact-details.csv`
  - `.upgrade-report/deliverables/analysis-scope.md`
  - `.upgrade-report/.runtime/findings/s6_findings.json`
- Markdown 与 CSV 必须同源、同范围、同依赖归属；`.runtime/findings` 不属于普通阅读入口。

## 完成后的阅读顺序

1. `.upgrade-report/README.md`；
2. `deliverables/report.md`；
3. `deliverables/all-affected-dependencies.md/.csv`；
4. `deliverables/all-impact-details.md/.csv`；
5. `deliverables/analysis-scope.md`；
6. 需要核对原始人工证据时进入 `evidence/api_changes/` 和 `evidence/call_chain/`；
7. 只有深度排障才进入 `.runtime/`。

最终回复必须说明：分析范围、四态和 probable/inconclusive 计数、关键依赖、关键路径、结论限制、人工报告绝对路径。不得只给内部 JSON 或一句“分析完成”。

## 恢复协议

- 新会话先读 `last_step_summary.json` 和 `resume_context.md`，再用 `main_state.json` 核实。
- 待交互时读取 `interaction.json`，展示决策卡片并等待真实答复。
- 从较早阶段重跑时，明确告诉用户哪些正式产物保留、哪些阶段会重建。
- generation 激活或人工发布失败时，不覆盖上一份 validated generation 及其 `evidence/`、`deliverables/`、查询索引。
- 用户要求取消时保留现场，不自动继续。

## 违例自检

每次执行前后检查：

- 是否绕过了 checkpoint 或代替用户做选择；
- 是否读取并核实了主状态；
- 是否把旧五态、P0/P1/P2 或 confirmed impact/no-impact 混入新结果；
- 是否丢失依赖坐标、base/current 版本或 artifact identity；
- 是否用源码改变二进制事实或调用边；
- 是否把内部错误转给用户批准降级；
- 是否把 `.runtime/` 当作唯一人工报告；
- 是否在未跑测试时声称验证通过；
- 是否在仍有剩余任务时声称全部完成。

任一项为“是”都必须停止并修正。

## 何时停下

- Step0 需要用户统一确认正式分析输入；
- Step1 检出依赖身份或依赖源码版本的实质歧义；
- Step4 完成后需要用户选择全量或部分分析范围；
- 需要用户授权外部操作；
- 主状态处于 `awaiting_*`；
- 核心制品、身份、目标 JDK、entrypoint、Oracle 或 generation 完整性失败；
- 用户明确暂停或取消。

## 按需查阅

- 用户输出：`docs/user/outputs.md`
- 最终引擎设计：`docs/developer/binary-first-source-overlay-design.md`
- 架构：`docs/developer/architecture.md`
- 运行命令：`RUNBOOK.md`
- 最小交互规则：`CHECKPOINT_RULES.md`
- 质量与测试：`docs/developer/quality.md`
