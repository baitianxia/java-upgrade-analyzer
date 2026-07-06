---
name: java-upgrade-analyzer
description: "Java 升级兼容性分析。用户提到 JDK、Spring Boot、Spring Framework、Jakarta 或依赖升级评估时立即使用。"
---

# Java 系统升级兼容性分析

使用说明与自我排查清单见：`README.md`（面向使用者）；本文件更多是技能规则与流程约束（面向维护/编排）。

极简版待交互硬规则见：`CHECKPOINT_RULES.md`。若只需要在每个阶段重读最小规则集，优先读取该文件，而不是重复通读整份 `SKILL.md`。

## 你的角色

你是**命令执行器**，不是业务决策者。

允许做的事：

1. 执行 `scripts/run_step.py`、门控脚本和只读检查命令
2. 读取 `.upgrade-report/main_state.json`、`.upgrade-report/interaction.json` 与本阶段产物
3. 向用户原样转述 `interaction.json` 中的 `question`、`options`、`files_to_review`，并优先消费其中的 `missing_inputs`、`fallback_inputs`、`input_modes`、`response_schema`、`input_normalization`、`action_requirements`、`selection_resolution`
4. 把用户的真实答复整理成结构化 `intent_patch`，再通过 `--response-json` 或 `--response-file` 传回下一条恢复命令

首次调用 `step1` 前，必须先读取静态前置协议，而不是先试跑：

```bash
python3 "$SKILL/scripts/run_step.py" --describe-step1-contract
```

这份 JSON 协议用于让 Agent 在首轮就知道：

1. `step1` 有哪些输入模式
2. 默认系统升级场景下应优先抽取哪些字段
3. 哪些字段属于兜底补全
4. 运行时 `interaction.json` 只负责本次动态缺口，不负责定义首轮收参规则

禁止做的事：

1. 预判用户会怎么回答
2. 跳过任何 `[CHECKPOINT]` 或任何 `awaiting_*` 状态
3. 在用户未回复前执行下一步
4. 用“我帮你确认了”代替真实用户输入
5. 把自己的总结、建议或判断伪装成用户答复

## Meta Rules

1. 本 Skill 含多个 `[CHECKPOINT]`；每个 `[CHECKPOINT]` 都是硬中断，不是建议。
2. 只要脚本输出包含 `AWAITING USER INPUT`、`run_step.py` 返回退出码 `4`，或 `.upgrade-report/main_state.json` 中的 `state.status` 进入 `awaiting_*`，就必须立即停止。
3. 停止后只允许读取 `.upgrade-report/interaction.json`，向用户原样转述问题、候选动作、关键产物，并按 `missing_inputs/input_modes/response_schema` 向用户索取缺失输入。
4. 未获得用户答复前，不得执行任何“继续”“恢复”“下一步”命令。
5. 如果发现自己越过了 `[CHECKPOINT]`，必须立即停止，明确承认越界，并回到最近一个待交互点。

## 目标

识别升级引入的兼容性风险，输出可追溯结论。默认**只分析，不直接修复**。

## 触发条件

出现以下任一场景时，必须立即使用本技能：

- JDK 版本升级，如 `8 -> 11`、`8 -> 17`、`11 -> 21`
- Spring Boot 大版本升级，如 `2.x -> 3.x`
- Spring Framework 升级，如 `5 -> 6`
- `javax -> jakarta` 迁移
- Maven / Gradle 依赖批量升级、兼容性评估、冲突排查

## 核心原则

1. **最终产物优先**：Step1 只比较单个目标模块的最终打包依赖；输入既可以是自动切分支后的真实构建结果，也可以是用户直接提供的 base/current 编译产物路径。`boot jar/war` 读最终产物，`thin jar` / 无嵌套依赖场景直接阻塞。若 direct artifact 模式还要继续进入 Step2+，必须显式给出 `base_branch/current_branch`，不能让系统自动猜。
2. **门控强制**：上一步输入不完整或门控失败，不进入下一步。
3. **结论可追溯**：每条结论都要记录证据来源。
4. **不猜测**：无法确认时必须区分四态：`reachable` / `uncertain` / `not_analyzed` / `not_found_in_static_analysis`，不要把”未覆盖”误写成”未影响”。
5. **影响优先**：主报告优先展示已证明触达当前系统的风险。
6. **单依赖包主键**：`coord` 是 per-dependency 分析与汇总的正式主键。
7. **removed 统一语义**：`change_type=removed` 的分析对象不是“空的新 jar”，而是 `old jar symbol_set`。
8. **主状态唯一真相源**：`step5_selected_coords` 等业务选择必须先写入 `main_state.json`，正式流程不得通过单步脚本 CLI 透传业务参数。

## 执行模式

把整个任务当成**状态机**，一次只推进一个 Step：

```text
main_state = read(.upgrade-report/main_state.json if exists)

if main_state.state.status startswith "awaiting_":
    interaction = read(.upgrade-report/interaction.json)
    向用户原样展示:
      - interaction.question
      - interaction.options
      - interaction.files_to_review
      - interaction.missing_inputs / fallback_inputs
      - interaction.input_modes
      - interaction.response_schema / input_normalization
    等待用户答复
    run("python3 .../run_step.py --step auto --response-json '<intent_patch JSON>'")
    停止

step = resolve_next_step(main_state)

if step 输入不足:
    向用户索取缺失输入
    停止

run("python3 .../run_step.py --step <step>")

if main_state.state.status startswith "awaiting_":
    回到上面的 CHECKPOINT 处理分支

if gate failed or step blocked:
    向用户说明阻塞原因
    停止

否则:
    进入下一步
```

硬规则：

1. 遇到 `awaiting_*` 时，唯一合法动作是“读交互文件 -> 问用户 -> 等用户答复 -> 用答复恢复”
2. `run_step.py` 退出码 `4` 表示 `AWAITING_USER`；必须读取 `interaction.json` 后停下问用户，不能把它当成失败重试，也不能当成成功完成
3. 恢复命令只使用 `--response-json` 或 `--response-file`；不得使用裸动作参数绕过结构化用户答复

优先使用统一调度入口 `scripts/run_step.py`。不要要求自己一次记住所有命令；具体命令、参数、产物清单统一按需查看 `RUNBOOK.md`。

## Removed Jar 语义

在依赖升级分析中，`removed jar` 不是旁路场景，而是统一模型中的一种 `change_type`：

- `upgraded`
- `removed`
- `added`

其中 `removed` 的正式语义为：

- `old` 存在，`new` 不存在
- Step4 必须从旧版 jar 导出最小符号集合
- 第一批最小闭环至少支持 `class`、`method`、`constructor`
- Step5/Step6 继续按单个 `coord` 汇总“是否触达系统源码”

## 会话开场协议

命令约定：

1. `$SKILL` 指向本 Skill 的安装目录。
2. 在当前仓库中，通常就是 `.../.trae/skills/java-upgrade-analyzer`。
3. 若执行环境没有预先注入 `$SKILL`，请先手动设置，或直接把命令中的 `$SKILL/scripts/...` 替换为本 Skill 的绝对路径。
4. 正式流程默认通过 `scripts/run_step.py` 调度；单独运行某个脚本仅用于开发调试，不等价于完整主状态流程。
5. 即使是正式流程里的恢复/重建动作，也不能把业务参数通过单步脚本 CLI 重新透传；恢复时仍应以 `main_state.json` 为唯一业务参数源。

安装 `tree-sitter` 相关依赖时，必须使用**当前实际执行 Skill 的那个 Python 解释器**，不要直接使用裸 `pip install`。推荐命令：

```bash
python3 -m pip install tree-sitter tree-sitter-java
```

首次进入任务时，先确认：

1. 当前工作目录是否就是待分析系统的 Maven 工程根目录；通常直接采用，不重复询问路径
2. `Step1` 选择哪一种输入方式：`artifact_inputs` 或 `checkout_build`
3. 若是 `artifact_inputs`：`base_artifact_path/current_artifact_path`
4. 若是 `checkout_build`：`base_branch/current_branch`
5. 本次唯一的 `target_module`；用户未明确时，先展示 reactor 候选并要求确认

如果用户首轮已经明确“只分析某个模块 / 只看某几个模块”，必须把该范围视为 `Step1` 前置输入，而不是等 `Step1` 跑完再纠偏。硬规则：

1. 在第一次执行 `step1` 前，就要通过 `--seed-json` 初始化 `target_module`，或直接通过 `--target-module` 传给 `run_step.py`
2. 禁止先按 root 范围执行 `step1`，再在 `Phase 2 [CHECKPOINT]` 里让用户二次确认模块
3. 若用户尚未明确模块，先展示 Maven reactor 候选并等待用户确认，不得静默选择 root、第一个模块或最大产物

优先一次性向用户收集执行所需信息，避免多轮追问。最小收集集建议包含：

1. 当前工作目录不是系统工程根目录时，才补充正确根目录
2. `Step1` 输入方式：`artifact_inputs` 或 `checkout_build`
3. 若是 `artifact_inputs`：`base_artifact_path/current_artifact_path`
4. 若是 `checkout_build`：`base_branch/current_branch`
5. 若 artifact 中某侧嵌套依赖缺少 `pom.properties`：优先补该侧 `branch`，特殊场景才补 `base_source_project_dir/current_source_project_dir`
6. 若某一侧 Maven 需要特定 JDK：补该侧 `base_jdk_home/current_jdk_home`；未提供时各侧默认回落主机 `JAVA_HOME`
7. 本次唯一的 `target_module`；确认后由 Maven reactor 自动推导系统源码范围
8. 依赖源码目录或仓库根目录（可选但强烈推荐；仅表示依赖源码，字段为 `dependency_source_dirs`）
9. `max_depth`（默认 5，表示最大累计追踪代价；全高置信度边时最多约 5 跳）
10. 是否包含 test 作用域（默认 false）
11. 是否允许降级执行（默认 false；缺少关键源码映射时将阻塞以避免漏分析）

如用户愿意，可直接让用户一次性填写初始化用的 `seed json`；调度器会通过 `--seed-json` 建立 `main_state.json`，后续步骤优先复用主状态，不再重复索取。

推荐模板：

```json
{
  "base_branch": "main",
  "current_branch": "feature/upgrade-test",
  "target_module": "app-module",
  "dependency_source_dirs": ["/abs/path/to/dependency-repo"],
  "max_depth": 5,
  "tool": "maven"
}
```

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --seed-json /abs/path/to/seed.json
```

如果 `.upgrade-report/main_state.json` 已存在，优先读取主状态，再决定从哪个 Step 恢复。

若需要执行单步，优先使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step <step1|step2|step3|step4|step5|step6> \
  --project-dir . \
  --report-dir .upgrade-report
```

说明：本文件中的命令默认使用 `python3`（适配 macOS/Linux）；若当前环境以 `python` 作为解释器入口，可等价替换。

### 最小参数用法（推荐）

Step1 必须显式提供一种输入方式；若两种方式都没给全，`run_step.py` 会先返回前置输入契约交互，而不是直接执行实际分析：

```bash
python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base_branch> \
  --current-branch <current_branch>
```

或直接提供两侧编译产物：

```bash
python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-artifact-path /abs/path/to/base-app.jar \
  --current-artifact-path /abs/path/to/current-app.jar
```

若系统升级分析默认语义是“同一系统、同一仓库、不同分支”，则 direct artifact 模式还推荐同时显式给出 `base_branch/current_branch`；当某一侧嵌套依赖缺少 `pom.properties` 时，Step1 会优先使用这两个分支在同一源码仓库执行 `mvn dependency:list` 补全坐标。

若 direct artifact 模式的两侧产物已经齐全，Step1 可以直接进入执行；`base_branch/current_branch` 属于强烈推荐的补全来源，不是 direct artifact 入口的执行前硬前置。

若用户已明确只分析某个模块，第一次执行 `step1` 时必须直接带模块参数，不得先跑 root 范围：

```bash
python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base_branch> \
  --current-branch <current_branch> \
  --primary-module module-a \
  --modules module-a
```

Step2 应优先消费 Step1 已确认并写入主状态的 `base_branch/current_branch`；对 direct artifact 模式，不得依赖工作区自动探测分支冒充产物来源。

如果希望按主状态续跑，可使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report
```

## 交互模型

本 Skill 必须按两类阶段执行：

- `[AUTO]`：可自动执行脚本、门控与主状态保存
- `[CHECKPOINT]`：必须先向用户汇报结果并等待答复，不能自动推进到下一阶段

强规则：

1. 只要进入 `[CHECKPOINT]`，就必须停下并向用户发问
2. 只要 `main_state.json.state.status` 为 `awaiting_user_input` 或其他 `awaiting_*`，不得继续推进
3. Claude Code 不会因为 Python 子进程输出 JSON 自动弹出对话，因此 Agent 必须主动读取 `.upgrade-report/main_state.json` 和 `.upgrade-report/interaction.json`
4. `main_state.json + interaction.json` 是恢复状态的实现细节；真正决定“这里必须停”的依据，是本文件中的 `[CHECKPOINT]` 约束

进入 `[CHECKPOINT]` 后，只允许做以下动作：

1. 读取 `.upgrade-report/main_state.json`
2. 若 `status` 为 `awaiting_*`，读取 `.upgrade-report/interaction.json`
3. 原样转述 `question`
4. 原样列出 `options`
5. 原样列出 `files_to_review`
6. 优先读取并转述 `missing_inputs`、`fallback_inputs`、`input_modes`
7. 按 `response_schema` / `input_normalization` 把用户原话整理成结构化答复，优先输出 `intent_patch`
8. 等待用户答复
9. 用用户原始答复构造 `--response-json` 或 `--response-file`

进入 `[CHECKPOINT]` 后，明确禁止：

1. 默认替用户选择 `continue`
2. 跳过提问直接执行恢复命令
3. 把自己的判断写成 `notes` 后直接恢复
4. 在用户未答复前进入下一个 `[AUTO]` 阶段
5. 看到退出码为 `0` 就认定整条链路已完成；`run_step.py` 退出码 `4` 代表待用户交互，不得越过

## 执行阶段

### Phase 1 [AUTO] Discovery

- 对应步骤：`step1`
- 目标：获取真实依赖结果，产出 `.upgrade-report/s1_dep_changes.csv`
- 输入：先确认唯一 `target_module`，再从以下方式二选一
  - `artifact_inputs`：`base_artifact_path/current_artifact_path`
  - `checkout_build`：`base_branch/current_branch`
  `primary_module/modules` 仅作为旧状态兼容名；新交互统一使用 `target_module`
- 规则：若两种输入方式都不完整，不进入实际 Step1，而是先进入前置输入契约交互（`reason_code=missing_step1_entry_inputs`）
- 规则：若用户首轮已明确模块范围，第一次执行 `step1` 时必须直接传 `target_module`；不得先跑 root 范围结果再靠待交互确认点纠偏
- 规则：对 direct artifact 模式，若后续要进入 Step2+，必须显式给出 `base_branch/current_branch`；不得依赖系统自动猜测
- 规则：若 Step1 进入 `unresolved_dependency_coordinates_after_enrichment`，Agent 必须先向用户暴露 `unresolved_items`，允许用户补 `manual_coord_overrides`，或明确选择 `confirm_unresolved`；这条补丁路径同时适用于直接产物模式和 checkout_build 模式
- 门控：执行 `step1_scope`

### Phase 2 [CHECKPOINT] Confirm Dependency Scope

- 对应步骤：`step1` 完成后立即进入
- 必须展示：构建来源、变更范围、`s1_dep_changes.csv`
- 必须确认：当前真实构建结果是否可信，是否可以作为后续分析范围
- 若用户指定“只分析某个模块”，或用户首轮其实已明确模块但 Agent 漏传导致仍跑成 root 范围，不得直接进入 `step2`；必须把该答复写成结构化 JSON，并以 `action=rerun_current_step` 连同 `primary_module` / `modules` 一起重跑 `step1`
- 用户答复前，不得进入 `step2`
- 允许动作：`continue`、`rerun_current_step`、`cancel`
- 禁止动作：在未得到用户确认前直接进入 `step2`
- 恢复命令模板：

```bash
# 用户确认当前范围可信
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'

# 用户要求只分析某个模块
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"primary_module":"module-a","modules":["module-a"]}}}'
```

### Phase 3 [AUTO] Context Build

- 对应步骤：`step2`
- 目标：从依赖树推断升级上下文
- 输入：`.upgrade-report/s1_dep_changes.csv`
- 输出：`.upgrade-report/s2_context.json`、`.upgrade-report/s2_dep_graph.json`
- 规则：若上下文缺字段，要求用户补齐 `s2_context.json` 或运行配置
- 门控：执行 `context`

### Phase 4 [CHECKPOINT] Confirm Upgrade Context

- 对应步骤：`step2` 完成后立即进入
- 必须展示：`s2_context.json`、`s2_dep_graph.json` 的关键摘要
- 必须确认：`base_branch`、`current_branch`、JDK / Spring Boot 口径、升级依赖识别结果是否正确
- 用户答复前，不得进入 `step3`
- 允许动作：`continue`、`cancel`
- 禁止动作：在用户未确认前直接进入 `step3`
- 恢复命令模板：

```bash
# 用户确认上下文正确
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'

# 用户补充分支后再恢复
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{"base_branch":"origin/main","current_branch":"feature/upgrade"}}}'
```

### Phase 5 [AUTO] Static Scan

- 对应步骤：`step3`
- 目标：执行 JDK / Spring Boot / 依赖兼容性静态扫描
- 输入：Step 2 上下文 + 依赖变更清单
- 输出：JDK / Spring Boot / 依赖 jar 兼容性扫描结果
- 规则：只运行与当前升级场景相关的扫描
- 规则：JDK/Spring/Jakarta 规则必须来自带版本、来源、校验日期的规则包，并按升级区间过滤；静态命中只能标记为候选证据，不能冒充已发生的编译失败
- 门控：执行 `scan`

### Phase 6 [AUTO] Evidence Build

- 对应步骤：`step4`
- 输入：依赖变更清单、上下文、分支信息、依赖源码目录（推荐字段：`dependency_source_dirs`）
- 输出：`.upgrade-report/s4_jar_compare/` 与 `all_changed_apis.csv`
- 重点：JApiCmp XML 是机器解析主证据，stdout 仅用于人读和 XML 失败回退；分别保留 binary/source compatibility，不能把“二进制兼容但源码重编译不兼容”合并掉
- 规则：正式流程默认不设置超时；仅当用户显式提供 `step4_git_diff_timeout` / `step4_japicmp_timeout` / `step4_fetch_timeout` 时才启用对应超时
- 规则：若提供 `dependency_source_dirs`，系统必须先自动识别模块坐标，再按依赖的 `old_version/new_version` 只在对应源码仓库远端分支 `remotes` 中匹配 ref；只去掉末尾 `-SNAPSHOT` 后，按“严格边界命中”筛选候选，且非 `DEV/dev` 分支优先于 `DEV/dev` 分支；old/new 两侧同时存在多个候选时，优先选择 remote 一致、版本前缀家族一致的 ref pair；若未匹配到或存在歧义，必须进入人工确认，不得直接套用主项目分支名
- 规则：依赖源码映射用于继续解释依赖消费者到业务入口的路径，但不是依赖引用发现的前提；所有变更依赖都必须执行最终制品字节码扫描，源码存在与否只影响后续可达性解释
- 门控：`step4` 完成后执行 `jar_compare`

### Phase 7 [CHECKPOINT] Confirm Evidence Completeness

- 对应步骤：`step4` 完成后进入
- 必须展示：`all_changed_apis.csv`、`git_ref_matches.txt/json`、`summary.txt`
- 必须确认：jar diff、源码 diff、依赖源码映射线索与变更集是否足以支撑下一步调用链分析；若只想分析部分变更 jar，应在这里指定 `all_changed_apis.csv` 中的 `coord` 或名称
- 若证据不足，应先补 `dependency_source_dirs`，而不是直接进入 `step5`
- 允许在 `continue` 时优先附带 `selected_targets`，让系统自动归一化为 `step5_selected_coords` / `step5_selected_names`
- `selection_options` 只反映 Step4 API 目标；每个候选都应带稳定 `selection_key`
- Step4 checkpoint 若只展示部分 `selection_options` 作为人工阅读摘要，这不应收窄正式选择范围；`selected_targets` 的解析仍必须基于完整候选集，允许用户直接提交未展示但合法的 `selection_key` / `coord` / `name`
- `selected_targets` 若填写 `selection_key` 或 `coord`，调度层必须严格按该唯一目标执行；若只填写 `name`，则按 `artifactId` 名称筛选命中的全部候选
- 恢复前必须遵守 `action_requirements`；若当前动作缺少 required / at_least_one_of 字段，必须先追问，不能空恢复
- 允许动作：`continue`、`cancel`
- 禁止动作：证据明显不足时仍直接进入 `step5`
- 恢复命令模板：

```bash
# 用户接受当前证据池，继续调用链分析
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'

# 用户接受当前证据池，但只分析指定依赖
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{"selected_targets":["coord:com.example:demo-lib"]}}}'

# 用户补充依赖源码映射后再恢复
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"dependency_source_dirs":["/abs/path/to/dependency-repo"]},"notes":"补依赖源码目录后复跑 Step5"}}'
```

### Phase 8 [AUTO] Call Chain Analysis

- 对应步骤：`step5`
- 输入：仅使用 `s4_jar_compare/all_changed_apis.csv`（由 Phase 4 产出）作为变更 API 目标集；若在 Phase 7 指定了 `selected_targets` 或正式 `step5_selected_coords` / `step5_selected_names`，则先过滤到命中的依赖子集再执行分析
- 输出：`.upgrade-report/s5_call_chain/`
- 附加证据：Step1 留存的 current 最终制品业务 class、嵌套运行时 JAR 字节码边与 `.upgrade-report/framework_adapters.json`
- 规则：正式流程默认不设置 Step5 外层超时；仅当用户显式提供 `step5_timeout` 时才启用超时
- 规则：若 `all_changed_apis.csv` 为空则跳过并说明原因
- 规则：名称筛选按 `coord` 的 `artifactId` 精确匹配；坐标筛选按 `coord` 精确匹配
- 规则：若用户通过 `selected_targets` 明确提交 `selection_key` 或 `coord`，Step5 只能分析对应唯一依赖；只有当用户只给出 `name` 时，才允许按名称批量筛选
- 规则：筛选匹配范围只允许来自 Step4 API；Step3 平台/框架风险和类级 candidate 不得追加为 Step5 变更 API
- 规则：显式重跑某一步前，调度层必须先清空该步骤全部正式输出，避免旧轮次的制品、目录或字节码证据混入本轮结果
- 规则：若反向调用链需要穿过跨依赖边界，**系统优先从 `dependency_source_dirs` 自动推断模块坐标与依赖源码映射**，无需用户重复配置
- 规则：所有依赖升级、降级、迁移和删除都必须扫描 current 最终制品中的业务 class 与全部运行时依赖 JAR；该扫描不受目标依赖或消费依赖是否存在源码映射影响
- 规则：Step1 必须把自动构建或用户提供的 base/current 最终制品留存到报告目录并记录 SHA-256；Step5 必须优先按 `lib_entry` 提取制品中的真实嵌套 JAR，不得用本地 Maven 仓库副本冒充完整制品证据
- 规则：本地 Maven JAR 只能作为显式 fallback；一旦使用、缺失嵌套 JAR、坐标 unresolved、SHA 不一致或 javap 失败，字节码覆盖必须降级，未命中不得解释为无影响
- `summary.json` 中的 `analysis_status` / `reason_code` 用于解释 reachable / uncertain / not_analyzed 成因；`by_api/*.json` / `by_api/*.txt` 中的 `evidence_paths` 是逐边证据
- 规则：对 `class_usage` / `field` 目标，Step5 必须先尝试业务源码中的直接类型/字段证据；只有直接证据失败后，才允许回落到 `CLASS_USAGE_ONLY` / `CALL_GRAPH_LIMITATION_SYMBOL_KIND`
- 规则：业务 class 字节码命中输出 `BUSINESS_ARTIFACT_BYTECODE_USAGE/reachable`；运行时依赖 JAR 命中保留 `PACKAGED_DEPENDENCY_BYTECODE_USAGE` / `RUNTIME_DEPENDENCY_USES_REMOVED_API` 事实，但若该依赖存在源码映射，Step5 必须先继续尝试回溯到业务代码，只有未能证明业务入口时才收敛为 `uncertain`
- 规则：验收测试必须包含真实 `jdeps` 对照；`jdeps` 能发现的静态跨 JAR 类依赖，本 Skill 不得漏报，并继续提供成员级方法/字段匹配
- 规则：业务源码图与当前业务字节码图使用统一 owner/name/signature 身份；冲突时保留两类 provenance，不得用字节码静默覆盖源码证据
- 规则：`s5_call_chain/alerts.csv` 是完整人工链路台账，不是高风险样例；每个 Step5 API 至少一行、每条唯一终止链路独立一行，禁止只保留第一条路径或静默截断；同一终止链路重复命中时合并为一行并用 `path_occurrence_count` 表示次数
- 规则：`alerts.csv` 必须作为完整主文件保留；当台账较大时，Step5 可额外输出 `alerts_reachable.csv`、`alerts_uncertain.csv`、`alerts_not_found_in_static_analysis.csv`、`alerts_not_analyzed.csv` 及 `alerts_<status>_NNN.csv` 分片作为人工阅读视图。拆分文件不得替代完整主文件，也不得做成轻量索引或样例子集
- 规则：链路台账必须显式给出 target/consumer 坐标、消费类和方法、业务入口、逐链路状态、中断原因、证据文件及稳定 api_id/path_id；API 汇总状态不得覆盖或删除其他候选链路
- 人工排查入口固定为 Step4 `all_changed_apis.csv`、Step5 `alerts.csv`、Step6 `s6_report.md`；其他 JSON/catalog 默认作为机器或深度排障证据
- 规则：业务字节码索引必须覆盖方法/构造/字段、类型指令、常量池/泛型签名/注解类引用与 `invokedynamic`，并按 current 制品 SHA-256 缓存；制品变化必须失效重建
- 规则：运行时依赖字节码必须解析 lambda/方法引用的 bootstrap method handle；Multi-Release JAR 必须按 `jdk_current` 选择生效 class，目标 JDK 未知时未命中不得解释为无影响
- 规则：Step5 必须独立解析与 Step4 目标相关的反射、可静态求值 MethodHandle 和资源间接引用；精确证据合并到统一图，动态或不唯一目标输出 `uncertain`，不得伪装为静态未找到
- 规则：`alerts.csv` 必须输出间接引用的证据类型、位置及能力覆盖状态；完全动态且无法关联到目标范围的线索不得污染所有 API
- 规则：间接调用覆盖必须按 Step4 API 独立求值；目标相关能力为 `partial/insufficient` 时禁止输出 `not_found_in_static_analysis`，严格模式必须将该覆盖缺口作为关键门控
- 规则：编译期常量变化不得因 class 中缺少字段访问而判为未使用，必须输出 `INLINED_CONSTANT_USAGE_UNDETECTABLE/uncertain`
- 规则：SPI、Spring、MyBatis 隐式关系由独立 Adapter 输出；条件未决和多实现必须保留 ambiguity，禁止任意绑定到某个实现
- 规则：Spring `@Bean` 必须绑定方法返回类型与实际构造实现；无法解析工厂返回实现时 Adapter 状态必须为 `partial`，禁止绑定到配置类并报告完整覆盖
- 规则：动态代理只有在注册点能够绑定具体 handler 时才能输出具体回调证据，但仅注册不能把 handler 提升为业务入口；声明式 HTTP Client 属于出站边，也不得作为业务代码入站入口
- 规则：`.upgrade-report/coverage.json` 是从证据派生的覆盖视图，状态仅允许 complete/partial/insufficient/not_applicable；它不是新的事实真相源
- 门控：执行 `call_chain`

**置信度加权深度策略**：
  - `max_depth`参数含义：最大累计追踪代价（不是最大跳数）
  - High confidence 边：每跳消耗 1 单位代价（max_depth=5时可追踪最多 5 跳）
  - Medium confidence 边：每跳消耗 2 单位代价（max_depth=5时可追踪最多 2-3 跳）
  - Low confidence 边：每跳消耗 5 单位代价（立即停止，相当于不追踪）
  
示例：
  - max_depth=5，全High边链路：最多5跳（cost累计5）
  - max_depth=5，全Medium边链路：最多2跳（cost累计4）
  - max_depth=5，混合链路：3High+1Medium=cost=5（达到上限）
- 关键节点识别：业务入口（Controller/Service）标记为 `reachable`，框架边界（@Autowired/动态代理）标记为 `not_analyzed`

**四态分类**：
  - `reachable`（高置信）：确定性链路，已触达系统代码，不要求必须到达最外层 HTTP 入口
  - `uncertain`（待确认）：候选链路，存在歧义需人工审查
  - `not_analyzed`（未分析）：已知分析能力受限（如缺依赖源码映射、行为变更、反射命中），**不能解释为"未影响"**
  - `not_found_in_static_analysis`（静态未找到）：在当前源码图中未找到调用路径，但不代表确定未影响，仍需结合 `not_analyzed` 与能力边界判断

### Phase 9 [CHECKPOINT] Confirm Impact Judgment

- 对应步骤：`step5` 完成后进入
- 必须展示：`reachable` / `uncertain` / `not_analyzed` / `not_found_in_static_analysis` 摘要与关键调用链证据
- 必须确认：当前影响判定是否可接受，是否还要补依赖源码映射后重跑
- 用户答复前，不得进入 `step6`
- 允许动作：`continue`、`rerun_current_step`、`cancel`
- 禁止动作：在未获用户答复前生成最终报告
- 恢复命令模板：

```bash
# 用户接受当前影响结论
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'

# 用户要求先补依赖源码映射，再重跑 Step5
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"dependency_source_dirs":["/abs/path/to/dependency-repo"]},"notes":"补依赖源码目录后复跑 Step5"}}'
```

### Phase 10 [AUTO] Final Report

- 对应步骤：`step6`
- 输入：前面所有产物
- 输出：`.upgrade-report/s6_findings.json`、`.upgrade-report/s6_report.md`
- 规则：主报告优先呈现已证明影响当前系统的项，并保持 Step5 用户侧结论分桶一致；`可能影响`、`需要补充输入` 与剩余 `未覆盖/未分析` 不能混并成同一详情列表

## 恢复与压缩

默认由 `run_step.py` 自动保存主状态。若步骤执行后进入待交互状态，还会额外生成 `.upgrade-report/interaction.json`，并以退出码 `4` 结束当前命令，供 Agent 读取并转成用户对话。若需要手动保存压缩摘要，执行：

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/context_compress.py" save \
  --report-dir .upgrade-report \
  --completed-step <步骤号> \
  --output .upgrade-report/context_summary.json
```

新对话开始时，如存在状态摘要，先恢复：

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/context_compress.py" load \
  --input .upgrade-report/context_summary.json
```

说明：

1. `context_compress.py load` 主要用于“新对话先读状态摘要”的人工恢复场景。
2. 正式续跑仍以 `run_step.py --step auto` 为主；它会根据 `main_state.json` 自动决定从哪一步继续。
3. 如果只是继续执行，不需要先手动运行 `context_compress.py load`。

## 恢复协议

`run_step.py` 在 `[CHECKPOINT]` 阶段不会把“待交互”当成普通成功完成，而是进入明确的待交互退出状态：

1. 更新 `.upgrade-report/main_state.json`
2. 生成 `.upgrade-report/interaction.json`
3. 标记 `status=awaiting_user_input`（或其他 `awaiting_*` 状态）
4. 在 stdout / stderr / `interaction.json` 中输出结构化交互提示
5. **以退出码 `4` 结束当前脚本**

Agent 在恢复或接收新的正式用户意图时必须：

1. 先读取 `main_state.json`
2. 若 `status` 为 `awaiting_*`，再读取 `interaction.json`
3. 若存在 `pending_interaction`，根据 `pending_interaction.question/options`，并优先结合 `pending_interaction.missing_inputs/fallback_inputs/input_modes/response_schema` 向用户发起对话
4. 将用户答复或新的正式业务意图整理为结构化 JSON；当前推荐统一整理为 `intent_patch`
5. 收到结构化输入后，再执行：

```bash
# 推荐：直接传 `intent_patch` 结构化答复
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'
```

```bash
# 推荐：答复较长时，写入文件后恢复
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-file .upgrade-report/user_response.json
```

说明：

- `--response-json` / `--response-file` 是统一的结构化交互入口
- 若当前存在 `pending_interaction`，它表示“恢复当前 checkpoint”
- 若当前不存在 `pending_interaction`，但用户提出了新的正式业务意图，调度器会把 `intent_patch` 桥接为合法的主状态更新与目标步骤重跑
- 必须传结构化用户答复；当前推荐形态例如 `--response-json '{"intent_patch":{"action":"continue","set":{}}}'`
- `cancel` 只表示停止当前续跑，不会清空已有产物
- 若上一条命令退出码为 `4`，优先读取 `interaction.json`，不要把它当成失败重试
- 若当前没有 `pending_interaction`，`intent_patch` 必须在 `set` / `clear` 中提供正式业务字段，或显式使用 `action=restart_from_step`
- 若 `step1` 需要切换到模块级分析，优先使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"primary_module":"module-a","modules":["module-a"]}}}'
```

- 不要只传裸动作；收到用户答复后，必须整理成完整结构化 JSON，再优先包成 `intent_patch` 恢复执行
- `step_manifest.json` 中的 `interaction` 是脚本级配置；本文件中的 `[CHECKPOINT]` 与“非 checkpoint 正式意图桥接”共同构成 Agent 必须遵守的流程约束

合法交互路径：

```text
存在 pending_interaction -> 读取 interaction.json -> 问用户 -> 等用户回复 -> 用用户原话构造 intent_patch 的 response-json/response-file -> 恢复 run_step.py
不存在 pending_interaction，但用户提出新的正式业务意图 -> 将意图整理成 intent_patch -> 用 response-json/response-file 写回主状态 -> 从目标步骤重跑
```

非法路径示例：

```text
看到 awaiting_* -> 自己判断“应该继续” -> 不带结构化答复直接恢复执行
```

上面的非法路径一律禁止。

## 违例自检

任一时刻，如果你发现自己已经：

1. 跳过了某个 `[CHECKPOINT]`
2. 在没有用户答复时执行了恢复命令
3. 用自己的判断替代了用户答复

那么必须立即执行以下补救动作：

1. 停止当前推进
2. 明确告诉用户“刚才越过了必须的人机确认点”
3. 回到最近一个 `awaiting_*` 状态
4. 重新读取 `interaction.json`
5. 按正确流程向用户提问

## 何时停下

出现以下任一情况时，停止推进并向用户说明阻塞点：

- 缺少上一步产物
- 门控失败
- JApiCmp / 本地 Maven 仓库 / 源码路径等关键依赖不可用
- 结果存在明显盲区，无法确认是否触达系统

## 按需查阅

- 详细步骤与命令：`RUNBOOK.md`
- 极简待交互硬规则：`CHECKPOINT_RULES.md`
- JDK 升级专项检查：`references/jdk_checklist.md`
- Spring Boot 升级专项检查：`references/springboot_checklist.md`
- 依赖源码专项子任务：`agents/internal_lib.md`
- 第三方依赖批量子任务：`agents/thirdparty_batch.md`
