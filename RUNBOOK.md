# Java Upgrade Analyzer Runbook

本文件承载**执行细节**。使用者先看 `README.md`（快速开始 + 自查清单），`SKILL.md` 主要保留协议与状态机规则。

## 使用方式

- 先阅读 `README.md`，按“自我排查”把输入/环境补齐
- 优先使用 `scripts/run_step.py` 执行单步，减少手动拼命令
- 只在需要具体命令时查阅本文件
- 每次只执行一个 Step，执行后立刻做门控与主状态保存
- 若 `run_step.py` 返回退出码 `4` 或进入待交互状态，优先读取 `.upgrade-report/.runtime/state/main_state.json` 与 `.upgrade-report/.runtime/state/interaction.json`，再由 Claude Code 向用户发问
- 若要在首次调用 `step1` 前让 Claude Code 先完成首轮抽参，可先执行 `python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --describe-step1-contract` 读取静态前置协议
- 所有 CSV 产物统一采用 UTF-8 BOM，可直接用 Excel 打开；脚本读取时兼容历史无 BOM 的 UTF-8 CSV

### 技能目录约定

- Claude Code 使用 `${CLAUDE_SKILL_DIR}` 指向当前 Skill 的安装目录
- 正式流程默认通过 `run_step.py` 调度；单脚本命令主要用于开发调试或门控排查
- 以下命令默认使用 `python3`（适配 macOS/Linux）；若当前环境以 `python` 作为解释器入口，可等价替换

### 推荐入口

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step <step1|step2|step3|step4|step5|step6> \
  --project-dir . \
  --report-dir .upgrade-report
```

### 项目无关的准确性双线对账

真实项目的分析结果与独立 Oracle 分别产出后，用统一数据入口逐 API 对账。接入新项目无需修改脚本或登记项目名；三个输入集合必须使用相同的 API 身份字段，Oracle 每条记录必须绑定本次最终制品 SHA-256，并提供可校验的独立证据来源。

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/dual_line_accuracy.py" \
  --api-universe /abs/path/to/independent_api_universe.csv \
  --analyzer-summary /abs/path/to/summary.json \
  --oracle-ledger /abs/path/to/independent_oracle.csv \
  --artifact-sha256 <final-artifact-sha256> \
  --ledger-out /abs/path/to/exhaustive_api_oracle.csv \
  --json-out /abs/path/to/dual_line_accuracy.json
```

API universe 必须来自独立 API diff、人工审核契约或其他外部事实源，不能直接复制分析器结果充当分母；空集合按失败处理。退出码 `0` 表示所有 API 身份与结论均验证一致，`1` 表示发现漏报、误报、冲突或未验证项，`2` 表示输入或证据协议无效。对账器不负责生成 Oracle；Oracle 应来自项目测试、运行时观测、JDK `javap`/`jdeps` 或其他不复用分析器实现的方法。

框架代理、反射或回调无法由静态字节码 Oracle 证明为 `reachable` 时，可用 `runtime_coverage_oracle.py` 执行项目自己的测试并读取 JaCoCo 原始覆盖。测试命令通过 JSON 字符串数组传入，不登记项目名；解析器要求测试实际执行且通过、覆盖 class ID 匹配，并要求被解析的 class JAR 是最终制品本身或其中 SHA-256 完全一致的嵌套 JAR。未覆盖只能输出 `uncertain`。

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/runtime_coverage_oracle.py" \
  --api-universe /abs/path/to/independent_api_universe.csv \
  --artifact /abs/path/to/final-application.jar \
  --classfiles /abs/path/to/extracted-provider.jar \
  --jacoco-exec /abs/path/to/jacoco.exec \
  --jacoco-classpath /abs/path/to/org.jacoco.core.jar \
  --jacoco-classpath /abs/path/to/asm.jar \
  --jacoco-classpath /abs/path/to/asm-commons.jar \
  --jacoco-classpath /abs/path/to/asm-tree.jar \
  --command-json /abs/path/to/test-command.json \
  --run-cwd /abs/path/to/project \
  --command-log-out /abs/path/to/runtime-test.log \
  --test-result-glob '/abs/path/to/target/surefire-reports/TEST-*.xml' \
  --evidence-out /abs/path/to/runtime-oracle-evidence.json \
  --oracle-out /abs/path/to/runtime-oracle.csv
```

若项目没有自行配置 JaCoCo，再额外传 `--jacoco-agent /abs/path/to/org.jacoco.agent-runtime.jar`；项目已有 agent 时不要重复注入。

若需要在首次执行前预置首轮输入，使用 `--seed-json` 建立主状态，不要手写 `.upgrade-report/.runtime/state/main_state.json`。

推荐模板：

```json
{
  "base_branch": "main",
  "current_branch": "feature/upgrade-test",
  "source_dirs": ["src/main/java"],
  "dependency_source_dirs": ["/abs/path/to/dependency-repo", "https://git.example.com/team/dependency-repo.git"],
  "max_depth": 5,
  "tool": "maven"
}
```

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --seed-json /abs/path/to/seed.json
```

按主状态自动续跑：

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report
```

- `Step5` 若单独直接执行且未显式传 `--report-dir`，会先尝试从 `--all-changed-apis` 的 `evidence/api_changes/all_changed_apis.csv` 推导报告目录；若仍缺失，再从 `--output-dir` 的父目录推导。

### tree-sitter 安装

- 分析器正式支持 CPython 3.12.x/3.13.x/3.14.x 与 Linux/macOS/Windows。JDK、Maven、Gradle 版本以 base/current 工程为准，不设全局最低版本；优先使用各 revision 的 `mvnw` / `gradlew` 和对应侧 JDK。
- 安装版本以根目录 `requirements-runtime.txt` 为唯一清单；Step5 运行时不会联网安装或修改 Python 环境。
- 在仓库根目录使用任一受支持的 CPython 3.12–3.14 执行显式 bootstrap：

```bash
python3 scripts/bootstrap_runtime.py
```

- 离线环境先准备受控 wheel 目录，再禁止索引访问安装：

```bash
python3 scripts/bootstrap_runtime.py --wheel-dir /abs/path/to/wheels
```

- 安装后运行门禁；它会实际执行外部命令、核对解析器 import/精确版本，并确认 Java 工具与当前项目的 Maven 或 Gradle 使用同一 JDK：

```bash
python3 scripts/quality_gate.py --profile quick --skip-real
```

- 环境不满足契约时，分析在开始前给出明确失败；Step5 缺少解析器时仍进入 checkpoint，且不会用正则静默生成结论。

## main_state.json（推荐）

复杂参数建议通过 `--seed-json` 收敛到 `.upgrade-report/.runtime/state/main_state.json`，避免每步重复拼接命令。
可先参考 `main_state.json` 的字段结构，再把首轮确认后的输入整理为 `seed json` 交给 `run_step.py` 初始化。
建议在任务开始时一次性让用户补齐该文件，后续不再按 Step 反复追问参数。

示例：

```json
{
  "base_branch": "main",
  "current_branch": "feature/upgrade-test",
  "source_dirs": [
    "src/main/java",
    "module-a/src/main/java"
  ],
  "dependency_source_dirs": [
    "D:/repo/dependency-a",
    "D:/repo/dependency-b-multi-module"
  ],
  "max_depth": 5,
  "include_test_scope": false,
  "tool": "maven"
}
```

说明：

- `dependency_source_dirs` 是推荐主入口；可填写源码工程目录、仓库根目录或 HTTPS/SSH Git 地址。Git 地址会先克隆到 `.upgrade-report/.runtime/cache/dependency_source_git/` 并在后续运行中复用。调度层只针对 Step1 已确认的变化 GAV，对构建清单执行一次有界模块定位；源码只补充版本差异证据，不会再次发现依赖或新增同 GAV 条目。
- Git 地址克隆复用宿主环境已有的 SSH key 或 Git credential helper，并设置 `GIT_TERMINAL_PROMPT=0`；克隆失败会保留既有正式产物并要求修正地址或权限，不会降级成一个空源码目录。
- 路径支持相对路径（相对 `project-dir`）和绝对路径。
- `dependency_source_dirs` 一旦提供，Step4 会通过 `git ls-remote` 查询源码仓库的实时远程分支，再按依赖 `old_version/new_version` 做严格边界匹配；old/new 两侧优先选择 remote 和版本前缀家族一致的 ref pair，同名候选只有 commit 相同才会自动合并。选定 ref 后会定向 fetch 并固定 commit，再执行源码 diff；不会以本地远端跟踪分支冒充远端最新状态。
- 唯一匹配会自动继续；确认卡中的方案会把 `old_ref/new_ref` 与 `expected_old_commit/expected_new_commit` 一起写回。执行前再次校验远端 ref：commit 不一致或 ref 消失时标记 `remote_ref_moved`，重新确认后才继续。`refs/heads/*` 在多个 remote 上指向不同 commit 时仍视为歧义，不能按排序取第一个。
- `dependency_source_dirs` 是唯一推荐用户入口；系统会自动推断后续所需映射。
- `main_state.json` 是唯一主状态和业务参数来源；步骤执行时不应再由 CLI 覆盖已确认的业务参数。
- 上述约束同样适用于正式恢复/重建路径；即使是重建 `step2` 上下文，也只能传壳层参数，不能把 `base_branch/current_branch/source_dirs` 之类的业务参数重新塞回单步脚本 CLI。
- 因此，Step2 若提示缺少 `base_branch/current_branch` 或提示两侧分支相同，修复方向应是检查 `main_state.json` 或回到最近 checkpoint 恢复，而不是补 CLI 业务参数。
- 首轮初始化输入应通过 `--seed-json` 写入主状态，后续步骤统一从主状态读取。

### 一次性收集模板（可直接发给用户）

```text
请一次性提供以下信息（可直接粘贴为 JSON）：
{
  "project_dir": "项目根目录",
  "base_branch": "基准分支，如 main",
  "current_branch": "当前分支",
  "source_dirs": ["src/main/java"],
  "dependency_source_dirs": ["依赖源码工程目录、仓库根目录或 Git 地址（可选）"],
  "max_depth": 5,
  "include_test_scope": false,
  "tool": "maven"
}
```

## 执行前预检

开始任何 Step 之前，先确认：

1. 已明确项目根目录、基准分支、当前分支
2. Shell 环境已初始化 `export PYTHONUTF8=1`
3. Claude Code 已提供 `${CLAUDE_SKILL_DIR}` 技能目录变量
4. 上一步产物存在且非空
5. `.upgrade-report/` 目录可写

若预检未通过，不执行脚本，先补齐缺失信息。

## 推荐的主状态结构

若脚本暂未产出结构化状态，至少保证 `.upgrade-report/.runtime/state/main_state.json` 能表达：

```json
{
  "completed_step_id": "step2",
  "current_step": "step3",
  "completed_steps": ["step1", "step2"],
  "blocked": false,
  "blocking_reason": null,
  "next_step_id": "step3",
  "status": "completed",
  "pending_interaction": null
}
```

新对话恢复时：

1. 先读取 `main_state.json`
2. 若 `status` 是 `awaiting_user_input` / `awaiting_input`，或上一条 `run_step.py` 命令退出码为 `4`，再读取 `interaction.json`
2. 再检查 `current_step` 所需输入文件是否存在
3. 文件缺失时，以实际文件状态为准，不盲信主状态中的旧产物摘要

例外：若用户只是要求查询某个方法的调用链，且 `.upgrade-report/.runtime/indexes/s5_query_index.json` 已存在，可以直接执行只读查询脚本返回调用链。这不属于 checkpoint 恢复，也不能顺带继续下一步或改写主状态。

待交互恢复命令示例：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'
```

补充说明：

- `run_step.py` 退出码 `4` 表示当前命令已进入待用户交互状态，不是普通失败
- 退出码 `4` 时不要直接重试上一条命令，应先读取 `interaction.json` 并等待用户答复
- 对当前 checkpoint 的答复直接使用其 `response_schema`；Step4 范围确认使用顶层 `action` / `selected_targets`。只有当前不存在 `pending_interaction`、用户提出新的正式业务意图时才使用 `intent_patch`
- 若当前不存在 `pending_interaction`，但用户提出了新的正式业务意图，也可以继续使用 `intent_patch`
- 这类输入不会伪装成 checkpoint 恢复；调度器会先把它桥接为主状态更新，再从推断出的目标步骤或 `restart_step_id` 重跑
- 非 checkpoint 场景下，`intent_patch` 必须在 `set` / `clear` 中提供至少一个正式业务字段，或显式使用 `action=restart_from_step`

### Step4 后按单依赖包进入 Step5

当 Step4 已生成 `evidence/api_changes/changed_dependencies.md` / `changed_dependencies.csv` 后，可通过依赖包完整坐标只让某个或某几个依赖进入 Step5。

Step4 成功且存在至少两个候选依赖时生成范围选择 checkpoint，由用户决定 Step5 全量或部分分析。0 个候选时没有系统触达目标，1 个候选时全量和选择该候选等价，系统直接继续。用户只需回复“全量分析”或“只分析 <依赖名称/完整坐标>”；调度器在内部转换范围字段，不向用户暴露 `selected_targets` / `selection_key`。范围卡同时展示依赖数、变化 API 数和高风险 API 数。推荐候选由 `recommended=true` 标识，规则为含高风险 API、删除或签名变化，或变化 API 数不少于 20。候选未全部展示时，卡片必须明确指出 `changed_dependencies.md` 是完整依赖选择清单，并指导用户从“依赖包”列取得未展示候选。内部源码/ref/超时故障不得成为该 checkpoint 的用户修复项。

让用户从 `changed_dependencies.md` 的“依赖包”列复制完整坐标，例如：

```text
com.example:legacy-lib
```

恢复输入示例：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"action":"continue","selected_targets":["com.example:legacy-lib"],"notes":"只分析所选依赖"}'
```

说明：

- 用户无需填写或理解 `selected_targets`；只需自然语言回复要分析的依赖名称或完整坐标，调度器负责生成内部字段
- `changed_dependencies.csv` 中的 `selection_key` 仅供程序兼容解析和自动化使用，不作为人工选择入口
- 这些选择字段必须先归一化写入 `main_state.json`
- 正式流程中不要把选中依赖直接透传给 `s5_call_chain*.py`
- Step5 只消费 Step4 API 目标的选中子集；Step3 candidate 保留为独立风险线索，不再生成合并后的 Step5 目标文件
- Step5 的 `summary.json -> graph_stats.indirect_usage` 会输出按 API、symbol kind 和调用机制拆分的覆盖矩阵；目标相关能力为 `partial/insufficient` 时，该 API 不得输出 `not_found_in_static_analysis`，对应总视图会派生到 `.upgrade-report/.runtime/coverage/coverage.json` 的 `indirect_usage_matrix`
- Step5 的 `.upgrade-report/framework_adapters.json` 当前基线包含 `java_spi`、`spring_basic`、`mybatis`、`dynamic_proxy_basic` 和 `declarative_http_client_basic`
- `dynamic_proxy_basic` 只为能够从注册点绑定到具体 handler 的回调输出证据，但仅注册不会把 handler 提升为业务入口；`declarative_http_client_basic` 生成的是业务向远端发起调用的出站证据；两者都不直接进入 `framework_entry_symbols`
- 若当前不在 Step4 范围 checkpoint，用户之后主动改变范围，可通过结构化新意图指定，例如：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{"selected_targets":["com.example:legacy-lib"]}}}'
```

- 调度器会先把 `selected_targets` 归一化为正式 `step5_selected_coords` / `step5_selected_names`，再自动桥接为从 `step5` 重跑，而不是直接卡死在“当前没有 pending interaction”
- 只有已进入 Step4 API 目标集的依赖才能通过 `step5_selected_coords` / `step5_selected_names` 被选中
- `selected_targets` 的正式解析范围始终是完整候选集，可以从 `changed_dependencies.md` 复制完整坐标提交
- 调度器会把本次全量/部分选择写入 `.runtime/cache/step5_selection.json`；Step6 使用该快照声明分析范围，部分分析不得生成全局无影响结论

若用户答复较长，优先使用：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-file .upgrade-report/user_response.json
```

## 输出目录

常用产物如下：

```text
.upgrade-report/
  README.md
  deliverables/
    report.md
  evidence/
    dependencies/
      dep_changes.csv
      dep_alerts.csv
      dep_summary.txt
      deps_current_resolved.csv
      build_provenance.json
      dependency_jars.json
      s1_artifacts/
      s1_dependency_jars/
    context/
      review.md
      context.json
      dep_graph.json
      source_mapping_summary.json
    static_scan/
      s3_jdk_removed_api.csv
      s3_jdk_javax_refs.csv
      s3_jdk_internal_api.csv
      s3_jdk_reflection.csv
      s3_jdk_serialization.txt
      s3_jdk_runtime_flags.csv
      s3_springboot_config.csv
      s3_springboot_autoconfig.txt
      s3_dependency_compat.csv
      s3_dependency_classfile.csv
    api_changes/
      changed_dependencies.md
      changed_dependencies.csv
      all_changed_apis.csv
      all_changed_apis_part_001.csv
      s4_per_dependency/
        <coord>/
          removed_jar_symbols.csv
          resolved_targets.csv
          summary.json
    call_chain/
      alerts.csv
      summary.json
      by_api/
      by_module/
  .runtime/
    observability/progress.jsonl
    state/
      main_state.json
      interaction.json
    coverage/
      coverage.json
      s3_coverage.json
      s4_coverage.json
    indexes/
    findings/
      s6_findings.json
    cache/
```

补充说明：

- 当某个依赖在 Step1 中被识别为 `移除` 时，Step4 会额外尝试从旧版 jar 导出 `public/protected class/method/constructor` 符号集
- 这些符号会写入 `evidence/api_changes/s4_per_dependency/<coord>/removed_jar_symbols.csv`
- Step5 会把单条 API 结果再汇总回 `evidence/api_changes/s4_per_dependency/<coord>/summary.json`
- Step6 会在最终报告中展示“单依赖包最终结论”表，汇总 `change_type`、`reaches_system_source`、`blocked_at`、`blocked_reason`

## Step 1：获取真实依赖结果

### 输入

- 用户提供项目根目录，以及 Step1 的其中一种输入
- 方式 A：基准分支、当前分支
- 方式 B：`base_artifact_path/current_artifact_path`，直接读取两侧编译产物；系统升级分析默认按“同一仓库、不同分支”处理
- 如需模块级分析，首轮就提供 `primary_module/modules`
- 若两种方式都未给全，`run_step.py` 会先进入 Step1 前置输入契约交互，而不是直接执行实际分析

### 建议命令

```bash
# 在项目根目录执行（bash / zsh）
export PYTHONUTF8=1

python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <基准分支> \
  --current-branch <当前分支>
```

如果只分析 `module-a`：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <基准分支> \
  --current-branch <当前分支> \
  --primary-module module-a \
  --modules module-a
```

说明：
- Maven 场景下，Step1 会真实执行目标模块的 `package`
- Gradle 场景下，Step1 优先调用项目 Wrapper，执行目标 project 的 `build -x test`；Groovy DSL、Kotlin DSL、`projectDir` 与 `project(...)` 模块依赖均纳入模块/源码范围推导
- 两种构建工具都可以跳过自动构建，直接读取用户提供的编译产物
- `boot jar/war` 直接读取最终产物
- `thin jar` / 无嵌套依赖场景当前不支持，会直接报错
- 若 Step1 先进入待交互，Claude Code 必须把 `interaction.json` 整理成用户可读的决策卡片：缺什么输入、可用哪种输入方式、可以直接怎么回复；协议字段只用于内部恢复命令构造
- 若某一侧编译包里的嵌套 jar 缺少 `pom.properties`，对同一系统升级场景优先补 `base_branch/current_branch`，让 Step1 在同一源码仓库自动切分支生成 Maven `dependency:list` 或 Gradle `runtimeClasspath` 报告补全坐标；但这不是 direct artifact 模式的执行前硬前置
- `base_source_project_dir/current_source_project_dir` 可以指向同一个仓库，但不能单独定义 base/current 身份；必须同时确认各侧 branch/tag/commit，确认后固定为 commit 再进入独立 detached worktree
- 直接产物模式先解析最终 JAR，仅当某一侧仍有依赖坐标缺失时才解析该侧源码并运行对应构建工具补全；自动构建模式则在构建前解析两侧 ref。解析时先查询实时远程 refs，候选按 commit 去重，唯一 commit 自动采用，多个不同 commit 则在构建前暂停确认；选定后仅定向 fetch 所需 ref，不执行 `git pull`，也不修改用户当前分支。
- 对 Step1 构建来源，远端不存在、认证失败、网络失败、超时或定向 fetch 失败时会暂停。瞬时网络错误在暂停前最多尝试 3 次（间隔 1 秒、3 秒），认证失败、ref 不存在和 ref 移动不重试；裸 SHA 必须先与实时远端记录的 `commit` 匹配并按 expected commit 固定。只有用户明确确认 `base/current_allow_local_source=true` 后才允许相应侧使用本地 commit；本地仓库有未提交修改时还需确认 `base/current_allow_dirty_local_source=true`。Step4 的依赖源码属于辅助证据：远端查询、fetch、ref 移动、未匹配等内部故障在受控重试后记录为 `DEPENDENCY_SOURCE_REF_UNAVAILABLE`，并自动改用最终 JAR 方法字节码指纹识别同签名实现变化；不会要求用户修复，也不会静默使用本地 ref。若字节码兜底也失败，行为覆盖成为关键缺口并限制最终结论。只有两个以上不同 commit pair 会改变源码对比范围时才暂停确认。
- 同时提供 branch/ref 与 source directory 时，以确认后的 branch/ref 为准；只有 source directory 时不得直接使用当前 checkout 执行坐标补全
- 若本次分析还要继续进入 Step2+，直接产物模式下请显式提供 `base_branch/current_branch`；系统不会自动拿工作区探测到的分支冒充这两个产物的来源
- 若这两个分支是在 Step1 review checkpoint 才补充，恢复 `continue` 后调度器会先把确认值写入 `step2.input`，再进入 Step2
- 任一步 checkpoint 恢复时，若主状态里该 step 已有更新后的 `input`，恢复逻辑会优先使用它，而不是继续沿用旧 `output`
- 若用户选择 `restart_from_step` 回跳更早步骤，调度器会优先复用当前 checkpoint 已确认的新上下文，再补目标步骤原有缺失字段
- 若直接产物中的嵌套 jar 缺少 `pom.properties`，可同时提供 `base_branch/current_branch`，让 Step1 额外生成 Maven `dependency:list` 或 Gradle `runtimeClasspath` 报告安全补全坐标
- `base_jdk_home/current_jdk_home` 为可选项；未提供时各侧默认回落主机 `JAVA_HOME`
- 若仍有依赖坐标无法安全补齐，Step1 会进入待交互；可补 `manual_coord_overrides`，或显式选择 `confirm_unresolved`。这条补丁路径同时适用于直接产物模式和自动切分支构建模式
- 选择 `confirm_unresolved` 后，未补齐项会保留在 `evidence/dependencies/dep_changes.csv` 并标记 `resolution_status=unresolved`；后续步骤会跳过这些行

若已提前拿到两侧产物，可直接这样执行：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-artifact-path /abs/path/to/base-app.jar \
  --current-artifact-path /abs/path/to/current-app.jar
```

若 Step1 返回待交互状态，给用户看的第一层只保留决策信息：

- 当前缺哪些输入
- 可以用哪种输入方式补齐
- 哪些信息是可选补充
- 用户可以直接怎么回复

`response_schema`、`input_normalization`、`action_requirements`、`selection_resolution` 仅用于 Claude Code 把用户原话整理成恢复命令，不作为用户主信息展示。

### 门控

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/gate.py" --step step1_scope --report-dir .upgrade-report
```

## Step 2：从依赖树推断上下文

- 依赖是否存在及实际版本以 Step1 留存的最终制品为准；该结果已经包含 Maven BOM / `<exclusions>` 或 Gradle dependency constraints / resolution strategy 的最终效果。
- `s2_dep_graph.json` 不再读取单个依赖的原始 POM 猜测传递父子边。没有构建工具最终解析树证据时，`edges` 保持为空并标记 `relationship_status=not_inferred_without_resolved_tree`，避免把已排除依赖画成幽灵关系。

```bash
export PYTHONUTF8=1

python3 "${CLAUDE_SKILL_DIR}/scripts/s2_context_from_deps.py" \
  --dep-changes .upgrade-report/evidence/dependencies/dep_changes.csv \
  --base <基准分支> \
  --current <当前分支> \
  --work-dir . \
  --output .upgrade-report/evidence/context/context.json \
  --output-dep-graph .upgrade-report/evidence/context/dep_graph.json
```

若脚本提示上下文字段无法推断，要求用户补齐 `evidence/context/context.json`，再进入下一步。

### 门控

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/gate.py" --step context --report-dir .upgrade-report
```

## Step 3：静态扫描

### 规则

- JDK 升级时运行 JDK 相关扫描
- Spring Boot 大版本升级时运行 Spring Boot 相关扫描
- 无论何种升级，默认补跑依赖 jar 兼容性扫描
- 正式流程会向 `stderr` 输出 `[进度][兼容性线索][准备/扫描/完成]` 等用户可读进度；长时间无新输出时每 30 秒发出一次运行心跳，有可靠分母时显示粗略预计剩余时间；原始任务、阶段、数量、已用时间和预计剩余时间同时写入 `.runtime/observability/progress.jsonl`
- 用户按 `Ctrl-C` 时，编排器会终止当前子进程、清理当前步骤的候选输出，保留已完成步骤及当前输入，并以退出码 130 结束；再次运行 `run_step.py --step auto` 即可安全重试当前任务。

### 参考命令

```bash
export PYTHONUTF8=1
$ctx = Get-Content .upgrade-report/evidence/context/context.json | ConvertFrom-Json

if ($ctx.jdk_upgraded) {
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type jdk_removed --source-dir . --output .upgrade-report/s3_jdk_removed_api.csv
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type javax --source-dir . --output .upgrade-report/s3_jdk_javax_refs.csv
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type jdk_internal --source-dir . --output .upgrade-report/s3_jdk_internal_api.csv
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type reflection --source-dir . --output .upgrade-report/s3_jdk_reflection.csv
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type serialization --source-dir . --output .upgrade-report/s3_jdk_serialization.txt
}

if ($ctx.springboot_major_upgrade) {
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type sb_config --source-dir . --output .upgrade-report/s3_springboot_config.csv
  python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type sb_autoconfig --source-dir . --output .upgrade-report/s3_springboot_autoconfig.txt
}

python3 "${CLAUDE_SKILL_DIR}/scripts/s3_scan.py" --type dep_compat \
  --source-dir . \
  --dep-changes .upgrade-report/evidence/dependencies/dep_changes.csv \
  --output .upgrade-report/s3_dependency_compat.csv
```

若需把 `test` 依赖纳入扫描，可为 `dep_compat` 追加 `--include-test-scope`。

### 门控

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/gate.py" --step scan --report-dir .upgrade-report
```

## Step 4：jar 包变更对比

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/s4_jar_compare.py" \
  --dep-changes .upgrade-report/evidence/dependencies/dep_changes.csv \
  --context .upgrade-report/evidence/context/context.json \
  --output-dir .upgrade-report/evidence/api_changes \
  --workers 4 \
  --source-branches <基准分支> <当前分支>
```

若依赖包有本地源码路径，可追加：

```bash
  --dependency-repo-mappings "groupId:artifactId=D:\repo\dependency-a"
```

更推荐写入 `main_state.json` 的 `dependency_source_dirs`，减少命令行复杂度。
提供后，Step4 会从远端实时查询结果中尝试将 `old_version/new_version` 匹配为对应依赖源码分支，例如 `origin/release-1.2.3`、`origin/hotfix-1.2.3`、`origin/support/1.2.3-DEV`；其中会先去掉末尾 `-SNAPSHOT`，按“严格边界命中”筛选候选。比如版本 `3.0.2` 会命中 `origin/auth-sdk3.0.2`，不会命中 `origin/auth-sdk3.0.2.1`。若 old/new 两侧同时存在多个候选，还会优先选择 remote 一致、版本前缀家族一致的 ref pair；同分候选指向同一 commit pair 时固定该 pair，指向两个以上不同 commit pair 且会改变 diff 范围时才进入人工确认。远端查询、fetch、ref 移动或未匹配等内部故障不会中断 JAR 分析；系统会自动执行最终 JAR 方法字节码兜底，只有源码与字节码两条行为证据都失败时才把覆盖率标记为关键缺口。

Step4 需要 JApiCmp 执行 jar 二进制 API 对比。正式流程会先自动尝试安装：

```bash
mvn dependency:get \
  -Dartifact=com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies
```

如果自动安装失败，Step4 会记录 `japicmp_preflight.json` 并以
`blocked_by_system` 停止，不生成用户确认项。环境恢复后可以重跑 Step4；
也可以事先在主状态中提供 `japicmp_jar` 绝对路径。

JApiCmp 是 Java 依赖升级分析的必需工具，不允许降级继续。缺少 JApiCmp 会漏掉删除方法、签名变化、字段变化、源码重编译不兼容等风险。

若处于离线/内网环境，建议额外准备：

- 预先下载好 `japicmp-*-jar-with-dependencies.jar`
- 在 `.upgrade-report/.runtime/state/main_state.json` 中填写 `japicmp_jar`
- 若无法使用 JApiCmp，停止 Step4；不得仅凭源码 diff / 其他证据生成后续升级结论

人工抽查点：

- 变更 API 数量为 0 的依赖
- `最终制品 JAR 证据缺失`
- `JApiCmp 未安装`
- 其他执行失败项
- Step1 按 `base_lib_entry/current_lib_entry` 一次性提取变化依赖 JAR，写入 `evidence/dependencies/s1_dependency_jars/` 和 `dependency_jars.json`，并在 Step1 门控校验条目与 SHA-256。正式 Step4 只直读这份清单，不重新打开 fat JAR、不递归检查内嵌归档，也不读取本地 Maven 仓库或下载同坐标 JAR
- Step4 默认 `step4_workers=4` 进行依赖级并行；如果本机 CPU/磁盘压力过高，可在主状态或命令行设为 1/2
- 正式流程默认不设置 Step4 超时；仅在主状态中显式写入 `step4_git_diff_timeout` / `step4_japicmp_timeout` / `step4_fetch_timeout` / `step4_tool_install_timeout` 时才启用对应限制。`step4_fetch_timeout` 只控制远端 Git 查询/抓取，JApiCmp 自动安装使用独立的 `step4_tool_install_timeout`
- 正式流程会向 `stderr` 输出 `[进度][依赖 API 变化][处理依赖/源码辅助对比/制品 API 对比/完成]` 等用户可读进度，并展示当前对象、数量和耗时

## Step 5：调用链影响分析

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/s5_call_chain.py" \
  --all-changed-apis .upgrade-report/evidence/api_changes/all_changed_apis.csv \
  --jdk-scan-dir .upgrade-report \
  --source-dirs src/main/java \
  --output-dir .upgrade-report/evidence/call_chain \
  --max-depth 5
```

若通过 `run_step.py` 执行，建议将 `source_dirs` / `dependency_source_dirs` / `max_depth` 写入 `main_state.json`，命令保持最小参数集。
- 若只想分析部分变更 jar，通过新的正式意图传入 `selected_targets`；调度器会先把它归一化为正式的 `step5_selected_coords` / `step5_selected_names`，再基于 Step4 API 生成过滤后的输入文件执行 Step5。
- 人工输入的 `selected_targets` 使用依赖包完整坐标，调度器必须严格匹配唯一目标；`selection_key` 仅供结构化自动化输入兼容解析。只有用户仅给出依赖名称时，才允许按 `artifactId` 名称筛选命中的全部候选。
正式流程默认不设置 Step5 外层超时；仅在主状态中显式写入 `step5_timeout` 时才启用限制。

规则：

- `max_depth` 默认值为 `5`，表示最大累计追踪代价，不是固定跳数
- 全高置信度边时通常可追踪约 5 跳；混合高/中置信度边时可达跳数会相应减少
- 只要回溯到系统代码即可记为 `reachable`，不要求必须到达最外层 HTTP 入口
- `summary.json` 中的 `analysis_status` / `reason_code` 用于解释 reachable / not_impacted / uncertain / not_found_in_static_analysis / not_analyzed 的成因；`by_api/*.json` 中的 `evidence_paths` 是逐边证据
- 若 `all_changed_apis.csv` 为空，直接跳过并说明“Step4 未提取到可追踪的变更 API”
- 若指定 `selected_targets`，优先按依赖包完整坐标精确匹配；结构化自动化输入仍可使用 `selection_key`。解析后归一化为程序内部的 `step5_selected_coords` / `step5_selected_names`
- `selected_targets` 基于完整候选集匹配，不依赖终端是否展示该候选
- 显式重跑 Step1 或 Step5 前，调度层会先清空该步骤全部正式输出，避免旧的制品、catalog、framework adapter 或对齐文件污染新一轮结果
- 若直接指定 `step5_selected_coords`，按 `coord` 精确匹配；若指定 `step5_selected_names`，按 `coord` 的 `artifactId` 精确匹配
- 若筛选条件未在 Step4 API 目标中命中，Step5 会直接报错，避免静默分析错范围
- 正式流程会向 `stderr` 输出 `[进度][系统触达证据][发现源码/构建调用图/跨依赖检查/追踪系统触达/生成结果/完成]` 等用户可读进度
- Step5 会生成内部查询索引 `.upgrade-report/.runtime/indexes/s5_query_index.json`。当用户询问某个方法的调用链时，Claude Code 可使用 `scripts/s5_query_call_chain.py` 即时查询；默认只把调用链返回给用户，不额外落查询结果文件。
- 该查询是只读旁路能力：Step5 完成后任意时刻都可使用；它不会改写主流程状态。
- 当 `reason_code` 为 `DIRECT_CLASS_USAGE`、`DIRECT_FIELD_USAGE`、`DIRECT_STATIC_IMPORT_USAGE` 时，表示 Step5 已直接在业务源码中找到类型/字段引用证据，而不是传统方法调用链
- `DIRECT_CLASS_USAGE` 仅接受声明类型、import（含 wildcard import）精确命中或 FQCN 直写等正式类型证据；若 simple name 已被 import 解析到其他 FQCN，不会再升级为直接类型命中
- 当 `reason_code` 为 `PACKAGED_DEPENDENCY_BYTECODE_USAGE` 时，表示 Step5 已在运行时依赖 jar 的字节码里稳定命中目标符号；若该依赖仍有可用源码映射，Step5 会先继续尝试回溯到业务代码，只有源码追踪未能确认业务入口时才保守收敛为 `uncertain`
- 对依赖源码或资源配置中的明确运行时主动入口，Step5 会把 `@Scheduled`、`@PostConstruct`、Spring Runner/Lifecycle、Quartz `Job.execute`、Spring XML `task:scheduled`、`init-method`、`MethodInvokingJobDetailFactoryBean` 等入口视为框架/容器可触发的链路起点；这类链路即使没有业务源码调用方，也可以证明运行时影响。
- Step5 运行时会在进度日志输出 `business_graph_ready`、`source_graph_ready`、`business_bytecode_collected`、`indirect_usage_collected`、`evidence_merged`、`trace_complete` 六个内存观测点。对应的当前/峰值 RSS、方法数和反向边规模保存在 `.upgrade-report/.runtime/observability/step5_timing.csv` 的 `memory` 段，可用于定位内存峰值阶段；这些指标不参与影响结论。
- JPA `@PrePersist`、`@PostPersist`、`@PreUpdate`、`@PostUpdate`、`@PreRemove`、`@PostRemove`、`@PostLoad` 会记录为实体生命周期回调；若静态证据不能证明生命周期实际触发，入口保持 conditional。`@Async` 本身不触发方法，只改变已有调用的执行线程，因此不会单独制造入口。

若 `uncertain` 或 `not_analyzed` 偏多，建议优先按这个顺序排查：

- 查看 `.upgrade-report/evidence/call_chain/summary.json` 中的 `uncertain_apis` 与 `not_analyzed_apis`
- 若出现 `DEPENDENCY_SOURCE_MAPPING_MISSING`，优先补齐 `dependency_source_dirs` 后重跑 Step5
- 若出现 `PACKAGED_DEPENDENCY_BYTECODE_USAGE`，优先打开命中的无源码依赖条目；如需继续证明是否回到系统源码，再补 `dependency_source_dirs`
- 若出现 `GRAPH_TRUNCATED`，提高 `--max-methods / --max-reverse-edges / --max-incoming-per-key`
- 若出现 `INTERFACE_OR_ABSTRACT_API` 或 `RESOURCE_OR_REFLECTION`，不要把结果解释为“未影响”
- 再打开 `.upgrade-report/evidence/call_chain/by_api/*.json`，核对 `reason_code` 与 `evidence_paths`

通过 `run_step.py` 恢复时，推荐直接使用：

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"dependency_source_dirs":["D:/repo/dependency-a"]},"notes":"补依赖源码目录后复跑 Step5"}}'
```

### 门控

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/gate.py" --step call_chain --report-dir .upgrade-report
```

## Step 6：汇总报告

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/s6_report.py" \
  --report-dir .upgrade-report \
  --output-findings .upgrade-report/.runtime/findings/s6_findings.json \
  --output-report .upgrade-report/deliverables/report.md
```

说明：

- `deliverables/report.md` 会保留 Step5 的用户侧结论分桶：`可能影响`、`需要补充输入` 与剩余的 `未覆盖/未分析` 会分别成段展示，不应再混写成单一“未覆盖”列表

## 每步完成后的固定动作

### 保存主状态摘要

若通过 `run_step.py` 执行，本动作会自动完成。手动执行时可使用：

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/context_compress.py" save \
  --report-dir .upgrade-report \
  --completed-step-id <step1|step2|step3|step4|step5|step6> \
  --output .upgrade-report/context_summary.json
```

### 查看错误摘要

```bash
export PYTHONUTF8=1
python3 "${CLAUDE_SKILL_DIR}/scripts/error_handler.py" summary --report-dir .upgrade-report
```

### 首次运行环境诊断

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/error_handler.py" summary --report-dir .upgrade-report
```

## 稳定执行建议

- 优先依赖文件状态，不依赖对话记忆
- 任一步失败后，不要直接尝试下一步
- 每一步结束都简要记录：输入是否齐全、输出是否生成、门控是否通过
- 优先让 `run_step.py` 负责门控与主状态更新，而不是在对话里手动记流程
- `scripts/step_manifest.json` 是机器可读流程定义，新增步骤时先更新它
