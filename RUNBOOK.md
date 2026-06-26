# Java Upgrade Analyzer Runbook

本文件承载**执行细节**。使用者先看 `README.md`（快速开始 + 自查清单），`SKILL.md` 主要保留协议与状态机规则。

## 使用方式

- 先阅读 `README.md`，按“自我排查”把输入/环境补齐
- 优先使用 `scripts/run_step.py` 执行单步，减少手动拼命令
- 只在需要具体命令时查阅本文件
- 每次只执行一个 Step，执行后立刻做门控与主状态保存
- 若 `run_step.py` 返回退出码 `4` 或进入待交互状态，优先读取 `.upgrade-report/main_state.json` 与 `.upgrade-report/interaction.json`，再由 Agent 向用户发问
- 若要在首次调用 `step1` 前让 Agent 先完成首轮抽参，可先执行 `python3 "$SKILL/scripts/run_step.py" --describe-step1-contract` 读取静态前置协议

### `$SKILL` 约定

- `$SKILL` 指向本 Skill 的安装目录
- 若运行环境没有自动注入 `$SKILL`，请先手动设置，或把命令中的 `$SKILL/scripts/...` 替换为实际绝对路径
- 正式流程默认通过 `run_step.py` 调度；单脚本命令主要用于开发调试或门控排查
- 以下命令默认使用 `python3`（适配 macOS/Linux）；若当前环境以 `python` 作为解释器入口，可等价替换

### 推荐入口

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/run_step.py" --step <step1|step2|step3|step4|step5|step6> \
  --project-dir . \
  --report-dir .upgrade-report
```

若需要在首次执行前预置首轮输入，使用 `--seed-json` 建立主状态，不要手写 `.upgrade-report/main_state.json`。

推荐模板：

```json
{
  "base_branch": "main",
  "current_branch": "feature/upgrade-test",
  "source_dirs": ["src/main/java"],
  "dependency_source_dirs": ["/abs/path/to/dependency-repo"],
  "max_depth": 5,
  "tool": "maven"
}
```

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --seed-json /abs/path/to/seed.json
```

按主状态自动续跑：

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report
```

### tree-sitter 安装

- 不要直接使用裸 `pip install`，否则很容易安装到错误的 Python 环境。
- 始终用**执行本 Skill 的同一个解释器**安装：

```bash
python3 -m pip install tree-sitter tree-sitter-java
```

- 若机器上有多个 Python / venv，先确认当前解释器：

```bash
python3 -c "import sys; print(sys.executable)"
python3 -m pip install tree-sitter tree-sitter-java
```

- 若已知 `run_step.py` 实际由某个绝对路径的解释器执行，直接对该解释器安装最稳：

```bash
"/abs/path/to/python" -m pip install tree-sitter tree-sitter-java
```

## main_state.json（推荐）

复杂参数建议通过 `--seed-json` 收敛到 `.upgrade-report/main_state.json`，避免每步重复拼接命令。
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

- `dependency_source_dirs` 是推荐主入口；只要提供源码工程目录或仓库根目录，调度层就会优先扫描仓库 `pom.xml` / `build.gradle` 并展开所有推断出的 `groupId:artifactId`。
- 路径支持相对路径（相对 `project-dir`）和绝对路径。
- `dependency_source_dirs` 一旦提供，Step4 会优先按依赖 `old_version/new_version` 只在匹配到的源码仓库远端分支 `remotes` 中匹配 git ref；只去掉末尾 `-SNAPSHOT` 后，按“严格边界命中”筛选候选，且非 `DEV/dev` 分支优先于 `DEV/dev` 分支；若 old/new 两侧同时存在多个候选，则优先选择 remote 一致、版本前缀家族一致的 ref pair；若仍未匹配到或存在歧义，则进入人工确认，而不是直接套用主项目分支名。
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
  "dependency_source_dirs": ["依赖源码工程目录或仓库根目录（可选）"],
  "max_depth": 5,
  "include_test_scope": false,
  "tool": "maven"
}
```

## 执行前预检

开始任何 Step 之前，先确认：

1. 已明确项目根目录、基准分支、当前分支
2. Shell 环境已初始化 `export PYTHONUTF8=1`
3. 若依赖 `$SKILL` 路径，已在当前会话正确设置
4. 上一步产物存在且非空
5. `.upgrade-report/` 目录可写

若预检未通过，不执行脚本，先补齐缺失信息。

## 推荐的主状态结构

若脚本暂未产出结构化状态，至少保证 `.upgrade-report/main_state.json` 能表达：

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

待交互恢复命令示例：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{}}}'
```

补充说明：

- `run_step.py` 退出码 `4` 表示当前命令已进入待用户交互状态，不是普通失败
- 退出码 `4` 时不要直接重试上一条命令，应先读取 `interaction.json` 并等待用户答复
- 推荐把用户答复整理成 `intent_patch`，再通过 `--response-json` / `--response-file` 恢复；不要继续沿用旧的顶层业务字段示例

若用户答复较长，优先使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-file .upgrade-report/user_response.json
```

## 输出目录

常用产物如下：

```text
.upgrade-report/
  s1_dep_changes.csv
  s2_context.json
  s2_dep_graph.json
  s3_jdk_removed_api.csv
  s3_jdk_javax_refs.csv
  s3_jdk_internal_api.csv
  s3_jdk_reflection.csv
  s3_jdk_serialization.txt
  s3_springboot_config.csv
  s3_springboot_autoconfig.txt
  s3_dependency_compat.csv
  s4_jar_compare/
    all_changed_apis.csv
  s5_call_chain/
  s6_findings.json
  s6_report.md
  main_state.json
```

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

python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <基准分支> \
  --current-branch <当前分支>
```

如果只分析 `module-a`：

```bash
python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <基准分支> \
  --current-branch <当前分支> \
  --primary-module module-a \
  --modules module-a
```

说明：
- Maven 场景下，Step1 会真实执行 `package`，或直接读取用户提供的编译产物
- `boot jar/war` 直接读取最终产物
- `thin jar` / 无嵌套依赖场景当前不支持，会直接报错
- 若 Step1 先进入待交互，Agent 不应只看 `question/options/files_to_review`，还应优先读取 `missing_inputs`、`fallback_inputs`、`input_modes`、`response_schema`、`input_normalization`
- 若某一侧编译包里的嵌套 jar 缺少 `pom.properties`，对同一系统升级场景优先补 `base_branch/current_branch`，让 Step1 在同一源码仓库自动切分支执行 `mvn dependency:list` 补全坐标；但这不是 direct artifact 模式的执行前硬前置
- `base_source_project_dir/current_source_project_dir` 仅保留给特殊兼容场景，不作为默认交互模型
- 若本次分析还要继续进入 Step2+，直接产物模式下请显式提供 `base_branch/current_branch`；系统不会自动拿工作区探测到的分支冒充这两个产物的来源
- 若这两个分支是在 Step1 review checkpoint 才补充，恢复 `continue` 后调度器会先把确认值写入 `step2.input`，再进入 Step2
- 任一步 checkpoint 恢复时，若主状态里该 step 已有更新后的 `input`，恢复逻辑会优先使用它，而不是继续沿用旧 `output`
- 若用户选择 `restart_from_step` 回跳更早步骤，调度器会优先复用当前 checkpoint 已确认的新上下文，再补目标步骤原有缺失字段
- 若直接产物中的嵌套 jar 缺少 `pom.properties`，可同时提供 `base_branch/current_branch`，让 Step1 额外执行 `mvn dependency:list` 安全补全坐标
- `base_jdk_home/current_jdk_home` 为可选项；未提供时各侧默认回落主机 `JAVA_HOME`
- 若仍有依赖坐标无法安全补齐，Step1 会进入待交互；可补 `manual_coord_overrides`，或显式选择 `confirm_unresolved`。这条补丁路径同时适用于直接产物模式和自动切分支构建模式
- 选择 `confirm_unresolved` 后，未补齐项会保留在 `s1_dep_changes.csv` 并标记 `resolution_status=unresolved`；后续步骤会跳过这些行

若已提前拿到两侧产物，可直接这样执行：

```bash
python3 "$SKILL/scripts/run_step.py" --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-artifact-path /abs/path/to/base-app.jar \
  --current-artifact-path /abs/path/to/current-app.jar
```

若 Step1 返回待交互状态，推荐 Agent 至少检查：

- `interaction.question`
- `interaction.missing_inputs`
- `interaction.fallback_inputs`
- `interaction.input_modes`
- `interaction.response_schema`
- `interaction.input_normalization`

### 门控

```bash
python3 "$SKILL/scripts/gate.py" --step step1_scope --report-dir .upgrade-report
```

## Step 2：从依赖树推断上下文

```bash
export PYTHONUTF8=1

python3 "$SKILL/scripts/s2_context_from_deps.py" \
  --dep-changes .upgrade-report/s1_dep_changes.csv \
  --base <基准分支> \
  --current <当前分支> \
  --work-dir . \
  --output .upgrade-report/s2_context.json \
  --output-dep-graph .upgrade-report/s2_dep_graph.json
```

若脚本提示上下文字段无法推断，要求用户补齐 `s2_context.json`，再进入下一步。

### 门控

```bash
python3 "$SKILL/scripts/gate.py" --step context --report-dir .upgrade-report
```

## Step 3：静态扫描

### 规则

- JDK 升级时运行 JDK 相关扫描
- Spring Boot 大版本升级时运行 Spring Boot 相关扫描
- 无论何种升级，默认补跑依赖 jar 兼容性扫描
- 正式流程会向 `stderr` 输出 `[progress][step3][plan|scan|done]` 日志，便于外部观察长耗时扫描的阶段推进

### 参考命令

```bash
export PYTHONUTF8=1
$ctx = Get-Content .upgrade-report/s2_context.json | ConvertFrom-Json

if ($ctx.jdk_upgraded) {
  python3 "$SKILL/scripts/s3_scan.py" --type jdk_removed --source-dir . --output .upgrade-report/s3_jdk_removed_api.csv
  python3 "$SKILL/scripts/s3_scan.py" --type javax --source-dir . --output .upgrade-report/s3_jdk_javax_refs.csv
  python3 "$SKILL/scripts/s3_scan.py" --type jdk_internal --source-dir . --output .upgrade-report/s3_jdk_internal_api.csv
  python3 "$SKILL/scripts/s3_scan.py" --type reflection --source-dir . --output .upgrade-report/s3_jdk_reflection.csv
  python3 "$SKILL/scripts/s3_scan.py" --type serialization --source-dir . --output .upgrade-report/s3_jdk_serialization.txt
}

if ($ctx.springboot_major_upgrade) {
  python3 "$SKILL/scripts/s3_scan.py" --type sb_config --source-dir . --output .upgrade-report/s3_springboot_config.csv
  python3 "$SKILL/scripts/s3_scan.py" --type sb_autoconfig --source-dir . --output .upgrade-report/s3_springboot_autoconfig.txt
}

python3 "$SKILL/scripts/s3_scan.py" --type dep_compat \
  --source-dir . \
  --dep-changes .upgrade-report/s1_dep_changes.csv \
  --output .upgrade-report/s3_dependency_compat.csv
```

若需把 `test` 依赖纳入扫描，可为 `dep_compat` 追加 `--include-test-scope`。

### 门控

```bash
python3 "$SKILL/scripts/gate.py" --step scan --report-dir .upgrade-report
```

## Step 4：jar 包变更对比

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/s4_jar_compare.py" \
  --dep-changes .upgrade-report/s1_dep_changes.csv \
  --context .upgrade-report/s2_context.json \
  --output-dir .upgrade-report/s4_jar_compare \
  --source-branches <基准分支> <当前分支>
```

若依赖包有本地源码路径，可追加：

```bash
  --dependency-repo-mappings "groupId:artifactId=D:\repo\dependency-a"
```

更推荐写入 `main_state.json` 的 `dependency_source_dirs`，减少命令行复杂度。
提供后，Step4 会默认尝试将 `old_version/new_version` 匹配为对应依赖源码仓库中的远端分支，例如 `origin/release-1.2.3`、`origin/hotfix-1.2.3`、`origin/support/1.2.3-DEV`；其中会先去掉末尾 `-SNAPSHOT`，按“严格边界命中”筛选候选。比如版本 `3.0.2` 会命中 `origin/auth-sdk3.0.2`，不会命中 `origin/auth-sdk3.0.2.1`。若 old/new 两侧同时存在多个候选，还会优先选择 remote 一致、版本前缀家族一致的 ref pair；若仍未匹配到或存在歧义，则进入人工确认。

若本地未准备 JApiCmp，可先执行：

```bash
mvn dependency:get \
  -Dartifact=com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies
```

若处于离线/内网环境，建议额外准备：

- 预先下载好 `japicmp-*-jar-with-dependencies.jar`
- 在 `.upgrade-report/main_state.json` 中填写 `japicmp_jar`
- 若无法使用 JApiCmp，需在结论里明确标注“Binary Incompatible 检测已降级，当前主要基于源码 diff / 现有证据”

人工抽查点：

- 变更 API 数量为 0 的依赖
- `jar 未找到`
- `JApiCmp 未安装`
- 其他执行失败项
- 正式流程默认不设置 Step4 超时；仅在主状态中显式写入 `step4_git_diff_timeout` / `step4_japicmp_timeout` / `step4_fetch_timeout` 时才启用对应限制
- 正式流程会向 `stderr` 输出 `[progress][step4][dependency|gitdiff|japicmp|done]` 日志，展示当前处理到哪个依赖、子阶段和耗时

## Step 5：调用链影响分析

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/s5_call_chain.py" \
  --all-changed-apis .upgrade-report/s4_jar_compare/all_changed_apis.csv \
  --jdk-scan-dir .upgrade-report \
  --source-dirs src/main/java \
  --output-dir .upgrade-report/s5_call_chain \
  --max-depth 5
```

若通过 `run_step.py` 执行，建议将 `source_dirs` / `dependency_source_dirs` / `max_depth` 写入 `main_state.json`，命令保持最小参数集。
若 Step4 checkpoint 只想分析部分变更 jar，可在恢复时把 `step5_selected_coords` / `step5_selected_names` 写入 `main_state.json`；调度器会先基于 `all_changed_apis.csv` 生成过滤后的输入文件，再执行 Step5。
正式流程默认不设置 Step5 外层超时；仅在主状态中显式写入 `step5_timeout` 时才启用限制。

规则：

- `max_depth` 默认值为 `5`，表示最大累计追踪代价，不是固定跳数
- 全高置信度边时通常可追踪约 5 跳；混合高/中置信度边时可达跳数会相应减少
- 只要回溯到系统代码即可记为 `reachable`，不要求必须到达最外层 HTTP 入口
- `summary.json` 中的 `analysis_status` / `reason_code` 用于解释 reachable / uncertain / not_analyzed 的成因；`by_api/*.json` 中的 `evidence_paths` 是逐边证据
- 若 `all_changed_apis.csv` 为空，直接跳过并说明“Step4 未提取到可追踪的变更 API”
- 若指定 `step5_selected_coords`，按 `coord` 精确匹配；若指定 `step5_selected_names`，按 `coord` 的 `artifactId` 精确匹配
- 若筛选条件未在 `all_changed_apis.csv` 中命中任何依赖，Step5 会直接报错，避免静默分析错范围
- 正式流程会向 `stderr` 输出 `[progress][step5][discovery|graph|bridge-check|trace|report|done]` 日志，展示源码映射发现、图构建、调用链追踪与报告生成的推进情况

若 `uncertain` 或 `not_analyzed` 偏多，建议优先按这个顺序排查：

- 查看 `.upgrade-report/s5_call_chain/summary.json` 中的 `uncertain_apis` 与 `not_analyzed_apis`
- 若出现 `DEPENDENCY_SOURCE_MAPPING_MISSING`，优先补齐 `dependency_source_dirs` 后重跑 Step5
- 若出现 `GRAPH_TRUNCATED`，提高 `--max-methods / --max-reverse-edges / --max-incoming-per-key`
- 若出现 `INTERFACE_OR_ABSTRACT_API` 或 `RESOURCE_OR_REFLECTION`，不要把结果解释为“未影响”
- 再打开 `.upgrade-report/s5_call_chain/by_api/*.json`，核对 `reason_code` 与 `evidence_paths`

通过 `run_step.py` 恢复时，推荐直接使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"dependency_source_dirs":["D:/repo/dependency-a"]},"notes":"补依赖源码目录后复跑 Step5"}}'
```

### 门控

```bash
python3 "$SKILL/scripts/gate.py" --step call_chain --report-dir .upgrade-report
```

## Step 6：汇总报告

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/s6_report.py" \
  --report-dir .upgrade-report \
  --output-findings .upgrade-report/s6_findings.json \
  --output-report .upgrade-report/s6_report.md
```

说明：

- `s6_report.md` 会保留 Step5 的用户侧结论分桶：`可能影响`、`需要补充输入` 与剩余的 `未覆盖/未分析` 会分别成段展示，不应再混写成单一“未覆盖”列表

## 每步完成后的固定动作

### 保存主状态摘要

若通过 `run_step.py` 执行，本动作会自动完成。手动执行时可使用：

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/context_compress.py" save \
  --report-dir .upgrade-report \
  --completed-step-id <step1|step2|step3|step4|step5|step6> \
  --output .upgrade-report/context_summary.json
```

### 查看错误摘要

```bash
export PYTHONUTF8=1
python3 "$SKILL/scripts/error_handler.py" summary --report-dir .upgrade-report
```

### 首次运行环境诊断

```bash
python3 "$SKILL/scripts/error_handler.py" summary --report-dir .upgrade-report
```

## 稳定执行建议

- 优先依赖文件状态，不依赖对话记忆
- 任一步失败后，不要直接尝试下一步
- 每一步结束都简要记录：输入是否齐全、输出是否生成、门控是否通过
- 优先让 `run_step.py` 负责门控与主状态更新，而不是在对话里手动记流程
- `scripts/step_manifest.json` 是机器可读流程定义，新增步骤时先更新它

## 开发者测试

- 最小回归：`python3 "$SKILL/scripts/smoke_regression.py"`
- 按主题回归：`python3 "$SKILL/scripts/smoke_regression.py" --group core|step5|orchestrator`
- 标准测试入口：`python3 -m unittest discover -s "$SKILL/tests" -v`
- 若需要保留临时目录便于排查：`python3 "$SKILL/scripts/smoke_regression.py" --keep-tmp`
- CI 工作流：`.github/workflows/smoke-regression.yml`
