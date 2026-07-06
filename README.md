## java-upgrade-analyzer

面向 Java 系统升级（JDK / Spring Boot / Spring Framework / Jakarta / 依赖批量升级）的兼容性分析工具链。目标是把“可能有问题”变成“可追溯的证据链”，并把结果沉淀到 `.upgrade-report/` 供团队协作排查。

若要和维护者对齐“当前代码实际上怎么工作”，优先看 `IMPLEMENTATION_OVERVIEW.md`；`SKILL.md` / `RUNBOOK.md` 主要分别承载运行规则和执行方法。

## 使用方式（Claude Code）

本 Skill 用于 Claude Code。典型使用流程如下：

先看这个高频约束：
- Step1 现在以目标模块的**真实构建结果**为准，不再以手工准备的 `dependency:tree` 文件作为正式输入
- Maven 场景下，Step1 正式入口支持两种方式：直接提供 `base_artifact_path/current_artifact_path`，或提供 `base_branch/current_branch` 自动构建
- 系统升级分析的默认语义是“同一系统、同一仓库、不同分支”；因此直接产物模式下，主输入应优先是 `base_branch/current_branch`，而不是两套源码路径
- `boot jar/war` 直接读取最终产物；`thin jar` / 无嵌套依赖场景当前不支持
- Agent 在首次调用 `step1` 前，可先执行 `python3 scripts/run_step.py --describe-step1-contract` 读取静态前置协议，再从提示词里抽取首轮参数
- 若 Step1 的两种入口都未给全，`run_step.py` 会先输出前置输入契约交互；Agent 应优先读取 `interaction.json` 中的 `missing_inputs`、`input_modes`、`response_schema`

### 🚀 快速开始

以下命令默认使用 `python3`（适配 macOS/Linux）；若在 Windows 环境中使用 `python` 作为当前解释器入口，可等价替换。

1. **直接运行分析**（推荐）
```bash
python3 scripts/run_step.py --step auto --project-dir . --report-dir .upgrade-report
```

如果想在第一次执行前一次性把首轮输入初始化到主状态，推荐先准备 `seed.json`，再通过 `--seed-json` 建立：

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
python3 scripts/run_step.py --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --seed-json /abs/path/to/seed.json
```

一次分析只对应一个目标部署模块。用户已明确时直接传入；未明确时，Step1 会展示 Maven reactor 候选并等待用户确认：

```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base-branch> \
  --current-branch <current-branch> \
  --target-module module-a
```

2. **分步运行**（调试场景）
```bash
python3 scripts/run_step.py --step step1 --project-dir . --report-dir .upgrade-report --base-branch <base-branch> --current-branch <current-branch>
python3 scripts/run_step.py --step step5 --project-dir . --report-dir .upgrade-report
```
说明：`Step5` 直接执行时，如果未显式传 `--report-dir`，现在会优先从 `--all-changed-apis` 的 `s4_jar_compare/all_changed_apis.csv` 路径推导报告目录；若未提供该参数，则再尝试从 `--output-dir` 的父目录推导。
如需定位 Step5 的完整分析过程，可仅在调试场景开启：
```bash
JUA_STEP5_DEBUG=1 python3 scripts/s5_call_chain_engine_integrated.py --report-dir .upgrade-report
JUA_STEP5_DEBUG=1 JUA_STEP5_DEBUG_BREAK=1 python3 scripts/s5_call_chain_engine_integrated.py --report-dir .upgrade-report --debug-analysis --debug-break
```
说明：`JUA_STEP5_DEBUG` / `--debug-analysis` 会输出覆盖输入解析、依赖源码发现、构图、调用点签名恢复、reverse_edges 入图、target 命中、回溯扩展、停止条件和最终归因的结构化调试日志；`JUA_STEP5_DEBUG_BREAK` / `--debug-break` 只用于本地断点定位，不属于正式流程参数。

### 运行进度日志

- `Step3`、`Step4`、`Step5` 在正式流程中会持续向 `stderr` 输出结构化进度日志，格式为 `[progress][stepX][phase]`
- 这些日志只用于展示当前阶段、处理进度与耗时，不写入 `main_state.json`，也不参与恢复协议或门控求值
- 长耗时阶段会额外输出阶段开始、阶段完成与累计耗时；批量循环会输出 `current/total` 形式的推进信息
- 若外部调用方只展示标准输出，请同步透传 `stderr`，否则会再次出现“外部看不到内部状态”的问题

### Step5 解析器策略

- Java 源码默认优先使用 `tree-sitter` 作为主解析链路
- Java Step5 现已优先使用 AST 提取方法定义、构造器、调用边、方法引用与局部类型信息，不再只依赖正则扫描方法体
- Step5 图构建会先建立全局方法返回值索引，再回填调用边，因而像 `var client = helper.makeClient(); client.call()` 这类跨文件链式调用也能更稳定命中
- Java lambda 参数类型传播、`new Foo()` 构造器调用以及构造器内部调用都已纳入 AST 主链路
- 当调用点签名不完整时，Step5 不再只依赖“所有参数都成功推断”这一条路径；若已知参数位足以在声明签名集合中唯一确定一个 overload，系统会恢复该唯一签名并写入带签名调用边，减少无签名回退造成的 `OVERLOAD_AMBIGUOUS_*`
- Step5 的纯性能优化只允许减少重复扫描、降低内存峰值与释放无用中间对象；不得改变四态语义、目标键规则、bridge-check 阻塞语义或正式输入输出契约
- 当前大输入场景下，Step5 会复用业务源码预分析结果、复用 overload 签名索引，并在进入完整图构建前释放预判阶段不再需要的大对象，以降低 CPU 与内存峰值
- Step5 对最终制品运行时依赖 JAR 做字节码扫描时，会先用常量池快路径过滤/命中不需要回溯业务链路的直接引用；需要 `consumer_method` 回溯业务链路的候选 class 仍使用 `javap` 精确解析，并默认以 4 个 worker 并行执行。可通过 `JUA_STEP5_BYTECODE_JAVAP_WORKERS=1` 关闭并行，或设置为 `1..16` 调整并行度。
- 若本机缺少依赖，不要直接用裸 `pip install`；请始终用**执行本 Skill 的同一个 Python**安装：

```bash
python3 -m pip install tree-sitter tree-sitter-java
```

- 若同一台机器存在多个 Python / venv，请先确认当前解释器路径，再用该解释器安装：

```bash
python3 -c "import sys; print(sys.executable)"
python3 -m pip install tree-sitter tree-sitter-java
```

- 最稳妥的方式是直接使用实际解释器绝对路径：

```bash
"/abs/path/to/python" -m pip install tree-sitter tree-sitter-java
```

- 若 `tree-sitter` 缺失、初始化失败或单文件运行异常，系统会自动降级到增强正则，不会整次分析直接中断
- Step5 的 `summary.json -> meta.graph_stats` 会记录 `parser_usage` 与 `parser_fallback_reasons`，用于判断本次有多少文件真正走了 AST 主链路
- Kotlin 仍走增强正则降级路径，当前没有独立的 tree-sitter-kotlin 主链路

### 传统方式

- 将本 Skill 目录放入 Claude Code 可发现的技能目录（项目级优先）：`.claude/skills/java-upgrade-analyzer/`。
- 在 Claude Code 中进入你的项目根目录后，通过 `/java-upgrade-analyzer` 触发，或直接描述你的升级场景（例如 “JDK 8 升到 17，评估兼容性风险”）。
- Agent 会自动推进分析步骤，并在关键节点给出”待用户交互清单”。
- 注意：`run_step.py` 进入待用户交互时会写入 `.upgrade-report/main_state.json` 与 `.upgrade-report/interaction.json`，并返回退出码 `4`；真正向用户提问需要由 Agent 读取这两个文件后在对话中发起。
- Agent 不应只转述 `question/options/files_to_review`；还应优先消费 `missing_inputs`、`fallback_inputs`、`input_modes`、`response_schema`、`input_normalization`
- 分析结果默认输出到 `.upgrade-report/`，交付入口为 `s6_report.md`。

### Step1 输入口径

Step1 现在以**真实构建结果**作为正式输入，用于确定分析范围与依赖变更集合，并作为后续所有阶段结论的前置依据。

**默认行为**：
- 通过 `run_step.py` 自动切换 `base/current` 分支后执行真实 `package`，或直接读取用户提供的 base/current 编译产物
- `boot jar/war` 直接读取最终产物中的嵌套依赖
- `thin jar` / 无嵌套依赖场景直接报错，不再回退到 `dependency:list`

**执行前置条件**：
- 自动构建模式：**必须**提供 `--base-branch`、`--current-branch`
- 直接产物模式：**必须**同时提供 `base_artifact_path` 和 `current_artifact_path`
- 若两种方式都未给全，Step1 不会直接执行，而是先进入前置输入契约交互，明确告诉 Agent 缺哪些字段、支持哪些输入方式、应该如何向用户追问
- 当某一侧嵌套 jar 缺少 `pom.properties`、需要借助 `mvn dependency:list` 补全坐标时，`dependency:list` 只能补充 `groupId/artifactId/classifier` 等坐标信息，不能改写编译产物中已经观察到的版本号；若两边冲突，应优先保留编译产物版本，必要时进入 `unresolved` / 人工确认
- 对同一系统升级场景，若某一侧编译包中的嵌套 jar 缺少 `pom.properties`，优先提供 `base_branch/current_branch`，Step1 会在同一源码仓库中自动切换分支执行 `mvn dependency:list` 补全坐标；但这不是 direct artifact 模式的执行前硬前置
- `base_source_project_dir` / `current_source_project_dir` 只作为特殊兼容能力保留，用于无法通过同一仓库双分支完成补全的场景
- 自动构建模式下，项目构建工具在 PATH 中可用，且目标模块在基准侧和当前侧都能成功构建
- 若直接产物模式还要继续执行 Step2+，建议同时显式提供 `base_branch/current_branch`；系统不会再偷偷用工作区自动探测到的分支顶上
- 若直接产物中的嵌套 jar 缺少 `pom.properties`，可同时提供 `base_branch/current_branch`，让 Step1 额外执行 `mvn dependency:list` 安全补全坐标
- `base_jdk_home` / `current_jdk_home` 为可选项；未提供时各侧默认回落主机 `JAVA_HOME`

**模块级分析额外规则**：
- 如果用户首轮已经明确 `primary_module/modules`，必须把它当作 `Step1` 的前置输入，第一次执行就直接传给 `run_step.py`
- 不允许先按 root 范围跑出一版 `s1_dep_changes.csv`，再在后续待交互确认点里改成模块级
- Maven 多模块场景下，Step1 当前只支持单模块；应通过 `--primary-module` 或单值 `--modules` 指定目标模块

**推荐命令**：
```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base-branch> \
  --current-branch <current-branch>
```

如果已经有两侧编译产物，可直接跳过自动构建：

```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-artifact-path /abs/path/to/base-app.jar \
  --current-artifact-path /abs/path/to/current-app.jar \
  --base-branch <base-branch> \
  --current-branch <current-branch>
```

若不是同仓库双分支场景，再改用双侧源码目录兜底：

```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-artifact-path /abs/path/to/base-app.jar \
  --current-artifact-path /abs/path/to/current-app.jar \
  --base-source-project-dir /abs/path/to/base-source-project \
  --current-source-project-dir /abs/path/to/current-source-project
```

若 Agent 先收到的是待交互状态，建议至少读取并利用这些字段再向用户提问：

- `interaction.question`
- `interaction.missing_inputs`
- `interaction.fallback_inputs`
- `interaction.input_modes`
- `interaction.response_schema`
- `interaction.input_normalization`

如果只分析 `module-a`：

```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base-branch> \
  --current-branch <current-branch> \
  --primary-module module-a \
  --modules module-a
```

## 产物总览（先看这些文件）

统一输出目录：`.upgrade-report/`

- Step1（依赖差异）
  - `s1_dep_changes.csv`
  - `s1_dep_summary.txt`
  - `s1_dep_alerts.csv`
  - `build_provenance.json`
  - `s1_artifacts/`
- Step2（上下文）
  - `s2_context.json`
  - `s2_dep_graph.json`
- Step4（依赖 jar / 源码差异）
  - `s4_jar_compare/all_changed_apis.csv`
  - `s4_jar_compare/all_changed_apis_alerts.csv`
  - `s4_jar_compare/summary.txt`
  - `s4_jar_compare/*_binary.txt`（JApiCmp 原始输出）
  - `s4_jar_compare/*_gitdiff_api_changes.txt`（依赖源码 git diff 原始输出）
  - `s4_jar_compare/*_removed_symbols.txt`（removed jar 的旧版 public/protected 符号导出摘要）
- Step5（调用链）
  - `s5_call_chain/summary.json`
  - `s5_call_chain/summary.txt`
  - `s5_call_chain/alerts.csv`
- Step4 per-dependency（按单个依赖坐标沉淀）
  - `s4_per_dependency/<coord>/removed_jar_symbols.csv`
  - `s4_per_dependency/<coord>/resolved_targets.csv`
  - `s4_per_dependency/<coord>/summary.json`
- Step6（汇总报告）
  - `s6_findings.json`
  - `s6_report.md`

人工排查默认只需要三个入口：Step4 `all_changed_apis.csv` 查看变化事实，Step5
`alerts.csv` 查看完整逐链路追踪过程，Step6 `s6_report.md` 查看最终汇总结论。
`alerts.csv` 不是样例子集：每个进入 Step5 的 API 至少一行，每条终止链路独立一行，
并明确消费依赖、消费类/方法、业务入口、链路状态、中断原因和原始证据位置。
如果同一终止链路在同一消费方法内重复命中，`alerts.csv` 会合并为一行，并通过
`path_occurrence_count` 标明重复命中次数；不同业务入口、不同消费方或不同完整链路不会合并。
当 `alerts.csv` 过大影响人工或表格工具打开时，Step5 会同时输出非空的阅读拆分文件：
`alerts_reachable.csv`、`alerts_uncertain.csv`、`alerts_not_found_in_static_analysis.csv`、
`alerts_not_analyzed.csv`；若单个分类仍过大，则输出
`alerts_<status>_001.csv`、`alerts_<status>_002.csv` 等分片。`alerts.csv` 仍是完整主文件，
拆分文件只是按链路状态生成的人工阅读视图，不是索引、抽样或替代结论。

## 产物字典（让使用者知道每个文件是什么）

说明：本节对 `.upgrade-report/` 目录下的产物给出**定义**、**生成来源/条件**与**用途/解读要点**。产物分为两类：
- **结果文件**：面向使用者直接阅读、筛选与交付。
- **证据文件**：用于结论追溯、抽样复核与问题定位。

默认策略为全量保留证据文件，以满足可追溯与可复核要求。

### Step1：真实构建依赖对比（确定分析范围）

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s1_dep_changes.csv` | 依赖变更明细表（每行一个依赖坐标） | Step1 对 `base/current` 两侧真实构建结果做对比生成 | 作为后续 Step3/Step4/Step5 的分析范围依据；应优先核对变更坐标、版本与 scope 是否符合预期 |
| `s1_deps_current_resolved.csv` | current 侧解析后的依赖清单（坐标、版本、scope、备注） | Step1 对 current 侧最终产物或 runtime 依赖结果做结构化提取生成 | 用于确认“当前构建实际生效的依赖集合”；用于定位 BOM/版本仲裁和打包插件导致的差异 |
| `s1_dep_alerts.csv` | 需人工复核的依赖变更子集（如降级、版本不确定、风险标记） | 从 `s1_dep_changes.csv` 按规则筛选生成 | Step1 的人工复核入口；该文件未确认前，后续分析结果可能出现范围偏差 |
| `s1_dep_summary.txt` | Step1 摘要（统计信息、关键告警 Top 列表） | Step1 依据解析结果汇总生成 | 用于快速确认输入是否正确（尤其是多模块/primary_module 场景）与变更规模分布 |
| `build_provenance.json` | base/current 最终制品的来源、构建状态、SHA-256 与留存路径 | Step1 在自动构建或直接产物模式下统一写入 | 是 Step5 校验“业务源码与制品是否对齐”的正式依据；重跑 Step1 时必须一起刷新 |
| `s1_artifacts/` | Step1 留存的 base/current 最终制品及必要附属文件 | Step1 对自动构建结果或用户提供产物做归档后生成 | 供 Step5 提取业务 class 和运行时嵌套 JAR；旧目录不得跨轮复用 |

补充说明：
- 当部分嵌套依赖无法安全补齐坐标时，Step1 会先进入待交互；无论当前走的是直接产物模式还是自动切分支构建模式，用户都可补 `manual_coord_overrides`，或显式选择 `confirm_unresolved`
- 选择 `confirm_unresolved` 后，未补齐项会保留在 `s1_dep_changes.csv`，并写成 `resolution_status=unresolved`
- 后续 Step2~Step5 会跳过 `resolution_status=unresolved` 的行，不把它们当作可继续消费的已解析依赖

### Step2：上下文推断（决定跑哪些扫描/规则）

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s2_context.json` | 项目升级上下文（JDK/Spring Boot 版本、技术栈标志、升级依赖清单等） | Step2 基于 `s1_dep_changes.csv` 以及少量 git/pom 只读信息推断生成 | 决定 Step3 扫描项与 Step4/5 策略选择；用于解释某些产物为何生成/为何跳过；缺字段时应按门控提示补齐 |
| `s2_dep_graph.json` | 升级依赖关系图（含分析顺序：叶→根） | Step2 基于发生版本变化的依赖生成 | 用于理解升级依赖之间的传播关系与推荐分析顺序 |

### Step3：静态扫描（背景信号，不等于影响系统）

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s3_jdk_removed_api.csv` | JDK 移除/不兼容 API 的静态命中表（文件/行号/命中片段等） | 在 `s2_context.json` 指示存在 JDK 升级场景时生成 | 用于暴露潜在编译期失败点；本文件为背景信号，是否影响当前系统以 Step5 的可达性结论为准 |
| `s3_jdk_javax_refs.csv` | `javax.*` 引用命中表 | 在 `s2_context.json` 指示存在 javax→jakarta 迁移风险时生成 | 用于评估迁移工作量与风险面；应区分 main/test 以及第三方代码引入的引用 |
| `s3_jdk_internal_api.csv` | JDK 内部 API（如 `sun.*`）引用命中表 | 在 JDK 升级场景下生成 | 用于暴露运行时兼容性风险；通常需结合替代方案或 JVM 启动参数进行处置 |

### Step4 / per-dependency：removed jar 与单依赖视图

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s4_jar_compare/*_removed_symbols.txt` | removed 依赖的旧版 jar 符号导出摘要 | 当 Step1 判定依赖为 `移除` 时，由 Step4 对旧版 jar 执行 `javap -public -s` 生成 | 用于确认旧版 jar 是否成功定位、导出了多少 public/protected 类/方法/构造器，以及是否存在导出错误 |
| `s4_per_dependency/<coord>/removed_jar_symbols.csv` | 某个依赖的 removed jar 旧版符号明细 | 仅在 `change_type=移除` 时生成 | 这是 removed jar 场景下的正式目标池，后续 Step5 会直接消费这些符号去证明是否触达系统源码 |
| `s4_per_dependency/<coord>/resolved_targets.csv` | 某个依赖最终归一化后的 Step5 输入视图 | Step4 完成后按单个 `coord` 生成 | 用于查看“这个依赖本轮究竟有哪些目标会进入 Step5”，会做去重和字段归一化 |
| `s4_per_dependency/<coord>/summary.json` | 某个依赖的阶段性摘要 | Step4 写入目标池与 removed jar 导出结果，Step5 再补写触达结论 | 这是“单个依赖包为集合”的主视图入口，可继续深入 `resolved_targets.csv` 或 `by_api/*.json` |
| `s3_jdk_reflection.csv` | 反射/动态调用相关命中表 | 在 JDK 升级场景下生成 | 用于识别可能绕过编译期检查的风险面；建议与回归测试结合复核 |
| `s3_jdk_serialization.txt` | 序列化兼容性相关扫描输出（文本摘要） | 在 JDK 升级场景下生成 | 用于指导回归验证范围（对外传输对象、落库对象等）；属于风险提示而非影响证明 |
| `s3_jdk_runtime_flags.csv` | 运行时参数/兼容性开关建议表 | 在 JDK 升级场景下生成 | 用于运行期兼容性处置与问题定位；不构成代码层结论 |
| `s3_springboot_config.csv` | Spring Boot 配置项/配置文件相关命中表 | 在 Spring Boot 升级场景下生成 | 用于定位启动失败与行为变化线索；建议结合实际配置文件逐项核对 |
| `s3_springboot_autoconfig.txt` | 自动装配元数据扫描输出（spring.factories/AutoConfiguration.imports） | 在 Spring Boot 升级场景下生成 | 用于识别 starter/内部组件的自动装配元数据迁移工作；属于迁移线索 |
| `s3_dependency_compat.csv` | 依赖兼容性规则命中表（基于规则库） | 依赖变化存在时生成 | 用于提供依赖兼容性风险提示与排查方向；是否影响当前系统以 Step5 结论为准 |
| `s3_dependency_classfile.csv` | 依赖 classfile 版本/字节码兼容性线索表 | 依赖变化存在时生成 | 用于定位类加载/启动阶段的强风险信号（版本不匹配等） |

### Step4：jar 对比（依赖变化事实 + 原始证据池）

目录：`s4_jar_compare/`

| 文件 | 是什么 | 因为什么会生成 | 代表什么 / 怎么看 |
|---|---|---|---|
| `s4_jar_compare/all_changed_apis.csv` | API 变化聚合明细表（来源可为 JApiCmp、git diff、changelog 任务等） | Step4 对变更依赖执行 jar 对比与（可选）源码对比后汇总生成 | 表示“依赖层面的变化事实集合”；Step5 会直接基于该文件做反向调用链分析 |
| `s4_jar_compare/all_changed_apis_alerts.csv` | 高优先级变化子集（如 P0/P1、未确认来源等） | 从 `all_changed_apis.csv` 按规则筛选生成 | 用于优先复核高风险变化；建议抽样回溯到对应原始证据文件 |
| `s4_jar_compare/summary.txt` | Step4 执行摘要（覆盖率、缺失项、失败原因、git diff 执行/跳过原因等） | Step4 汇总生成 | 用于判断 Step4 证据是否完整（如 jar 缺失、JApiCmp 缺失、升级依赖源码未配置）以及后续反向调用链分析的置信度 |
| `s4_jar_compare/changed_classes.json` | 类级变更索引（按依赖聚合的 added/removed/modified 类集合） | Step4 在构建类级索引成功时生成 | 用于辅助定位发生变化的类集合 |
| `s4_jar_compare/*_binary.txt` | JApiCmp 原始输出（单依赖维度） | Step4 对单个依赖执行 JApiCmp 后生成 | 二进制兼容性变化的原始判据；用于对 `all_changed_apis.csv` 进行证据追溯与复核 |
| `s4_jar_compare/*_gitdiff_api_changes.txt` | 依赖源码差异提取结果（单依赖维度） | 仅在提供 `dependency_source_dirs` 且可定位对比 ref 时生成 | 用于识别“签名不变但行为变更”等二进制对比难以覆盖的风险来源；属于证据文件 |
| `s4_jar_compare/*_behavior.txt` | 行为变更分析任务单（changelog/release notes 线索，通常待确认） | 仅在缺少可用源码仓库且存在版本升级场景时生成 | 表示待人工确认的行为变化线索；通常不作为已确认结论，应在复核后标注与处置 |

### Step5：调用链影响（影响证明）

目录：`s5_call_chain/`

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s5_call_chain/summary.json` | 调用链结论汇总（reachable/not_found_in_static_analysis/uncertain/not_analyzed）、`reason_code`、按 API 的能力覆盖与关键证据摘要 | Step5 仅对 Step4 API 目标执行普通调用、字节码、反射、MethodHandle、资源、表达式语言及框架边分析后生成 | 影响判定的核心结论文件；目标相关能力为 partial/insufficient 时不会输出 not_found；抽样复核时先看 `analysis_status/reason_code`，再沿 call_paths 定位证据 |
| `s5_call_chain/alerts.csv` | 完整链路台账（每个 API 至少一行、每条终止链路一行） | Step5 从全部终止路径结构化导出，不抽样 | 完整主文件；自动化和完整审计优先读取这里 |
| `s5_call_chain/alerts_<status>.csv` / `alerts_<status>_NNN.csv` | `alerts.csv` 的人工阅读拆分文件 | Step5 按 `path_status` 从完整台账派生；仅非空分类生成，超过阈值时按序号分片 | 人工复核大文件时优先打开；内容仍来自完整台账，不是轻量索引或样例 |
| `s5_call_chain/summary.txt` | Step5 摘要（数量统计、Top 模块/Top 风险、uncertain/not_analyzed 原因分类等） | Step5 汇总生成 | 用于快速掌握总体影响分布；若 uncertain 或 not_analyzed 比例较高，应优先补齐依赖源码映射、检查图截断与框架装配路径 |
| `s5_call_chain/by_api/*.json` | 单条风险的完整调用链证据（`evidence_paths`、逐跳命中点、reason_code 等） | Step5 对单个候选生成 | 用于复核 reachable/uncertain 结论与定位截断点；属于证据文件 |
| `s5_call_chain/by_module/*_impacts.json` | 按模块聚合的影响摘要 | Step5 对调用链结果进行模块聚合后生成 | 用于按业务域拆解责任与处置优先级；属于视图文件 |
| `s5_artifact_bytecode/` | Step5 从 current 最终制品解出的运行时依赖 JAR 与业务 class 缓存 | Step5 读取 Step1 留存制品并完成字节码入口扫描后生成 | 用于保存字节码扫描的实际输入；重跑 Step5 时必须与调用链结果一起刷新 |
| `s5_artifact_bytecode_catalog.json` | Step5 对 current 最终制品、业务 class 与运行时依赖 JAR 的提取清单与覆盖状态 | Step5 读取 Step1 留存制品并完成字节码入口扫描后生成 | 用于判断字节码证据是否完整；重跑 Step5 时必须与调用链结果一起刷新 |
| `s5_artifact_bytecode_index.json` | 按 current 制品 SHA-256 缓存的业务 class 字节码索引 | Step5 在构建字节码事实库时生成 | 用于复用方法/字段/类型/`invokedynamic` 证据；制品变化或重跑 Step5 时必须失效重建 |
| `framework_adapters.json` | SPI、Spring、MyBatis、动态代理等框架隐式边适配结果 | Step5 的框架适配器阶段生成 | 用于解释部分非显式源码边来源；旧轮次 adapter 结果不得污染本轮 |
| `source_artifact_alignment.json` | 源码 revision/dirty 状态与 Step1 制品溯源的一致性检查结果 | Step5 对源码目录与 Step1 留存制品做对齐校验后生成 | 用于决定字节码未命中能否反证源码候选；重跑 Step5 时必须同步刷新 |

### Step6：汇总报告（给使用者交付）

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `s6_findings.json` | 最终结构化输出（findings，含 Step5 的 `reason_code/evidence_paths` 摘要） | Step6 汇总 Step1~Step5 产物后生成 | 用于自动化消费（流水线集成、趋势分析、工单/看板对接等） |
| `s6_report.md` | 最终人类可读报告（按 P0/P1/P2/❓，并单列“可能影响”“需要补充输入”“未覆盖/未分析”） | Step6 基于 findings 渲染生成 | 面向交付与评审；风险条目应可回溯到 Step5 的 `by_api/*.json` 证据文件进行复核，且应与 Step5 的 `user_conclusion` 分桶保持一致 |

### 运行态文件（跨步骤）

| 文件 | 定义 | 生成来源/条件 | 用途与解读 |
|---|---|---|---|
| `main_state.json` | 唯一主状态文件（业务参数、步骤输入输出、待交互状态） | 由调度器维护；首次初始化输入应通过 `--seed-json` 建立，再由调度器持续更新 | 决定当前分析实际采用的输入、当前步骤、已完成步骤和待交互状态 |
| `interaction.json` | 待交互展示文件 | 调度器在进入待交互状态时生成 | 仅用于向 Agent/用户展示问题、选项、缺失输入和恢复提示，不参与运行期求值 |

## main_state.json（唯一主状态文件）

首轮确认后的输入应通过 `--seed-json` 建立到 `.upgrade-report/main_state.json`（与报告目录同级，便于团队协作复跑与复核），后续统一由调度器维护。

最常用字段：
- `base_branch` / `current_branch`
- `target_module`：本次唯一的目标部署模块；确认后自动生成 `project_scope` 和 reactor 依赖闭包
- `source_dirs`：旧状态兼容/异常覆盖字段；标准 Maven 工程无需用户填写或确认
- `dependency_source_dirs`：依赖源码目录列表，支持单模块工程根目录或多模块仓库根目录；系统会自动推断模块坐标，并派生 Step4 git diff 所需源码映射与 Step5 依赖源码映射
- `max_depth`：调用链最大累计代价（默认 5，高置信度边最多5跳，详见 SKILL.md 置信度加权深度策略）
- `allow_degraded`：是否允许缺关键输入时继续（不建议，可能漏分析）

推荐只提供：
- 列表字符串：`["/abs/repo-a", "/abs/repo-b"]`
- 列表对象：`[{"path":"/abs/repo-a"}]`

对 `dependency_source_dirs` 而言，只要给到源码工程目录或仓库根目录，调度层都会优先扫描仓库中的多模块 `pom.xml` / `build.gradle` 并自动展开所有推断出的坐标。

`dependency_source_dirs` 是唯一推荐用户入口；其余映射属于内部派生结果，不建议直接配置。

## 自我排查（按这个顺序做）

### 1) 看主状态：当前停在哪一步 / 为什么停下

`.upgrade-report/main_state.json` 会记录：
- `state.current_step` / `state.completed_step`：当前停在哪一步、上一步完成到哪里
- `state.status` / `state.blocking_reason`：当前状态以及阻塞原因
- `pending_interaction`：待用户交互信息（问题、选项、建议动作）
- 各步骤 `input` / `derived` / `output`：本次分析实际采用的输入与阶段结果快照

若出现待交互状态，可同时查看 `.upgrade-report/interaction.json`。Agent 应根据 `pending_interaction.question/options` 向用户提问，而不是仅把 Python 输出当作报错。

若 `run_step.py` 返回退出码 `4`：
- 这表示“需要用户答复”，不是步骤失败
- 优先读取 `.upgrade-report/interaction.json`
- 收到用户答复后，用 `--response-json` 或 `--response-file` 恢复，不要直接重试原命令
- 推荐把用户答复整理成 `intent_patch` 结构后再恢复，而不是直接在顶层透传业务字段

若出现阻塞或待确认，优先根据 `blocking_reason` / `pending_interaction` 补齐信息或完成复核，再继续推进流程。

### 3) Step1 常见问题：多模块“拿错目标模块”

现象：
- 指定模块分析时，实际构建范围落回了 root 模块

排查与规避：
- 第一次执行 `Step1` 就要显式带上 `--primary-module/--modules`
- 必须同时提供 `--base-branch`、`--current-branch`
- 重点复核 `s1_dep_summary.txt` 中的 `primary_module`、`current_packaging_mode` 与产物路径

```bash
python3 scripts/run_step.py --step step1 \
  --project-dir . \
  --report-dir .upgrade-report \
  --base-branch <base-branch> \
  --current-branch <current-branch> \
  --primary-module module-a \
  --modules module-a
```

### 4) Step4 常见问题：你给了依赖源码，但没看到 git diff

git diff 路径触发条件（同时满足才会执行）：
- 你提供了依赖源码目录：`dependency_source_dirs`（指向依赖源码工程/仓库根目录，且该目录是 git repo）
- Step4 拿到了可对比的两个 ref（分支/标签/commit）
  - 默认：只根据依赖版本号在该依赖仓库的远端分支 `remotes` 中匹配；只去掉末尾 `-SNAPSHOT` 后，按“严格边界命中”筛选候选
  - 示例：版本 `3.0.2` 会命中 `origin/auth-sdk3.0.2`，不会命中 `origin/auth-sdk3.0.2.1`
  - 优先级：`非 DEV` 分支高于 `DEV/dev` 分支；若 old/new 两侧同时存在多个候选，会优先选择 remote 一致、版本前缀家族一致的 ref pair；若同优先级下仍有多个候选，则进入人工确认
  - 常见命中形式：`origin/release-1.2.3`、`origin/hotfix-1.2.3`、`origin/support/1.2.3-DEV`
  - 若未匹配到，或存在歧义，则进入人工确认
  - 注意：这里不会直接沿用主项目的 `base_branch/current_branch` 作为依赖源码仓库的对比分支

补充口径：
- 不是所有升级依赖都会自动做 git diff；只有成功从 `dependency_source_dirs` 识别并匹配到升级依赖的源码模块才会走这条路径

自查点：
- 看 `.upgrade-report/s4_jar_compare/summary.txt` 的 “源码对比（git diff）” 小节：会列出已执行/跳过原因
- 看对应原始输出：`s4_jar_compare/*_gitdiff_api_changes.txt`，文件头会写明命中的 `base_ref/cur_ref`、版本匹配原因、git 命令与工作目录

补充说明：
- 源码 git diff 能识别两类变化：
  - 签名变化（删除/新增/签名变更）
  - `BEHAVIOR_CHANGED`：public/protected 方法签名不变但方法体变更（更容易被二进制对比漏掉）

### 5) Step4 常见问题：JApiCmp 对比不完整 / jar 找不到

排查顺序：
- 查看对应的 `*_binary.txt` 是否写了“jar 未找到 / JApiCmp 未安装”
- 机器解析以对应的 `*_binary.xml` 为准；文本只用于人读或 XML 失败回退
- 确认本机 Maven 仓库完整（尤其是私服依赖）
- 需要时手动拉取：

```bash
mvn -q dependency:get -Dartifact=<groupId:artifactId>:<version>
```

若处于离线/内网环境：
- 建议预先准备 `japicmp-*-jar-with-dependencies.jar`
- 在 `main_state.json` 中补 `japicmp_jar`
- 若无法使用 JApiCmp，最终结论需显式标注“Binary Incompatible 检测已降级”

### 6) Step5 常见问题：调用链被截断 / 候选为空

若 `all_changed_apis.csv` 为空，不等于“无风险”，应优先查看 `.upgrade-report/s4_jar_compare/summary.txt` 与相关原始证据文件，确认是否存在 jar 缺失、git diff 跳过或提取失败。

调用链跨依赖边界的正式语义：
- 业务源码范围来自统一 `project_scope`；业务字节码以 Step1 留存并校验 SHA-256 的 current 最终制品为主，`target/classes` 只作为降级辅助
- SPI、Spring、MyBatis、`dynamic_proxy_basic` 与 `declarative_http_client_basic` 的隐式关系写入 `.upgrade-report/framework_adapters.json`
- 优先在 `main_state.json` 中补齐 `dependency_source_dirs`，这样 Step5 可以继续做“有源码依赖”回溯
- 无论是否存在依赖源码映射，Step5 都会从 current 最终制品按 `lib_entry` 提取实际运行时 JAR，对所有升级、降级、迁移和删除依赖执行字节码级类/方法/字段匹配
- 运行时 JAR 扫描会解析 lambda/方法引用的 `invokedynamic` bootstrap method handle；Multi-Release JAR 按 Step2 `jdk_current` 选择实际生效版本，目标 JDK 未知时不会用未命中反证无影响
- `.upgrade-report/s5_artifact_bytecode_catalog.json` 记录精确制品提取数量、业务 class 数、fallback、缺失项和覆盖状态；使用本地 Maven 仓库 fallback 时状态不会是 `complete`
- `.upgrade-report/s5_artifact_bytecode_index.json` 按 current 制品 SHA-256 缓存业务 class 的方法、构造、字段、类型指令、常量池/签名/注解引用和 `invokedynamic` 证据；SHA 变化会自动失效
- `.upgrade-report/source_artifact_alignment.json` 记录源码 revision/dirty 状态与 Step1 制品溯源是否一致；未对齐时，字节码未命中不得反证源码候选
- `alerts.csv` 的 `reason/action` 按每条终止路径的 `stop_reason` 生成；`path_id` 基于符号与证据类型等语义字段，不受工作目录或证据绝对路径变化影响
- `reason_code=BUSINESS_ARTIFACT_BYTECODE_USAGE` 表示 current 最终制品中的业务 class 已确认引用目标符号；这项事实不依赖源码是否存在
- 当 `reason_code=PACKAGED_DEPENDENCY_BYTECODE_USAGE` 时，表示已经在最终制品的运行时依赖 JAR 中稳定命中目标符号，但当前源码追踪仍未证明是否回到系统源码，因此会收敛为 `uncertain`；若依赖源码可用，Step5 会先继续尝试把链路回溯到业务代码，再决定是否回退到这项结论
- 当 `reason_code=RUNTIME_DEPENDENCY_USES_REMOVED_API` 时，表示某个仍被打入最终制品的依赖 JAR 继续引用已整体删除依赖的类/方法/字段；应优先检查命中的消费类和业务入口，并验证 `NoClassDefFoundError` / `NoSuchMethodError` 风险
- Step3 的 JDK、Jakarta namespace 与 Spring Boot 迁移规则分别来自 `references/rules/jdk.json`、`jakarta.json` 和 `spring-boot.json`；输出会记录规则 ID 与规则包版本
- Step3 的 `s3_coverage.json` 同时记录规则包 SHA-256、权威来源、最后核验日期和按升级区间激活的扫描；Step4 的 `coverage.json` 分离二进制 API 与行为差异覆盖
- 编译期常量值变化输出 `CONSTANT_VALUE_CHANGED`；调用方可能已经内联旧值，因此没有 `getstatic/getfield` 也只能判为 `INLINED_CONSTANT_USAGE_UNDETECTABLE/uncertain`

建议复核顺序：
- 先看 `.upgrade-report/s5_call_chain/summary.json` 中的 `uncertain_apis` 与 `not_analyzed_apis`
- 若存在 `DEPENDENCY_SOURCE_MAPPING_MISSING`，优先补齐 `dependency_source_dirs` 后重跑 Step5
- 若存在 `PACKAGED_DEPENDENCY_BYTECODE_USAGE`，优先审查命中的运行时依赖及其入口；若要继续证明是否回到系统源码，可补 `dependency_source_dirs`
- 若存在 `GRAPH_TRUNCATED`，提高 `--max-methods / --max-reverse-edges / --max-incoming-per-key` 后重跑
- 若存在 `INTERFACE_OR_ABSTRACT_API`、`RESOURCE_OR_REFLECTION`，不要把结果当成“未影响系统”
- 查看 `.upgrade-report/coverage.json` 判断各证据面是 `complete`、`partial`、`insufficient` 还是 `not_applicable`；其中 `indirect_usage_matrix` 会按 symbol kind 和调用机制列出反射、MethodHandle、资源、表达式语言等覆盖矩阵

### 7) 如何理解 Step5 四态结论

- `reachable`：已经回溯到业务源码，属于当前系统的真实风险
- `not_found_in_static_analysis`：当前静态分析未找到路径，不代表确定未影响；仍需结合依赖源码映射、反射/资源配置与分析能力边界判断
- `uncertain`：发现候选路径但存在低置信歧义，必须人工确认
- `not_analyzed`：工具已知未覆盖该场景，不能解释为“未影响”；常见原因包括行为变更、字节码分析未完成、资源/反射命中、接口/抽象 API、图截断
- 再打开 `.upgrade-report/s5_call_chain/by_api/*.json`，核对 `evidence_paths` 与 `reason_code`

若通过 `run_step.py` 执行并卡在 Step5 待交互，可直接使用：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"rerun_current_step","set":{"dependency_source_dirs":["/abs/path/to/dependency-repo"]},"notes":"补依赖源码目录后重跑 Step5"}}'
```

对外兼容说明：
- `summary.json` 的正式语义已收敛为 `reachable` / `uncertain` / `not_analyzed` / `not_found_in_static_analysis`
- `deprecated_aliases` 仅用于帮助旧消费方迁移，不代表系统内部仍维护旧语义分支

## 开发者

- 推荐统一质量门入口：
  - 快速检查：`python3 scripts/quality_gate.py --profile quick`
  - Step5/字节码/输出语义相关修改：`python3 scripts/quality_gate.py --profile step5`
  - 打包或重要提交前：`python3 scripts/quality_gate.py --profile release`
  - 只查看计划不执行：`python3 scripts/quality_gate.py --profile release --dry-run`
- 单独运行准确性基准矩阵：`python3 scripts/accuracy_benchmark.py --profile core|step5|all`
- 审计真实项目“通过但可疑”的质量信号：`python3 scripts/quality_signal_audit.py /path/to/real_project_result.json`
- 运行完整最小回归：`python3 scripts/smoke_regression.py`
- 按主题运行回归：`python3 scripts/smoke_regression.py --group core|step5|orchestrator`
- 通过标准测试入口运行：`python3 -m unittest discover -s tests -v`
- 保留临时工作区排查：`python3 scripts/smoke_regression.py --keep-tmp`
- CI 已提供 GitHub Actions 工作流：`.github/workflows/smoke-regression.yml`
