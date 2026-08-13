# Java Upgrade Analyzer Runbook

本文件给维护者提供执行和排障命令。普通使用者先看 `README.md`；正式流程始终由 `scripts/run_step.py` 调度。

## 运行前提

- CPython 3.10 或更高版本；
- base/current 两侧可复核的最终制品；
- 必须提供的应用 Git 源码仓库；当前项目仓库可自动识别，但仍需在 Step0 确认；
- 与两侧运行环境一致的完整目标 JDK；
- Step1 可留存的 base/current 完整最终制品；系统会自动生成固定制品 SHA、运行路径顺序、loader/resource policy 和业务入口的 `binary_pipeline_config`，仅在特殊部署模型下才需要显式覆盖；
- 可选的依赖包源码在 Step0 一次收集，待 Step1 解析出依赖身份后再自动匹配仓库和版本；
- 可写的 `.upgrade-report/`。

所有 CSV 使用 UTF-8 BOM，适合 Excel 直接打开。JSON 和 Markdown 使用 UTF-8。

Step4–Step6 只有 binary-first 引擎。没有旧引擎选择、灰度、兼容或 fallback 参数；失败时停止并保留上一份已经独立验证且完整发布的 generation。

## 推荐入口

首次查看 Step0 统一确认协议：

```bash
python3 scripts/run_step.py --describe-step0-contract
```

初始化并自动运行到必要确认点：

```bash
python3 scripts/run_step.py --step auto \
  --project-dir /abs/path/to/project \
  --report-dir /abs/path/to/project/.upgrade-report \
  --seed-json /abs/path/to/runtime-input.json
```

`runtime-input.json` 示例见 `runtime_config.example.json`。后续业务参数以
`.upgrade-report/.runtime/state/main_state.json` 为唯一主状态，不要在每一步重新拼接一套参数。
新流程不兼容旧状态或旧交互记录。报告目录中的状态 schema 不匹配时会重新建立 Step0；
修改应用源码、base/current 版本、模块、构建工具或 JDK 时也应从 Step0 重新确认。
`--seed-json` 只用于首次初始化。

确认后，Step0 会在任何正式构建和大规模扫描前执行真实前置检查，并把内容绑定结果写入
`.upgrade-report/.runtime/state/step0_preflight.json`：两侧 JDK 必须从各自确认的绝对
`JDK Home/bin` 成功完成 `javac -> javap -> java` 探针，且平台镜像完整；固定 commit 的
worktree 必须能够创建、验证和精确清理；Maven/Gradle 必须在对应 JDK 环境中启动并加载
项目模型；ASM、直接输入的 JAR 和输出目录也必须通过完整性检查。Git worktree 清单固定
使用 `git worktree list --porcelain`，不使用不受支持的 `-z` 组合，也不在命令失败后静默
切换语义。Step1 才产生的运行时 JAR 无法提前存在，因此在 Step1 产出后立即校验摘要和
完整 ZIP CRC，校验通过前不进入 Step2。

恢复运行：

```bash
python3 scripts/run_step.py --step auto \
  --project-dir /abs/path/to/project \
  --report-dir /abs/path/to/project/.upgrade-report
```

恢复用户确认：

```bash
python3 scripts/run_step.py --step auto \
  --project-dir /abs/path/to/project \
  --report-dir /abs/path/to/project/.upgrade-report \
  --response-file /abs/path/to/user-response.json
```

退出码 `4` 表示等待用户输入。必须读取 `main_state.json` 和 `interaction.json`，按
`CHECKPOINT_RULES.md` 向用户展示决策卡，不能代替用户选择。

## Binary pipeline 输入

配置 schema 为 `java-upgrade-analyzer.binary-pipeline-input.v1`。base/current 每个运行时制品至少包含：

- `path`：实际 JAR/ZIP；
- `coord`：带版本依赖坐标；
- `lineage`：跨版本稳定依赖身份，通常为 `groupId:artifactId[:classifier]`；
- `logical_location`、`loader_realm`、`path_kind`、`slot`：有序运行路径身份；
- 完整 `runtime_profile`：目标 JDK、loader topology、入口和覆盖状态。

正常 `run_step.py` 流程从 Step1 的双侧业务制品、完整依赖 JAR 清单和目标 JDK 自动物化以上字段。显式 `binary_pipeline_config` 是高级调试/特殊 loader 部署入口，不是普通用户必须手写的前置条件；自动物化无法证明闭包完整时失败关闭并列出具体缺口。

`source_inputs` 记录业务源码与依赖源码各自的实际可用状态和来源，不是用户授权合同。存在源码时必须形成按 `owner_type`、`owner_coord` 区分的 `source_overlay.source_sets`；缺少某一类源码只产生该类覆盖缺口，不能关闭另一类已经可用的源码。源码只增加人类可理解的位置和语义，不能改变运行时提供者、变化事实、精确可执行边或正式裁决。

可直接调试 generation：

```bash
python3 scripts/binary_pipeline.py \
  --config /abs/path/to/binary-pipeline-input.json \
  --output-root /abs/path/to/.upgrade-report/.runtime/binary_authority \
  --result-json /abs/path/to/.upgrade-report/.runtime/state/binary_pipeline_result.json
```

## Step4–Step6 数据流

1. Step4 读取最终制品并构建二进制事实，按 target runtime 重建有效 class/resource provider，冻结变化裁决与投影，再执行独立 Oracle 验证。
2. 只有验证通过的 generation 才原子激活；Step4 从该 generation 发布依赖和 API 人工复核材料。
3. Step5 从同一 generation 发布四态系统触达证据，可按 Step4 已确认的依赖坐标限制范围。
4. Step6 校验 Step5 与 active generation 身份一致后发布最终报告。

四态互斥：`reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed`。
`not_found_in_static_analysis` 只表示当前静态范围未发现路径，不表示安全或不受影响。没有运行时验证时只输出 `probable_impact` 或 `inconclusive`，不输出“确认有影响/确认无影响”。

## 人工复核路径

先看：

1. `evidence/api_changes/changed_dependencies.md`：哪些依赖引起变化、优先顺序和明细入口；
2. `evidence/api_changes/s4_per_dependency/*/summary.md`：单个依赖的变化 API；
3. `evidence/api_changes/review.md`：包含不可投影事实、诊断候选和证据缺口的完整复核；
4. `evidence/call_chain/summary.md` 与 `alerts.csv`：每个依赖/API 的四态和路径；
5. `deliverables/report.md`：最终结论和范围；完整明细位于同目录的 dependency/API Markdown 与 CSV。

内部文件分开存放：

- `.runtime/binary_authority/`：不可变 generation、SQLite、验证附件和失败记录；
- `.runtime/state/`：工作流主状态；
- `.runtime/indexes/`：查询索引；
- `.runtime/observability/`：进度和耗时，不是结论证据。

不要要求人工从内部 JSON/SQLite 反推结论。

## 原子发布与失败处理

- 新 generation 写入独立目录，内容身份不包含耗时、绝对临时路径或时间戳；
- 独立验证失败时不激活；
- generation 激活后若 Step4 人工报告发布失败，调度层恢复上一 active pointer；
- Step4/5 报告目录使用 stage + replace 发布，不能留下半套文件；
- 失败证据写入 `.runtime/binary_authority/binary_failures/`；不要删除上一份有效输出；
- 失败证据包含原因码、失败 phase、最后一条结构化进度、子进程结构化结果、traceback 和
  有界 `run.log` 尾部，不再要求先人工翻完整日志才能定位根因；
- 每次执行在 ref 解析前恢复带有效所有权租约的分析器临时 worktree，并把结果写入 `.runtime/observability/git_worktree_recovery.json`；禁止用全局 `git worktree prune` 代替精确恢复，避免影响用户 worktree；
- 输入、目标 JDK、loader policy 或 coverage 缺失会失败关闭，不调用其他引擎补算。

## 性能与进度

- 长阶段通过统一进度事件和 heartbeat 告知用户仍在运行；
- 独立验证会分别上报 JDK 复核、制品 inventory、直接边、结构/指令、目标 JVM 批次、
  跨版本语义、闭世界结果和流式写入进度，而不是只写 heartbeat；
- `.runtime/observability/step4_timing.csv` 记录事实解析、reconciliation、裁决、trace、generation 写入、独立验证和人读报告发布耗时；
- `.runtime/observability/step5_timing.csv` 记录范围过滤、索引和报告发布耗时；
- `.runtime/binary_authority/binary_observability/` 保存 cache 命中和 pipeline 原始计时；这些数据不进入 generation 内容身份。

性能优化只能减少重复解析、I/O、内存和确定无关的工作，不能缩小声明范围、降低身份精度或把未完成结果改成负结论。

## 重跑

单步安全重跑：

```bash
python3 scripts/run_step.py --step step4 \
  --project-dir /abs/path/to/project \
  --report-dir /abs/path/to/project/.upgrade-report
```

Step4 重跑会生成或复用内容绑定的 generation；若失败发生在不可变 generation 已写完、
独立验证尚未通过之后，重跑只会在配置、输入制品、JDK、源码 snapshot、实现代码和
generation 身份全部一致时复用该 generation 并重做验证。任一身份变化都会拒绝断点并
完整重建，不能用旧 generation 掩盖输入变化。Step5/6 只消费 active generation。范围改变时从 Step4 的范围确认恢复，让调度器清理 Step5 及之后的用户输出；不要手工混合两次 generation 的文件。

## 开发验证

```bash
python3 -m compileall -q scripts tests
python3 scripts/test_trust_gate.py
python3 scripts/quality_gate.py --profile blackbox
python3 scripts/quality_gate.py --profile whitebox
python3 scripts/quality_gate.py --profile performance
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
python3 scripts/accuracy_benchmark.py --profile all
python3 scripts/binary_performance_gate.py --verify-recorded-gate tests/fixtures/binary_first/performance_gate.json
python3 scripts/binary_real_project_guard.py --manifest tests/fixtures/binary_first/real_projects/mybatis_sample_xml_noop.json --verify-manifest
```

`blackbox` 保护公开输入输出，`whitebox` 保护当前内部实现，`performance` 保护小规模性能与正确性守恒；具体原则见 `docs/developer/testing-strategy.md`。release profile 先执行测试可信度门，再使用 unittest discovery 唯一分类并运行全部测试，新增测试不会因未登记而漏跑。对重要引擎改动还必须执行同一真值输入的 `main`/当前分支对比，逐项核对依赖身份、变化对象、路径、漏报、误报、覆盖边界、耗时和内存；只比较总数不构成有效证据。

公开能力盘点位于 `tests/fixtures/system_test_capability_matrix.json`。`python3 scripts/test_trust_gate.py` 会输出 covered/partial/missing 数和具体阻断项；局部测试即使全部通过，只要矩阵未完成，`test_suite_runner.py --suite all` 与 Release 准出仍会以 `PUBLIC_CAPABILITY_MATRIX_INCOMPLETE` 失败，避免把“已测部分通过”误报成“系统全面可靠”。
