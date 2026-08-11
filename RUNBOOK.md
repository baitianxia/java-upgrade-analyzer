# Java Upgrade Analyzer Runbook

本文件给维护者提供执行和排障命令。普通使用者先看 `README.md`；正式流程始终由 `scripts/run_step.py` 调度。

## 运行前提

- CPython 3.10 或更高版本；
- base/current 两侧可复核的最终制品；
- 与两侧运行环境一致的完整目标 JDK；
- Step1 可留存的 base/current 完整最终制品；系统会自动生成固定制品 SHA、运行路径顺序、loader/resource policy 和业务入口的 `binary_pipeline_config`，仅在特殊部署模型下才需要显式覆盖；
- Step2 已说明源码用途，并通过统一入口收集用户还能提供的源码位置或记录暂不补充；编译模式已取得的业务源码直接使用；
- 可写的 `.upgrade-report/`。

所有 CSV 使用 UTF-8 BOM，适合 Excel 直接打开。JSON 和 Markdown 使用 UTF-8。

Step4–Step6 只有 binary-first 引擎。没有旧引擎选择、灰度、兼容或 fallback 参数；失败时停止并保留上一份已经独立验证且完整发布的 generation。

## 推荐入口

首次查看 Step1 输入协议：

```bash
python3 scripts/run_step.py --describe-step1-contract
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
- 输入、目标 JDK、loader policy 或 coverage 缺失会失败关闭，不调用其他引擎补算。

## 性能与进度

- 长阶段通过统一进度事件和 heartbeat 告知用户仍在运行；
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

Step4 重跑会生成或复用内容绑定的 generation；Step5/6 只消费 active generation。范围改变时从 Step4 的范围确认恢复，让调度器清理 Step5 及之后的用户输出；不要手工混合两次 generation 的文件。

## 开发验证

```bash
python3 -m py_compile scripts/*.py tests/*.py
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
python3 scripts/accuracy_benchmark.py --profile all
```

release profile 使用 unittest discovery，新增测试不会因未登记而漏跑。对重要引擎改动还必须执行同一真值输入的 `main`/当前分支对比，逐项核对依赖身份、变化对象、路径、漏报、误报、覆盖边界、耗时和内存；只比较总数不构成有效证据。
