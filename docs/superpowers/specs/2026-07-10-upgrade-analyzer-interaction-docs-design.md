# 升级分析 Skill 交互与文档体验设计

## 问题定义

当前工程已经具备较完整的分析能力，但用户体验仍然割裂。用户在运行过程中会看到控制台输出、checkpoint 问题、`.upgrade-report/` 产物、最终报告和工程文档。它们表达的是同一条分析链路，但目前没有统一成一套面向使用者的阅读和决策路径。

典型问题包括：

- 程序知道候选对象，但没有把候选对象变成用户能直接选择的任务。
- checkpoint 暴露了较多内部字段，用户难以判断应该如何回复。
- `.upgrade-report/` 中用户文件、深排查证据和程序文件已经分层，但部分文档和输出仍没有明确告诉用户先看哪里、为什么看、看完做什么判断。
- 最终报告容易被误解为处置建议。报告应客观提供分析结果、证据和限制，不应替用户决定修改或验证动作。

本设计把问题定义为端到端体验问题，而不是单个 Step 的文案问题。

## 目标

本次设计覆盖两条主线：

1. 运行时交互体验
   - 首轮输入要让用户知道需要提供什么。
   - 每个 checkpoint 要让用户知道为什么停下、有哪些可选动作、每个动作需要什么输入。
   - 候选对象要按用户能理解和操作的粒度展示。
   - Agent 转述时要把程序结构化信息转换成可直接回复的问题。

2. 落地文档和产物体验
   - 工程文档要区分用户入口、深排查指南、程序/维护文档。
   - `.upgrade-report/` 产物要区分交付报告、复核证据和运行时状态。
   - 用户可见文件第一屏要说明本文件回答什么问题、当前结果是什么、下一步看哪里。
   - 最终报告只呈现客观分析结果、证据和结论限制。

## 非目标

本设计不改变分析结论语义。

本设计不要求减少分析范围、跳过证据或用抽样替代完整台账。

本设计不把最终报告改成修复建议或测试建议。报告只说明“分析发现了什么、证据是什么、哪些地方不能确认”。

本设计不要求用户从 API 级明细中选择 Step5 范围。API 级文件仍保留为事实明细和深排查证据。

运行时 checkpoint 可以给出“推荐默认动作”，因为 checkpoint 的目标是恢复流程。最终报告不能给处置建议；最终报告只能提供证据导航，例如“对应证据见哪个文件”。

## 目标读者

主流程优先服务业务研发和应用负责人。他们关心：

- 本次分析覆盖了什么范围。
- 哪些依赖和 API 有变化。
- 当前系统是否有证据触达这些变化。
- 哪些结果已经确认，哪些结果缺少材料。
- 需要查看哪些证据才能做自己的判断。

工具操作者和维护者是第二层读者。他们关心：

- 每个 Step 如何恢复、重跑和排障。
- 程序状态和证据文件如何对应。
- Agent 应该如何转述 checkpoint。
- 哪些输出供程序使用，哪些输出供人复核。

## 文档分层

工程文档分为三类。

| 类型 | 读者 | 文件 | 作用 |
|---|---|---|---|
| 用户入口文档 | 业务研发、应用负责人 | `README.md`, `docs/user/outputs.md` | 说明如何运行、如何阅读结果、如何理解结论 |
| 深排查文档 | 工具操作者、高级复核人 | `RUNBOOK.md`, `docs/user/outputs.md` 的深排查章节 | 说明如何定位证据、恢复 checkpoint、重跑步骤 |
| 程序/维护文档 | Agent、维护者 | `SKILL.md`, `docs/developer/*` | 说明状态机、字段契约、实现约束和质量门禁 |

文档之间必须形成清晰路径：

```text
README.md
  -> docs/user/outputs.md
  -> deliverables/report.md
  -> evidence/* 深排查证据
  -> RUNBOOK.md 或 docs/developer/* 维护说明
```

`SKILL.md` 是 Agent 执行协议，不应作为普通用户理解结论的入口。

## `.upgrade-report/` 产物分层

`.upgrade-report/` 中的文件按读者分层。

```text
.upgrade-report/
  deliverables/  # 用户和评审优先阅读
  evidence/      # 深入复核证据
  .runtime/      # 程序和 Agent 使用
```

### `deliverables/`

`deliverables/` 只放面向人阅读的交付结果。

`deliverables/report.md` 的职责是客观呈现：

- 本次分析范围；
- 结果分组；
- 证据摘要；
- 结论限制；
- 附录文件索引。

`deliverables/report.md` 不输出：

- 修改建议；
- 测试建议；
- 发布建议；
- 处置优先级建议。

这些动作由用户基于分析结果自行判断。

### `evidence/`

`evidence/` 放可复核证据。用户只有在需要核对结论、解释差异或继续排查时才进入这一层。

`evidence/api_changes/` 应同时提供两种视图：

| 文件 | 粒度 | 读者用途 |
|---|---|---|
| `changed_dependencies.md` | 依赖包 | Step4 后选择 Step5 分析范围 |
| `changed_dependencies.csv` | 依赖包 | 自动化、筛选、批量处理 |
| `all_changed_apis.csv` | API | 完整 API 变化事实集合 |
| `all_changed_apis_part_*.csv` | API | 大文件拆分阅读 |
| `s4_per_dependency/<coord>/` | 单依赖包 | 单个依赖包的 API 变化和后续 Step5 汇总 |

`evidence/call_chain/alerts.csv` 保持完整链路台账，不变成样例或抽样。

### `.runtime/`

`.runtime/` 只供程序和 Agent 使用。普通用户不应被要求先阅读 `.runtime/` 才能理解结论。

如果用户可见文档引用 `.runtime/`，必须说明该文件用于恢复、排障或程序判断，而不是人工结论入口。

## 用户可见文件首屏规范

所有用户可见文件第一屏应回答五个问题：

1. 这个文件回答什么问题。
2. 本文件覆盖什么范围。
3. 当前结果摘要是什么。
4. 如果要继续复核，下一步看哪里。
5. 完整明细在哪里。

示例结构：

```text
# 文件标题

本文件回答：...
分析范围：...
当前结果：...
优先阅读：...
完整明细：...
```

CSV 文件无法放长说明时，应提供相邻 Markdown 说明文件。例如 `changed_dependencies.csv` 应配套 `changed_dependencies.md`。

## 运行时交互规范

每个 checkpoint 都输出一张“决策卡片”。决策卡片面向用户，不面向内部实现。

固定结构：

```text
当前需要确认什么
为什么现在停下
推荐默认动作
其他可选动作
候选对象列表
完整候选文件
用户可以直接怎么回复
```

checkpoint 可以继续保留结构化字段，例如 `response_schema`、`action_requirements`、`selection_resolution`。但 Agent 转述时不应直接把这些字段名作为主内容展示给用户。

## Agent 转述规范

Agent 读取 `interaction.json` 后，应按用户问题组织回复。

推荐格式：

```text
当前停在：StepX
需要你确认：...

推荐动作：...

你可以选择：
- ...
- ...
- ...

候选对象：
| 选择值 | 对象 | 数量 | 说明 |

完整候选见：...

你可以直接回复：
- “全量继续”
- “只分析 coord:xxx 和 coord:yyy”
- “我补充依赖源码目录 /path/to/repo 后重跑”
```

Agent 不应把下面内容作为普通用户的主信息：

- `action_requirements`;
- `at_least_one_of`;
- `selection_resolution`;
- `input_normalization`;
- `response_schema`;
- `runtime_rules`。

这些字段仍可用于 Agent 构造恢复命令。

## Step 级交互设计

每个 Step 定义同一组信息：

- 用户问题；
- 用户可见输出；
- 深排查输出；
- 程序输出；
- checkpoint 触发条件；
- checkpoint 展示模板；
- 用户可直接回复的样例。

### Step1：确定分析对象

用户问题：

```text
要分析哪个系统、哪个模块、哪两个版本或产物？
```

用户可见输出：

- `evidence/dependencies/dep_summary.txt`;
- `evidence/dependencies/dep_changes.csv`;
- `evidence/dependencies/dep_alerts.csv`。

checkpoint 应说明：

- 缺少哪个输入；
- 为什么这个输入会影响后续分析；
- 用户可以提供哪几种等价输入；
- 每种输入方式的后果。

### Step2：确认上下文

用户问题：

```text
这次升级涉及哪些 JDK、Spring、依赖和源码范围？
```

用户可见输出：

- `evidence/context/context.json` 的人类摘要；
- `evidence/context/dep_graph.json` 的深排查入口。

checkpoint 应说明上下文字段缺失会影响哪些后续 Step。

### Step3：背景风险扫描

用户问题：

```text
除依赖 API 变化外，JDK、Jakarta、Spring 等升级是否留下背景风险线索？
```

Step3 输出是背景线索，不直接证明当前系统受影响。用户文档必须明确这一点。

### Step4：依赖 API 变化事实

用户问题：

```text
哪些依赖包发生了可复核的 API 变化？
```

Step4 后进入 Step5 前，用户选择范围的主入口必须是依赖包维度。

新增或强化文件：

```text
evidence/api_changes/changed_dependencies.md
evidence/api_changes/changed_dependencies.csv
```

`changed_dependencies.md` 示例：

```text
# 发生 API 变化的依赖包

本文件回答：哪些依赖包有 API 变化，是否要进入 Step5 调用链分析。
完整 API 明细：all_changed_apis.csv

| 选择值 | 依赖包 | 变化 API 数 | 高风险 API 数 | 主要变化类型 | 明细 |
|---|---|---:|---:|---|---|
| `coord:com.foo:a` | `com.foo:a` | 128 | 12 | removed, signature_changed | `s4_per_dependency/.../summary.json` |
| `coord:com.foo:b` | `com.foo:b` | 8 | 1 | behavior_changed | `s4_per_dependency/.../summary.json` |
```

Step4 checkpoint 示例：

```text
当前需要确认：Step5 是全量分析，还是只分析部分依赖包？

推荐动作：
- 依赖包较少时，选择“全量继续”。
- 依赖包很多时，从下表选择一个或多个依赖包。
- 如果缺少依赖源码，先补 dependency_source_dirs 后重跑。

可选依赖包：
| 选择值 | 依赖包 | 变化 API 数 | 高风险 API 数 |
|---|---|---:|---:|
| `coord:com.foo:a` | `com.foo:a` | 128 | 12 |
| `coord:com.foo:b` | `com.foo:b` | 8 | 1 |

完整候选：evidence/api_changes/changed_dependencies.md
API 明细：evidence/api_changes/all_changed_apis.csv

你可以直接回复：
- “全量继续”
- “只分析 coord:com.foo:a”
- “只分析 coord:com.foo:a 和 coord:com.foo:b”
- “我补充依赖源码目录 /path/to/repo 后重跑”
```

API 维度文件 `all_changed_apis.csv` 只作为完整事实集合和深排查入口，不作为普通选择入口。

### Step5：调用链影响分析

用户问题：

```text
这些依赖 API 变化是否有证据触达当前系统？
```

用户可见输出：

- `evidence/call_chain/summary.txt`;
- `evidence/call_chain/alerts.csv`;
- `evidence/call_chain/alerts_*.csv`。

Step5 checkpoint 应客观说明：

- 哪些项已经有证据；
- 哪些项缺少材料；
- 缺少的材料是什么；
- 用户补材料后会重跑什么范围。

不应输出笼统表述，例如“当前没有已闭环确认影响”。应改为明确说法：

```text
当前没有找到“当前系统代码或当前构建产物触达这些变更 API”的证据。
其中 12 项缺少依赖源码或构建产物，无法完成回溯。
```

### Step6：最终报告

用户问题：

```text
本次分析客观发现了什么？哪些结论有证据，哪些结论有限制？
```

报告结构：

1. 核心结论；
2. 结论限制；
3. 分析结果总表；
4. 附录。

报告不输出处置建议。报告可以提供证据入口，但不替用户判断下一步动作。

## 结果术语规范

用户可见术语固定为：

| 术语 | 含义 |
|---|---|
| 已确认影响 | 找到当前系统代码或当前构建产物触达变更 API 的证据 |
| 可能影响 | 有候选证据，但不足以确认完整链路 |
| 已确认不受影响 | 当前制品证据显示 API 未实际消失或变更不影响该调用 |
| 未发现静态调用路径 | 已完成当前静态分析范围，但没有找到调用路径 |
| 未完成分析 | 缺少输入、工具能力或证据，导致该项不能完成分析 |

禁止在用户可见输出中使用未解释的内部状态替代这些术语。

## 验证计划

实现时需要验证两类结果。

### 功能验证

- Step4 生成 `changed_dependencies.md` 和 `changed_dependencies.csv`。
- Step4 checkpoint 的 `selection_options` 使用依赖包维度。
- 用户通过依赖包选择后，Step5 只分析对应依赖包的 API。
- `all_changed_apis.csv` 保持完整，不被依赖包视图替代。
- Step6 报告不输出修改、测试或发布建议。

### 体验验证

- 每个 checkpoint 都有明确问题、推荐动作、可选动作和可直接回复示例。
- 用户从 `README.md` 能找到 `.upgrade-report/` 阅读入口。
- 用户从 `docs/user/outputs.md` 能理解 `deliverables/`、`evidence/`、`.runtime/` 的区别。
- 用户打开 `deliverables/report.md` 第一屏能知道本次分析范围、当前结果和证据入口。
- 用户不需要阅读 `.runtime/` 才能理解分析结论。

### 回归测试

至少增加以下测试：

- Step4 依赖包维度候选生成测试；
- Step4 checkpoint 文案和 `selection_options` 测试；
- `selected_targets` 选择依赖包后过滤 Step5 输入的测试；
- Step6 报告不包含处置建议类固定词的测试；
- docs/user 输出指南包含三层产物说明的测试或快照检查。

## 风险与取舍

依赖包维度选择会牺牲 API 级精细控制，但更符合普通用户选择范围的方式。API 级控制可以保留给深排查或高级参数，但不作为主交互入口。

更强的 checkpoint 文案会增加输出长度。设计上应把主问题、推荐动作和候选表放前面，把内部恢复协议留给 JSON 字段和 Agent 使用。

最终报告不写建议可能让部分用户希望看到“下一步怎么做”。这是刻意取舍：报告是客观分析结果，不是改造方案。用户或 Agent 可以基于报告另起任务生成处置计划，但该计划不属于 Step6 报告。

## 完成标准

本设计完成后，用户应能做到：

- 在首次运行前知道需要准备哪些输入。
- 在每个 checkpoint 知道为什么停、能选什么、如何直接回复。
- 在 Step4 后按依赖包选择 Step5 范围，而不是从大量 API 行中挑选。
- 在 `.upgrade-report/` 中区分交付报告、复核证据和程序状态。
- 阅读最终报告时获得客观分析结果、证据和限制，而不是被工具替代决策。
