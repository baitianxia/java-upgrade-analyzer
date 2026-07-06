# 测试策略与质量门禁

本工程的核心风险不是“脚本是否能跑完”，而是升级影响结论是否可信。测试必须同时覆盖：

- 漏报：真实受影响链路没有被发现。
- 误报：无关 API、无关依赖或同名符号被错误归入影响范围。
- 降级语义：分析能力不足时必须输出 `uncertain` 或 `not_analyzed`，不能伪装成 `not_found_in_static_analysis`。
- 人工复核：输出文件必须保留足够证据，不能只给摘要样例。

## 必跑质量门禁

推荐优先使用统一质量门入口：

```bash
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
```

只想查看会执行哪些命令时使用：

```bash
python3 scripts/quality_gate.py --profile release --dry-run
```

高风险准确性契约也可以单独按矩阵执行：

```bash
python3 scripts/accuracy_benchmark.py --profile core
python3 scripts/accuracy_benchmark.py --profile step5
python3 scripts/accuracy_benchmark.py --profile all
```

`accuracy_benchmark.py` 把历史上反复出问题的能力点显式分组，包括 `jdeps` 对照、运行时依赖字节码链路、反射/MethodHandle、owner/import/signature 精度、`alerts.csv` 完整台账和 Step6 汇总结论。它不是替代真实项目测试，而是防止已知准确性合同在后续修改中退化。

质量风险矩阵见 `QUALITY_RISK_MATRIX.md`。真实项目矩阵即使 `passed`，也必须关注 `non_gating_production_missing`、`not_analyzed`、`uncertain` 和 skipped 等质量信号：

```bash
python3 scripts/real_project_regression.py --case all --json-out /private/tmp/jua-real/result.json
python3 scripts/quality_signal_audit.py /private/tmp/jua-real/result.json
```

每次修改分析逻辑后至少执行 quick 或等价命令：

```bash
python3 scripts/accuracy_benchmark.py --profile core
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/smoke_regression.py --group core
python3 scripts/smoke_regression.py --group step5
python3 -m py_compile scripts/*.py
git diff --check
```

涉及 Step4 或 Step5 时，应额外执行对应局部测试：

```bash
python3 scripts/quality_gate.py --profile step5
python3 -m unittest tests.test_step4_stability
python3 -m unittest tests.test_step5_key_matching tests.test_business_bytecode_graph tests.test_artifact_bytecode_catalog tests.test_indirect_usage_analyzer
```

## 修复准入：先分析，再改代码

每个修复都必须先写清楚“为什么这个修复是合理的”，不能为了某个真实项目或某个单点样例临时放宽规则。修复前至少确认：

- Java 语义是否成立：例如 varargs、装箱、继承、重载、静态 import、字段访问是否符合编译期规则。
- 适用边界是否明确：该规则适用于哪些 owner、签名、表达式形态；哪些情况必须继续保持 `uncertain` / `not_analyzed`。
- 是否会引入误报：特别是同名不同 owner、同名不同重载、raw key fallback、简单名 import 冲突。
- 是否有正反成对回归：新增命中能力时，必须同时覆盖“应该命中”和“不应该命中”。
- 是否经过真实项目验证：Step5/字节码/输出语义相关修复，至少跑一个真实项目；高风险修复应跑 `--case all`。

禁止把以下做法作为修复：

- 为了让某个 API reachable，直接把 raw key 全部归入目标签名。
- 在有多个重载时，因为名字相同就判定命中。
- 因为真实项目 grep 有结果，就忽略签名、owner 或 test/prod 区分。
- 把能力不足伪装成 `not_found_in_static_analysis`。

## 测试分层：不要只跑几个场景

测试按风险分层执行，不能用少量单测替代大范围验证：

| 层级 | 执行时机 | 命令/方式 | 目标 |
|---|---|---|---|
| L0 精准回归 | 每次局部修改后立即执行 | 相关 `unittest` 单例或单文件 | 快速验证刚修的正反例 |
| L1 准确性基准矩阵 | 修改 Step4/Step5 逻辑后执行 | `python3 scripts/accuracy_benchmark.py --profile step5` | 按风险类别验证已知高危准确性契约 |
| L2 Step 相关回归 | 修改 Step4/Step5 逻辑后执行 | `tests.test_step5_key_matching`、`test_business_bytecode_graph`、`test_artifact_bytecode_catalog`、`test_indirect_usage_analyzer` | 覆盖签名、owner、字节码、间接调用 |
| L3 Smoke | 修改分析主流程后执行 | `smoke_regression.py --group core` 和 `--group step5` | 防止主流程和输出合同破坏 |
| L4 全量单测 | 较大逻辑调整或提交前执行 | `python3 -m unittest discover -s tests -p 'test_*.py'` | 防止跨步骤回归 |
| L5 真实项目矩阵 | Step5 准确性/输出语义/性能相关修改后执行 | `python3 scripts/real_project_regression.py --case all` | 用真实项目发现解析边界和误报/漏报 |
| L6 质量信号审计 | 真实项目矩阵执行后 | `python3 scripts/quality_signal_audit.py result.json` | 防止 passed 掩盖 non-gating miss、not_analyzed、skipped |

如果 L5/L6 每次都发现新问题，说明当前测试矩阵仍不充分，应优先扩充真实项目探针和最小 fixture，而不是继续局部修补。

## 正例和负例必须成对

新增一种命中能力时，必须同时增加“应该命中”和“不应误报”的测试。

| 能力点 | 正例：应该命中 | 负例：不应误报 |
|---|---|---|
| Step4 JApiCmp XML | 当前 jar 顶层类型/成员变化 | 嵌套 interface/annotation、JDK 标准类型、第三方噪声类型 |
| Step5 方法调用 | 签名精确或可安全 assignable | 同名不同签名、同名不同 owner、fallback simple-only |
| Step5 字段访问 | import/static import/FQCN 指向目标 owner | 简单名相同但 import 指向其他 owner |
| Step5 跨依赖字节码 | 业务可回溯到命中依赖 | 依赖命中但没有业务入口，或业务只连到无关分支 |
| Step1 依赖配对 | 完整坐标或唯一迁移可确认 | 同 artifactId 不同 group 的歧义配对 |
| 输出台账 | 每条唯一有效链路有完整 path/evidence，重复命中通过 occurrence count 表达 | 只输出抽样、轻量索引、缺少消费方，或把不同入口链路错误合并 |

## 高风险回归池

以下场景属于必须长期保留的回归池：

- JApiCmp XML 中的 `java.io.Serializable`、`java.lang.Comparable`、`java.lang.annotation.Annotation` 不得进入 `all_changed_apis.csv`。
- `StringUtils.EMPTY` 必须校验 import owner；`org.apache.commons.lang3.StringUtils.EMPTY` 不得误归到 `io.seata.common.StringUtils.EMPTY`。
- `String` 实参可以安全匹配 `CharSequence` 形参，但不能放宽成任意同名重载。
- `business -> dep-a -> dep-b -> changed API` 必须能输出完整链路；未回到业务入口时只能是 `uncertain`。
- alerts 拆分文件只能作为阅读视图，不能替代完整 `alerts.csv`。

## 真实项目验证

单元测试不能替代真实项目验证。涉及调用链准确性、字节码扫描或输出语义时，建议至少选一个真实 Maven 项目做探针：

- 选择真实项目源码作为系统工程。
- 人工构造小的 `all_changed_apis.csv`，模拟 Step4 输出。
- 运行 Step5，检查 `summary.txt`、`summary.json`、`alerts.csv`、`alerts_<status>.csv`。
- 将发现的问题固化为最小 fixture 回归，而不是只保留一次性运行记录。

本仓库提供一个非 CI 的真实项目回归入口，用于本地已有真实项目源码时执行：

```bash
python3 scripts/real_project_regression.py --case all
python3 scripts/real_project_regression.py --case commons-text
python3 scripts/real_project_regression.py --case dubbo
python3 scripts/real_project_regression.py --case seata
```

该脚本会：

- 复用真实项目源码运行 Step5，并记录耗时、summary 和报告目录。
- 对选定 API 做 production/test baseline 对照，production 缺失才作为门控失败。
- 将无法由简单 grep 区分重载的检查标记为非门控，只用于人工观察，不能据此宣称实现漏报。
- 在本地缺少真实项目或探针 CSV 时输出 `skipped`，不替代单元测试和 smoke。

已使用过的真实项目探针：

- Apache Commons Text：验证 `commons-lang3` 方法/字段引用、assignable 签名和字段 import owner。
- Apache Dubbo：验证大型多模块项目中的 `StringUtils`、`CollectionUtils`、`URL`、`NetUtils` 调用链和重载安全。
- Apache Seata：验证 `StringUtils` 字段/方法、单签名 raw 调用保留、生产源码与测试源码区分。

## 结论口径

测试结论必须明确区分：

- “已验证通过”：有自动化测试或 smoke 证据。
- “当前未覆盖”：尚无测试，不应宣称安全。
- “能力缺口”：实现目前做不到，应记录为 TODO 或输出 `not_analyzed`。

不要把“没有发现问题”写成“没有问题”。
