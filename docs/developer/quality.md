# 质量门禁与测试策略

本文面向维护者，定义本工程修改代码时必须遵守的质量要求。

修改代码前应先阅读 [工程宪法](constitution.md)。本文中的测试策略和质量门禁都服务于工程宪法，不得用“测试通过”替代对原则性约束的判断。

## 基本原则

准确性优先于性能。

性能优化只能减少重复计算、降低内存峰值或改善索引结构，不能降低分析覆盖面或改变结论语义。

任何修复都不能只为了一个单一场景硬编码；修复前必须判断它是否符合整体分析模型。

## 修改准入

修复或优化前先回答：

1. 这个问题属于漏报、误报、性能、可读性还是交互问题；
2. 影响哪个 Step；
3. 是否会改变正式输出契约；
4. 是否可能影响 Step5 五态语义；
5. 是否需要新增正例和负例；
6. 是否需要真实项目或压力模型验证。

## 常用质量门

快速检查：

```bash
python3 scripts/quality_gate.py --profile quick
```

Step5 相关修改：

```bash
python3 scripts/quality_gate.py --profile step5
```

发布或重要提交前：

```bash
python3 scripts/quality_gate.py --profile release
```

完整 unittest：

```bash
python3 -m unittest discover -s tests -v
```

准确性基准：

```bash
python3 scripts/accuracy_benchmark.py --profile core
python3 scripts/accuracy_benchmark.py --profile step5
python3 scripts/accuracy_benchmark.py --profile all
```

Smoke：

```bash
python3 scripts/smoke_regression.py
python3 scripts/smoke_regression.py --group core
python3 scripts/smoke_regression.py --group step5
python3 scripts/smoke_regression.py --group orchestrator
```

## 必须守住的语义

### Step1

- 以真实构建结果或用户提供的构建产物为准；
- 多模块项目必须明确目标部署模块；
- 不得用不完整 dependency tree 替代正式产物事实；
- 无法安全解析的坐标必须显式进入交互或 unresolved。

### Step4

- `all_changed_apis.csv` 是 Step5 的正式输入；
- JApiCmp XML/文本、git diff、removed jar symbol export 都应保留可追溯证据；
- JDK 标准类、第三方无关类不能误归入目标依赖 API 变化；
- removed jar 场景必须导出旧版 public/protected 符号。

### Step5

- 不得漏掉 jdeps 能发现的跨 JAR 类依赖；
- 删除依赖、升级依赖、字段变化、构造器变化、多依赖链路都要覆盖；
- 反射、MethodHandle、资源、表达式语言不能静默当成未命中；
- `reachable` / `not_impacted` / `uncertain` / `not_found_in_static_analysis` / `not_analyzed` 语义不能混淆；`not_impacted` 必须有当前制品中的相同类字节码证据；
- `alerts.csv` 必须是完整链路台账，不是样例；
- 性能优化不能通过减少分析范围实现。
- 重载匹配必须同时校验全限定类名和参数描述符；最终制品已完整扫描且精确描述符未命中时，不得被无签名别名阻塞为 `not_analyzed`。
- 不得把具有方法体的接口 `static` / `default` / `private` 方法当成动态代理边界。

### Step6

- 主报告应面向阅读者表达结论；
- 大量明细应进入附属文件，避免 Markdown 预览器被大量标题和长列表拖垮；
- `s6_findings.json` 保持结构化消费能力。

## 测试分层

| 层级 | 目的 |
|---|---|
| 单元测试 | 验证具体函数和边界行为 |
| 契约测试 | 验证跨 Step 输入输出语义 |
| 准确性基准 | 验证高风险分析能力不退化 |
| Smoke | 验证主流程可跑通 |
| 压力模型 | 验证大 API、大依赖、大边数下的复杂度 |
| 真实项目验证 | 验证工程化输入和真实依赖结构 |

## 正例和负例

每个能力增强都应尽量成对补测试：

- 正例：应该命中；
- 负例：相似但不应该命中；
- 边界例：输入不完整时应该进入 `uncertain` 或 `not_analyzed`，不能误判为无影响。

示例：

- commons-lang 被删除，业务直接调用：应 reachable；
- commons-lang 被删除，运行时依赖调用但无法回业务：应 uncertain；
- 同名 `StringUtils.EMPTY` 来自 commons-lang3，不应误报 commons-lang；
- JApiCmp 输出中的 JDK 标准接口不应误归为目标依赖 API。

## 性能验证

性能问题不能只靠真实项目暴露。

应主动构造压力模型：

- API 数量大；
- 运行时依赖 JAR 多；
- reverse edges 多；
- 多依赖链路深；
- 反射/MethodHandle 候选多；
- class/field 变化多。

每次执行真实项目矩阵时，性能也必须作为质量信号审计。超过 Step4/Step5 配置预算、图规模异常下降、边截断、edge cap 命中，都不能只作为日志观察；其中耗时超预算应输出 `performance_regression`，P1 阻塞 release。性能优化只能降低重复计算和资源消耗，不能通过缩小分析范围换取通过。

Step4 性能验证优先看：

```text
evidence/api_changes/step4_timing.csv
```

关键阶段：

- `artifact_resolve`;
- `dependency.gitdiff`;
- `dependency.japicmp`;
- `dependency.removed_jar_export`;
- `dependency.changed_classes`;
- `dependencies.process_all`;
- `write.*`。

Step5 性能验证优先看：

```text
evidence/call_chain/step5_timing.csv
```

关键指标：

- `main.indirect_usage_potential_legacy_method_target_pairs`;
- `main.indirect_usage_owner_presence_scans`;
- `bytecode_scan.elapsed_sec`;
- `bytecode_expand.elapsed_sec`;
- `trace.incoming_edges_scanned`;
- `trace.declared_signature_index_elapsed_sec`;
- `trace.direct_class_usage_elapsed_sec`;
- `trace.direct_field_usage_elapsed_sec`;
- `report.elapsed_sec`。

## 真实项目验证口径

真实项目验证不能只证明“能跑完”。

项目规模不能替代测试覆盖率。真实项目 case 必须声明生命周期：

- `discovery`：Step4 产生的 API 必须 100% 进入 Step5；
- `convergence`：保持全量覆盖，同时把 P0/P1 问题沉淀为 fixture；
- `guard`：只运行已声明的代表性探针，输出不得暗示项目级全量覆盖。

每次运行必须分别通过五类门禁：

- 覆盖门禁：记录 API population、selected、accounted 和 coverage ratio；
- 证据门禁：区分缺运行时 jar、缺源码映射、测试配置错误和真实外部缺失；
- 结论门禁：按 reason code 与 symbol kind 分组 `not_analyzed`，不得压成一条模糊汇总；
- 真值门禁：没有 reviewed ground truth 的探索结果只能是 `observed`，不能宣称准确性通过；
- 性能门禁：同时约束绝对耗时、每千 API 耗时、候选配对总数与每 API 配对数。

runner 状态必须由质量信号派生。存在 blocking signal 时状态必须为 `failed`；
只有 ground truth 尚未完成且没有其他阻断时才是 `observed`；独立 audit 的发布决定
不得与 runner 文本状态冲突。

至少应记录：

- 项目规模；
- 依赖数量；
- API 变化数量；
- Step1~Step6 每步耗时；
- reachable / uncertain / not_found / not_analyzed 分布；
- 随机抽样复核结果；
- 与 jdeps 或人工预期不一致的差异。

误报与漏报复核应使用稳定哈希做分层抽样，至少覆盖结论状态、symbol kind、
reason code、源码/字节码/反射证据模式以及 production/test 分类。宽泛 grep 只能用来
发现候选，不能作为 owner 或重载签名精度的最终真值。

如果每轮真实项目测试都发现新问题，说明测试矩阵仍不足，应继续补充针对性测试和压力模型。

真实项目矩阵必须按“发现池”而不是“固定纪念碑”维护。每次执行真实项目测试时都要遵守：

- 探索期项目用于发现未知问题；
- 收敛期项目必须把 P0/P1 findings 转成 L0/L1/L2 fixture；
- 守护期项目只保留少量代表性 probe；
- 当一个项目的问题都已沉淀且不再发现新信号时，应把主要发现预算轮换到更适合暴露未知问题的新工程。

优先轮换到能覆盖当前能力边界的工程，例如 Spring Boot 2 到 3、Jakarta 迁移、多模块应用、annotation processor、SPI、反射、动态代理、fat jar、shaded jar、nested jar、Kotlin/Groovy 混合 Java、复杂 Maven 依赖管理等。

真实项目测试必须先校验测试资产本身。若项目不是有效 Git checkout、源码规模低于 case 假设，或 `target/generated-sources` 占比异常高，应输出 `project_asset_invalid` 并阻塞 release，不能继续跑 Step4/Step5 后把资产问题误归因成 analyzer 能力缺口。

## Fixture Debt

每个 P0/P1 真实项目质量信号都必须进入以下状态之一：

- 已沉淀为 L0/L1/L2 回归测试；
- 已记录为 planned，并写清楚目标 fixture 形态；
- 已 waived，并写清楚原因和过期时间。

Release 门禁会统计 blocking signal 中尚未沉淀的 `fixture_debt`。不能让真实项目反复发现同一类问题，却只保留一次性运行记录。

## 打包前最低要求

打包给使用者验证前至少执行：

```bash
python3 scripts/quality_gate.py --profile quick
```

如果改动涉及 Step5、Step4 或输出文件语义，至少再执行相关定向测试或 `step5` profile。

打包文件应排除：

- `.git/`;
- `.idea/`;
- `.upgrade-report/`;
- `__pycache__/`;
- `.pytest_cache/`;
- 历史 zip；
- 临时日志。
