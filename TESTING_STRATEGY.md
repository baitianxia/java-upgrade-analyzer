# 测试策略与质量门禁

本工程的核心风险不是“脚本是否能跑完”，而是升级影响结论是否可信。测试必须同时覆盖：

- 漏报：真实受影响链路没有被发现。
- 误报：无关 API、无关依赖或同名符号被错误归入影响范围。
- 降级语义：分析能力不足时必须输出 `uncertain` 或 `not_analyzed`，不能伪装成 `not_found_in_static_analysis`。
- 人工复核：输出文件必须保留足够证据，不能只给摘要样例。

## 必跑质量门禁

每次修改分析逻辑后至少执行：

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/smoke_regression.py --group core
python3 scripts/smoke_regression.py --group step5
python3 -m py_compile scripts/*.py
git diff --check
```

涉及 Step4 或 Step5 时，应额外执行对应局部测试：

```bash
python3 -m unittest tests.test_step4_stability
python3 -m unittest tests.test_step5_key_matching tests.test_business_bytecode_graph tests.test_artifact_bytecode_catalog tests.test_indirect_usage_analyzer
```

## 正例和负例必须成对

新增一种命中能力时，必须同时增加“应该命中”和“不应误报”的测试。

| 能力点 | 正例：应该命中 | 负例：不应误报 |
|---|---|---|
| Step4 JApiCmp XML | 当前 jar 顶层类型/成员变化 | 嵌套 interface/annotation、JDK 标准类型、第三方噪声类型 |
| Step5 方法调用 | 签名精确或可安全 assignable | 同名不同签名、同名不同 owner、fallback simple-only |
| Step5 字段访问 | import/static import/FQCN 指向目标 owner | 简单名相同但 import 指向其他 owner |
| Step5 跨依赖字节码 | 业务可回溯到命中依赖 | 依赖命中但没有业务入口，或业务只连到无关分支 |
| Step1 依赖配对 | 完整坐标或唯一迁移可确认 | 同 artifactId 不同 group 的歧义配对 |
| 输出台账 | 每条有效链路有完整 path/evidence | 只输出抽样、轻量索引或缺少消费方 |

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

已使用过的真实项目探针：

- Apache Commons Text：验证 `commons-lang3` 方法/字段引用、assignable 签名和字段 import owner。

## 结论口径

测试结论必须明确区分：

- “已验证通过”：有自动化测试或 smoke 证据。
- “当前未覆盖”：尚无测试，不应宣称安全。
- “能力缺口”：实现目前做不到，应记录为 TODO 或输出 `not_analyzed`。

不要把“没有发现问题”写成“没有问题”。
