# Step5 Binary Trace 设计

Step5 不再构建独立的源码优先调用图。它从 Step4 已独立验证并激活的同一 binary generation 发布系统触达结果；正式实现为 `binary_trace_engine.py`，用户视图由 `binary_report.py` 发布。

## 输入边界

- 当前 target runtime 的有效 class/member provider；
- Step4 冻结的 targetable change facts；
- 业务入口 profile；
- loader realm、描述符、dispatch 和 coverage；
- 可选 source overlay，只补充位置与解释。

Step5 不读取旧版 API CSV 来重建事实。`all_changed_apis.csv` 只用于用户范围选择和外部兼容消费，generation 中的正式 identity 才是 trace 输入。

## 图与路径

节点和边使用 owner、member、JVM descriptor、loader realm 和实际制品身份。不能沿裸方法名或简单类名扩展确定路径。接口/虚方法候选若不能唯一解析，进入 possible path；覆盖或预算不足则记录为不完整。

正式四态互斥：

| 状态 | 含义 |
|---|---|
| `reachable` | 在声明的静态运行闭包中发现至少一条有效路径 |
| `uncertain` | 存在候选路径，但 dispatch/provider/覆盖不足以形成精确路径 |
| `not_found_in_static_analysis` | 当前完整声明的静态范围未发现路径；不表示安全 |
| `not_analyzed` | 输入、能力或预算使该目标未完成分析 |

影响结论与 reachability 独立：没有运行时验证时只允许 `probable_impact` 或 `inconclusive`。静态分析不输出 confirmed impact/no-impact。

## 范围

Step4 范围卡以依赖坐标选择 Step5 全量或部分范围。部分范围必须把 included/excluded API identity 写入 Step5 summary；Step6 只能报告 included 范围，未选对象不能被计为无影响或未完成。

## 用户输出

- `evidence/call_chain/summary.md`：按依赖汇总四态；
- `evidence/call_chain/alerts.csv`：每个 API 的依赖、状态、路径、原因和 identity；
- `evidence/call_chain/by_api/`：逐 API 完整 JSON；
- `.runtime/indexes/s5_query_index.json`：即时查询索引，不是人工复核入口。

`alerts.csv` 必须覆盖全部纳入 API，不能只给样例。Markdown 首屏说明 `not_found_in_static_analysis` 的边界，并明确下一层明细入口。

## 失败与性能

Step5 报告只消费 validated generation。sidecar 被篡改、validation attachment 不一致或 Step5 generation 与 active pointer 不一致时失败关闭。发布使用 stage + atomic replace。

Trace 使用内容寻址 snapshot cache、有界路径数和节点预算；任何预算命中都必须反映到 coverage/`not_analyzed`，不能静默截断。Step5 发布耗时写入 `.runtime/observability/step5_timing.csv`，不参与结论身份。
