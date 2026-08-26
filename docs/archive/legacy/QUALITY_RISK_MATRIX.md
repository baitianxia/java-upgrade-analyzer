# 质量风险矩阵：降低缺陷密度的工程规则

当前目标不是承诺零 bug，而是把“每轮真实测试都能发现 bug”的状态降下来。判断标准不再是单次 `passed`，而是每个历史缺陷模式是否已经变成可执行的覆盖合同。

## 1. 缺陷模式归类

| 缺陷模式 | 典型表现 | 风险 | 必须覆盖的测试 |
|---|---|---|---|
| owner 解析错误 | 同名 `StringUtils` / `EMPTY` 被归到错误包 | 误报或漏报 | import、static import、wildcard import、same package 的正反例 |
| signature 丢失 | `char[]` 变成 `char`，`Object...` 变成不兼容签名 | 漏报真实调用或错误 `not_analyzed` | primitive/object array、varargs、泛型、修饰符参数 |
| overload 误配 | 只按方法名命中错误重载 | 高危误报 | 精确签名、compatible 签名、wrong overload 负例 |
| 字节码链路缺失 | `business -> depA -> depB -> changed API` 没发现 | 高危漏报 | 二跳/三跳、字段、wrong overload、unconnected dependency hit |
| 间接调用漏扫 | 反射、MethodHandle、表达式语言未关联 Step4 API | 漏报 | exact reflection、dynamic member uncertain、MethodHandle、resource/expression |
| 输出台账不完整 | `alerts.csv` 只输出样例或吞掉不同入口链路 | 影响人工复核 | 完整链路、后缀路径合并、不同入口保留、拆分文件 |
| Step4 噪声污染 | JApiCmp 把 JDK 标准类当目标 API | 大量误报 | JDK 类型过滤、目标 artifact owner 校验 |
| 真实项目信号被忽略 | `passed` 但存在 non-gating prod_missing / not_analyzed | 缺陷长期潜伏 | `quality_signal_audit.py` 审计 |

## 2. 修复准入升级

任何准确性修复必须同时满足：

- 修复前能用最小 fixture 复现。
- 修复后至少有一个正例和一个不扩大误报的负例；若暂时缺负例，必须记录原因。
- 如果来自真实项目，必须重新跑对应真实项目 case。
- 如果属于上表缺陷模式，必须加入 `accuracy_benchmark.py`。
- 真实项目即使 `passed`，也要审计 `non_gating_production_missing`、`not_analyzed`、`uncertain` 和 skipped。

## 3. 真实项目通过不等于健康

`real_project_regression.py --case all` 的 `passed` 只表示 gating baseline 未失败。以下情况仍然要作为质量信号处理：

- `summary.not_analyzed > 0`
- `summary.uncertain > 0`
- `summary.not_found_in_static_analysis > 0`
- `gating=false` 且 `production_missing > 0`
- case 被 `skipped`

推荐固定执行：

```bash
python3 scripts/real_project_regression.py --case all \
  --report-root /private/tmp/jua-real-regression \
  --json-out /private/tmp/jua-real-regression/result.json

python3 scripts/quality_signal_audit.py /private/tmp/jua-real-regression/result.json
```

需要把所有可疑信号都当失败时：

```bash
python3 scripts/quality_signal_audit.py /private/tmp/jua-real-regression/result.json --strict
```

只把 skipped 或 gating 失败等高危信号当失败时：

```bash
python3 scripts/quality_signal_audit.py /private/tmp/jua-real-regression/result.json --fail-on-high
```

## 4. 退出“每轮都发现新 bug”的标准

短期内不以“没有发现问题”作为成功，而以趋势作为成功：

- 连续多轮真实项目矩阵不再发现新的缺陷模式。
- 新发现的问题能归入已有缺陷模式，而不是全新盲区。
- `non_gating_production_missing` 都有明确解释，并逐步升级为更精确的 gating probe。
- `not_analyzed` 和 `uncertain` 的数量有稳定基线，任何漂移都有解释。
- 每次真实 bug 都进入 accuracy benchmark 或 smoke，不再只停留在一次性运行记录。
