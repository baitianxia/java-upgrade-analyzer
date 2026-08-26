# 质量门禁与准确性契约

本 Skill 的质量目标不是“脚本跑完”，而是升级影响结论可被信任、可被复核、可被重复验证。所有 Step4/Step5/输出语义相关变更，都必须优先保护以下契约。

## 1. 不可破坏的语义契约

- `jdeps` 能发现的跨 JAR 类依赖，本 Skill 不得漏报；在此基础上，Step5 应继续提供方法/字段级证据。
- 删除依赖、升级依赖、降级依赖和迁移依赖只要在业务源码、业务字节码或运行时依赖 JAR 中命中目标符号，就不能静默输出“无影响”。
- `business -> dep-a -> dep-b -> changed API` 这类多依赖链路必须保留完整路径；如果未能回到业务入口，只能输出 `uncertain`，并指出具体命中的依赖、JAR、class 与 target。
- 性能优化不得改变四态语义：`reachable`、`uncertain`、`not_analyzed`、`not_found_in_static_analysis` 不能因为缓存、快路径或并行化而漂移。
- `alerts.csv` 是完整人工链路台账，不是样例列表；每条唯一终止链路必须独立输出，重复命中只能通过 occurrence count 合并。
- 同名简单类名或字段名必须按 owner/import/package/classpath 解析；不能因为 simple name 相同就归入目标 API。
- JApiCmp 输出里的 JDK 标准类、接口或注解噪声不能污染 Step4 目标 API 池。
- 能力不足时必须暴露为 `uncertain` 或 `not_analyzed`，不得伪装成 `not_found_in_static_analysis`。

## 2. 分层质量门

推荐统一使用：

```bash
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
```

其中准确性基准矩阵也可以单独执行：

```bash
python3 scripts/accuracy_benchmark.py --profile core
python3 scripts/accuracy_benchmark.py --profile step5
python3 scripts/accuracy_benchmark.py --profile all
python3 scripts/accuracy_benchmark.py --profile step5 --dry-run
```

`accuracy_benchmark.py` 不是新的分析逻辑，而是把高风险准确性契约显式分组：`jdeps` 对照、运行时依赖字节码链路、反射/MethodHandle、owner/import/signature 精度、`alerts.csv` 完整台账、Step6 汇总结论等。它用于防止“修了一个真实项目，却忘了保护同类问题”。

各 profile 含义：

| Profile | 适用场景 | 覆盖范围 |
|---|---|---|
| `quick` | 小范围文档/脚本调整后的快速检查 | Python 编译、核心准确性矩阵、核心语义单测、smoke core |
| `step5` | 修改 Step5、字节码、反射、alerts 或调用链时 | Python 编译、Step5 准确性矩阵、Step5 相关单测、smoke core/step5、可选真实项目矩阵 |
| `release` | 打包给真实工程测试或提交重要变更前 | Python 编译、完整准确性矩阵、完整单测、smoke all、真实项目矩阵、`git diff --check` |

如果本地没有真实项目缓存，可临时使用：

```bash
python3 scripts/quality_gate.py --profile step5 --skip-real
```

但这只能说明“真实项目矩阵未覆盖”，不能宣称真实场景安全。

真实项目矩阵执行后，还应审计“通过但可疑”的质量信号：

```bash
python3 scripts/real_project_regression.py --case all \
  --json-out /private/tmp/jua-real/result.json
python3 scripts/quality_signal_audit.py /private/tmp/jua-real/result.json
```

`quality_signal_audit.py` 会显式列出 skipped、`not_analyzed`、`uncertain`、`not_found_in_static_analysis` 与 non-gating production missing。需要把这些信号作为失败处理时，可使用 `--strict` 或 `--fail-on-high`。

## 3. 真实项目矩阵基线

真实项目矩阵至少记录：

- `reachable / uncertain / not_analyzed / not_found_in_static_analysis`
- `alerts.csv` 行数和关键 API 命中数
- production/test baseline 差异
- `visited_classes / javap_classes / hit_apis`
- Step5 阶段耗时
- bytecode scan / bytecode expand 的候选 class 数与并行度

一旦这些指标发生漂移，必须解释是合理能力变化、输入变化，还是回归。

真实项目 `passed` 不能直接等价于健康：non-gating production missing、`not_analyzed` 和 skipped 必须进入质量信号审计，并按 `QUALITY_RISK_MATRIX.md` 解释或升级为准确性基准。

## 4. 修复准入

每个修复前必须回答：

- 这个修复是否符合 Java 编译期/字节码语义？
- 是否同时覆盖正例和负例？
- 是否会改变四态结论？
- 是否会吞掉 `alerts.csv` 的链路？
- 是否会影响多依赖链路或 `consumer_method` 回溯？
- 是否会把能力不足误判为静态未找到？

禁止为了某个单一真实项目场景放宽 owner、签名或重载规则。

## 5. 打包前最低要求

打包给真实工程测试前，至少执行：

```bash
python3 scripts/quality_gate.py --profile release
```

如果时间不允许完整真实矩阵，必须明确说明跳过项：

```bash
python3 scripts/quality_gate.py --profile release --skip-real
```

并在交付说明中标记“真实项目矩阵未执行”。
