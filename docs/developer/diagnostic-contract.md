# 跨步骤诊断契约

所有面向用户或下游工具的诊断 JSON 使用
`java-upgrade-analyzer.diagnostic.v1` 契约。

## 命名规则

- JSON 字段名统一使用小写 `snake_case`。
- `reason_code` / `reason_codes[]` 的值统一使用大写 `UPPER_SNAKE_CASE`。
- 原因码描述语义，不混入瞬时处理过程，推荐结构为
  `DOMAIN_SUBJECT_CONDITION`。
- 诊断来源步骤写入独立的 `origin_step` 字段，不要求用户从原因码猜测步骤。
- 旧原因码通过 `reason_code_aliases[]` 或覆盖组件中的
  `reason_code_aliases{}` 暴露；新输出只使用规范原因码。

当前重点原因码：

| 来源步骤 | 规范原因码 | 旧名称 |
|---|---|---|
| Step1 | `DEPENDENCY_COORDINATES_UNRESOLVED` | `unresolved_dependency_coordinates_after_enrichment` |
| Step4 | `DEPENDENCY_SOURCE_REF_UNAVAILABLE` | 无 |
| Step4 | `JAPICMP_EXECUTION_FAILED` | 无 |
| Step4 | `JAPICMP_TIMEOUT` | 无 |
| Step5 | `SPRING_RUNTIME_CLASS_AMBIGUOUS` | `SPRING_PACKAGED_CLASS_AMBIGUOUS` |
| Step5 | `MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED` | 无 |

## 输出约定

Step1 交互卡、Step4 覆盖文件和 Step5 `summary.json` 都应提供：

- 诊断契约或 schema；
- 规范 `reason_code`；
- `origin_step`；
- 旧码别名；
- 触发条件、影响范围、建议决策、修复动作和完成标准。

Step6 使用同一原因目录生成主报告，不单独维护另一套解释词汇。旧版结果在读取时先
归一化原因码，再进行聚合，避免同一问题因新旧拼写被拆成两条诊断。

Step4 的 `all_changed_apis.csv` 只保存真实 API 变化事实，不使用伪造 API 行承载执行
错误。用户首先阅读 `dependency_analysis_status.md`，其中使用中文直接说明每个依赖
的 API 对比结果、实现变化检查结果、最终结论、是否完整、能否按无变化处理、形成结论
前是否还需处理，以及下一步动作。
`dependency_analysis_status.csv` 与 `dependency_analysis_status.json` 供机器读取。字段名
必须带明确对象，例如 `api_comparison_status`、`api_comparison_failure_reason`、
`implementation_check_status`，不得使用无法看出所指对象的 `status`、`failure_message`
或 `result_interpretation`。`api_comparison_status` 的值为：

- `changes_detected`：对比成功且发现 API 变化；
- `no_api_change`：对比成功且没有可见 API 变化；
- `failed`：没有形成 API 数据，禁止解释为零变化；
- `not_applicable`：不存在可执行的 old/new 二进制对比范围。

用户文档不得要求用户根据英文枚举、API 行是否存在或多个文件之间的缺失关系猜测结论。
机器字段必须同时提供对应的 `*_text`、明确布尔结论以及 `next_action`。禁止使用
`needs_fix` 这类无法判断修复对象的模糊字段；证据不完整统一使用
`requires_action_before_conclusion`，表示必须按 `next_action` 处理并重新分析后才能
采用结论。
