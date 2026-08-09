# 跨步骤诊断契约

用户和下游诊断 JSON 使用 `java-upgrade-analyzer.diagnostic.v1`。

## 命名

- 字段名：`lower_snake_case`；
- `reason_code`：`UPPER_SNAKE_CASE`，表达稳定语义而非瞬时动作；
- 来源：独立 `origin_step`；
- 历史拼写只通过 `reason_code_aliases` 归一化，新输出不发布旧码。

常用原因码包括：

| 阶段 | 原因码 | 含义 |
|---|---|---|
| Step1 | `DEPENDENCY_COORDINATES_UNRESOLVED` | 最终制品条目尚未绑定唯一依赖身份 |
| Step4 | `BINARY_PIPELINE_CONFIG_REQUIRED` | 缺少显式 target runtime 输入 |
| Step4 | `BINARY_ARTIFACT_PARSE_FAILED` | 制品事实未完整形成 |
| Step4 | `BINARY_INDEPENDENT_VALIDATION_FAILED` | generation 未通过独立 Oracle |
| Step4 | `BINARY_GENERATION_FAILED` | binary generation 或原子发布失败 |
| Step5 | `BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED` | active generation 内容完整性失败 |
| Step6 | `BINARY_STEP5_GENERATION_MISMATCH` | Step5 范围与 active generation 不一致 |

具体代码可以更细，但必须符合 `diagnostic_contract.py` 的规范化规则。

## 输出位置

- 工作流阻塞与恢复：`.runtime/state/main_state.json`、`interaction.json`；
- binary generation 失败：`.runtime/binary_authority/binary_failures/`；
- coverage：generation 的 `binary_coverage.json` 以及用户报告中的范围说明；
- 人工变化复核：`evidence/api_changes/review.md`；
- 最终结论边界：`deliverables/analysis-scope.md`。

API CSV 不使用伪造行承载系统错误。诊断候选与正式变化在 generation 和 `review.md` 中分开；`all_changed_apis.csv` 只发布可进入触达分析的正式 API 投影。

## 用户说明

面向用户时先说明：哪个依赖/范围、发生什么、结论为何受限、系统已做什么、需要用户做什么。只有缺少系统无法获取的外部事实、授权或会改变范围的选择才请求用户输入。

不得要求用户从英文枚举、行数为零或文件缺失推断“没有变化”。coverage 不完整必须明确写成“当前范围不能形成完整结论”，并给出证据路径和重跑完成标准。

## 失败关闭

binary-first 没有兼容或降级分支。诊断建议只允许修复输入/环境后重跑受影响阶段；不能建议忽略缺口、批准使用旧引擎或扩大结论。上一份已验证 generation 可继续保留，但不得冒充本次失败输入的新结果。
