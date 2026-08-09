# 待优化项

本文只记录尚未完成且仍适用于当前 binary-first 架构的工作。历史实现问题不在现行 TODO 中保留。

状态快照日期：2026-08-09。当前共 1 项：待执行 1，阻塞 0，失败 0。

## 为归档安全校验建立显式策略等级

- 优先级：P2。执行状态：待执行。验证状态：问题已确认，改造尚未实施。
- 当前事实：生产调用点包括 Step1/gate 的 `require_safe_archive`，以及 binary artifact diff 和独立 Oracle 的 `inspect_archive`。binary artifact diff 已从版本化 support manifest 读取限制；其他调用仍以参数或默认值表达策略。
- 风险：内部生成归档、Step1 留存制品、完整 runtime 制品和潜在不可信外部归档的风险与性能预算不同；如果调用者未显式选择策略，新入口可能沿用不合适的默认限制。
- 待办：建立集中、不可变的命名策略，至少区分内部生成归档、Step1 浅扫描、完整 runtime 扫描和不可信外部归档；所有生产调用点显式选择策略。
- 验收：策略身份进入相关 cache/coverage；调整一种策略不改变其他策略；高膨胀率、超限总量、过多 entry、过深嵌套、重复路径、正常大型 JAR 均有正反例和资源预算验证。

历史审计见 [`docs/archive/2026-07-22-historical-zip-audit.md`](docs/archive/2026-07-22-historical-zip-audit.md)。
