# MIGRATION-001：系统、项目与历史文档分域

## 原因

旧结构主要按读者分为 `user/`、`developer/`，同时把大量有日期的设计计划放在未被文档地图收录的 `superpowers/`。这使当前系统合同、项目过程和历史资料的权威边界不清晰，也让维护者难以判断某份设计是否仍然生效。

本次整理采用 `system/`、`project/`、`archive/` 三个权威域，并保留 Skill 分发必须使用稳定相对路径的根运行文档。

## 路径映射

| 原路径 | 新路径 | 当前职责 |
|---|---|---|
| `docs/user/outputs.md` | `docs/system/operations/outputs.md` | 当前输出与复核合同 |
| `docs/developer/architecture.md` | `docs/system/architecture/overview.md` | 当前架构概览 |
| `docs/developer/binary-first-source-overlay-design.md` | `docs/system/architecture/binary-first-engine.md` | 当前引擎合同 |
| `docs/developer/step5-design.md` | `docs/system/architecture/step5-binary-trace.md` | 当前 Step5 合同 |
| `docs/developer/technical-sharing.md` | `docs/system/architecture/technical-overview.md` | 非完整技术摘要 |
| `docs/developer/diagnostic-contract.md` | `docs/system/contracts/diagnostics.md` | 当前诊断契约 |
| `docs/developer/constitution.md` | `docs/system/quality/constitution.md` | 当前工程原则 |
| `docs/developer/quality.md` | `docs/system/quality/quality-gates.md` | 当前质量门禁 |
| `docs/developer/testing-strategy.md` | `docs/system/quality/testing-strategy.md` | 当前测试策略 |
| `docs/developer/binary-first-capability-migration-audit.md` | `docs/project/audits/binary-first-capability-migration.md` | 有基线的迁移审计 |
| `TODO.md` | `docs/project/roadmap/README.md` | planning-only 候选工作 |
| `docs/superpowers/` | `docs/project/iterations/historical-2026-07/` | 历史设计与计划 |
| `docs/archive/*.md` 旧版规范 | `docs/archive/legacy/` | 非当前历史正文 |

## 兼容性处理

`SKILL.md`、`RUNBOOK.md` 和 `CHECKPOINT_RULES.md` 没有移动，因为程序、测试和已分发 Skill 依赖这些稳定路径。所有当前代码测试、夹具和活动文档引用更新到新路径；历史设计正文中的字面旧路径保留，用本记录解释映射。

## 结论边界

本次变更只整理文档权威和导航，不改变分析器运行行为、公开输出 schema、质量门禁结论或历史项目状态。
