# Agent 执行入口

本目录不定义独立分析管线。所有 Agent 均执行仓库根目录 [`SKILL.md`](../SKILL.md) 和 [`CHECKPOINT_RULES.md`](../CHECKPOINT_RULES.md)，并通过 `scripts/run_step.py` 进入当前状态机。

依赖复核只能消费当前 validated binary generation 及其人工投影：

- `evidence/api_changes/changed_dependencies.md` 与 `all_changed_apis.csv`；
- `evidence/call_chain/summary.md`、`alerts.csv` 与 `by_api/`；
- `deliverables/report.md` 和完整依赖/API 明细。

不得以源码 `git diff`、本地 Maven 仓库同坐标文件、在线下载的替代 JAR 或历史目录作为正式依赖、变化或调用边证据。源码和外部发布说明只提供解释或候选线索，不能改变 runtime provider、二进制变化事实、可执行边或正式四维结果。

结论语义与文件边界以 [`docs/system/architecture/binary-first-engine.md`](../docs/system/architecture/binary-first-engine.md) 和 [`docs/system/operations/outputs.md`](../docs/system/operations/outputs.md) 为唯一正文所有者。
