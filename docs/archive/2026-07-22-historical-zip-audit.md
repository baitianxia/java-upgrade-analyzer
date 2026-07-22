# 历史 ZIP 归属审计

审计日期：2026-07-22（Asia/Shanghai）。

状态：已完成。所有者已确认不保留、不重新制作、不交付两个历史 ZIP；对应 Git 提交继续作为历史源码的可恢复记录。

## 制品清单

| 历史文件名 | 文件名绑定的源码提交 | 当前可恢复性 |
|---|---|---|
| `java-upgrade-analyzer-codex-pig-real-audit-1599903-20260720.zip` | `1599903dd8838c7f66c1b2415550b0fa8f9a47fb` | 提交仍是当前 `main` 的祖先，可从 Git 恢复源码状态 |
| `java-upgrade-analyzer-performance-optimization-fdb3895-20260717.zip` | `fdb3895920a7f6ee697dbc14ce0b4aec78f9c7f5` | 提交仍是当前 `main` 的祖先，可从 Git 恢复源码状态 |

## 已核实事实

1. `git log --all -- '*.zip' '*.ZIP'` 没有结果；两个 ZIP 从未受 Git 跟踪。
2. 当前仓库没有 ZIP。对精确文件名执行本机 Spotlight 查询也没有结果，但该结果不能覆盖未索引位置或本机无读取权限的 Desktop、Documents、Downloads 等目录。
3. `docs/superpowers/plans/2026-07-17-csv-excel-encoding.md` 的最终工作区验收曾明确要求只保留
   `java-upgrade-analyzer-performance-optimization-fdb3895-20260717.zip` 这一未跟踪文件。这证明它在 2026-07-17 的语境中是有意保留的交付候选，不是偶然缓存。
4. `75dd55b5f113ecbe34dbd90eb6d86724ac500070` 首次把两个文件同时写入正式 TODO；后续 `d064f61412703e2d4b112ef8883215eb80d298c3` 将它们明确描述为早于当前源码的旧版完整打包快照，并要求所有者决定通过 GitHub Release/制品库交付还是清理。
5. 本轮无法访问 GitHub SSH/API，因此不能核验远端 Release 附件或其他制品库；当前仓库也没有记录任何交付 URL、版本号或历史 ZIP 的 SHA-256。

## 决策依据

- 两个 ZIP 都是早于当前源码的完整快照，源码状态已由不可变 Git 提交覆盖。
- 仓库与 Spotlight 均未发现原 ZIP，因此不需要执行文件删除操作。
- 重新制作旧完整源码包会产生重复交付物，没有独立于 Git 历史的保存价值。

## 所有者决定记录

- 决定：不保留、不重新制作、不通过 GitHub Release 或其他制品库交付。
- 确认人：项目所有者（本任务用户）。
- 确认时间：2026-07-22（Asia/Shanghai）。
- 交付位置或清理说明：无交付位置；当前没有可删除的原 ZIP。历史源码分别由 `1599903dd8838c7f66c1b2415550b0fa8f9a47fb` 和 `fdb3895920a7f6ee697dbc14ce0b4aec78f9c7f5` 保留。
