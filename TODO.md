# 待优化项

本文只记录尚未完成或尚未取得充分验证证据的工作。确认完成的项目直接删除，不在待办文档中保留历史设计正文；历史决策应进入 `docs/archive/` 或 Git 记录。

状态快照日期：2026-07-21。完整原则和移交上下文见
[`docs/developer/handoff.md`](docs/developer/handoff.md)。

当前共 3 项：已完成 0、正在执行 0、待执行 3、阻塞 0、失败 0。
所有条目的交付验证状态均为未验证。

## 1. 对齐历史进度记录与当前代码

- 执行状态：待执行。
- 验证状态：未验证。
- 已核实事实：本机忽略文件 `.superpowers/sdd/progress.md` 仍以 `f376270` 为基线并写着
  `Task 4: in progress`；它不受 Git 跟踪，不能作为接手者的正式状态源。
- 已核实事实：`docs/developer/capability-family-audit.md`、`quality.md`、`constitution.md`
  和 `architecture.md` 的最近提交早于当前代码基线，之后已有证据、Oracle、产物身份和远程 ref 相关改动。
- 待办：逐条用代码、测试和提交记录核对旧 progress 中的 follow-up；仍未完成的保留在本文件，
  已完成的归档或删除；同步需要更新的能力审计、架构和质量文档。
- 验收：不存在相互冲突的“进行中/已完成”描述；每个当前待办都能指向可复现证据和验收条件。

## 2. 建立当前 HEAD 的新鲜质量基线

- 执行状态：待执行，依赖第 1 项收敛。
- 验证状态：未验证；2026-07-21 的 37 项定向契约测试和 `quick` profile 已通过，
  但不能替代本项要求的完整 release 与真实项目验证。
- 无法确认：当前 HEAD 是否通过完整 `release` 门禁和最新真实项目矩阵；本次移交未运行这些验证。
- 待办：依次运行 quick、受影响的 Step5/Smoke、release，并使用 `--include-real` 明确加入选定的
  真实项目守护矩阵；保存结构化结果、质量信号审计、复盘与 capability closure。
- 验收：结果绑定具体 commit、环境、profile 和真实项目范围；没有失败、跳过、fixture debt、
  阻塞信号或未说明的未验证项。

## 3. 处理历史压缩包

- 执行状态：待执行。
- 验证状态：未验证。
- 已核实事实：移交文档编写时，工作区包含
  `java-upgrade-analyzer-codex-pig-real-audit-1599903-20260720.zip`、
  `java-upgrade-analyzer-performance-optimization-fdb3895-20260717.zip` 两个未跟踪文件。
- 已核实事实：两个 ZIP 分别是 2026-07-20 和 2026-07-17 左右的旧版完整打包快照，内容早于当前源码。
- 待办：确认两个 ZIP 是仍需通过 GitHub Release/制品库交付的历史版本，还是可清理的本地文件；
  不要把过期完整源码快照直接混入当前源码提交。
- 验收：需要移交的内容已进入明确提交或交付清单；不需要的内容经所有者确认后处理；工作区状态可解释。
