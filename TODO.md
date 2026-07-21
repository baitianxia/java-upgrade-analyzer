# 待优化项

本文只记录尚未完成或尚未取得充分验证证据的工作。确认完成的项目直接删除，不在待办文档中保留历史设计正文；历史决策应进入 `docs/archive/` 或 Git 记录。

状态快照日期：2026-07-21。完整原则和移交上下文见
[`docs/developer/handoff.md`](docs/developer/handoff.md)。

当前共 4 项：已完成 0、正在执行 0、待执行 4、阻塞 0、失败 0。
所有条目的交付验证状态均为未验证；第 1 项仅完成了现状失败复现。

## 1. 明确 quality gate 的真实项目 opt-in 契约

- 执行状态：待执行。
- 验证状态：未验证。
- 已核实事实：工作区的 `tests/test_quality_gate.py` 新增了
  `test_all_profiles_default_to_regression_only`，要求 `quick`、`step5`、`release`
  在没有显式 opt-in 时都不加入真实项目任务。
- 已核实事实：2026-07-21 定向运行该测试时，`step5` 和 `release` 两个子用例失败；
  `scripts/quality_gate.py::build_plan()` 当前默认 `skip_real=False`。
- 待办：确认这一契约是否为最终决策；若确认，实现明确的 opt-in 接口并同步 CLI 帮助、
  `docs/developer/quality.md`、CI 调用和相应测试；若不确认，必须说明理由后调整测试，不能让失败测试长期悬空。
- 验收：默认计划和显式 opt-in 计划都有测试；三个 profile 的 dry-run 与文档一致；相关测试通过。

## 2. 对齐历史进度记录与当前代码

- 执行状态：待执行。
- 验证状态：未验证。
- 已核实事实：本机忽略文件 `.superpowers/sdd/progress.md` 仍以 `f376270` 为基线并写着
  `Task 4: in progress`；它不受 Git 跟踪，不能作为接手者的正式状态源。
- 已核实事实：`docs/developer/capability-family-audit.md`、`quality.md`、`constitution.md`
  和 `architecture.md` 的最近提交早于当前代码基线，之后已有证据、Oracle、产物身份和远程 ref 相关改动。
- 待办：逐条用代码、测试和提交记录核对旧 progress 中的 follow-up；仍未完成的保留在本文件，
  已完成的归档或删除；同步需要更新的能力审计、架构和质量文档。
- 验收：不存在相互冲突的“进行中/已完成”描述；每个当前待办都能指向可复现证据和验收条件。

## 3. 建立当前 HEAD 的新鲜质量基线

- 执行状态：待执行，依赖第 1、2 项收敛。
- 验证状态：未验证。
- 无法确认：当前 HEAD 是否通过完整 `release` 门禁和最新真实项目矩阵；本次移交未运行这些验证。
- 待办：先运行第 1 项的定向测试，再按最终 opt-in 契约依次运行 quick、受影响的 Step5/Smoke、
  release 和明确选择的真实项目守护矩阵；保存结构化结果、质量信号审计、复盘与 capability closure。
- 验收：结果绑定具体 commit、环境、profile 和真实项目范围；没有失败、跳过、fixture debt、
  阻塞信号或未说明的未验证项。

## 4. 处理本地未提交内容和历史压缩包

- 执行状态：待执行。
- 验证状态：未验证。
- 已核实事实：移交文档编写时，工作区包含 `tests/test_quality_gate.py` 的未提交修改，以及
  `java-upgrade-analyzer-codex-pig-real-audit-1599903-20260720.zip`、
  `java-upgrade-analyzer-performance-optimization-fdb3895-20260717.zip` 两个未跟踪文件。
- 待办：确认测试改动的归属并完成、拆分提交或明确撤销；确认两个 ZIP 是交付物、历史留档还是可清理文件。
- 验收：需要移交的内容已进入明确提交或交付清单；不需要的内容经所有者确认后处理；工作区状态可解释。
