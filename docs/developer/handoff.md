# 工程移交说明

本文给接手维护者提供最短的上下文恢复路径。原则的完整定义仍以
[工程宪法](constitution.md)、[架构说明](architecture.md) 和
[质量门禁](quality.md) 为准；当前工作项以根目录 [TODO](../../TODO.md) 为准。

## 状态快照

- 快照日期：2026-07-21（Asia/Shanghai）。
- 交接审计起点：`main@e313356`；本次文档复核以 `main@69b60af` 为代码基线，当时本地 `main` 比 `origin/main@e24d7ab` 超前 2 个提交；后续状态必须以 `git status` 和 `git log` 为准。
- 工程定位：供 Claude Code 使用的 Java 升级兼容性分析 Skill；它负责分析风险、输出证据和结论，不自动修改待分析工程。
- 已核实：根目录 `TODO.md` 在 `641c39f` 清空了当时已验证完成的待办；这不代表当前工作区没有移交事项。
- 已核实：TODO 曾记录一个未受 Git 跟踪的 `.superpowers/sdd/progress.md`，其基线停留在 `f376270` 且含有过期的 `Task 4: in progress`。2026-07-21 复核时该文件已不存在，Git 历史也无法恢复其逐行内容；它不再构成状态冲突，也不得作为正式状态源。
- 已核实：quality gate 的所有 profile 默认只运行本地回归；真实项目矩阵必须通过 `--include-real` 显式加入。只有 release、本地回归、完整 guard 和质量审计全部通过时才允许发布；GitHub release workflow 会物化并运行完整 guard。
- 已核实：移交早期曾记录两个未跟踪的历史 ZIP；当前工作区干净且仓库目录中已无这两个文件，其最终归属仍待所有者确认。
- 已验证：2026-07-21 在 `d064f61` 上，quick 的语法检查、Oracle 独立性、核心确定性、核心准确性基准和 21 项核心语义测试通过。
- 已核实：运行契约现已固定为 CPython 3.12.x 与精确解析器版本；本机 Python 3.14.6 会在分析前以 `unsupported_python` 明确失败，不再触发隐式联网安装。2026-07-21 已在隔离 CPython 3.12.12、JDK 21、macOS 环境通过离线 wheel bootstrap、44 项定向测试和 quick 全部 7 个任务；这属于当前工作区证据，完整 Step5/release/真实项目矩阵仍需在提交后建立新鲜证据。
- 无法确认：当前 HEAD 是否通过完整 `release` 门禁和最新真实项目矩阵。本次移交没有执行这两项验证，旧提交或旧文档中的结果不能替代当前证据。

接手后先执行：

```bash
git status --short --branch
git log -5 --oneline
sed -n '1,240p' TODO.md
```

不要先清理工作区；先确认未跟踪 ZIP 是否需要保留。

## 必须继续遵守的原则

1. **准确性优先。** 不能用缩小分析范围、降低匹配精度、跳过证据或隐藏不确定性换性能。
2. **最终制品是事实主线。** 依赖范围、版本、JAR 内容和字节码以实际构建/部署制品为准；源码只补充行为与可读性，不能覆盖制品事实。证据应绑定可核验的制品身份和 SHA-256。
3. **证据不足就失败关闭。** 严格区分 `reachable`、`not_impacted`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed`；未找到证据不等于确认无影响。
4. **匹配必须精确。** 优先使用依赖坐标、全限定类名、成员签名和所属制品。简单类名、裸方法名或无签名 key 不能跨包、跨类、跨 JAR 形成确定链路。
5. **正式流程只有一个入口和一个真相源。** 使用 `scripts/run_step.py` 调度；业务参数与运行状态只以 `.upgrade-report/.runtime/state/main_state.json` 为准。`interaction.json` 只用于展示待交互内容。
6. **Checkpoint 必须停。** 遇到退出码 `4`、`AWAITING USER INPUT` 或 `awaiting_*` 状态时，读取状态和交互文件、向用户展示决策卡片并等待真实答复；禁止代用户选择或自行续跑。
7. **修能力模型，不修单一案例。** 每个缺陷都要覆盖广义正例、负例和边界例；真实项目发现的问题应沉淀到 capability family、fixture 和故障注入，而不是项目名特判。
8. **独立事实对账。** 分析器结果与 Oracle 必须保持实现独立，并对完整 API 身份集合、物理边、语义引用和最终制品身份做闭集核验；不能复制分析器结果充当 Oracle。
9. **性能优化不改变语义或范围。** 允许缓存、索引、并行和已证明安全的剪枝；性能门同时验证 API、制品、类、边、Oracle 和故障注入范围没有缩水。
10. **用户输出先讲结论与原因。** `alerts.csv` 是完整链路台账，不是抽样；主报告先给依赖、变化 API、结论、原因和关键链路，再指向完整证据。内部术语不能替代用户可理解的表达。
11. **变更必须经过分层验证。** 至少覆盖针对性单元/契约测试；重要改动再按影响范围运行 quick、Step5、smoke、真实项目与 release 门禁，并记录提交、环境、范围和结果。
12. **状态陈述必须可核验。** 区分已核实事实、基于证据的推断和无法确认；实现状态与验证状态分开报告。局部测试通过不能写成全部完成。
13. **文档必须服从代码事实。** 行为、状态机、输入输出契约或用户流程变化时，同步维护 `SKILL.md`、`RUNBOOK.md` 和开发者文档；不能描述代码尚不支持的能力。

## 架构与阅读路径

```text
用户入口 README.md
  -> 运行协议 SKILL.md / CHECKPOINT_RULES.md
  -> 命令细节 RUNBOOK.md
  -> 调度入口 scripts/run_step.py
  -> 唯一主状态 .upgrade-report/.runtime/state/main_state.json
  -> Step1..Step6 证据与最终报告
```

维护时按改动范围阅读：

- 改原则或结论语义：先读 [工程宪法](constitution.md)。
- 改调度、状态、Step 间契约：读 [架构说明](architecture.md)。
- 改 Step5 建图、匹配或五态结论：再读 [Step5 设计](step5-design.md)。
- 改测试、真实项目或发布流程：读 [质量门禁](quality.md) 和
  [Capability Family Audit](capability-family-audit.md)。
- 改用户可见产物：读 [输出复核指南](../user/outputs.md)。

## 当前待办摘要

当前共 8 项：已完成 0、正在执行 0、待执行 8、阻塞 0、失败 0。每项均未完成交付验证；
验收条件、依赖关系和现状证据见 [TODO](../../TODO.md)。

1. 建立当前 HEAD 的完整质量基线。
2. 扩展类型语义与长链路覆盖。
3. 明确 Kotlin 与混合语言能力边界。
4. 建立一次扫描、多目标复用的源码事实索引。
5. 观测完整进程树内存。
6. 拆分超大模块并收紧异常处理。
7. 增强覆盖率、性质测试和变异测试。
8. 确认历史 ZIP 的最终归属。

## 维护与交付纪律

- 不修改、不覆盖来源不明的未提交工作；提交前精确暂存本次文件。
- 不把 `.upgrade-report/`、缓存、IDE 文件、历史 ZIP 或临时日志加入源码包。
- 代码改动前先写清问题类别、影响 Step、输出契约风险和验证矩阵。
- 每轮真实项目测试后执行质量信号审计、复盘和 capability-family closure；任一门禁失败时，不得宣称本轮完成。
- 打包前至少执行 `python3 scripts/quality_gate.py --profile quick`；涉及 Step4、Step5 或输出语义时增加相应 profile 和定向测试。需要真实项目证据时显式增加 `--include-real`。
