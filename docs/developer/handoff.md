# 工程移交说明

本文给接手维护者提供最短的上下文恢复路径。原则的完整定义仍以
[工程宪法](constitution.md)、[架构说明](architecture.md) 和
[质量门禁](quality.md) 为准；当前工作项以根目录 [TODO](../../TODO.md) 为准。

## 状态快照

- 快照日期：2026-07-22（Asia/Shanghai）。
- 交接审计起点：`main@e313356`；本次文档复核以 `main@69b60af` 为代码基线，当时本地 `main` 比 `origin/main@e24d7ab` 超前 2 个提交；后续状态必须以 `git status` 和 `git log` 为准。
- 工程定位：供 Claude Code 使用的 Java 升级兼容性分析 Skill；它负责分析风险、输出证据和结论，不自动修改待分析工程。
- 已核实：根目录 `TODO.md` 在 `641c39f` 清空了当时已验证完成的待办；这不代表当前工作区没有移交事项。
- 已核实：TODO 曾记录一个未受 Git 跟踪的 `.superpowers/sdd/progress.md`，其基线停留在 `f376270` 且含有过期的 `Task 4: in progress`。2026-07-21 复核时该文件已不存在，Git 历史也无法恢复其逐行内容；它不再构成状态冲突，也不得作为正式状态源。
- 已核实：quality gate 的所有 profile 默认只运行本地回归；真实项目矩阵必须通过 `--include-real` 显式加入。只有 release、本地回归、完整 guard 和质量审计全部通过时才允许发布；GitHub release workflow 会物化并运行完整 guard。
- 已核实：移交早期曾记录两个未跟踪的历史 ZIP；它们从未进入 Git，仓库目录中已无这两个文件，对应源码状态仍可由 `1599903dd8838c7f66c1b2415550b0fa8f9a47fb` 和 `fdb3895920a7f6ee697dbc14ce0b4aec78f9c7f5` 恢复。2026-07-22 所有者确认不保留、不重新制作、不交付这两个过期快照；完整时间线与决定见 [历史 ZIP 归属审计](../archive/2026-07-22-historical-zip-audit.md)。
- 已验证：2026-07-21 在 `d064f61` 上，quick 的语法检查、Oracle 独立性、核心确定性、核心准确性基准和 21 项核心语义测试通过。
- 已核实：运行契约支持 CPython 3.12.x、3.13.x 与 3.14.x，解析器依赖仍精确固定；PR quick 门禁在三个 Python 小版本上分别执行。2026-07-22 已在隔离 CPython 3.12.13/3.13.14/3.14.6、JDK 21、macOS 环境完成固定依赖安装与本地兼容性验证；跨平台最终证据以提交后的 CI 矩阵为准。
- 已验证：`main@5b41834` 在 CPython 3.12.13、JDK 21.0.8、Maven 3.9.16、macOS 下通过 `guard-capability` 与完整 `release --include-real --real-case guard`；完整单测 2000 项（跳过 1 项）、9 个真实项目、质量信号审计、复盘与 capability closure 全部通过，发布裁决为 `release_allowed`。
- 已验证：Kotlin/KTS 已明确为 partial capability；`.kts`、标准源集分类、Java/Kotlin 双向 fixture、最终制品 class 闭集和 `not_impacted` 失败关闭均有定向回归，466 项 Step5/拓扑测试与 quick 通过。
- 已验证：Step5 会按坐标与 owner 预热多目标反向传播并复用目标无关的前驱转换；开启/关闭复用后的五态、路径指纹与完整 `alerts.csv` 字节一致，1×/2×/4× 共享子图的转换物化次数为近线性增长。
- 已验证：quick/Step5 测试范围由 capability-family profile 声明生成并支持稳定分片；全部 enforced 引用可加载。核心分支覆盖为 `signature_utils` 76.09%、结论策略 88.89%，11 类生产变异全部被杀死，性质测试两轮无 flaky/超时，增强后的 quick 通过。
- 已验证：Step5 已建立事实提取、身份、图契约、纯追踪策略、图查询、结论与渲染的单向模块边界；策略分支覆盖 92.31%。两条 `javap` 路径使用统一结构化失败，且工具失败经过 collector ingestion 后仍保留为 blocking evidence。
- 已验证：以 `main@5b4183492cf1d026ade20590dfa20a4173aa7c7a` 为基线的当前工作区于 2026-07-22 通过完整 `release --include-real --real-case guard`：2035 项单测通过（跳过 1 项），smoke、用户场景、9 个真实项目、质量信号审计、复盘与 capability closure 全部通过，阻塞与非阻塞质量信号均为 0，发布裁决为 `release_allowed`。本机证据为 `/private/tmp/jua-final-release-2-quality-gate.json` 和 `/private/tmp/jua-final-release-2/real_project_guard.json`；这些临时路径只用于本轮复核，后续提交后应重新生成证据。

接手后先执行：

```bash
git status --short --branch
git log -5 --oneline
sed -n '1,240p' TODO.md
```

不要清理本轮未提交改动；历史 ZIP 已确认无需保留，也没有当前文件需要删除。

## 必须继续遵守的原则

1. **准确性优先。** 不能用缩小分析范围、降低匹配精度、跳过证据或隐藏不确定性换性能。
2. **最终制品是事实主线。** 依赖范围、版本、JAR 内容和字节码以实际构建/部署制品为准；源码只补充行为与可读性，不能覆盖制品事实。证据应绑定可核验的制品身份和 SHA-256。
3. **证据不足就失败关闭。** 严格区分 `reachable`、`not_impacted`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed`；未找到证据不等于确认无影响。
4. **匹配必须精确。** 优先使用依赖坐标、全限定类名、成员签名和所属制品。简单类名、裸方法名或无签名 key 不能跨包、跨类、跨 JAR 形成确定链路。
5. **正式流程只有一个入口和一个真相源。** 使用 `scripts/run_step.py` 调度；业务参数与运行状态只以 `.upgrade-report/.runtime/state/main_state.json` 为准。`interaction.json` 只用于展示待交互内容。
6. **Checkpoint 必须停。** 遇到退出码 `4`、`AWAITING USER INPUT` 或 `awaiting_*` 状态时，读取状态和交互文件、向用户展示决策卡片并等待真实答复；禁止代用户选择或自行续跑。
7. **修能力模型，不修单一案例。** 每个缺陷都要按根因族横向检查其他 Step、模块、平台分支、缓存、降级路径和上下游校验，覆盖广义正例、负例和边界例；必须记录已修复点与经证据确认不受影响的同类点。真实项目发现的问题应沉淀到 capability family、fixture 和故障注入，而不是项目名特判。
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

当前没有已确认的待办。历史 ZIP 的所有者决定已归档，现状见 [TODO](../../TODO.md)。

类型语义与长链路覆盖已收口：Java 类级使用会消费 AST/类型元数据中的声明、泛型、
注解、继承/实现、throws、类字面量、instanceof、强转、方法引用、构造器和静态限定事实；简单名必须唯一解析，
同名 import 和值遮蔽均有负例。全精确高置信路径按图规模自适应放宽，默认最多 15 cost，
medium/low、多态与 fallback 仍使用原预算；深度截断会把预算、目标和候选数写入
`path_details` 与 `alerts.csv coverage_details`。1/2/5/12 跳、15-cost 截断、预算单调性、
该能力的历史定向回归、`quick`、`smoke_core` 和 `smoke_step5` 已通过；当前轮次的完整
Step5/拓扑集合与最终发布证据以状态快照和质量门结果为准，不再沿用早期 456 项测试的过期失败描述。

Step5 资源观测已收口：Linux 通过 `/proc`、macOS 通过 `libproc` 采集 Python 与全部
后代进程的 RSS 高水位，并记录自身/子进程 CPU、外部命令墙钟、总调用数、并发高水位、
按工具调用数和 `.runtime` 临时文件体积高水位。
`JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB` 产生显式告警，
并把后续 `javap` 收敛为单 worker、释放可重载的正文字符串缓存；
`JUA_STEP5_PROCESS_TREE_HARD_RSS_MB` 在阶段边界失败关闭。相关定向测试、实际子进程压力测试、
`smoke_core`、`smoke_step5` 与用户场景已通过；后续修改必须继续由当前声明式 Step5 profile
和完整 release/guard 复核，不能用这段历史证据替代新鲜门禁。

## 维护与交付纪律

- 不修改、不覆盖来源不明的未提交工作；提交前精确暂存本次文件。
- 不把 `.upgrade-report/`、缓存、IDE 文件、历史 ZIP 或临时日志加入源码包。
- 代码改动前先写清问题类别、影响 Step、输出契约风险和验证矩阵。
- 每轮真实项目测试后执行质量信号审计、复盘和 capability-family closure；任一门禁失败时，不得宣称本轮完成。
- 打包前至少执行 `python3 scripts/quality_gate.py --profile quick`；涉及 Step4、Step5 或输出语义时增加相应 profile 和定向测试。需要真实项目证据时显式增加 `--include-real`。
