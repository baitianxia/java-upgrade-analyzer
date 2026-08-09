# 待优化项

本文只记录尚未完成或尚未取得充分验证证据的工作。确认完成的项目直接删除，不在待办文档中保留历史设计正文；历史决策应进入 `docs/archive/` 或 Git 记录。

状态快照日期：2026-08-09。完整原则见 [`AGENTS.md`](AGENTS.md)，当前架构和
质量上下文见 [`docs/developer/`](docs/developer/)。

当前共 2 项：已完成 0、正在执行 0、待执行 2、阻塞 0、失败 0。

## 1. 为归档安全校验建立显式策略等级

- 优先级：P2。执行状态：待执行。验证状态：问题已确认，改造尚未实施或验证。
- 已核实事实：生产代码有 10 个 `require_safe_archive` 直接调用点，分布在 7 个脚本中；另有 3 个直接 `inspect_archive` 调用。旧调用中的 2 个同样继承底层默认值，新 binary artifact 路径已显式传入版本化限制。10 个强制校验调用全部隐式继承条目数、总解压大小、膨胀率、嵌套深度和嵌套归档大小限制；其中 3 个还继承嵌套扫描默认值。
- 已核实事实：`require_safe_archive(path, **limits)` 支持调用者单独覆盖限制，因此并非技术上无法收紧；缺口是没有按归档来源和消费方式强制选择的命名策略，无法集中审计和防止新调用点遗漏严格限制。
- 风险：修改通用资源默认值会同时改变现有内部生成制品、Step1 留存依赖和完整制品扫描的性能或兼容性；未来不可信外部归档若沿用当前 `max_expansion_ratio=None` 的内部默认策略，可能引入可避免的 CPU、I/O 和解压资源消耗。
- 无法确认：当前部署边界是否已允许攻击者可控归档进入这些路径；若已允许，本项应升级为 P1 安全项。
- 待办：建立集中、不可变的命名策略，至少区分内部生成归档、Step1 留存依赖的浅扫描、完整制品扫描和不可信外部归档；要求生产调用点显式选择策略。先在命名策略下保持现有行为，再独立收紧不可信外部归档的膨胀率、解压总量、条目数和嵌套限制。
- 验收：所有生产调用点都有可审计的显式策略；调整任一策略不改变其他策略的行为或缓存身份；现有归档语义、失败关闭结果和性能基线无回退；不可信策略有高膨胀率、超限总量、过多条目、过深嵌套及正常大型 JAR 的正反例和资源预算验证。

历史 ZIP 的所有者决定已归档到
[`docs/archive/2026-07-22-historical-zip-audit.md`](docs/archive/2026-07-22-historical-zip-audit.md)。

## 2. 证明 legacy Step4 源码 diff 的语义解析完整性

- 优先级：P2。执行状态：待执行。验证状态：binary 权威路径已消除此依赖；显式 legacy/fallback 路径中的静默漏识别风险仍待修复和验证。
- 迁移进度（2026-08-09）：`binary_strict` 与成功的 `binary_with_legacy_fallback` binary generation 已使用 ASM 最终制品事实、runtime-effective 裁决和独立 Oracle，源码只作 overlay，因此本项不再影响 binary 权威。`legacy`、`shadow` 以及 binary generation 整体失败后另起的纯 legacy generation 仍会使用旧源码 diff，不能把 binary 能力倒推为旧路径已修复。
- 已核实事实：依赖源码目录缺失、非 Git 仓库、old/new ref 无法固定、fetch 失败、`git diff` 命令异常和超时等显式失败，会写入逐依赖 gitdiff 证据、`dependency_analysis_status.*`、`summary.txt`、`timeouts.json` / `git_ref_pending.json` 和 `.runtime/observability/step4_timing.csv`。源码 diff 失败后还会自动尝试发布 JAR 方法体字节码对比；兜底也失败时，状态为分析不完整且禁止按无变化处理。
- 已核实事实：`parse_gitdiff_apis()` 当前主要用正则从 Java/Kotlin diff 提取方法签名和方法体变化，没有输出输入文件/变更块/声明的解析覆盖率、未识别语法数量或 parser completeness。只要 `git diff` 命令成功，非空 diff 解析出 0 条 API 也会作为成功运行进入 `gitdiff_runs`，随后可能显示为 `no_source_change`；错误 module/path 选择导致空 diff 也缺少独立的范围完整性证明。
- 风险：新语法、复杂或多行声明、注解/泛型/record/Kotlin 特性、路径过滤、错误模块范围及正则未覆盖格式可能静默漏掉实现变化。JApiCmp 能保护二进制 API 结构变化，但源码解析静默漏失不会触发“源码 diff 失败”的发布 JAR 方法体兜底，因此签名不变的行为变化可能被错误解释为未发现源码变化。
- 已确定边界：源码 diff 仅是 binary 模式的可选 overlay；在 legacy/fallback generation 中仍是权威输入之一。后续需确定 Java/Kotlin 分别使用 AST/PSI、编译产物方法体 diff、结构化 Git diff 或组合方案，以及文件重命名、生成源码、模块边界、不可编译 revision 和语言版本不支持时的失败边界。修复前不得把“命令成功且解析结果为 0”自动等同为语义覆盖完整。
- 待办：增加 diff 输入清单和解析覆盖账本，至少记录选中的 repo/module/ref/commit、Java/Kotlin 变更文件数、hunk 数、候选声明数、成功解析数、未识别数、过滤文件及稳定原因码；空 diff 必须证明选定模块在固定 commit pair 间确实无适用文件变化。存在未识别适用变更时，自动尝试独立的发布 JAR 方法实现对比；两条路径均不完整时输出 `implementation_check_status=failed/partial`，禁止 `can_treat_as_no_change=true`。
- 待办：为解析器建立与生产实现独立的 Oracle 和 mutation，包括复杂 Java/Kotlin 声明、注解、泛型、嵌套/匿名类型、record、构造器、字段/静态常量、文件移动、模块路径错误、过滤误命中、非空 diff 返回零行及故意删除解析规则；证明质量门能够发现静默漏识别。
- 验收：任何适用的非空源码差异必须被解析为具体变化、被明确分类为非 API/非实现差异，或产生带文件/hunk/原因码的覆盖缺口，不能静默消失；`no_source_change` 仅在范围身份和解析覆盖均完整时出现；源码解析缺口能触发 JAR 行为兜底且逐依赖状态保留原始缺口；真实工程中 Oracle 已确认的签名不变实现变化漏报为无变化的数量为 0。
