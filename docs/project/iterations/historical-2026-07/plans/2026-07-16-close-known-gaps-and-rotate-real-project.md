# Close Known Gaps And Rotate Real Project Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复当前已确认的测试隔离与 Step5 重载推断问题，清理已完成待办，并用新的真实项目逐 API 核验准确性和性能。

**Architecture:** 保持制品 SHA 缓存的生产语义不变，在测试边界清理进程级缓存；类型推断在源码表达式类型与目标 varargs 兼容层修复，不对单一 API 硬编码。真实项目阶段继续使用独立字节码 Oracle、闭集 API 对账、性能预算和测试轮次复盘。

**Tech Stack:** Python 3 unittest、Java/JDK javap/jdeps、Maven、现有 Step4/Step5 质量门禁与真实项目 runner。

## Global Constraints

- 不降低证据强度，不使用 `target/classes` 替代最终制品。
- 每个生产修复必须先有失败回归。
- 真实项目逐 API 核验不得抽样，分析器输出不得反向充当 Oracle。
- 当前工作树已有其他改动，不回退或覆盖无关修改。

---

### Task 1: Test Cache Isolation

**Files:**
- Modify: `tests/test_step5_key_matching.py`

- [ ] 增加或调整测试生命周期，使每个测试前后清理 `clear_immutable_artifact_parse_cache()`。
- [ ] 先用相邻两用例复现顺序依赖，再验证两个顺序均通过。
- [ ] 运行 core accuracy benchmark，确认门禁不再受测试顺序影响。

### Task 2: Boolean And Varargs Overload Inference

**Files:**
- Modify: `scripts/enhanced_source_analyzer.py` 或实际类型推断归属模块
- Modify: `scripts/signature_utils.py` 或实际签名兼容归属模块
- Modify: `tests/test_step5_key_matching.py`

- [ ] 为比较、逻辑、取反和括号表达式的 `boolean` 推断增加失败测试。
- [ ] 为 `(boolean, String, Object...)` 匹配 `(boolean, String)` 与额外参数增加失败测试，并保留错误重载负例。
- [ ] 最小实现通用表达式类型与 varargs 兼容规则。
- [ ] 运行定向测试及 Commons Text 对应回归。

### Task 3: TODO Truthfulness

**Files:**
- Modify: `TODO.md`

- [ ] 删除状态表中确认已完成的 1-11 项及其历史章节。
- [ ] 只保留尚未完成或新真实项目产生的待办，并保证每项状态单一明确。
- [ ] 校验文档不再同时出现“已完成”和“待处理问题”的冲突描述。

### Task 4: Local Quality Gates

**Files:**
- No planned production edits unless a gate exposes a new defect.

- [ ] 运行完整 unittest。
- [ ] 运行 `quality_gate.py --profile step5`。
- [ ] 运行 release 门禁；缺少真实项目输入时明确记录，不使用通过字样掩盖跳过。

### Task 5: New Real Project Rotation

**Files:**
- Modify/Create: matching real-project fixture, regression and retrospective files only when evidence requires them.

- [ ] 从未覆盖拓扑矩阵选择不同真实 Git 项目并固定 revision。
- [ ] 构建最终可部署制品并记录 SHA-256。
- [ ] 由独立 Oracle 穷举目标 API，运行 Step5 后闭集逐 API 对账。
- [ ] 审计性能、解析失败、`uncertain`、`not_analyzed` 和额外输出。
- [ ] 发现问题时先写最小失败回归，再修生产代码；无新场景后形成复盘与轮换结论。

### Task 6: Final Verification

**Files:**
- Modify: only files required by findings from Task 5.

- [ ] 重跑受影响测试、完整门禁和真实项目 Oracle。
- [ ] 检查 `git diff --check`、任务状态和未验证项。
- [ ] 仅在所有要求均有新鲜证据时报告完成。
