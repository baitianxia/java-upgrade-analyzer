# 测试轮次复盘门禁设计

## 目标

把“真实项目发现问题 -> 修复 -> 再换项目”升级为可审计的收敛闭环。每轮测试必须回答：发现了什么、为什么上一轮没有发现、修复属于架构改进还是案例补丁、增加了哪些覆盖、性能是否变化、还有什么债务、下一轮为什么选择该项目。

## 设计

新增独立的 `test_round_retrospective.py`。它只消费真实项目 runner JSON、质量信号审计 JSON、可选的人工/Agent finding review 和历史台账，不复用分析器结论充当真值。脚本生成机器可读 JSON、可读 Markdown 和追加式 history JSON。

Runner 与 audit 通过 canonical payload SHA-256 绑定；复盘同时校验项目 Git revision/dirty 状态、API 与边 Oracle 计数、性能预算和完整性。旧中间输出在任务开始前清理。输入缺失或损坏时也必须生成 `blocked` 复盘，而不是只留下异常退出。

每个 finding 必须有稳定 ID，并填写 `root_cause_family`、`escape_reason`、`optimization_action` 和 `status`，避免 P2/P3 信号未经解释便消失。P0/P1 还必须填写 `resolution_scope` 和 `regression_test`。缺失必填字段时复盘门禁失败。`resolution_scope=case_patch` 对 P0/P1 永远失败；同一根因族跨轮重复时必须标记 `architecture_review_required`。

每轮汇总以下事实：

- 项目、revision、case 生命周期和 API/edge oracle 完整性；
- 新增缺陷数、重复根因数和严重度；
- 新增拓扑覆盖与仍缺失拓扑；
- fixture debt 和回归测试引用；
- 性能预算及回归信号；
- 项目决策：`continue`、`guard`、`rotate` 或 `blocked`。

## 门禁

`quality_gate.py --profile step5|release` 在真实项目和质量信号审计后强制运行复盘脚本。以下情况阻塞：

- P0/P1 finding 未归因、未说明逃逸原因或未沉淀回归；
- P0/P1 只做案例补丁；
- 同一根因族重复出现但没有架构复审动作；
- oracle、coverage、fixture debt 或性能结果不完整；
- 没有给出下一轮项目决策和依据。

`rotate` 还必须指定不同于当前项目的下一项目，以及至少一个当前尚未覆盖的目标拓扑。Round identity 只使用真实结果和 audit 的语义字段，不包含时间戳、输出路径等非语义元数据；重跑旧轮次原位更新 history，不能改变跨轮趋势顺序。

当本轮无新增 P0/P1、真值和性能门禁完整、fixture debt 为零且当前项目没有新增拓扑时，建议 `rotate`；仍有新增覆盖时建议进入 `guard` 或继续收敛。该建议不能覆盖显式阻塞信号。

## 测试

使用纯字典 fixture 覆盖：干净轮次、finding 字段缺失、案例补丁、重复根因、性能回归、oracle 不完整、拓扑新增及项目轮换。质量门禁测试保证复盘任务位于 signal audit 之后，并且真实项目被跳过时不会伪造复盘完成。
