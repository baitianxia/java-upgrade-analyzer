# 当前工作上下文

本文是维护者和 Agent 开始工程工作时的首要文档入口，只负责导航当前基线，不重复系统合同。

## 当前系统基线

- Step4～Step6 只有一条 binary-first 主线；源码是解释覆盖层，不创建二进制事实或可执行边。
- 当前架构和状态模型以[系统架构](../system/architecture/README.md)为准。
- 诊断、交互和输出边界分别以[系统契约](../system/contracts/README.md)和[运行文档](../system/operations/README.md)为准。
- 质量结论必须绑定实际执行证据；当前门禁见[质量与测试](../system/quality/README.md)。

## 当前项目状态

- 当前开发记录是 [2026-08-27 binary-first 27GB 性能收敛](iterations/2026-08-27-binary-27gb-performance.md)：第二轮实现、固定 400 JAR 性能证据重录和最终工作树完整 Release 已通过；changed 完整流水线独立复采相对上一记录提升 52.924%。尚待关闭的是目标 Windows 10/Xeon/32GB 主机上的 27GB 实机复跑，不能用本地合成规模门替代该结论。
- 当前增量优化为闭世界路径复核增加有界 evidence 工作集缓存：关系查询同时带回 member/linkage 状态，重复路径不再为同一 evidence 重新执行状态查询；缓存达到 8192 项后按 LRU 淘汰，旧适配器和 orphan evidence 保留精确回退。Step4 相关定向回归 219/219 通过，`git diff --check` 通过；尚未在目标 Windows 27GB 数据上重新录制墙钟和 RSS，因此不把本地回归计为目标机达标。
- 本轮继续把大 sidecar 的字段索引和原始 SHA-256 合并到同一次 mmap 生命周期；结构化索引失败仍使用原有完整字节哈希，字段偏移和完整性身份均不放宽。新增流式摘要测试后，Step4 相关定向回归为 220/220 通过；目标 Windows 27GB 的墙钟和 RSS 仍需实机复测。
- trace 建图进一步采用窄列投影，只读取 direct-edge identity、caller、kind 和 symbolic target 六个字段，省去建图阶段对 `edge_json` 的读取和 Python 对象搬运；220 项 Step4 定向回归仍通过。该改动减少单次扫描成本，尚未替代目标机完整复测。
- 上一份完成记录是 [2026-08-27 跨阶段正确性、可靠性与性能修复](iterations/2026-08-27-cross-stage-remediation.md)。
- `historical-2026-07/` 是迁移前形成的历史设计和计划记录，不是当前开发授权。
- 尚未完成的两个候选事项位于 [Roadmap](roadmap/README.md)，两者均需先满足各自的证据或观测条件。

## 开始修改前

1. 先读取本页与受影响的 `docs/system/` 唯一所有者文档；
2. 用代码、测试、日志或最小复现确认实际问题；
3. 只在需要历史原因时读取 `project/iterations/`、`project/audits/` 或 `archive/`；
4. 变更后执行与风险相称的测试，并同步更新当前文档和引用路径。
