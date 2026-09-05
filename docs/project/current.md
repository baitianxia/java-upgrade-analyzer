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
- immutable SQLite 读连接增加 256MB mmap 和 64MB 页缓存上限提示；不支持这些 SQLite 提示时自动保留默认行为，查询结果和失败关闭语义不变。220 项定向回归通过，目标机 RSS/墙钟仍需实测。
- 本轮在独立验证生命周期内为会被多个校验域消费的 `authoritative_change_facts`、runtime semantic `rows` 和 entrypoint `records` 增加有界磁盘行 spool；首次读取仍完整解析并校验源文件，后续读取复用压缩行而不把多 GiB JSON 展开到 Python 堆。源文件大小/mtime 变化会阻断混合事实，spool 创建、读写或清理失败则丢弃派生缓存并从权威 sidecar 精确续读，不改变事实集合。direct-edge replay 同时把 `edge_json` 的严格布尔判定下推到 SQLite，并对高重复的小型 edge payload 使用 8192 项有界解码缓存，避免数百万次 Python JSON 对象构造；Step4 定向回归 223/223 通过。目标 Windows 27GB 墙钟、CPU 和 RSS 尚未复测，不能把本地微基准外推为目标机倍数结论。
- 上一份完成记录是 [2026-08-27 跨阶段正确性、可靠性与性能修复](iterations/2026-08-27-cross-stage-remediation.md)。
- `historical-2026-07/` 是迁移前形成的历史设计和计划记录，不是当前开发授权。
- 尚未完成的两个候选事项位于 [Roadmap](roadmap/README.md)，两者均需先满足各自的证据或观测条件。

## 开始修改前

1. 先读取本页与受影响的 `docs/system/` 唯一所有者文档；
2. 用代码、测试、日志或最小复现确认实际问题；
3. 只在需要历史原因时读取 `project/iterations/`、`project/audits/` 或 `archive/`；
4. 变更后执行与风险相称的测试，并同步更新当前文档和引用路径。
