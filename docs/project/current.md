# 当前工作上下文

本文是维护者和 Agent 开始工程工作时的首要文档入口，只负责导航当前基线，不重复系统合同。

## 当前系统基线

- Step4～Step6 只有一条 binary-first 主线；源码是解释覆盖层，不创建二进制事实或可执行边。
- 当前架构和状态模型以[系统架构](../system/architecture/README.md)为准。
- 诊断、交互和输出边界分别以[系统契约](../system/contracts/README.md)和[运行文档](../system/operations/README.md)为准。
- 质量结论必须绑定实际执行证据；当前门禁见[质量与测试](../system/quality/README.md)。

## 当前项目状态

- 当前没有在 `project/iterations/` 中登记为活动或已授权的开发轮次。
- `historical-2026-07/` 是迁移前形成的历史设计和计划记录，不是当前开发授权。
- 尚未完成的两个候选事项位于 [Roadmap](roadmap/README.md)，两者均需先满足各自的证据或观测条件。

## 开始修改前

1. 先读取本页与受影响的 `docs/system/` 唯一所有者文档；
2. 用代码、测试、日志或最小复现确认实际问题；
3. 只在需要历史原因时读取 `project/iterations/`、`project/audits/` 或 `archive/`；
4. 变更后执行与风险相称的测试，并同步更新当前文档和引用路径。
