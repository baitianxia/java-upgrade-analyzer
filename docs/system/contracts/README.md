# 系统契约

本目录描述跨步骤或面向调用方的稳定语义。

- [跨步骤诊断契约](diagnostics.md)：诊断 schema、原因码、输出位置和失败关闭规则。
- [`SKILL.md`](../../../SKILL.md)：Claude Code 执行协议、步骤和恢复规则。
- [`CHECKPOINT_RULES.md`](../../../CHECKPOINT_RULES.md)：运行时实际读取的最小交互规则。
- [`scripts/step_manifest.json`](../../../scripts/step_manifest.json)：可执行步骤、门禁和交互定义。

根目录的运行时合同保留在那里，是因为 Skill 分发和程序读取依赖稳定相对路径；它们仍属于当前系统契约，不是项目过程文档。
