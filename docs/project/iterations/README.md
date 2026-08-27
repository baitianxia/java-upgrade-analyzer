# 开发记录

本目录保存有时间边界的设计和实施计划。记录说明当时准备做什么，不自动证明计划已经完成，也不能覆盖当前系统文档。

- [2026 年 7 月历史记录](historical-2026-07/README.md)：原 `docs/superpowers/` 下的 plans 与 specs，迁移后保持正文内容不变。

新的开发记录应明确目标、范围、输入事实、验收方法、实际结果和未完成项。只有实际验证成立且已回写 `docs/system/` 的内容，才属于当前系统语义。

- [2026-08-27 跨阶段正确性、可靠性与性能修复](2026-08-27-cross-stage-remediation.md)：Step1～Step6、binary-first、门禁、基础设施、文档与性能证据的逐项核对、修复和验证结果。
- [2026-08-27 binary-first 27GB 性能收敛](2026-08-27-binary-27gb-performance.md)：针对 802 制品、750 万调用边和 29GB generation 的独立验证换页、随机 I/O、内存与 CPU 利用率优化；目标 Windows 完整复跑仍是显式未完成证据。
