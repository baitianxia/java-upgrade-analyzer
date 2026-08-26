# 文档中心

本文档是仓库文档的总入口。文档按“当前系统事实、项目过程、历史资料”分域，避免当前契约、待办计划和历史设计互相覆盖。

## 日常入口

1. [当前工作上下文](project/current.md)：维护者和 Agent 开始工作时的首要入口。
2. [当前系统文档](system/README.md)：产品边界、架构、跨步骤契约、运维说明和质量下限。
3. [项目文档](project/README.md)：路线图、开发记录、审计和文档治理。
4. [使用说明](../README.md)：用户快速开始、输入方式、交互和结果阅读。
5. [历史文档](archive/README.md)：仅用于解释旧设计或目录迁移，不指导当前实现。

## 权威域

| 位置 | 权威性 | 回答的问题 | 不能用于 |
|---|---|---|---|
| `system/` | 当前系统规范 | 系统现在是什么、必须保持哪些契约和质量边界 | 宣称某个计划已实施或某次验证已通过 |
| `project/current.md` | 当前开发导航 | 当前应读取哪些文档、是否存在活动开发记录 | 改写系统契约 |
| `project/roadmap/` | 规划候选 | 后续可能做什么、进入条件是什么 | 直接授权实现或宣称能力存在 |
| `project/iterations/`、`project/audits/` | 项目记录与证据 | 当时计划、设计或审计发现了什么 | 自动覆盖当前 `system/` 语义 |
| `archive/` | 历史 | 解释旧状态和迁移原因 | 作为当前开发默认输入 |
| 根目录运行文档 | Skill 分发合同 | Claude Code 如何执行、恢复和交互 | 承载维护治理或历史设计 |

## 目录结构

```text
docs/
├── README.md
├── system/
│   ├── product/
│   ├── architecture/
│   ├── contracts/
│   ├── operations/
│   └── quality/
├── project/
│   ├── current.md
│   ├── roadmap/
│   ├── iterations/
│   ├── audits/
│   └── governance/
└── archive/
    ├── migration-records/
    └── legacy/
```

## 根目录保留项

当前工程是可分发的 Claude Code Skill，因此以下文件有运行时或高频入口职责，不迁入 `docs/`：

- `README.md`：使用者入口；
- `SKILL.md`：Claude Code 执行合同；
- `RUNBOOK.md`：可随 Skill 分发的命令手册；
- `CHECKPOINT_RULES.md`：运行时读取的最小交互规则；
- `AGENTS.md`：仓库级工程约束。

## 修改规则

- 当前系统语义只修改 `system/` 中的唯一所有者文档；项目记录通过链接引用，不复制一份新真相。
- 新计划先进入 `project/roadmap/`；设计和验证记录不得仅凭“已计划”改写为“已实现”。
- 历史文档保留当时语境。需要恢复旧正文时优先使用 Git 历史，不把旧规则重新提升为当前规范。
- 修改路径后必须同步更新当前文档、运行文档、测试夹具中的引用，并执行链接检查和受影响的文档契约测试。
