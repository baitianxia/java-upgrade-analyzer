# 文档地图

本文档用于说明工程文档的阅读入口和目录职责。

## 快速入口

| 读者 | 建议先看 | 用途 |
|---|---|---|
| 使用者 | [../README.md](../README.md) | 快速运行、常见输入、主要产物 |
| Claude Code | [../SKILL.md](../SKILL.md) | 执行协议、交互硬规则、状态机约束 |
| 人工复核人 | [user/outputs.md](user/outputs.md) | `.upgrade-report/` 产物、复核顺序、状态语义 |
| 所有维护者 | [developer/constitution.md](developer/constitution.md) | 工程宪法、不可违背的原则性约束 |
| 维护者 | [developer/architecture.md](developer/architecture.md) | 当前架构、Step1~Step6 职责、状态模型 |
| Step5 修改者 | [developer/step5-design.md](developer/step5-design.md) | 调用链、字节码、反射、alerts 台账语义 |
| 测试/发布负责人 | [developer/quality.md](developer/quality.md) | 质量门禁、测试矩阵、真实项目验证口径 |

## 目录职责

```text
docs/
├── README.md                 # 文档地图
├── user/                     # 面向使用者和人工复核
│   └── outputs.md
├── developer/                # 面向维护、设计和质量保障
│   ├── constitution.md
│   ├── architecture.md
│   ├── step5-design.md
│   ├── quality.md
│   └── technical-sharing.md
└── archive/                  # 历史设计资料和已归档决策
```

## 根目录保留什么

根目录只保留高频入口和 Skill 必需文件：

- `README.md`：使用者快速入口；
- `SKILL.md`：Claude Code 执行分析任务时的运行时规则；
- `RUNBOOK.md`：详细命令手册；
- `CHECKPOINT_RULES.md`：最小交互硬规则；
- `TODO.md`：待优化项；
- `scripts/`、`tests/`、`references/`、`agents/`：正式代码与规则资源。

打包产物放在 `dist/`，运行报告放在 `.upgrade-report/`，这两类都不应作为源码结构的一部分阅读。
