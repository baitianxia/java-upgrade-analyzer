# Claude Code Skill 发现与触发优化设计

## 目标

让 Claude Code 在用户使用自然语言提出 Java 升级影响问题时，更稳定地自动选择 `java-upgrade-analyzer`，并在加载后正确进入统一调度流程。

本次只调整 Skill 元数据、入口文档结构、安装交付约束和触发评估，不修改 Step1～Step6 的分析算法或结论语义。

## 已核实的问题

1. `/java-upgrade-analyzer` 可以直接调用，证明 Skill 已被 Claude Code 正确发现。
2. 自动选择 Skill 时，Claude Code 主要依据 `SKILL.md` frontmatter 中的 `description`；完整正文尚未加载。
3. 当前描述未直接覆盖“升级影响分析”“依赖删除影响”“哪些业务受影响”“JAR/API 变化”等常见表达。
4. 当前 `SKILL.md` 为 665 行，超过 Claude Code 官方建议的 500 行。过长不会直接导致发现失败，但会增加加载后遗漏关键入口规则的风险。
5. `dist/` 中存在多个目录结构不一致的 ZIP，容易让使用者选错交付包。

## 方案

### 1. 元数据采用双层触发描述

`description` 保留完整的核心语义，确保不支持 `when_to_use` 的旧版 Claude Code 仍可匹配；`when_to_use` 补充自然语言触发短语和场景关键词。

核心关键词必须靠前：

- Java 升级影响分析
- 兼容性评估
- 依赖/JAR 升级、降级、删除、替换
- API 变化与业务调用链影响
- JDK、Spring Boot、Spring Framework、Jakarta

描述必须同时说明“做什么”和“什么时候使用”，不得只写内部六步流程。

### 2. 精简 `SKILL.md` 为运行入口

主文件只保留 Claude 每次执行都必须掌握的内容：

1. 触发范围与不适用范围；
2. 首轮输入协议和统一入口；
3. checkpoint 硬中断规则；
4. Step1～Step6 的职责概览；
5. 即时调用链查询例外；
6. 按需读取的一级文档索引。

详细命令、字段、恢复示例和专项规则分别保留在 `RUNBOOK.md`、`CHECKPOINT_RULES.md` 与 `references/`。所有必要参考从 `SKILL.md` 直接链接，避免多层跳转。

目标：`SKILL.md` 不超过 500 行，关键启动规则出现在前 100 行内。

### 3. 明确唯一安装和交付结构

README 明确支持两种安装位置：

```text
~/.claude/skills/java-upgrade-analyzer/SKILL.md
<project>/.claude/skills/java-upgrade-analyzer/SKILL.md
```

发布时只保留一个面向 Claude Code 的 ZIP，压缩包根目录必须是 `java-upgrade-analyzer/`，其下一层直接包含 `SKILL.md`。旧的、根目录结构不一致的交付包不再作为推荐入口。

安装说明同时提供两个验证动作：

1. `/java-upgrade-analyzer` 可见并可直接调用；
2. 新会话询问“分析这个 Java 系统的升级影响”时，Claude 自动选择该 Skill。

### 4. 建立触发评估集

增加机器可读的评估清单，至少覆盖三类用例：

#### 应自动触发

- 分析当前 Java 系统的升级影响。
- commons-lang 被删除会影响哪些业务？
- 评估 Spring Boot 2 升级到 3 的兼容性风险。
- 这些 Maven 依赖升级后哪些 API 和调用链受影响？
- JDK 8 升级到 17 是否存在运行风险？

#### 不应自动触发

- 修复一个普通 Java 空指针异常。
- 格式化当前 Java 文件。
- 优化一段与升级无关的 SQL。
- 为现有方法补充单元测试。

#### 触发后的执行契约

- 必须先读取 Step1 静态前置协议；
- 必须确认输入模式和目标模块；
- 必须通过 `scripts/run_step.py` 调度；
- 遇到 checkpoint 必须停止并等待用户答复；
- 不得只输出泛泛的升级建议代替实际分析。

静态测试验证 frontmatter、关键词覆盖、行数和交付目录结构；真实 Claude Code 评估在全新会话中分别验证自动触发与不触发用例。

## 兼容性与风险控制

- 不设置 `disable-model-invocation: true`，保证 Claude 可以自动选择该 Skill。
- 保留 `description` 中的全部核心触发语义，不依赖 `when_to_use` 才能工作。
- 精简只移动文档内容，不删除流程约束；移动前后使用契约测试核对关键规则仍可达。
- 不把 Skill 改成默认 subagent 执行，避免丢失当前会话、用户输入和 checkpoint 交互上下文。
- 触发属于模型选择，无法承诺绝对 100%；直接使用 `/java-upgrade-analyzer` 始终作为确定性入口。

## 验收标准

1. frontmatter 可被 YAML 正确解析，`name`、`description`、`when_to_use` 均符合 Claude Code 规则。
2. `description` 独立包含核心能力及主要触发场景。
3. `SKILL.md` 不超过 500 行，关键入口规则位于前 100 行。
4. 应触发、不应触发和执行契约评估均有明确断言。
5. Claude Code 发布 ZIP 只有一个合法 Skill 根目录，解压后路径符合官方发现规则。
6. 原有单元测试、核心 smoke 和 Skill 文档契约测试全部通过。
7. 至少使用全新 Claude Code 会话验证一次自然语言自动触发和一次负例不触发，并如实记录模型、版本和结果。
