# Binary-first Java 升级分析：技术分享

## 问题模型

Java 升级分析不是“源码里有没有某个字符串”，而是三个连续问题：目标运行时实际加载什么、这些有效制品发生了什么变化、业务入口能否静态触达这些变化。任何一层身份不完整，后续都不能给出更强结论。

## 单一事实链

```text
base/current 最终制品 + 完整目标 JDK + RuntimeProfile
  -> class/member/resource facts
  -> target-independent runtime reconciliation
  -> change decision + projection freeze
  -> binary trace
  -> independent Oracle validation
  -> atomic generation activation
  -> Step4/5/6 human reports
```

源码位于旁路 overlay：它可以把 JVM descriptor 翻译为源码位置、参数名和注释语义，但不能选择 runtime provider、创建变化事实或证明可执行边。

## 为什么以 generation 为中心

所有正式 sidecar、SQLite 和验证附件绑定同一 analysis context 与内容身份。Step4、Step5、Step6 不再彼此复制并重新解释 CSV，因此不会出现一个阶段修正事实、另一个阶段仍消费旧投影的情况。耗时和临时路径被排除在 generation 身份之外，既能观察性能又保持重复运行稳定。

## 依赖身份

每条结果同时携带 logical lineage、base/current coord/version、物理制品 SHA、runtime origin 和 loader slot。人读报告按依赖分组，不允许只显示 API 而让复核人猜哪个包引起变化。

## 结果表达

静态触达采用 `reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed` 四态；impact、static linkage 和 runtime verification 是独立维度。这样避免把“找到静态路径”夸大成运行时事故，也避免把“静态没找到”伪装成安全。

## 独立验证

生产事实主要由固定 ASM helper 生成，Oracle 使用独立的 JDK/classfile/resource 读取路径复算关键事实，并校验正式结果闭合。Oracle 不复用生产 decision/tracer；验证失败的 generation 永不激活。

## 人机输出分层

- `.runtime/binary_authority/`：机器权威和审计；
- `evidence/api_changes/`：按依赖复核变化；
- `evidence/call_chain/`：按依赖/API 复核系统路径；
- `deliverables/`：最终结论、范围和完整明细。

普通使用者从 `changed_dependencies.md` 开始，不需要打开 SQLite 或拼接 sidecar。CSV 适合筛选，Markdown 解释结论和阅读路径。

## 工程收益

- 准确性：事实、runtime reconciliation、trace 和 Oracle 绑定同一上下文；
- 用户体验：依赖维度、中文摘要、明确边界和连续阅读路径保留；
- 性能：snapshot cache、SQLite 批处理、一次事实构建多阶段复用，并提供真实阶段计时。

这次替换改变的是引擎，不是产品原则：证据完整、表达诚实、人工可读、交互必要且前置、性能可测量仍然是验收标准。
