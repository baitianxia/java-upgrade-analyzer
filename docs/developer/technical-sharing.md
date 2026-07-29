# Java Upgrade Analyzer：把 Java 升级风险变成可复核证据链

## 文档定位

`java-upgrade-analyzer` 是一个面向 Java 系统升级场景的兼容性分析 Skill。它不是依赖版本 diff 工具，也不是单纯的源码扫描脚本，而是一套围绕“证据链”设计的升级影响分析系统。

它要回答的核心问题是：

```text
依赖升级后，到底哪些 API 变了？
这些变化是否真的触达当前业务系统？
如果无法确认，证据链断在哪里？
```

这篇文档从工程设计视角介绍：我们遇到了什么问题，为什么传统方法不够，系统用了哪些技术，如何把这些技术组合成一条证据生产线，以及如何保证分析结论可信。

## 目录

- [一、从一个升级风险场景说起](#一从一个升级风险场景说起)
- [二、我们真正解决的不是 diff，而是证明](#二我们真正解决的不是-diff而是证明)
- [三、核心模型：三层事实](#三核心模型三层事实)
- [四、总体架构：证据生产线](#四总体架构证据生产线)
- [五、关键技术一：从最终制品提取构建事实](#五关键技术一从最终制品提取构建事实)
- [六、关键技术二：用多源证据构建 API 变化事实池](#六关键技术二用多源证据构建-api-变化事实池)
- [七、关键技术三：用反向图证明变化是否触达业务](#七关键技术三用反向图证明变化是否触达业务)
- [八、关键技术四：把框架和动态调用纳入证据体系](#八关键技术四把框架和动态调用纳入证据体系)
- [九、关键技术五：用状态机约束 Agent 执行](#九关键技术五用状态机约束-agent-执行)
- [十、结果表达：五态而不是二值判断](#十结果表达五态而不是二值判断)
- [十一、端到端示例：removed jar 风险如何被证明](#十一端到端示例removed-jar-风险如何被证明)
- [十二、工程保障：可复核、可恢复、可回归](#十二工程保障可复核可恢复可回归)
- [十三、代码阅读地图](#十三代码阅读地图)
- [十四、总结](#十四总结)

## 一、从一个升级风险场景说起

假设一次升级删除了一个旧依赖：

```text
base:    com.example:legacy-lib:1.0.0
current: com.example:legacy-lib 不存在
```

这个变化看起来很简单，但真正的问题并不简单。

我们不能直接说“删除依赖就一定影响业务”，因为业务可能根本没有使用它。也不能因为业务源码里没有 import 就说“没有风险”，因为 current 最终制品里的其他运行时依赖可能仍然调用这个旧 jar 的 API。

因此，一个可靠的分析系统必须连续回答三件事：

```text
1. 这个 jar 真的从最终制品里消失了吗？
2. 它被删除前暴露过哪些可被调用的 API？
3. 当前业务或运行时依赖是否仍然触达这些 API？
```

这就是本工程的基本思路：不直接下结论，而是逐层生产证据。

## 二、我们真正解决的不是 diff，而是证明

Java 升级分析里，很多传统方法只能解决一部分问题。

| 方法 | 能回答什么 | 回答不了什么 |
|---|---|---|
| dependency diff | 哪些依赖版本变了 | API 具体变了什么、业务是否受影响 |
| grep 源码 | 显式文本引用在哪里 | 运行时依赖、反射、框架隐式调用 |
| JApiCmp | old/new jar 的二进制 API 差异 | 当前系统是否使用这些差异 API |
| 源码调用图 | 业务源码调用关系 | 依赖 API 是否真实变化、字节码层引用 |
| Agent 自动执行 | 自动跑流程 | 输入不完整时容易猜错或越过确认点 |

所以本工程不是把这些方法简单堆起来，而是把它们放进一条明确的证明链路中：

```text
先证明分析对象真实，
再证明 API 变化真实，
最后证明业务触达真实。
```

## 三、核心模型：三层事实

整个工程围绕三层事实展开。

| 事实层 | 要回答的问题 | 主要技术 |
|---|---|---|
| 构建事实 | 当前系统最终制品真实带了什么 | artifact 解包、fat jar/war 结构识别、Maven 坐标补全 |
| 变化事实 | 升级前后依赖 API 真实变了什么 | JApiCmp、git diff、removed jar 符号导出、CSV 契约 |
| 触达事实 | 变化 API 是否触达业务系统 | tree-sitter AST、字节码解析、反向调用图、框架/反射补偿 |

这三层事实对应三个核心 Step：

```text
Step1  证明构建事实
Step4  证明变化事实
Step5  证明触达事实
```

Step2 负责把项目上下文收敛到统一状态，Step3 提供背景风险线索，Step6 把证据组织成最终报告。

这个模型的价值在于职责清晰：

- Step1 不判断 API 风险，只回答系统真实打包了什么；
- Step4 不判断业务影响，只回答 API 真实变了什么；
- Step5 不重新定义 API 变化，只回答变化是否触达业务。

## 四、总体架构：证据生产线

系统整体是一条带状态的证据生产线：

```text
Step1 构建事实
  -> Step2 上下文收敛
  -> Step3 背景风险线索
  -> Step4 API 变化事实池
  -> Step5 业务触达证明
  -> Step6 证据报告
```

从输入到输出，每一步都把上一层的模糊问题转换成下一层可消费的结构化证据。

| 阶段 | 输入问题 | 技术手段 | 输出证据 |
|---|---|---|---|
| Step1 | 系统真实带了什么依赖 | 构建产物解析、fat jar/war 解包、Maven 坐标补全 | `evidence/dependencies/dep_changes.csv`、`evidence/dependencies/build_provenance.json` |
| Step2 | 分析哪个模块和源码范围 | Maven reactor 解析、project scope 推导、上下文归一化 | `evidence/context/context.json`、`evidence/context/dep_graph.json` |
| Step3 | 背景风险有哪些 | 规则包扫描、源码/资源文本扫描、JDK/Jakarta/Spring 规则 | `s3_*.csv`、`s3_*.txt` |
| Step4 | API 真实变了什么 | JApiCmp、git diff、removed jar 符号导出、CSV 契约 | `all_changed_apis.csv` |
| Step5 | 变化是否触达业务 | AST、字节码、反向图、置信度追踪、动态调用补偿 | `alerts.csv`、`summary.json`、`by_api/*.json` |
| Step6 | 如何交付复核 | 多源证据聚合、分析完成状态归并、Markdown 报告生成 | `.runtime/findings/s6_findings.json`、`deliverables/report.md`、`deliverables/all-affected-dependencies.md`、`deliverables/all-impact-details.md` |

正式流程由 `scripts/run_step.py` 编排，并通过 `.upgrade-report/` 持久化所有关键证据。最终报告不是黑盒结论，而是可以沿文件回溯到每一步的输入、输出和证据来源。

Step6 的主报告固定先给依赖层面结论，再给 API 及调用关系，最后说明全部用户可见文件。`all-affected-dependencies.md/.csv` 保存本轮范围内全部依赖结果；`all-impact-details.md/.csv` 保存本轮范围内全部 API 结果及完整调用关系；同类 Markdown 与 CSV 使用相同数据和排序。`alerts.csv` 保留一行一条的原始分析记录，不承担面向用户的汇总阅读职责。

## 五、关键技术一：从最终制品提取构建事实

### 为什么需要

Java 项目的声明依赖不等于运行时依赖。Spring Boot fat jar、war、shade jar、多模块部署都会改变最终制品形态。如果从 `pom.xml` 出发，分析范围可能一开始就错。

### 用了什么技术

Step1 使用最终制品优先的分析方式：

- 通过 base/current 分支构建目标模块，或直接消费用户提供的 old/new artifact；
- 识别普通 jar、Spring Boot fat jar、war 等产物结构；
- 从 `BOOT-INF/lib`、`WEB-INF/lib` 等目录提取运行时依赖；
- 读取 jar 内 `META-INF/maven/**/pom.properties` 补 Maven 坐标；
- 坐标缺失时优先结合 Maven `dependency:list` 或 Gradle `runtimeClasspath` artifact inventory 与物理文件名补全；
- 构建输出漏掉 reactor/project 依赖身份时，只从目标模块运行时闭包补内部模块坐标：解析 Maven 有效属性或 Gradle 精确 project path，并保留构建工具已解析结果的优先级；
- 内部模块的唯一主归档可匹配自定义 `finalName`，但项目模型不能把最终制品中不存在的模块扩展为依赖事实；
- 把构建来源、artifact 路径、模块信息写入 `build_provenance.json`。

### 达成的效果

这一步把“项目配置里声明了什么”转换成“最终制品真实携带什么”。

后续 Step4 使用这些依赖定位 old/new jar，Step5 使用留存 artifact 分析业务字节码和运行时依赖。也就是说，构建事实决定了整条证据链的起点是否可信。

## 六、关键技术二：用多源证据构建 API 变化事实池

### 为什么需要

依赖版本变化不等于 API 风险。Step5 需要的是一个明确目标池：

```text
哪个依赖？
哪个 API？
是什么符号类型？
变化类型是什么？
证据来自哪里？
```

### 用了什么技术

Step4 使用三类主要技术构建 API 变化事实。

第一类是 JApiCmp。它对 old/new jar 做二进制兼容性分析，识别 class、method、field、constructor 的删除、签名变化、访问级别变化，以及 binary/source compatibility 标记。

第二类是依赖源码 git diff。如果用户提供了依赖源码，系统会匹配 old/new 版本对应的 git ref，再从源码 diff 中提取行为变化或源码级 API 变化线索。这补充了 JApiCmp 不擅长表达的行为变化。

第三类是 removed jar 符号导出。如果某个依赖被删除，new jar 不存在，系统会把 old jar 的 public/protected class、method、constructor 导出为目标池。这样即使依赖已经从 current 制品消失，Step5 仍然可以检查业务或其他运行时依赖是否还在触达旧 API。

所有变化最终统一写入：

```text
evidence/api_changes/all_changed_apis.csv
```

字段由 `scripts/s4_contract.py` 统一定义，包含 `coord`、`change_type`、`api_name`、`symbol_kind`、`api_signature`、`source`、`evidence_path` 等。

### 达成的效果

Step4 把“依赖版本变了”转换成“这些具体 API 发生了可复核变化”。

这使 Step5 不需要猜测分析目标，而是消费一个结构化、可校验、可追溯的 API 变化事实池。

## 七、关键技术三：用反向图证明变化是否触达业务

### 为什么需要

知道 API 变了，还不能说明当前系统受影响。我们需要证明变化 API 是否被业务源码、业务字节码或运行时依赖触达。

### 用了什么技术

Step5 的核心是“反向图 + 多证据融合”。

源码侧使用 tree-sitter Java AST 提取 class、method、import、参数、返回类型、局部变量、调用点和 receiver 类型。tree-sitter 不可用或解析不完整时，增强正则会兜底提取关键调用信息。

字节码侧解析最终制品中的业务 class 和 current 运行时依赖 jar。系统优先走 classfile constant pool 快路径，提取 method、field、constructor、class、invokedynamic 引用；复杂场景回退到 `javap`。

图模型上，Step5 不从所有业务入口正向遍历，而是从 Step4 给出的目标 API 反向追踪：

```text
callee_key -> caller edges
```

这让搜索围绕“变化 API”收敛，而不是扫描整个系统的所有调用可能性。

追踪过程中还引入置信度加权。高置信边 cost 低，可以走更远；低置信边 cost 高，会更早停止。这样既保留可靠多跳链路，又避免低质量候选无限扩散。

### 达成的效果

Step5 把 API 变化目标转换成 lookup key，再在源码图、字节码图、运行时依赖图和候选证据中反向查找 caller。

最终输出不是简单的“命中/未命中”，而是：

```text
是否触达业务；
触达路径是什么；
证据来自源码还是字节码；
如果无法确认，链路卡在哪里。
```

核心产物包括：

```text
evidence/call_chain/alerts.csv
evidence/call_chain/summary.json
evidence/call_chain/by_api/*.json
```

## 八、关键技术四：把框架和动态调用纳入证据体系

### 为什么需要

真实 Java 系统里，大量调用不表现为普通 `a.b()`：

- `Class.forName`；
- `getMethod` / `invoke`；
- MethodHandle；
- Java SPI；
- Spring bean 和注解；
- MyBatis mapper；
- 动态代理；
- 声明式 HTTP client；
- 配置文件和表达式语言。

如果系统只认普通调用图，就会系统性漏掉这些风险。

### 用了什么技术

工程引入两类补偿能力。

`framework_adapters.py` 面向框架机制，把 SPI、Spring、MyBatis、动态代理、声明式 HTTP client 等隐式关系转换为候选边或入口线索。

`indirect_usage_analyzer.py` 面向反射和资源线索，识别字符串类名、`Class.forName`、`getMethod`、`getField`、MethodHandle、资源文件中的类名或方法名等。

### 达成的效果

这些能力不承诺完美还原运行时，但它们能把动态调用从“完全不可见”提升为“有证据可复核”。

如果线索足够完整，系统可以形成可确认链路；如果证据不足，结果会进入 `uncertain` 或 `not_analyzed`，而不是被静默当成未命中。

## 九、关键技术五：用状态机约束 Agent 执行

### 为什么需要

这个 Skill 通常由 Agent 执行。Agent 的优势是自动化，但升级分析里很多节点不能自动猜：

- 多模块项目分析哪个部署模块；
- 依赖源码目录是否对应正确 Maven 坐标；
- old/new 版本应该匹配哪个 git ref；
- 图不完整时是否允许继续；
- 用户是否只想分析某个依赖。

### 用了什么技术

正式入口统一为 `scripts/run_step.py`，并通过两个状态文件约束流程。

`.upgrade-report/.runtime/state/main_state.json` 是唯一主状态和业务参数真相源，保存当前 Step、已完成 Step、每步输入输出、用户确认参数和待交互状态。

`.upgrade-report/.runtime/state/interaction.json` 只负责展示待确认问题，不参与求值。用户答复必须整理成结构化 `intent_patch`，再恢复到主状态。

### 达成的效果

状态机让流程可以中断、恢复、重跑，也防止 Agent 越过 checkpoint 或把自己的判断当成用户确认。

这解决的是分析流程的可信度问题。

## 十、结果表达：五态而不是二值判断

### 为什么需要

静态分析最危险的误用，是把“没找到”说成“没有风险”。

没找到可能只是因为依赖源码缺失、反射参数动态生成、框架隐式边无法还原、字节码命中无法回溯业务入口，或者方法重载无法安全消歧。

### 用了什么模型

Step5 使用五态表达证据强度：

| 状态 | 语义 |
|---|---|
| `reachable` | 已找到确认链路并触达业务代码 |
| `not_impacted` | 当前制品中的其他运行时依赖以完全相同的类字节码保留目标 API；只证明该 API 未实际消失 |
| `uncertain` | 有候选证据，但不足以确认 |
| `not_found_in_static_analysis` | 静态分析执行过，但当前证据未找到路径 |
| `not_analyzed` | 输入或能力不足，无法有效分析 |

### 达成的效果

五态结果把“确认影响”“符号被相同字节码保留”“候选风险”“静态未找到”“未有效分析”分开。

因此报告既能给出明确风险，也能表达分析盲区，不会把静态分析边界伪装成“确定无风险”。

## 十一、端到端示例：removed jar 风险如何被证明

删除依赖是最能体现这套设计的场景。

### 1. 构建事实

Step1 从 base/current 最终制品里提取运行时依赖，发现：

```text
base:    com.example:legacy-lib:1.0.0 存在
current: com.example:legacy-lib 不存在
```

这一步只证明 removed dependency 是真实构建事实。

### 2. 变化事实

Step4 发现 new jar 不存在，于是导出 old jar 的 public/protected 符号：

```text
com.example.LegacyClient
com.example.LegacyClient.call(String)
com.example.LegacyException.<init>(String)
```

这些符号进入 `all_changed_apis.csv`，成为 Step5 的正式目标。

### 3. 触达事实

Step5 对目标执行多证据追踪：

- 查业务源码是否直接 import 或调用；
- 查业务 class 字节码是否引用；
- 扫描 current 运行时依赖 jar 是否仍调用 old API；
- 如果运行时依赖命中，再尝试回溯到业务入口；
- 如果中间存在反射、SPI 或框架线索，则进入补偿分析。

最后可能得到：

| 结果 | 含义 |
|---|---|
| `reachable` | 已找到业务代码到 removed API 的链路 |
| `not_impacted` | 当前制品中的其他依赖以完全相同的类字节码保留该 API；不覆盖资源、SPI 等非 API 内容 |
| `uncertain` | 运行时依赖命中 removed API，但无法确认是否被业务入口触发 |
| `not_found_in_static_analysis` | 静态分析执行过，当前没找到路径 |
| `not_analyzed` | 缺少关键输入或能力覆盖不足 |

这个例子体现了核心思想：不是因为 jar 被删就直接报业务受影响，也不是因为业务源码没 import 就说没风险，而是沿构建事实、变化事实、触达事实逐层证明。

## 十二、工程保障：可复核、可恢复、可回归

### 可复核

每个关键结论都尽量保留证据文件：

- Step1 保留依赖变化和构建来源；
- Step4 保留 JApiCmp、git diff、removed jar 符号和 `all_changed_apis.csv`；
- Step5 保留 `alerts.csv`、`summary.json`、`by_api/*.json`；
- Step6 输出 `.runtime/findings/s6_findings.json`、`deliverables/report.md`、`deliverables/all-affected-dependencies.md` 和 `deliverables/all-impact-details.md`。

其中 `alerts.csv` 是原始分析记录，不是样例抽样；`all-impact-details.md` 基于这些记录按 API 归并完整调用关系，供用户顺序阅读。`report.md` 中未展开的依赖和 API 分别由两份独立全量明细承接。

### 可恢复

主状态和 checkpoint 让流程可以恢复：

- `main_state.json` 是唯一真相源；
- `interaction.json` 只做展示；
- 退出码 4 表示等待用户输入；
- 结构化 `intent_patch` 用于恢复；
- 重跑步骤时清理下游旧产物，避免旧证据混入新结果。

### 可回归

工程用质量门保护关键语义：

```bash
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
```

测试覆盖：

- 单元测试；
- 跨 Step 契约；
- Step5 正负例；
- smoke；
- accuracy benchmark；
- real project regression；
- 性能压力模型。

性能优化只能减少重复计算、优化索引或复用结果，不能通过减少分析范围改变语义。

## 十三、代码阅读地图

正文不围绕代码展开，但如果要继续深入，可以按技术线索读：

| 技术线索 | 主要文件 |
|---|---|
| 编排和状态机 | `scripts/run_step.py`、`scripts/step_manifest.json` |
| 构建事实 | `scripts/s1_dep_diff.py` |
| 上下文和项目范围 | `scripts/s2_context_from_deps.py`、`scripts/analysis_contract.py` |
| 背景风险线索 | `scripts/s3_scan.py`、`references/rules/*.json` |
| API 变化事实池 | `scripts/s4_jar_compare.py`、`scripts/s4_contract.py` |
| 源码图 | `scripts/enhanced_source_analyzer.py` |
| 字节码证据 | `scripts/business_bytecode_graph.py` |
| 反向追踪和五态结果 | `scripts/confidence_weighted_tracer.py` |
| 动态调用补偿 | `scripts/framework_adapters.py`、`scripts/indirect_usage_analyzer.py` |
| 报告生成 | `scripts/s6_report.py` |
| 质量门 | `scripts/quality_gate.py`、`tests/` |

推荐阅读顺序：

```text
run_step.py
  -> s1_dep_diff.py
  -> s4_contract.py / s4_jar_compare.py
  -> s5_call_chain_engine_integrated.py
  -> enhanced_source_analyzer.py
  -> confidence_weighted_tracer.py
  -> business_bytecode_graph.py
  -> framework_adapters.py / indirect_usage_analyzer.py
  -> s6_report.py
```

读代码时建议始终带着三层事实模型：

```text
这个文件是在证明构建事实、变化事实，还是触达事实？
```

## 十四、总结

`java-upgrade-analyzer` 的核心不是某个单一算法，而是一组围绕升级影响分析建立的工程模型和技术组合：

```text
构建事实：通过真实制品和运行时依赖提取证明系统实际打包了什么。
变化事实：通过 JApiCmp、git diff、removed jar 符号导出证明 API 发生了什么变化。
触达事实：通过源码图、字节码图、反向追踪和动态调用补偿证明变化是否触达业务。
```

围绕这三层事实，工程又建立了三类保障：

```text
状态机保障：输入不可信时不自动推进。
契约保障：跨 Step 数据有稳定结构和语义。
五态保障：只在相同类字节码保留目标 API 时输出 `not_impacted`，并且不把静态分析边界伪装成无风险。
```

这套设计的目标不是让工具替代人的判断，而是让升级评估从“靠经验猜风险”变成“沿证据链复核风险”。
