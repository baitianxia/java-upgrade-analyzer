# java-upgrade-analyzer

这是一个给 Claude Code 使用的 Java 升级兼容性分析 Skill。

它用于回答：

> JDK、Spring、Jakarta 或依赖升级/删除后，哪些变更 API 真的会影响当前业务系统？

使用者不需要直接运行内部脚本。正确使用方式是：在 Claude Code 中描述你的升级场景，让 Claude Code 调用本 Skill，按交互提示补充信息，并查看最终报告。

---

## 它能做什么

这个 Skill 会围绕升级前后差异建立一条可复核证据链：

- 识别依赖 jar 的新增、删除、升级；
- 识别依赖 API 的类、方法、字段变化；
- 分析 JDK、Spring、Jakarta 等框架级迁移风险；
- 追踪变化 API 是否被业务源码、业务字节码或运行时依赖 jar 使用；
- 尽量给出完整调用链，例如“业务代码 A → 依赖 B → 依赖 C → 变更 API D”；
- 输出人工可复核的明细和最终汇总报告。

它不是自动修代码工具。默认只分析风险、输出证据和结论。

---

## 适合什么时候用

推荐在这些场景使用：

- JDK 8 → 11 / 17 / 21；
- Spring Boot 2.x → 3.x；
- Spring Framework 5 → 6；
- `javax.*` → `jakarta.*`；
- Maven 依赖批量升级；
- 某个依赖 jar 被删除；
- 想确认某个依赖 API 变化是否真正影响当前业务系统。

典型问题示例：

- “帮我分析这个工程从 JDK 8 升到 17 的兼容性风险。”
- “使用 java-upgrade-analyzer 分析 Spring Boot 2 升 3 的影响。”
- “commons-lang 这个 jar 删除后，当前系统是否还有直接或间接调用？”
- “这个依赖版本升级后，哪些 API 变化会触达业务代码？”

---

## 在 Claude Code 中如何使用

在待分析 Java 工程中打开 Claude Code，然后直接提出需求即可：

```text
使用 java-upgrade-analyzer 分析当前工程从 main 分支升级到 feature/upgrade 分支的兼容性风险。
目标模块是 app-module。
如果需要依赖源码，我可以提供 /abs/path/to/dependency-source-repo。
```

或者：

```text
使用 java-upgrade-analyzer 分析 commons-lang 被删除对当前系统的影响。
目标模块是 app-module。
```

Claude Code 会负责：

1. 读取本 Skill 的规则；
2. 判断需要哪些输入；
3. 调用内部分析脚本；
4. 遇到 checkpoint 时停下来向你确认；
5. 根据你的答复恢复执行；
6. 最后告诉你应该看哪些报告文件、结论是什么。

你不需要手工执行 `scripts/run_step.py`。这些命令是 Claude Code/Skill 内部使用的。

---

## 第一次使用时建议告诉 Claude Code 什么

为了少来回追问，建议一开始就提供这些信息：

| 信息 | 是否必需 | 说明 |
|---|---:|---|
| 待分析工程 | 通常已知 | Claude Code 当前打开的工程；如果不是目标工程，请明确路径 |
| 目标模块 | 必需 | 本次唯一分析的可部署模块；多模块项目必须明确 |
| 升级前后来源 | 必需 | 通常是 base/current 分支，也可以是已有 base/current jar/war |
| 依赖源码路径 | 可选但推荐 | 依赖包源码仓库路径，用于提升 API 行为变更和跨依赖调用链分析能力 |
| 特殊 JDK | 可选 | 如果 base/current 需要不同 JDK 构建，请说明 |

推荐一次性这样说：

```text
使用 java-upgrade-analyzer 分析当前工程升级影响：
- base 分支：main
- current 分支：feature/upgrade
- 目标模块：app-module
- 依赖源码路径：/abs/path/to/dependency-source-repo
- 最大调用链深度使用默认值
```

如果你已经有升级前后的构建产物，可以这样说：

```text
使用 java-upgrade-analyzer 分析已有产物：
- base 产物：/abs/path/to/base-app.jar
- current 产物：/abs/path/to/current-app.jar
- base 分支：main
- current 分支：feature/upgrade
- 目标模块：app-module
```

说明：

- 标准 Maven 结构下，业务系统源码路径通常不需要你提供，Skill 会从目标模块推断。
- `dependency_source_dirs` 指的是依赖包源码路径，不是当前业务系统源码路径。
- 如果存在多个可部署模块且无法唯一判断，Claude Code 必须让你选择目标模块。

---

## Claude Code 停下来问问题怎么办

分析过程中，Skill 可能会进入 checkpoint。Claude Code 会停下来向你确认，而不是继续猜。

常见确认点：

- 目标模块不明确；
- 输入方式不完整；
- 依赖坐标或版本无法安全补齐；
- Step4 证据不完整，是否继续；
- Step5 缺少依赖源码映射，是否补充后重跑；
- 是否从某一步重新分析。

你只需要用自然语言回答即可，例如：

```text
目标模块选择 app-module，继续。
```

```text
依赖源码目录是 /abs/path/to/dependency-source-repo，补充后重跑 Step5。
```

```text
从 Step4 重新跑。
```

Claude Code 会把你的答复整理成 Skill 需要的结构化输入，并恢复执行。

---

## 如何要求重新分析某一步

每一步都支持重跑。你可以直接告诉 Claude Code：

```text
从 Step4 重新跑。
```

或者：

```text
Step6 已经生成了，但我想补充依赖源码后，从 Step5 重新分析。
```

重跑时，Skill 会清理目标步骤及后续步骤的旧状态和旧产物，避免新旧结果混用。

可重跑步骤：

| Step | 含义 |
|---|---|
| Step1 | 重新比较 base/current 最终依赖差异 |
| Step2 | 重新建立升级上下文、源码和依赖映射 |
| Step3 | 重新扫描 JDK/Spring/Jakarta 等框架级风险 |
| Step4 | 重新比较变更依赖 jar 的 API 变化 |
| Step5 | 重新追踪变化 API 是否触达业务代码 |
| Step6 | 重新生成最终报告 |

---

## 结果在哪里看

所有产物默认在待分析工程的：

```text
.upgrade-report/
```

人工复核优先看这三个文件：

| 顺序 | 文件 | 用途 |
|---:|---|---|
| 1 | `.upgrade-report/evidence/api_changes/all_changed_apis.csv` | 查看依赖 API 变化事实 |
| 2 | `.upgrade-report/evidence/call_chain/alerts.csv` | 查看每个变化 API 的调用链追踪台账 |
| 3 | `.upgrade-report/deliverables/report.md` | 查看最终汇总结论 |

如果 `alerts.csv` 很大，Skill 会额外生成按状态拆分的阅读视图：

```text
.upgrade-report/evidence/call_chain/alerts_reachable.csv
.upgrade-report/evidence/call_chain/alerts_uncertain.csv
.upgrade-report/evidence/call_chain/alerts_not_found_in_static_analysis.csv
.upgrade-report/evidence/call_chain/alerts_not_analyzed.csv
```

这些拆分文件只是方便阅读；完整主文件仍然是：

```text
.upgrade-report/evidence/call_chain/alerts.csv
```

如果只是想确认某个方法“到底有没有调用链”，可以让 Claude Code 基于 Step5 查询索引即时查询。默认只返回调用链，不额外落文件：

```text
查询 com.foo.Bar.baz(String) 的调用链
```

这个查询是只读能力。只要 Step5 已经成功完成并生成查询索引，即使当前还停在确认点等待你决定是否继续，也可以直接查询，不会推进后续步骤。

---

## Step5 结果状态怎么理解

| 状态 | 含义 |
|---|---|
| `reachable` | 已找到调用链并触达业务代码，属于确认影响 |
| `uncertain` | 有候选证据，但链路、源码映射、反射、框架或字节码证据不足，需要人工确认 |
| `not_found_in_static_analysis` | 静态分析执行过，但当前源码、字节码和框架证据中没有找到引用路径；不等于确定无影响 |
| `not_analyzed` | 输入缺失或工具能力不足，无法完成有效分析 |

特别注意：

- `not_found_in_static_analysis` 不是“确定不影响”。
- 反射、动态代理、运行时配置、依赖源码缺失都可能让结果进入 `uncertain` 或 `not_analyzed`。
- 删除依赖 jar 的场景下，即使业务源码没有直接引用，运行时依赖 jar 使用了被删 API 也会进入 Step5 证据链。

---

## 六个步骤分别做什么

| Step | 作用 | 关键产物 |
|---|---|---|
| Step1 | 比较 base/current 最终依赖差异 | `evidence/dependencies/dep_changes.csv` |
| Step2 | 建立升级上下文、源码和依赖映射 | `evidence/context/context.json` |
| Step3 | 分析 JDK/Spring/Jakarta 等框架级风险 | `evidence/static_scan/*.csv` |
| Step4 | 比较变更依赖 jar 的 API 变化 | `evidence/api_changes/all_changed_apis.csv` |
| Step5 | 追踪变化 API 是否触达业务代码 | `evidence/call_chain/alerts.csv` |
| Step6 | 汇总成人可读报告 | `deliverables/report.md` |

---

## 常见问题

### 多模块项目必须选择目标模块吗？

是。一次分析只对应一个目标部署模块。

如果工具发现多个可部署模块且无法唯一判断，Claude Code 必须让你选择，不能静默选择 root、第一个模块或最大产物。

### 依赖源码路径应该填什么？

填依赖包自己的源码仓库根目录，例如：

```text
/Users/me/source/dependency-project
```

不要填当前业务系统的源码目录。当前业务系统源码通常由 Maven 模块结构自动推断。

### 没有依赖源码还能分析吗？

可以，但准确性会下降。

没有依赖源码时，Skill 仍会尽量通过业务源码、业务字节码、运行时依赖 jar 字节码和框架适配器追踪影响。但依赖内部行为变化、跨依赖源码调用链、部分反射/配置关系可能只能给出 `uncertain` 或 `not_analyzed`。

### Step5 很慢怎么办？

让 Claude Code 查看：

```text
.upgrade-report/evidence/call_chain/step5_timing.csv
```

重点关注：

- `business_bytecode`
- `framework_adapter_merge`
- `business_graph`
- `trace`
- `bytecode_expand`
- `main.indirect_usage_*`

不要只看总耗时猜瓶颈。运行时依赖 jar 很多、变更 API 很多、依赖间调用链很深时，Step5 会明显变慢。

### 没安装 japicmp 会怎样？

Step4 需要 JApiCmp 做 jar API 对比。

如果缺失，Skill 会先自动尝试安装 JApiCmp。自动安装失败时，Claude Code 会停下来提示你手动安装或提供 `japicmp_jar`；只有你明确确认接受降级后，才会继续。

不安装 JApiCmp 的后果是：二进制 API 对比证据不完整，可能漏掉删除方法、签名变化、字段变化、源码重编译不兼容等风险。

### tree-sitter 缺失会中断吗？

默认会先阻断确认，不会静默降级。

Step5 默认会先使用运行 Skill 的同一个 Python 环境自动安装 `tree-sitter` 和 `tree-sitter-java`。如果自动安装失败，Claude Code 会停下来提示你手动安装；只有你明确确认接受降级后，才会继续使用增强正则。

不安装 tree-sitter 的后果是：Java AST 主链路不可用，源码调用链、重载签名、lambda、构造器、方法引用、局部变量类型传播等识别能力会下降。

---

## 面向维护者：内部执行入口

普通使用者不需要直接执行这些命令。它们是 Claude Code 根据 `SKILL.md` 和 checkpoint 协议内部调用的入口。

统一调度脚本：

```text
scripts/run_step.py
```

主状态文件：

```text
.upgrade-report/.runtime/state/main_state.json
```

待交互文件：

```text
.upgrade-report/.runtime/state/interaction.json
```

维护或排障时可以参考：

- `SKILL.md`：Claude Code 执行规则和 checkpoint 硬约束；
- `CHECKPOINT_RULES.md`：最小交互硬规则；
- `docs/user/outputs.md`：输出文件说明；
- `docs/developer/architecture.md`：整体架构；
- `docs/developer/step5-design.md`：Step5 调用链分析设计；
- `docs/developer/quality.md`：质量和测试策略。
