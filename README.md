# java-upgrade-analyzer

这是一个给 Claude Code 使用的 Java 升级兼容性分析 Skill。

它用于回答：

> JDK、Spring、Jakarta 或依赖升级/删除后，哪些变更 API 真的会影响当前业务系统？

使用者只需要在 Claude Code 中描述升级场景，让 Claude Code 调用本 Skill，按交互提示补充信息，并查看最终报告。

---

## 它能做什么

这个 Skill 会围绕升级前后差异建立一条可复核证据链：

- 识别依赖 jar 的新增、删除、升级；
- 识别依赖 API 的类、方法、字段变化；
- 识别 DTO/数据对象字段新增、删除或类型变化，并判断该类型是否进入业务代码、定时任务、消息监听等系统运行路径；
- 分析 JDK、Spring、Jakarta 等框架级迁移风险；
- 追踪变化 API 是否被业务源码、业务字节码或运行时依赖 jar 使用；
- 尽量给出完整调用链，例如“业务代码 A → 依赖 B → 依赖 C → 变更 API D”；
- 在系统触达证据分析完成后，支持按指定方法即时查询调用链，直接返回链路文本；
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

---

## 快速开始

在待分析 Java 工程中打开 Claude Code，然后用自然语言说明升级前后来源和目标模块。推荐一次性这样说：

```text
使用 java-upgrade-analyzer 分析当前工程升级影响：
- base 分支：main
- current 分支：feature/upgrade
- 目标模块：app-module
- 依赖源码路径：/abs/path/to/dependency-source-repo
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

Claude Code 会负责：

1. 读取本 Skill 的规则；
2. 判断需要哪些输入；
3. 执行分析流程；
4. 遇到需要确认的信息时停下来向你确认；
5. 根据你的答复恢复执行；
6. 最后告诉你应该看哪些报告文件、结论是什么。

为了少来回追问，首次使用时重点提供这些信息：

| 信息 | 是否必需 | 说明 |
|---|---:|---|
| 待分析工程 | 通常已知 | Claude Code 当前打开的工程；如果不是目标工程，请明确路径 |
| 目标模块 | 必需 | 本次唯一分析的可部署模块；多模块项目必须明确 |
| 升级前后来源 | 必需 | 通常是 base/current 分支，也可以是已有 base/current jar/war |
| 依赖源码路径 | 可选但推荐 | 依赖包源码仓库路径，用于提升 API 行为变更和跨依赖调用链分析能力 |
| 特殊 JDK | 可选 | 如果 base/current 需要不同 JDK 构建，请说明 |

说明：

- 标准 Maven 结构下，业务系统源码路径通常不需要你提供，Skill 会从目标模块推断。
- 依赖源码路径指的是依赖包自己的源码仓库路径，不是当前业务系统源码路径。
- 如果存在多个可部署模块且无法唯一判断，Claude Code 必须让你选择目标模块。
- 如果只表达“想分析什么”，但没有提供 base/current 来源或目标模块，Claude Code 会继续追问，不会猜测执行。
- 如果只是查询某个方法调用链，则需要当前工程已经跑完 Step5 并生成查询索引。

---

## Claude Code 停下来问问题怎么办

分析过程中，Skill 可能会遇到需要人工确认的信息。Claude Code 会停下来向你确认，而不是继续猜。

常见确认点：

- 目标模块不明确；
- 输入方式不完整；
- 依赖坐标或版本无法安全补齐；
- 依赖 API 变化证据不完整，是否补充材料后重新分析；
- 系统触达证据缺少依赖源码，是否补充后重新分析；
- 是否从某项任务重新分析。

你只需要用自然语言回答即可，例如：

```text
目标模块选择 app-module，继续。
```

```text
依赖源码目录是 /abs/path/to/dependency-source-repo，补充后重新分析系统触达证据。
```

```text
从依赖 API 变化重新分析。
```

Claude Code 会把你的答复整理成 Skill 需要的结构化输入，并恢复执行。

---

## 如何阅读结果

运行后 `.upgrade-report/README.md` 是产物目录的落地阅读入口；它会把 `deliverables/`、`evidence/`、`.runtime/` 的用途分开说明。

1. 先看 `.upgrade-report/deliverables/report.md`，了解客观分析结果和结论限制。
2. 如果需要核对依赖 API 变化，先看 `.upgrade-report/evidence/api_changes/changed_dependencies.md`。
3. 如果需要核对完整 API 明细，再看 `.upgrade-report/evidence/api_changes/all_changed_apis.csv`。
4. 如果需要核对调用链证据，看 `.upgrade-report/evidence/call_chain/alerts.csv`。
5. `.upgrade-report/.runtime/` 是程序状态目录，普通阅读不需要进入。

依赖 API 变化分析完成后，如果 Claude Code 询问系统触达证据是全量分析还是只分析部分依赖包，候选项来自 `changed_dependencies.md/csv` 的依赖包维度清单，不需要从 `all_changed_apis.csv` 逐行挑 API。

---

## 即时查询某个方法的调用链

当 Step5 已经生成调用链查询索引后，如果你只是想确认某个方法是否存在调用链，可以直接让 Claude Code 查询：

```text
查询 com.foo.Bar.baz(String) 的调用链
```

或者：

```text
帮我看一下 org.apache.commons.lang.StringUtils.isBlank(String) 是从哪里被调用到的。
```

默认行为：

- 直接在对话中返回调用链；
- 默认按全限定名精确匹配，不会自动退回简单名匹配，避免 `StringUtils`、`JSONArray`、`isEmpty` 这类同名类/方法串链误报；
- 如果没有精确命中，会明确告诉你“未找到精确匹配的调用链”；
- 不额外生成查询结果文件；
- 不重跑 Step5；
- 不推进 Step6；
- 即使当前流程停在某个确认点，只要 Step5 查询索引已经生成，也可以只读查询。

如果确实需要按简单名扩大排查范围，可以让 Claude Code 显式开启 fuzzy 查询；这类结果只适合辅助定位，不能直接作为确定影响结论。

这个能力适合用来复核分析结果，例如确认：

- 某个 `reachable` API 的完整链路是否符合预期；
- 某个依赖方法是否通过其他依赖间接触达业务代码；
- 报告里某条链路为什么成立；
- 人工排查时临时追问某个方法的上游调用者。

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

产物目录自带阅读入口：

| 文件 | 用途 |
|---|---|
| `.upgrade-report/README.md` | 唯一产物入口；显示当前任务、暂停原因、下一步和按问题找文件 |
| `.upgrade-report/deliverables/report.md` | 最终客观分析结果、证据和结论限制 |
| `.upgrade-report/evidence/context/review.md` | 给人看的升级上下文确认页 |
| `.upgrade-report/evidence/api_changes/changed_dependencies.md` | 依赖包维度的 API 变化和范围选择入口 |
| `.upgrade-report/evidence/call_chain/alerts.csv` | 完整系统触达证据台账 |

人工阅读优先按这个顺序：

| 顺序 | 文件 | 用途 |
|---:|---|---|
| 1 | `.upgrade-report/deliverables/report.md` | 查看最终客观分析结果和结论限制 |
| 2 | `.upgrade-report/evidence/api_changes/changed_dependencies.md` | 查看依赖包维度的 API 变化摘要和 Step5 选择值 |
| 3 | `.upgrade-report/evidence/api_changes/all_changed_apis.csv` | 查看完整 API 变化事实 |
| 4 | `.upgrade-report/evidence/call_chain/alerts.csv` | 查看每个变化 API 的完整调用链台账 |

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

## Step5 结果状态怎么理解

| 状态 | 含义 |
|---|---|
| `reachable` | 已找到调用链并触达业务代码，属于确认影响 |
| `not_impacted` | 直接制品证据证明该变更 API 仍由当前运行时依赖以完全相同的类字节码提供；仅证明该 API 未实际消失，不代表被删除 jar 的资源、SPI 或其他非 API 内容没有影响 |
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
| Step4 | 比较变更依赖 jar 的 API 变化 | `evidence/api_changes/changed_dependencies.md`、`evidence/api_changes/all_changed_apis.csv` |
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

### Step4 / Step5 很慢怎么办？

Step4 慢时，让 Claude Code 先查看：

```text
.upgrade-report/.runtime/observability/step4_timing.csv
```

重点关注：

- `artifact_resolve`
- `dependency.gitdiff`
- `dependency.japicmp`
- `dependency.removed_jar_export`
- `dependency.changed_classes`
- `write.*`

这些指标可以判断耗时主要来自 jar 定位/解压、源码 diff、JApiCmp、删除依赖符号导出、类 hash 或输出汇总。

Step5 慢时，让 Claude Code 查看：

```text
.upgrade-report/.runtime/observability/step5_timing.csv
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

如果缺失，Skill 会先自动尝试安装 JApiCmp。自动安装失败时，Claude Code 会停下来提示你手动安装或提供 JApiCmp 工具路径；安装完成前不会继续分析。

不安装 JApiCmp 的后果是：二进制 API 对比证据不完整，可能漏掉删除方法、签名变化、字段变化、源码重编译不兼容等风险。

### tree-sitter 缺失会中断吗？

默认会先阻断确认，不会静默降级。

Step5 会把 `tree-sitter` 和 `tree-sitter-java` 自动安装到工具自己的缓存目录，不修改系统 Python 或项目虚拟环境，并设置安装超时。如果自动安装或加载失败，Claude Code 会停下来提示你手动安装；安装完成前不会使用增强正则继续分析。

不安装 tree-sitter 的后果是：Java AST 主链路不可用，源码调用链、重载签名、lambda、构造器、方法引用、局部变量类型传播等识别能力会下降。
