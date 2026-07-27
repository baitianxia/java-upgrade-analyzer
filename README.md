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

所有 CSV 产物统一采用 UTF-8 BOM，可直接用 Excel 打开，中文不会因默认编码识别错误而乱码。

---

## 适合什么时候用

推荐在这些场景使用：

- JDK 8 → 11 / 17 / 21；
- Spring Boot 2.x → 3.x；
- Spring Framework 5 → 6；
- `javax.*` → `jakarta.*`；
- Maven / Gradle 依赖批量升级；
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
- 依赖源码路径或 Git 地址：/abs/path/to/dependency-source-repo 或 https://git.example.com/team/dependency-source-repo.git
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
| 依赖源码路径或 Git 地址 | 可选但推荐 | 依赖包源码仓库本地路径或 HTTPS/SSH Git 地址，用于提升 API 行为变更和跨依赖调用链分析能力 |
| 特殊 JDK | 可选 | 如果 base/current 需要不同 JDK 构建，请说明 |

说明：

- 标准 Maven / Gradle 结构下，业务系统源码路径通常不需要你提供，Skill 会从 reactor 或 Gradle project graph 推断。
- Maven 项目优先使用对应 base/current revision 内的 `mvnw` / `mvnw.cmd`，没有 Wrapper 时才使用系统 `mvn`；分析器不规定 Maven 最低版本。
- Gradle 项目同时支持 Groovy DSL 与 Kotlin DSL；优先使用仓库内 `gradlew` / `gradlew.bat`，没有 Wrapper 时才使用系统 `gradle`。多模块选择既可写 `app`，也可写 `:app`。
- JDK、Maven、Gradle 均以用户工程为准。base/current 可分别使用不同 JDK；实际工具链不兼容时按真实构建命令失败原因阻塞，不会因分析器预设版本白名单提前拒绝。
- Gradle 自动构建执行目标模块的 `build -x test`；缺失嵌套 JAR 坐标时，优先从 `runtimeClasspath` 的 resolved artifacts 采集“组件坐标 ↔ 物理文件”清单，其中 `project :module` 会按精确 Gradle project path 映射为内部模块的 group、artifact、version。不支持 artifact inventory 的旧 Gradle/插件才回退到组件依赖树；文件锁冲突只对原命令按 1 秒、3 秒退避重试，不触发组件树回退、不删除锁，也不停止其他 Gradle daemon。Maven 同样保留 `dependency:list` 输出的绝对 artifact 文件。物理文件精确匹配优先于文件名解释；构建工具未报告 classifier 时，才以清单中的完整 version 为锚唯一推导，例如将 `jffi-1.2.23-native.jar` 解析为 `com.github.jnr:jffi:native`。多个最终身份同时匹配时才保留歧义，不按文件名猜选。最终依赖版本与内容仍以实际 fat JAR / boot JAR / WAR 为准。thin JAR 本身不包含运行时依赖，不能作为正式比较结果。
- 依赖源码输入指的是依赖包自己的源码仓库，不是当前业务系统源码路径。既可以填写本地目录，也可以直接填写 HTTPS/SSH Git 地址；远端仓库会克隆到 `.upgrade-report/.runtime/cache/dependency_source_git/`，不会切换或修改用户工作区。
- Git 克隆复用当前环境已有的 SSH key 或 Git 凭据配置，并禁用交互式密码提示；地址不可达或无权限时会明确停止，不会把失败仓库当成有效源码继续分析。
- base/current 可以使用同一个工程目录；两侧身份由各自确认后的远程分支、tag 或 commit 决定。Skill 会查询远端最新 ref、定向 fetch 并固定到具体 commit，在隔离快照中分析，不会切换或拉取你的当前分支。
- 直接产物模式会先解析 JAR；只有依赖坐标仍缺失时才使用对应侧源码补全。Step4 的依赖源码默认只取远端：唯一 ref pair 或多个名称指向同一 commit pair 时自动采用；只有两个以上不同 commit pair、且选择会改变源码对比范围时，才把全部歧义依赖及方案编号汇总到一张决策卡中，用户可一次答全。
- Step1 先从 fat JAR/WAR 解析坐标；坐标确认后通过一次留存遍历固化 Step4 所需的变化 JAR、Step5 所需的全部 current 运行时 JAR和业务内容。Step4、Step5 直接读取这份清单，不会再次解包 fat JAR、递归查询嵌套 JAR、读取本地 Maven 仓库或下载替代 JAR。源码只增强 Step1 已确定的 GAV，不会重新发现同坐标依赖。
- Step5 的 JAR 类型元数据 `javap` 单次超时为 30 秒；超时后对同一命令最多尝试 3 次，按 1 秒、3 秒退避。非超时错误不盲目重试；重试耗尽后只限制对应类型及相关调用路径，不会把一个类的失败提升为全部 API 的全局“未分析”。
- 分支名只用于定位和展示，确认卡选择会同时绑定 repo、remote、canonical ref、artifact 与当时的 commit SHA。Step1 首次选定的 SHA 是固定快照；后续查询为空或 ref 已移动只触发受控重试和按原 SHA 物化，不会改用新 SHA，也不会要求用户重新确认。Step4 的依赖源码 ref 移动或不可用时不要求用户修复，而是从升级前后最终 JAR 比较同签名方法的规范化字节码，继续识别实现变化。
- 远端 `ls-remote`/`fetch` 对超时、连接重置、临时 DNS/HTTP 5xx 等瞬时错误最多尝试 3 次，重试间隔为 1 秒、3 秒；已选定 SHA 后，定向查询中的 ref 空结果或新 commit 观测也会重试，但不会替换该 SHA。认证失败等确定性错误不重试。Step4 自动重试耗尽后会记录 `DEPENDENCY_SOURCE_REF_UNAVAILABLE`，不会生成要求用户处理网络、权限或 ref 的确认卡，也不会静默使用本地对象；只有运行前已经明确提供 `allow_local_source=true` 时才允许采用本地兜底。若最终 JAR 方法字节码兜底也无法完成，行为变化覆盖会成为关键缺口，报告不得输出“完整”或“不受影响”结论。
- 无论是否提供源码，依赖范围、版本、JAR 内容和字节码调用边始终以 base/current 最终制品为准；源码只用于补坐标、行为差异和可读性解释，不能把最终制品中不存在的模块扩展进确定性结论。
- 只提供源码目录不能证明它对应哪一侧制品；这种输入会先要求确认 revision，确认前不会执行 Maven 或 Gradle。
- 如果存在多个可部署模块且无法唯一判断，Claude Code 必须让你选择目标模块。
- 如果只表达“想分析什么”，但没有提供 base/current 来源或目标模块，Claude Code 会继续追问，不会猜测执行。
- 如果只是查询某个方法调用链，则需要当前工程已经跑完 Step5 并生成查询索引。

---

## Claude Code 停下来问问题怎么办

使用 `--step auto` 时，流程会连续执行到下一个确实需要用户决定的检查点，不再每完成一个步骤就退出。Claude Code 只在缺少外部事实、需要授权或不同选择会实质改变分析结果时停下来；其余步骤自动继续。

常见确认点：

- 目标模块不明确；
- 输入方式不完整；
- 两侧最终制品已经提供，但后续上下文仍缺少基准侧或当前侧分支；该信息会合并到已有的依赖范围确认中，不新增一次确认；
- JDK 版本或业务源码范围无法从制品、构建文件和项目结构可靠确定；
- 用户提供了源码仓库线索，并产生了会改变源码行为覆盖率的映射建议；系统会要求明确采用或拒绝，拒绝后不会重复询问；
- 依赖坐标或版本无法安全补齐；
- 依赖源码存在两个以上不同 commit pair，且选择会改变源码差异范围；
- Step4 识别出至少两个可分析依赖后，选择 Step5 的全量或部分分析范围；0 个或 1 个候选不存在实际范围取舍，系统会直接继续；
- 是否从某项任务重新分析。

正常流程中的确认顺序是：先确认分析对象与实际依赖范围；升级上下文只有在关键事实缺失时才确认；依赖 API 变化完成后确认全量或部分系统触达范围。兼容性线索扫描、证据完整的升级上下文、系统触达分析和最终报告都会自动衔接。

Step4 识别出至少两个可分析依赖后会让你选择 Step5 的分析范围：全量分析覆盖更完整，部分分析可以降低耗时，但最终结论只适用于所选范围。范围卡会同时展示依赖数、变化 API 数和高风险 API 数。0 个或 1 个候选不存在实际范围取舍，系统会直接继续。确认范围后，系统会连续执行 Step5 和 Step6，不再要求点击“继续”。超时、依赖源码缺失等内部证据故障会自动记录覆盖缺口并生成受限结论，不会混入范围选择要求用户修复。

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

暂停、等待确认或系统阻塞时，`.upgrade-report/README.md` 会同时写明“已保留到哪项任务”和“恢复后从哪里继续”。从较早任务重新分析时，终端会明确说明哪些既有产物继续保留、哪些任务及之后的产物会按新输入重建，避免把恢复误解为整条流程从头开始。

长任务即使暂时没有新结果，也会定期输出“仍在运行 + 已用时间”心跳；有可靠进度分母时同时显示粗略预计剩余时间。按 `Ctrl-C` 主动停止时，系统会终止当前子进程、清理当前任务的半成品，保留之前已完成任务及当前输入；再次运行即可从当前任务安全重试。

---

## 如何阅读结果

运行后 `.upgrade-report/README.md` 是产物目录的落地阅读入口；它会把 `deliverables/`、`evidence/`、`.runtime/` 的用途分开说明。

1. 先打开 `.upgrade-report/README.md`；这里只链接本轮已经生成的文件，并在等待确认时保留问题、选项和可直接使用的回复示例。
2. 看 `.upgrade-report/deliverables/report.md`：先读依赖层面的结论，再读 API 和调用关系。
3. 主报告没有展开的依赖，全部位于 `.upgrade-report/deliverables/all-affected-dependencies.md`。
4. 主报告没有展开的 API 和完整调用关系，全部位于 `.upgrade-report/deliverables/all-impact-details.md`。
5. `.upgrade-report/evidence/call_chain/alerts.csv` 是一行一条的原始分析记录，用于核对明细中的调用关系和证据文件。
6. `.upgrade-report/deliverables/analysis-scope.md` 记录本轮纳入和未纳入调用关系分析的依赖及 API 数量。
7. `.upgrade-report/.runtime/` 是程序状态目录，普通阅读不需要进入。

流程完成状态会区分“分析已完成”和“分析已完成，但存在结论限制”。部分范围、关键证据覆盖不完整、可能影响、存在候选证据但结论未确定、本次未完成或证据读取异常都不会被包装成无限制的完整结论。

依赖 API 变化分析完成后，系统会在执行 Step5 前确认分析范围：

1. **全量分析**：覆盖全部发生 API 变化的依赖包，结论覆盖最完整。
2. **部分分析（仅在明确控制耗时时）**：可优先查看含高风险 API、删除或签名变化，或变化 API 数不少于 20 个的依赖包。
3. **从全部候选中选择部分范围**：打开 `.upgrade-report/evidence/api_changes/changed_dependencies.md`，从完整清单复制“依赖包”列中的坐标，例如：`只分析 com.foo:bar、com.foo:baz`。

不需要从 `all_changed_apis.csv` 逐行挑选 API。“部分分析优先项”只用于用户已经决定缩小范围后的排序，不表示系统建议缩小范围，也不代表已经确认影响当前系统。

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
| `.upgrade-report/README.md` | 产物入口；显示当前任务、暂停原因、结果状态和本轮产物 |
| `.upgrade-report/deliverables/report.md` | 依赖层面结论、API 及调用关系、用户可见文件说明 |
| `.upgrade-report/deliverables/all-affected-dependencies.md` | 全部变化依赖的分析结果和对应 API 明细链接 |
| `.upgrade-report/deliverables/all-impact-details.md` | 全部变化 API 的分析结果和完整调用关系 |
| `.upgrade-report/evidence/context/review.md` | 给人看的升级上下文确认页 |
| `.upgrade-report/evidence/api_changes/changed_dependencies.md` | 依赖包维度的 API 变化和范围选择入口 |
| `.upgrade-report/evidence/call_chain/alerts.csv` | 完整系统触达证据台账 |

人工阅读优先按这个顺序：

| 顺序 | 文件 | 用途 |
|---:|---|---|
| 1 | `.upgrade-report/deliverables/report.md` | 先看依赖结论，再看 API 和调用关系 |
| 2 | `.upgrade-report/deliverables/all-affected-dependencies.md` | 查看全部变化依赖及完成、未完成状态 |
| 3 | `.upgrade-report/deliverables/all-impact-details.md` | 查看全部变化 API 和完整调用关系 |
| 4 | `.upgrade-report/evidence/call_chain/alerts.csv` | 核对一行一条的原始分析记录 |

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
| Step6 | 生成依赖结论、API 调用关系和两份全量明细 | `deliverables/report.md`、`deliverables/all-affected-dependencies.md`、`deliverables/all-impact-details.md` |

---

## 常见问题

### 多模块项目必须选择目标模块吗？

是。一次分析只对应一个目标部署模块。

如果工具发现多个可部署模块且无法唯一判断，Claude Code 必须让你选择，不能静默选择 root、第一个模块或最大产物。

### 依赖源码路径或 Git 地址应该填什么？

填依赖包自己的源码仓库根目录，例如：

```text
/Users/me/source/dependency-project
```

也可以直接在 `dependency_source_dirs` 中填写 Git 地址，例如：

```json
{"dependency_source_dirs":["https://git.example.com/team/dependency-project.git"]}
```

不要填当前业务系统的源码目录。当前业务系统源码通常由 Maven reactor 或 Gradle project graph 自动推断。

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

其中 `memory.*_process_tree_peak_rss_mb` 是 Python、`javap`、`jdeps` 等全部后代进程的
瞬时 RSS 总和峰值；`memory.*_external_process_count_<tool>` 和
`memory.*_external_process_peak_concurrency`、`memory.*_temporary_file_peak_bytes` 和
`memory.*_external_process_wall_sec` 用于区分进程启动、临时文件与 Python 建图压力。需要限制内存时，
可设置 `JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB`（告警）或
`JUA_STEP5_PROCESS_TREE_HARD_RSS_MB`（在阶段边界失败关闭），单位均为 MiB。

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

如果缺失，Skill 会先自动尝试安装 JApiCmp。自动安装失败时，本次执行会记录为系统环境阻塞，不会生成一项让用户决定如何处理的业务确认；安装完成前也不会继续生成不完整的 API 结论。

不安装 JApiCmp 的后果是：二进制 API 对比证据不完整，可能漏掉删除方法、签名变化、字段变化、源码重编译不兼容等风险。

### tree-sitter 缺失会中断吗？

默认会按系统环境错误阻断，不会生成用户确认，也不会静默降级。

运行环境支持 CPython 3.12.x、3.13.x 和 3.14.x，并在 Skill 根目录用当前受支持的解释器显式执行 `python3 scripts/bootstrap_runtime.py` 安装固定版本的 `tree-sitter` 与 `tree-sitter-java`。PR quick 门禁会在三个 Python 小版本上分别执行。离线环境可增加 `--wheel-dir /abs/path/to/wheels`，安装过程会禁止访问包索引。分析运行时不会联网安装；依赖缺失、版本不符或加载失败时会在分析前明确停止，安装完成前不会使用增强正则继续分析。

不安装 tree-sitter 的后果是：Java AST 主链路不可用，源码调用链、重载签名、lambda、构造器、方法引用、局部变量类型传播等识别能力会下降。

### Kotlin 与 KTS 的结论边界是什么？

当前 Kotlin/KTS 是 partial capability：工具会收集 `.kt`、`.kts` 并用增强正则提供候选线索，但不会把它宣称为 Kotlin 编译器级语义。只要与目标 API 相关的 Kotlin/KTS 文件进入当前最终制品闭集，静态未命中和 `not_impacted` 捷径都会失败关闭为 `PARTIAL_LANGUAGE_ANALYSIS`。生产与测试代码依据 `src/<sourceSet>/...` 分类，生产类名包含 `Test` 不会被误判为测试代码。
