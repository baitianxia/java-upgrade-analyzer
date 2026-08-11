# java-upgrade-analyzer

这是一个给 Claude Code 使用的 Java 升级兼容性分析 Skill，用于评估 Java 运行平台、应用框架、规范迁移和项目依赖变化对业务系统的实际影响。

它用于回答：

> Java 工程的运行平台、框架或依赖发生变化后，哪些兼容性风险真的会影响当前业务系统？

使用者只需要在 Claude Code 中描述升级场景，让 Claude Code 调用本 Skill，按交互提示补充信息，并查看最终报告。

---

## 它能做什么

这个 Skill 会围绕变化前后的最终制品、源码和调用关系建立一条可复核证据链：

- 比较目标模块的升级前后最终制品，识别依赖 JAR 的新增、删除、升级和降级；
- 识别依赖 API 的类、方法、字段变化；
- 识别 DTO/数据对象字段新增、删除或类型变化，并判断该类型是否进入业务代码、定时任务、消息监听等系统运行路径；
- 扫描 JDK 升级、Spring 等框架升级以及 `javax.* → jakarta.*` 规范/命名空间迁移风险；
- 追踪变化 API 是否被业务源码、业务字节码或运行时依赖 JAR 使用；
- 尽量给出完整调用链，例如“业务代码 A → 依赖 B → 依赖 C → 变更 API D”；
- 在系统触达证据分析完成后，支持按指定方法即时查询调用链，直接返回链路文本；
- 输出人工可复核的明细和最终汇总报告。

它不是自动修代码工具。默认只分析风险、输出证据和结论。

所有 CSV 产物统一采用 UTF-8 BOM，可直接用 Excel 打开，中文不会因默认编码识别错误而乱码。

---

## 适合什么时候用

推荐在以下类型的 Java 工程变化中使用：

- **运行平台升级**：例如 JDK 8 → 11 / 17 / 21；
- **应用框架升级**：例如 Spring Boot 2.x → 3.x、Spring Framework 5 → 6；
- **规范或命名空间迁移**：例如 `javax.*` → `jakarta.*`；
- **项目依赖变化**：例如 Maven / Gradle 依赖新增、删除、升级、降级或批量调整；
- **影响复核**：确认某个依赖或 API 的变化是否真正触达当前业务系统。

---

## 快速开始

在待分析 Java 工程中打开 Claude Code，然后用自然语言说明升级前后来源和目标模块。推荐一次性这样说：

```text
使用 java-upgrade-analyzer 分析当前工程升级影响：
- base 分支：main
- current 分支：feature/upgrade
- 目标模块：app-module
- 可补充的源码位置：/abs/path/to/source-repo 或 https://git.example.com/team/dependency-source-repo.git
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
| 升级前后来源 | 必需 | 通常是 base/current 分支，也可以是已有 base/current JAR/WAR |
| 是否还能补充相关源码 | 必需确认一次 | 这是收集可选输入，不是源码使用授权；编译模式已取得的业务源码会直接使用。可以一次提交多个源码目录或 Git 地址，也可以暂不补充 |
| 源码目录或 Git 地址 | 选择补充时可选 | 不要求预先区分业务源码和依赖源码；系统按项目范围与依赖坐标自动分类，只有无法可靠分类时才询问映射 |
| 特殊 JDK | 可选 | 如果 base/current 需要不同 JDK 构建，请说明 |
| Binary runtime 快照 | 系统自动生成 | Step1 从两侧最终制品、完整运行依赖和目标 JDK 自动生成；特殊 loader/容器部署可用 `binary_pipeline_config.example.json` 显式覆盖。无法证明闭包完整时系统会列出缺口并停止，不要求普通用户手写内部配置 |

说明：

- 编译模式已经取得被分析系统源码，标准 Maven / Gradle 结构下会从 reactor 或 Gradle project graph 推断业务源码范围并直接使用；Step2 询问的是是否还能补充其他相关源码，主要是依赖源码。
- 直接制品模式通过同一个入口接收被分析系统源码和依赖源码。用户无需判断源码类型；系统自动分类并分别记录覆盖，无法可靠分类时才请求一次归属映射。
- Maven 项目优先使用对应 base/current revision 内的 `mvnw` / `mvnw.cmd`，没有 Wrapper 时才使用系统 `mvn`；分析器不规定 Maven 最低版本。
- Gradle 项目同时支持 Groovy DSL 与 Kotlin DSL；优先使用仓库内 `gradlew` / `gradlew.bat`，没有 Wrapper 时才使用系统 `gradle`。多模块选择既可写 `app`，也可写 `:app`。
- JDK、Maven、Gradle 均以用户工程为准。base/current 可分别使用不同 JDK；实际工具链不兼容时按真实构建命令失败原因阻塞，不会因分析器预设版本白名单提前拒绝。
- Gradle 自动构建执行目标模块的 `build -x test`；缺失嵌套 JAR 坐标时，优先从 `runtimeClasspath` 的 resolved artifacts 采集“组件坐标 ↔ 物理文件”清单。不支持 artifact inventory 的旧 Gradle/插件才回退到组件依赖树；文件锁冲突只对原命令按 1 秒、3 秒退避重试，不触发组件树回退、不删除锁，也不停止其他 Gradle daemon。Maven 同样保留 `dependency:list` 输出的绝对 artifact 文件。
- Maven `dependency:list` 漏掉 reactor 内部模块，或 Gradle 只返回 `ProjectComponentIdentifier` 时，Step1 会从目标模块的实际运行时闭包补齐内部模块坐标：Maven 解析继承和 `${revision}`、`${project.version}` 等有效属性，Gradle 按精确 project path 读取实际 group、artifact、version。只补目标闭包中的依赖模块，不把目标模块自身或无关 sibling 纳入依赖；构建工具已经给出的坐标和版本优先，源码模型不能覆盖它们。若内部模块存在唯一主归档，还会用该物理文件匹配自定义 `finalName`。
- 物理文件精确匹配优先于文件名解释；构建工具未报告 classifier 时，才以清单中的完整 version 为锚唯一推导，例如将 `jffi-1.2.23-native.jar` 解析为 `com.github.jnr:jffi:native`。多个最终身份同时匹配时才保留歧义，不按文件名猜选。项目模型只帮助识别最终制品中实际存在的内部 JAR，不能扩展制品范围。最终依赖版本与内容仍以实际 Fat JAR、Spring Boot JAR 或 WAR 为准。Thin JAR 本身不包含运行时依赖，不能作为正式比较结果。
- 系统内部仍区分业务源码和依赖源码：依赖源码指依赖包自己的源码仓库。统一输入支持本地目录和 HTTPS/SSH Git 地址；识别为依赖源码的远端仓库会克隆到 `.upgrade-report/.runtime/cache/dependency_source_git/`，不会切换或修改用户工作区。
- Git 克隆复用当前环境已有的 SSH key 或 Git 凭据配置，并禁用交互式密码提示；地址不可达或无权限时会明确停止，不会把失败仓库当成有效源码继续分析。
- base/current 可以使用同一个工程目录；两侧身份由各自确认后的远程分支、tag 或 commit 决定。Skill 会查询远端最新 ref、定向 fetch 并固定到具体 commit，在隔离快照中分析，不会切换或拉取你的当前分支。
- 直接产物模式会先解析 JAR；只有依赖坐标仍缺失时才使用对应侧源码补全。Step4 的依赖源码默认只取远端：唯一 ref pair 或多个名称指向同一 commit pair 时自动采用；只有两个以上不同 commit pair、且选择会改变源码对比范围时，才把全部歧义依赖及方案编号汇总到一张决策卡中，用户可一次答全。
- Step1 先从 fat JAR/WAR 解析坐标；坐标确认后通过一次留存遍历固化 Step4 所需的变化 JAR、Step5 所需的全部 current 运行时 JAR和业务内容。Step4、Step5 直接读取这份清单，不会再次解包 fat JAR、递归查询嵌套 JAR、读取本地 Maven 仓库或下载替代 JAR。Step4 使用的依赖源码只增强 Step1 已确定的 GAV，不会重新发现同坐标依赖。
- Step5 的 JAR 类型元数据 `javap` 单次超时为 30 秒；超时后对同一命令最多尝试 3 次，按 1 秒、3 秒退避。非超时错误不盲目重试；重试耗尽后只限制对应类型及相关调用路径，不会把一个类的失败提升为全部 API 的全局“未分析”。
- 分支名只用于定位和展示，确认卡选择会同时绑定 repo、remote、canonical ref、artifact 与当时的 commit SHA。Step1 首次选定的 SHA 是固定快照；后续查询为空或 ref 已移动只触发受控重试和按原 SHA 物化，不会改用新 SHA，也不会要求用户重新确认。Step4 的依赖源码 ref 移动或不可用时不要求用户修复，而是从升级前后最终 JAR 比较同签名方法的规范化字节码，继续识别实现变化。
- 远端 `ls-remote`/`fetch` 对超时、连接重置、临时 DNS/HTTP 5xx 等瞬时错误最多尝试 3 次，重试间隔为 1 秒、3 秒；已选定 SHA 后，定向查询中的 ref 空结果或新 commit 观测也会重试，但不会替换该 SHA。认证失败等确定性错误不重试。Step4 自动重试耗尽后会记录 `DEPENDENCY_SOURCE_REF_UNAVAILABLE`，不会生成要求用户处理网络、权限或 ref 的确认卡，也不会静默使用本地对象；只有运行前已经明确提供 `allow_local_source=true` 时才允许采用本地兜底。若最终 JAR 方法字节码兜底也无法完成，行为变化覆盖会成为关键缺口，报告不得输出“完整”或“不受影响”结论。
- 可用源码用于增加文件/行号、声明与注解、可读上下文和候选关系，并在受支持的常量内联场景与字节码共同形成证明；未提供的业务或依赖源码会分别记录解释覆盖缺口。无论如何，依赖范围、版本、JAR 内容和精确字节码调用边始终以 base/current 最终制品为准。
- 源码映射不会混进 API 变化目录或变成无归属的路径列表：`evidence/source_analysis/review.md` 和 `method_mappings.csv` 同时展示源码归属依赖、实际二进制制品、方法、文件/行号、声明与注解；`candidate_relationships.csv` 另列源码候选调用关系并明确它不是可执行边。人工复核时可以直接判断是哪一个依赖提供的源码解释。
- 只提供源码目录不能证明它对应哪一侧制品；这种输入会先要求确认 revision，确认前不会执行 Maven 或 Gradle。
- 如果存在多个可部署模块且无法唯一判断，Claude Code 必须让你选择目标模块。
- 如果只表达“想分析什么”，但没有提供 base/current 来源或目标模块，Claude Code 会继续追问，不会猜测执行。
- 如果只是查询某个方法调用链，则需要当前工程已经跑完 Step5 并生成查询索引。

### Binary-first 分析引擎

Step4–6 只使用 binary-first 引擎，没有 legacy、shadow、灰度或 fallback 模式。运行配置必须设置：

```json
{
  "binary_pipeline_config": "/abs/path/to/binary-pipeline-input.json"
}
```

输入模板见 `binary_pipeline_config.example.json`，完整运行配置见 `runtime_config.example.json`。身份、支持边界、独立 Oracle 或 sidecar 完整性任一失败时，当前 generation 失败关闭并保留上一份已验证结果；系统不会调用旧引擎补算，也不会逐 API、逐事实或逐边降级。

binary 输出使用 `reachability_status`、`static_linkage_status`、`impact_conclusion`、`runtime_verification_status` 四个独立维度。静态分析最多给出 `probable_impact`，不会伪造 `confirmed_impact`、`confirmed_no_impact` 或已经执行的运行验证。人工复核先看 `evidence/api_changes/changed_dependencies.md`，再进入 `s4_per_dependency/` 的依赖明细；批量筛选使用 `all_changed_apis.csv`。详细文件和复核顺序见 `docs/user/outputs.md`。

---

## Claude Code 停下来问问题怎么办

使用 `--step auto` 时，流程会连续执行到下一个确实需要用户决定的检查点，不再每完成一个步骤就退出。Claude Code 只在缺少外部事实、需要授权或不同选择会实质改变分析结果时停下来；其余步骤自动继续。

常见确认点：

- 目标模块不明确；
- 输入方式不完整；
- 两侧最终制品已经提供，但后续上下文仍缺少基准侧或当前侧分支；该信息会合并到已有的依赖范围确认中，不新增一次确认；
- JDK 版本或业务源码范围无法从制品、构建文件和项目结构可靠确定；
- 是否还能补充其他相关源码；编译模式已取得的业务源码直接使用，用户只需通过统一入口补充更多源码或明确暂不补充；
- 用户提供了源码仓库线索，并产生了会改变源码行为覆盖率的映射建议；系统会要求明确采用或拒绝，拒绝后不会重复询问；
- 依赖坐标或版本无法安全补齐；
- 依赖源码存在两个以上不同 commit pair，且选择会改变源码差异范围；
- Step4 识别出至少两个可分析依赖后，选择 Step5 的全量或部分分析范围；0 个或 1 个候选不存在实际范围取舍，系统会直接继续；
- 是否从某项任务重新分析。

正常流程中的确认顺序是：先确认分析对象与实际依赖范围；随后说明源码作用，并用一个入口收集所有可补充源码或记录暂不补充。编译模式已取得的业务源码不需要授权或重复提交；用户提交的位置由系统自动分类。依赖 API 变化完成后确认全量或部分系统触达范围。兼容性线索扫描、系统触达分析和最终报告会自动衔接。

Step4 识别出至少两个可分析依赖后会让你选择 Step5 的分析范围：全量分析覆盖更完整，部分分析可以降低耗时，但最终结论只适用于所选范围。范围卡会展示依赖数、变化 API 数，以及按业务最终制品直接字节码引用证据排序的 Top 10 依赖和理由。删除或签名变化不会获得额外权重，依赖源码是否可用只作为解释条件展示。0 个或 1 个候选不存在实际范围取舍，系统会直接继续。确认范围后，系统会连续执行 Step5 和 Step6，不再要求点击“继续”；Step5 会把 binary-first 的四态摘要写成非阻塞 `user_decision_card`，供 Agent 直接转述。内部证据故障由系统自动重试或失败关闭，不会混入范围选择要求用户批准降级。

你只需要用自然语言回答即可，例如：

```text
目标模块选择 app-module，继续。
```

```text
可以补充源码，位置是 /abs/path/to/business-source 和 /abs/path/to/dependency-source-repo。
```

```text
暂时无法补充其他源码，按现有制品和源码证据继续。
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
2. **部分分析（仅在明确控制耗时时）**：先看 Top 10 影响复核优先项。排序依次比较业务最终制品精确直接引用的变更 API 数、签名不完整候选引用数、引用指令数和变更 API 总数；变更类型和源码可用性不加权。
3. **从全部候选中选择部分范围**：打开 `.upgrade-report/evidence/api_changes/changed_dependencies.md`，从完整清单复制“依赖包”列中的坐标，例如：`只分析 com.foo:bar、com.foo:baz`。

不需要从 `all_changed_apis.csv` 逐行挑选 API。Top 10 只用于用户已经决定缩小范围后的排序，不表示系统建议缩小范围，也不代表已经确认对当前系统有影响；未观察到业务字节码直接引用同样不代表无影响，跨依赖和框架路径仍由 Step5 分析。

---

## 即时查询方法、依赖或包的调用链

当 Step5 已经生成调用链查询索引后，可以按方法、依赖坐标或 Java 包前缀查询：

```text
查询 com.foo.Bar.baz(String) 的调用链
```

或者：

```text
帮我看一下 org.apache.commons.lang.StringUtils.isBlank(String) 是从哪里被调用到的。
```

```text
查询 commons-lang 的调用链
查询 org.apache.commons.lang 包下所有变更 API 的调用链
```

默认行为：

- 直接在对话中返回调用链；
- 默认按全限定名精确匹配，不会自动退回简单名匹配，避免 `StringUtils`、`JSONArray`、`isEmpty` 这类同名类/方法串链误报；
- 方法全限定名未带签名时，仅聚合该全限定方法的已签名重载，不会按 `equals` 等简单名扩散；
- 依赖可使用完整 `groupId:artifactId[:classifier]` 坐标；仅使用 artifactId 时必须在本次分析范围内唯一，否则会要求改用完整坐标；
- 包前缀按 Java 包段边界匹配，`org.apache.commons.lang` 不会命中 `org.apache.commons.lang3`；
- 聚合查询默认最多返回 20 条；达到上限时会明确提示，可通过 `--limit` 调整；
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
| Step3 | 重新扫描运行平台、应用框架及规范/命名空间迁移风险 |
| Step4 | 重新比较变更依赖 JAR 的 API 变化 |
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

完整主文件是：

```text
.upgrade-report/evidence/call_chain/alerts.csv
```

## Step5 结果状态怎么理解

| 状态 | 含义 |
|---|---|
| `reachable` | 已找到从声明入口到变化 API 的静态调用路径；表示静态触达，不等于已经通过运行测试确认影响 |
| `uncertain` | 已有候选证据，或系统已识别出阻止确定结论的具体静态分析边界，需要按优先级复核 |
| `not_found_in_static_analysis` | 静态分析执行过，但当前范围没有找到引用路径且没有候选路径；不等于确定无影响，也不能视为安全 |
| `not_analyzed` | 输入缺失或工具能力不足，无法完成有效分析 |

特别注意：

- `not_found_in_static_analysis` 不是“确定不影响”。
- 反射、动态代理、运行时配置、依赖源码缺失都可能让结果进入 `uncertain` 或 `not_analyzed`。
- 删除依赖 JAR 的场景下，即使业务源码没有直接引用，运行时依赖 JAR 使用了被删 API 也会进入 Step5 证据链。
- 主报告会按依赖坐标完整展开全部 `reachable` 和 `uncertain` API；`not_found_in_static_analysis` 只在正文中给统计，逐项记录位于 `all-impact-details.md`。

---

## 六个步骤分别做什么

| Step | 作用 | 关键产物 |
|---|---|---|
| Step1 | 比较 base/current 最终依赖差异 | `evidence/dependencies/dep_changes.csv` |
| Step2 | 建立升级上下文、源码和依赖映射 | `evidence/context/context.json` |
| Step3 | 分析运行平台、应用框架、规范/命名空间迁移风险，并比较双侧制品中的 MyBatis/ORM 数据库契约变化 | `evidence/static_scan/*.csv`、`evidence/static_scan/s3_database_contract_changes.md` |
| Step4 | 比较变更依赖 JAR 的 API 变化 | `evidence/api_changes/changed_dependencies.md`、`evidence/api_changes/all_changed_apis.csv` |
| Step5 | 追踪变化 API 是否触达业务代码 | `evidence/call_chain/alerts.csv` |
| Step6 | 生成依赖结论、API 调用关系和两份全量明细 | `deliverables/report.md`、`deliverables/all-affected-dependencies.md`、`deliverables/all-impact-details.md` |

---

## 常见问题

### 多模块项目必须选择目标模块吗？

是。一次分析只对应一个目标部署模块。

如果工具发现多个可部署模块且无法唯一判断，Claude Code 必须让你选择，不能静默选择 root、第一个模块或最大产物。

### 源码路径或 Git 地址应该填什么？

可以一次填写被分析系统或依赖包的源码目录，例如：

```text
/Users/me/source/dependency-project
```

也可以在统一的 `source_locations` 中填写依赖源码 Git 地址，例如：

```json
{"source_locations":["https://git.example.com/team/dependency-project.git"]}
```

不需要自行标注源码类型。编译模式的业务源码通常已由 Maven reactor 或 Gradle project graph 自动推断；直接制品模式可以在同一列表中补充业务源码。

### 没有依赖源码还能分析吗？

可以。系统会先说明缺少源码的影响并记录你的选择。正式变化和精确调用图来自 base/current 最终制品、运行时依赖与目标 JDK 字节码，不依赖源码才能成立；不提供源码会减少文件/行号、声明与注解、可读上下文、候选关系和受支持常量内联证明的覆盖，但不会被解释成“没有影响”。

### Step4 / Step5 很慢怎么办？

Step4 可能超过 Agent 单次命令时限时，Claude Code 应从一开始就使用 `run_step.py --background`，并自行监视以下文件；不应要求用户另开 Git Bash/PowerShell、运行 nohup/临时脚本、授予管理员权限或配置 Defender/杀毒排除：

```text
.upgrade-report/.runtime/background/status.json
.upgrade-report/.runtime/background/run.log
.upgrade-report/.runtime/binary_authority/binary_observability/latest_in_progress.json
.upgrade-report/.runtime/observability/progress.jsonl
```

Step4 完成后再查看：

```text
.upgrade-report/.runtime/observability/step4_timing.csv
```

重点关注 artifact inventory、ASM fact extraction、runtime reconciliation、decision/projection、batch trace、Oracle validation 和 publication 阶段。结合 archive/class/edge 数、缓存命中率与峰值 RSS，可以区分制品解析、运行时裁决、图遍历、独立验证或报告发布的瓶颈。

Step5 慢时，让 Claude Code 查看：

```text
.upgrade-report/.runtime/observability/step5_timing.csv
```

不要只看总耗时、缓存条目数或被中断次数猜瓶颈，也不要把多次中断的累计时间外推为剩余时间。运行时闭包很大、class/edge 很多或独立 Oracle 扫描量很大时，Step4 的整代构建会明显变慢；Step5 只是发布同一 generation 的选择范围和查询视图，不会重新扫描制品。统一后台任务失败时，Claude Code 应读取状态和日志后自动恢复或安全停止，而不是让用户选择执行环境。

### Binary-first 需要哪些分析工具？

生产事实解析使用版本和 SHA 固定的 ASM helper；独立 Oracle 使用目标 JDK 中的 `java`、`javac`、`javap`、`jmods` 和 `lib/modules` 做交叉验证。缺失完整目标 JDK、helper 完整性不符或 Oracle 无法完成时，generation 失败关闭，不会安装或调用 JApiCmp 旧引擎补算。

tree-sitter 只服务可选 source overlay 的源码解释，不是 executable edge 或二进制变化的权威来源。覆盖层不可用会留下明确解释缺口；它不能改变二进制 fact、依赖身份或静态触达路径。

### Kotlin 与 KTS 的结论边界是什么？

Kotlin/KTS 是否可分析由 binary support manifest、最终 classfile 和 RuntimeProfile 决定。源码覆盖层不会把增强正则结果提升为正式调用边；未知 inline 或未注册语言语义进入 `uncertain`、`not_analyzed` 或 generation failure，不能把静态未命中解释为安全。
