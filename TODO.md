# 待优化项

> 实施状态（2026-07-05）：前 11 项优化已落地并通过自动化回归；第 12 项为真实项目回归暴露的新待办。
> 已完成章节保留讨论背景作为设计记录；明确标记“待办”的章节仍表示当前能力缺口。

| 项目 | 状态 | 主要落点 |
|---|---|---|
| 1. 统一源码范围 | 已完成 | `analysis_contract.py`、`run_step.py`；Maven reactor、非标准源码/资源根、目标模块确认 |
| 2. field/class 语义 | 已完成 | 源码直接引用 + 制品字节码字段/类型证据；能力不足返回 `not_analyzed` |
| 3. 安全依赖配对 | 已完成 | 完整坐标优先；同名 artifact 歧义不自动迁移配对 |
| 4. 覆盖模型 | 已完成 | `coverage.json` 及 Step3/4/5 子覆盖；标准模式限制安全结论，严格模式硬门控 |
| 5. 构建溯源 | 已完成 | base/current 成功构建、制品 SHA、源码 revision/profile 对齐与冲突降级 |
| 6. 版本化规则包 | 已完成 | JDK/Jakarta/Spring Boot 规则区间、来源、核验日期和 SHA |
| 7. JApiCmp XML | 已完成 | XML 主解析、source/binary 分离、常量值、文本降级和缺失类覆盖降级 |
| 8. 源码+字节码混合图 | 已完成 | 方法/构造/字段/类型/常量池/签名/注解/`invokedynamic` method handle、MR-JAR 目标 JDK 选择，制品哈希缓存与 jdeps 对照测试 |
| 9. Framework Adapter | 已完成 | SPI、Spring、MyBatis 独立证据、歧义/条件保留、`@Bean` 实现解析及统一图合并 |
| 10. 人工复核链路台账 | 已完成 | `alerts.csv` 每 API 至少一行、每条终止链路一行，逐路径原因、稳定语义 ID、显式消费方/业务入口且不抽样 |
| 11. Step5 分析能力补全 | 已完成当前清单的可交付基线 | Step4 唯一目标集；已落地精确反射、常见反射字节码、静态 MethodHandle、资源/表达式引用、动态代理与声明式 HTTP Client Adapter、覆盖矩阵与正式产物接线 |
| 12. Step5 boolean/varargs 重载推断 | 待办 | 真实 Commons Text 回归暴露：`Validate.isTrue(boolean, String, Object...)` 仍因 boolean 表达式与 varargs 签名推断不足被保守归为 `not_analyzed` |

## 12. Step5 boolean 表达式与 varargs 重载推断补强

### 背景

使用真实 Git 项目 Apache Commons Text（commit `87ace21`）作为被分析系统，模拟
`commons-lang3` API 删除并运行 Step5：

- `StringUtils.isBlank(CharSequence)` 曾因源码调用被推断为 `isBlank(String)`，被重载安全过滤阻断；已通过 Java 内置类型 assignability 修复。
- `Validate.isTrue(boolean, String, Object...)` 仍被归为 `not_analyzed / OVERLOAD_AMBIGUOUS_TARGET`。

当前 `Validate.isTrue` 问题的直接原因是源码调用图里只稳定产生了无签名 key，且部分调用的参数推断出现
`(StringUtils, String)` 一类错误签名；在目标 API 存在重载时，Step5 不能安全地把无签名命中升级为 reachable。

### 优化方向

- 补强布尔表达式类型推断：比较表达式、逻辑表达式、取反、括号表达式应推断为 `boolean`。
- 补强 varargs 兼容：目标形如 `(boolean, String, Object...)` 时，应能安全匹配 `(boolean, String)` 以及后续额外引用类型参数。
- 继续保持重载安全：不得因为存在无签名 `Validate.isTrue` 命中就直接判定 reachable。
- 将 Commons Text `Validate.isTrue` 场景固化为真实项目或精简 fixture 回归，防止后续再次被误判为“未分析”。

### 验收口径

- Commons Text 真实项目回归中，`StringUtils.isBlank(CharSequence)`、`StringUtils.isEmpty(CharSequence)`、`StringUtils.defaultString(String)`、`StringUtils.EMPTY`、`ArrayUtils.isEmpty(char[])` 均为 reachable。
- 在补强 boolean/varargs 后，`Validate.isTrue(boolean, String, Object...)` 能在真实源码调用中安全识别为 reachable。
- 现有错误重载防护测试仍通过，不能引入同名重载误报。

## 1. 简化系统源码相关内部参数模型

### 背景

当前 skill 在系统源码相关输入上同时存在多套概念与落点，例如：

- `project_dir`
- `source_dirs`
- `source-dir`
- `main_state.json` 中的范围类字段
- `s2_context.json` 中的范围类字段
- 各 Step 自己的兜底恢复逻辑

这会带来两类问题：

- 对用户暴露了过多实现细节；用户已经提供系统源码时，不应再被迫理解这些内部参数差异。
- 内部也存在重复真相源和语义不一致问题，导致不同 Step 对"分析范围"的理解可能不一致。

### 目标

把"系统源码输入"相关模型简化为更少、更稳定的内部概念，并减少对用户暴露的实现细节。

目标方向：

- 系统工程已经作为当前工作目录打开时，不再向用户暴露或重复询问 `project_dir` / `source_dirs` / `source-dir` 这类实现细节。
- 内部减少重复真相源，统一"系统根"与"实际分析范围"的语义。
- 各 Step 不再各自重新猜测、恢复或覆盖范围定义。

### 当前讨论结论

建议将内部模型收敛为以下层次：

1. 用户输入层
   - `base_branch`
   - `current_branch`
   - `modules`
   - `dependency_source_dirs`
   - 运行选项，如 `allow_degraded` / `max_depth` / `include_test_scope`
2. 标准化运行上下文
   - 从当前工作目录派生的 `system_source`
   - `analysis_scope`
   - `build_tool`
   - 自动推导出的依赖源码映射结果
3. Step 临时入参层
   - 仅在调用具体脚本时，把标准化上下文转换为脚本参数

### 最终交互口径

当前交互流程通常已经由 Claude Code 的工作目录和调度命令中的
`--project-dir` 确定系统工程根目录，因此本项优化**不新增**“请用户提供系统工程根目录”的交互。

正常 Maven 工程的建议流程为：

1. 直接把当前任务的工程工作目录作为内部 `system_source`。
2. 根据 Maven reactor、目标构建模块和标准目录模型自动生成 `analysis_scope`。
3. 自动识别系统源码目录，不再要求用户填写或确认 `source_dirs`。
4. 只有工程根目录无法确定、存在多个候选工程、源码布局无法从 Maven 模型解析，或自动推导结果存在歧义时，才进入人工交互。
5. `dependency_source_dirs` 继续只表示升级依赖包的源码工程或仓库路径，不得与待分析系统的源码路径混用。

因此，这项优化的重点不是把现有输入改成“用户只提供系统工程根目录”，而是复用已经存在的工程上下文，消除正常流程中的 `source_dirs` 人工确认。

### `analysis_scope` 推导建议

- 单模块 Maven 工程：把当前模块作为推荐候选供用户确认；确认后自动识别 `src/main/java`、`src/main/kotlin`、`src/main/groovy` 与资源目录。
- 系统可以从 Maven reactor 中发现并展示候选模块，但候选识别只用于辅助用户选择，不作为自动决定目标模块的最终依据。
- 用户已经明确目标模块时：把该输入视为已确认，直接采用，不再重复询问。
- 用户尚未明确目标模块时：在第一次执行 Step1 前进入交互，由用户确认本次需要分析的目标模块；即使只发现一个候选模块，也可以把它作为推荐项展示，但不应静默代替用户选择。
- 不得默认选择第一个模块、仓库根模块、体积最大的产物，或当前恰好能够解析的制品所属模块。
- 目标部署模块确定后：通过 Maven reactor 依赖关系自动纳入它依赖的 `common`、`domain` 等业务模块，不应无差别扫描仓库中的全部模块，也不应纳入与目标模块没有依赖关系的其他部署模块。
- 一次分析只对应一个最终部署模块及其构建产物；需要分析多个可部署模块时，应分别执行，避免把不同部署单元的依赖范围、源码范围和影响结论混合在一起。
- 目标模块确认与制品能力检查必须分开：先由用户确认分析对象，再判断该模块的最终制品是否属于当前支持的布局；不支持时应报告能力缺口，不得自动切换到其他模块。
- 非标准源码目录：优先从 effective Maven model 和构建插件配置推导，不应仅依赖目录名递归猜测。
- 自动推导后生成统一的派生视图，至少包含目标模块、纳入的 reactor 模块、源码根、资源根、排除模块、推导状态与原因码。
- Step2 负责生成并展示该视图；Step3、Step5 必须消费同一份已确认视图，不得各自重新扫描和覆盖范围。
- `source_dirs` 保留为兼容字段或异常场景覆盖项，但不再作为正常用户输入，也不应在普通 Step2 checkpoint 中列为推荐确认字段。

### 建议保留的核心概念

- `system_source`
- `base_branch`
- `current_branch`
- `modules`
- `dependency_source_dirs`

### 建议降级为派生值或兼容名的概念

- `project_dir`
- `source_dirs`
- `source-dir`
- `dependency_repo_mappings`
- `dependency_source_mappings`

### 待处理问题

- 明确唯一真相源应如何在 `main_state.json`、执行期 `run_context` 视图与 `s2_context.json` 之间分层，避免多处同时生效。
- 明确 `Step2`、`Step3`、`Step5` 对分析范围的统一消费方式。
- 明确用户输入模型与内部执行模型的边界，避免内部参数继续泄漏到交互层。
- 明确多模块场景下，"系统根"和"分析范围"的最终定义与推导规则。
- `Step3` 当前应默认围绕 `source_dirs` 扫描；只有极少数运行时入口文件是否需要根级补扫，后续再单独设计和处理。

### 验收口径

完成该优化后，应满足：

- 已经在系统工程目录中启动任务时，不再重复询问工程根目录。
- 标准 Maven 工程不再要求用户填写或确认 `source_dirs`。
- 只有自动推导失败或存在歧义时，才要求用户提供范围覆盖信息。
- 用户未预先明确目标模块时，必须在 Step1 前完成一次目标模块确认；选择后各 Step 使用同一个目标模块及 reactor 依赖闭包。
- 候选模块发现和制品可解析性不得替代用户对分析目标的确认，也不得导致系统静默切换目标模块。
- `dependency_source_dirs` 在交互、状态和执行脚本中始终只表示依赖包源码路径。
- 内部只保留一套共享的范围语义，不再由多个 Step 各自兜底。
- `Step2` 确认过的范围信息能够被后续步骤一致消费，不再出现文档语义与实际执行范围不一致。

## 2. 明确 Step5 对 `field/class` 变更的处理语义

### 背景

当前 `Step5` 会接收 `Step4` 传下来的 `symbol_kind=field/class` 变更项，但其核心分析模型仍以方法调用链为主。

这会带来一个语义问题：

- `method/constructor` 变更通常可以沿"谁调用了谁"的反向调用链继续追踪。
- `field/class` 变更更接近字段访问、类型引用、构造使用或类级影响，并不天然等价于方法调用边。
- 在当前能力下，这类变更可能被落到 `not_found_in_static_analysis`，但真实语义更可能是"当前模型未覆盖"而不是"静态确认未使用"。

### 目标

明确 `Step5` 对 `field/class` 变更的正式处理策略，避免把能力边界误写成影响结论。

目标方向：

- 明确 `field/class` 是否属于 `Step5` 当前支持范围。
- 若当前不支持，明确应输出 `not_analyzed` 或单独 reason code，而不是误落到 `not_found_in_static_analysis`。
- 若后续要支持，需单独设计字段访问/类型引用/构造使用等分析能力，而不是继续复用纯方法调用链模型。

### 当前讨论结论

本问题已修复；以下内容保留为当时的设计背景。

当前共识：

- 这是 `Step5` 的语义边界问题，不是单纯的文案问题。
- `field/class` 不能直接等同于方法级反向调用链。
- 在未补齐相应静态分析能力前，应避免输出过强的"静态未找到"语义。

### 待处理问题

- 梳理 `Step4 -> Step5` 对 `symbol_kind=field/class` 的实际输入契约。
- 明确 `field/class` 在当前版本中的期望四态归类。
- 评估是否需要新增专用 reason code，例如表达"当前调用链模型不覆盖字段/类级影响"。
- 补齐最小回归用例，覆盖 `field`、`class` 两类输入，防止后续再次误分类。

### 验收口径

完成该优化后，应满足：

- `field/class` 变更不会再被误写为"静态未找到路径"。
- 报告能清楚区分"当前没找到"与"当前没分析到"。
- `Step5` 的实现、输出语义和文档约束保持一致。

## 3. 避免 Step1 对同名 `artifactId` 依赖产生错误配对

### 背景

当前 Step1 在比较 base/current 最终制品依赖时，主要使用 `artifactId + classifier` 作为条目配对键。这样可以识别 `groupId` 发生迁移但 `artifactId` 保持不变的依赖，例如：

- `com.old:demo-client:1.0`
- `com.new:demo-client:2.0`

但 `artifactId` 并不是全局唯一标识。如果同一侧或两侧同时存在多个不同 `groupId`、相同 `artifactId` 的依赖，当前按组排序后按位置配对的方式可能把真实的升级、新增和删除误判为多次 `groupId` 迁移。

典型歧义场景：

```text
base:
  com.company.a:common:1.0
  com.company.b:common:1.0

current:
  com.company.b:common:2.0
  com.company.c:common:1.0
```

真实变化可能是：

- `com.company.b:common` 从 `1.0` 升级到 `2.0`
- `com.company.a:common` 被删除
- `com.company.c:common` 被新增

当前逻辑则可能错误配对为：

- `com.company.a:common -> com.company.b:common`
- `com.company.b:common -> com.company.c:common`

### 目标

在保留 `groupId` 迁移识别能力的同时，避免同名 `artifactId` 场景被静默错误配对。

### 建议方案

采用两阶段匹配：

1. 第一阶段按完整坐标 `groupId:artifactId:classifier` 精确配对。
2. 第二阶段只处理第一阶段剩余的未配对条目，再按 `artifactId + classifier` 尝试识别 `groupId` 迁移。
3. 只有 base/current 两侧均为唯一候选时，才自动判定为 `groupId` 迁移。
4. 任意一侧存在多个候选时，不按排序位置猜测，应标记为 `unresolved` 并进入人工确认。
5. 在 Step1 输出中保留候选坐标、匹配依据和歧义原因，便于 checkpoint 复核。

### 待处理问题

- 调整 `_build_step1_change_rows` 的配对顺序，先完整坐标匹配，再处理跨 group 候选。
- 明确跨 group 唯一匹配的正式 `change_type` 与证据字段。
- 为歧义匹配设计稳定的 `reason_code` 和交互协议。
- 确认 classifier、同名多版本、同一制品重复物理条目等情况的匹配规则。
- 补齐精确匹配、唯一跨 group 迁移和多候选歧义三类回归测试。

### 验收口径

完成该优化后，应满足：

- 完整坐标相同的依赖始终优先互相配对。
- 唯一的一对跨 group 同名依赖仍可识别为迁移。
- 多个不同 group 使用相同 `artifactId` 时不会再按排序位置静默配对。
- 无法唯一判断的条目以 `unresolved` 明确暴露，而不是产生错误的升级、新增或删除结论。

## 4. 建立统一的证据完整度与分析覆盖状态

### 背景

当前各步骤已经分别记录 jar 缺失、源码映射缺失、解析器降级、git ref 待确认、超时和四态分析结果，但这些信息分散在 Step4 summary、Step5 graph stats、错误文件、门控输出和 checkpoint 中。

当最终报告显示 `P0=0`、`P1=0` 或没有找到调用路径时，用户很难快速区分以下情况：

1. 本次目标已经完整分析，确实没有发现已确认影响。
2. 仅完成了部分分析，当前没有发现影响，但仍存在明确盲区。
3. 关键证据缺失，本次实际上不足以形成兼容性结论。

如果缺少统一的证据完整度视图，"没有发现风险"容易被误读为"已经证明没有风险"。

### 目标

建立统一、可追溯的覆盖状态，让最终报告能够准确说明本次分析完成了什么、没有完成什么，以及缺失证据对结论的具体影响。

覆盖状态不采用单一百分比，正式使用以下四级语义：

- `complete`：该维度计划内目标已完成分析，没有影响结论的已知缺口。
- `partial`：该维度完成了部分有效分析，但存在明确盲区；已有正向证据仍然有效。
- `insufficient`：关键输入或工具缺失，当前不足以形成该维度的有效结论。
- `not_applicable`：根据本次升级范围，该维度不适用，不属于分析缺失。

### 建议覆盖维度

#### Step1：依赖范围

- 两侧制品类型与来源
- 计划/实际解析的依赖数量
- 已解析坐标数量
- `unresolved` 数量与原因
- 不支持的制品类型或异常嵌套结构

#### Step3：静态扫描

- 计划和实际扫描的源码目录
- Java、Kotlin、配置文件数量
- 文件读取失败数量
- 因升级条件不适用而跳过的扫描项

#### Step4：变化证据

必须拆分以下两个维度，不能合并成一个 Step4 总状态：

1. `binary_api_diff`
   - 应分析的变更依赖数
   - JApiCmp/旧 jar 符号分析成功数
   - jar 缺失、工具失败和超时数
2. `behavior_diff`
   - 需要源码行为分析的依赖数
   - 源码映射覆盖数
   - git ref 已确认/待确认数
   - git diff 成功、跳过和失败数

缺少依赖源码只降低行为变化覆盖，不应否定已经获得的二进制变化证据。

#### Step5：业务可达性

- 输入目标 API 数和实际完成分析数
- `reachable` / `uncertain` / `not_analyzed` / `not_found_in_static_analysis` 数量
- Java AST、Java regex 降级和 Kotlin regex 文件数量
- 依赖源码映射缺失数量
- 图截断、边上限、解析失败等完整性原因

### 产物与真相源边界

建议新增派生产物：

```text
.upgrade-report/coverage.json
```

约束：

1. `coverage.json` 由各步骤已有事实和产物自动汇总，用户不需要手工填写。
2. 它是面向报告和门控的派生视图，不替代 `main_state.json` 的主状态真相源。
3. 各步骤仍应保留自己的原始计数、错误和原因码，`coverage.json` 不成为唯一证据来源。
4. 每个状态必须附带原因码和客观计数，避免只有 `partial` 而无法解释缺口。

### 报告与门控语义

报告措辞必须受覆盖状态约束：

- `complete`：允许表述为"在本次明确分析范围内，未发现已确认影响"，仍不得表述为绝对安全。
- `partial`：必须同时展示已有结论和明确盲区，例如"当前未发现已确认影响，但行为变化分析缺少部分依赖源码"。
- `insufficient`：必须明确表述为"证据不足，不能形成兼容性结论"。
- `not_applicable`：说明该维度为何不适用于本次升级，不计入缺失项。

运行模式建议：

- 标准模式：允许 `partial` 生成报告，但必须显著展示盲区；关键维度为 `insufficient` 时进入 checkpoint 或阻断。
- 严格模式：关键维度不是 `complete` 时阻断，不接受带已知盲区的最终结论。
- 只有真正影响结论的缺口才触发 checkpoint，避免覆盖统计增加无意义的人工确认。

### 待处理问题

- 定义 `coverage.json` schema、版本号、维度枚举和原因码集合。
- 明确每个 Step 负责提供哪些原始覆盖事实，以及 Step6 如何汇总。
- 明确标准模式和严格模式下哪些维度属于关键维度。
- 处理空目标集合：区分"没有目标"、"目标不适用"和"目标提取失败"。
- 在最终报告顶部展示整体覆盖状态和关键盲区摘要。
- 增加覆盖状态的回归测试，验证缺 jar、缺源码、解析器降级、空 API 集和完整分析场景。

### 验收口径

完成该优化后，应满足：

- 最终报告能够直接回答本次分析是否完整，以及不完整的具体原因。
- `P0=0`、`P1=0` 或零调用路径不再被误解为绝对无风险。
- 二进制变化证据和行为变化证据的覆盖状态相互独立。
- 标准模式能保留部分有效结论并明确盲区，严格模式能阻断关键覆盖缺失。
- 覆盖信息全部从运行事实自动生成，不增加用户填写内部统计字段的负担。

## 5. 使用构建溯源校验静态 P0，避免把证据冲突写成已确认编译失败

### 产品定位

本 Skill 只分析 base/current 均已成功构建并产出最终制品的升级结果，定位为"升级完成后的兼容性复核工具"。

明确不扩展以下场景：

- current 升级分支尚未构建成功时的编译错误排障
- 使用临时 dependency tree 代替 current 最终制品继续完整流程
- 在 current 没有最终制品时生成正式兼容性结论

如果任意一侧构建失败或没有受支持的最终制品，Step1 继续保持阻塞语义。

### 背景

自动构建模式会对 base/current 分支执行真实 Maven `package`。如果 current 构建成功，并且构建源码、依赖、模块和最终制品与 Step5 分析对象完全一致，那么 current 主源码已经通过编译。

此时若 Step4/Step5 又得出"业务源码调用了已删除或签名不兼容 API，因此已确认编译失败"，两份证据不能同时成立。可能原因包括：

- Step5 分析源码与 current 构建 commit 不一致
- direct artifact 与当前分析源码并非同一构建来源
- Step1 和 Step5 模块范围不一致
- 构建实际使用的依赖与 Step4 对比依赖不一致
- Step4 API 身份、声明类型或签名解析错误
- Step5 重载、继承、类型归属或调用点匹配错误
- 产物为旧产物或构建 profile/生成源码范围不同

因此，静态分析发现的 P0 默认只能表达"编译不兼容候选"；如果同时存在完全对齐的构建成功证据，应表达为"证据冲突"，不能继续展示为已确认编译失败。

### 正式结论语义

建议将相关结论拆分为：

- `binary_incompatibility`：依赖 API 已确认发生二进制/源码不兼容变化，这是依赖层变化事实。
- `compile_break_candidate`：静态分析认为当前业务源码引用了该变化 API，但没有实际编译失败证据。
- `evidence_conflict`：current 构建成功且构建证据与分析对象完全对齐，但静态分析仍预测编译失败。

最终报告不再把纯静态结果直接命名为"P0 编译失败"。建议使用：

- `P0 静态编译不兼容候选`
- `证据冲突，需复核`

只有未来存在真实编译器失败证据并能归因到具体变化 API 时，才允许使用 `compile_failure_confirmed`；该能力不属于当前产品范围。

### 构建溯源要求

自动构建模式应为 base/current 分别记录：

```json
{
  "status": "success",
  "commit": "<git commit>",
  "module": "<primary module>",
  "jdk": "<effective jdk>",
  "command": "<build command>",
  "artifact_path": "<final artifact>",
  "artifact_sha256": "<sha256>"
}
```

Step5 同时记录：

- 实际分析的源码 revision
- `source_dirs`
- 模块范围
- 实际使用的依赖变化输入身份

只有以下信息全部对齐，current 构建成功才能用于反证静态 P0：

1. 构建 commit 与分析源码 commit 一致
2. 构建模块与分析模块一致
3. 构建最终制品与 Step1 读取制品一致
4. 构建依赖与 Step1/Step4 的依赖身份和版本一致
5. 分析范围没有因 profile、生成源码或目录配置产生已知偏差

### Direct artifact 模式

用户直接提供 current jar/war，只能证明该产物曾被成功构建，不能天然证明它与当前正在分析的源码属于同一个 commit。

系统可尝试从以下信息建立关联：

- `git.properties`
- `build-info.properties`
- Manifest 中的 revision/build 信息
- CI 注入的 commit/build metadata
- 用户显式提供并确认的制品来源 revision

若无法建立可靠关联，应记录：

```text
source_artifact_alignment=unverified
```

此时静态结果保留为 `compile_break_candidate`，不能因为"产物存在"而自动转成 `evidence_conflict`。

### 待处理问题

- 定义 Step1 构建溯源字段和 schema 版本。
- 自动构建模式记录 commit、模块、JDK、构建命令和制品 SHA-256。
- direct artifact 模式增加构建元数据探测和 `source_artifact_alignment` 状态。
- Step5 记录分析源码 revision、模块和输入依赖身份。
- Step6 增加构建证据与静态 P0 的一致性检查。
- 调整 P0 报告标题和 reason code，避免把静态预测写成实际编译结果。
- 为完全对齐、无法对齐、commit 不一致、模块不一致和依赖版本不一致补齐回归测试。

### 验收口径

完成该优化后，应满足：

- base/current 构建失败时仍在 Step1 阻塞，不生成正式升级结论。
- 纯静态分析结果不会再被表述为"已确认编译失败"。
- current 构建成功且证据完全对齐时，冲突的静态 P0 被明确标记为 `evidence_conflict`。
- direct artifact 无法关联源码 revision 时，报告明确显示来源未验证，不使用构建成功反证静态结果。
- 每条编译不兼容候选都能追溯到构建、源码、模块、依赖版本和 API 变化证据。

## 6. 将 Step3 JDK/Spring 扫描规则升级为版本化知识库

### 背景

当前 JDK、Spring Boot、Jakarta 和运行参数相关规则主要直接写在 `s3_scan.py` 的 Python 常量和正则中。扫描过程能够发现一批常见风险，但规则内容、适用版本、匹配方式和扫描引擎耦合在一起。

当前主要问题：

- JDK 规则没有统一、严格地根据 `jdk_base -> jdk_current` 过滤适用范围。
- 例如分析 `JDK 8 -> 11` 时，JDK 17/20 才废弃或移除的规则也可能被扫描并展示，形成与本次升级无关的误报。
- `REMOVED`、`DEPRECATED`、默认行为变化和运行参数变化缺少统一的适用区间模型。
- 新增或修正规则需要修改 Python 代码，知识维护与扫描实现无法独立评审。
- 规则缺少统一的官方来源、最后验证时间和规则包版本。
- 纯文本正则命中与结构化引用、JDK 工具证据之间的可信度没有统一分层。

### 目标

将“扫描引擎”和“升级知识”分离，通过离线、版本化、可追溯的规则包，确保 Step3 只应用与本次升级区间相关的规则，并明确每条命中的证据类型和可信度。

### 知识库结构

建议新增：

```text
knowledge/
  jdk_rules.json
  spring_boot_rules.json
  spring_framework_rules.json
  jakarta_rules.json
```

优先使用 JSON，避免为运行时新增 YAML 解析依赖。

规则最小字段建议包含：

```json
{
  "id": "jdk.removed.javax_xml_bind",
  "ecosystem": "jdk",
  "category": "removed_api",
  "deprecated_version": 9,
  "removed_version": 11,
  "applies_when": {
    "crosses_removed_version": true
  },
  "matchers": [
    {
      "type": "java_reference",
      "pattern": "javax.xml.bind"
    }
  ],
  "severity": "P0",
  "confidence": "high",
  "message": "JAXB 从 JDK 11 中移除",
  "remediation": [
    "显式添加 JAXB API 和实现依赖"
  ],
  "sources": [
    {
      "title": "官方迁移文档",
      "url": "<official-url>"
    }
  ],
  "last_verified": "<date>"
}
```

### 版本适用语义

不同规则类型必须使用不同的适用条件，不能只保存一个描述性版本字符串。

#### API 移除

当满足以下条件时应用：

```text
base < removed_version <= current
```

例如 JAXB/JDK11 规则：

- `8 -> 11`：应用
- `8 -> 17`：应用
- `11 -> 17`：不应用
- `17 -> 21`：不应用

#### API 废弃

根据规则语义使用 `crosses_deprecated_version` 或 `target_at_least`，但只能输出废弃提醒，不能自动归类为编译失败。

#### 默认行为变化

使用 `base_before`、`target_at_least` 或明确的 source/target range 表达跨版本边界。

#### Spring Boot/Spring Framework

使用来源版本区间和目标版本区间，例如：

```json
{
  "source_range": "[2.0,3.0)",
  "target_range": "[3.0,4.0)"
}
```

`javax -> jakarta` 等规则只在跨越相应大版本边界时应用，不在所有 Spring 升级中重复提示。

### 匹配器和证据等级

建议支持并区分以下 matcher：

- `java_import`
- `method_invocation`
- `type_reference`
- `config_key`
- `resource_content`
- `text_regex`
- `bytecode_reference`
- `tool_output`

匹配器类型必须参与置信度求值：

- JDK 工具或精确字节码引用：高
- AST/import/类型引用：中高或高
- 配置键精确匹配：高
- 纯文本正则：中低，默认只生成候选信号

纯文本正则命中不得直接冒充已确认业务影响。

### 三层证据模型

Step3 建议按三层产生证据：

1. JDK 官方工具
   - `jdeprscan`
   - `jdeps --jdk-internals`
   - 用于废弃 API、内部 API 和 class 依赖证据
2. 版本化知识库
   - 补充移除模块、JVM 参数、默认行为、TLS/Locale/GC 等迁移知识
3. 源码和配置扫描
   - 补充字符串类名、XML、YAML/properties、SPI、反射和启动脚本

三层结果必须保留各自的 `evidence_type`，不能互相冒充。

### 规则包发布与可追溯性

运行时不自动联网更新规则，避免同一 Skill 版本在不同时间产生不可重复的结论。

规则包应：

- 随 Skill 版本发布
- 通过代码评审更新
- 每条规则包含官方来源与 `last_verified`
- 记录规则包版本和 SHA-256
- 允许加载企业自定义规则，但必须保留来源和覆盖/扩展行为记录

`coverage.json` 应记录：

```json
{
  "rule_pack": {
    "jdk": "<version>",
    "spring_boot": "<version>",
    "custom": "<optional-version>"
  }
}
```

### 输出与兼容策略

Step3 内部建议先生成统一结构化 finding：

```json
{
  "rule_id": "jdk.removed.javax_xml_bind",
  "status": "applicable",
  "match_type": "java_import",
  "confidence": "high",
  "file": "<path>",
  "line": 12,
  "upgrade_range": "8->17",
  "evidence_level": "source_reference",
  "severity": "P0_candidate",
  "source": "official_jdk_rule_pack"
}
```

迁移初期继续生成现有 `s3_*.csv/.txt`，保证 Step6 和现有测试兼容；后续再逐步让 Step6 直接消费结构化 finding。

### 分阶段实施

第一阶段：

- 将现有 JDK/Spring 规则外置为 JSON
- 实现严格版本区间过滤
- 保持现有扫描器和 CSV 输出

第二阶段：

- 引入统一 matcher 和 finding schema
- 接入 `jdeprscan`、`jdeps`
- 增加规则来源、规则包版本和覆盖统计

第三阶段：

- Step6 直接消费结构化 finding
- 支持经过校验的企业扩展规则包

### 待处理问题

- 定义统一规则 schema 和版本范围表达方式。
- 明确 JDK、Spring Boot、Spring Framework、Jakarta 各规则包的边界。
- 为现有规则补齐官方来源、适用版本和最后验证日期。
- 明确工具不可用时的 `partial/insufficient` 覆盖语义。
- 防止自定义规则静默覆盖内置规则。
- 为每条版本边界补齐正向/反向测试，例如 `8->11` 应命中而 `11->17` 不应命中 JAXB 移除规则。

### 验收口径

完成该优化后，应满足：

- Step3 只执行与本次 base/current 升级区间相关的规则。
- `JDK 8 -> 11` 不再展示只与 JDK17/20 相关的风险。
- 每条命中都能追溯到规则 ID、规则包版本、证据类型和官方来源。
- 纯文本正则不会被直接解释为已确认业务影响。
- 规则更新不需要修改扫描引擎核心代码。
- 相同 Skill 版本和相同输入能够重复生成相同规则结论。

## 7. 将 Step4 JApiCmp 迁移为结构化 XML 主解析并区分源码/二进制兼容性

### 背景

当前 Step4 执行 JApiCmp 后，主要解析 stdout 中面向人工阅读的 diff 文本，再转换为 `all_changed_apis.csv`。现有实现已经为 declaring type、构造器、字段、方法链末端、泛型签名、嵌套类和部分工具输出差异增加了较多兼容逻辑。

这种方式的问题是：

- 人类可读文本不是稳定的数据契约，JApiCmp 版本或输出格式变化可能造成静默误解析。
- 当前使用 `--only-incompatible`，主要关注 binary incompatible 项，不能完整表达 source compatibility 与 binary compatibility 的差异。
- `--ignore-missing-classes` 可以让分析继续，但会隐藏 classpath 不完整这一证据缺口。
- 单一 `change_type` 无法完整表达一个 API 同时具有删除、源码不兼容和二进制不兼容等多个事实。

JApiCmp 0.21.2 原生支持 `--xml-file` 输出，因此可以在不更换工具的前提下迁移到结构化结果。

### 目标

使用 JApiCmp XML 作为机器解析的正式数据来源，同时保留 stdout 文本作为人工证据和兼容兜底；完整区分源码兼容性和二进制兼容性，避免文本解析脆弱性和兼容性语义丢失。

### 双轨输出与解析策略

JApiCmp 一次执行同时产生：

```text
JApiCmp
  ├── XML：正式机器解析输入
  └── stdout：人工阅读证据与解析失败兜底
```

约束：

1. XML 原始文件和 stdout 原始文本都必须保留。
2. 正式结果优先从 XML 生成。
3. XML 缺失、损坏或 schema 不支持时，才允许回退现有文本解析器。
4. 文本回退必须记录原因码，并将 `binary_api_diff` 覆盖状态降为 `partial`，不得静默回退。
5. XML parser 必须记录实际支持的 JApiCmp 版本范围。

### 兼容性事实模型

建议先保存 JApiCmp 原始兼容性事实：

```json
{
  "binary_compatible": false,
  "source_compatible": false,
  "compatibility_changes": [
    "METHOD_REMOVED"
  ],
  "old_signature": "(java.lang.String)",
  "new_signature": null,
  "japicmp_version": "0.21.2"
}
```

再映射为内部主分类和兼容性标记：

- 方法/类/字段删除 -> `REMOVED`
- 参数或返回类型变化 -> `SIGNATURE_CHANGED`
- 可见性降低 -> `ACCESS_REDUCED`
- 注解不兼容变化 -> `ANNOTATION_INCOMPATIBLE`
- `binary_compatible=false` -> `BINARY_INCOMPATIBLE`
- `source_compatible=false` -> `SOURCE_INCOMPATIBLE`

为保持现有 Step5 兼容，继续保留单值 `change_type` 作为主分类，同时新增：

```text
compatibility_flags[]
binary_compatible
source_compatible
compatibility_changes[]
```

### 源码兼容但二进制不兼容 / 二进制兼容但源码不兼容

Step4 必须分别保存两种兼容性事实，不能只保留二进制不兼容结果。

典型的“二进制兼容但源码不兼容”场景包括：

- 新增重载后，原源码中的 `method(null)`、lambda 或方法引用重新编译时产生歧义，但已有 class 仍绑定原方法描述符。
- 泛型签名变化后，JVM 擦除描述符保持一致，但原源码重新编译时类型检查失败。
- 方法新增受检异常后，已有 class 仍能链接，但原源码重新编译时需要新增 catch/throws。
- 类型参数约束变严格后，擦除描述符保持一致，但原源码不再满足泛型约束。

结合当前产品定位：base/current 都已经成功构建。因此，`source_compatible=false` 只能先生成 `compile_break_candidate`。如果 current 构建证据与分析源码、模块、依赖和制品完全对齐，则应转为 `evidence_conflict`，不能直接报告 current 已编译失败。

### JApiCmp 执行参数

迁移后建议评估将：

```text
--only-incompatible
```

调整为：

```text
--only-modified
```

由 XML parser 根据 `binary_compatible`、`source_compatible` 和 compatibility changes 决定正式分类，避免漏掉 binary compatible 但 source incompatible 的变化。

该调整应在双轨结果验证通过后实施，不能与第一阶段直接绑定上线。

### Missing class 处理

长期目标是尽量为 JApiCmp 提供 old/new 完整 classpath，而不是无条件依赖 `--ignore-missing-classes`。

如果仍需忽略缺失类，必须记录：

```text
missing_class_policy=ignored
binary_api_diff=partial
reason_code=JAPICMP_MISSING_CLASSES_IGNORED
```

已有正向不兼容证据仍然有效，但不能据此形成完整的负向结论。

### 原因码

至少定义：

- `JAPICMP_XML_NOT_GENERATED`
- `JAPICMP_XML_INVALID`
- `JAPICMP_XML_SCHEMA_UNSUPPORTED`
- `JAPICMP_TEXT_FALLBACK_USED`
- `JAPICMP_MISSING_CLASSES_IGNORED`
- `JAPICMP_VERSION_UNSUPPORTED`

### 工具版本与可重复性

- 继续固定 JApiCmp 版本，不在运行时自动升级。
- 记录 JApiCmp 实际版本与 jar SHA-256。
- XML parser 明确声明支持版本。
- 升级 JApiCmp 时必须运行 XML 黄金样本回归。

### 分阶段实施

#### 第一阶段：双输出比对

- 增加 `--xml-file`
- 文本解析暂时仍作为正式结果
- 同时解析 XML，并逐条比较文本/XML 的 API 身份、符号类型、签名和变化类型
- 差异只告警，不改变当前正式业务行为

#### 第二阶段：XML 成为主输入

- XML 生成正式 `all_changed_apis.csv`
- stdout 仅用于人工证据和失败兜底
- 文本回退标记 `partial`

#### 第三阶段：扩展兼容性模型

- 评估切换为 `--only-modified`
- 同时分析 source/binary compatibility
- 增加 `compatibility_flags`
- 完善注解、字段、类级变化语义

### 测试要求

建立固定 JApiCmp 0.21.2 XML 黄金样本，至少覆盖：

- 方法删除
- 返回类型变化
- 参数变化
- 构造器删除
- 字段变化
- class 可见性变化
- 注解变化
- 泛型变化
- 嵌套类
- binary compatible 但 source incompatible
- 缺失 classpath
- XML 解析失败后的文本回退

测试应断言 XML 到内部 finding 的映射，而不仅是字符串解析结果。

### 验收口径

完成该优化后，应满足：

- 正式 API 变化结果优先来自结构化 XML，而不是人类可读文本。
- stdout 原始证据仍被完整保留。
- XML 失败不会静默回退，报告能明确显示回退和覆盖降级。
- source compatibility 与 binary compatibility 分别保存和展示。
- binary compatible 但 source incompatible 的变化不会被 `--only-incompatible` 静默遗漏。
- 纯静态源码不兼容结果遵守构建溯源规则，不直接写成 current 已编译失败。

## 8. 将 Step5 升级为源码 AST 与业务字节码混合证据图

### 背景

当前 Step5 主要从业务和依赖源码构建方法调用图：Java 优先使用 tree-sitter AST，解析失败和 Kotlin 场景降级到增强正则；同时已经存在依赖 jar 元数据补图、`javap` 和 packaged runtime dependency 字节码兜底能力。

现有能力对源码可读性、调用位置和人工复核较友好，但源码侧仍需要推断 receiver 类型、重载签名、泛型、继承派发、lambda 和生成方法。在 Lombok、生成源码、复杂链式调用、Kotlin 或 AST 降级场景中，调用边可能缺失或不精确。

由于本 Skill 已明确只分析 base/current 均成功构建的升级结果，current 最终制品中的业务 `.class` 是本次真实构建行为的重要证据，应提升为 Step5 的正式证据源，而不只在依赖源码映射缺失时做局部兜底。

### 目标

在现有源码 AST 图基础上，引入 current 业务制品字节码中的真实调用、字段和类型引用，并合并为一张统一证据图：

```text
源码 AST：提供源码语义、文件和行号
业务字节码：确认真实编译后的调用目标和 JVM 描述符
框架/配置证据：后续补充动态和隐式调用边
```

本优化不替换源码 AST，也不创建一套与现有图互不关联的独立图。

### 字节码证据范围

至少支持：

- `invokevirtual`：普通实例方法调用
- `invokestatic`：静态方法调用
- `invokeinterface`：接口方法调用
- `invokespecial`：构造器、父类和私有方法调用
- `invokedynamic`：lambda、方法引用等动态调用点的可解析 bootstrap 信息
- `getfield` / `putfield`：实例字段读写
- `getstatic` / `putstatic`：静态字段读写
- `new`：对象构造
- `checkcast` / `instanceof`：类型转换和类型判断
- class 常量池、注解、方法描述符和泛型签名中的类型引用

这些证据将用于补强 method、constructor、field 和 class 四类变化目标。

### 统一符号身份

源码和字节码必须归一化到同一套符号身份，建议以 JVM owner/name/descriptor 为精确主键：

```text
method:      owner#name(descriptor)
constructor: owner#<init>(descriptor)
field:       owner#field:descriptor
class:       owner
```

同时保留 Java 可读签名，用于与 Step4 `api_name/api_signature` 和报告展示兼容。

内部调用边示例：

```json
{
  "caller": "com.example.OrderService#process()V",
  "callee": "com.example.Client#send(Ljava/lang/String;)V",
  "edge_kind": "method_call",
  "source_evidence": {
    "file": "OrderService.java",
    "line": 42,
    "parser": "tree_sitter"
  },
  "bytecode_evidence": {
    "opcode": "invokevirtual",
    "descriptor": "(Ljava/lang/String;)V",
    "class_entry": "BOOT-INF/classes/com/example/OrderService.class"
  },
  "confidence": "high"
}
```

### 证据合并语义

建议使用以下优先级：

- 源码与字节码指向同一精确符号：`high`，作为最强普通调用边。
- 只有字节码精确调用边：`high`，说明真实制品存在该引用；源码位置可通过 LineNumberTable 尽量恢复。
- 只有源码精确 AST 边：`medium/high`，保留现有规则，但记录没有字节码交叉确认的原因。
- 只有增强正则边：按现有规则保持较低置信度。
- 源码与字节码目标冲突：不得静默选择其中一个，应生成 `SOURCE_BYTECODE_EDGE_CONFLICT` 并进入人工复核或 `uncertain`。

源码图和字节码图的缺失不能相互冒充：例如 class 因 profile 未构建、源码不属于 current commit 或调试行号缺失，都应保留明确原因。

### 与构建溯源联动

只有在第 5 项定义的构建溯源满足以下条件时，业务字节码才能作为 current 源码的交叉验证证据：

- current artifact 与 Step1 记录的 artifact path/SHA-256 一致
- artifact 对应的 commit 与分析源码 revision 一致
- 模块范围一致
- 构建依赖与 Step1/Step4 输入一致

direct artifact 无法验证源码对齐时，字节码引用本身仍是有效的制品事实，但不能自动映射为当前工作区源码行，也不能用来反证源码候选。

### 业务 class 发现

根据 current 最终制品类型读取业务 class：

- Spring Boot jar：`BOOT-INF/classes/`
- war：`WEB-INF/classes/`
- 其他受支持的 packaged jar：主 class entries

必要时可以复用构建目录，但最终制品仍是正式证据来源；构建目录只能作为行号和源码映射的辅助来源。

### 实现策略

不建议第一阶段直接对所有业务和依赖 class 执行大量独立 `javap` 进程。

建议分阶段：

#### 第一阶段：目标驱动的业务字节码确认

- 只对 Step4 目标 API 和 Step5 bridge-check 涉及的业务 class 做字节码扫描
- 复用现有 `javap -c -s -p` 解析能力
- 将精确 method/field/class 引用作为 Step5 附加证据
- 不改变现有源码图主流程，只比较和补强结果

#### 第二阶段：共享业务字节码索引

- 一次扫描 current 业务 class，建立方法、字段、类型和反向引用索引
- 避免每个 API 重复运行 `javap`
- 将索引缓存到报告目录，缓存键包含 artifact SHA-256 和分析引擎版本

#### 第三阶段：专用字节码提取器

- 评估使用独立 Java/ASM helper 批量输出结构化 JSON
- 减少对 `javap` 文本格式和大量子进程的依赖
- helper 版本、依赖和输出 schema 必须固定并可复现

### 对生成代码和 Lombok 的价值

字节码图可以看到源码中不存在的方法体和桥接方法，例如 Lombok getter/setter、编译器 bridge method、lambda synthetic method 和 annotation processor 生成代码。

这些边应标记为 `bytecode_only`，报告中说明源码位置可能只能恢复到类或调用行，不能伪造源码方法定义。

### field/class 专项语义

引入字节码后，Step5 对非方法符号应分别处理：

- field：读、写、静态访问、字段描述符
- class：构造、类型转换、`instanceof`、方法/字段签名类型、注解和常量池引用
- constructor：`new + invokespecial <init>`

对于编译期常量内联，业务 class 可能不再保留字段访问边。此时需要单独比较 constant value 与 class 常量池，不能把没有 `getstatic` 解释为未使用。

### 能力边界

源码 + 字节码混合图仍不能完整解决：

- 反射和动态类名
- Spring 动态代理、AOP 和条件 Bean
- SPI 和配置注册
- 运行时生成类
- 序列化框架动态字段访问

这些场景继续使用 `uncertain/not_analyzed`，并由后续框架 adapter 或配置证据补充，不能因为有字节码图就输出过强的负向结论。

### 覆盖状态

`coverage.json` 中增加：

- 业务 class 总数和已扫描数
- 业务方法总数和已索引数
- method/field/class 字节码边数量
- 字节码扫描失败数量
- LineNumberTable 可用数量
- source+bytecode 一致边、source-only、bytecode-only 和 conflict 数量
- artifact/source alignment 状态

### 测试要求

至少覆盖：

- 精确实例/静态/接口调用
- 构造器调用
- 字段读写和静态字段访问
- `new/checkcast/instanceof`
- lambda 和方法引用
- 方法重载描述符
- Lombok/生成方法等 bytecode-only 场景
- bridge method
- 源码与字节码冲突
- 缺失 LineNumberTable
- Boot jar、war 业务 class 发现
- 编译期常量内联
- direct artifact 来源未验证

### 验收口径

完成该优化后，应满足：

- current 业务字节码成为 Step5 正式、可追溯的证据来源。
- 源码和字节码使用统一符号主键并合并到同一张反向图。
- 精确字节码调用可以纠正或补充源码类型推断、重载和生成代码缺口。
- field/class 不再只依赖方法调用图或文本搜索。
- 源码/字节码冲突被明确暴露，不会静默覆盖。
- 动态框架和反射盲区仍保持保守四态语义。

### 补充决策：所有依赖变更统一使用最终制品字节码基线

源码映射只能增强业务路径解释，不能成为依赖引用发现的前提。升级、降级、删除、坐标迁移及传递依赖版本变化都必须先完成以下分析：

1. Step1 在临时 worktree 清理前留存 base/current 最终制品，并记录 SHA-256。
2. Step5 从 current 最终制品直接提取业务 class 和每个 `lib_entry` 对应的嵌套 JAR。
3. 对 Step4 变化类、方法、构造器和字段扫描全部业务 class 与运行时依赖字节码。
4. 本地 Maven 仓库只能作为降级来源，不能冒充最终制品；使用 fallback 时覆盖状态至少降为 `partial`。
5. 任意嵌套 JAR 缺失、坐标 unresolved、制品哈希不一致或字节码解析失败时，未命中不得输出为无影响。
6. 使用真实 `javac/jdeps/javap` 建立回归对照：`jdeps` 能发现的跨 JAR 静态依赖，本 Skill 必须发现；在此基础上继续提供成员级兼容性与业务可达性。

这项规则替代“只在没有目标依赖源码映射时触发字节码 fallback”的旧语义，也不能只针对依赖删除场景打补丁。

## 9. 使用独立 Framework Adapter 补充 Spring、MyBatis 和 SPI 隐式调用边

### 背景

通用源码 AST 和业务字节码图主要能够识别显式 Java/JVM 调用，但实际 Java 系统中存在大量由框架、配置和资源注册驱动的隐式调用：

- Spring `@EventListener`、`@Bean`、Runner、Filter、Interceptor、Converter 等回调
- Spring Bean 接口注入到具体实现的运行时派发
- Spring Boot `AutoConfiguration.imports` 和旧版 `spring.factories`
- MyBatis Mapper 接口到 XML statement 的绑定
- `ServiceLoader.load` 到 `META-INF/services` 实现类注册
- Jackson/JPA 等基于注解、反射和运行时代理的成员访问

这些关系通常不存在普通 Java 调用边。继续把所有框架规则硬编码进通用 tracer，会导致框架语义互相污染、覆盖率不可解释、边来源不清晰，也难以独立测试和演进。

### 目标

为不同框架建立独立 Adapter，由 Adapter 读取自己理解的源码、字节码、注解、配置和资源证据，输出统一格式的框架节点、边、finding 和覆盖状态，再合并进 Step5 的统一证据图。

Adapter 不替代通用 AST/字节码图，只负责补充框架隐式关系。

### Adapter 协议

每个 Adapter 至少实现：

```text
detect(context)
analyze(inputs)
```

统一输出建议：

```json
{
  "adapter": "spring",
  "version": "1.0",
  "status": "complete",
  "nodes": [],
  "edges": [],
  "findings": [],
  "coverage": {},
  "warnings": []
}
```

每条框架边至少包含：

- `edge_kind`
- `confidence`
- `adapter`
- `adapter_version`
- `evidence`
- `activation_conditions`
- `candidate_count`
- `ambiguity_reason`

框架边必须使用独立 `edge_kind`，不能伪装成普通 `instance_call/static_call`。

### 保守求值规则

Adapter 只能根据可验证证据建立边：

- 注解、资源文件或配置明确注册：可建立对应框架边。
- 接口只有唯一可用实现且 Bean 条件明确：可建立较高置信度派发边。
- 存在多个实现但缺少 `@Qualifier`、`@Primary` 或明确条件：不得任选一个实现。
- `@Conditional*`、profile 或 property 条件无法求值：记录 activation condition，结论保持 `uncertain`。
- 动态代理只能建立到接口/代理边界的框架边，不能无证据归因到具体实现。
- Adapter 解析失败或覆盖不完整时，必须反映到 `coverage.json`，不能退化为"没有框架调用"。

多候选示例应输出：

```text
reason_code=AMBIGUOUS_FRAMEWORK_DISPATCH
analysis_status=uncertain
```

### 第一阶段：SPI Adapter

优先实现确定性较高的资源注册关系：

- `ServiceLoader.load(Interface.class)`
- `META-INF/services/<interface>`
- Spring Boot `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- 旧版 `META-INF/spring.factories`

SPI Adapter 应建立：

```text
加载点/框架启动 -> 接口 -> 注册实现
```

并记录资源路径、行号、接口和实现类名。

### 第二阶段：Spring 基础 Adapter

优先覆盖：

- `@EventListener`
- `ApplicationRunner`
- `CommandLineRunner`
- `@Bean`
- `Filter`
- `HandlerInterceptor`
- `Converter` / `Formatter`
- `WebMvcConfigurer`
- 明确唯一实现的 Bean 注入

框架入口示例：

```json
{
  "caller": "SPRING_EVENT_DISPATCH",
  "callee": "OrderListener.handle(OrderCreatedEvent)",
  "edge_kind": "spring_event_listener",
  "confidence": "high",
  "evidence": {
    "annotation": "@EventListener",
    "file": "OrderListener.java",
    "line": 20
  }
}
```

现有 tracer 中对 Formatter、WebMvcConfigurer 等框架入口的硬编码识别，应逐步迁移到 Adapter 或共享框架语义层，避免形成两套规则。

### 第三阶段：MyBatis Adapter

至少支持：

- Mapper 接口与 XML namespace 对应关系
- 方法名与 statement id 对应关系
- parameterType/resultType 类型引用
- TypeHandler
- MyBatis plugin Interceptor
- 注解式 Mapper 查询

MyBatis Adapter 应区分：

- Java 调用 Mapper 接口方法：普通/字节码调用边
- Mapper 方法到 XML statement：MyBatis binding 边
- XML 中引用的类型和处理器：配置/资源引用边

### 后续 Adapter

根据真实项目需求再评估：

- Jackson
- JPA/Hibernate
- Spring Security
- Spring Batch
- 消息监听器与消息框架

不在第一阶段试图覆盖所有框架。

### Adapter 启用策略

根据 Step2 tech flags、当前依赖和资源文件自动探测：

- 框架明确不存在：`not_applicable`
- 框架存在且 Adapter 完整执行：`complete`
- 框架存在但部分资源/条件不可求值：`partial`
- 框架存在但关键输入无法读取：`insufficient`

用户可显式禁用某个 Adapter，但必须记录禁用原因，严格模式下按覆盖规则求值。

### 与统一图的合并

Adapter 输出的边与 AST/字节码边使用统一符号身份，但保留独立 provenance：

```text
explicit_source_call
bytecode_call
spring_event_listener
spring_bean_dispatch
mybatis_mapper_binding
java_spi_registration
spring_autoconfiguration_registration
```

追踪器可以沿框架边回溯，但置信度衰减和停止条件应根据 `edge_kind` 单独配置。

### 覆盖与报告

`coverage.json` 中按 Adapter 记录：

- 是否检测到对应框架
- Adapter 版本
- 扫描源码/资源数量
- 生成节点和边数量
- 唯一绑定数
- 多候选/条件未决数
- 解析失败数
- 状态与原因码

报告中的调用链必须显式展示框架边，例如：

```text
Spring Event Dispatch
  -> OrderListener.handle() [spring_event_listener]
  -> OrderService.process() [bytecode_call]
  -> ChangedApi.call()
```

### 测试要求

至少覆盖：

- ServiceLoader 唯一实现和多个实现
- SPI 文件缺失/无效类名
- AutoConfiguration.imports 和 spring.factories
- `@EventListener`
- Runner/Filter/Interceptor/Converter/Formatter 回调
- Bean 唯一实现、`@Primary`、`@Qualifier` 和多实现歧义
- `@ConditionalOnProperty` 条件可求值/不可求值
- MyBatis Mapper XML namespace、statement id 和类型引用
- Adapter 不适用、部分覆盖和执行失败
- Adapter 边与普通源码/字节码边混合回溯

### 验收口径

完成该优化后，应满足：

- 框架隐式调用不再依赖通用 tracer 中不断增加的特殊分支。
- 每条框架边都能追溯到 Adapter、版本和原始注解/配置/资源证据。
- 多实现、条件 Bean 和动态代理不会被武断归因到某个具体实现。
- SPI 和 Spring 基础场景能够补充普通调用图无法发现的业务入口和实现绑定。
- Adapter 的缺失或失败会降低覆盖状态，不会被解释为没有框架影响。
- 新增框架能力可以通过独立 Adapter 扩展，而不破坏通用 AST/字节码图。

## 11. Step5 变更 API 分析能力补全（当前清单的可交付基线已完成）

### 当前落地状态

当前已落地：Step5 不再合并 Step3 candidate；已增加链式/局部变量反射解析、常见 javac 反射字节码还原、静态 MethodHandle（含 `findConstructor/findGetter/findSetter/findSpecial`）、目标相关资源/表达式引用、`dynamic_proxy_basic` 与 `declarative_http_client_basic` 框架 Adapter，以及按 API 求值的 `summary.json -> graph_stats.indirect_usage` / `coverage.json -> indirect_usage_matrix` 覆盖矩阵。目标相关能力为 partial/insufficient 时会阻止 `not_found_in_static_analysis`；动态代理必须从注册点绑定 handler 才输出具体证据，但不会仅凭注册提升为业务入口；声明式 HTTP Client 仅输出出站证据。复杂跨方法数据流、更广泛表达式方言和更多框架 Adapter 继续保留为后续增强，不属于当前清单的交付基线。

### 问题

当前 Step5 已覆盖普通源码调用、制品字节码引用、部分 `invokedynamic` 和框架隐式边，
但仍存在已知调用机制和间接引用语义未被统一图识别的问题。任何未覆盖机制都可能让
真实引用被错误归入 `not_found_in_static_analysis`。

反射是当前已经确认的一个具体缺口。例如：

```java
Class.forName("org.apache.commons.lang.StringUtils")
    .getMethod("isBlank", String.class)
    .invoke(null, value);
```

即使 Step4 已确认 `org.apache.commons.lang.StringUtils.isBlank(String)` 发生变化，
当前 Step5 仍可能因为缺少反射数据流解析而输出 `not_found_in_static_analysis`。
同类缺口还可能出现在显式 `MethodHandle` 查找/调用、可解析的配置或资源成员引用、
尚未覆盖的代理/框架派发等机制中。

### 职责边界

- Step3：分析 JDK、Spring/Jakarta 等平台和框架升级规则导致的风险，不参与 Step5 的变更 API 反射调用分析。
- Step4：输出类、方法、构造器和字段的具体变化及精确签名。
- Step5：仅以 Step4 变更 API 为目标，独立解析业务源码、依赖源码、资源配置和制品字节码中的直接及间接引用，并继续回溯业务入口。

### 优化方案

- 停止把 `s3_risk_candidates.csv` 追加到 Step5 的变更 API 集合；Step5 目标清单只来自 Step4 `all_changed_apis.csv`。
- 建立 Step5 能力矩阵，按 symbol kind 与调用机制记录 `complete/partial/insufficient/not_applicable`，明确普通调用、反射、MethodHandle、资源配置和框架 Adapter 的覆盖状态。
- 将不同机制统一输出为 owner/name/signature 身份和标准证据边，再与 Step4 变更 API 做目标驱动匹配。
- 优先补齐已确认缺口，但不得用不断增加的孤立正则代替可扩展的语义分析器或 Adapter。

#### 反射与动态调用

- 在 Step5 构建反射调用索引，并只与 Step4 变更 API 做目标匹配，避免把所有反射风险扩散到全部 API。
- 在源码 AST 中跟踪 `Class`、`Method`、`Constructor` 和 `Field` 的局部变量及链式表达式。
- 关联 `Class.forName`/类字面量、`getMethod/getDeclaredMethod`、参数类型列表与最终 `invoke`。
- 在业务和依赖字节码中识别对应的 `ldc`、反射 API 调用与局部数据流，补充源码缺失场景。
- 识别可静态求值的 `MethodHandles.Lookup.findVirtual/findStatic/findConstructor/findGetter/findSetter` 与后续 `invoke/invokeExact`。
- 目标类、成员名和参数类型均可确定时，生成 `reflection_method_invocation` 等精确证据边，并沿 Step5 统一反向图追踪业务入口。
- 精确反射边触达业务代码时输出 `reachable`；只在运行时依赖中确认、但未回溯到业务入口时输出 `uncertain` 并展示具体消费依赖。
- 只能确定部分信息或字符串来自参数、配置、拼接，但仍能关联到目标依赖、类或变更 API 时，输出 `REFLECTION_OVERLOAD_UNRESOLVED` 或 `REFLECTION_TARGET_DYNAMIC`；不得降为普通静态未找到。
- 完全动态且无法关联到任何目标范围的反射只保留为独立风险，不得让全部变更 API 变成 `uncertain`。

#### 其他缺失语义

- 对 XML、properties、YAML、SPI 元数据等资源中的类名或成员名建立目标相关索引；能够唯一解析时生成资源引用边，不能唯一解析时保留候选和停止原因。
- 通过能力矩阵持续盘点动态代理、表达式语言、序列化、代码生成和新增框架 Adapter 等缺口；每项必须定义适用条件、证据强度和失败语义。
- 对 JNI、任意字符串拼接、外部配置注入等静态不可求值场景明确标记能力边界，不承诺虚假的完整解析。

#### 结论约束

- 只有与目标 API 相关的所有适用分析器都完整执行且未命中，才允许输出 `not_found_in_static_analysis`。
- 相关分析器部分执行、解析失败或发现无法唯一解析的目标线索时，输出 `uncertain` 或 `not_analyzed` 并记录具体原因；禁止把能力缺口解释为无引用。
- 将所有新增证据边纳入 `alerts.csv` 的完整路径、证据位置、置信度和覆盖状态。

### 验收标准

- Step5 输入目标与 Step4 `all_changed_apis.csv` 一致，不再由 Step3 类级候选扩展。
- 每个 Step4 API 都输出按 symbol kind 和调用机制划分的覆盖状态，`not_found_in_static_analysis` 可追溯到完整覆盖依据。
- 能识别链式写法和拆分到局部变量的 `Class.forName -> getMethod -> invoke`。
- 能区分重载方法，并按参数类型生成统一 owner/name/signature 身份。
- 覆盖 `getDeclaredMethod`、构造器和字段反射的等价场景。
- 能识别目标可静态求值的 MethodHandle 调用和配置/资源间接引用。
- Step5 能将精确反射边与源码、字节码及框架边合并，并完整回溯到业务入口。
- 只在依赖中命中时，`alerts.csv` 明确给出消费依赖、消费类、方法及反射证据链。
- 能关联到目标范围的动态类名或方法名不会产生武断绑定，而是稳定输出 `uncertain`；无法关联目标范围时不污染其他 API 结论。
- 增加源码、真实编译字节码、资源配置、MethodHandle 和反射回归测试，确保已知能力缺口不会被报告为安全未命中。
