# Step5 首次完整运行性能优化设计

## 目标

显著降低 Step5 在 400+ JAR、约 10 万个 class 场景中的首次完整运行时间，同时保持分析结果、证据、覆盖范围和失败语义完全不变。优化不能依赖上一次运行留下的缓存，但允许同一次 Step5 进程内的分析器共享已经核验的事实。

本设计不设置固定分钟数。是否接受优化由同机多轮基准决定：真实项目总耗时中位数必须下降，目标热点阶段必须明显下降，峰值内存不得上升，机器可读结果指纹必须完全一致。

## 当前事实与根因

当前代码已经具备若干局部能力：

- `business_bytecode_graph.py` 可以直接解析 classfile，并在不确定时回退 `javap`；
- `confidence_weighted_tracer.py` 有进程内不可变解析缓存，但只覆盖追踪器自身的数据契约；
- `topology_coverage.py` 独立解析类层级；
- `framework_adapters.py` 中多个适配器分别打开 JAR、枚举 class/resource，并各自调用 `javap`；
- 业务字节码、框架适配、拓扑和运行时依赖追踪使用不同的中间表示，不能复用彼此已经完成的 ZIP 目录扫描、class header、常量池和 `javap` 结果。

因此，主要问题不是单个循环，而是同一物理 class 在一次 Step5 中被不同消费者重复读取和解析。

## 设计原则

1. Step1 留存的 current 最终制品仍是唯一依赖事实来源。
2. 不减少 JAR、class、API、框架适配器、调用深度或低置信候选。
3. 新共享层只提供事实，不改变现有分析器的结论规则。
4. 轻量事实可以全量建立；方法级可执行边只在现有逻辑本来就会解析时建立。
5. classfile 直接解析只在能力完整时作为权威结果；不确定、动态或非法结构必须沿用现有 `javap` 回退。
6. 解析异常必须保留为失败事实，不能转换成空引用或安全结论。
7. 不用提高无界并行度换取速度；并行度必须有上限并继续服从现有环境变量和资源策略。
8. 新旧路径在迁移期并存。新路径与旧路径不一致时，本轮采用旧路径结果，并把差异写入内部审计指标。

## 总体架构

新增 `Step5ArtifactFactStore`，生命周期限定为单次 Step5：

```text
current 最终制品与已提取运行时 JAR
                 │
                 ▼
       Step5ArtifactFactStore
       ├─ ArtifactInventory
       ├─ ClassHeaderFact
       ├─ ConstantPoolSummary
       ├─ ExecutableEdgeFact（按需）
       ├─ ResourceFact（按需）
       └─ JavapFact（按需、单飞）
                 │
       ┌─────────┼──────────┬───────────┐
       ▼         ▼          ▼           ▼
 业务字节码图  框架适配器  类型层级   运行时依赖追踪
```

共享层不预先构建完整调用图，也不保存所有 class 原始字节。它保存紧凑、不可变、可核验的事实和读取位置，避免为速度重新引入高内存峰值。

## 数据模型

### ArtifactIdentity

- `coord`
- `artifact_path`
- `artifact_sha256`
- `artifact_entry`
- `target_jdk`

所有缓存键必须包含 SHA-256 和目标 JDK。路径不是身份依据。

### ArtifactInventory

- 经过 Multi-Release JAR 选择后的逻辑 class 名与物理 entry；
- resource entry；
- class/resource 数量；
- 枚举或读取失败；
- 最终制品归属和模块坐标。

同一 JAR 的 ZIP 中央目录在本轮只枚举一次。目录结果使用元组和只读映射，不缓存全部 entry 内容。

### ClassHeaderFact

- class FQCN、访问标志；
- superclass、interfaces；
- classfile major version；
- declared method/field 的 JVM descriptor；
- bridge/synthetic/enum 等标记；
- runtime-visible/invisible annotation 类型；
- 解析状态与失败原因。

这是业务建图、拓扑和框架适配可以共享的轻量事实。

### ConstantPoolSummary

只保存下游实际查询需要的紧凑事实：引用的 owner/member/descriptor、字符串/反射标记、BootstrapMethods 和框架标记。不保存通用 Python 常量池对象树。

### ExecutableEdgeFact

保持现有 `parse_classfile_calls` 的字段和顺序。只为以下 class 生成：

- 当前最终制品中的业务 class；
- 变更 API 的常量池候选 class；
- 调用链扩展过程中现有算法要求解析的 class；
- 框架适配器现有逻辑明确要求方法体证据的 class。

### JavapFact

同一个 `ArtifactIdentity + class entry + target JDK + canonical option profile` 使用单飞机制：并发请求只启动一个 `javap`，其他消费者等待并复用不可变输出。失败结果也被缓存并带具体原因，防止多个适配器重复失败。

统一 profile 使用能够覆盖现有消费者的 `-v -c -p -s`。若某个消费者证明需要不同语义，使用独立、显式版本化的 profile，不能错误复用。

## 数据流

1. Step5 建立运行时依赖 catalog 后创建 fact store。
2. fact store 校验每个 JAR 的 SHA-256，并按需建立一次性 inventory。
3. 业务源码图仍按现有 tree-sitter 逻辑构建，不受字节码事实层影响。
4. 业务 class 字节码收集通过 fact store 获取 executable edges；边字段、顺序和失败语义保持不变。
5. 框架适配器先迁移重复最多且契约明确的 artifact inventory、类层级和共享 `javap` 读取；源码 AST/资源语义判定逻辑不改。
6. 运行时依赖追踪复用相同 classfile 解析结果和 `javap` 输出，但 API 候选筛选、反向搜索和结论逻辑不改。
7. 每个迁移消费者运行影子对照：比较旧结果与新结果的规范化事实集合、顺序敏感字段和失败列表。
8. 只有对照一致时使用共享结果；否则回退旧结果并记录 `fact_store_parity_mismatch`。

## 内存与并发

- inventory、header 和摘要采用紧凑元组/冻结 dataclass；
- 不缓存所有 class 原始 bytes；读取后解析并释放；
- executable edges 按 class 缓存，消费者最后一次使用后允许释放非共享投影；
- 不把 JSON 序列化副本作为进程内缓存值；
- ZIP 读取按 artifact 分片，并发 worker 有固定上限；
- `javap` 使用独立小型工作池，沿用当前超时、失败台账和并发限制；
- 不同时并行运行多个高内存分析阶段。

## 迁移顺序

### 阶段一：只读共享基础设施

实现 artifact identity、inventory、class header、解析单飞和性能指标，不接管任何正式结果。

### 阶段二：业务字节码消费者

迁移 `collect_business_bytecode_batch`。这是字段契约最清晰、可用现有边台账严格比较的消费者。

### 阶段三：框架适配器公共读取

先迁移 ZIP inventory、class header 和 `javap`；保留各适配器自己的语义解析与输出顺序。

### 阶段四：运行时依赖追踪

把 tracer 现有私有不可变缓存接到共享 store，保持常量池快路径、Multi-Release 选择和动态场景回退规则不变。

拓扑覆盖只有在共享 header 与现有 `_classfile_header_parents` 的所有回归结果一致后才迁移。

## 可观测性

在现有 `.runtime/observability/step5_timing.csv` 增加 `artifact_facts` 段：

- inventory build elapsed、hit/miss；
- class bytes read count/bytes；
- header、constant-pool、executable parse 次数和耗时；
- fact cache hit/miss；
- `javap` 请求、实际启动、共享命中、失败和耗时；
- 各消费者读取次数；
- parity comparison 次数和 mismatch 数；
- 每个 artifact 的慢项 Top。

这些指标只用于诊断，不参与结论。

## 正确性门禁

每项迁移必须同时满足：

1. `summary.json`、`alerts.csv`、查询索引的规范化指纹完全一致；
2. API 状态、reason code、路径节点及顺序、证据类型、文件、行号、coverage 和失败台账一致；
3. classfile 解析失败不会变成空集合；
4. Multi-Release JAR、Lambda、反射、bridge/synthetic、内部类、重载、数组/varargs 和非法 classfile 回归通过；
5. 真实多模块项目与至少一个大型项目结果审计通过；
6. 三轮冷启动总耗时中位数下降，目标阶段耗时下降，峰值 RSS 不上升；
7. 如果 parity mismatch 非零，该消费者仍使用旧结果，优化不得宣称完成。

## 明确不做

- 不缩短 max depth 或限制 API 数量；
- 不采样 JAR/class；
- 不用 simple name 代替 FQCN/descriptor；
- 不删除 framework adapter；
- 不把缓存命中失败解释为未找到调用链；
- 不以提高全局并行度作为第一阶段方案；
- 不在首次运行性能项目中依赖跨运行持久缓存命中。

## 交付标准

最终交付必须包含独立提交、单元/故障注入测试、结果指纹对照、三轮冷启动基准、真实项目审计、完整测试结果，以及未迁移消费者和剩余风险的准确说明。
