# Step5 调用链分析设计

本文面向维护者，说明当前 Step5 的实际分析模型、结果语义和关键边界。

## Step5 的目标

Step5 消费 Step4 产生的 API 变化集合，判断这些变化是否可能影响当前业务系统。

它关注的问题是：

1. 变化 API 是否被业务源码直接调用；
2. 变化 API 是否被当前最终制品中的业务 class 引用；
3. 变化 API 是否被运行时依赖 JAR 引用；
4. 跨依赖调用链能否继续回溯到业务代码；
5. 反射、MethodHandle、表达式语言、资源配置和框架隐式边是否提供候选证据。

## 输入

主要输入：

| 输入 | 来源 | 用途 |
|---|---|---|
| `evidence/api_changes/all_changed_apis.csv` | Step4 | API 变化目标集合 |
| `evidence/api_changes/git_ref_matches.json` | Step4 | 确认依赖当前版本对应的源码 ref 和模块路径 |
| `evidence/dependencies/build_provenance.json` | Step1 | 确认业务制品来源 |
| `evidence/dependencies/s1_artifacts/` | Step1 | 提取业务 class 和运行时依赖 JAR |
| 系统源码目录 | `project_dir` / `project_scope` | 构建业务源码调用图 |
| `dependency_source_dirs` | 用户可选输入 | 提供依赖源码仓库位置；Step5 会固定到 Step4 已确认的当前版本，不直接使用工作区当前分支 |

## 证据层

Step5 当前不是单一源码扫描，而是多证据融合。

| 证据 | 作用 |
|---|---|
| 业务源码 AST/增强正则 | 构建业务方法、调用边、类型和 import 信息 |
| 业务字节码 | 证明最终制品中的业务 class 是否真实引用目标 |
| 运行时依赖 JAR 字节码 | 发现依赖包之间对变化 API 的引用 |
| 依赖源码映射 | 补足跨依赖源码链路；只允许与当前运行时 JAR 同坐标、同版本且实际打包的类进入图 |
| framework adapters | 补充 SPI、Spring、MyBatis、动态代理、运行时主动入口等隐式边 |
| indirect usage analyzer | 识别反射、MethodHandle、资源、表达式语言等候选 |

## 分析流程

简化流程：

```text
Step4 all_changed_apis
  -> 构建系统源码图
  -> 提取 current 最终制品业务 class
  -> 扫描 current 运行时依赖 JAR
  -> 将依赖源码固定到 Step4 确认的 current ref，并按同坐标 JAR 类清单过滤
  -> 合并反射/框架/字节码证据
  -> 对每个 API 做反向追踪
  -> 输出 evidence/call_chain/alerts.csv / summary.json / by_api
```

## 依赖源码版本对齐

依赖源码只是运行时 JAR 的辅助证据，不能扩大当前制品的实际范围。Step5 使用 Step4 已确认的 `current ref` 创建只读的 detached worktree 快照，不切换、不修改用户仓库的当前分支、HEAD 或未提交内容。

对齐后还会按相同依赖坐标的 current JAR 类清单过滤源码：源码仓库中存在、但没有打进该 JAR 的类和方法不会进入调用图。这能防止错误分支、其他 profile、未打包模块或仓库附带源码形成虚假链路。

以下任一情况都会拒绝该源码映射：

- Step4 没有唯一确认 current ref；
- 源码映射与 Step4 记录的 Git 仓库不一致；
- ref、模块路径或快照无效；
- current 最终制品中没有同坐标 JAR，无法校验源码范围。

拒绝后 Step5 继续使用 current JAR 字节码证据，不会退回本地工作区当前分支。对齐明细写入 `evidence/call_chain/dependency_source_alignment.json`，包括选定 ref、commit、JAR 类数量以及被保留和排除的源码类数量。

## 目标键与反向图

Step5 会为每个变更 API 构建目标 key，例如：

- 精确方法签名；
- 无签名方法名回退；
- 构造器 key；
- 字段 key；
- 类级使用 key；
- 多态或兼容签名候选。

源码图和字节码图会写入 `reverse_edges`，即：

```text
callee_key -> caller edges
```

目标匹配必须遵守两个准确性边界：

- 不会把任意类的同名方法隐式合并到 `java.lang.Object`；继承边只能来自已证明的类型元数据。
- 源码图只命中其他重载、但当前最终制品已完整扫描且未命中目标精确描述符时，结论是 `not_found_in_static_analysis`，不是 `not_analyzed`。

依赖接口中已有方法体的 `static` / `default` / `private` 方法不属于动态代理边界，不得因“无实现类”提前停止回溯。

反向追踪从目标 API 出发，沿调用者方向回溯，直到：

- 触达业务代码；
- 达到最大累计 cost；
- 触达框架边界；
- 找不到更多调用者；
- 由于输入或能力不足停止。

## 置信度和深度

`max_depth` 表示最大累计 cost，不是简单 hop 数。

高置信边 cost 较低，可以走更深；低置信边 cost 较高，会更早停止。

这样做的目的：

- 保留高置信多跳链路；
- 避免低置信候选无限扩散；
- 让 `uncertain` 明确保留为人工复核对象。

## 五态结果

| 状态 | 语义 |
|---|---|
| `reachable` | 已找到确认链路并触达业务代码 |
| `not_impacted` | removed API 的旧类与当前其他运行时依赖中的同名类字节码完全一致，证明该 API 未从当前制品消失 |
| `uncertain` | 有候选证据，但链路或证据不足以确认 |
| `not_found_in_static_analysis` | 分析已执行，但当前静态证据未找到路径 |
| `not_analyzed` | 输入缺失、工具能力不足或覆盖不完整，无法有效分析 |

重要边界：

- `not_found_in_static_analysis` 不是“确定不影响”。
- `not_analyzed` 不能被当成无风险。
- `not_impacted` 只证明目标 API 符号仍被相同字节码提供，不证明被删除 jar 的资源、SPI、清单或其他非 API 内容没有影响。
- 字节码命中运行时依赖使用目标 API，但无法回溯到业务入口时，通常应进入 `uncertain`，并保留消费依赖、消费类和消费方法。

## 删除依赖 jar 的语义

删除依赖时，Step4 会从旧版 JAR 导出 public/protected 符号作为目标池。

Step5 需要检查：

1. 业务源码是否直接引用已删除符号；
2. 业务字节码是否引用已删除符号；
3. current 最终制品中的其他运行时依赖 JAR 是否仍引用已删除符号；
4. 如果运行时依赖命中，能否继续回溯到业务入口。

因此，删除依赖不是只看业务源码 import。运行时依赖仍使用被删 API 时，也必须进入证据链。

## 反射和间接调用

Step5 负责处理与 API 变化相关的反射风险，例如：

```java
Class.forName("org.apache.commons.lang.StringUtils")
    .getMethod("isBlank", String.class)
    .invoke(null, value);
```

当前支持的间接证据包括：

- `Class.forName`;
- `getMethod` / `getDeclaredMethod`;
- `getField` / `getDeclaredField`;
- `getConstructor` / `getDeclaredConstructor`;
- `MethodHandles`;
- 资源文件中的类名或方法线索；
- 表达式语言中的类型引用。

精确匹配能形成边时，进入调用链；动态 member 或不完整证据会进入 `uncertain` 或覆盖矩阵。

## 运行时主动入口

并非所有影响链路都必须从业务源码显式调用开始。若依赖源码中存在容器或框架会主动触发的入口，例如 `@Scheduled`、`@PostConstruct`、Spring Runner/Lifecycle 或 Quartz `Job.execute`，Step5 会把该方法作为框架主动入口。只要该入口链路触达变更 API，就可以形成影响链路。

## alerts.csv 设计原则

`alerts.csv` 是完整链路台账，不是抽样。

保留规则：

- A → B → C 已包含 B → C 时，同一命中的纯后缀可以不单独保留；
- E → B → C 与 A → B → C 是不同入口，需要保留；
- F → C 是不同消费方或不同链路，也需要保留；
- 每个进入 Step5 的 API 至少有一行，避免无声遗漏。

## 性能优化原则

Step5 的性能优化必须保持分析语义不变。

允许：

- 缓存重复排序结果；
- 构建等价索引；
- 复用字节码扫描结果；
- 对业务 class 使用 classfile 直接解析作为快路径，但解析失败、遇到反射/MethodHandle 线索或格式不确定时必须回退 `javap`；
- 记录耗时指标；
- 减少重复扫描。

不允许：

- 缩短搜索深度来换速度；
- 跳过低置信但有意义的候选；
- 把 `uncertain` 降级成 `not_found_in_static_analysis`；
- 用采样替代完整 alerts 台账；
- 为单一测试场景硬编码规则。

## 当前性能诊断点

Step5 会输出：

```text
.runtime/observability/step5_timing.csv
```

重点看：

- `main.indirect_usage_*`;
- `main.business_bytecode_elapsed_sec`;
- `main.business_bytecode_classes_scanned`;
- `main.business_bytecode_classfile_fast_path_classes`;
- `main.business_bytecode_javap_fallback_classes`;
- `bytecode_scan.*`;
- `bytecode_expand.*`;
- `trace.incoming_edges_scanned`;
- `trace.incoming_edges_cache_*`;
- `trace.declared_signature_index_*`;
- `trace.direct_class_usage_*`;
- `trace.direct_field_usage_*`;
- `report.*`。

## 维护检查清单

修改 Step5 时至少检查：

1. 是否改变四态语义；
2. 是否影响 overload 安全过滤；
3. 是否影响删除依赖 jar 场景；
4. 是否影响运行时依赖多跳链路；
5. 是否影响反射/MethodHandle/资源证据；
6. 是否影响 `alerts.csv` 完整性；
7. 是否补充正例和负例测试；
8. 是否运行 Step5 质量门。
