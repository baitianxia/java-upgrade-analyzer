# Java Upgrade Analyzer 核心业务分析逻辑准确性缺陷 (共 50 项)

## 复核状态（2026-07-13）

本文下方保留原始问题陈述，作为待验证假设，**不等同于已确认缺陷**。准确性问题必须同时具备可重复的最小工程、目标 API、期望链路和实际产物，才能进入修复队列；否则容易把分析边界或已经修复的问题误报为新缺陷。

| 条目 | 初步状态 | 复核依据 / 后续动作 |
| --- | --- | --- |
| 1、5、6、7、9、17、24、26、28、32、36、39 | 已有实现和自动化回归保护 | 分别覆盖 BootstrapMethods 方法引用、Multi-release JAR、同坐标内部桥、`tableswitch`/`lookupswitch`、反射不确定性、`<clinit>`、static import、varargs/数组描述符、方法引用及同坐标多模块。新增报告前必须先复现与既有测试相矛盾的具体案例。 |
| 2、10、12、22、23、49、50 | 已有针对性防护，仍需反例验证 | 当前使用完整 owner/签名优先匹配、过滤 JDK 伪 API、区分无覆盖与静态未命中，并保留按业务入口区分的链路。若发现反例，必须附上 Step4 API 行和 Step5/6 产物。 |
| 3、4、8、11、13、14、16、18–21、25、27、29–35、37、38、40–48 | 待复现 / 可能的能力边界 | 涉及 SpEL/OGNL、IoC 条件、SPI、Lombok、跨语言产物、框架回调及运行时行为。它们不能仅凭静态代码阅读判定为漏报或误报；将以真实可编译工程建立固定回归样例后逐项决定“实现、明确标为 uncertain，或不在工具承诺范围”。 |

### 录入规范

每个后续条目至少要补齐：

1. 可复现的最小 Maven/Gradle 工程或固定真实项目 commit；
2. base/current 的实际 JAR、目标 JDK 与 Maven 最终依赖树；
3. Step4 中的变更 API 身份（坐标、FQCN、完整签名）；
4. 期望与实际的 `alerts.csv` / `summary.json` 行；
5. 对应的自动化回归测试名称。


针对“分析结果是否存在问题”的进一步追问，本报告完全抛弃了工程规范、代码风格及外部崩溃问题，**100% 聚焦于分析工具的准确性、假阴性（漏报）、假阳性（误报）、调用链追踪断链及报告指标失真等核心业务逻辑**。

这些缺陷导致生成的 `alerts.csv`、`summary.json` 等关键产物无法反映真实的 Java 升级影响。具体如下：

## 一、 漏报 (False Negatives) - 致命的调用链断裂 (15项)
1. **Lambda 与方法引用追踪断链**：字节码解析器缺失 `BootstrapMethods` 的正确处理逻辑，导致函数式编程中的闭包调用无法溯源回业务层，产生高危漏报。
2. **同名简单类名碰撞误报**：正则降级模式下，`import` 解析不严格，导致如 `commons-lang3` 和 `commons-lang` 的 `StringUtils` 会产生交叉误报。
3. **Spring SpEL 表达式漏扫**：`@Value` 或 XML 中的 SpEL 表达式由于未进行深度 AST 提取，隐藏的 API 调用被完全遗漏。
4. **多态与接口派发过度近似（误报）**：当变更 API 是接口方法时，引擎未结合实际实例化类型（如 `new Impl()`），直接将所有实现类的调用标记为命中。
5. **多版本 JAR (Multi-release JAR) 解析失效**：依赖包存在 `META-INF/versions/11/` 等多版本字节码时，只扫描根目录导致 Java 11+ 特有 API 变更漏扫。
6. **同坐标桥接跳过（内桥断裂）**：内桥调用扫描时跳过相同坐标（Same Coordinate）依赖，导致库内真实调用链断裂。
7. **`tableswitch` 与 `lookupswitch` 偏移计算异常**：特定控制流指令解析错误导致后续字节码分析截断，遗漏该方法后续的调用链路。
8. **动态代理 (JDK/CGLIB) 注册点误认为业务入口**：在 `framework_adapters` 处理时，仅发现接口注册点，却错误地将 `Proxy` 提升为等同于直接调用的业务入口。
9. **反射调用 `Method.invoke` 模糊匹配失效**：参数反射加载由于静态分析无法推断参数值，直接粗暴丢弃，未归入 `uncertain` 队列。
10. **重载方法 (Overload) 签名误配**：`char[]` 变化为 `char` 时，类型降级策略过于宽泛，导致签名不同的重载方法被错误关联。
11. **MyBatis 动态 SQL (`<if test="...">`) 漏报**：XML 适配器未能解析 OGNL 表达式内的字段引用，导致数据库层的实体类字段变更漏报。
12. **泛型擦除导致的签名丢失**：从字节码恢复泛型签名时丢失类型参数，导致 `List<String>` 与 `List<Integer>` 混淆。
13. **Synthetic 桥接方法引发路径爆炸**：编译器自动生成的 `bridge` 方法由于未被屏蔽，导致同一逻辑在报告中输出多条冗余调用链（误报/噪声）。
14. **Enum `values()`/`valueOf` 虚假调用**：枚举类的内置合成方法变化被错误地认为是依赖升级引发的破坏性 API 变更。
15. **测试作用域 (Test Scope) 污染编译期结果**：依赖树解析未正确隔离 `<scope>test</scope>`，导致仅在测试用例中存在的废弃 API 污染主干报告。

## 二、 误报 (False Positives) - 过度近似与噪声污染 (10项)
16. **`not_analyzed` 状态异常膨胀**：如 `dubbo-samples` 测试中 8/9 API 未完成分析，原因为缺失源码映射时错误地停止探索而非降级。
17. **`<clinit>` 静态块调用断链**：静态初始化块中对依赖的调用未正确关联到触发类加载的业务侧方法，导致溯源断裂。
18. **嵌套类/匿名内部类 (Inner Classes) 溯源丢失**：`Outer$1` 等内部类名映射回源码 `Outer.java` 失败，导致证据链在最后一步无法呈现源码行号。
19. **Dubbo SPI 扩展点加载遗漏**：`META-INF/dubbo/` 下的 SPI 配置文件未被纳入依赖入口点，导致自定义扩展类变更漏报。
20. **`uncertain` 桶吞噬明确结论**：低置信度边本应在人工复核清单，却在二次过滤时被错误移出，造成信息丢失。
21. **依赖冲突引发的虚假版本分析**：Maven 依赖仲裁后实际使用的是 `2.0`，但分析器却拿 `1.0` 版本的源码进行了扫描对比。
22. **`JApiCmp` 将 JDK 标准类混入目标 API（噪声污染）**：对比 JAR 时未正确过滤 `java.lang.*`，导致海量标准库变动涌入 `all_changed_apis.csv`。
23. **缺少源码时直接 `not_found_in_static_analysis` 假阴性**：在 `allow_degraded=False` 且无源码映射时，工具应返回 `not_analyzed`，却错误输出了安全假阴性结论。
24. **静态导入 (Static Import) 的 `*` 匹配遗漏**：AST 解析器针对 `import static org.apache...*` 场景未能正确解析目标方法的 FQCN。
25. **`@Autowired` 按类型注入的隐式接口匹配断链**：当依赖接口发生变更时，使用该接口的业务类由于未显式 `new`，未被识别为直接关联。

## 三、 框架适配层盲区 (隐式调用/IoC/AOP) (10项)
26. **可变长参数 (Varargs) 解析断层**：`Object...` 在字节码对应 `[Ljava/lang/Object;`，但源码分析层将其误认为单元素，导致追踪失败。
27. **跨模块继承 (`Cross-Jar Bridge`) 虚假覆盖**：子类继承依赖包父类并重写方法，当父类方法被删除时，引擎错误认为子类不再调用而漏报。
28. **基本类型数组后缀丢失**：签名解析时 `byte[]` 丢失 `[]` 后缀，变成 `byte` 导致匹配目标 API 失败。
29. **链式调用 (Chained Call) 对象类型推断中断**：如 `builder.setA().setB()`，当 `setA()` 返回父类型时，`setB()` 的接收者类型推断错误。
30. **Lombok `@Data` 隐式调用漏扫**：Lombok 自动生成的 `get/set`、`toString` 未在 AST 阶段展开，若其内部调用了废弃依赖则完全隐形。
31. **Spring Boot `@ConditionalOnClass` 忽视**：仅分析源码时未考虑装配条件，导致永远不会加载的类产生大量误报（假阳性）。
32. **方法引用 `ClassName::method` 未解析为真实调用**：方法引用在 AST 中不同于普通 MethodInvocation，当前正则或轻量 AST 模式容易遗漏。
33. **`JApiCmp` 无视 `provided` 依赖引发 ClassNotFound**：JAR 对比时因为缺少运行时 `provided` 依赖，导致大面积方法被误判为“已被删除”。
34. **注解元数据内的枚举引用漏报**：如 `@MyAnnotation(type = DeprecatedEnum.OLD)`，注解参数的变动未被作为业务调用的起点。
35. **常量池 (Constant Pool) 解析快路径失效回退时丢失 String 引用**：特定长字符串常量在慢路径解析时被截断。

## 四、 字节码、多版本与特殊语法处理失效 (10项)
36. **`invokedynamic` 指令的 Bootstrap 方法签名误读**：Lambda 之外的其他 invokedynamic 场景（如字符串拼接 `StringConcatFactory`）被错误解析。
37. **无源码依赖的 `reachable` 误降级**：当依赖的依赖（二级传递）缺失源码时，即便能通过字节码连通业务，也被错误降级为 `uncertain`。
38. **全局 `deadline` 抢占导致正常链路被切断**：并行覆盖率计算超时时，直接丢弃已发现的部分调用图，产生高危漏报。
39. **多模块项目 (Multi-module) 内部依赖图解析错误**：`gs-multi-module` 场景中，兄弟模块的源码未合并构建统一 AST 图。
40. **重写第三方库方法的隐式回调漏报**：如实现 Tomcat 的 `Filter` 接口，由于框架回调机制未显式调用，引擎判定为“孤立节点”。
41. **YAML/Properties 配置文件的 Bean 属性映射失效**：`spring.datasource.url` 变动未关联到 `DataSourceProperties.setUrl()`。
42. **`try-with-resources` 隐式 `close()` 遗漏**：如果被关闭的流类的方法签名发生改变，隐式调用不会体现在 AST 方法调用节点中。
43. **Kotlin 编译产物的 `DefaultImpls` 匹配失败**：Kotlin 接口默认方法在字节码中对应 `Interface$DefaultImpls`，无法正确对齐到 Java API 目标。
44. **Scala 编译产物的混淆名称漏配**：Scala 生成的 `$anonfun` 或 `$$` 命名规则未在正则降级中做脱敏处理。
45. **接口默认方法 (Default Method) 的错误向下传递**：父接口新增默认方法，引擎错误报告所有未覆盖该方法的子类都有编译错误。

## 五、 指标失真与报告结果歧义 (5项)
46. **日志框架适配器的 `%X{...}` MDC 上下文漏扫**：特定框架日志埋点隐式引用了被删除的第三方 MDC 常量。
47. **`Exception` 捕获块内的类型匹配断裂**：`catch (SpecificThirdPartyException e)` 的类型变化未被视作强依赖 API 变更。
48. **`-SNAPSHOT` 快照版本在 Git Diff 时的分支对齐歧义**：Step4 中 old/new 对齐远端分支时因快照后缀问题导致选取错误的代码树。
49. **分析结果台账 `alerts.csv` 聚合覆盖**：当不同业务入口调用同一废弃 API 时，CSV 中只保留了一条证据，影响人工复核。
50. **置信度加权 (Confidence Weighting) 计算倒置**：正则匹配的低置信度边在计算总跳数权重时未正确衰减，导致其排在了高置信度 AST 边之前。
