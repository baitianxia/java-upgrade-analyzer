# Binary-first 能力迁移审计

## 审计结论

本审计以 `main@8cc40d29b932ec86c15aa8c09d4e3f9abae56073` 的 9 个能力族，以及当时实际执行的框架和真实项目场景为基线。判断标准不是旧文件是否仍存在，而是新引擎是否同时具备生产路径、正例、反例/失败边界、独立验证和需要最终制品的真实项目守卫。

当前工作树已为 9 个旧能力族、36 类具体机制和旧拓扑清单中的 18 种稳定拓扑登记当前生产路径与可加载测试。登记状态不是发布结论：只有完整 unittest discovery、测试健康/变异门、全部真实项目轮换、10 万 class 性能与范围守恒门都实际通过，`quality_gate.py --profile release` 才允许发布。

机器可执行台账位于 `tests/fixtures/binary_first/capability_migration.json`，校验器为 `scripts/binary_capability_migration_audit.py`。审计器不只读取手写状态：它从固定 `main` 基线独立计算 Git 删除集，对账 48 个已删除生产脚本、72 个已删除测试模块和 18 个已删除真实项目/拓扑 JSON 资产，并在代码中固定 9 个能力族、36 类机制和 18 种拓扑。即使同时删除台账声明和记录，也会因硬编码基线不一致而失败。

## 本轮已补齐范围

- 从最终制品 classfile 自动识别 Scheduled、事件/消息监听、Web、初始化/JPA 生命周期、Runner、ApplicationListener、Lifecycle、Servlet/Filter、转换器、拦截器和 Quartz 回调。
- 支持继承接口和 runtime meta-annotation，不要求用户逐个填写入口方法。
- 依赖包回调只有在业务 Boot 启动字节码与选中的 `AutoConfiguration.imports`、`spring.factories` 或传递 `@Import` 同时成立时才是精确入口；缺少激活证据时只形成候选路径。
- 普通业务 `main` 不再因方法名相同就自动成为精确生产入口；需要 launcher/Manifest、profile 声明或显式入口证据。
- JPA 生命周期回调没有实体实际使用证据时保持候选，不伪造成精确入口。
- 人工调用链保留原目录和列结构，并填充入口类型、入口所属依赖和激活原因。
- 独立 Oracle 使用目标 JVM 反射、独立资源解析和独立 direct-edge 真值重建入口集合；删除生产入口记录会产生 `ORACLE_ENTRYPOINT_SET_MISMATCH`。
- 依赖包独有的 `@Scheduled` 自动配置由完整制品流水线验证：必须保留依赖坐标、`spring_boot_auto_configuration_import` 激活原因和精确入口；仅有注解而无激活证明时保持候选。
- Spring XML/Quartz、MyBatis、transaction、Spring Data/AOP/Security/bean wiring、Feign、Dubbo、反射/MethodHandle、动态代理和隐式数据契约均有具名语义边及独立重建。
- 最终制品同时保留 base/current 完整有序运行闭包；Multi-Release JAR 只解析目标 JVM 实际选择的版本，物理变体仍保留为制品清单。
- 真实项目轮换覆盖 MyBatis XML/annotation、Spring transaction、Spring scheduling 和 Spring AMQP 字符串回调；源构建绑定固定 Git commit、argv、工作目录和最终 SHA。

## 当前迁移状态

台账内项目均为 `enforced`，没有登记的 blocking gap。该状态只表示替代实现与测试证据存在，不表示当前提交已通过发布验证。最终结果应以本提交生成的 release gate JSON 为准，不能继承历史运行或本文件中的文字。

18 种稳定拓扑包括业务直调、同/跨 JAR 桥接、同坐标多模块、重载、构造器、接口/虚调用、静态/字段、invokedynamic、反射、SPI、框架代理，以及源码与字节码一致/真实冲突。36 类机制的逐项用户影响和测试引用见机器台账，其中整包依赖删除必须保留成员级 API 明细和依赖归属；报告导航、明细上限、长阶段进度与恢复、依赖身份确认、JVM 数组类型解析、MyBatis 运行扩展、字符串注册的消息监听回调和不可变发布也都是阻断性能力，避免在文档与执行清单之间形成第二套可漂移事实。

## 门禁规则

1. 9 个基线能力族缺少任何一个记录，台账结构校验失败。
2. `enforced` 项必须存在可加载的生产路径和测试，且不得保留 blocking gap。
3. `partial` 或 `missing` 项必须说明具体缺口，不能用“新引擎不同”代替迁移证据。
4. 台账结构正确只说明没有隐瞒；只要仍有不完整能力族或缺失机制，release 仍为 `blocked`。
5. 18 个被删除的旧真实项目/拓扑资产必须逐个登记可加载的替代测试和当前资产；只保留删除路径计数、却没有替代证据，同样阻断发布。
6. 后续每修复一种机制，要先增加正例、负例和独立验证，再把状态提升为 `enforced`；需要真实打包拓扑的机制还必须恢复 pinned real-project guard。
7. 固定基线的 Git 删除集必须与台账完全相等；新增未登记删除、删除机制记录或删除已登记测试引用都会直接失败。
8. 18 种历史稳定拓扑由代码常量独立固定；台账声明和拓扑记录同时删除仍会失败。
