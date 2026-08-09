# Binary-first 能力迁移审计

## 审计结论

本审计以 `main@8cc40d29b932ec86c15aa8c09d4e3f9abae56073` 的 9 个能力族，以及当时实际执行的框架和真实项目场景为基线。判断标准不是旧文件是否仍存在，而是新引擎是否同时具备生产路径、正例、反例/失败边界、独立验证和需要最终制品的真实项目守卫。

当前结论是：依赖包内框架入口的本轮补齐已经在显式支持范围内形成生产实现、正负端到端测试、独立 Oracle 和人工报告证据；整个引擎替换仍未达到可合并状态。9 个旧能力族均存在未完成迁移证据，19 类具体机制缺失，另有 2 类只完成部分迁移。`quality_gate.py --profile release` 因此必须阻断，而不能只凭 unittest 数量通过。

机器可执行台账位于 `tests/fixtures/binary_first/capability_migration.json`，校验器为 `scripts/binary_capability_migration_audit.py`。审计器不只读取手写状态：它还从固定 `main` 基线独立计算 Git 删除集，并对账 48 个已删除生产脚本和 18 个已删除真实项目/拓扑 JSON 资产；后续再删除旧生产路径或删掉一条机制记录都会使台账结构失败。

## 本轮已补齐范围

- 从最终制品 classfile 自动识别 Scheduled、事件/消息监听、Web、初始化/JPA 生命周期、Runner、ApplicationListener、Lifecycle、Servlet/Filter、转换器、拦截器和 Quartz 回调。
- 支持继承接口和 runtime meta-annotation，不要求用户逐个填写入口方法。
- 依赖包回调只有在业务 Boot 启动字节码与选中的 `AutoConfiguration.imports`、`spring.factories` 或传递 `@Import` 同时成立时才是精确入口；缺少激活证据时只形成候选路径。
- 普通业务 `main` 不再因方法名相同就自动成为精确生产入口；需要 launcher/Manifest、profile 声明或显式入口证据。
- JPA 生命周期回调没有实体实际使用证据时保持候选，不伪造成精确入口。
- 人工调用链保留原目录和列结构，并填充入口类型、入口所属依赖和激活原因。
- 独立 Oracle 使用目标 JVM 反射、独立资源解析和独立 direct-edge 真值重建入口集合；删除生产入口记录会产生 `ORACLE_ENTRYPOINT_SET_MISMATCH`。

## 旧能力族迁移状态

| 能力族 | 状态 | 主要阻断证据 |
|---|---|---|
| artifact identity / ownership | 部分 | 核心物理身份存在，但 reactor/嵌套模块归属证明及真实多模块守卫被删除 |
| canonical evidence identity | 部分 | 核心 canonical identity 存在，缺少跨项目、多坐标、inner class/overload 闭集守卫 |
| evidence completeness visibility | 部分 | class/resource 局部失败可见，旧工具/解析器故障注入矩阵和真实项目负结论守卫被删除 |
| framework activation semantics | 部分 | 自动入口与 Java ServiceLoader 资源激活已补，XML、代理、MyBatis、反射、Dubbo SPI 等语义边未迁移 |
| closed world pipeline | 部分 | decision/projection 守恒存在，Oracle 尚未逐路径、逐结论、逐人工报告行闭集对账 |
| reproducible test assets | 缺失 | pinned manifest、物化器、SHA 绑定执行和真实项目矩阵均被删除 |
| performance without scope loss | 部分 | 有固定性能数据和小型缓存测试，release 不重跑完整 scope-equivalence 门 |
| test gate integrity | 缺失 | release 曾只运行 unittest discovery；branch/mutation/flaky/slow/capability catalog 门被删除 |
| module and tool failure boundaries | 部分 | 新模块已有边界，但纯 trace policy 与统一 typed subprocess fault 合同未迁移 |

## 仍缺失且会影响用户结论的机制

| 缺失机制 | 用户可见风险 |
|---|---|
| Spring XML scheduled / Quartz | 任务只在业务或依赖 XML 注册时不会成为路径入口 |
| MyBatis mapper proxy | annotation/XML mapper 调用无法通过代理语义触达 MyBatis 或实现 API |
| Spring transaction proxy | `@Transactional` 代理/拦截路径可能被报告为“未发现调用路径” |
| Spring Data repository proxy | repository 接口、默认实现和自定义实现不能按运行时工厂语义连接 |
| Spring AOP | advice 与 join point 之间没有正式语义边 |
| Spring Security filter chain | filter 顺序、anchor 与 callback 不进入可达图 |
| Spring bean wiring | `@Bean`/XML 创建与注入关系不能把接口调用连接到实际实现 |
| Spring component scan / conditions | 无法证明扫描范围、配置属性和 class condition 是否真正激活入口 |
| declarative HTTP client | Feign 等声明式接口调用不产生框架 outbound 边 |
| exact reflection / MethodHandle | 已可从常量和注册点证明的动态目标仍不会进入正式图 |
| dynamic proxy | `InvocationHandler` 注册与代理接口调用没有连接 |
| Dubbo SPI | Dubbo extension/adaptive/provider callback 没有迁移；Java `ServiceLoader` 资源激活已迁移，不应混为一谈 |
| implicit data contract | 序列化/绑定隐式消费的字段或类型变化在没有直接字段指令时会被当成未使用 |
| automatic runtime profile | 普通项目/最终制品不能自动转换为新引擎所需的有序制品闭包、loader realm 和入口合同 |
| fat JAR 自动物化 | 用户只提供一个可执行 Fat JAR 时，系统不会自动生成业务 classes 与有序嵌套依赖闭包 |
| pinned real-project rotation | 合成测试可以全部通过，却无法暴露常见框架组合和打包拓扑回退 |
| generated/metamorphic regression | 手写样例通过时，图变换、输入重排和生产 mutation 回退仍可能漏过 |
| typed tool failure matrix | timeout、缺工具、权限、非零退出和空输出没有跨全部边界的失败关闭证明 |
| branch/mutation/flaky/slow gates | 普通 unittest 通过仍可能掩盖未覆盖分支、幸存 mutation、flaky 或异常慢测试 |

## 已识别但只完成部分迁移

| 部分机制 | 当前边界 |
|---|---|
| dependency source snapshot alignment | 用户显式提供的源码会绑定并作为 overlay 使用，但旧版自动仓库/ref/module 发现与 detached snapshot 物化未迁移 |
| JPA entity activation proof | 能发现生命周期回调并保留为候选路径，但尚不能证明 persistence unit/entity 实际激活 |

## 门禁规则

1. 9 个基线能力族缺少任何一个记录，台账结构校验失败。
2. `enforced` 项必须存在可加载的生产路径和测试，且不得保留 blocking gap。
3. `partial` 或 `missing` 项必须说明具体缺口，不能用“新引擎不同”代替迁移证据。
4. 台账结构正确只说明没有隐瞒；只要仍有不完整能力族或缺失机制，release 仍为 `blocked`。
5. 后续每修复一种机制，要先增加正例、负例和独立验证，再把状态提升为 `enforced`；需要真实打包拓扑的机制还必须恢复 pinned real-project guard。
6. 固定基线的 Git 删除集必须与台账完全相等；新增未登记删除、删除机制记录或删除已登记测试引用都会直接失败。
