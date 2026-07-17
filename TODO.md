# 待优化项

本文只记录尚未完成或尚未取得充分验证证据的工作。确认完成的项目直接删除，不在待办文档中保留历史设计正文；历史决策应进入 `docs/archive/` 或 Git 记录。

## 编译期常量的双重影响证据

状态：**待设计与实现**。

Commons Text 1.12.0 的逐 API 制品审计确认：`StringUtils.EMPTY` 在源码中有直接字段引用，但作为编译期常量被内联后，最终 JAR 中客观不存在 `getstatic/getfield` 边。当前模型只能将其保守归为源码与制品对齐未验证，尚不能分别表达：

- 下次编译时会因字段删除而失败的源码影响；
- 当前已编译制品中不存在字段链接边的运行时影响。

完成标准：

- 在统一证据模型中分离编译期影响与运行时可达影响，不把源码引用伪装成最终制品调用边；
- 使用独立工具确认旧字段是否具备 JVM `ConstantValue` 属性，并核对调用方最终 class 是否已内联；
- 对删除、值变化、非编译期常量和源码/制品版本不一致分别给出稳定结论；
- 逐 API Oracle 同时拒绝漏报、误报、额外输出和无法证明的强结论。

## 应用内部模块的框架激活闭包

状态：**待设计与实现**。

Mall 真实 Fat Jar 的逐 API 审计确认：`mall-common` 与 `mall-security` 已被最终制品所有权证据识别为应用内部模块，其中 3 个 Hutool API 存在精确可执行调用边；但调用方是 Spring `@Aspect`/安全元数据组件，当前静态图尚未用独立框架注册证据证明这些方法会连接到应用入口，因此结论保守保持 `uncertain / BUSINESS_ENTRY_NOT_CONFIRMED`。

Dubbo RPC consumer 的后续真实项目审计已补齐 Spring Boot `CommandLineRunner` / `ApplicationRunner`：Oracle 会同时验证 `Start-Class`、`SpringApplication.run`、运行时可见 `@Component`、Runner 接口以及 `run()` 中的目标调用。该子场景已完成；本项仍保留，因为 Spring AOP、安全过滤链及普通未注册组件尚未形成同等强度的完整闭包。

完成标准：

- 内部模块不能仅因被打包就自动视为已激活，必须取得配置、注解、Bean 注册或框架回调的独立证据；
- 对 Spring AOP 切面、安全过滤链和普通未注册组件分别建立正反例，禁止把未激活类提升为 `reachable`；
- 框架激活边必须绑定当前最终制品 SHA、资源或字节码条目及稳定语义身份；
- 使用独立 Oracle 逐 API 验证完整路径，并拒绝漏报、额外路径和无法证明的强结论。
