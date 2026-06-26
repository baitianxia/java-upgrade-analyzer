# JDK 升级检查清单

格式：每条包含【触发条件 | 检查方式 | 修复方案】，分析时逐条勾选。

---

## 一、已移除 API（脚本 04 会扫描，这里补充替换方案）

- [ ] **JAXB** `javax.xml.bind.*` — JDK 11 移除  
  检查：`removed.csv` 中有 JAXB 命中 / `jdeprscan.txt` 中有 javax.xml.bind  
  修复：添加依赖 `jakarta.xml.bind:jakarta.xml.bind-api` + `com.sun.xml.bind:jaxb-impl`

- [ ] **JAX-WS** `javax.xml.ws.*` — JDK 11 移除  
  修复：添加依赖 `jakarta.xml.ws:jakarta.xml.ws-api` + 实现包

- [ ] **JavaBeans Activation** `javax.activation.*` — JDK 11 移除  
  修复：添加 `jakarta.activation:jakarta.activation-api`

- [ ] **CORBA** `org.omg.*` / `javax.rmi.*` — JDK 11 移除  
  修复：无直接替代，需重构或使用第三方 CORBA 库

- [ ] **Nashorn JS 引擎** `jdk.nashorn.*` — JDK 15 移除  
  修复：迁移到 GraalJS (`org.graalvm.js:js`) 或其他 JS 引擎

- [ ] **RMI Activation** `java.rmi.activation.*` — JDK 17 移除  
  修复：无直接替代，需重构

- [ ] **Thread.stop/suspend/resume** — JDK 20 移除  
  修复：`Thread.interrupt()` + 协作式中断模式

- [ ] **Class.newInstance()** — JDK 9 废弃，后续版本可能移除  
  修复：`clazz.getDeclaredConstructor().newInstance()`

- [ ] **finalize()** — JDK 18 废弃  
  修复：`java.lang.ref.Cleaner` 或 `try-with-resources`

- [ ] **new URL(String)** — JDK 20 废弃  
  修复：`URI.create(s).toURL()`

---

## 二、JPMS 强封装（JDK 16+ 默认启用）

**触发条件：** `internal.csv` 或 `reflection.csv` 有命中，或使用了以下框架/库。

**验证方式：** 查看运行时是否抛出 `InaccessibleObjectException` 或 `IllegalAccessException`。

常见需要 `--add-opens` 的场景：

| 场景 | 所需参数 |
|---|---|
| Spring CGLIB 代理 | `--add-opens java.base/java.lang=ALL-UNNAMED` |
| Hibernate 字节码增强 | `--add-opens java.base/java.lang=ALL-UNNAMED` |
| Jackson 反射 | `--add-opens java.base/java.util=ALL-UNNAMED` |
| Mockito 测试 | `--add-opens java.base/java.lang.reflect=ALL-UNNAMED` |
| Fastjson 反射序列化 | `--add-opens java.base/java.lang=ALL-UNNAMED` |
| Lombok 编译期处理 | `--add-opens java.base/java.lang=ALL-UNNAMED` |
| 自定义 ClassLoader | `--add-opens java.base/java.lang=ALL-UNNAMED` |
| ByteBuddy / ASM | `--add-opens java.base/java.lang=ALL-UNNAMED` |

**检查项：**
- [ ] 启动脚本/Dockerfile 中的 JAVA_OPTS 已包含必要的 `--add-opens`
- [ ] `--illegal-access=permit` 已移除（JDK 17 起该参数无效且报警告）

---

## 三、GC 与 JVM 参数

**已移除的 GC 参数（JDK 14）：**
- [ ] `-XX:+UseConcMarkSweepGC` (CMS) → 改用 `-XX:+UseG1GC` 或 `-XX:+UseZGC`
- [ ] `-XX:+UseParNewGC` → 随 CMS 一起移除
- [ ] `-XX:+UseSerialGC` 仍可用，但不推荐

**已移除的其他参数：**
- [ ] `--illegal-access=permit/warn/debug/deny` — JDK 17 起移除
- [ ] `-XX:+AggressiveOpts` — JDK 11 移除
- [ ] `-XX:+PrintGCDetails` — JDK 9 起改用 `-Xlog:gc*`
- [ ] `-XX:+PrintGCDateStamps` — JDK 9 起改用 `-Xlog:gc*::time`
- [ ] `-XX:+TraceClassLoading` — JDK 11 起改用 `-Xlog:class+load=info`

**默认值变更（可能影响行为）：**
- [ ] 默认 GC：JDK 8 Server 模式为 Parallel GC → JDK 9+ 为 G1GC（内存/延迟特性不同）
- [ ] 默认 Locale 数据源：JDK 9+ 改为 CLDR（日期/数字/货币格式化输出可能不同）
- [ ] TLS 1.0/1.1：JDK 11+ 默认禁用（对外 HTTPS 调用老系统可能失败）
- [ ] Compact Strings：JDK 9+ 字符串内部改用 byte[]（一般有益，极少数场景需注意）

---

## 四、Jakarta EE 命名空间

**需要替换为 jakarta.* 的包（Java EE 相关）：**

| 旧包 | 新包 |
|---|---|
| javax.servlet.* | jakarta.servlet.* |
| javax.persistence.* | jakarta.persistence.* |
| javax.validation.* | jakarta.validation.* |
| javax.annotation.* | jakarta.annotation.* |
| javax.transaction.* | jakarta.transaction.* |
| javax.mail.* | jakarta.mail.* |
| javax.websocket.* | jakarta.websocket.* |
| javax.inject.* | jakarta.inject.* |
| javax.xml.bind.* | jakarta.xml.bind.* |
| javax.xml.ws.* | jakarta.xml.ws.* |

**不需要替换的 javax 包（JDK 自身）：**  
`javax.crypto` / `javax.net` / `javax.security.auth` / `javax.sql` / `javax.management` / `javax.naming` / `javax.swing` / `javax.imageio`

**脚本盲区（需 AI 补充检查）：**
- [ ] 字符串常量中的类名：`Class.forName("javax.servlet.Filter")`
- [ ] XML 配置中的 filter-class 等属性值
- [ ] META-INF/services SPI 文件内容
- [ ] properties/yml 中引用的类名
- [ ] 第三方库内部仍使用 javax（字节码层面冲突，Step 6 的 `10_jar_scan.sh` 会检测）
