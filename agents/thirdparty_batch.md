# Agent：第三方依赖批量分析

自包含执行文件。每次处理 3~5 个依赖。父任务传入：

```
deps: [
  {coord: "groupId:artifactId", old_ver: "X", new_ver: "Y", class: "C|D|E"},
  ...
]
main_proj_path: <主项目路径>
skill_dir:      <Skill 目录绝对路径>
target_jdk:     <目标 JDK 版本>
target_sb:      <目标 Spring Boot 版本，如无则填 "none">
```

---

## Windows 约束

本 Agent 的任务说明必须按**跨平台**方式执行，不要假定目标环境存在 `bash`、`grep`、`find`、`head` 或 `/tmp`。

- 在 Windows 环境下，优先复用主流程已生成的 `s4_jar_compare/all_changed_apis.csv`、`s5_call_chain/` 等产物
- 若需要补充检索，使用 IDE/平台自带搜索或等价的 Python 脚本，不要输出只能在 Unix shell 中执行的命令
- 临时文件放在项目内的 `.upgrade-report/agent_tmp/`，不要写 `/tmp/...`

## 对每个依赖执行以下序列

总规则：

- Step3 结果属于静态信号，不直接等于“已影响当前系统”。
- 对 `P0/P1` 的最终判定，必须优先引用 Step5 的可达性证据；若没有 Step5 或等价调用链佐证，只能标记为 `❓信息不足` 或较低置信度，不能直接下 `P0/P1` 结论。
- 若执行环境没有联网能力，必须在输出中显式说明“当前为离线分析”，并按本文件的离线降级路径执行。

### 1. 提取主项目调用清单

从 groupId/artifactId 推断 Java 包名前缀（如 `com.baomidou:mybatis-plus` → `com.baomidou.mybatisplus`），然后：

将调用清单写入 `.upgrade-report/agent_tmp/<artifactId>_calls.txt`。  
实现方式要求：

- 优先使用主流程 `Step 4` 的变更集与 `Step 5` 已有调用链结果
- 若主流程没有覆盖到，再用跨平台搜索方式补充：
  - 搜索 `import <推断包名>`
  - 搜索典型注解/工厂类/配置键
  - 搜索 `extends` / `implements` / 静态调用
- 不要要求用户或执行环境提供 `grep`/`bash`

若包名推断不确定，明确说明推断依据，不要静默猜测。

### 2a. 已升级依赖的变更分析（C/D 类）

联网查阅以下信息源（按优先级，每项都要标注来源 URL）：
1. 🟢 官方 Migration Guide / Upgrade Guide
2. 🟢 GitHub Releases 页面 / CHANGELOG.md
3. 🟡 官方文档版本说明
4. 🟡 GitHub Issues（`label:breaking-change`）
5. 🟠 可信社区博客（如 Baeldung）

**C 类（大版本升级）必须查阅至少 2 个独立信息源。**

若无法联网：

- 降级为本地证据优先：`s4_jar_compare/all_changed_apis.csv`、`s5_call_chain/`、jar 反编译/`zipfile` 扫描、仓库内已有 `CHANGELOG.md`
- 在结论中把信息来源标注为“离线”，不要伪装成已核对官方文档
- C 类在离线场景下允许输出更多 `❓`，但必须明确说明原因

提取以下类型变更：

| 变更类型 | 影响级别 | 暴露时机 |
|---|---|---|
| 类/方法被删除 | P0 | 编译失败(CE) |
| 方法签名变更 | P0 | 编译失败(CE) |
| 行为变更（默认值/逻辑） | P2 | 运行时特定场景(ST) |
| 异常类型变更 | P1 | 运行时(RE) |
| 废弃新增 | P3 | 编译警告 |

### 2b. 未升级依赖的环境兼容性验证（E 类）

联网查证（每项标注来源 URL）：
- 该版本是否官方声明支持目标 JDK？
- 该版本内部是否还使用 `javax.*`（对 Spring Boot 3 环境有影响）？
- GitHub Issues 中是否有目标 JDK 版本的兼容性 Bug 报告？
- 是否有推荐的兼容版本？

**无法联网或信息不足时：** 可用 javap 反编译验证

要求：

- 从本机 Maven 仓库定位 jar
  - 常见路径：`~/.m2/repository`
  - 跨平台代码路径：`Path.home() / '.m2' / 'repository'`
- 使用 `jar tf` / Python `zipfile` / 主流程 Step 3 的 `dep_compat` 结果检查 `javax.*`、自动装配元数据等信号
- 不要使用 `find ~/.m2 | head | grep`

### 3. 交叉影响判定

调用清单 × 变更清单，逐项输出影响判定表。  
信息可信度列：🟢已验证（官方文档）/ 🟡高度可能（changelog）/ 🟠推测 / ❓信息不足

**特别关注这类高影响依赖，即使是小版本升级也要认真对待：**
- 序列化库（Jackson/Fastjson）：行为变更可能导致跨版本缓存/消息不兼容
- ORM 框架（MyBatis/JPA）：SQL 生成逻辑变更、方言变更
- 连接池（HikariCP/Druid）：连接参数变更影响稳定性
- 日志框架（Logback/Log4j）：配置格式变更、MDC 行为变更

### 2c. 行为变更专项（所有 C/D 类都需要）

API 签名不变但逻辑变化的情况是最危险的，编译不报错，只在特定场景下静默产出错误结果。  
重点排查以下类型（联网查 changelog 时专门搜索这些关键词）：

| 关键词 | 含义 |
|---|---|
| `default behavior changed` | 默认行为变更 |
| `null handling` | 空值处理方式变更 |
| `empty string` | 空字符串处理变更 |
| `encoding` / `charset` | 编码默认值变更 |
| `date format` / `timezone` | 日期时间格式或时区处理变更 |
| `sort` / `order` | 排序稳定性或顺序变更 |
| `precision` / `rounding` | 数值精度或舍入行为变更 |
| `exception type changed` | 抛出异常类型变更（catch 块可能漏掉） |

**如果发现行为变更但无法通过静态分析确认影响范围，标注为 ❓ 并建议补充单元测试覆盖该路径。**

---

## 输出格式（严格遵守）

```
=== [批次：dep1 / dep2 / dep3] 完成 ===

[dep1 groupId:artifactId v旧→v新]
  调用点：N 处
  信息来源：[URL1], [URL2]
  结论：✅兼容 / ⚠️N处需关注 / ❌N处不兼容 / 🔄需升级
  关键问题：
    1. [P0/CE] 文件:行号 — 描述 | 建议：XXX

[dep2 ...]
  ...

❓ 信息不足（需人工验证）：
  1. dep名称 — 问题描述 | 建议验证方式：XXX

脚本盲区（如有）：
  1. 描述 | 漏掉原因：XXX
```
