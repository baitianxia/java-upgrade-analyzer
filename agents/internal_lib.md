# Agent：依赖源码兼容性分析

自包含执行文件。父任务传入以下参数后，此 Agent 独立完成分析：

```
lib_name:       <库名>
lib_path:       <库本地路径>
lib_base_br:    <基准分支>
lib_cur_br:     <当前分支，若无则填 "same">
main_proj_path: <主项目路径>
skill_dir:      <Skill 目录绝对路径>
mode:           <"upgraded"=A类 | "unchanged"=B类>
target_jdk:     <目标 JDK 版本，如 21>
```

---

## Windows 约束

本 Agent 在 Windows 环境下不得依赖 `bash`、`grep`、`sed`、`tr`、`/tmp`。

- 临时产物统一写入 `$lib_path/.lib-scan/` 或主项目 `.upgrade-report/agent_tmp/`
- 主项目调用清单优先复用 `Step 4` / `Step 5` 已有产物（尤其 `all_changed_apis.csv` 与 `s5_call_chain/`）
- 若需要补充扫描，使用 Python 脚本、IDE 搜索或 Git 原生命令，不要输出只能在 Unix shell 中运行的流水线命令

## 执行序列

### 1. 扫描依赖源码自身（A 类 + B 类都要做）

在依赖源码目录运行扫描脚本，检查该依赖**自身**的 JDK 兼容性。  
这是最容易被遗漏的盲区：主项目改得再完美，依赖源码自身不兼容同样会在运行时崩溃。

实现要求：

- 输出目录使用 `$lib_path/.lib-scan`
- 自身兼容性扫描统一复用主流程 Python 脚本能力，不要调用历史 `*.sh`
- 至少覆盖：
  - `javax.*` 残留
  - JDK 已移除 API
  - JDK 内部 API / 强反射
  - `pom.xml` / `build.gradle` 中的编译目标版本

判断依赖源码自身的兼容状态：
- javax.csv 中有无未迁移的 Java EE 引用（排除 javax.crypto/net/sql 等 JDK 自身包）
- removed.csv 中有无已移除 API 的使用
- 库自身的编译目标版本（pom.xml 的 `<release>` 或 `<target>`）是否已更新

**若发现问题，这是 P0/P1 级别，必须优先报出。**

### 2. 提取 API 变更（仅 A 类：版本已升级）

实现要求：

- 在 `$lib_path` 中执行 `git diff`
- API diff 结果写入 `$lib_path/.lib-scan/<lib_name>_api_diff.txt`
- 依赖 diff 结果写入 `$lib_path/.lib-scan/<lib_name>_dep_diff.txt`
- 允许使用 `git diff` 原生命令；后续筛选请用 Python 解析，不要依赖 `grep -E | grep -v`

分析 api_diff.txt，识别：
- **Breaking Change（删除）**：仅有 `-` 行的方法/类
- **Breaking Change（签名变更）**：同名方法出现在 `-` 和 `+` 两侧但参数/返回值不同
- **新增**：仅有 `+` 行，主项目无需改动
- **行为变更**：签名相同但方法体 diff 差异显著——需人工判断是否影响语义

### 3. 提取主项目调用清单

实现要求：

- 先从 `pom.xml`、源码目录或 `Step 4` 产物推断库包名前缀
- 调用清单写入 `.upgrade-report/agent_tmp/<lib_name>_calls.txt`
- 搜索内容至少覆盖：
  - `import`
  - `extends` / `implements`
  - 静态方法调用
  - Spring 配置 / SPI / 注解侧引用
- 不要依赖 `grep|sed|tr`

### 4. 交叉影响判定

将调用清单 × API 变更/自身兼容问题，逐项输出：

```
文件:行号 | 调用的 API | 变更类型 | 影响级别 | 建议
```

影响级别：P0（编译失败）/ P1（运行时崩溃）/ P2（行为变更，需验证）/ P3（废弃警告）

---

## 输出格式（严格遵守，父任务依赖此格式汇总）

```
=== [$lib_name] 完成 ===
模式：$mode | 目标JDK：$target_jdk

【自身兼容性】
  javax 残留：N 处（需迁移）/ ✅ 无
  已移除API：N 处 / ✅ 无
  编译目标版本：已更新✅ / 未更新❌ / 未确认❓

【API变更（A类）】
  Breaking Changes：N 个
  行为变更（需人工确认）：N 个

【主项目影响】
  调用点总数：N 处
  受影响：P0=N | P1=N | P2=N | ❓=N

关键问题：
  1. [P0/CE] 文件:行号 — 描述 | 建议：XXX

待人工验证：
  1. 描述 | 验证方式：XXX

脚本盲区（如有）：
  1. 描述 | 漏掉原因：XXX
```
