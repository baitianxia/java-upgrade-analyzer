# Step1 分支定位与坐标补全设计

## 背景

Step1 以 base/current 最终制品为依赖事实来源；当 Fat Jar、WAR 或嵌套 Jar 缺少 `pom.properties` 时，才使用 Maven `dependency:list` 补充 `groupId`、`artifactId` 和 classifier。

同一系统的 base/current 通常来自同一个源码仓库的不同分支，因此 `base_source_project_dir` 与 `current_source_project_dir` 可以是同一路径。源码目录本身不能表达版本身份，版本身份必须由明确的 branch、tag 或 commit 决定。

当前缺陷是：同一侧同时存在 source directory 和 branch 时，Step1 优先直接使用 source directory，导致 branch 被忽略。本地工作区当前检出的 revision 可能只对应一侧，从而产生错误坐标或重复确认。

## 目标

1. 已提供 base/current branch 或 commit 时，Step1 自动固定到对应 revision 并补充坐标。
2. 精确 ref 不存在时，能够从本地分支和远端跟踪分支中寻找唯一、安全的候选。
3. 分支候选存在歧义时，在 Maven 构建或依赖解析前请求用户确认。
4. 只有 source directory、没有可确认 ref 时，不得直接使用；必须先确认该目录对应的 revision 和制品侧。
5. 所有选择结果记录实际 ref、commit、匹配方式和候选，保证重跑稳定、过程可审计。

## 方案比较

### 方案 A：保持 source directory 优先

改动最小，但同一路径无法同时代表 base/current 两个 revision，会继续产生版本错配。否决。

### 方案 B：branch/ref 优先，唯一候选自动使用，歧义时确认

先精确解析用户提供的 ref；失败后搜索本地分支和已有的远端跟踪分支。只有唯一高置信度候选时自动使用，否则在耗时操作前确认。该方案兼顾自动化和准确性，采用。

### 方案 C：任何非精确 ref 都要求人工确认

最保守，但会让常见的 `release-x.y.z`、`origin/release-x.y.z` 表达差异频繁阻塞。只在候选不唯一或匹配不足时采用该行为，不作为默认方案。

## 设计

### 1. Ref 解析顺序

每一侧独立执行以下流程：

1. 对输入 ref 执行 `git rev-parse --verify <ref>^{commit}`。
2. 精确成功：记录 ref 和 commit，创建 detached worktree。
3. 精确失败：枚举 `refs/heads/*` 与 `refs/remotes/*`，排除远端 `HEAD`。
4. 候选匹配仅接受以下安全等价形式：
   - 完整短名一致，例如 `release-1.2.0` 与 `origin/release-1.2.0`；
   - 去除唯一 remote 前缀后完整一致；
   - 输入包含明确版本标识时，复用 Step4 的版本边界匹配规则，但不得匹配到更长的数字版本片段。
5. 唯一最高分候选自动使用；并列候选或低置信度候选进入确认。
6. 不执行隐式 `git fetch`，避免网络副作用；只使用仓库当前已有的本地和远端跟踪 refs。

### 2. Source directory 规则

- branch/ref 与 source directory 同时存在：branch/ref 优先，source directory 仅提供仓库位置。
- 只有 source directory：读取 Git root、当前 ref 和 commit，生成确认任务；用户确认后固定该 commit 的 detached worktree。
- base/current source directory 相同：允许，但两侧必须分别绑定不同或明确确认的 commit。
- 无法读取 commit、目录不是 Git 仓库或用户未确认：停止坐标补全，不得直接执行 `dependency:list`。

### 3. 交互与循环保护

确认任务必须展示：侧别、原始 ref、候选 ref、候选 commit、源码仓库路径和未识别的嵌套 Jar。

将“未识别依赖集合 + 原始 ref + 候选集合 + source directory”生成稳定指纹。相同指纹且输入没有变化时，不再重复执行 Maven，而是明确提示哪些输入尚未确认。

用户确认后，将 resolved ref 和 commit 写入 Step1 input；后续重跑直接使用 commit，不再重新模糊匹配。

### 4. 证据与可观测性

Step1 进度日志增加 ref 解析阶段，至少记录：

- `side`
- `requested_ref`
- `resolved_ref`
- `resolved_commit`
- `resolution_mode`：`exact`、`unique_local`、`unique_remote`、`user_confirmed`
- 候选数量和是否需要确认

正式依赖结果继续以最终制品为准；ref 解析只用于坐标补全，不能用 Maven 结果覆盖制品中已经可靠识别的版本。

## 测试范围

1. 同一侧同时提供 branch 与 source directory 时，必须调用 branch worktree，不得直接使用当前工作区。
2. base/current source directory 相同、branch 不同时，分别解析到两个不同 commit。
3. 精确本地分支、精确远端 ref、唯一远端短名候选均能自动解析。
4. 两个 remote 存在同名分支时必须暂停确认。
5. 只有 source directory 时必须暂停确认，确认后固定 commit。
6. 相同未确认输入重跑时不得重复执行 Maven。
7. Fat Jar filename-only 依赖通过对应分支的 `dependency:list` 成功补齐坐标。
8. 已可靠解析的 Fat Jar 坐标和版本不得被 Maven 补全结果改写。

## 非目标

- 不在 Step1 内自动执行 `git fetch`。
- 不允许模糊候选在歧义情况下自动胜出。
- 不改变 Step4 对依赖源码版本 ref 的匹配职责。
- 不使用工作区当前 checkout 状态同时代表 base/current 两侧。
