# 最终制品优先与远程源码解析设计

## 目标

保持最终制品为升级分析的唯一事实源；只有分析确实需要源码时，默认使用远程分支的最新确定 commit。远程不可用时必须暂停并由用户确认，禁止静默使用本地分支或当前工作区。

## 证据优先级

正式优先级固定为：

```text
base/current 最终制品
→ 与最终制品对应的远程源码快照（辅助证据）
→ 用户明确确认的本地源码快照（兜底证据）
```

约束：

1. 依赖范围、实际版本、JAR 内容、编译后方法/字段和字节码调用边只以最终制品为准。
2. 源码不能覆盖最终制品事实，也不能把最终制品中不存在的模块扩展进确定性调用图。
3. 源码与最终制品无法对齐时，只能记录覆盖缺口或待复核线索，不能生成确定结论。

## 何时允许读取源码

只有以下能力需要源码辅助：

1. Step1 最终制品内嵌 JAR 缺少可靠 Maven 坐标，需要按 base/current 来源补全坐标；
2. Step4 需要识别 JAR 二进制对比无法覆盖的、签名不变的行为变化；
3. Step5 需要补充源码位置、业务语义、框架配置或字节码调用链的解释；
4. 注解、XML、配置等证据无法仅从字节码完整恢复。

上述条件未触发时，不得为了“信息更丰富”额外读取源码。

## 远程源码解析流程

### 明确远程的输入

用户输入 `origin/release-x` 时，只解析该 remote 的对应分支。

### 未明确远程的输入

用户输入 `release-x` 时：

1. 查询仓库所有 remote 的同名远程分支；
2. 仅有一个候选时自动选择；
3. 多个候选指向同一 commit 时允许自动选择，但记录全部 remote 来源；
4. 多个候选指向不同 commit 时进入 checkpoint，由用户选择 remote；
5. 不得因为存在同名本地分支而提前结束远程匹配。

### 远程新鲜度

本地 `refs/remotes/*` 不是远程最新状态的充分证据。正式流程应：

1. 优先用 `git ls-remote --heads/--tags` 查询远端事实；
2. 选定 ref 后执行定向 fetch，将对象取回工具使用的 ref/commit；
3. 固定具体 commit，并从该 commit 创建 detached 临时 worktree 或源码快照；
4. 不 checkout、不 merge、不 rebase、不 pull 用户本地分支；
5. 记录 remote、requested ref、resolved ref、commit、查询时间和失败原因。

## 本地源码兜底

以下任一情况都视为远程不可用：

- remote 不存在；
- 远程没有匹配分支或 tag；
- 网络不可达；
- 认证失败；
- `ls-remote` 或定向 fetch 超时/失败；
- 多个远程候选无法唯一确定。

远程不可用时：

1. 生成 checkpoint，不继续耗时分析；
2. 展示远程失败原因、本地候选及其 commit；
3. 只有用户明确提交“允许使用本地源码”的结构化答复后，才固定本地 commit；
4. 本地工作区存在未提交修改时，默认不得作为源码证据；如确需使用，必须再次明确确认并记录 dirty 状态；
5. 报告和 provenance 必须标注 `user_confirmed_local_source`，不能描述成远程最新版本。

## 各步骤行为

### Step1

- 先解析最终制品；只有坐标缺失时才启动源码补全。
- direct artifact 模式使用用户提供的 base/current ref 定位远程源码快照。
- checkout build 模式先固定远程 commit，再在 detached worktree 中构建；构建得到的最终制品成为后续事实源。
- 禁止同名本地分支截断远程候选解析。

### Step4

- JApiCmp 和 removed-symbol 分析只使用 Step1 留存的 old/current JAR。
- 依赖源码版本匹配查询远程真实 refs，而不是只读取可能过期的 `refs/remotes/*`。
- 远程源码仅补充 git diff/行为变化证据。

### Step5

- 当前最终制品的业务 class 和运行时依赖 JAR 字节码图是主图。
- 只有与最终制品坐标、版本和固定 commit 对齐的源码才允许进入增强图。
- 本地兜底源码必须带用户确认 provenance；来源不一致时不得生成确定性源码边。

### Step6

- 明确区分最终制品证据、远程源码辅助证据和用户确认的本地源码证据。
- 源码不可用或不对齐不能被解释为“未影响”。

## 状态与交互契约

新增或统一以下来源状态：

- `remote_source_resolved`
- `remote_source_ambiguous`
- `remote_source_unavailable`
- `awaiting_local_source_confirmation`
- `user_confirmed_local_source`

checkpoint 的结构化答复至少包含：

- `action=confirm_local_source` 或重新提供 remote/ref；
- 目标 side/coord；
- 用户确认的本地 ref 或 commit；
- 明确的 `allow_local_source=true`。

未收到上述确认时，不得自动回落。

## 测试范围

1. 同名本地和远程分支指向不同 commit：必须选择远程，不得命中本地。
2. 多个 remote 同名且 commit 相同：自动解析并记录全部来源。
3. 多个 remote 同名且 commit 不同：checkpoint。
4. 远程分支不存在、认证失败、超时：checkpoint，不使用本地。
5. 用户确认本地 fallback：固定本地 commit并记录 provenance。
6. dirty 本地工作区：未经再次确认不得使用。
7. direct artifact 坐标完整：Step1 不为坐标补全触发源码访问；Step4/Step5 仍只在各自确有源码辅助需求时读取。
8. Step4 JAR 证据保持来自最终制品，远程源码不得替换 JAR。
9. Step5 源码与制品不对齐：源码边不得进入确定性调用图。
10. 原有 Step1～Step6、完整回归和真实项目 smoke 不发生准确性退化。

## 验收标准

1. 所有需要源码的正式路径均实现远程优先、本地人工确认兜底。
2. 不存在 `git pull`、隐式 checkout 或修改用户当前分支的实现。
3. 远程解析失败不会被吞噬或静默解释为本地可用。
4. provenance 能回答使用了哪个 remote/ref/commit，以及为何使用本地兜底。
5. 最终制品优先契约测试、分支解析测试、checkpoint 测试和完整回归全部通过。
