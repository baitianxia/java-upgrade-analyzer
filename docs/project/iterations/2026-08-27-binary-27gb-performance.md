# 2026-08-27 binary-first 27GB 性能收敛

## 状态

实现、本地正确性/密度验证、固定 400 JAR 性能证据重录及完整 Release 复核均已完成；记录已经过 candidate → provisional → 独立 recapture → final 和正式回放。Intel Xeon Gold 6266C、Windows 10、32GB 目标机上的 27GB 完整 Step4 尚未复跑，因此当前不能宣称“5 小时目标已经在目标机达成”。

## 输入事实与目标

问题样本为 802 个制品（base 417、current 405）、约 106875 class/侧、1568073 member、7510256 direct edge、128456 archive entry；生成数据约 29GB，其中两侧 SQLite 约 22.6GB、JSON 约 5.6GB。旧验证墙钟超过 46 小时，但累计 CPU 只有约 4.5 小时，CPU 利用率约 9.7%，主要时间耗在大对象常驻后的换页和随机重读。

本轮目标是把同级 27GB 输入的完整处理压到 5 小时内，同时保持以下不可突破条件：不采样、不跳 class/edge/archive entry、不减少 JVM observation、不缩小支持范围、不把超时或缺失证据解释为无影响；任何性能提示失效时必须精确回退。

## 根因

- reconciliation chunk 以随机 SHA 主键遍历，丢失 reconciler 原有的 direct-edge `rowid` 局部性；
- 独立 runtime validation 对数百万 edge identity 重复执行 SHA B-tree 查询；
- 闭世界索引为五个解析域分别建立 64 字符 SHA 临时索引并重复读取调用边；
- 高基数字符串池和 resolved-member 投影缓存缺少合适边界，磁盘 spool 完成后仍保留瞬态对象；
- 802 个制品的 SHA 与 ZIP/resource/XML inventory 串行执行，8 核机器大部分 CPU 闲置；
- semantic transition 在流式插入期间同时维护两个 B-tree，增加虚拟磁盘随机写。
- DecisionEngine 的 base/current provider 与 definition compact view 仍分别保留 realm、runtime-profile 和状态枚举的重复字符串对象，在 changed 路径形成可稳定复现的主进程 RSS 峰值。

## 实施

1. fact-store schema 升级到 `binary-fact-sqlite-v9`，新增每个 reconciliation kind 的 chunk ordinal。ordinal 纳入持久化内容身份和 backup 对账，但只作为性能提示；删除一个 ordinal 后 Oracle 和生产 hydration 仍读取完整记录集合。
2. runtime validation 在大库/内存压力路径按 `rowid` 顺序读取 direct edge；乱序、缺失或旧格式记录回退到精确 SHA 查询。resolved-member 正负投影使用按可用内存调整的硬上限 cache。
3. 闭世界索引用一个 direct-edge 顺序扫描同时合并 member、dispatch、type、class-init、linkage 五域；临时表只保存整数 `edge_rowid`，孤立 evidence 单独保存，所有查询仍可得到原 SHA evidence 的精确状态。取消五次宽表扫描和 SHA 临时映射库。
4. validation string pool 限制为 250000 个、单字符串 4096 字符；达到上限只停止共享对象，不改变返回值。semantic transition 索引在流式写完后一次构建。
5. 制品 SHA 和唯一 content/target inventory 使用按可用内存限制的 rolling worker；每个物理路径仍完整计算 SHA，重复内容只在全部路径验证后复用一次完整 ZIP/resource/XML 真值。
6. 为 inventory、runtime reconciliation 和闭世界合并保留有界进度、CPU 和 RSS 观测；资源紧张时降低 worker/cache，不降低分析范围。
7. DecisionEngine 仅对 realm、runtime-profile 与封闭状态枚举字段共享不可变字符串；class 名、身份和证据保持逐记录独立，记录值与正式身份不变。

## 本地证据

固定 macOS arm64、12 logical CPU、CPython 3.14.6、JDK 21.0.8 上已得到：

| 验证 | 结果 |
|---|---:|
| fact-store / I/O locality / Oracle boundary / performance safety | 169/169 通过 |
| reconciler / decision / trace / fact-store 组合 | 110/110 通过 |
| 完整 binary pipeline 普通路径 | 165/165 通过 |
| 强制大库顺序路径的同一完整 pipeline | 165/165 通过 |
| performance profile | 164/164 通过，0 skip |
| quick profile | 1042/1042 通过，1 个非 Windows 允许项 skip |
| Step5 profile | 1637/1637 通过，2 个门控允许项 skip |
| whitebox profile | 3209/3209 通过，2 个门控允许项 skip |
| release 全量测试 / 健康门 | 3435/3435 通过（61 blackbox、3210 whitebox、164 performance）；98/98 分支、15/15 变异、84 项两轮稳定 |
| 500000 edge / 2500000 五域记录局部密度门 | 5.884s，五域计数完全相等 |
| 7510256 edge / 37551280 五域记录目标密度门 | 86.350s，五域各 7510256 条 |
| 固定 400 JAR / 100000 class recorded gate | identical 181.807s / 742.0MB；changed 266.617s / 758.3MB；issue 0 |

目标密度门产生 1.400GB 的最小事实库和 2.220GB 的紧凑索引，进程峰值约 68.9MB。它证明新的五域合并算法在实际 edge 数量上保持线性、有界内存和完整计数；它不是 27GB 完整流水线，也不包含真实 class/JAR/JVM 观察成本，不能替代目标 Windows 复跑。

另外，500000 个唯一字符串的 retained pool 从约 62.4MB 降到约 31.2MB；1000000 次、100000 个唯一 resolved-member 请求只读取 100000 行，避免 900000 次重复查询。两项都保留逐值精确相等断言。

400 JAR changed 诊断 probe 将 DecisionEngine self peak 从 782.7MB 降到 729.7MB（约 53.0MB），decision phase 从 20.877s 到 20.841s；JVM completed-child peak 和 100000 class、250 个正式变化/API、0 validation issue 均保持，证明内存下降不是缩小观察范围。该诊断只用于归因，最终固定性能值仍以新的 candidate/独立 recapture 为准。

Oracle string pool 另以同一 changed probe 比较 64000、250000、500000 三个上限：64000 使 validation self peak 升至约 901MB；500000 虽比 250000 少约 16MB self peak，但验证约慢 4 秒。保留 250000 作为当前耗时/内存 Pareto 点；两个被拒绝的变体均为 0 validation issue，但不会因为单项指标改善而进入生产。

完整 Release 复核还暴露并修正了一个既有工具链合同缺口：三个 Spring Guide `source_build` SHA 由 JDK 21 生成，而 workflow 原先在记录 JDK 17 后直接构建。逐条目比较证明 JDK 17/21 产物只在 manifest 的 `Build-Jdk-Spec` 和一个语义相同但 constant-pool 排序不同的 class 上变化。manifest 现显式声明 `build_jdk_major=21`，guard 在构建前校验并绑定该 JDK，Release CI 在保留 JDK 8/17 参考路径后激活 JDK 21；没有通过覆盖 digest 绕过。

2026-08-28 从当前工作树执行的最终 `release` 结果为 `passed`：3435 项全部被选择和裁决，0 failure、0 error、0 expected failure、0 unexpected success、0 loader failure、0 非预期 skip；两个精确 skip 分别由同次 Release 真实 MyBatis 项目和原生 Windows 门替代。6/6 固定真实项目均通过且 issue 列表为空，400 JAR/100000 class source-bound 记录回放 `issue_count=0`，全流程无子进程超时。

## 尚未关闭的证据

- 在指定 Windows 10 / Xeon Gold 6266C / 32GB 主机上以相同 802 制品完整运行 Step4，核对总墙钟 ≤5h、validation issue=0、事实/API/path 身份集合与基线一致；
- 非 Windows 执行仍不能替代原生 Windows 套件。

## 当前文档

本轮遵循并更新 `docs/system/architecture/binary-first-engine.md`、`RUNBOOK.md`、`docs/project/current.md` 和本记录。5 小时是目标机验收门槛，不是当前本地合成结果的结论。
