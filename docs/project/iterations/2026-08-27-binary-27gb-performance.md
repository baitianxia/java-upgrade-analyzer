# 2026-08-27 binary-first 27GB 性能收敛

## 状态

第二轮实现、本地正确性/兼容性验证、固定 400 JAR 性能证据重录和最终工作树完整 Release 均已完成；性能记录已经过 candidate → provisional → 全新目录独立 recapture → final 和仓库内正式回放。Intel Xeon Gold 6266C、Windows 10、32GB 目标机上的 27GB 完整 Step4 尚未复跑，因此当前不能宣称“5 小时目标已经在目标机达成”。

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
- 每个 JAR 各自启动 ASM/Javap JVM，helper 在父子进程重复编译，固定启动和进程树回收成本随 400+ 制品线性增长；
- base/current reconciliation 串行占用两倍墙钟，且相同 runtime side 仍可能重复构建同一百万级证据图；
- class fact 为 target ArtifactInstance 重写完整 JSON 后重新压缩，reconciliation payload 又为每条记录重复保存相同 key/status/subject；
- 独立 javap 扫描在线程池中执行 CPU 密集 Python 投影，受 GIL 限制，同时主进程保留过大的解码图。

## 实施

1. fact-store schema 由 v9 继续升级到 `binary-fact-sqlite-v11`。v9 的 per-kind chunk ordinal 仍只是局部性提示；v10 分离 payload/metadata；v11 以规范化 shape+value 列式记录去除重复 key，并从固定 payload 字段派生 status/subject。v9/v10 保留只读解码，shape、数量或 metadata 损坏失败关闭。
2. runtime validation 在大库/内存压力路径按 `rowid` 顺序读取 direct edge；乱序、缺失或旧格式记录回退到精确 SHA 查询。resolved-member 正负投影使用按可用内存调整的硬上限 cache。
3. 闭世界索引用一个 direct-edge 顺序扫描同时合并 member、dispatch、type、class-init、linkage 五域；临时表只保存整数 `edge_rowid`，孤立 evidence 单独保存，所有查询仍可得到原 SHA evidence 的精确状态。取消五次宽表扫描和 SHA 临时映射库。
4. validation string pool 限制为 250000 个、单字符串 4096 字符；达到上限只停止共享对象，不改变返回值。semantic transition 索引在流式写完后一次构建。
5. 制品 SHA 和唯一 content/target inventory 使用按可用内存限制的 rolling worker；每个物理路径仍完整计算 SHA，重复内容只在全部路径验证后复用一次完整 ZIP/resource/XML 真值。
6. 为 inventory、runtime reconciliation 和闭世界合并保留有界进度、CPU 和 RSS 观测；资源紧张时降低 worker/cache，不降低分析范围。
7. DecisionEngine 仅对 realm、runtime-profile 与封闭状态枚举字段共享不可变字符串；class 名、身份和证据保持逐记录独立，记录值与正式身份不变。
8. ASM parser 改为最多六个有界长驻 JVM 会话；每次交换仍验证完整分帧协议、数量和摘要。父进程编译的 helper 以源码/class/JDK/ASM 字节绑定传给 reconciliation 子进程；任何绑定或 transport 失败都回到完整 one-shot parser。空闲会话以 EOF 正常关闭，异常才执行进程树终止。
9. artifact snapshot 采用 rolling worker，在主线程写 SQLite 时提前补充下一个独立 JAR 任务；base/current 同内容用一项内存 template，但两条真实路径仍分别完整校验 SHA。normalized class fact 用受 SHA-256 保护的 row-owned identity 占位符，使 current 侧 exact rebind 能直接复用压缩事实而不解压/重压。
10. 不同 runtime side 的 base/current reconciliation 在内存不少于 6GiB 且两侧各至少 4000 class 时进入两个隔离进程；每个进程独占一侧 SQLite 并验证 profile/platform/capability/result identity。进程不可用时完整串行回退。完全相同的 runtime side 只 reconcile 一次，再用 SQLite backup 复制全部证据。
11. reconciliation writer 使用 v11 列式 payload、payload-derived metadata 和原生 canonical JSON identity；所有记录仍可逐条恢复，缺字段与显式 null 不合并。运行时 class reference 被提前投影为小表，避免后续为发现 owner 解压全部 class fact。
12. 独立 Oracle 按制品使用最多六个 spawn 进程并行 javap 解析/投影，worker 只返回受 schema 校验的压缩证据；每个 worker 内用目标 JDK `ToolProvider` 长驻会话移除逐 JAR JVM 冷启动。spawn、绑定或 session 失败自动回到原线程/one-shot javap，仍扫描全部 class。
13. Oracle 对 declared member、runtime observation、archive inventory、production edge projection 和 base/current 严格相等字段使用有界缓存/共享；只在完整输入、数据库逻辑内容或逐值 JSON 类型和值相等后复用，任何证明缺失都重新计算。
14. 严格相同 runtime side 在生成 Oracle sidecar 时，从同一份已完成 SQLite backup 的精确字节镜像产生两个具名文件；独立验证器仍检查两个路径、字节摘要和绑定身份，但不再为已证明逐字节相同的 20GB 级数据库做两次逻辑重读。不同 side 完全不走该路径。
15. ASM/Javap 会话仍并行执行 EOF 关闭；所有清理线程 join 后由所有者主线程恢复 POSIX SIGTERM 状态，避免进程组已清空但信号管理器残留。对应组合测试验证后续进程合同不受污染。
16. 闭世界 formal path 复核为重复 evidence 增加 8192 项有界 LRU 工作集；关系查询同时返回 member/linkage 状态，路径层的后续状态读取复用同一证明结果，超出上限或旧适配器缺少 orphan 表时回到原查询。所有关系、状态和失败关闭语义保持不变。

## 本地证据

固定 macOS arm64、12 logical CPU、CPython 3.14.6、JDK 21.0.8 上已得到：

| 验证 | 结果 |
|---|---:|
| fact-store / I/O locality / Oracle boundary / performance safety | 169/169 通过 |
| reconciler / decision / trace / fact-store 组合 | 110/110 通过 |
| 完整 binary pipeline 普通路径 | 165/165 通过 |
| 强制大库顺序路径的同一完整 pipeline | 165/165 通过 |
| performance 分区（最终 Release） | 166/166 通过，0 skip |
| quick profile | 1042/1042 通过，1 个非 Windows 允许项 skip |
| Step5 profile | 1637/1637 通过，2 个门控允许项 skip |
| whitebox profile | 3209/3209 通过，2 个门控允许项 skip |
| release 全量测试 / 健康门 | 3508/3508 通过（61 blackbox、3281 whitebox、166 performance；3506 pass、2 个精确替代执行 skip）；98/98 分支、15/15 变异、84 项两轮稳定 |
| 独立结构审计 | 3446/3446 所选测试通过；严格 complete 审计仍报告 0 callable、2 static edge、8 已登记 dynamic edge、168 branch alternative 缺口 |
| 500000 edge / 2500000 五域记录局部密度门 | 5.884s，五域计数完全相等 |
| 7510256 edge / 37551280 五域记录目标密度门 | 86.350s，五域各 7510256 条 |
| 固定 400 JAR / 100000 class recorded gate | identical 93.932s / 728.5MB；changed 125.512s / 750.6MB lifecycle peak（627.2MB pipeline peak）；issue 0 |

目标密度门产生 1.400GB 的最小事实库和 2.220GB 的紧凑索引，进程峰值约 68.9MB。它证明新的五域合并算法在实际 edge 数量上保持线性、有界内存和完整计数；它不是 27GB 完整流水线，也不包含真实 class/JAR/JVM 观察成本，不能替代目标 Windows 复跑。

另外，500000 个唯一字符串的 retained pool 从约 62.4MB 降到约 31.2MB；1000000 次、100000 个唯一 resolved-member 请求只读取 100000 行，避免 900000 次重复查询。两项都保留逐值精确相等断言。

新的正式 changed 复采相对上一份 266.617 秒记录降到 125.512 秒，提升 52.924%；CPU 从 852.204 降到 269.239 秒，下降 68.407%。主要 phase 从 artifact 58.446→41.077 秒、reconciliation 65.806→25.324 秒、decision 21.119→4.416 秒、validation 117.443→51.268 秒。lifecycle peak 从 758317056 降到 750616576 字节（下降 1.015%）；由于该口径包含已结束子进程的历史 high-water，pipeline 自报峰值更能反映当前主流程，从 758317056 降到 627195904 字节（下降 17.291%）。100000/100000 class、250 个正式变化、250 个正式 API 和 0 validation issue 均保持。

source-owned policy 以旧 changed 记录的一半为硬线，固定上限 133.308 秒。候选为 126.676 秒；全新目录 recapture 为 125.512 秒，两次差异 0.923%，final build 与仓库内 fixture 回放均为 `passed`、`issue_count=0`。相同双侧从 181.807 降到 93.932 秒，提升 48.334%；该特殊路径只计算一侧确定性 reconciliation，并从一份精确 SQLite 字节镜像生成两侧具名证据，独立 Oracle 仍验证两个 sidecar、完整结果和绑定身份，未为凑百分比跳过校验。诊断还实测了 8 个 ASM worker（100.054 秒）和 8 个 javap 进程（100.535 秒），两者都比正式 6/6 配置慢且 RSS/CPU 更高，故拒绝落地。

Oracle string pool 另以同一 changed probe 比较 64000、250000、500000 三个上限：64000 使 validation self peak 升至约 901MB；500000 虽比 250000 少约 16MB self peak，但验证约慢 4 秒。保留 250000 作为当前耗时/内存 Pareto 点；两个被拒绝的变体均为 0 validation issue，但不会因为单项指标改善而进入生产。

完整 Release 复核还暴露并修正了一个既有工具链合同缺口：三个 Spring Guide `source_build` SHA 由 JDK 21 生成，而 workflow 原先在记录 JDK 17 后直接构建。逐条目比较证明 JDK 17/21 产物只在 manifest 的 `Build-Jdk-Spec` 和一个语义相同但 constant-pool 排序不同的 class 上变化。manifest 现显式声明 `build_jdk_major=21`，guard 在构建前校验并绑定该 JDK，Release CI 在保留 JDK 8/17 参考路径后激活 JDK 21；没有通过覆盖 digest 绕过。

最终第二轮工作树的 `release` 结果为 `passed`：3508 项全部被唯一选择和裁决（61 blackbox、3281 whitebox、166 performance），3506 项实际通过、2 项精确替代执行 skip，0 failure、0 error、0 expected failure、0 unexpected success、0 loader failure、0 非预期 skip。98/98 个登记分支替代、15/15 个登记变异和 84 项两轮稳定检查通过；6/6 个固定真实项目均通过且 issue 列表为空，其中完全相同的 MyBatis XML 双侧由独立完整制品字节身份 Oracle 证明正式结果严格为 0。400 JAR/100000 class 的 source-bound 记录证据重放通过，250 个输入变化、250 个正式结果和 0 validation issue 保持。两个 skip 分别由同次 Release 的真实 MyBatis 项目门和原生 Windows 门替代；前者已有本次执行证据，后者仍等待目标平台证据。

独立运行 `whitebox_coverage_gate.py --suite all-internal --require-complete` 时，3446 项所选测试本身全部通过，但结构充分性仍失败：0 个 callable、2 条 static edge、8 条已登记 dynamic edge 和 168 个 branch alternative 未观测。与本轮实现前保存的同类报告比较，callable/static-edge/dynamic-edge 缺口分别从 1/6/8 变为 0/2/8，分支缺口从 335 降为 168；没有新增 callable、static-edge 或 dynamic-edge 缺口。仅新增的两个 branch gap 中，SQLite 大文件进度条件已经通过同一边界测试的精确两侧追踪关闭；另一个是 `compat._attach_windows_managed_job` 的 Windows 原生 Job Object 迭代路径，不能在 macOS 上模拟关闭。尝试扩展到 `all-tests` 时，3506 项实际执行到结尾，仅 Gradle checkout 黑盒因受限沙箱禁止 socket 失败，结构缺口结论不变；正式 Release 已在具备该外部条件的独立执行中通过。上述既有结构债务不冒充本轮通过项，也不改变 3508 项 Release、真实项目和性能守恒证据。

## 尚未关闭的证据

- 在指定 Windows 10 / Xeon Gold 6266C / 32GB 主机上以相同 802 制品完整运行 Step4，核对总墙钟 ≤5h、validation issue=0、事实/API/path 身份集合与基线一致；
- 非 Windows 执行仍不能替代原生 Windows 套件。

## 当前文档

本轮遵循并更新 `docs/system/architecture/binary-first-engine.md`、`RUNBOOK.md`、`docs/project/current.md` 和本记录。5 小时是目标机验收门槛，不是当前本地合成结果的结论。
