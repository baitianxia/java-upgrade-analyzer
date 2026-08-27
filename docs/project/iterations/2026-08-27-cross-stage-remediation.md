# 2026-08-27 跨阶段正确性、可靠性与性能修复

## 状态

已完成。实现、当前系统文档、性能证据和直接受影响测试已同步；真实 Windows GUI 父进程测试未在 macOS 参考机执行，保留既有平台专属门禁。

## 输入事实与判定

本轮逐项核对 Step1～Step6、binary-first 引擎、质量门、Step3 扫描、基础设施、文档和测试治理报告。确认存在并修复的主要问题包括：Maven timestamped SNAPSHOT 排序、POM JDK 优先级、Step6 二次扫描、未知 reachability 发布崩溃、GBK 子进程、mutation/branch 空跑、质量门超时与并发结果名、低信任 XML、Java 文本块/泛型解析、Step3 重扫与 `javax.annotation.processing` 误报、白盒局部实例调用、Windows lease 活性、共享可变 JDK 缓存、无界进度日志，以及 semantic overlay 全量常驻和 Spring hierarchy 重算。

以下报告项经当前代码、测试或资产盘点证明不成立：

- `access & 0x0018 == 0x0018` 在 Python 中等价于 `(access & 0x0018) == 0x0018`；`0x0018` 是 `ACC_STATIC | ACC_FINAL`，不含 `ACC_PUBLIC`，现有 package-private 常量测试通过；
- 测试资产不是 12 个 fixture：按 Git 跟踪清单盘点为 311 个 `tests/` 文件、159 个 fixture 文件和 20 个 blackbox 源文件；工作目录中的更高计数包含 `__pycache__`，不作为资产数量；
- `generated_topology_seed_43.json` 由 `test_binary_generated_regression.py` 的独立图真值回归直接消费，不是孤儿；
- 当前能力迁移审计不是 166 个 issue，而是 9/9 family、18/18 topology、36/36 mechanism 全部 accounted，issue 为 0。

Oracle 的 Windows 盘符规范化、WinError 5 spawn 重试、每 class/group 300 秒上限和总 `javap` 预算已存在于进入本轮的代码基线；本轮用相应边界测试和完整 quick 门再次验证，没有重复实现第二层等价检查。

## 实施结果

### 正确性与安全

- Step1 对 `1.0-20240101.0900-123` 等 timestamped SNAPSHOT 分离数值基、时间戳和 build sequence；
- Step2 先读取模块实际插件，再读取 `pluginManagement`，并合并 release/target/source 与 execution 声明；
- Step3 的依赖 XML 统一进入 `safe_xml`，DTD/ENTITY 检测覆盖 UTF-16/32 NUL/BOM 形态；
- Java 源码辅助分析支持文本块、泛型 cast 和显式 invocation type argument，并统一两条解析路径的绝对文件身份；
- Jakarta 规则和配置扫描排除 JDK 自带 `javax.annotation.processing` 等命名空间；
- Step4 报告对未知 reachability fail-safe 为 `not_analyzed` 并保留原值；
- 白盒静态图解析无歧义局部实例方法，拒绝参数、重赋值、import、delete 和异常变量遮蔽。

### 性能与内存

- Step6 为 overview/dependency 建立一次索引，移除逐项扫描 583K API 集合的 O(n²) 路径；
- Step3 多规则扫描合并为单次目录遍历；
- semantic overlay 的 class/member 数据改为 SQLite 流式读取和有界缓存，不再构造全量 members/classes 字典；Spring 实现关系一次预索引，hierarchy 使用有界记忆化；
- 进入本轮的基线已经包含 binary attachment 流式校验、lazy reconciliation payload、fact-store 流式内容身份、毒类二分/重试和 Oracle 有界预算；直接回归证明这些路径仍有效；
- `progress.jsonl` 当前段和 previous 段各限 8 MiB，单事件限 256 KiB，观测失败不影响正式结果。

### 质量门与运行可靠性

- 所有托管 Python 子进程强制 UTF-8，消除 GBK stdout 误杀；
- mutation worker 加载失败不再计为 killed；branch 函数清单为空或改名不再 vacuous pass；
- quality gate 的测试、性能、JDK 探针均有有限 timeout，性能结果使用 PID 唯一文件名；终端状态标记改为 ASCII；
- Windows ACCESS_DENIED/未知进程状态保守视为存活，lease 扫描不再因 256 条截断永久失败；
- JDK preflight 缓存保存不可变规范字节并为调用方返回新对象；
- Oracle `_spawn_javap` 的进程所有权转移纳入生命周期审计，两个调用方均验证成功释放和失败清理。

### 文档与治理

- 重写 `docs/system/operations/outputs.md`，删除旧工具产物、虚构边 CSV 和旧影响状态，改为真实 generation、四维结果和当前文件入口；
- 普通流程的 `binary_pipeline_config` 明确为 Step1 自动物化；性能 fixture 只约束开发/发布审计，不阻断普通 Step4；
- `AWAITING USER INPUT` 旧字面协议改为退出码 4、`awaiting_*` 主状态和 `JUA_CONFIRMATION_JSON` 机器事件；
- 删除两份零引用旧 Agent 流程并增加单一当前入口；删除四个已由 `s3_scan.py` 取代的 shell 脚本；
- 记录并执行候选→provisional→独立复采→final 的性能证据恢复流程。

## 性能证据

固定参考环境为 macOS arm64、12 logical CPU、CPython 3.14.6、JDK 21.0.8。正式复采规模为 400 JAR / 100000 class：

| 指标 | 结果 | 门限 |
|---|---:|---:|
| cold | 122.768s | 170s |
| warm P50 / P95 | 44.597s / 44.719s | 65s / 75s |
| identical full pipeline | 182.194s | 400s |
| one-JAR-changed full pipeline | 268.543s | 500s |
| 最大记录 RSS | 752238592 bytes | 3221225472 bytes |

两条完整 pipeline 的 validation issue 均为 0；变化侧 authoritative fact 和 formal result 均精确为 250。最终 recorded gate 回放 `issue_count=0`，support manifest 的 SHA 与 live source identity 一致。

## 验证

- `python3 -m compileall -q scripts tests`：通过；
- 跨 Step1/2/3/5/6、编码、安全、基础设施定向组：452 项通过；
- Step4 组件组：534 项通过；
- Step4 artifact/output/pipeline 集成组：465 项通过；
- 性能/发布权威/白盒文档组：171 项通过；
- `quality_gate.py --profile quick`：1042 项通过，0 failure、0 error，1 个既有 Windows GUI 专属 allowlisted skip；
- `test_trust_gate.py`：90/90 公共能力覆盖，内部模块盘点通过；
- `defect_regression_gate.py`：26 个登记缺陷、58 个回归测试，issue 0；
- `binary_capability_migration_audit.py --require-release-ready`：通过，issue 0；
- `binary_performance_gate.py --verify-recorded-gate ...`：通过，issue 0。

## 当前文档

本轮遵循并更新了当前唯一所有者：

- `docs/system/architecture/binary-first-engine.md`；
- `docs/system/architecture/overview.md`；
- `docs/system/operations/outputs.md`；
- `docs/system/quality/quality-gates.md`；
- 根运行合同 `README.md`、`RUNBOOK.md`、`SKILL.md` 和 `CHECKPOINT_RULES.md`。

没有已知的当前文档冲突。真实 Windows 原生执行仍由现有 Windows profile/CI 验证；本轮 macOS 运行只证明跨平台静态合同、模拟 WinError 边界和非 Windows 路径。
