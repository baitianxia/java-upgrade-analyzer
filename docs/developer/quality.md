# 质量门禁与测试策略

本文定义 binary-first 引擎的开发准入。测试服务于准确性、用户体验和性能，不能用“测试通过”掩盖错误模型或不完整验证。

## 不可突破的门槛

1. 最终制品和目标运行时是正式事实；源码只是可选解释层。
2. 依赖坐标、版本、lineage、物理制品 SHA 和运行路径身份必须贯穿变化事实、触达结果和最终报告。
3. 四态语义互斥，不把静态未命中写成无影响，不把静态路径写成运行时确认。
4. coverage 缺口必须随 scope 和 generation 保留；失败关闭，不能转入旧引擎。
5. 普通复核人必须能从 Markdown/CSV 直接理解“哪个依赖、哪个变化、路径、原因、缺口和下一步”。
6. `.runtime` 内部制品与 `evidence`/`deliverables` 人读产物严格分开。
7. 性能优化不得缩小分析范围、降低身份精度或减少证据。

## 测试 profiles

```bash
python3 scripts/quality_gate.py --profile quick
python3 scripts/quality_gate.py --profile step5
python3 scripts/quality_gate.py --profile release
```

- `quick`：模型、制品 diff、target runtime reconciliation、裁决、trace 和 generation 输出；
- `step5`：在 quick 上增加 ASM/fact store/cache/source overlay、端到端 pipeline、查询、调度和用户输出契约；
- `release`：`python3 -m unittest discover -s tests`，发现并运行全部当前测试。

准确性定向门：

```bash
python3 scripts/accuracy_benchmark.py --profile core
python3 scripts/accuracy_benchmark.py --profile step5
python3 scripts/accuracy_benchmark.py --profile all
```

Category 只使用当前 binary 能力名；旧引擎 category 不保留调用别名。

## 必测能力

### Artifact facts

- class/member/access/descriptor/constant/code fingerprint；
- manifest、service provider、module/resource 选择语义；
- ZIP 时间戳、entry 顺序等 packaging noise 不产生变化事实；
- traversal、重复 entry、膨胀比、嵌套深度、CRC/解析失败均有界失败；
- MR-JAR、未知资源和不支持 class major 正确记录覆盖边界。

### Target runtime reconciliation

- 同名 class 多制品、parent-first/child-first、有序 slot、module/classpath；
- base-only/current-only/exact lineage 配对；
- 目标 JDK platform image 身份一致；
- provider 不唯一或运行闭包不完整时不得猜测。

### Decision and projection

- authoritative facts、diagnostic candidates、excluded decisions 分离；
- 可投影 API 与已确认但不可投影的 service/resource 等事实分离；
- 每条事实绑定依赖、base/current 制品、原因码和证据；
- source overlay 不得改变权威裁决。

### Trace

- owner/member/descriptor/loader realm 精确匹配；
- 重载、继承、接口 dispatch 和多态候选边界；
- `reachable`、`uncertain`、`not_found_in_static_analysis`、`not_analyzed` 互斥且计数闭合；
- 路径集合的完整性和预算限制明确；
- `not_found_in_static_analysis` 永不提升为安全结论。

### Publication and UX

- active generation 完整性与 validation attachment 校验；
- Step4/5 目录原子替换，失败保留上一版本；
- Step4 首屏以依赖包为入口，提供单依赖 Markdown、完整 review 和 CSV；
- Step5/Step6 每条 API 和依赖保留坐标，部分范围不能冒充全量；
- CSV 为 UTF-8 BOM；Markdown/CSV 同一语义；
- 内部 SQLite/sidecar 不发布到 `evidence` 或 `deliverables`；
- 用户卡使用“可能影响/仍不确定”，不输出旧五态或运行时确认空壳。

### Architecture boundary

必须有自动测试验证旧 Step4–Step6 文件不存在，manifest 只路由 binary generation/report，调度器不暴露旧引擎、灰度、兼容或降级参数。删除旧实现时同步删除其专属测试；保留的安全、平台、编码和 Oracle 原则应重写到当前引擎测试中。

## 独立 Oracle

`binary_validation_oracle.py` 必须从原始制品、目标 JDK 和不可变 generation sidecar 独立重建关键事实，不调用生产 ASM parser、provider resolver、decision engine 或 tracer。边界由 `tests/fixtures/oracle_boundary.json` 和静态审计测试约束。

验证至少覆盖：

- generation sidecar SHA 和身份；
- 独立 class/member/resource 差异；
- 目标运行时 provider/outcome；
- 最终制品直接调用边；
- 正式投影和四态计数闭合。

Oracle 失败或证据不足时 generation 不得激活。

## 性能门

性能门必须同时记录输入规模、冷/热 cache、总耗时、阶段耗时和可取得的峰值内存。固定性能 fixture 位于 `tests/fixtures/binary_first/performance_gate.json`，其内容身份在 support manifest 中固定。

允许：内容寻址缓存、批量事务、有界并行、索引、避免重复解析。禁止：抽样 API、跳过依赖、缩短路径而不报告、降低描述符/loader 精度、用源码替代制品。

## 同输入分支对比

引擎替换的 A/B 结论必须先写真值，再运行两分支。每个 case 至少记录：

- 输入制品 SHA、JDK 和 runtime profile；
- 预期依赖、变化对象、正式/诊断类别、路径与覆盖边界；
- 两分支实际人读文件和机器事实；
- 漏报、误报、依赖归属错误、路径错误和不诚实负结论；
- wall time、cache 状态和峰值内存（可取得时）。

只比较行数、状态总数或单个成功案例没有说服力。推荐至少包含：精确 removed/descriptor change、确认但不可投影的 resource/service 变化、packaging-only noise、覆盖不完整失败关闭。

## 提交准出

- 所有现存测试实际通过；
- 公开文档与代码一致；
- 人读报告已抽查依赖身份和阅读路径；
- 旧引擎入口/参数/活动文档已清除；
- 性能数据存在且不进入确定性 generation；
- A/B 使用相同输入并按预先真值评估；
- Git diff 只包含本次目标，提交信息说明 engine replacement 和用户输出保持。
