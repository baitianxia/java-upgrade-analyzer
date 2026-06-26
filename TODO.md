# 待优化项

## 1. 简化系统源码相关内部参数模型

### 背景

当前 skill 在系统源码相关输入上同时存在多套概念与落点，例如：

- `project_dir`
- `source_dirs`
- `source-dir`
- `main_state.json` 中的范围类字段
- `s2_context.json` 中的范围类字段
- 各 Step 自己的兜底恢复逻辑

这会带来两类问题：

- 对用户暴露了过多实现细节；用户已经提供系统源码时，不应再被迫理解这些内部参数差异。
- 内部也存在重复真相源和语义不一致问题，导致不同 Step 对"分析范围"的理解可能不一致。

### 目标

把"系统源码输入"相关模型简化为更少、更稳定的内部概念，并减少对用户暴露的实现细节。

目标方向：

- 用户已提供系统源码时，不再向用户暴露 `project_dir` / `source_dirs` / `source-dir` 这类实现细节。
- 内部减少重复真相源，统一"系统根"与"实际分析范围"的语义。
- 各 Step 不再各自重新猜测、恢复或覆盖范围定义。

### 当前讨论结论

建议将内部模型收敛为以下层次：

1. 用户输入层
   - 系统源码
   - `base_branch`
   - `current_branch`
   - `modules`
   - `dependency_source_dirs`
   - 运行选项，如 `allow_degraded` / `max_depth` / `include_test_scope`
2. 标准化运行上下文
   - `system_source`
   - `analysis_scope`
   - `build_tool`
   - 自动推导出的依赖源码映射结果
3. Step 临时入参层
   - 仅在调用具体脚本时，把标准化上下文转换为脚本参数

### 建议保留的核心概念

- `system_source`
- `base_branch`
- `current_branch`
- `modules`
- `dependency_source_dirs`

### 建议降级为派生值或兼容名的概念

- `project_dir`
- `source_dirs`
- `source-dir`
- `dependency_repo_mappings`
- `dependency_source_mappings`

### 待处理问题

- 明确唯一真相源应如何在 `main_state.json`、执行期 `run_context` 视图与 `s2_context.json` 之间分层，避免多处同时生效。
- 明确 `Step2`、`Step3`、`Step5` 对分析范围的统一消费方式。
- 明确用户输入模型与内部执行模型的边界，避免内部参数继续泄漏到交互层。
- 明确多模块场景下，"系统根"和"分析范围"的最终定义与推导规则。
- `Step3` 当前应默认围绕 `source_dirs` 扫描；只有极少数运行时入口文件是否需要根级补扫，后续再单独设计和处理。

### 验收口径

完成该优化后，应满足：

- 用户只需提供"系统源码"及少量必要事实，不再理解内部参数差异。
- 内部只保留一套共享的范围语义，不再由多个 Step 各自兜底。
- `Step2` 确认过的范围信息能够被后续步骤一致消费，不再出现文档语义与实际执行范围不一致。

## 2. 明确 Step5 对 `field/class` 变更的处理语义

### 背景

当前 `Step5` 会接收 `Step4` 传下来的 `symbol_kind=field/class` 变更项，但其核心分析模型仍以方法调用链为主。

这会带来一个语义问题：

- `method/constructor` 变更通常可以沿"谁调用了谁"的反向调用链继续追踪。
- `field/class` 变更更接近字段访问、类型引用、构造使用或类级影响，并不天然等价于方法调用边。
- 在当前能力下，这类变更可能被落到 `not_found_in_static_analysis`，但真实语义更可能是"当前模型未覆盖"而不是"静态确认未使用"。

### 目标

明确 `Step5` 对 `field/class` 变更的正式处理策略，避免把能力边界误写成影响结论。

目标方向：

- 明确 `field/class` 是否属于 `Step5` 当前支持范围。
- 若当前不支持，明确应输出 `not_analyzed` 或单独 reason code，而不是误落到 `not_found_in_static_analysis`。
- 若后续要支持，需单独设计字段访问/类型引用/构造使用等分析能力，而不是继续复用纯方法调用链模型。

### 当前讨论结论

本问题已确认存在，但当前轮次**暂不修复**，先记录为待办。

当前共识：

- 这是 `Step5` 的语义边界问题，不是单纯的文案问题。
- `field/class` 不能直接等同于方法级反向调用链。
- 在未补齐相应静态分析能力前，应避免输出过强的"静态未找到"语义。

### 待处理问题

- 梳理 `Step4 -> Step5` 对 `symbol_kind=field/class` 的实际输入契约。
- 明确 `field/class` 在当前版本中的期望四态归类。
- 评估是否需要新增专用 reason code，例如表达"当前调用链模型不覆盖字段/类级影响"。
- 补齐最小回归用例，覆盖 `field`、`class` 两类输入，防止后续再次误分类。

### 验收口径

完成该优化后，应满足：

- `field/class` 变更不会再被误写为"静态未找到路径"。
- 报告能清楚区分"当前没找到"与"当前没分析到"。
- `Step5` 的实现、输出语义和文档约束保持一致。
