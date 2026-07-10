# Checkpoint Rules

1. 看到 `AWAITING USER INPUT`、`main_state.json.status=awaiting_*`，或 `run_step.py` 返回退出码 `4` 时，必须立即停止。
2. 停止后只能做四件事：读 `main_state.json`、读 `interaction.json`、把交互内容整理成用户可读的决策卡片、等待用户回复。
3. 禁止跳过用户确认，禁止替用户选择 `continue`，禁止伪造用户答复。
4. 恢复时优先使用 `--response-json` 或 `--response-file`，把用户真实答复整理成 `intent_patch` 后传回 `run_step.py`。
5. 在用户未回复前，禁止执行任何“继续”“恢复”“下一步”命令。
6. 决策卡片必须覆盖当前所有交互点：缺少 Step1 输入、Step1/Step2/Step4/Step5 checkpoint、补依赖源码目录、补 git ref/超时参数、选择 Step5 依赖包范围、从指定步骤重跑。
7. 给用户看的第一层只写决策信息：当前要确认什么、为什么停下、可选动作、需要补什么、候选对象、完整候选或证据文件、可以直接怎么回复。
8. `response_schema`、`action_requirements`、`selection_resolution`、`input_normalization`、`runtime_rules` 只用于整理恢复命令，不作为用户主信息展示。
