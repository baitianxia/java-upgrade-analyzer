# Checkpoint Rules

1. 看到 `AWAITING USER INPUT`、`main_state.json.status=awaiting_*`，或 `run_step.py` 返回退出码 `4` 时，必须立即停止。
2. 停止后只能做四件事：读 `main_state.json`、读 `interaction.json`、问用户、等待用户回复。
3. 禁止跳过用户确认，禁止替用户选择 `continue`，禁止伪造用户答复。
4. 恢复时优先使用 `--response-json` 或 `--response-file`，把用户真实答复整理成 `intent_patch` 后传回 `run_step.py`。
5. 在用户未回复前，禁止执行任何“继续”“恢复”“下一步”命令。
