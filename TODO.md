# 待优化项

本文只记录尚未完成或尚未取得充分验证证据的工作。确认完成的项目直接删除，不在待办文档中保留历史设计正文；历史决策应进入 `docs/archive/` 或 Git 记录。

## 主动缺陷发现全链路

- 生成拓扑与变形变体必须实际经过生产 Step4 到 Step5 的结论路径；当前只执行了生产字节码 collector，部分变形仅改变 truth manifest 或未改变实际输入。

## 公开运行契约

- 干净副本必须仅按 `SKILL.md` 公共入口成功完成 Step1 到 Step6、checkpoint 恢复和幂等重跑；Ubuntu、macOS、Windows 的必选 CI 矩阵必须取得实际运行证据。当前只验证了首个 checkpoint 和工作流静态结构。
