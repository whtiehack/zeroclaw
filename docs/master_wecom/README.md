# `docs/master_wecom`

本目录在 `temp/upstream-master-wecom-port` 分支里承担两类用途：

- 保留从 `master_wecom` 复制过来的历史文档，作为迁移参考，不直接等同于当前分支决策
- 记录当前临时分支基于 `upstream/master` 重建 `master_wecom` 必需能力的操作文档

当前分支的统一入口：

- [会话入口与执行索引](./session-bootstrap.md)
- [2026-03-25 临时分支重建执行文档](./upstream-port-bootstrap-2026-03-25.md)

当前使用规则：

- 本分支不是旧 `master_wecom` 的直接延续，而是基于 `upstream/master` 的临时重建分支
- 后续功能迁移以 [branch-features.md](./branch-features.md) 为需求来源，以 [upstream-port-bootstrap-2026-03-25.md](./upstream-port-bootstrap-2026-03-25.md) 为执行准则
- 历史文档默认只作为背景材料，不直接覆盖当前分支判断

文档索引：

- [分支独有功能清单](./branch-features.md)
- [合并记录模板](./TEMPLATE-master-sync.md)
- [2026-03-19 上游提单失误记录](./agent-upstream-reporting-mistakes-2026-03-19.md)
- [2026-03-20 `master_wecom` 同步 `master` 记录](./master-sync-2026-03-20.md)
- [2026-03-22 `master_wecom` 同步 `master` 记录](./master-sync-2026-03-22.md)
- [2026-03-23 `full` 模式下保留 `non_cli_excluded_tools` 的本地记录](./full-non-cli-excluded-tools-2026-03-23.md)
- [2026-03-23 draft newline 上游处理失误记录](./draft-newline-upstreaming-mistakes-2026-03-23.md)
- [2026-03-23 `wecom_ws` cron delivery merge gap 记录](./wecom-ws-cron-delivery-merge-gap-2026-03-23.md)
- [2026-03-17 历史分叉分析](./upstream-master-divergence-report-2026-03-17.md)
