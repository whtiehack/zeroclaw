# `master_wecom` 会话入口

更新时间：`2026-03-26`

## 1. 当前分支语境

- 当前工作分支是 `master_wecom`
- 当前分支已经切到以上游 `master` 为基线重建后的结果
- 后续开发默认在当前 `master_wecom` 上继续推进，不再使用临时移植分支

## 2. 进入仓库后的默认顺序

1. 先读 [upstream-port-bootstrap-2026-03-25.md](./upstream-port-bootstrap-2026-03-25.md)
2. 再把 [branch-features.md](./branch-features.md) 当作需求来源
3. 历史记录类文档只作为参考，不直接等于当前方案

## 3. 当前分支硬约束

- 继续以当前上游基线为准，不回退到旧 `master_wecom` 代码面
- 不因为旧补丁已经存在，就默认照搬到新基线
- 遇到与上游现有 streaming、draft、prompt、provider 能力重叠的旧补丁，先判断是否还能删除或重做
- `docs/master_wecom/` 文档提交与功能代码提交继续分离

## 4. 当前入口文档

- [2026-03-25 上游基线重建执行文档](./upstream-port-bootstrap-2026-03-25.md)
- [分支独有功能清单](./branch-features.md)
- [目录索引](./README.md)

## 5. 历史参考文档

以下文档保留为历史背景材料：

- [2026-03-17 历史分叉分析](./upstream-master-divergence-report-2026-03-17.md)
- [2026-03-20 `master_wecom` 同步 `master` 记录](./master-sync-2026-03-20.md)
- [2026-03-22 `master_wecom` 同步 `master` 记录](./master-sync-2026-03-22.md)
- [2026-03-23 `wecom_ws` cron delivery merge gap 记录](./wecom-ws-cron-delivery-merge-gap-2026-03-23.md)
