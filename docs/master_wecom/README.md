# `master_wecom` 分支文档

更新时间：`2026-03-26`

## 分支语境

- `master_wecom` 是企业微信 AI Bot 通道（`wecom_ws`）的主开发分支

## 开发约束

### 最小修改原则

- 公共层代码不得随意修改
- 能在 `wecom_ws` 或局部模块内完成的需求，不得扩散到通用框架
- 只有在不改公共层就无法正确实现需求时，才允许修改公共层，且改动范围必须最小、必要性必须明确

### 公共层规则

- 公共层改动必须单独提交，不与 `wecom_ws` 或文档混在一起
- 公共层测试遵循最小原则，能不加就不加
- 实现时尽量少加代码、少改代码、少引入新抽象，不为单点问题做大范围重构
- 不随意删除、覆盖或重写上游实现；若必须偏离，上报原因并压到最小

### `wecom_ws` 行为要求

- 群聊历史按群共享，不被 transport `req_id` / `thread_ts` 切碎
- 发送者身份、时间戳注入优先在 `wecom_ws` 通道边界完成
- 草稿流体验保持旧分支感受，但实现限制在 `wecom_ws` 内
- `channel_delivery_instructions` 必须包含 `wecom_ws` 专用提示词

### Prompt 与时间

- prompt/time 改动遵循最小必要原则，不顺手联动修改其他时间链路

### 构建与测试

- 本地默认 debug 编译，不做 release
- 测试二进制放到 `~/.zeroclaw/zeroclaw`

### 提交边界

- 公共层、`wecom_ws`、`docs/master_wecom/` 三类提交分开
- 文档驱动开发：先记文档、列待办，再按文档推进

### 上游交互

- 向上游提 PR / issue 时，不得带入 `wecom_ws` 分支语境，因为上游没有 `wecom_ws`
- 涉及公共层问题时，用上游已有的 channel（如 `telegram`）举例，日志和路径一律脱敏

### 新功能记录

- 在本分支添加新功能时，须在 `docs/master_wecom/` 下新建独立文档记录

### 协作

- 普通实现细节不频繁停下问，但覆盖上游语义、删除既有能力或扩大公共层改动时必须先确认
- "只改这一处""不要动别的"这类约束必须严格按字面执行

## 文档索引

### 当前文档

| 文件 | 说明 |
|------|------|
| [branch-features.md](./branch-features.md) | 分支独有功能清单 |
| [TEMPLATE-master-sync.md](./TEMPLATE-master-sync.md) | 合并记录模板 |

### 历史参考

以下文档保留为历史背景材料，不直接等于当前方案：

| 文件 | 说明 |
|------|------|
| [upstream-port-bootstrap-2026-03-25.md](./upstream-port-bootstrap-2026-03-25.md) | 上游基线重建执行记录 |
| [upstream-master-divergence-report-2026-03-17.md](./upstream-master-divergence-report-2026-03-17.md) | 历史分叉分析 |
| [master-sync-2026-03-20.md](./master-sync-2026-03-20.md) | 同步 master 记录 |
| [master-sync-2026-03-22.md](./master-sync-2026-03-22.md) | 同步 master 记录 |
| [wecom-ws-cron-delivery-merge-gap-2026-03-23.md](./wecom-ws-cron-delivery-merge-gap-2026-03-23.md) | cron delivery merge gap 记录 |
| [full-non-cli-excluded-tools-2026-03-23.md](./full-non-cli-excluded-tools-2026-03-23.md) | non_cli_excluded_tools 决策记录 |
| [agent-upstream-reporting-mistakes-2026-03-19.md](./agent-upstream-reporting-mistakes-2026-03-19.md) | 上游提单失误经验 |
| [draft-newline-upstreaming-mistakes-2026-03-23.md](./draft-newline-upstreaming-mistakes-2026-03-23.md) | draft newline 处理失误经验 |
