# `master_wecom` 上游修复吸收评审（`2026-04-13`）

更新时间：`2026-04-13`

## 1. 基线与评审边界

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 对比上游分支 | `upstream/master` |
| 共同祖先 | `15616063596de025801efdfe6a4680167a5814a5` |
| 分叉计数 | `master_wecom` ahead `107`，`upstream/master` ahead `403` |
| 适合直接参考的上游窗口 | `15616063..1a61ea73` |
| 不建议直接照搬的窗口 | `d8f09f02` 之后的 workspace 拆分阶段 |

### 本次评审的硬约束

- 目标不是机械同步 `upstream/master`，而是挑选值得吸收的修复，且不能破坏 `wecom_ws`。
- `wecom_ws` 必须继续保持这几条本地语义：
  - 群聊历史不能被 transport `req_id` 或 `thread_ts` 切碎。
  - 发送者身份与时间戳注入优先留在 `wecom_ws` 通道边界。
  - 草稿流体感保持当前分支行为。
  - `channel_delivery_instructions` 继续保留 `wecom_ws` 专用提示词。
- 公共层只做最小必要改动，不顺手扩大到 `wecom_ws` 之外的行为重写。

### 必须忽略的一段上游历史

- 上游存在一次“先合并 153 个提交，再整体回滚”的异常历史。
- 回滚提交是 `c3ff6353`：`revert: roll back 153 commits merged today to restore state at 1362d69f`。
- `c3ff6353` 的 tree 与 `1362d69f` 完全一致，因此这 153 个临时合入提交应视为逻辑上无效。
- 结论：
  - 不直接从那 153 个临时提交里挑 cherry-pick。
  - 只吸收回滚后重新落地、并且在当前上游主线仍然成立的提交。

## 2. trait / 公共接口变动

### 直接 trait 签名变化

- 本次建议吸收的提交里，没有必须同步的 `src/**/traits.rs` 直接签名变化。
- 结论是：这批修复主要是公共行为契约修正，不是编译期接口破坏。

### 隐性契约变化

- `agent` 历史修剪的契约更严格了：
  - `tool_use` / `tool_result` 不能被剪断成孤立片段。
  - 被截断的 tool result 仍要保留 JSON 信封和 `tool_call_id`。
- `channels` 公共层出现了一个对本地有吸引力但要谨慎接线的新语义：
  - `keep_tool_context_turns` 可以保留最近若干轮工具上下文。
  - 但主动 `ContextCompressor` 进 channel 模式会改变历史裁剪路径，风险高于收益。
- `providers` 公共层更偏向“请求发送前做兼容性归一化”：
  - OpenAI-compatible API 前清理非法 tool schema。
  - Bedrock 兜底空 content block。
- `cron` / `daemon` 的 recall 契约收紧：
  - 计划任务不应把普通 `Conversation` 记忆混进 recall。

## 3. 框架层新增能力与可吸收修复

### `agent` / 历史管理

| commit | 主题 | 建议 | 说明 |
| --- | --- | --- | --- |
| `87698ad1` | `tool_use/tool_result` 按原子组修剪 | 建议吸收 | 是 `35dd0914` / `d72c2128` 的关键配套，能避免工具对话被剪断 |
| `35dd0914` | 截断 tool result 时保留 JSON 信封 | 建议吸收 | 修复 `tool_call_id` 丢失问题，但最好与 `87698ad1` 成组吸收 |
| `d72c2128` | `trim_history` 跳过孤立 `tool_result` | 建议吸收 | 防止历史裁剪后残留无主 `tool_result` |

当前本地关注点：

- `src/agent/history_pruner.rs`
- `src/agent/history.rs`
- `src/agent/agent.rs`
- `src/agent/loop_.rs`

结论：

- 这组修复值得吸收。
- 正确顺序不是单独挑一条，而是先 `87698ad1`，再 `35dd0914`，最后 `d72c2128`。

### `providers`

| commit | 主题 | 建议 | 说明 |
| --- | --- | --- | --- |
| `30c540bb` | OpenAI-compatible API 发送前清理 tool schema type 数组 | 建议吸收 | 风险低，不改 `wecom_ws` 语义 |
| `0f7244e6` | Bedrock 空 content block 过滤 | 建议吸收 | 值得单独拆出来吸收 |
| `0f7244e6` | custom provider model 切换修复 | 建议吸收，但拆分处理 | 价值有，但会碰 `src/tools/`，风险高于 Bedrock 半边 |
| `7e2c364f` | Anthropic streaming 使用配置的 `max_tokens` | 可选吸收 | 仅在本地确实使用 Anthropic 流式时收益明显 |
| `3eca2668` | keyless custom provider 支持 | 条件吸收 | 只有确实需要无鉴权 custom provider 时再拿 |

当前本地关注点：

- `src/providers/compatible.rs`
- `src/providers/ollama.rs`
- `src/providers/bedrock.rs`
- `src/providers/anthropic.rs`
- `src/tools/model_switch.rs`

结论：

- `30c540bb` 是本批里最稳的一条 provider 修复。
- `0f7244e6` 不建议整条照搬，必须拆成两个 patch 看待。
- `3eca2668` 不是 `0f7244e6` 的硬依赖。

### `channels`

| commit | 主题 | 建议 | 说明 |
| --- | --- | --- | --- |
| `472d040f` | `keep_tool_context_turns` 保留最近 N 轮工具消息 | 值得吸收，但只拿半边 | 对 channel 模式有帮助，但应手工移植，不整条 cherry-pick |
| `472d040f` | channel 模式主动 `ContextCompressor` | 暂缓 | 会改公共层历史裁剪节奏，`wecom_ws` 风险最高 |
| `c70e86cc` | streaming draft 更新时剥离 `<think>` 标签 | 建议吸收 | 直接改善 draft-heavy 通道，`wecom_ws` 受益明显 |

当前本地关注点：

- `src/channels/mod.rs`
- `src/config/schema.rs`
- `src/channels/wecom_ws.rs`

结论：

- `c70e86cc` 是对 `wecom_ws` 直接有感知收益的通用层修复。
- `472d040f` 只能做拆分式人工吸收，优先保留工具上下文，延后主动压缩。

### `daemon` / `cron`

| commit | 主题 | 建议 | 说明 |
| --- | --- | --- | --- |
| `2f4b32a9` | recall 过滤 `Conversation` 记忆 | 建议吸收 | 风险低，能减少定时任务 prompt 污染 |

当前本地关注点：

- `src/cron/scheduler.rs`
- `src/daemon/mod.rs`

## 4. 其它 channel 更新

- 本次值得吸收的上游更新，主体不是“其它 channel 新功能”，而是公共层、provider 与 agent 修复。
- 其它 channel 里唯一对 `wecom_ws` 直接有参考价值的是 `c70e86cc`：
  - 这是公共 streaming draft 清洗。
  - `wecom_ws` 也依赖 draft 更新，因此收益是直接的。
- `3eca2668` 里带的 Lark / Feishu cron delivery 更偏其它 channel 增量能力：
  - 对 `wecom_ws` 没有直接帮助。
  - 如果不做对应 channel 工作，这部分没必要一起吸收。

## 5. 对 `wecom_ws` 的影响

### 直接接口破坏

- 没有发现必须同步的 trait 级硬破坏。
- 风险主要来自公共层行为偏移，而不是接口签名变化。

### merge 热点

- `src/channels/mod.rs`
  - 同时承载 channel history、draft、压缩与 `wecom_ws` 共享语义，是本批最敏感热点。
- `src/agent/history.rs`
- `src/agent/history_pruner.rs`
- `src/agent/agent.rs`
- `src/tools/model_switch.rs`

### 可以直接受益的吸收项

- `30c540bb`
- `2f4b32a9`
- `87698ad1`
- `35dd0914`
- `d72c2128`
- `c70e86cc`

这些提交共同特点是：

- 不依赖 `wecom_ws` 专有逻辑。
- 主要修正 agent / provider / draft 的通用 bug。
- 对 `wecom_ws` 是“增强稳定性”，不是“重写语义”。

### 需要人工拆分的吸收项

- `0f7244e6`
  - Bedrock 空块过滤可单独拿。
  - custom provider model switching 修复要单独审 `src/tools/model_switch.rs`。
- `472d040f`
  - 只建议先拿 `keep_tool_context_turns` 相关部分。
  - 主动 channel context compression 暂不进入第一批。

### 明确不建议现在吸收的项

| commit | 原因 |
| --- | --- |
| `33710e7d` | 把 sender user ID 注入通用 channel system prompt，和本地 `wecom_ws` 边界注入策略可能冲突 |
| `472d040f` 的主动压缩半边 | 会改变 channel history 裁剪路径，可能影响群聊共享历史与 draft 体感 |
| `5f0f7e08` | 配置 warning 修复有价值，但不是当前同步重点 |

## 6. 依赖关系与拆分原则

### 隐藏依赖

1. `35dd0914` 不应孤立吸收。

- 它修的是“被截断后的 tool result 仍能保持结构”。
- 但如果历史修剪本身仍允许把 `tool_use` / `tool_result` 剪断，修复收益会打折。
- 所以建议先吸收 `87698ad1`。

1. `d72c2128` 最好放在上面两条之后。

- 它处理的是裁剪尾部残留孤立 `tool_result`。
- 如果前两条没进来，历史状态机仍然偏脆。

1. `0f7244e6` 必须拆分。

- Bedrock 半边和 `model_switch` 半边风险级别不同。
- 不要把 provider 修复和 `src/tools/` 风险一起打包进一条本地 patch。

1. `472d040f` 必须拆分。

- `keep_tool_context_turns` 是“保留更多必要上下文”。
- 主动 `ContextCompressor` 是“改变压缩路径与时机”。
- 对 `wecom_ws` 来说，两者风险不是一个量级。

### 拆分原则

- 能在通用层以单点修复落地的，不把 `wecom_ws` 逻辑拖进去。
- 只要会改到群聊历史分桶、draft 推送节奏、`channel_delivery_instructions`，就单独评审，不和低风险修复混批。

## 7. 建议吸收顺序

### 第一批：低风险、可直接见效

1. `30c540bb`
2. `2f4b32a9`
3. `87698ad1`
4. `35dd0914`
5. `d72c2128`
6. `c70e86cc`

### 第二批：拆分后再进

1. `0f7244e6` 的 Bedrock 半边
2. `0f7244e6` 的 `model_switch` 半边
3. `472d040f` 的 `keep_tool_context_turns` 半边

### 第三批：按实际需求决定

1. `7e2c364f`
2. `3eca2668`

### 暂缓

1. `472d040f` 的主动 `ContextCompressor` 半边
2. `33710e7d`
3. `5f0f7e08`

## 8. 建议的实施方式

- 不建议直接做一次大 merge。
- 更适合的方式是：
  - 先按上面的顺序做小批量人工移植。
  - 每批只覆盖一个风险域。
  - 公共层 patch、`wecom_ws` 回归保护、文档记录分开提交。
- 如果后续开始动手，建议每一批都附一条“为什么不会影响 `wecom_ws`”的本地说明。

## 9. 回归检查清单

### 必跑测试

- `cargo test conversation_history_key_wecom_ws_ignores_req_id_thread_ts`
- `cargo test process_channel_message_restores_wecom_ws_history_across_req_ids`
- `cargo test parse_runtime_command_allows_new_session_and_models_for_wecom_ws`
- `cargo test wecom_ws --lib`

### 常规验证

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

### 手工检查

- 同一群内不同 `req_id` 的消息仍落到同一历史桶。
- `wecom_ws` draft 流不泄露 `<think>`。
- tool progress 在 draft 流里仍可见。
- `/new`、`/models`、`/model`、`/config` 在 `wecom_ws` 下仍正常。
- `interrupt_on_new_message` 的体感不变。

## 10. 最终结论

- 你列的 6 个提交里，真正适合第一批直接吸收的是：
  - `30c540bb`
  - `2f4b32a9`
  - `35dd0914`
  - `d72c2128`
- 但其中 `35dd0914` 和 `d72c2128` 不应单独拿，最好补上隐藏依赖 `87698ad1`。
- `0f7244e6` 与 `472d040f` 都值得吸收，但都必须拆分，不能整条照搬。
- 除你列的 6 条外，额外最值得补进来的有：
  - `87698ad1`
  - `c70e86cc`
- `7e2c364f` 与 `3eca2668` 留作条件项即可，不必纳入第一批。
