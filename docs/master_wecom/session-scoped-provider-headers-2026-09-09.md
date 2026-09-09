# 会话级 provider header（`{session}` 占位符）

日期：`2026-09-09`

## 问题

`[extra_headers]` 的值在进程启动时就被烘进 reqwest `Client` 的 default headers（`providers/compatible.rs` 的 `http_client()`），一个实例只有一个值。

上游中转按 session header 做 sticky routing / prompt cache（OpenRouter 的 `x-session-id`、CLIProxyAPI 的 `x-session-affinity`）时，整个实例的所有会话在上游眼里是同一个 session：供应商路由无法按对话固定，多用户互相踩 prompt cache 前缀。

## 方案

新增 `src/providers/session_scope.rs`（公共层，约 70 行）：

- `tokio::task_local!` 存当前会话 token，与既有的 `PROVIDER_FALLBACK`（`providers/reliable.rs`）、`TOOL_LOOP_COST_TRACKING_CONTEXT`（`agent/cost.rs`）同模式
- `session_token_from_key()`：会话 key → `sha256` 前 16 位 hex。会话 key 含通道侧用户/会话标识，**不能原样发给第三方上游**，哈希后既稳定又不泄露身份
- `substitute_session_placeholder()`：把 header 值里的 `{session}` 换成当前 token；不含占位符时返回 `None`，调用方走零分配路径

接入点：

| 位置 | 说明 |
|------|------|
| `channels/mod.rs` `dispatch_worker` | 用 `conversation_history_key(&msg)` 包住整个 `process_channel_message`，覆盖主循环、历史压缩、草稿等全部 LLM 调用 |
| `gateway/ws.rs` | 两处 `process_chat_message` 调用用 `session_key` 包住 |
| `providers/compatible.rs` `http_client()` | 构造 default headers 时做占位符替换 |

配置（不含 `{session}` 的值行为完全不变，向后兼容）：

```toml
[extra_headers]
"x-session-id"       = "zeroclaw-<实例名>-{session}"
"x-session-affinity" = "zeroclaw-<实例名>-{session}"
```

## 为什么落在 `http_client()`

流式路径上 RequestBuilder 是在 `tokio::spawn` **里面**构造的（`compatible.rs` 三处流式实现），task_local 到那里已经丢了；`Client` 是在 spawn **之前**建的。所以 `http_client()` 是唯一在所有路径上都还处于会话作用域内的地方，不能改成在各 `.post()` 调用点加 `.header()`。

同理，`dispatch_worker` 里必须包住 future 本身，不能只在父任务上设置。

## 边界

- 只对 OpenAI-compatible provider 生效：`extra_headers` 仅由 `providers/mod.rs` 的 compat 闭包应用，`anthropic-custom` 等路径拿不到
- 无会话作用域时（cron、heartbeat、一次性工具）占位符退化为 `default`，header 仍是合法稳定值
- CLI 单用户路径未接入，无实际收益
- `Box::pin` 包一层是 clippy `large_futures` 要求（`process_channel_message` future 约 17KB）

## 效果预期

会话级 ID 只保证"每个对话钉住一家供应商"，**不等于 cache 命中一定变好**：钉到不做 prompt cache 的供应商时该对话反而更差。要保命中需在上游侧限定供应商白名单，与本改动相互独立。
