# 正文流式回复 & draft 限流

日期：`2026-03-29`

## 背景

工具执行完成后，模型开始写正文回复时，之前的实现会等 `finalize_draft` 才一次性发送，用户体验为"长时间无响应后突然出现完整回复"。需要在正文阶段也实现逐步流式推送。

## 实现

### 1. 正文流式 (`in_final_answer`)

在 `StreamDraftState` 新增 `in_final_answer: bool` 标志。

**检测机制**：框架在每次 live delta 转发前会发 `DraftEvent::Clear`，重置 `accumulated` 内容。当工具活动后收到的 content 不再以 `last_content` 为前缀时（`!content.starts_with(&state.last_content)`），说明内容被重置，**试探性**进入 final-answer 模式。

**为什么是试探性**：`DraftEvent::Clear` 有 5 个发射点，其中 L2088 在每次迭代的 live delta 转发前都会触发，包括批次间的思考内容（inter-batch narration）。因此内容重置不一定意味着正文开始。

**安全措施**：
- 进入 `in_final_answer` 时**不清空** `work_log` 和 `pending_content`，保留用于回退
- 如果进入后又收到 `Progress` 事件，说明检测误报，立即回退到工具活动模式
- 回退时 `work_log` 完整保留，`pending_content` 正常 flush 回 `work_log`

**正文模式行为**：
- 直接流式推送 content，不经过 work_log 10 行限制
- 受 `draft_update_interval_ms` 限流

### 2. draft 限流 (`draft_update_interval_ms`)

参考 Telegram 通道的同名配置，对 WS 帧发送做频率限制。

- 配置项：`wecom_ws.draft_update_interval_ms`，默认 300ms
- 实现：per-stream `Instant` 追踪，WS 发送前检查，发送后记录
- `should_throttle_draft_edit` / `record_draft_edit` 辅助方法
- 清理时机：`clear_draft_state` 同步清理

### 3. 公共层改动

`src/config/schema.rs` — `WeComWsConfig` 新增字段：

```rust
#[serde(default = "default_wecom_ws_draft_update_interval_ms")]
pub draft_update_interval_ms: u64,  // 默认 300
```

## 相关 commit

| commit | 说明 |
|--------|------|
| `7c36c05d` | 删除死代码 `floor_char_boundary` |
| `45f3c4d9` | 正文流式 + Clear 多次触发安全处理 |
| `5b391951` | `draft_update_interval_ms` 限流 |
