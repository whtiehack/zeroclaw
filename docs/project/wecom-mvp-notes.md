# WeCom MVP Notes (wecom_cx)

This document records the implementation decisions for the WeCom integration.

## Architecture

All WeCom business logic lives in the **channel layer** (`src/channels/wecom.rs`).
The gateway (`src/gateway/wecom.rs`) is a stateless HTTP relay (~91 lines) that forwards
raw HTTP requests to the channel via mpsc and returns the oneshot response.

```
HTTP POST /wecom
  → gateway: parse query params + body
  → mpsc::send(WeComInboundRequest { query, body, reply_tx })
  → channel.listen(): receive, decrypt, verify, route, process
  → oneshot reply_tx.send(WeComInboundResponse { status_code, body })
  → gateway: return HTTP response
```

This design follows the same pattern as Telegram (long-poll) and Discord (WebSocket):
`listen()` is the true message entry point, conforming to Channel trait semantics.

## Scope

- Encrypted callback verification and message decrypt flow for `GET/POST /wecom`.
- All runtime state managed in channel layer (in-memory):
  - `conversation_scope` history
  - `execution_scope` in-flight lock
  - stream state / inflight task tracking / expiry cleanup
  - idempotency store
- `response_url` cache and expiry cleanup.
- Attachment download/decrypt/save flow for `image` and `file` message types.
- Voice behavior:
  - with transcript: enters model chain
  - without transcript: immediate fixed reply + emoji, no model execution
- Fallback outbound chain when no valid `response_url` remains:
  1. scope-level push webhook URL from memory key `wecom_push_url::<conversation_scope>`
  2. global fallback robot webhook URL in config
- Scheduled-delivery integration:
  - Channel passes `conversation_scope` as reply target into tool loop context.
  - `cron_add` agent jobs can auto-fill `delivery={"mode":"announce","channel":"wecom","to":"<conversation_scope>"}`.
  - Scheduler delivery supports `channel="wecom"` and uses scope target for push.

## Conversation Scope Rules

- Single chat: `user:<userid>`
- Group chat (default): `group:<chatid>` (all members share one conversation history)
- Group per-user split: not enabled in current behavior; planned to be controlled via memory state in future.
- `history_max_turns` default: 50 (aligned with `MAX_CHANNEL_HISTORY` used by Telegram/Discord).

`execution_scope` follows `conversation_scope` to prevent history corruption under concurrency.

## Session Governance

Clear-session commands allow users to reset conversation history without restarting the service:

- Supported commands (exact match, with optional @mentions): `/clear`, `/new`
- Behavior: clears the in-memory conversation state for the current `conversation_scope` and returns a confirmation message.
- The check runs before stop-command and execution-lock handling.

## Context Injection Rules

- Static context (first turn only): `WECOM_STATIC_CONTEXT_V1` — injected into **system prompt** (not user message) to reduce token usage and keep user messages clean.
- Conversation history: passed as structured `Vec<ChatMessage>` (user/assistant pairs) directly into the LLM message list, aligning with Telegram/Discord's multi-turn model. History is **no longer** injected as a `[WECOM_HISTORY]` text block inside the user message.
- Shared-group dynamic context (every turn): `WECOM_TURN_CONTEXT_V1` with `sender_userid`
- Single chat does not repeat sender injection each turn.

## Prompt / Delivery Instruction Handling

- Channel passes channel identity (`wecom`) into the agent pipeline via `process_message_for_channel_with_history()`.
- Agent injects WeCom delivery instructions into the **system prompt** (same layer as other channel system constraints).
- Agent extracts `WECOM_STATIC_CONTEXT_V1` block from the composed user message and appends it to the system prompt as `## WeCom Context`.
- User message payload after extraction contains only business context (quotes, current input). History is delivered as separate `ChatMessage` entries.
- Push URL configuration guidance is provided solely via system prompt channel delivery instructions (`channel_delivery_instructions("wecom")`); no duplicate hint in static context.
- `execution_scope` is used internally for concurrency control (locks, inflight tracking) but is not exposed to the LLM context.
- WeCom composed payload includes:
  - shared-group turn context (`WECOM_TURN_CONTEXT_V1`, when enabled)
  - quote context (`WECOM_QUOTE`, when present)
  - normalized current user message / attachment markers.
- Prior conversation history is passed as structured `ChatMessage` list via `process_message_for_channel_with_history()`, resulting in LLM seeing: `[system, user1, assistant1, ..., current_user]`.

## Gateway ↔ Channel Communication

```rust
/// Gateway → Channel
pub struct WeComInboundRequest {
    pub query: WeComCallbackQuery,  // HTTP query params (signature, timestamp, nonce, echostr)
    pub body: Bytes,                // raw HTTP body
    pub reply_tx: oneshot::Sender<WeComInboundResponse>,
}

/// Channel → Gateway
pub struct WeComInboundResponse {
    pub status_code: u16,
    pub body: String,
}
```

Both GET (URL verification) and POST (encrypted callbacks) use the same path.
The channel distinguishes them by checking `query.echostr`.

## Streaming Strategy

- Current implementation uses native WeCom passive stream replies:
  - callback response returns encrypted `msgtype=stream` payload
  - first reply uses `finish=false`
  - subsequent `msgtype=stream` refresh callbacks return latest content with same `stream.id`
  - final state returns `finish=true`
- When model output exceeds stream content max length (20480 bytes), overflow part falls back to `response_url` / push-webhook delivery as supplemental message.
- `response_url` cache is still retained for long-task fallback and proactive push.

## Busy / Stop Behavior

- If same `execution_scope` is already processing:
  - normal message: immediate stream reply with busy text and random emoji
  - busy text includes: `如果需要停止当前消息处理，请发送停止或者stop。`
- If busy and incoming message contains `停止` or `stop` (case-insensitive):
  - current in-flight task is aborted
  - active stream state is marked `finish=true` with stop message
  - current callback returns an immediate stop confirmation stream reply

## Known Gaps / Follow-up

- Attachment type sniffing is minimal (fixed extension defaults for now).
- Fallback push URL governance currently relies on URL validation + memory key convention.

## Config Keys Added

- `[channels_config.wecom] token`
- `[channels_config.wecom] encoding_aes_key`
- `[channels_config.wecom] progress_mode` (`off` by default; configurable to `compact` or `verbose`)
- `[channels_config.wecom] file_retention_days`
- `[channels_config.wecom] max_file_size_mb`
- `[channels_config.wecom] response_url_cache_per_scope`
- `[channels_config.wecom] response_url_ttl_secs`
- `[channels_config.wecom] lock_timeout_secs`
- `[channels_config.wecom] history_max_turns`
- `[channels_config.wecom] fallback_robot_webhook_url`
