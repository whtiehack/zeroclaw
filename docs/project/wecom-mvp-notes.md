# WeCom MVP Notes (wecom_cx)

This document records the implementation decisions for the WeCom MVP gateway integration.

## Scope

- Added encrypted callback verification and message decrypt flow for `GET/POST /wecom`.
- Added WeCom-specific runtime state in gateway layer (in-memory):
  - `conversation_scope` history
  - `execution_scope` in-flight lock
  - stream state / inflight task tracking / expiry cleanup
- Added `response_url` cache and expiry cleanup in WeCom channel layer (`WeComChannel`).
- Added attachment download/decrypt/save flow for `image` and `file` message types.
- Added voice behavior:
  - with transcript: enters model chain
  - without transcript: immediate fixed reply + emoji, no model execution
- Added fallback outbound chain when no valid `response_url` remains:
  1. scope-level push webhook URL from memory key `wecom_push_url::<conversation_scope>`
  2. global fallback robot webhook URL in config

## Conversation Scope Rules

- Single chat: `user:<userid>`
- Group shared-history chat (whitelist): `group:<chatid>`
- Group non-shared chat: `group:<chatid>:user:<userid>`

`execution_scope` follows `conversation_scope` to prevent history corruption under concurrency.

## Context Injection Rules

- Static context (first turn only): `WECOM_STATIC_CONTEXT_V1`
- Shared-group dynamic context (every turn): `WECOM_TURN_CONTEXT_V1` with `sender_userid`
- Single / non-shared group do not repeat sender injection each turn.

## Prompt / Delivery Instruction Handling (Current)

- Gateway passes channel identity (`wecom`) into the agent pipeline.
- Agent injects WeCom delivery instructions into the **system prompt** (same layer as other channel system constraints).
- User message payload remains pure WeCom-composed content (no channel-delivery preamble prepended into user text).
- WeCom composed payload includes:
  - static context (`WECOM_STATIC_CONTEXT_V1`, first turn only)
  - recent history block (`WECOM_HISTORY`)
  - shared-group turn context (`WECOM_TURN_CONTEXT_V1`, when enabled)
  - quote context (`WECOM_QUOTE`, when present)
  - normalized current user message / attachment markers.
- A dedicated `PromptGuard` blocking/sanitizing stage is currently **not** wired in the WeCom callback ingress path.

## Streaming Strategy in MVP

- Current MVP now uses native WeCom passive stream replies:
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
- PromptGuard module exists globally but is not currently enforced in the WeCom callback ingestion path.

## Config Keys Added

- `[channels_config.wecom] token`
- `[channels_config.wecom] encoding_aes_key`
- `[channels_config.wecom] group_shared_history_enabled`
- `[channels_config.wecom] group_shared_history_chat_ids`
- `[channels_config.wecom] file_retention_days`
- `[channels_config.wecom] max_file_size_mb`
- `[channels_config.wecom] response_url_cache_per_scope`
- `[channels_config.wecom] response_url_ttl_secs`
- `[channels_config.wecom] lock_timeout_secs`
- `[channels_config.wecom] history_max_turns`
- `[channels_config.wecom] fallback_robot_webhook_url`
