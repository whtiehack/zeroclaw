# WeCom MVP Notes (wecom_cx)

This document records the implementation decisions for the WeCom MVP gateway integration.

## Scope

- Added encrypted callback verification and message decrypt flow for `GET/POST /wecombot/callback`.
- Added WeCom-specific runtime state in gateway layer (in-memory):
  - `conversation_scope` history
  - `execution_scope` in-flight lock
  - `response_url` cache and expiry cleanup
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

## Streaming Strategy in MVP

- Current MVP uses chunked markdown delivery (multi-send) to emulate progressive output.
- It does not yet implement native WeCom `msgtype=stream` passive-refresh protocol.
- This keeps implementation simple while preserving long-output delivery and retry fallbacks.

## Known Gaps / Follow-up

- Passive encrypted stream protocol (`msgtype=stream` + refresh callbacks) is not implemented yet.
- Attachment type sniffing is minimal (fixed extension defaults for now).
- Fallback push URL governance currently relies on URL validation + memory key convention.

## Config Keys Added

- `[channels_config.wecom] token`
- `[channels_config.wecom] encoding_aes_key`
- `[channels_config.wecom] group_shared_history_enabled`
- `[channels_config.wecom] group_shared_history_chat_ids`
- `[channels_config.wecom] file_retention_days`
- `[channels_config.wecom] max_file_size_mb`
- `[channels_config.wecom] response_url_cache_per_scope`
- `[channels_config.wecom] lock_timeout_secs`
- `[channels_config.wecom] history_max_turns`
- `[channels_config.wecom] fallback_robot_webhook_url`
