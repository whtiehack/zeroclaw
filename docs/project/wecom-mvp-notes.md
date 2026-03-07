# WeCom MVP Notes (wecom_cx)

This document records the current WeCom implementation as it exists in code.
It is intentionally descriptive, not aspirational.

## Maintenance Contract

- Before analyzing or changing WeCom-related code, read this document first.
- If you change WeCom code, update this document in the same change.
- If this document is outdated, update it.

## Architecture

- The WeCom integration lives in [`src/channels/wecom.rs`](../../src/channels/wecom.rs).
- There is no `src/gateway/wecom.rs` in the current codebase.
- `WeComChannel::listen()` starts its own `axum` HTTP listener on `0.0.0.0:<port>` and serves:
  - `GET /wecom` for URL verification
  - `POST /wecom` for encrypted callbacks
- The small `WeComInboundRequest` / `WeComInboundResponse` bridge still exists, but it is internal to the channel module rather than a separate gateway layer.

```text
GET/POST /wecom
  → WeComChannel listener (axum)
  → verify signature + decrypt
  → normalize / route callback
  → optionally forward ChannelMessage into shared channel runtime
  → return encrypted passive reply or plain "success"
```

## Responsibility Split

`src/channels/wecom.rs` owns the WeCom-specific transport logic:

- signature verification and AES decrypt/encrypt
- callback routing
- `response_url` cache
- passive stream state
- inbound idempotency
- attachment download / decrypt / persist
- outbound webhook fallback chain

`src/channels/mod.rs` owns the shared runtime behavior:

- conversation history
- system prompt assembly
- LLM + tool execution
- draft/progress streaming
- interruption on newer messages
- scheduler delivery wiring

## Scope Rules

Current scope strings are:

- single chat: `user--<sender_userid>`
- group chat: `group--<chatid>`

These scopes are used differently in the runtime:

- conversation history key: `wecom_<reply_target>`
- interruption key: `wecom_<reply_target>_<sender>`

Practical effect:

- group chats share one conversation history per group
- interruption is sender-scoped inside that group, not group-wide
- a newer message from the same sender interrupts that sender's previous in-flight request when `interrupt_on_new_message` is enabled

There is no current "busy reply" branch for WeCom. The implementation interrupts the previous sender-scoped task instead of returning a special busy message.

## Inbound Callback Flow

### URL Verification

- `GET /wecom` is treated as verification when `echostr` is present.
- The channel verifies `msg_signature` against `token + timestamp + nonce + echostr`.
- On success it decrypts `echostr` and returns the plaintext body.

### Normal Encrypted Callback

For `POST /wecom`, the channel:

1. parses `{ "encrypt": "..." }`
2. verifies signature against the encrypted body
3. decrypts JSON payload
4. parses inbound metadata (`msgid`, `msgtype`, `chattype`, `chatid`, `from.userid`, `response_url`, etc.)
5. drops duplicate non-stream callbacks via an in-memory idempotency set
6. caches `response_url` by conversation scope

Supported model-bound inbound message types are:

- `text`
- `voice`
- `image`
- `file`
- `mixed`

Special routing:

- `stream`: treated as a passive refresh poll; returns the current stream state for `stream.id`
- `event`: explicit handling only for `enter_chat`, `template_card_event`, and `feedback_event`; everything else is acked with `success`
- unsupported `msgtype`: ignored with HTTP 200 / `success`

## Message Normalization

Normalized content forwarded into the shared framework is built as follows:

- `text`: trimmed raw text
- `voice`:
  - with transcript: `[Voice transcript]\n...`
  - without transcript: immediate fixed reply, no model execution
- `image`: download + decrypt + save, then emit `[IMAGE:/absolute/path]`
- `file`: download + decrypt + save, then emit `[Document: /absolute/path]`
- `mixed`: concatenate text items plus downloaded image markers

Quote handling:

- quoted `image` and `file` attachments are materialized before composition
- quoted `mixed` messages currently materialize image items only
- quote context is prepended as:

```text
[WECOM_QUOTE]
msgtype=...
content=...
[/WECOM_QUOTE]
```

Attachment persistence behavior:

- files are stored under `<workspace>/wecom_files/`
- images are persisted with `.png`
- generic files are persisted with `.bin`
- cleanup runs opportunistically on inbound traffic

## Passive Stream Behavior

Normal model-bound requests use native WeCom passive stream replies:

1. generate `stream_id`
2. create in-memory stream state with bootstrap content `正在处理中，请稍候。`
3. immediately return encrypted `msgtype=stream` with `finish=false`
4. forward the normalized message into the shared channel runtime
5. shared draft updates mutate the in-memory stream state
6. later `stream` poll callbacks fetch the latest content by `stream_id`
7. final state sets `finish=true`

Current stream constraints:

- stream text is trimmed to `20480` bytes
- overflow text is sent separately through the normal outbound fallback chain
- stream state TTL is `7200` seconds

Final reply image handling:

- only `[IMAGE:/absolute/path]` markers are promoted into final WeCom stream `msg_item` images
- max 10 images
- only `jpg`, `jpeg`, `png`
- each image must be `<= 10 MiB`

Outbound document/file upload is not implemented. `[Document: ...]` markers are for inbound normalized context, not outbound WeCom upload behavior.

## Prompt and Context Injection

WeCom-specific prompt wiring currently happens in [`src/channels/mod.rs`](../../src/channels/mod.rs):

- `channel_delivery_instructions("wecom")` are appended directly to the system prompt
- `build_channel_system_prompt()` appends `[WECOM_STATIC_CONTEXT_V1]` directly to the system prompt
- there is no current "inject into user message, then extract later" step

`WECOM_STATIC_CONTEXT_V1` currently contains:

- `chat_type`
- `conversation_scope`
- `push_url_memory_key=wecom_push_url::<conversation_scope>`
- `sender_userid` for single chats only

Additional per-turn behavior:

- in shared group chats, current user content is prefixed with `[sender: <userid>]`
- prior conversation history is passed as structured `Vec<ChatMessage>`
- quote context stays in the user content payload as `WECOM_QUOTE`

## Session Reset and Stop Handling

Clear-session behavior:

- exact `/clear` and `/new` commands are recognized
- edge `@mentions` are stripped before comparison
- WeCom first returns a confirmation passive stream
- then it forwards `/clear` into the shared framework so conversation history is cleared

Stop behavior:

- if extracted text contains `停止` or `stop`, WeCom returns a stop confirmation passive stream
- it then forwards `/new` into the shared framework
- the shared runtime cancels the previous sender-scoped in-flight task

Stop-signal extraction currently reads text from:

- `text.content`
- `voice.content`
- text items inside `mixed.msg_item`

## Outbound Delivery Chain

`WeComChannel::send()` and overflow delivery use the same 3-layer order:

1. cached `response_url`
2. memory key `wecom_push_url::<scope>`
3. config `fallback_robot_webhook_url`

Additional notes:

- scope webhook and fallback webhook must be valid `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?...` URLs
- fallback webhook sends are prefixed with `[FallbackPush]`
- webhook delivery uses WeCom group-bot `markdown`
- markdown is chunked with an `8000`-byte target and `20480`-byte hard cap
- if all 3 layers fail, the outbound message is dropped with a warning

Scheduled delivery integration:

- `cron_add` can target `delivery={"mode":"announce","channel":"wecom","to":"<scope>"}`
- scheduler uses the live registered WeCom channel when available
- otherwise it constructs a temporary `WeComChannel` and still calls `send()`

## Runtime State and Persistence

Current in-memory state inside the channel:

- `response_url` cache, pruned by TTL and per-scope capacity
- passive stream state map
- idempotency set for inbound `msgid`

Persistence details:

- downloaded attachments are stored on disk under `<workspace>/wecom_files/`
- file retention is config-driven
- cleanup interval is fixed at 30 minutes
- idempotency state is memory-only and resets on process restart

## Config Surface

Current `[channels_config.wecom]` keys:

- `token`
- `encoding_aes_key`
- `port`
- `file_retention_days`
- `max_file_size_mb`
- `response_url_cache_per_scope`
- `response_url_ttl_secs`
- `lock_timeout_secs`
- `history_max_turns`
- `fallback_robot_webhook_url`
- `progress_mode`

Current defaults from `src/config/schema.rs`:

- `port = 9898`
- `file_retention_days = 3`
- `max_file_size_mb = 20`
- `response_url_cache_per_scope = 50`
- `response_url_ttl_secs = 3600`
- `lock_timeout_secs = 900`
- `history_max_turns = 50`
- `progress_mode = compact`

## Gaps and Sharp Edges

- `history_max_turns` exists in config schema, but current history trimming still uses the shared `MAX_CHANNEL_HISTORY = 50` constant in `src/channels/mod.rs`.
- `lock_timeout_secs` exists in config schema, but current WeCom runtime logic does not consume it.
- outbound file/document upload is not implemented; only final-stream image markers are upgraded to WeCom image items.
- quote `mixed` handling materializes image items, not generic file items.
- attachment type sniffing is intentionally minimal; persisted extensions are fixed defaults (`png` / `bin`).
