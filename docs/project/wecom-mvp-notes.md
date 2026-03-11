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
- `WeComChannel::listen()` opens a WebSocket connection to `wss://openws.work.weixin.qq.com`.
- The channel subscribes with `bot_id + secret`, keeps the socket alive with JSON `ping` frames, and reconnects with exponential backoff when the socket drops.

```text
WeCom WS
  → aibot_subscribe
  → aibot_msg_callback / aibot_event_callback
  → normalize / route callback
  → forward ChannelMessage into shared channel runtime
  → aibot_respond_msg / aibot_send_msg back over the same WS
```

## Responsibility Split

`src/channels/wecom.rs` owns the WeCom-specific transport logic:

- WebSocket connection lifecycle
- subscription / heartbeat / reconnect handling
- callback routing
- inbound idempotency
- attachment download / decrypt / persist
- direct WS replies (`aibot_respond_msg`, `aibot_respond_welcome_msg`)
- active push sends (`aibot_send_msg`)

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
- outbound `aibot_send_msg` target parsing: `user--... -> chat_type=1`, `group--... -> chat_type=2`

Practical effect:

- group chats share one conversation history per group
- interruption is sender-scoped inside that group, not group-wide
- a newer message from the same sender interrupts that sender's previous in-flight request when `interrupt_on_new_message` is enabled

There is no current "busy reply" branch for WeCom. The implementation interrupts the previous sender-scoped task instead of returning a special busy message.

## Inbound WebSocket Flow

`aibot_msg_callback`:

1. read `headers.req_id`
2. parse `body` into `ParsedInbound`
3. drop duplicate `msgid` via in-memory idempotency
4. materialize quote attachments if present
5. normalize content
6. forward `ChannelMessage` into the shared runtime

Supported model-bound inbound message types are:

- `text`
- `voice`
- `image`
- `file`
- `mixed`

`aibot_event_callback`:

- `enter_chat`: immediate `aibot_respond_welcome_msg`
- `template_card_event`: log only
- `feedback_event`: log only
- `disconnected_event`: trigger reconnect

Unsupported message types are ignored with a debug/info log.

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

## Attachment Decrypt Behavior

Current attachment decrypt behavior in code:

- the channel reads `image.aeskey` / `file.aeskey` from the inbound message body when present
- the implementation treats the incoming `aeskey` as base64-decoded key material
- decrypt uses AES-256-CBC with IV = first 16 bytes of the decoded key
- WeCom-style padding is stripped after decrypt

If no `aeskey` is present, the current code writes the raw bytes as-is.

## Streaming Reply Behavior

Normal model-bound requests use native WeCom WS streaming replies:

1. inbound callback provides `headers.req_id`
2. `ChannelMessage.thread_ts` carries that `req_id` into the shared runtime
3. `send_draft()` allocates a fresh `stream_id`
4. the channel stores `stream_id -> req_id` in memory
5. bootstrap reply is sent via `aibot_respond_msg`
6. `update_draft()` refreshes the same stream via `aibot_respond_msg`
7. `finalize_draft()` sends the final `finish=true` frame
8. `cancel_draft()` sends an empty `finish=true` frame

Current stream constraints:

- stream text is trimmed to `20480` bytes
- overflow text is sent separately through `aibot_send_msg`
- all updates for one inbound callback reuse the original `req_id`

Important current limitation:

- although the shared runtime still parses `[IMAGE:/absolute/path]` markers, the WeCom WS implementation currently drops stream images because the long-connection doc does not currently support `msg_item` on `aibot_respond_msg`

Outbound document/file upload is not implemented. `[Document: ...]` markers are for inbound normalized context, not outbound WeCom upload behavior.

## Prompt and Context Injection

WeCom-specific prompt wiring currently happens in [`src/channels/mod.rs`](../../src/channels/mod.rs):

- `channel_delivery_instructions("wecom")` are appended directly to the system prompt
- `build_channel_system_prompt()` appends `[WECOM_STATIC_CONTEXT_V1]` directly to the system prompt
- there is no current "inject into user message, then extract later" step

`WECOM_STATIC_CONTEXT_V1` currently contains:

- `chat_type`
- `conversation_scope`
- `sender_userid` for single chats only

Additional per-turn behavior:

- in shared group chats, current user content is prefixed with `[sender_userid=<userid>]`
- shared group history preserves that `[sender_userid=<userid>]` prefix on cached user turns
- prior conversation history is passed as structured `Vec<ChatMessage>`
- quote context stays in the user content payload as `WECOM_QUOTE`

## Session Reset and Stop Handling

Clear-session behavior:

- exact `/clear` and `/new` commands are recognized
- edge `@mentions` are stripped before comparison
- WeCom immediately sends a final stream confirmation reply
- then it forwards `/clear` into the shared framework so conversation history is cleared

Stop behavior:

- if extracted text contains `停止` or `stop`, WeCom sends a stop confirmation stream
- it then forwards `/new` into the shared framework
- the shared runtime cancels the previous sender-scoped in-flight task

Stop-signal extraction currently reads text from:

- `text.content`
- `voice.content`
- text items inside `mixed.msg_item`

## Outbound Delivery Chain

`WeComChannel::send()` sends directly over the live WeCom WebSocket using `aibot_send_msg`.

Current behavior:

- input `recipient` must be a WeCom scope string (`user--...` or `group--...`)
- outbound content is chunked with an `8000`-byte target and `20480`-byte hard cap
- each chunk becomes a WS `aibot_send_msg` markdown frame
- each `aibot_send_msg` currently waits for the WeCom ack frame and surfaces `errcode/errmsg` back to the caller
- there is no current `response_url` cache
- there is no current scope webhook lookup
- there is no current config fallback webhook

Scheduled delivery integration:

- `cron_add` can target `delivery={"mode":"announce","channel":"wecom","to":"<scope>"}`
- scheduler requires a live registered WeCom channel
- the channel waits briefly for WS readiness before outbound sends
- if the WeCom runtime is not connected, scheduler delivery fails
- if WeCom rejects proactive push for that session, the scheduler now receives the platform error instead of a false success

## Runtime State and Persistence

Current in-memory state inside the channel:

- idempotency set for inbound `msgid`
- `stream_id -> req_id` map for active draft updates
- current WS outbound sender (`ws_tx`) when connected

Persistence details:

- downloaded attachments are stored on disk under `<workspace>/wecom_files/`
- file retention is config-driven
- cleanup interval is fixed at 30 minutes
- idempotency state is memory-only and resets on process restart
- `stream_id -> req_id` state is memory-only and resets on process restart

## Config Surface

Current `[channels_config.wecom]` keys:

- `bot_id`
- `secret`
- `file_retention_days`
- `max_file_size_mb`
- `history_max_turns`
- `progress_mode`

Current defaults from `src/config/schema.rs`:

- `file_retention_days = 3`
- `max_file_size_mb = 20`
- `history_max_turns = 50`
- `progress_mode = compact`

## Gaps and Sharp Edges

- `history_max_turns` exists in config schema, but current history trimming still uses the shared `MAX_CHANNEL_HISTORY = 50` constant in `src/channels/mod.rs`.
- the current WS implementation depends on a live channel runtime; there is no offline or fallback delivery path for WeCom cron sends.
- proactive push still depends on the platform-side session prerequisite: the target user/group must already have an eligible WeCom bot session, and `aibot_send_msg` failure is surfaced from the ack frame.
- stream image items are intentionally dropped for WS mode because the current long-connection doc does not advertise `msg_item` support on `aibot_respond_msg`.
- outbound file/document upload is not implemented.
- quote `mixed` handling materializes image items, not generic file items.
- attachment type sniffing is intentionally minimal; persisted extensions are fixed defaults (`png` / `bin`).
