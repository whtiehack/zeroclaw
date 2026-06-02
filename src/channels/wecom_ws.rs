use super::traits::{Channel, ChannelMessage, SendMessage};
use crate::config::schema::CardButtonExecConfig;
use crate::config::StreamMode;
use aes::Aes256;
use anyhow::{Context, Result};
use async_trait::async_trait;
#[cfg(unix)]
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::Engine as _;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use chrono::Local;
use futures_util::{SinkExt, StreamExt};
use md5 as md5_crate;
use parking_lot::Mutex;
use rand::RngExt;
#[cfg(unix)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

// ── Constants ────────────────────────────────────────────────────────

const WECOM_WS_URL: &str = "wss://openws.work.weixin.qq.com";
const WECOM_BACKOFF_INITIAL_SECS: u64 = 5;
const WECOM_BACKOFF_MAX_SECS: u64 = 60;
const WECOM_PING_INTERVAL_SECS: u64 = 30;
const WECOM_SUBSCRIBE_TIMEOUT_SECS: u64 = 10;
const WECOM_COMMAND_TIMEOUT_SECS: u64 = 10;
const WECOM_HTTP_TIMEOUT_SECS: u64 = 60;
const WECOM_WS_READY_WAIT_SECS: u64 = 10;
const WECOM_WS_READY_POLL_MILLIS: u64 = 100;
const WECOM_STREAM_CONFLICT_MAX_RETRIES: usize = 3;
const WECOM_STREAM_CONFLICT_RETRY_BASE_MILLIS: u64 = 150;
const WECOM_EXPIRED_STREAM_REQ_TTL_SECS: u64 = 3600;
const WECOM_DRAFT_UPDATE_MAX_LINES: usize = 10;

const WECOM_MARKDOWN_MAX_BYTES: usize = 20_480;
const WECOM_MARKDOWN_CHUNK_BYTES: usize = 8_000;
const WECOM_MEDIA_UPLOAD_CHUNK_BYTES: usize = 512 * 1024;
const WECOM_MEDIA_UPLOAD_MAX_CHUNKS: usize = 100;
const WECOM_MEDIA_FILE_MAX_BYTES: usize = 20 * 1024 * 1024;
const WECOM_MEDIA_IMAGE_MAX_BYTES: usize = 2 * 1024 * 1024;
const WECOM_MEDIA_VOICE_MAX_BYTES: usize = 2 * 1024 * 1024;
const WECOM_MEDIA_VIDEO_MAX_BYTES: usize = 10 * 1024 * 1024;
const WECOM_EMOJIS: &[&str] = &[
    "\u{1F642}",
    "\u{1F604}",
    "\u{1F91D}",
    "\u{1F680}",
    "\u{1F44C}",
];
const WECOM_FILE_CLEANUP_INTERVAL_SECS: u64 = 1800;
const WECOM_STREAM_BOOTSTRAP_CONTENT: &str =
    "\u{6b63}\u{5728}\u{5904}\u{7406}\u{4e2d}\u{ff0c}\u{8bf7}\u{7a0d}\u{5019}\u{3002}";

// ── WebSocket outbound command ───────────────────────────────────────

enum WsOutbound {
    Frame(Value),
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct WeComLocalSendRequest {
    recipient: String,
    #[serde(default)]
    message: String,
    /// Optional WeCom `template_card` object. When present an interactive card is pushed via
    /// `aibot_send_msg` (`msgtype=template_card`) instead of a markdown/text message.
    #[serde(default)]
    card: Option<Value>,
}

#[cfg(unix)]
async fn handle_wecom_local_send(
    State(channel): State<WeComWsChannel>,
    Json(payload): Json<WeComLocalSendRequest>,
) -> (StatusCode, Json<Value>) {
    let recipient = payload.recipient.trim().to_string();
    if recipient.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "recipient is required"
            })),
        );
    }

    // Interactive template-card push (takes precedence over `message`).
    if let Some(card) = payload.card {
        return match channel.send_template_card_to_scope(&recipient, card).await {
            Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
            Err(err) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "ok": false,
                    "error": err.to_string()
                })),
            ),
        };
    }

    let message = payload.message.trim();
    if message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "message or card is required"
            })),
        );
    }

    match channel.send(&SendMessage::new(message, recipient)).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true
            })),
        ),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "error": err.to_string()
            })),
        ),
    }
}

// ── Internal types ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ParsedInbound {
    msg_id: String,
    msg_type: String,
    chat_type: String,
    chat_id: Option<String>,
    sender_userid: String,
    aibot_id: String,
    raw_payload: Value,
}

#[derive(Debug, Clone)]
struct ScopeDecision {
    conversation_scope: String,
    shared_group_history: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessDecision {
    Allowed,
    AllowlistMissing,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentKind {
    Image,
    File,
}

impl AttachmentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::File => "file",
        }
    }
}

#[derive(Debug)]
enum NormalizedMessage {
    Ready(String),
    VoiceMissingTranscript,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundAttachmentKind {
    Image,
    File,
    Voice,
    Video,
}

impl OutboundAttachmentKind {
    fn from_marker(marker: &str) -> Option<Self> {
        match marker.trim().to_ascii_uppercase().as_str() {
            "IMAGE" | "PHOTO" => Some(Self::Image),
            "DOCUMENT" | "FILE" => Some(Self::File),
            "VOICE" | "AUDIO" => Some(Self::Voice),
            "VIDEO" => Some(Self::Video),
            _ => None,
        }
    }

    fn infer_from_target(target: &str) -> Self {
        let normalized = target
            .split('?')
            .next()
            .unwrap_or(target)
            .split('#')
            .next()
            .unwrap_or(target);

        let extension = Path::new(normalized)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        match extension.as_str() {
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => Self::Image,
            "mp4" | "mov" | "mkv" | "avi" | "webm" => Self::Video,
            "mp3" | "m4a" | "wav" | "flac" | "ogg" | "oga" | "opus" | "amr" | "silk" => Self::Voice,
            _ => Self::File,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::File => "file",
            Self::Voice => "voice",
            Self::Video => "video",
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::Image => WECOM_MEDIA_IMAGE_MAX_BYTES,
            Self::File => WECOM_MEDIA_FILE_MAX_BYTES,
            Self::Voice => WECOM_MEDIA_VOICE_MAX_BYTES,
            Self::Video => WECOM_MEDIA_VIDEO_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundAttachment {
    kind: OutboundAttachmentKind,
    target: String,
}

#[derive(Debug, Clone)]
struct PreparedOutboundAttachment {
    kind: OutboundAttachmentKind,
    source_path: PathBuf,
    filename: String,
    bytes: Vec<u8>,
    md5_hex: String,
}

struct SimpleIdempotencyStore {
    seen: Mutex<HashSet<String>>,
}

impl SimpleIdempotencyStore {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
    fn record_if_new(&self, key: &str) -> bool {
        self.seen.lock().insert(key.to_string())
    }
}

#[derive(Clone)]
struct WeComRuntimeConfig {
    workspace_dir: PathBuf,
    allowed_users: Vec<String>,
    allowed_groups: Vec<String>,
    file_retention_days: u32,
    max_file_size_bytes: u64,
    stream_mode: StreamMode,
    draft_update_interval_ms: u64,
    card_button_exec: Option<CardButtonExecConfig>,
}

#[derive(Debug, Default, Clone)]
struct StreamDraftState {
    /// Rolling work log buffer (tool progress + model narration during tool activity).
    work_log: String,
    /// Last accumulated content snapshot from `update_draft` (used to compute delta).
    last_content: String,
    /// Whether any tool/progress activity has been seen in this draft lifecycle.
    has_tool_activity: bool,
    /// Content delta buffered after tool activity — might be inter-batch narration
    /// or final answer.  Flushed into `work_log` on next Progress, discarded on
    /// `finalize_draft` / `clear_draft_state`.
    pending_content: String,
    /// True once we detect the framework `Clear` → content reset, meaning
    /// the model has finished tools and is streaming the final answer.
    in_final_answer: bool,
}

// ── MediaDecryptor (per-attachment AES key) ──────────────────────────

struct MediaDecryptor;

impl MediaDecryptor {
    /// Decrypt WeCom media attachment using per-message AES key.
    /// AES-256-CBC, IV = first 16 bytes of key, WeCom-style PKCS padding.
    fn decrypt(aeskey_b64: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
        let raw_key = base64::engine::general_purpose::STANDARD
            .decode(aeskey_b64.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(aeskey_b64.trim()))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(aeskey_b64.trim()))
            .context("failed to decode WeCom media aeskey")?;

        if raw_key.len() < 32 {
            anyhow::bail!(
                "WeCom media aeskey too short: expected >= 32 bytes, got {}",
                raw_key.len()
            );
        }

        let key = &raw_key[..32];
        let iv = &key[..16];

        let mut buf = encrypted.to_vec();
        let plaintext = cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| anyhow::anyhow!("failed to decrypt WeCom media attachment"))?;
        Ok(strip_wecom_padding(plaintext)?.to_vec())
    }
}

// ── WeComWsChannel struct ────────────────────────────────────────────

/// WeCom (企业微信) channel — WebSocket long-connection mode.
///
/// Connects to `wss://openws.work.weixin.qq.com`, subscribes with bot_id + secret.
/// Inbound messages arrive as plaintext JSON frames (no encryption).
/// Outbound replies are pushed directly via WS frames (streaming supported).
/// Media attachments are encrypted per-URL with individual AES keys.
#[derive(Clone)]
pub struct WeComWsChannel {
    bot_id: String,
    secret: String,
    cfg: WeComRuntimeConfig,
    client: reqwest::Client,
    ws_tx: Arc<tokio::sync::Mutex<Option<mpsc::Sender<WsOutbound>>>>,
    pending_responses:
        Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<Result<()>>>>>,
    pending_json_responses:
        Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<Result<Value>>>>>,
    expected_heartbeat_ack: Arc<tokio::sync::Mutex<Option<String>>>,
    respond_msg_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    last_cleanup: Arc<Mutex<Instant>>,
    idempotency: Arc<SimpleIdempotencyStore>,
    req_id_map: Arc<Mutex<HashMap<String, String>>>, // stream_id → req_id
    expired_stream_req_ids: Arc<Mutex<HashMap<String, Instant>>>,
    draft_states: Arc<Mutex<HashMap<String, StreamDraftState>>>,
    last_draft_edit: Arc<Mutex<HashMap<String, Instant>>>,
}

// ── Construction + WS helpers ────────────────────────────────────────

impl WeComWsChannel {
    pub fn new(
        config: &crate::config::schema::WeComWsConfig,
        workspace_dir: &Path,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(WECOM_HTTP_TIMEOUT_SECS))
            .build()
            .context("failed to initialize WeCom HTTP client")?;

        Ok(Self {
            bot_id: config.bot_id.clone(),
            secret: config.secret.clone(),
            cfg: WeComRuntimeConfig {
                workspace_dir: workspace_dir.to_path_buf(),
                allowed_users: normalize_wecom_allowlist(config.allowed_users.clone()),
                allowed_groups: normalize_wecom_allowlist(config.allowed_groups.clone()),
                file_retention_days: config.file_retention_days,
                max_file_size_bytes: config.max_file_size_mb.saturating_mul(1024 * 1024),
                stream_mode: config.stream_mode,
                draft_update_interval_ms: config.draft_update_interval_ms,
                card_button_exec: config.card_button_exec.clone(),
            },
            client,
            ws_tx: Arc::new(tokio::sync::Mutex::new(None)),
            pending_responses: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pending_json_responses: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            expected_heartbeat_ack: Arc::new(tokio::sync::Mutex::new(None)),
            respond_msg_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
            idempotency: Arc::new(SimpleIdempotencyStore::new()),
            req_id_map: Arc::new(Mutex::new(HashMap::new())),
            expired_stream_req_ids: Arc::new(Mutex::new(HashMap::new())),
            draft_states: Arc::new(Mutex::new(HashMap::new())),
            last_draft_edit: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn wait_for_ws_sender(&self) -> Result<mpsc::Sender<WsOutbound>> {
        let deadline = Instant::now() + Duration::from_secs(WECOM_WS_READY_WAIT_SECS);

        loop {
            if let Some(tx) = self.ws_tx.lock().await.as_ref().cloned() {
                return Ok(tx);
            }

            if Instant::now() >= deadline {
                anyhow::bail!("WeCom WebSocket not connected");
            }

            tokio::time::sleep(Duration::from_millis(WECOM_WS_READY_POLL_MILLIS)).await;
        }
    }

    /// Send a JSON frame through the WebSocket outbound channel.
    async fn ws_send_frame(&self, frame: Value) -> Result<()> {
        let tx = self.wait_for_ws_sender().await?;
        tx.send(WsOutbound::Frame(frame))
            .await
            .map_err(|_| anyhow::anyhow!("WeCom WS outbound channel closed"))
    }

    #[cfg(unix)]
    fn local_send_socket_path(&self) -> PathBuf {
        self.cfg.workspace_dir.join("tmp/zeroclaw-wecom_ws.sock")
    }

    #[cfg(unix)]
    async fn start_local_send_socket(&self) {
        let socket_path = self.local_send_socket_path();
        let socket_log_path = absolute_log_path(&socket_path);

        if let Some(parent) = socket_path.parent() {
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                tracing::warn!(
                    path = %absolute_log_path(parent).display(),
                    "[wecom_ws] failed to create local send socket directory: {err:#}"
                );
                return;
            }
        }

        if let Err(err) = tokio::fs::remove_file(&socket_path).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %socket_log_path.display(),
                    "[wecom_ws] failed to remove stale local send socket: {err:#}"
                );
                return;
            }
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(
                    path = %socket_log_path.display(),
                    "[wecom_ws] failed to bind local send socket: {err:#}"
                );
                return;
            }
        };

        tracing::info!(
            path = %socket_log_path.display(),
            "[wecom_ws] local send socket ready"
        );

        let app = Router::new()
            .route("/send", post(handle_wecom_local_send))
            .with_state(self.clone());

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::warn!(
                    path = %socket_log_path.display(),
                    "[wecom_ws] local send socket stopped: {err:#}"
                );
            }
            let _ = tokio::fs::remove_file(&socket_path).await;
        });
    }

    async fn ws_send_frame_and_wait_for_response(
        &self,
        frame: Value,
        req_id: &str,
        command: &str,
    ) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_responses
            .lock()
            .await
            .insert(req_id.to_string(), tx);

        if let Err(err) = self.ws_send_frame(frame).await {
            self.pending_responses.lock().await.remove(req_id);
            return Err(err);
        }

        match tokio::time::timeout(Duration::from_secs(WECOM_COMMAND_TIMEOUT_SECS), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => anyhow::bail!(
                "WeCom WS {command} response channel closed before ack (req_id={req_id})"
            ),
            Err(_) => {
                self.pending_responses.lock().await.remove(req_id);
                anyhow::bail!(
                    "WeCom WS {command} ack timeout after {}s (req_id={req_id})",
                    WECOM_COMMAND_TIMEOUT_SECS
                );
            }
        }
    }

    async fn ws_send_frame_and_wait_for_json_response(
        &self,
        frame: Value,
        req_id: &str,
        command: &str,
    ) -> Result<Value> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_json_responses
            .lock()
            .await
            .insert(req_id.to_string(), tx);

        if let Err(err) = self.ws_send_frame(frame).await {
            self.pending_json_responses.lock().await.remove(req_id);
            return Err(err);
        }

        match tokio::time::timeout(Duration::from_secs(WECOM_COMMAND_TIMEOUT_SECS), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => anyhow::bail!(
                "WeCom WS {command} response channel closed before ack (req_id={req_id})"
            ),
            Err(_) => {
                self.pending_json_responses.lock().await.remove(req_id);
                anyhow::bail!(
                    "WeCom WS {command} ack timeout after {}s (req_id={req_id})",
                    WECOM_COMMAND_TIMEOUT_SECS
                );
            }
        }
    }

    async fn register_heartbeat_req_id(&self, req_id: &str) {
        *self.expected_heartbeat_ack.lock().await = Some(req_id.to_string());
    }

    async fn maybe_handle_command_response(&self, frame: &Value) -> bool {
        let Some(req_id) = frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str)
        else {
            return false;
        };

        let Some(errcode) = frame.get("errcode").and_then(Value::as_i64) else {
            return false;
        };

        let errmsg = frame
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        if let Some(waiter) = self.pending_json_responses.lock().await.remove(req_id) {
            let result = if errcode == 0 {
                Ok(frame.clone())
            } else {
                Err(anyhow::anyhow!(
                    "WeCom command failed: req_id={req_id} errcode={errcode} errmsg={errmsg}"
                ))
            };
            let _ = waiter.send(result);
            return true;
        }

        if let Some(waiter) = self.pending_responses.lock().await.remove(req_id) {
            let result = if errcode == 0 {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "WeCom command failed: req_id={req_id} errcode={errcode} errmsg={errmsg}"
                ))
            };
            let _ = waiter.send(result);
            return true;
        }

        let is_heartbeat_ack = {
            let mut pending = self.expected_heartbeat_ack.lock().await;
            if pending.as_deref() == Some(req_id) {
                *pending = None;
                true
            } else {
                false
            }
        };

        if is_heartbeat_ack {
            if errcode != 0 {
                tracing::warn!(
                    req_id,
                    errcode,
                    errmsg,
                    "[wecom_ws] heartbeat response failed"
                );
            }
            return true;
        }

        if errcode == 0 {
            tracing::debug!(
                req_id,
                errcode,
                errmsg,
                "[wecom_ws] unsolicited command response"
            );
        } else {
            tracing::warn!(
                req_id,
                errcode,
                errmsg,
                "[wecom_ws] command response failed without a waiter"
            );
        }

        true
    }

    async fn respond_msg_lock_for_req_id(&self, req_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.respond_msg_locks
            .lock()
            .await
            .entry(req_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    async fn cleanup_respond_msg_lock(&self, req_id: &str) {
        self.respond_msg_locks.lock().await.remove(req_id);
    }

    fn cleanup_expired_stream_req_ids_locked(expired: &mut HashMap<String, Instant>) {
        let cutoff = Duration::from_secs(WECOM_EXPIRED_STREAM_REQ_TTL_SECS);
        expired.retain(|_, marked_at| marked_at.elapsed() < cutoff);
    }

    fn is_expired_stream_req_id(&self, req_id: &str) -> bool {
        if req_id.is_empty() {
            return false;
        }

        let mut expired = self.expired_stream_req_ids.lock();
        Self::cleanup_expired_stream_req_ids_locked(&mut expired);
        expired.contains_key(req_id)
    }

    fn remember_expired_stream_req_id(&self, req_id: &str) {
        if req_id.is_empty() {
            return;
        }

        let mut expired = self.expired_stream_req_ids.lock();
        Self::cleanup_expired_stream_req_ids_locked(&mut expired);
        expired.insert(req_id.to_string(), Instant::now());
    }

    async fn expire_stream_req_id(&self, req_id: &str, stream_id: Option<&str>) {
        if let Some(stream_id) = stream_id {
            self.req_id_map.lock().remove(stream_id);
        }

        if req_id.is_empty() {
            return;
        }

        self.remember_expired_stream_req_id(req_id);
        self.cleanup_respond_msg_lock(req_id).await;
    }

    fn clear_draft_state(&self, message_id: &str) {
        self.draft_states.lock().remove(message_id);
        self.last_draft_edit.lock().remove(message_id);
    }

    /// Returns `true` if the draft update should be skipped due to rate-limiting.
    fn should_throttle_draft_edit(&self, message_id: &str) -> bool {
        let interval = self.cfg.draft_update_interval_ms;
        if interval == 0 {
            return false;
        }
        let edits = self.last_draft_edit.lock();
        if let Some(last_time) = edits.get(message_id) {
            let elapsed = u64::try_from(last_time.elapsed().as_millis()).unwrap_or(u64::MAX);
            elapsed < interval
        } else {
            false
        }
    }

    fn record_draft_edit(&self, message_id: &str) {
        self.last_draft_edit
            .lock()
            .insert(message_id.to_string(), Instant::now());
    }

    fn note_progress_update(&self, message_id: &str, text: &str) -> Option<String> {
        let mut states = self.draft_states.lock();
        let state = states.entry(message_id.to_string()).or_default();

        if !state.has_tool_activity {
            // First tool activity — seed work_log with any pre-tool narration.
            if !state.last_content.is_empty() {
                state.work_log.push_str(&state.last_content);
                if !state.last_content.ends_with('\n') {
                    state.work_log.push('\n');
                }
            }
            state.has_tool_activity = true;
        }

        // If we were streaming the final answer but got an unexpected progress,
        // fall back to tool-activity mode — our detection was premature.
        // work_log was kept intact on purpose; pending_content flush below
        // will fold any buffered narration back into work_log.
        if state.in_final_answer {
            state.in_final_answer = false;
        }

        // Flush pending content — it was inter-batch narration, not final answer.
        if !state.pending_content.is_empty() {
            state.work_log.push_str(&state.pending_content);
            if !state.pending_content.ends_with('\n') {
                state.work_log.push('\n');
            }
            state.pending_content.clear();
        }

        state.work_log.push_str(text);
        Some(render_work_log(&state.work_log))
    }

    fn note_content_update(&self, message_id: &str, content: &str) -> Option<String> {
        let mut states = self.draft_states.lock();
        let state = states.entry(message_id.to_string()).or_default();

        if !state.has_tool_activity {
            // No tool activity yet — normal streaming reply, show accumulated content.
            state.last_content.clear();
            state.last_content.push_str(content);
            return Some(sanitize_outbound_draft_content(content));
        }

        if state.in_final_answer {
            // Already in final answer phase — stream content directly, no line limit.
            state.last_content.clear();
            state.last_content.push_str(content);
            return Some(sanitize_outbound_draft_content(content));
        }

        // Tool activity mode — check if the framework reset accumulated content
        // (DraftEvent::Clear before forwarding).  When that happens the new
        // content no longer starts with last_content.
        //
        // Note: Clear fires both before inter-batch narration and before the
        // final answer — we cannot distinguish them here.  We tentatively enter
        // `in_final_answer` and show the content directly.  If a Progress event
        // arrives afterward the flag is reverted (see `note_progress_update`).
        // We intentionally keep work_log intact so it can be restored on revert.
        let is_continuation =
            state.last_content.is_empty() || content.starts_with(&state.last_content);

        if !is_continuation {
            // Content was reset → tentatively enter final-answer streaming.
            // Keep work_log and pending_content intact for potential fallback.
            state.in_final_answer = true;
            state.last_content.clear();
            state.last_content.push_str(content);
            return Some(sanitize_outbound_draft_content(content));
        }

        // Inter-batch narration — compute delta and buffer it.
        let delta = content.strip_prefix(&state.last_content).unwrap_or(content);
        state.last_content.clear();
        state.last_content.push_str(content);
        if !delta.is_empty() {
            state.pending_content.push_str(delta);
        }

        // Don't update display — keep showing current work_log.
        // Pending content will be flushed on next Progress or discarded on finalize.
        None
    }

    async fn fail_pending_responses(&self, reason: &str) {
        let pending = {
            let mut guard = self.pending_responses.lock().await;
            std::mem::take(&mut *guard)
        };
        let pending_json = {
            let mut guard = self.pending_json_responses.lock().await;
            std::mem::take(&mut *guard)
        };

        *self.expected_heartbeat_ack.lock().await = None;

        for (req_id, waiter) in pending {
            let _ = waiter.send(Err(anyhow::anyhow!(
                "WeCom WebSocket disconnected before response: req_id={req_id} reason={reason}"
            )));
        }

        for (req_id, waiter) in pending_json {
            let _ = waiter.send(Err(anyhow::anyhow!(
                "WeCom WebSocket disconnected before response: req_id={req_id} reason={reason}"
            )));
        }
    }

    fn access_decision(&self, inbound: &ParsedInbound) -> AccessDecision {
        evaluate_access_decision(&self.cfg.allowed_users, &self.cfg.allowed_groups, inbound)
    }

    async fn respond_access_denied(
        &self,
        req_id: &str,
        inbound: &ParsedInbound,
        decision: AccessDecision,
    ) {
        let message = build_access_denied_message(inbound, decision);
        let stream_id = next_stream_id();
        if let Err(err) = self
            .ws_queue_respond_msg(req_id, &stream_id, &message, true)
            .await
        {
            tracing::warn!(
                sender_userid = %inbound.sender_userid,
                chat_type = %inbound.chat_type,
                chat_id = %inbound.chat_id.as_deref().unwrap_or("-"),
                error = %format_args!("{err:#}"),
                "[wecom_ws] failed to send access-denied response"
            );
        }
    }

    /// Send an `aibot_respond_msg` streaming frame.
    fn build_respond_msg_frame(
        req_id: &str,
        stream_id: &str,
        content: &str,
        finish: bool,
    ) -> Value {
        serde_json::json!({
            "cmd": "aibot_respond_msg",
            "headers": { "req_id": req_id },
            "body": {
                "msgtype": "stream",
                "stream": {
                    "id": stream_id,
                    "finish": finish,
                    "content": normalize_stream_content(content),
                },
            },
        })
    }

    async fn ws_queue_respond_msg(
        &self,
        req_id: &str,
        stream_id: &str,
        content: &str,
        finish: bool,
    ) -> Result<()> {
        let frame = Self::build_respond_msg_frame(req_id, stream_id, content, finish);
        self.ws_send_frame(frame).await
    }

    async fn ws_send_respond_msg(
        &self,
        req_id: &str,
        stream_id: &str,
        content: &str,
        finish: bool,
    ) -> Result<()> {
        let frame = Self::build_respond_msg_frame(req_id, stream_id, content, finish);
        if req_id.is_empty() {
            return self.ws_send_frame(frame).await;
        }

        let stream_lock = self.respond_msg_lock_for_req_id(req_id).await;
        let _guard = stream_lock.lock().await;
        let mut attempt = 0usize;

        let result = loop {
            match self
                .ws_send_frame_and_wait_for_response(frame.clone(), req_id, "aibot_respond_msg")
                .await
            {
                Ok(()) => break Ok(()),
                Err(err)
                    if is_wecom_data_version_conflict_error(&err)
                        && attempt < WECOM_STREAM_CONFLICT_MAX_RETRIES =>
                {
                    let retry_in_ms =
                        WECOM_STREAM_CONFLICT_RETRY_BASE_MILLIS.saturating_mul(1u64 << attempt);
                    attempt += 1;
                    tracing::warn!(
                        req_id,
                        stream_id,
                        attempt,
                        retry_in_ms,
                        "WeCom stream reply hit data-version conflict; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(retry_in_ms)).await;
                }
                Err(err) => break Err(err),
            }
        };

        if finish {
            self.cleanup_respond_msg_lock(req_id).await;
        }

        result
    }

    // ── file cleanup ─────────────────────────────────────────────────

    fn maybe_cleanup_files(&self) {
        let now = Instant::now();
        {
            let mut last = self.last_cleanup.lock();
            if now.duration_since(*last) < Duration::from_secs(WECOM_FILE_CLEANUP_INTERVAL_SECS) {
                return;
            }
            *last = now;
        }

        let retention = Duration::from_secs(u64::from(self.cfg.file_retention_days) * 86_400);
        let root = self.cfg.workspace_dir.join("wecom_ws_files");
        tokio::spawn(async move {
            cleanup_inbox_files(root, retention).await;
        });
    }

    // ── WS message dispatch ──────────────────────────────────────────

    /// Returns `true` if the caller should trigger reconnection.
    async fn handle_ws_message(&self, frame: Value, tx: &mpsc::Sender<ChannelMessage>) -> bool {
        if self.maybe_handle_command_response(&frame).await {
            return false;
        }

        let cmd = frame.get("cmd").and_then(Value::as_str).unwrap_or("");

        match cmd {
            "aibot_msg_callback" => {
                let channel = self.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    channel.handle_msg_callback(frame, &tx).await;
                });
                false
            }
            "aibot_event_callback" => self.handle_event_callback(frame, tx).await,
            _ => {
                tracing::debug!("[wecom_ws] ignoring WS frame cmd={cmd}");
                false
            }
        }
    }

    // ── Message callback handling ────────────────────────────────────

    async fn handle_msg_callback(&self, frame: Value, tx: &mpsc::Sender<ChannelMessage>) {
        let req_id = frame
            .get("headers")
            .and_then(|h| h.get("req_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let body = match frame.get("body") {
            Some(b) => b.clone(),
            None => {
                tracing::warn!("[wecom_ws] msg_callback missing body");
                return;
            }
        };

        let parsed = match parse_inbound_payload(body) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!("[wecom_ws] msg_callback parse failed: {err:#}");
                return;
            }
        };

        // Idempotency check
        if !parsed.msg_id.is_empty() {
            let key = format!("wecom_ws_msg_{}", parsed.msg_id);
            if !self.idempotency.record_if_new(&key) {
                return;
            }
        }

        let scopes = compute_scopes(&parsed);

        // Log inbound info
        let preview = crate::util::truncate_with_ellipsis(&inbound_content_preview(&parsed), 80);
        let msg_id_str = if parsed.msg_id.trim().is_empty() {
            "-"
        } else {
            parsed.msg_id.as_str()
        };
        tracing::info!(
            "[wecom_ws] from {} in {}: {} (msg_type={}, msg_id={})",
            parsed.sender_userid,
            scopes.conversation_scope,
            preview,
            parsed.msg_type,
            msg_id_str
        );

        match self.access_decision(&parsed) {
            AccessDecision::Allowed => {}
            AccessDecision::AllowlistMissing => {
                tracing::warn!(
                    sender_userid = %parsed.sender_userid,
                    chat_type = %parsed.chat_type,
                    chat_id = %parsed.chat_id.as_deref().unwrap_or("-"),
                    "[wecom_ws] inbound denied because allowlist is not configured"
                );
                self.respond_access_denied(&req_id, &parsed, AccessDecision::AllowlistMissing)
                    .await;
                return;
            }
            AccessDecision::Denied => {
                tracing::warn!(
                    sender_userid = %parsed.sender_userid,
                    chat_type = %parsed.chat_type,
                    chat_id = %parsed.chat_id.as_deref().unwrap_or("-"),
                    "[wecom_ws] inbound denied by allowlist"
                );
                self.respond_access_denied(&req_id, &parsed, AccessDecision::Denied)
                    .await;
                return;
            }
        }

        self.maybe_cleanup_files();

        // ── Command detection ────────────────────────────────────────

        let stop_text = extract_stop_signal_text(&parsed).unwrap_or_default();

        // Clear session
        if is_clear_session_command(&stop_text) {
            tracing::info!(
                "WeCom session cleared: scope={} msg_id={}",
                scopes.conversation_scope,
                parsed.msg_id
            );
            let _ = tx
                .send(ChannelMessage {
                    id: parsed.msg_id.clone(),
                    sender: framework_sender_identity(&parsed, &scopes),
                    reply_target: scopes.conversation_scope.clone(),
                    content: "/new".to_string(),
                    channel: "wecom_ws".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: Some(req_id),
                    interruption_scope_id: None,
                    attachments: vec![],
                })
                .await;
            return;
        }

        // Stop command
        if is_stop_runtime_command(&stop_text) {
            let _ = tx
                .send(ChannelMessage {
                    id: parsed.msg_id.clone(),
                    sender: framework_sender_identity(&parsed, &scopes),
                    reply_target: scopes.conversation_scope.clone(),
                    content: "/stop".to_string(),
                    channel: "wecom_ws".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: Some(req_id),
                    interruption_scope_id: None,
                    attachments: vec![],
                })
                .await;
            return;
        }

        if let Some(runtime_command) = extract_runtime_routing_command(&stop_text) {
            tracing::info!(
                "WeCom runtime command forwarded: scope={} msg_id={} command={}",
                scopes.conversation_scope,
                parsed.msg_id,
                runtime_command
            );
            let _ = tx
                .send(ChannelMessage {
                    id: parsed.msg_id.clone(),
                    sender: framework_sender_identity(&parsed, &scopes),
                    reply_target: scopes.conversation_scope.clone(),
                    content: runtime_command,
                    channel: "wecom_ws".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: Some(req_id),
                    interruption_scope_id: None,
                    attachments: vec![],
                })
                .await;
            return;
        }

        // Voice without transcript
        if is_voice_without_transcript(&parsed) {
            let msg = format!(
                "\u{6211}\u{73b0}\u{5728}\u{65e0}\u{6cd5}\u{5904}\u{7406}\u{8bed}\u{97f3}\u{6d88}\u{606f} {}",
                random_emoji()
            );
            let stream_id = next_stream_id();
            let _ = self
                .ws_queue_respond_msg(&req_id, &stream_id, &msg, true)
                .await;
            return;
        }

        // Unsupported message type
        if !is_model_supported_msgtype(&parsed.msg_type) {
            tracing::info!(
                "WeCom unsupported message ignored: msg_type={} msg_id={}",
                parsed.msg_type,
                parsed.msg_id
            );
            return;
        }

        // ── Forward normal message to framework ──────────────────────

        let channel_self = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut inbound = parsed;
            channel_self
                .materialize_quote_attachments(&mut inbound)
                .await;
            let normalized = channel_self.normalize_message(&inbound).await;

            let content = match normalized {
                NormalizedMessage::VoiceMissingTranscript => {
                    let msg = format!(
                        "\u{6211}\u{73b0}\u{5728}\u{65e0}\u{6cd5}\u{5904}\u{7406}\u{8bed}\u{97f3}\u{6d88}\u{606f} {}",
                        random_emoji()
                    );
                    let stream_id = next_stream_id();
                    let _ = channel_self
                        .ws_queue_respond_msg(&req_id, &stream_id, &msg, true)
                        .await;
                    return;
                }
                NormalizedMessage::Unsupported => {
                    let msg = "\u{6682}\u{4e0d}\u{652f}\u{6301}\u{8be5}\u{6d88}\u{606f}\u{7c7b}\u{578b}\u{3002}";
                    let stream_id = next_stream_id();
                    let _ = channel_self
                        .ws_queue_respond_msg(&req_id, &stream_id, msg, true)
                        .await;
                    return;
                }
                NormalizedMessage::Ready(content) => content,
            };

            let composed = compose_content_for_framework(&inbound, &scopes, &content);

            tracing::info!(
                "WeCom: forwarding to framework: msg_id={} req_id={} scope={}",
                inbound.msg_id,
                req_id,
                scopes.conversation_scope
            );

            let _ = tx
                .send(ChannelMessage {
                    id: inbound.msg_id.clone(),
                    sender: framework_sender_identity(&inbound, &scopes),
                    reply_target: scopes.conversation_scope.clone(),
                    content: composed,
                    channel: "wecom_ws".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: Some(req_id),
                    interruption_scope_id: None,
                    attachments: vec![],
                })
                .await;
        });
    }

    // ── Event callback handling ──────────────────────────────────────

    /// Returns `true` if the caller should trigger reconnection.
    async fn handle_event_callback(
        &self,
        frame: Value,
        tx: &mpsc::Sender<ChannelMessage>,
    ) -> bool {
        let req_id = frame
            .get("headers")
            .and_then(|h| h.get("req_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let body = frame.get("body").cloned().unwrap_or(Value::Null);
        let event_type = parse_event_type(&body).unwrap_or_else(|| "unknown".to_string());

        match event_type.as_str() {
            "enter_chat" => {
                let content = format!(
                    "\u{4f60}\u{597d}\u{ff0c}\u{6b22}\u{8fce}\u{6765}\u{627e}\u{6211}\u{804a}\u{5929} {}",
                    random_emoji()
                );
                let welcome = serde_json::json!({
                    "cmd": "aibot_respond_welcome_msg",
                    "headers": { "req_id": req_id },
                    "body": {
                        "msgtype": "text",
                        "text": { "content": content }
                    }
                });
                let _ = self.ws_send_frame(welcome).await;
                false
            }
            "template_card_event" => {
                let event_key = extract_template_card_event_key(&body).unwrap_or_default();
                let task_id = extract_template_card_event_task_id(&body).unwrap_or_default();
                let userid = body
                    .get("from")
                    .and_then(|f| f.get("userid"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let chattype = body
                    .get("chattype")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let chatid = body
                    .get("chatid")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let scope = if chattype.eq_ignore_ascii_case("group") && !chatid.is_empty() {
                    format!("group--{chatid}")
                } else {
                    format!("user--{userid}")
                };
                tracing::info!(
                    "WeCom template_card_event received: event_key={event_key} scope={scope} userid={userid} task_id={task_id}"
                );
                if event_key.is_empty() {
                    tracing::warn!(
                        "WeCom template_card_event missing event_key; nothing to dispatch"
                    );
                } else if self.card_button_is_exec(&event_key) {
                    // “单独的那种”：key 在 exec 白名单内，直接触发命令，绕过 LLM。
                    self.maybe_dispatch_card_button(&event_key, &scope, &userid, &task_id);
                } else {
                    // “LLM 的”：注入一条消息回框架，由 LLM 处理（它发的卡片它接）。
                    self.route_card_click_to_framework(
                        tx, &event_key, &task_id, &scope, &userid, &body,
                    )
                    .await;
                }
                false
            }
            "feedback_event" => {
                let summary = extract_feedback_event_summary(&body)
                    .unwrap_or_else(|| "feedback=invalid-payload".to_string());
                tracing::info!("WeCom feedback_event received: {summary}");
                false
            }
            "disconnected_event" => {
                tracing::warn!("[wecom_ws] received disconnected_event, triggering reconnect");
                true
            }
            other => {
                tracing::debug!("[wecom_ws] ignoring event_type={other}");
                false
            }
        }
    }

    /// Bridge a template-card button click to the configured external command.
    ///
    /// No-op unless `card_button_exec` is configured and `event_key` is allowlisted. The command
    /// receives `<event_key> <scope> <userid> <task_id>` as trailing argv (never via a shell), so
    /// the (semi-trusted) ids cannot inject shell syntax. The child is spawned detached and reaped
    /// in the background; all business logic / authorization lives inside the command itself.
    fn maybe_dispatch_card_button(&self, event_key: &str, scope: &str, userid: &str, task_id: &str) {
        let Some(exec) = self.cfg.card_button_exec.as_ref() else {
            tracing::info!(
                "WeCom template_card_event: card_button_exec not configured, event_key={event_key} ignored"
            );
            return;
        };
        if !card_event_key_allowed(&exec.allowed_keys, event_key) {
            tracing::warn!(
                "WeCom template_card_event: event_key={event_key} not in allowed_keys, ignored"
            );
            return;
        }

        let mut cmd = tokio::process::Command::new(&exec.command);
        cmd.args(&exec.args)
            .arg(event_key)
            .arg(scope)
            .arg(userid)
            .arg(task_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(mut child) => {
                tracing::info!(
                    "WeCom card button dispatched: event_key={event_key} scope={scope} userid={userid} pid={:?}",
                    child.id()
                );
                // Reap the short-lived dispatcher so it doesn't linger as a zombie.
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(err) => {
                tracing::error!(
                    "WeCom card button dispatch failed to spawn ({}): {err}",
                    exec.command
                );
            }
        }
    }

    /// Whether a clicked button routes to the direct-exec bridge (vs. back to the model).
    fn card_button_is_exec(&self, event_key: &str) -> bool {
        self.cfg
            .card_button_exec
            .as_ref()
            .is_some_and(|e| card_event_key_allowed(&e.allowed_keys, event_key))
    }

    /// Route a (non-exec) card button click back to the framework as a synthetic message so the
    /// model that sent the card can handle the interaction. Replies go out as an active push
    /// (`thread_ts: None`) since event callbacks carry no stream `req_id`.
    async fn route_card_click_to_framework(
        &self,
        tx: &mpsc::Sender<ChannelMessage>,
        event_key: &str,
        task_id: &str,
        scope: &str,
        userid: &str,
        body: &Value,
    ) {
        let id = body
            .get("msgid")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("cardclick-{}", random_ascii_token(8)));

        let is_group = scope.starts_with("group--");
        let sender = if is_group {
            scope.to_string()
        } else {
            userid.to_string()
        };

        let now = Local::now().format("%Y-%m-%d %H:%M:%S %Z");
        let mut content = format!("[{now}] [\u{5361}\u{7247}\u{6309}\u{94ae}\u{70b9}\u{51fb}] event_key={event_key}");
        if !task_id.is_empty() {
            content.push_str(&format!(" task_id={task_id}"));
        }
        if is_group && !userid.is_empty() {
            content = format!("[sender_userid={userid}] {content}");
        }

        tracing::info!(
            "WeCom card click routed to framework: event_key={event_key} scope={scope} userid={userid}"
        );

        let _ = tx
            .send(ChannelMessage {
                id,
                sender,
                reply_target: scope.to_string(),
                content,
                channel: "wecom_ws".to_string(),
                timestamp: bytes_timestamp_now(),
                thread_ts: None,
                interruption_scope_id: None,
                attachments: vec![],
            })
            .await;
    }

    // ── Attachment handling ──────────────────────────────────────────

    async fn materialize_quote_attachments(&self, inbound: &mut ParsedInbound) {
        let quote_type = inbound
            .raw_payload
            .get("quote")
            .and_then(|v| v.get("msgtype"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");

        if quote_type == "image" {
            let quote_obj = inbound
                .raw_payload
                .get("quote")
                .and_then(|v| v.get("image"));
            let quote_url = quote_obj
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
            let aeskey = quote_obj
                .and_then(|v| v.get("aeskey"))
                .and_then(Value::as_str);
            if let Some(url) = quote_url {
                let marker = match self
                    .download_and_store_attachment(&url, AttachmentKind::Image, inbound, aeskey)
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        log_attachment_processing_failure(
                            "WeCom quote image processing failed",
                            &err,
                            inbound,
                            AttachmentKind::Image,
                            &url,
                        );
                        "[\u{5f15}\u{7528}\u{56fe}\u{7247}\u{4e0b}\u{8f7d}\u{5931}\u{8d25}]"
                            .to_string()
                    }
                };
                if let Some(quote) = inbound.raw_payload.get_mut("quote") {
                    quote["image"] = serde_json::json!({ "local_path": marker });
                }
            }
            return;
        }

        if quote_type == "file" {
            let quote_obj = inbound.raw_payload.get("quote").and_then(|v| v.get("file"));
            let quote_url = quote_obj
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
            let aeskey = quote_obj
                .and_then(|v| v.get("aeskey"))
                .and_then(Value::as_str);
            if let Some(url) = quote_url {
                let marker = match self
                    .download_and_store_attachment(&url, AttachmentKind::File, inbound, aeskey)
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        log_attachment_processing_failure(
                            "WeCom quote file processing failed",
                            &err,
                            inbound,
                            AttachmentKind::File,
                            &url,
                        );
                        "[\u{5f15}\u{7528}\u{6587}\u{4ef6}\u{4e0b}\u{8f7d}\u{5931}\u{8d25}]"
                            .to_string()
                    }
                };
                if let Some(quote) = inbound.raw_payload.get_mut("quote") {
                    quote["file"] = serde_json::json!({ "local_path": marker });
                }
            }
            return;
        }

        if quote_type == "mixed" {
            let quote_images: Vec<(usize, String, Option<String>)> = inbound
                .raw_payload
                .get("quote")
                .and_then(|v| v.get("mixed"))
                .and_then(|v| v.get("msg_item"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, item)| {
                            let item_type = item
                                .get("msgtype")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            if item_type != "image" {
                                return None;
                            }
                            let img = item.get("image")?;
                            let url = img
                                .get("url")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|v| !v.is_empty())?;
                            let aeskey = img
                                .get("aeskey")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            Some((idx, url.to_string(), aeskey))
                        })
                        .collect()
                })
                .unwrap_or_default();

            if quote_images.is_empty() {
                return;
            }

            let mut results: Vec<(usize, String)> = Vec::with_capacity(quote_images.len());
            for (idx, url, aeskey) in &quote_images {
                let marker = match self
                    .download_and_store_attachment(
                        url,
                        AttachmentKind::Image,
                        inbound,
                        aeskey.as_deref(),
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        log_attachment_processing_failure(
                            "WeCom quote mixed image processing failed",
                            &err,
                            inbound,
                            AttachmentKind::Image,
                            url,
                        );
                        "[\u{5f15}\u{7528}\u{56fe}\u{7247}\u{4e0b}\u{8f7d}\u{5931}\u{8d25}]"
                            .to_string()
                    }
                };
                results.push((*idx, marker));
            }

            if let Some(items) = inbound
                .raw_payload
                .get_mut("quote")
                .and_then(|v| v.get_mut("mixed"))
                .and_then(|v| v.get_mut("msg_item"))
                .and_then(Value::as_array_mut)
            {
                for (idx, marker) in results {
                    if let Some(item) = items.get_mut(idx) {
                        item["image"] = serde_json::json!({ "local_path": marker });
                    }
                }
            }
        }
    }

    async fn normalize_message(&self, inbound: &ParsedInbound) -> NormalizedMessage {
        match inbound.msg_type.as_str() {
            "text" => {
                let content = inbound
                    .raw_payload
                    .get("text")
                    .and_then(|v| v.get("content"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();

                if content.is_empty() {
                    NormalizedMessage::Unsupported
                } else {
                    NormalizedMessage::Ready(content)
                }
            }
            "voice" => {
                let content = inbound
                    .raw_payload
                    .get("voice")
                    .and_then(|v| v.get("content"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();

                if content.is_empty() {
                    NormalizedMessage::VoiceMissingTranscript
                } else {
                    NormalizedMessage::Ready(format!("[Voice transcript]\n{content}"))
                }
            }
            "image" => {
                let image_obj = inbound.raw_payload.get("image");
                let url = image_obj
                    .and_then(|v| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let aeskey = image_obj
                    .and_then(|v| v.get("aeskey"))
                    .and_then(Value::as_str);

                if url.is_empty() {
                    return NormalizedMessage::Unsupported;
                }

                match self
                    .download_and_store_attachment(url, AttachmentKind::Image, inbound, aeskey)
                    .await
                {
                    Ok(marker) => NormalizedMessage::Ready(marker),
                    Err(err) => {
                        log_attachment_processing_failure(
                            "WeCom image processing failed",
                            &err,
                            inbound,
                            AttachmentKind::Image,
                            url,
                        );
                        NormalizedMessage::Ready(
                            "[Image attachment processing failed; please continue without this image.]"
                                .to_string(),
                        )
                    }
                }
            }
            "file" => {
                let file_obj = inbound.raw_payload.get("file");
                let url = file_obj
                    .and_then(|v| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let aeskey = file_obj
                    .and_then(|v| v.get("aeskey"))
                    .and_then(Value::as_str);

                if url.is_empty() {
                    return NormalizedMessage::Unsupported;
                }

                match self
                    .download_and_store_attachment(url, AttachmentKind::File, inbound, aeskey)
                    .await
                {
                    Ok(marker) => NormalizedMessage::Ready(marker),
                    Err(err) => {
                        log_attachment_processing_failure(
                            "WeCom file processing failed",
                            &err,
                            inbound,
                            AttachmentKind::File,
                            url,
                        );
                        NormalizedMessage::Ready(
                            "[File attachment processing failed; please continue without this file.]"
                                .to_string(),
                        )
                    }
                }
            }
            "mixed" => {
                let mut text_parts = Vec::new();
                if let Some(items) = inbound
                    .raw_payload
                    .get("mixed")
                    .and_then(|v| v.get("msg_item"))
                    .and_then(Value::as_array)
                {
                    for item in items {
                        let item_type = item
                            .get("msgtype")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if item_type == "text" {
                            if let Some(text) = item
                                .get("text")
                                .and_then(|v| v.get("content"))
                                .and_then(Value::as_str)
                            {
                                let trimmed = text.trim();
                                if !trimmed.is_empty() {
                                    text_parts.push(trimmed.to_string());
                                }
                            }
                        } else if item_type == "image" {
                            let img = item.get("image");
                            let url = img.and_then(|v| v.get("url")).and_then(Value::as_str);
                            let aeskey = img.and_then(|v| v.get("aeskey")).and_then(Value::as_str);
                            if let Some(url) = url {
                                match self
                                    .download_and_store_attachment(
                                        url,
                                        AttachmentKind::Image,
                                        inbound,
                                        aeskey,
                                    )
                                    .await
                                {
                                    Ok(marker) => text_parts.push(marker),
                                    Err(err) => {
                                        log_attachment_processing_failure(
                                            "WeCom mixed image processing failed",
                                            &err,
                                            inbound,
                                            AttachmentKind::Image,
                                            url,
                                        );
                                        text_parts.push(
                                            "[Image attachment processing failed in mixed message.]"
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                if text_parts.is_empty() {
                    NormalizedMessage::Unsupported
                } else {
                    NormalizedMessage::Ready(text_parts.join("\n\n"))
                }
            }
            other => {
                tracing::info!(
                    "[wecom_ws] unsupported msg_type={other}, raw_payload={}",
                    inbound.raw_payload
                );
                NormalizedMessage::Unsupported
            }
        }
    }

    async fn download_and_store_attachment(
        &self,
        url: &str,
        kind: AttachmentKind,
        inbound: &ParsedInbound,
        aeskey: Option<&str>,
    ) -> Result<String> {
        if self.cfg.max_file_size_bytes == 0 {
            anyhow::bail!("WeCom max_file_size_bytes is zero");
        }

        let started = Instant::now();
        let chat_id = inbound.chat_id.as_deref().unwrap_or("single");
        let url_target = summarize_attachment_url_for_log(url);
        tracing::info!(
            msg_id = %inbound.msg_id,
            msg_type = %inbound.msg_type,
            chat_type = %inbound.chat_type,
            chat_id = %chat_id,
            sender_userid = %inbound.sender_userid,
            attachment_kind = %kind.as_str(),
            url_target = %url_target,
            has_aeskey = aeskey.is_some(),
            timeout_secs = WECOM_HTTP_TIMEOUT_SECS,
            "WeCom attachment download started"
        );

        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to download WeCom attachment: kind={} msg_id={} url_target={} elapsed_ms={}",
                    kind.as_str(),
                    inbound.msg_id,
                    url_target,
                    started.elapsed().as_millis(),
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let body_preview = truncate_for_log(&body, 512);
            anyhow::bail!(
                "WeCom attachment download failed: kind={} msg_id={} url_target={} status={} body_preview={}",
                kind.as_str(),
                inbound.msg_id,
                url_target,
                status,
                body_preview
            );
        }

        if let Some(len) = response.content_length() {
            if len > self.cfg.max_file_size_bytes {
                tracing::warn!(
                    msg_id = %inbound.msg_id,
                    attachment_kind = %kind.as_str(),
                    declared_bytes = len,
                    max_file_size_bytes = self.cfg.max_file_size_bytes,
                    "WeCom attachment skipped: declared size exceeds configured limit"
                );
                return Ok(format!(
                    "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                    kind, len, self.cfg.max_file_size_bytes
                ));
            }
        }

        let bytes = response
            .bytes()
            .await
            .with_context(|| {
                format!(
                    "failed to read WeCom attachment bytes: kind={} msg_id={} url_target={} elapsed_ms={}",
                    kind.as_str(),
                    inbound.msg_id,
                    url_target,
                    started.elapsed().as_millis(),
                )
            })?;

        if bytes.len() as u64 > self.cfg.max_file_size_bytes {
            tracing::warn!(
                msg_id = %inbound.msg_id,
                attachment_kind = %kind.as_str(),
                actual_bytes = bytes.len(),
                max_file_size_bytes = self.cfg.max_file_size_bytes,
                "WeCom attachment skipped: payload exceeds configured limit"
            );
            return Ok(format!(
                "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                kind,
                bytes.len(),
                self.cfg.max_file_size_bytes
            ));
        }

        // Decrypt if aeskey is present; otherwise use raw bytes
        let decrypted = match aeskey {
            Some(key) => MediaDecryptor::decrypt(key, &bytes).with_context(|| {
                format!(
                    "failed to decrypt WeCom attachment: kind={} msg_id={} url_target={} encrypted_bytes={}",
                    kind.as_str(),
                    inbound.msg_id,
                    url_target,
                    bytes.len(),
                )
            })?,
            None => bytes.to_vec(),
        };
        let decrypted_len = decrypted.len();

        let ext = match kind {
            AttachmentKind::Image => "png",
            AttachmentKind::File => "bin",
        };
        let safe_scope = normalize_scope_component(&format!(
            "{}_{}",
            inbound.chat_id.as_deref().unwrap_or("single"),
            inbound.sender_userid
        ));
        let ts = bytes_timestamp_now();
        let file_name = format!(
            "{safe_scope}_{ts}_{}_{}.{}",
            inbound.msg_id,
            random_ascii_token(6),
            ext
        );

        let dir = self.cfg.workspace_dir.join("wecom_ws_files");
        tokio::fs::create_dir_all(&dir).await.with_context(|| {
            format!(
                "failed to create WeCom inbox directory: msg_id={} path={}",
                inbound.msg_id,
                dir.display()
            )
        })?;
        let path = dir.join(file_name);

        tokio::fs::write(&path, decrypted).await.with_context(|| {
            format!(
                "failed to persist WeCom attachment: kind={} msg_id={} path={}",
                kind.as_str(),
                inbound.msg_id,
                path.display()
            )
        })?;

        self.maybe_cleanup_files();

        let abs = path.canonicalize().unwrap_or(path);
        tracing::info!(
            msg_id = %inbound.msg_id,
            attachment_kind = %kind.as_str(),
            url_target = %url_target,
            encrypted_bytes = bytes.len(),
            decrypted_bytes = decrypted_len,
            local_path = %abs.display(),
            elapsed_ms = started.elapsed().as_millis(),
            "WeCom attachment download completed"
        );
        match kind {
            AttachmentKind::Image => Ok(format!("[IMAGE:{}]", abs.display())),
            AttachmentKind::File => Ok(format!("[Document: {}]", abs.display())),
        }
    }

    async fn ws_send_scoped_message(
        &self,
        scope: &str,
        payload: Value,
        command: &str,
    ) -> Result<()> {
        let (chat_type, chatid) = parse_scope(scope)?;
        let req_id = random_ascii_token(16);
        let frame = serde_json::json!({
            "cmd": "aibot_send_msg",
            "headers": { "req_id": req_id },
            "body": {
                "chatid": chatid,
                "chat_type": chat_type,
            }
        });

        let mut frame = frame;
        frame["body"]
            .as_object_mut()
            .context("WeCom send message body must be an object")?
            .extend(
                payload
                    .as_object()
                    .context("WeCom send payload must be an object")?
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );

        self.ws_send_frame_and_wait_for_response(frame, &req_id, command)
            .await?;
        tracing::info!(scope = %scope, req_id = %req_id, command, "WeCom send ack received");
        Ok(())
    }

    async fn send_markdown_chunks_to_scope(&self, scope: &str, content: &str) -> Result<()> {
        let chunks = split_markdown_chunks(content);

        tracing::info!(
            "WeCom: sending message to scope={}, len={}, chunks={}",
            scope,
            content.len(),
            chunks.len()
        );

        let total_chunks = chunks.len();
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let chunk_len = chunk.len();
            self.ws_send_scoped_message(
                scope,
                serde_json::json!({
                    "msgtype": "markdown",
                    "markdown": { "content": chunk }
                }),
                "aibot_send_msg",
            )
            .await?;
            tracing::info!(
                scope = %scope,
                chunk_index = idx + 1,
                chunk_count = total_chunks,
                chunk_len,
                "WeCom markdown chunk delivered"
            );
        }

        Ok(())
    }

    /// Push an interactive template card to a conversation scope via `aibot_send_msg`.
    /// `card` is the raw WeCom `template_card` object (e.g. a `button_interaction` card).
    async fn send_template_card_to_scope(&self, scope: &str, card: Value) -> Result<()> {
        let payload = serde_json::json!({
            "msgtype": "template_card",
            "template_card": card,
        });
        self.ws_send_scoped_message(scope, payload, "aibot_send_msg")
            .await?;
        tracing::info!(scope = %scope, "WeCom template_card delivered");
        Ok(())
    }

    async fn prepare_outbound_attachments(
        &self,
        attachments: &[OutboundAttachment],
    ) -> Result<Vec<PreparedOutboundAttachment>> {
        let mut prepared = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            prepared.push(self.prepare_outbound_attachment(attachment).await?);
        }
        Ok(prepared)
    }

    async fn prepare_outbound_attachment(
        &self,
        attachment: &OutboundAttachment,
    ) -> Result<PreparedOutboundAttachment> {
        let resolved_path = self
            .resolve_outbound_attachment_path(&attachment.target)
            .await
            .with_context(|| {
                format!(
                    "failed to resolve WeCom outbound attachment target: {}",
                    attachment.target
                )
            })?;

        let metadata = tokio::fs::metadata(&resolved_path).await.with_context(|| {
            format!(
                "failed to stat WeCom outbound attachment: {}",
                resolved_path.display()
            )
        })?;
        if !metadata.is_file() {
            anyhow::bail!(
                "WeCom outbound attachment must be a file: {}",
                resolved_path.display()
            );
        }

        let bytes = tokio::fs::read(&resolved_path).await.with_context(|| {
            format!(
                "failed to read WeCom outbound attachment: {}",
                resolved_path.display()
            )
        })?;
        let max_bytes = attachment
            .kind
            .max_bytes()
            .min(usize::try_from(self.cfg.max_file_size_bytes).unwrap_or(usize::MAX));
        if bytes.len() < 5 {
            anyhow::bail!(
                "WeCom outbound attachment is too small: {} ({} bytes, minimum 5 bytes)",
                resolved_path.display(),
                bytes.len()
            );
        }
        if bytes.len() > max_bytes {
            anyhow::bail!(
                "WeCom outbound attachment exceeds size limit: {} ({} bytes > {} bytes for {})",
                resolved_path.display(),
                bytes.len(),
                max_bytes,
                attachment.kind.as_str()
            );
        }

        let filename = resolved_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("attachment-{}", random_ascii_token(8)));
        let filename = trim_utf8_to_max_bytes(&filename, 256);
        let md5_hex = format!("{:x}", md5_crate::compute(&bytes));

        Ok(PreparedOutboundAttachment {
            kind: attachment.kind,
            source_path: resolved_path,
            filename,
            bytes,
            md5_hex,
        })
    }

    async fn resolve_outbound_attachment_path(&self, target: &str) -> Result<PathBuf> {
        let candidate = target
            .trim()
            .trim_matches(|c| matches!(c, '`' | '"' | '\''));
        if candidate.is_empty() {
            anyhow::bail!("empty outbound attachment target");
        }
        if is_http_url(candidate) {
            anyhow::bail!("WeCom outbound attachments do not support remote URLs: {candidate}");
        }

        let candidate = candidate.strip_prefix("file://").unwrap_or(candidate);
        let resolved = if let Some(rel) = candidate.strip_prefix("/workspace/") {
            self.cfg.workspace_dir.join(rel)
        } else {
            PathBuf::from(candidate)
        };

        if !resolved.is_absolute() {
            anyhow::bail!(
                "WeCom outbound attachment path must be an absolute local path: {candidate}"
            );
        }

        tokio::fs::canonicalize(&resolved)
            .await
            .with_context(|| format!("attachment path not found: {}", resolved.display()))
    }

    async fn upload_media(&self, attachment: &PreparedOutboundAttachment) -> Result<String> {
        let total_size = attachment.bytes.len();
        let total_chunks = total_size.div_ceil(WECOM_MEDIA_UPLOAD_CHUNK_BYTES);
        if total_chunks == 0 || total_chunks > WECOM_MEDIA_UPLOAD_MAX_CHUNKS {
            anyhow::bail!(
                "WeCom outbound attachment exceeds chunk limit: {} ({} chunks > {})",
                attachment.source_path.display(),
                total_chunks,
                WECOM_MEDIA_UPLOAD_MAX_CHUNKS
            );
        }

        tracing::info!(
            path = %attachment.source_path.display(),
            kind = %attachment.kind.as_str(),
            size_bytes = total_size,
            total_chunks,
            "WeCom outbound attachment upload started"
        );

        let init_req_id = random_ascii_token(16);
        let init_response = self
            .ws_send_frame_and_wait_for_json_response(
                serde_json::json!({
                    "cmd": "aibot_upload_media_init",
                    "headers": { "req_id": init_req_id },
                    "body": {
                        "type": attachment.kind.as_str(),
                        "filename": attachment.filename.clone(),
                        "total_size": total_size,
                        "total_chunks": total_chunks,
                        "md5": attachment.md5_hex.clone(),
                    }
                }),
                &init_req_id,
                "aibot_upload_media_init",
            )
            .await?;
        let upload_id = init_response
            .pointer("/body/upload_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("WeCom upload init response missing body.upload_id")?;

        for (chunk_index, chunk) in attachment
            .bytes
            .chunks(WECOM_MEDIA_UPLOAD_CHUNK_BYTES)
            .enumerate()
        {
            let req_id = random_ascii_token(16);
            let base64_data = base64::engine::general_purpose::STANDARD.encode(chunk);
            self.ws_send_frame_and_wait_for_response(
                serde_json::json!({
                    "cmd": "aibot_upload_media_chunk",
                    "headers": { "req_id": req_id },
                    "body": {
                        "upload_id": upload_id,
                        "chunk_index": chunk_index,
                        "base64_data": base64_data,
                    }
                }),
                &req_id,
                "aibot_upload_media_chunk",
            )
            .await?;
        }

        let finish_req_id = random_ascii_token(16);
        let finish_response = self
            .ws_send_frame_and_wait_for_json_response(
                serde_json::json!({
                    "cmd": "aibot_upload_media_finish",
                    "headers": { "req_id": finish_req_id },
                    "body": {
                        "upload_id": upload_id,
                    }
                }),
                &finish_req_id,
                "aibot_upload_media_finish",
            )
            .await?;
        let media_id = finish_response
            .pointer("/body/media_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("WeCom upload finish response missing body.media_id")?
            .to_string();

        tracing::info!(
            path = %attachment.source_path.display(),
            kind = %attachment.kind.as_str(),
            media_id = %media_id,
            "WeCom outbound attachment upload completed"
        );

        Ok(media_id)
    }

    async fn send_uploaded_attachment_to_scope(
        &self,
        scope: &str,
        attachment: &PreparedOutboundAttachment,
        media_id: &str,
    ) -> Result<()> {
        let payload_key = attachment.kind.as_str();
        let mut payload = serde_json::json!({
            "msgtype": payload_key,
            (payload_key): {
                "media_id": media_id,
            }
        });
        if attachment.kind == OutboundAttachmentKind::Video {
            payload[payload_key]["title"] =
                Value::String(trim_utf8_to_max_bytes(&attachment.filename, 64));
        }

        self.ws_send_scoped_message(scope, payload, "aibot_send_msg")
            .await
            .with_context(|| {
                format!(
                    "failed to send WeCom outbound attachment: {}",
                    attachment.source_path.display()
                )
            })
    }

    async fn send_prepared_attachments_to_scope(
        &self,
        scope: &str,
        attachments: &[PreparedOutboundAttachment],
    ) -> Result<()> {
        for attachment in attachments {
            let media_id = self.upload_media(attachment).await?;
            self.send_uploaded_attachment_to_scope(scope, attachment, &media_id)
                .await?;
        }
        Ok(())
    }

    async fn send_final_content(
        &self,
        recipient: &str,
        req_id: Option<&str>,
        stream_id: Option<&str>,
        content: &str,
    ) -> Result<()> {
        // Strip `[CARD ...]` markers first so cards (like image attachments) are sent as separate
        // messages — WeCom does not allow a stream message to carry a template card.
        let (content_wo_cards, card_specs) = parse_card_markers(content);
        let (text, attachment_specs) = extract_outbound_attachments(&content_wo_cards);
        let prepared_attachments = self.prepare_outbound_attachments(&attachment_specs).await?;
        let has_extras = !prepared_attachments.is_empty() || !card_specs.is_empty();
        let text = if has_extras && text.trim().is_empty() {
            "\u{5df2}\u{53d1}\u{9001}".to_string()
        } else {
            text
        };

        if let Some(req_id) = req_id.filter(|req_id| !req_id.is_empty()) {
            let stream_id = stream_id.unwrap_or_else(|| unreachable!("stream id is required"));
            let (stream_content, overflow) = split_stream_content_and_overflow(&text);
            self.ws_send_respond_msg(req_id, stream_id, &stream_content, true)
                .await?;

            if let Some(extra) = overflow {
                let extra_msg = format!("[\u{8865}\u{5145}\u{6d88}\u{606f}]\n{extra}");
                self.send_markdown_chunks_to_scope(recipient, &extra_msg)
                    .await?;
            }
        } else {
            self.send_markdown_chunks_to_scope(recipient, &text).await?;
        }

        if !prepared_attachments.is_empty() {
            self.send_prepared_attachments_to_scope(recipient, &prepared_attachments)
                .await?;
        }

        for card in card_specs {
            self.send_template_card_to_scope(recipient, card).await?;
        }

        Ok(())
    }
}

// ── Channel trait impl ───────────────────────────────────────────────

#[async_trait]
impl Channel for WeComWsChannel {
    fn name(&self) -> &str {
        "wecom_ws"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        if let Some(req_id) = message
            .thread_ts
            .as_deref()
            .filter(|req_id| !req_id.is_empty())
        {
            if self.is_expired_stream_req_id(req_id) {
                return self
                    .send_final_content(&message.recipient, None, None, &message.content)
                    .await;
            }

            let stream_id = next_stream_id();
            return match self
                .send_final_content(
                    &message.recipient,
                    Some(req_id),
                    Some(&stream_id),
                    &message.content,
                )
                .await
            {
                Ok(()) => Ok(()),
                Err(err) if is_wecom_stream_update_expired_error(&err) => {
                    tracing::info!(
                        req_id,
                        stream_id = %stream_id,
                        "[wecom_ws] stream reply expired; falling back to standard message send"
                    );
                    self.expire_stream_req_id(req_id, Some(&stream_id)).await;
                    self.send_final_content(&message.recipient, None, None, &message.content)
                        .await
                }
                Err(err) => Err(err),
            };
        }

        self.send_final_content(&message.recipient, None, None, &message.content)
            .await
    }

    async fn listen(&self, tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        tracing::info!(
            "[wecom_ws] starting WebSocket listener (bot_id={})",
            self.bot_id
        );

        #[cfg(unix)]
        self.start_local_send_socket().await;

        let mut backoff = WECOM_BACKOFF_INITIAL_SECS;

        loop {
            tracing::info!("[wecom_ws] connecting to {WECOM_WS_URL}");

            let ws_stream = match tokio_tungstenite::connect_async(WECOM_WS_URL).await {
                Ok((stream, _)) => {
                    tracing::info!("[wecom_ws] WebSocket connected");
                    stream
                }
                Err(err) => {
                    tracing::warn!(
                        "[wecom_ws] WebSocket connect failed: {err:#}, retrying in {backoff}s"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(WECOM_BACKOFF_MAX_SECS);
                    continue;
                }
            };

            let (mut ws_write, mut ws_read) = ws_stream.split();

            // Send subscribe
            let subscribe_req_id = random_ascii_token(16);
            let subscribe = serde_json::json!({
                "cmd": "aibot_subscribe",
                "headers": { "req_id": subscribe_req_id },
                "body": {
                    "bot_id": self.bot_id,
                    "secret": self.secret,
                },
            });
            if let Err(err) = ws_write
                .send(WsMessage::Text(subscribe.to_string().into()))
                .await
            {
                tracing::warn!("[wecom_ws] subscribe send failed: {err:#}, retrying in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(WECOM_BACKOFF_MAX_SECS);
                continue;
            }

            // Wait for subscribe response
            let subscribe_ok = match tokio::time::timeout(
                Duration::from_secs(WECOM_SUBSCRIBE_TIMEOUT_SECS),
                ws_read.next(),
            )
            .await
            {
                Ok(Some(Ok(WsMessage::Text(text)))) => match serde_json::from_str::<Value>(&text) {
                    Ok(val) => {
                        if let Some(resp_req_id) = val
                            .get("headers")
                            .and_then(|h| h.get("req_id"))
                            .and_then(Value::as_str)
                        {
                            if resp_req_id != subscribe_req_id {
                                tracing::warn!(
                                    expected_req_id = %subscribe_req_id,
                                    got_req_id = %resp_req_id,
                                    "[wecom_ws] subscribe response req_id mismatch"
                                );
                            }
                        }
                        let errcode = val.get("errcode").and_then(Value::as_i64).unwrap_or(-1);
                        if errcode == 0 {
                            tracing::info!("[wecom_ws] subscribe succeeded");
                            true
                        } else {
                            let errmsg = val
                                .get("errmsg")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown");
                            tracing::error!(
                                "[wecom_ws] subscribe rejected: errcode={errcode} errmsg={errmsg}"
                            );
                            false
                        }
                    }
                    Err(err) => {
                        tracing::warn!("[wecom_ws] subscribe response parse failed: {err:#}");
                        false
                    }
                },
                Ok(Some(Ok(_))) => {
                    tracing::warn!("[wecom_ws] unexpected subscribe response frame type");
                    false
                }
                Ok(Some(Err(err))) => {
                    tracing::warn!("[wecom_ws] subscribe response read error: {err:#}");
                    false
                }
                Ok(None) => {
                    tracing::warn!("[wecom_ws] WebSocket closed before subscribe response");
                    false
                }
                Err(_) => {
                    tracing::warn!("[wecom_ws] subscribe response timeout");
                    false
                }
            };

            if !subscribe_ok {
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(WECOM_BACKOFF_MAX_SECS);
                continue;
            }

            // Create mpsc channel for outbound frames
            let (out_tx, mut out_rx) = mpsc::channel::<WsOutbound>(64);
            *self.ws_tx.lock().await = Some(out_tx);
            backoff = WECOM_BACKOFF_INITIAL_SECS; // reset on successful connect

            let mut ping_interval =
                tokio::time::interval(Duration::from_secs(WECOM_PING_INTERVAL_SECS));
            ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut should_reconnect = false;

            // Inner loop: process WS frames
            loop {
                tokio::select! {
                    _ = ping_interval.tick() => {
                        let ping_req_id = random_ascii_token(16);
                        self.register_heartbeat_req_id(&ping_req_id).await;
                        let ping = serde_json::json!({
                            "cmd": "ping",
                            "headers": { "req_id": ping_req_id },
                        });
                        if let Err(err) = ws_write
                            .send(WsMessage::Text(ping.to_string().into()))
                            .await
                        {
                            tracing::warn!("[wecom_ws] ping send failed: {err:#}");
                            break;
                        }
                    }
                    Some(outbound) = out_rx.recv() => {
                        match outbound {
                            WsOutbound::Frame(value) => {
                                if let Err(err) = ws_write
                                    .send(WsMessage::Text(value.to_string().into()))
                                    .await
                                {
                                    tracing::warn!(
                                        "[wecom_ws] outbound frame send failed: {err:#}"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    msg = ws_read.next() => {
                        match msg {
                            Some(Ok(WsMessage::Text(text))) => {
                                match serde_json::from_str::<Value>(&text) {
                                    Ok(frame) => {
                                        should_reconnect =
                                            self.handle_ws_message(frame, &tx).await;
                                        if should_reconnect {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            "[wecom_ws] WS frame parse error: {err:#}"
                                        );
                                    }
                                }
                            }
                            Some(Ok(WsMessage::Close(_))) => {
                                tracing::info!("[wecom_ws] WebSocket closed by server");
                                break;
                            }
                            Some(Ok(WsMessage::Pong(_) | _)) => {}
                            Some(Err(err)) => {
                                tracing::warn!("[wecom_ws] WS read error: {err:#}");
                                break;
                            }
                            None => {
                                tracing::info!("[wecom_ws] WebSocket stream ended");
                                break;
                            }
                        }
                    }
                }
            }

            // Disconnect cleanup
            *self.ws_tx.lock().await = None;
            self.fail_pending_responses("socket disconnected").await;

            if should_reconnect {
                // Server-initiated disconnect — reconnect quickly
                tracing::info!("[wecom_ws] disconnected (server event), reconnecting immediately");
                backoff = WECOM_BACKOFF_INITIAL_SECS;
            } else {
                tracing::info!("[wecom_ws] disconnected, will reconnect in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(WECOM_BACKOFF_MAX_SECS);
            }
        }
    }

    async fn health_check(&self) -> bool {
        self.ws_tx.lock().await.is_some()
    }

    fn supports_draft_updates(&self) -> bool {
        self.cfg.stream_mode != StreamMode::Off
    }

    async fn send_draft(&self, message: &SendMessage) -> Result<Option<String>> {
        if self.cfg.stream_mode == StreamMode::Off {
            return Ok(None);
        }

        // thread_ts carries the req_id from handle_msg_callback
        let req_id = message.thread_ts.as_deref().unwrap_or("");
        if req_id.is_empty() || self.is_expired_stream_req_id(req_id) {
            return Ok(None);
        }
        let stream_id = next_stream_id();
        self.req_id_map
            .lock()
            .insert(stream_id.clone(), req_id.to_string());
        self.draft_states
            .lock()
            .insert(stream_id.clone(), StreamDraftState::default());

        match self
            .ws_send_respond_msg(req_id, &stream_id, WECOM_STREAM_BOOTSTRAP_CONTENT, false)
            .await
        {
            Ok(()) => Ok(Some(stream_id)),
            Err(err) if is_wecom_stream_update_expired_error(&err) => {
                tracing::info!(
                    req_id,
                    stream_id = %stream_id,
                    "[wecom_ws] stream draft bootstrap expired; disabling streaming for this request"
                );
                self.expire_stream_req_id(req_id, Some(&stream_id)).await;
                Ok(None)
            }
            Err(err) => {
                self.req_id_map.lock().remove(&stream_id);
                self.clear_draft_state(&stream_id);
                Err(err)
            }
        }
    }

    async fn update_draft(&self, _recipient: &str, message_id: &str, content: &str) -> Result<()> {
        let req_id = self
            .req_id_map
            .lock()
            .get(message_id)
            .cloned()
            .unwrap_or_default();
        if req_id.is_empty() {
            self.clear_draft_state(message_id);
            return Ok(());
        }
        if self.is_expired_stream_req_id(&req_id) {
            self.req_id_map.lock().remove(message_id);
            self.clear_draft_state(message_id);
            return Ok(());
        }
        let Some(draft_content) = self.note_content_update(message_id, content) else {
            return Ok(());
        };
        if self.should_throttle_draft_edit(message_id) {
            return Ok(());
        }
        match self
            .ws_send_respond_msg(&req_id, message_id, &draft_content, false)
            .await
        {
            Ok(()) => {
                self.record_draft_edit(message_id);
                Ok(())
            }
            Err(err) if is_wecom_stream_update_expired_error(&err) => {
                tracing::info!(
                    req_id = %req_id,
                    stream_id = %message_id,
                    "[wecom_ws] stream draft update expired; stopping further draft writes"
                );
                self.expire_stream_req_id(&req_id, Some(message_id)).await;
                self.clear_draft_state(message_id);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn update_draft_progress(
        &self,
        _recipient: &str,
        message_id: &str,
        text: &str,
    ) -> Result<()> {
        let req_id = self
            .req_id_map
            .lock()
            .get(message_id)
            .cloned()
            .unwrap_or_default();
        if req_id.is_empty() {
            self.clear_draft_state(message_id);
            return Ok(());
        }
        if self.is_expired_stream_req_id(&req_id) {
            self.req_id_map.lock().remove(message_id);
            self.clear_draft_state(message_id);
            return Ok(());
        }

        let Some(draft_content) = self.note_progress_update(message_id, text) else {
            return Ok(());
        };
        if self.should_throttle_draft_edit(message_id) {
            return Ok(());
        }

        match self
            .ws_send_respond_msg(&req_id, message_id, &draft_content, false)
            .await
        {
            Ok(()) => {
                self.record_draft_edit(message_id);
                Ok(())
            }
            Err(err) if is_wecom_stream_update_expired_error(&err) => {
                tracing::info!(
                    req_id = %req_id,
                    stream_id = %message_id,
                    "[wecom_ws] stream draft progress expired; stopping further draft writes"
                );
                self.expire_stream_req_id(&req_id, Some(message_id)).await;
                self.clear_draft_state(message_id);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn finalize_draft(&self, recipient: &str, message_id: &str, content: &str) -> Result<()> {
        let content = if content.trim().is_empty() {
            "\u{26a0}\u{fe0f} LLM \u{8fd4}\u{56de}\u{4e86}\u{7a7a}\u{6587}\u{672c}\u{ff0c}\u{53ef}\u{80fd}\u{6267}\u{884c}\u{51fa}\u{9519}"
        } else {
            content
        };
        let req_id = self
            .req_id_map
            .lock()
            .get(message_id)
            .cloned()
            .unwrap_or_default();
        if req_id.is_empty() {
            self.req_id_map.lock().remove(message_id);
            self.clear_draft_state(message_id);
            return self
                .send_final_content(recipient, None, None, content)
                .await;
        }
        if self.is_expired_stream_req_id(&req_id) {
            self.req_id_map.lock().remove(message_id);
            self.clear_draft_state(message_id);
            return self
                .send_final_content(recipient, None, None, content)
                .await;
        }

        match self
            .send_final_content(recipient, Some(&req_id), Some(message_id), content)
            .await
        {
            Ok(()) => {
                self.req_id_map.lock().remove(message_id);
                self.clear_draft_state(message_id);
                Ok(())
            }
            Err(err) if is_wecom_stream_update_expired_error(&err) => {
                tracing::info!(
                    req_id = %req_id,
                    stream_id = %message_id,
                    "[wecom_ws] stream final reply expired; falling back to standard message send"
                );
                self.expire_stream_req_id(&req_id, Some(message_id)).await;
                self.clear_draft_state(message_id);
                self.send_final_content(recipient, None, None, content)
                    .await
            }
            Err(err) => {
                self.req_id_map.lock().remove(message_id);
                self.clear_draft_state(message_id);
                Err(err)
            }
        }
    }

    async fn cancel_draft(&self, _recipient: &str, message_id: &str) -> Result<()> {
        let req_id = self
            .req_id_map
            .lock()
            .get(message_id)
            .cloned()
            .unwrap_or_default();
        self.req_id_map.lock().remove(message_id);
        self.clear_draft_state(message_id);
        if req_id.is_empty() || self.is_expired_stream_req_id(&req_id) {
            return Ok(());
        }

        match self
            .ws_send_respond_msg(&req_id, message_id, "消息已中断", true)
            .await
        {
            Ok(()) => Ok(()),
            Err(err) if is_wecom_stream_update_expired_error(&err) => {
                tracing::info!(
                    req_id = %req_id,
                    stream_id = %message_id,
                    "[wecom_ws] stream cancel expired; nothing left to cancel"
                );
                self.expire_stream_req_id(&req_id, None).await;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────────

fn strip_wecom_padding(input: &[u8]) -> Result<&[u8]> {
    let Some(last) = input.last() else {
        anyhow::bail!("invalid WeCom padding: empty payload");
    };
    let pad_len = *last as usize;
    if pad_len == 0 || pad_len > 32 || pad_len > input.len() {
        anyhow::bail!("invalid WeCom padding length");
    }
    Ok(&input[..input.len() - pad_len])
}

fn is_wecom_data_version_conflict_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("errcode=6000") || msg.contains("data version conflict")
}

fn is_wecom_stream_update_expired_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("errcode=846608")
        || msg.contains("stream message update expired")
        || (msg.contains("cannot update") && msg.contains(">6 minutes"))
}

fn parse_inbound_payload(payload: Value) -> Result<ParsedInbound> {
    let msg_type = payload
        .get("msgtype")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if msg_type.is_empty() {
        anyhow::bail!("missing msgtype");
    }

    let msg_id = payload
        .get("msgid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let chat_type = payload
        .get("chattype")
        .and_then(Value::as_str)
        .unwrap_or("single")
        .to_string();

    let chat_id = payload
        .get("chatid")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let sender_userid = payload
        .get("from")
        .and_then(|v| v.get("userid"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let aibot_id = payload
        .get("aibotid")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    Ok(ParsedInbound {
        msg_id,
        msg_type,
        chat_type,
        chat_id,
        sender_userid,
        aibot_id,
        raw_payload: payload,
    })
}

fn compute_scopes(inbound: &ParsedInbound) -> ScopeDecision {
    let chat_type = inbound.chat_type.to_ascii_lowercase();
    if chat_type == "group" {
        let chat_id = inbound
            .chat_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let scope = format!("group--{chat_id}");
        return ScopeDecision {
            conversation_scope: scope,
            shared_group_history: true,
        };
    }

    let scope = format!("user--{}", inbound.sender_userid);
    ScopeDecision {
        conversation_scope: scope,
        shared_group_history: false,
    }
}

fn normalize_wecom_identity(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_wecom_allowlist(entries: Vec<String>) -> Vec<String> {
    entries
        .into_iter()
        .map(|entry| normalize_wecom_identity(&entry))
        .filter(|entry| !entry.is_empty())
        .collect()
}

fn allowlist_matches(allowlist: &[String], candidate: &str) -> bool {
    let candidate = normalize_wecom_identity(candidate);
    !candidate.is_empty()
        && allowlist
            .iter()
            .any(|entry| entry == "*" || entry == &candidate)
}

fn evaluate_access_decision(
    allowed_users: &[String],
    allowed_groups: &[String],
    inbound: &ParsedInbound,
) -> AccessDecision {
    if allowed_users.is_empty() && allowed_groups.is_empty() {
        return AccessDecision::AllowlistMissing;
    }

    if allowlist_matches(allowed_users, &inbound.sender_userid) {
        return AccessDecision::Allowed;
    }

    if inbound.chat_type.eq_ignore_ascii_case("group")
        && inbound
            .chat_id
            .as_deref()
            .is_some_and(|chat_id| allowlist_matches(allowed_groups, chat_id))
    {
        return AccessDecision::Allowed;
    }

    AccessDecision::Denied
}

fn build_access_denied_message(inbound: &ParsedInbound, decision: AccessDecision) -> String {
    let userid = normalize_wecom_identity(&inbound.sender_userid);
    let userid = if userid.is_empty() {
        "unknown"
    } else {
        userid.as_str()
    };

    if inbound.chat_type.eq_ignore_ascii_case("group") {
        let chatid = inbound
            .chat_id
            .as_deref()
            .map(normalize_wecom_identity)
            .filter(|chatid| !chatid.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        return match decision {
            AccessDecision::AllowlistMissing => format!(
                "管理员尚未配置 WeCom allowlist，当前机器人不接收任何群消息。\n\n群 chatid: {chatid}\n发送者 userid: {userid}\n\n请在 channels_config.wecom_ws.allowed_groups 或 channels_config.wecom_ws.allowed_users 中加入允许项，也可以临时设置为 [\"*\"] 进行测试。"
            ),
            AccessDecision::Denied => format!(
                "当前群未被允许使用此机器人。\n\n群 chatid: {chatid}\n发送者 userid: {userid}\n\n请管理员将该群加入 channels_config.wecom_ws.allowed_groups，或将你的 userid 加入 channels_config.wecom_ws.allowed_users。"
            ),
            AccessDecision::Allowed => String::new(),
        };
    }

    match decision {
        AccessDecision::AllowlistMissing => format!(
            "管理员尚未配置 WeCom allowlist，当前机器人不接收任何消息。\n\n你的 userid: {userid}\n\n请在 channels_config.wecom_ws.allowed_users 中加入允许项，也可以临时设置为 [\"*\"] 进行测试。"
        ),
        AccessDecision::Denied => format!(
            "你没有权限使用此机器人。\n\n你的 userid: {userid}\n\n请管理员将你的 userid 加入 channels_config.wecom_ws.allowed_users。"
        ),
        AccessDecision::Allowed => String::new(),
    }
}

/// Map WeCom inbound identity to the framework sender field.
///
/// For group chats we deliberately collapse sender to the conversation scope so
/// the existing framework history key logic naturally becomes group-shared.
fn framework_sender_identity(inbound: &ParsedInbound, scopes: &ScopeDecision) -> String {
    if scopes.shared_group_history {
        scopes.conversation_scope.clone()
    } else {
        inbound.sender_userid.clone()
    }
}

/// Compose content for framework: quote context (if any) + normalized user text,
/// then inject local timestamp and optional sender marker directly at the
/// channel boundary so no framework-wide WeCom-specific prompt/history logic is needed.
fn compose_content_for_framework(
    inbound: &ParsedInbound,
    scopes: &ScopeDecision,
    normalized: &str,
) -> String {
    let quote_context = extract_quote_context(&inbound.raw_payload);
    let base = match quote_context {
        Some(quote) => format!("{quote}\n\n{normalized}"),
        None => normalized.to_string(),
    };

    let now = Local::now().format("%Y-%m-%d %H:%M:%S %Z");
    let timestamped = format!("[{now}] {base}");

    if scopes.shared_group_history && !inbound.sender_userid.trim().is_empty() {
        format!("[sender_userid={}] {timestamped}", inbound.sender_userid)
    } else {
        timestamped
    }
}

fn normalize_scope_component(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// Parse scope string into (chat_type, chatid) for aibot_send_msg.
/// `user--{userid}` → (1, userid), `group--{chatid}` → (2, chatid)
fn parse_scope(scope: &str) -> Result<(u32, &str)> {
    if let Some(userid) = scope.strip_prefix("user--") {
        Ok((1, userid))
    } else if let Some(chatid) = scope.strip_prefix("group--") {
        Ok((2, chatid))
    } else {
        anyhow::bail!("WeCom: invalid scope format: {scope}")
    }
}

fn summarize_attachment_url_for_log(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return "empty-url".to_string();
    }
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or("unknown-host");
            let query_state = if parsed.query().is_some() {
                "query=present"
            } else {
                "query=none"
            };
            format!(
                "{}://{}{} ({query_state})",
                parsed.scheme(),
                host,
                parsed.path()
            )
        }
        Err(_) => format!("invalid-url(len={})", trimmed.len()),
    }
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let prefix: String = input.chars().take(max_chars).collect();
    format!("{prefix}...(truncated)")
}

fn log_attachment_processing_failure(
    stage: &str,
    err: &anyhow::Error,
    inbound: &ParsedInbound,
    kind: AttachmentKind,
    url: &str,
) {
    tracing::warn!(
        msg_id = %inbound.msg_id,
        msg_type = %inbound.msg_type,
        chat_type = %inbound.chat_type,
        chat_id = %inbound.chat_id.as_deref().unwrap_or("single"),
        sender_userid = %inbound.sender_userid,
        attachment_kind = %kind.as_str(),
        url_target = %summarize_attachment_url_for_log(url),
        error = %format_args!("{err:#}"),
        "{stage}"
    );
}

fn random_emoji() -> &'static str {
    let idx = rand::rng().random_range(0..WECOM_EMOJIS.len());
    WECOM_EMOJIS[idx]
}

fn random_ascii_token(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = String::with_capacity(len);
    let mut rng = rand::rng();
    for _ in 0..len {
        let idx = rng.random_range(0..CHARSET.len());
        out.push(CHARSET[idx] as char);
    }
    out
}

fn next_stream_id() -> String {
    format!("zs_{}", random_ascii_token(20))
}

#[cfg(unix)]
fn absolute_log_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn is_stop_runtime_command(text: &str) -> bool {
    let stripped = strip_edge_mentions(text);
    if stripped.is_empty() {
        return false;
    }

    let command_token = stripped.split_whitespace().next().unwrap_or("");
    let base_command = command_token.split('@').next().unwrap_or(command_token);
    base_command.eq_ignore_ascii_case("/stop")
}

fn is_clear_session_command(text: &str) -> bool {
    let stripped = strip_edge_mentions(text);
    if stripped.is_empty() {
        return false;
    }

    let mut parts = stripped.split_whitespace();
    let command_token = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return false;
    }

    let base_command = command_token.split('@').next().unwrap_or(command_token);
    base_command.eq_ignore_ascii_case("/clear") || base_command.eq_ignore_ascii_case("/new")
}

fn extract_runtime_routing_command(text: &str) -> Option<String> {
    let stripped = strip_edge_mentions(text);
    if stripped.is_empty() || !stripped.starts_with('/') {
        return None;
    }

    let command_token = stripped.split_whitespace().next()?;
    let base_command = command_token.split('@').next().unwrap_or(command_token);
    if base_command.eq_ignore_ascii_case("/model")
        || base_command.eq_ignore_ascii_case("/models")
        || base_command.eq_ignore_ascii_case("/config")
    {
        Some(stripped)
    } else {
        None
    }
}

pub(crate) fn strip_edge_mentions(text: &str) -> String {
    let s = text.trim();
    if s.is_empty() {
        return String::new();
    }

    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut start = 0usize;
    loop {
        while start < len && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        if start >= len || bytes[start] != b'@' {
            break;
        }
        start += 1;
        while start < len && !bytes[start].is_ascii_whitespace() {
            start += 1;
        }
    }

    let mut end = len;
    loop {
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if end <= start {
            break;
        }
        let mut probe = end;
        while probe > start && !bytes[probe - 1].is_ascii_whitespace() && bytes[probe - 1] != b'@' {
            probe -= 1;
        }
        if probe > start && bytes[probe - 1] == b'@' {
            end = probe - 1;
        } else {
            break;
        }
    }

    s[start..end].trim().to_string()
}

fn extract_stop_signal_text(inbound: &ParsedInbound) -> Option<String> {
    match inbound.msg_type.as_str() {
        "text" => inbound
            .raw_payload
            .get("text")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned),
        "voice" => inbound
            .raw_payload
            .get("voice")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned),
        "mixed" => {
            let mut texts = Vec::new();
            let items = inbound
                .raw_payload
                .get("mixed")
                .and_then(|v| v.get("msg_item"))
                .and_then(Value::as_array)?;
            for item in items {
                if item
                    .get("msgtype")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v == "text")
                {
                    if let Some(content) = item
                        .get("text")
                        .and_then(|v| v.get("content"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        texts.push(content.to_string());
                    }
                }
            }
            if texts.is_empty() {
                None
            } else {
                Some(texts.join("\n"))
            }
        }
        _ => None,
    }
}

fn inbound_content_preview(inbound: &ParsedInbound) -> String {
    if let Some(text) = extract_stop_signal_text(inbound) {
        return text;
    }

    match inbound.msg_type.as_str() {
        "image" => "[Image message]".to_string(),
        "file" => inbound
            .raw_payload
            .get("file")
            .and_then(|v| v.get("filename"))
            .and_then(Value::as_str)
            .map(|name| format!("[File message: {name}]"))
            .unwrap_or_else(|| "[File message]".to_string()),
        "event" => "[Event callback]".to_string(),
        other => format!("[{other} message]"),
    }
}

fn trim_utf8_to_max_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut out = String::new();
    for ch in input.chars() {
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

fn normalize_stream_content(input: &str) -> String {
    trim_utf8_to_max_bytes(input, WECOM_MARKDOWN_MAX_BYTES)
}

fn split_stream_content_and_overflow(input: &str) -> (String, Option<String>) {
    if input.len() <= WECOM_MARKDOWN_MAX_BYTES {
        return (input.to_string(), None);
    }

    let mut head = String::new();
    let mut tail = String::new();
    let mut overflow = false;
    for ch in input.chars() {
        if !overflow && head.len() + ch.len_utf8() <= WECOM_MARKDOWN_MAX_BYTES {
            head.push(ch);
        } else {
            overflow = true;
            tail.push(ch);
        }
    }

    if tail.is_empty() {
        (head, None)
    } else {
        (head, Some(tail))
    }
}

fn find_matching_close(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_http_url(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://")
}

fn parse_attachment_markers(message: &str) -> (String, Vec<OutboundAttachment>) {
    let mut cleaned = String::with_capacity(message.len());
    let mut attachments = Vec::new();
    let mut cursor = 0usize;

    while cursor < message.len() {
        let Some(open_rel) = message[cursor..].find('[') else {
            cleaned.push_str(&message[cursor..]);
            break;
        };

        let open = cursor + open_rel;
        cleaned.push_str(&message[cursor..open]);

        let Some(close_rel) = find_matching_close(&message[open + 1..]) else {
            cleaned.push_str(&message[open..]);
            break;
        };

        let close = open + 1 + close_rel;
        let marker = &message[open + 1..close];
        let parsed = marker.split_once(':').and_then(|(kind, target)| {
            let kind = OutboundAttachmentKind::from_marker(kind)?;
            let target = target.trim();
            if target.is_empty() {
                return None;
            }
            Some(OutboundAttachment {
                kind,
                target: target.to_string(),
            })
        });

        if let Some(attachment) = parsed {
            attachments.push(attachment);
        } else {
            cleaned.push_str(&message[open..=close]);
        }
        cursor = close + 1;
    }

    (cleaned.trim().to_string(), attachments)
}

fn parse_path_only_attachment_hint(message: &str) -> Option<OutboundAttachment> {
    let trimmed = message.trim();
    if trimmed.is_empty() || trimmed.contains('\n') {
        return None;
    }

    let candidate = trimmed.trim_matches(|c| matches!(c, '`' | '"' | '\''));
    if candidate.chars().any(char::is_whitespace) {
        return None;
    }
    if is_http_url(candidate) {
        return None;
    }

    let candidate = candidate.strip_prefix("file://").unwrap_or(candidate);
    if !Path::new(candidate).is_absolute() {
        return None;
    }

    Some(OutboundAttachment {
        kind: OutboundAttachmentKind::infer_from_target(candidate),
        target: candidate.to_string(),
    })
}

/// Maximum buttons WeCom allows on a `button_interaction` template card.
const WECOM_CARD_MAX_BUTTONS: usize = 6;

/// Parse `[CARD ...]` markers emitted by the model into ready-to-send `template_card` objects,
/// returning the message with those markers stripped. Mirrors `parse_attachment_markers`, so the
/// card is delivered as a separate `aibot_send_msg` after the (streamed) text — WeCom does not
/// allow combining a stream message with a template card.
///
/// Grammar: `[CARD title=... | desc=... | task_id=... | btn=<text>:<event_key> | btn=...]`
/// Fields are `|`-separated `key=value`; `btn` repeats (1..=6). `btn` value splits on the FIRST
/// `:` so an event key may itself contain `:` (e.g. `town:static`).
fn parse_card_markers(message: &str) -> (String, Vec<Value>) {
    let mut cleaned = String::with_capacity(message.len());
    let mut cards = Vec::new();
    let mut cursor = 0usize;

    while cursor < message.len() {
        let Some(open_rel) = message[cursor..].find('[') else {
            cleaned.push_str(&message[cursor..]);
            break;
        };
        let open = cursor + open_rel;
        cleaned.push_str(&message[cursor..open]);

        let Some(close_rel) = find_matching_close(&message[open + 1..]) else {
            cleaned.push_str(&message[open..]);
            break;
        };
        let close = open + 1 + close_rel;
        let marker = &message[open + 1..close];

        match parse_card_marker_body(marker) {
            Some(card) => cards.push(card),
            None => cleaned.push_str(&message[open..=close]),
        }
        cursor = close + 1;
    }

    (cleaned.trim().to_string(), cards)
}

fn parse_card_marker_body(marker: &str) -> Option<Value> {
    let rest = marker.trim();
    let rest = rest
        .strip_prefix("CARD")
        .or_else(|| rest.strip_prefix("card"))?;
    let rest = rest.trim_start();

    let mut title: Option<String> = None;
    let mut desc: Option<String> = None;
    let mut task_id: Option<String> = None;
    let mut buttons: Vec<(String, String)> = Vec::new();

    for field in rest.split('|') {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "title" => title = Some(value.to_string()),
            "desc" => desc = Some(value.to_string()),
            "task_id" => task_id = Some(sanitize_card_task_id(value)),
            "btn" | "button" => {
                if let Some((text, event_key)) = value.split_once(':') {
                    let text = text.trim();
                    let event_key = event_key.trim();
                    if !text.is_empty() && !event_key.is_empty() {
                        buttons.push((text.to_string(), event_key.to_string()));
                    }
                }
            }
            _ => {}
        }
    }

    // A button_interaction card needs at least one button and a title or desc.
    if buttons.is_empty() || (title.is_none() && desc.is_none()) {
        return None;
    }
    buttons.truncate(WECOM_CARD_MAX_BUTTONS);

    let mut main_title = serde_json::Map::new();
    if let Some(t) = title {
        main_title.insert("title".to_string(), Value::String(t));
    }
    if let Some(d) = desc {
        main_title.insert("desc".to_string(), Value::String(d));
    }

    let button_list: Vec<Value> = buttons
        .into_iter()
        .map(|(text, key)| serde_json::json!({ "text": text, "style": 1, "key": key }))
        .collect();

    let task_id = task_id.unwrap_or_else(|| format!("llmcard-{}", random_ascii_token(12)));

    Some(serde_json::json!({
        "card_type": "button_interaction",
        "main_title": Value::Object(main_title),
        "task_id": task_id,
        "button_list": button_list,
    }))
}

/// Keep only WeCom-legal `task_id` characters (`[A-Za-z0-9_-@]`, <=128 bytes).
fn sanitize_card_task_id(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '@'))
        .take(128)
        .collect();
    if s.is_empty() {
        format!("llmcard-{}", random_ascii_token(12))
    } else {
        s
    }
}

fn extract_outbound_attachments(message: &str) -> (String, Vec<OutboundAttachment>) {
    let (cleaned, attachments) = parse_attachment_markers(message);
    if !attachments.is_empty() {
        return (cleaned, attachments);
    }

    if let Some(attachment) = parse_path_only_attachment_hint(message) {
        return (String::new(), vec![attachment]);
    }

    (message.to_string(), Vec::new())
}

fn retain_latest_lines(content: &str, max_lines: usize) -> String {
    if content.is_empty() || max_lines == 0 {
        return String::new();
    }

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() <= max_lines {
        return content.to_string();
    }

    lines[lines.len() - max_lines..].join("\n")
}

fn render_work_log(content: &str) -> String {
    sanitize_outbound_draft_content(&retain_latest_lines(content, WECOM_DRAFT_UPDATE_MAX_LINES))
}

fn sanitize_outbound_draft_content(content: &str) -> String {
    let (cleaned, attachments) = extract_outbound_attachments(content);
    if attachments.is_empty() {
        content.to_string()
    } else if cleaned.trim().is_empty() {
        WECOM_STREAM_BOOTSTRAP_CONTENT.to_string()
    } else {
        cleaned
    }
}

fn parse_event_type(payload: &Value) -> Option<String> {
    payload
        .get("event")
        .and_then(|v| v.get("eventtype"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_template_card_event_key(payload: &Value) -> Option<String> {
    payload
        .get("event")
        .and_then(|v| v.get("template_card_event"))
        .and_then(|v| {
            v.get("event_key")
                .or_else(|| v.get("eventkey"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

/// Whether a template-card `event_key` may trigger the configured exec bridge.
/// Empty allowlist denies all; a single `"*"` entry allows any key.
fn card_event_key_allowed(allowed_keys: &[String], event_key: &str) -> bool {
    allowed_keys.iter().any(|k| k == "*" || k == event_key)
}

fn extract_template_card_event_task_id(payload: &Value) -> Option<String> {
    payload
        .get("event")
        .and_then(|v| v.get("template_card_event"))
        .and_then(|v| {
            v.get("task_id")
                .or_else(|| v.get("taskid"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_feedback_event_summary(payload: &Value) -> Option<String> {
    let feedback = payload.get("event")?.get("feedback_event")?;
    let feedback_id = feedback
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("-");
    let feedback_type = feedback
        .get("type")
        .and_then(Value::as_i64)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let content = feedback
        .get("content")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("-");
    Some(format!(
        "feedback_id={feedback_id} feedback_type={feedback_type} content={content}"
    ))
}

fn extract_quote_context(payload: &Value) -> Option<String> {
    let quote = payload.get("quote")?;
    let quote_type = quote
        .get("msgtype")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())?;

    let content = match quote_type {
        "text" => quote
            .get("text")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "[\u{5f15}\u{7528}\u{6587}\u{672c}\u{4e3a}\u{7a7a}]".to_string()),
        "voice" => quote
            .get("voice")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[\u{5f15}\u{7528}\u{8bed}\u{97f3}\u{8f6c}\u{5199}] {v}"))
            .unwrap_or_else(|| {
                "[\u{5f15}\u{7528}\u{8bed}\u{97f3}\u{65e0}\u{8f6c}\u{5199}]".to_string()
            }),
        "image" => quote
            .get("image")
            .and_then(|v| v.get("local_path"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[\u{5f15}\u{7528}\u{56fe}\u{7247}] {v}"))
            .unwrap_or_else(|| "[\u{5f15}\u{7528}\u{56fe}\u{7247}]".to_string()),
        "file" => quote
            .get("file")
            .and_then(|v| v.get("local_path"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[\u{5f15}\u{7528}\u{6587}\u{4ef6}] {v}"))
            .unwrap_or_else(|| "[\u{5f15}\u{7528}\u{6587}\u{4ef6}]".to_string()),
        "mixed" => {
            let mut parts = Vec::new();
            if let Some(items) = quote
                .get("mixed")
                .and_then(|v| v.get("msg_item"))
                .and_then(Value::as_array)
            {
                for item in items {
                    let item_type = item
                        .get("msgtype")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if item_type == "text" {
                        if let Some(text) = item
                            .get("text")
                            .and_then(|v| v.get("content"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            parts.push(text.to_string());
                        }
                    } else if item_type == "image" {
                        if let Some(path) = item
                            .get("image")
                            .and_then(|v| v.get("local_path"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            parts.push(format!("[\u{5f15}\u{7528}\u{56fe}\u{7247}] {path}"));
                        } else {
                            parts.push("[\u{5f15}\u{7528}\u{56fe}\u{7247}]".to_string());
                        }
                    }
                }
            }

            if parts.is_empty() {
                "[\u{5f15}\u{7528}\u{56fe}\u{6587}\u{6d88}\u{606f}]".to_string()
            } else {
                parts.join("\n")
            }
        }
        _ => format!("[\u{5f15}\u{7528}\u{6d88}\u{606f} type={quote_type}]"),
    };

    let content = trim_utf8_to_max_bytes(&content, 4_096);
    Some(format!(
        "[WECOM_QUOTE]\nmsgtype={quote_type}\ncontent={content}\n[/WECOM_QUOTE]"
    ))
}

fn bytes_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn split_markdown_chunks(input: &str) -> Vec<String> {
    if input.is_empty() {
        return vec![String::new()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();

    for line in input.lines() {
        let candidate = if current.is_empty() {
            line.to_string()
        } else {
            format!("{current}\n{line}")
        };

        if candidate.len() > WECOM_MARKDOWN_CHUNK_BYTES
            && !current.is_empty()
            && current.len() <= WECOM_MARKDOWN_MAX_BYTES
        {
            chunks.push(current);
            current = line.to_string();
            continue;
        }

        current = candidate;
    }

    if !current.is_empty() {
        if current.len() <= WECOM_MARKDOWN_MAX_BYTES {
            chunks.push(current);
        } else {
            let mut buf = String::new();
            for ch in current.chars() {
                if buf.len() + ch.len_utf8() > WECOM_MARKDOWN_CHUNK_BYTES {
                    chunks.push(buf);
                    buf = String::new();
                }
                buf.push(ch);
            }
            if !buf.is_empty() {
                chunks.push(buf);
            }
        }
    }

    if chunks.is_empty() {
        chunks.push(String::new());
    }

    chunks
}

fn is_model_supported_msgtype(msg_type: &str) -> bool {
    matches!(msg_type, "text" | "voice" | "image" | "file" | "mixed")
}

fn is_voice_without_transcript(inbound: &ParsedInbound) -> bool {
    if inbound.msg_type != "voice" {
        return false;
    }
    inbound
        .raw_payload
        .get("voice")
        .and_then(|v| v.get("content"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
}

async fn cleanup_inbox_files(root: PathBuf, retention: Duration) {
    if !root.exists() {
        return;
    }

    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else {
            continue;
        };

        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let Ok(meta) = entry.metadata().await else {
                continue;
            };

            if meta.is_dir() {
                stack.push(path);
                continue;
            }

            let Ok(modified) = meta.modified() else {
                continue;
            };

            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or_else(|_| Duration::from_secs(0));
            if age > retention {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
