use super::{run_gateway_chat_with_tools, AppState};
use aes::Aes256;
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::Engine as _;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5 as md5_crate;
use parking_lot::Mutex;
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const WECOM_RESPONSE_URL_TTL_SECS: u64 = 3600;
const WECOM_MARKDOWN_MAX_BYTES: usize = 20_480;
const WECOM_MARKDOWN_CHUNK_BYTES: usize = 8_000;
const WECOM_EMOJIS: &[&str] = &["🙂", "😄", "🤝", "🚀", "👌"];
const WECOM_HISTORY_WINDOW_TURNS: usize = 12;
const WECOM_FILE_CLEANUP_INTERVAL_SECS: u64 = 1800;
const WECOM_STREAM_STATE_TTL_SECS: u64 = 7200;
const WECOM_CONVERSATION_TTL_SECS: u64 = 172_800;
const WECOM_HTTP_TIMEOUT_SECS: u64 = 60;
const WECOM_STREAM_BOOTSTRAP_CONTENT: &str = "正在处理中，请稍候。";
const WECOM_STREAM_MAX_IMAGES: usize = 10;
const WECOM_IMAGE_MAX_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(super) struct WeComCallbackQuery {
    pub msg_signature: String,
    pub timestamp: String,
    pub nonce: String,
    pub echostr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WeComEncryptedEnvelope {
    encrypt: String,
}

#[derive(Clone)]
struct WeComRuntime {
    cfg: WeComRuntimeConfig,
    crypto: WeComCrypto,
    client: reqwest::Client,
    response_urls: Arc<Mutex<HashMap<String, VecDeque<ResponseUrlEntry>>>>,
    execution_locks: Arc<Mutex<HashMap<String, ExecutionLockEntry>>>,
    inflight_tasks: Arc<Mutex<HashMap<String, InflightTaskEntry>>>,
    stream_states: Arc<Mutex<HashMap<String, StreamState>>>,
    conversations: Arc<Mutex<HashMap<String, ConversationState>>>,
    last_cleanup: Arc<Mutex<Instant>>,
    fingerprint: String,
}

#[derive(Clone)]
struct WeComRuntimeConfig {
    workspace_dir: PathBuf,
    group_shared_history_enabled: bool,
    group_shared_history_chat_ids: Vec<String>,
    file_retention_days: u32,
    max_file_size_bytes: u64,
    response_url_cache_per_scope: usize,
    lock_timeout_secs: u64,
    history_max_turns: usize,
    fallback_robot_webhook_url: Option<String>,
}

#[derive(Debug, Clone)]
struct WeComCrypto {
    token: String,
    key: [u8; 32],
}

#[derive(Debug, Clone)]
struct ParsedInbound {
    msg_id: String,
    msg_type: String,
    chat_type: String,
    chat_id: Option<String>,
    sender_userid: String,
    aibot_id: String,
    response_url: Option<String>,
    raw_payload: Value,
}

#[derive(Debug, Clone)]
struct ScopeDecision {
    conversation_scope: String,
    execution_scope: String,
    shared_group_history: bool,
}

#[derive(Debug, Clone)]
struct ResponseUrlEntry {
    url: String,
    expires_at: Instant,
    received_at: Instant,
    msg_id: String,
}

#[derive(Debug, Clone)]
struct ExecutionLockEntry {
    owner_msg_id: String,
    stream_id: String,
    expires_at: Instant,
}

struct InflightTaskEntry {
    owner_msg_id: String,
    stream_id: String,
    expires_at: Instant,
    handle: JoinHandle<()>,
}

#[derive(Debug, Clone)]
struct StreamState {
    execution_scope: String,
    conversation_scope: String,
    owner_msg_id: String,
    content: String,
    finish: bool,
    images: Vec<StreamImageItem>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct StreamImageItem {
    base64: String,
    md5: String,
}

#[derive(Debug, Clone)]
struct ConversationState {
    static_injected: bool,
    turns: VecDeque<ConversationTurn>,
    last_active_at: Instant,
}

#[derive(Debug, Clone)]
struct ConversationTurn {
    role: TurnRole,
    content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TurnRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentKind {
    Image,
    File,
}

#[derive(Debug, Clone)]
struct ComposedInput {
    user_message_for_model: String,
    user_turn_for_history: String,
}

#[derive(Debug)]
enum NormalizedMessage {
    Ready(String),
    VoiceMissingTranscript,
    Unsupported,
}

impl Default for ConversationState {
    fn default() -> Self {
        Self {
            static_injected: false,
            turns: VecDeque::new(),
            last_active_at: Instant::now(),
        }
    }
}

fn runtime_store() -> &'static Mutex<HashMap<String, Arc<WeComRuntime>>> {
    static STORE: OnceLock<Mutex<HashMap<String, Arc<WeComRuntime>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime_key(state: &AppState) -> String {
    state
        .config
        .lock()
        .config_path
        .to_string_lossy()
        .to_string()
}

fn normalize_scope_component(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':' {
                ch
            } else {
                '_'
            }
        })
        .collect()
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

fn contains_stop_command(text: &str) -> bool {
    text.contains("停止") || text.to_ascii_lowercase().contains("stop")
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
                    {
                        let trimmed = content.trim();
                        if !trimmed.is_empty() {
                            texts.push(trimmed.to_string());
                        }
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

fn trim_utf8_to_max_bytes(input: &str, max_bytes: usize) -> String {
    if input.as_bytes().len() <= max_bytes {
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
    if input.as_bytes().len() <= WECOM_MARKDOWN_MAX_BYTES {
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

fn parse_image_markers(text: &str) -> (String, Vec<String>) {
    let mut cleaned = String::new();
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("[IMAGE:") {
        cleaned.push_str(&rest[..start]);
        let after_tag = &rest[start + 7..]; // skip "[IMAGE:"
        if let Some(end) = after_tag.find(']') {
            let path = after_tag[..end].trim();
            if !path.is_empty() {
                paths.push(path.to_string());
            }
            rest = &after_tag[end + 1..];
        } else {
            // No closing bracket — keep the text as-is
            cleaned.push_str(&rest[start..start + 7]);
            rest = after_tag;
        }
    }
    cleaned.push_str(rest);
    // Trim excessive blank lines left by removed markers
    let cleaned = cleaned
        .lines()
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    (cleaned, paths)
}

async fn prepare_stream_images(paths: &[String]) -> Vec<StreamImageItem> {
    let mut items = Vec::new();
    for path_str in paths.iter().take(WECOM_STREAM_MAX_IMAGES) {
        let path = Path::new(path_str);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(ext.as_str(), "jpg" | "jpeg" | "png") {
            tracing::warn!(
                "WeCom stream image skipped (unsupported extension): {}",
                path_str
            );
            continue;
        }
        let data = match tokio::fs::read(path).await {
            Ok(d) => d,
            Err(err) => {
                tracing::warn!("WeCom stream image read failed: {} — {err:#}", path_str);
                continue;
            }
        };
        if data.len() > WECOM_IMAGE_MAX_BYTES {
            tracing::warn!(
                "WeCom stream image skipped (too large: {} bytes): {}",
                data.len(),
                path_str
            );
            continue;
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let digest = md5_crate::compute(&data);
        let md5_hex = format!("{:x}", digest);
        items.push(StreamImageItem {
            base64: b64,
            md5: md5_hex,
        });
    }
    items
}

fn make_stream_payload(
    stream_id: &str,
    content: &str,
    finish: bool,
    images: &[StreamImageItem],
) -> Value {
    let mut stream_obj = serde_json::json!({
        "id": stream_id,
        "finish": finish,
        "content": normalize_stream_content(content),
    });
    if finish && !images.is_empty() {
        let msg_items: Vec<Value> = images
            .iter()
            .map(|img| {
                serde_json::json!({
                    "msgtype": "image",
                    "image": {
                        "base64": img.base64,
                        "md5": img.md5,
                    }
                })
            })
            .collect();
        stream_obj["msg_item"] = Value::Array(msg_items);
    }
    serde_json::json!({
        "msgtype": "stream",
        "stream": stream_obj,
    })
}

fn make_text_payload(content: &str) -> Value {
    serde_json::json!({
        "msgtype": "text",
        "text": {
            "content": content,
        }
    })
}

fn parse_stream_id(payload: &Value) -> Option<String> {
    payload
        .get("stream")
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
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
            .unwrap_or_else(|| "[引用文本为空]".to_string()),
        "voice" => quote
            .get("voice")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[引用语音转写] {v}"))
            .unwrap_or_else(|| "[引用语音无转写]".to_string()),
        "image" => quote
            .get("image")
            .and_then(|v| v.get("local_path"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[引用图片] {v}"))
            .unwrap_or_else(|| "[引用图片]".to_string()),
        "file" => quote
            .get("file")
            .and_then(|v| v.get("local_path"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| format!("[引用文件] {v}"))
            .unwrap_or_else(|| "[引用文件]".to_string()),
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
                            parts.push(format!("[引用图片] {path}"));
                        } else {
                            parts.push("[引用图片]".to_string());
                        }
                    }
                }
            }

            if parts.is_empty() {
                "[引用图文消息]".to_string()
            } else {
                parts.join("\n")
            }
        }
        _ => format!("[引用消息 type={quote_type}]"),
    };

    let content = trim_utf8_to_max_bytes(&content, 4_096);
    Some(format!(
        "[WECOM_QUOTE]\nmsgtype={quote_type}\ncontent={content}\n[/WECOM_QUOTE]"
    ))
}

fn parse_wecom_business_response(body: &str) -> Result<()> {
    let parsed: Value = serde_json::from_str(body).context("invalid WeCom response json")?;
    let errcode = parsed
        .get("errcode")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("missing errcode in WeCom response"))?;
    if errcode != 0 {
        let errmsg = parsed
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        anyhow::bail!("errcode={errcode} errmsg={errmsg}");
    }
    Ok(())
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

fn is_valid_robot_webhook_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };

    parsed.scheme() == "https"
        && parsed
            .host_str()
            .map(|host| host.eq_ignore_ascii_case("qyapi.weixin.qq.com"))
            .unwrap_or(false)
        && parsed.path().starts_with("/cgi-bin/webhook/send")
}

fn wecom_static_context(
    inbound: &ParsedInbound,
    scopes: &ScopeDecision,
    include_sender: bool,
) -> String {
    let chat_id = inbound.chat_id.as_deref().unwrap_or("-");
    let mut lines = vec![
        "[WECOM_STATIC_CONTEXT_V1]".to_string(),
        format!("chat_type={}", inbound.chat_type),
        format!("chat_id={chat_id}"),
        format!("conversation_scope={}", scopes.conversation_scope),
        format!("execution_scope={}", scopes.execution_scope),
        format!("aibot_id={}", inbound.aibot_id),
        format!(
            "push_url_memory_key=wecom_push_url::{}",
            scopes.conversation_scope
        ),
        "push_url_set_hint=When user asks to configure proactive push, call memory_store with push_url_memory_key and store a valid WeCom robot webhook URL."
            .to_string(),
    ];

    if include_sender {
        lines.push(format!("sender_userid={}", inbound.sender_userid));
    }

    lines.push("[/WECOM_STATIC_CONTEXT_V1]".to_string());
    lines.join("\n")
}

fn wecom_turn_context(inbound: &ParsedInbound) -> String {
    [
        "[WECOM_TURN_CONTEXT_V1]".to_string(),
        format!("sender_userid={}", inbound.sender_userid),
        format!("msg_id={}", inbound.msg_id),
        "[/WECOM_TURN_CONTEXT_V1]".to_string(),
    ]
    .join("\n")
}

fn bytes_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_turn_history(turns: &[ConversationTurn]) -> String {
    if turns.is_empty() {
        return String::new();
    }

    let mut out = String::from("[WECOM_HISTORY]\n");
    for turn in turns {
        match turn.role {
            TurnRole::User => {
                out.push_str("User: ");
                out.push_str(&turn.content);
                out.push_str("\n\n");
            }
            TurnRole::Assistant => {
                out.push_str("Assistant: ");
                out.push_str(&turn.content);
                out.push_str("\n\n");
            }
        }
    }
    out.push_str("[/WECOM_HISTORY]\n");
    out
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

        if candidate.as_bytes().len() > WECOM_MARKDOWN_CHUNK_BYTES
            && !current.is_empty()
            && current.as_bytes().len() <= WECOM_MARKDOWN_MAX_BYTES
        {
            chunks.push(current);
            current = line.to_string();
            continue;
        }

        current = candidate;
    }

    if !current.is_empty() {
        if current.as_bytes().len() <= WECOM_MARKDOWN_MAX_BYTES {
            chunks.push(current);
        } else {
            // Hard split by char boundary when a single line is too long.
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

impl WeComCrypto {
    fn new(token: &str, encoding_aes_key: &str) -> Result<Self> {
        let padded = format!("{}=", encoding_aes_key.trim());
        let raw = base64::engine::general_purpose::STANDARD
            .decode(padded)
            .context("failed to decode WeCom EncodingAESKey")?;
        if raw.len() != 32 {
            anyhow::bail!("invalid WeCom EncodingAESKey length: expected 32 bytes");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);

        Ok(Self {
            token: token.trim().to_string(),
            key,
        })
    }

    fn verify_signature(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
        encrypt: &str,
    ) -> bool {
        let mut parts = vec![
            self.token.as_str(),
            timestamp.trim(),
            nonce.trim(),
            encrypt.trim(),
        ];
        parts.sort_unstable();

        let mut sha = Sha1::new();
        sha.update(parts.join(""));
        let expected = hex::encode(sha.finalize());
        expected.eq_ignore_ascii_case(msg_signature.trim())
    }

    fn encrypt_json_ciphertext(
        &self,
        plaintext: &str,
        nonce: &str,
        timestamp: &str,
        receive_id: &str,
    ) -> Result<String> {
        let plaintext_bytes = plaintext.as_bytes();
        if plaintext_bytes.len() > (u32::MAX as usize) {
            anyhow::bail!("WeCom plaintext payload too large");
        }

        let mut raw = Vec::with_capacity(plaintext_bytes.len() + receive_id.len() + 64);
        raw.extend_from_slice(random_ascii_token(16).as_bytes());
        raw.extend_from_slice(&(plaintext_bytes.len() as u32).to_be_bytes());
        raw.extend_from_slice(plaintext_bytes);
        raw.extend_from_slice(receive_id.as_bytes());

        let pad_len = 32 - (raw.len() % 32);
        let actual_pad = if pad_len == 0 { 32 } else { pad_len };
        raw.extend(vec![actual_pad as u8; actual_pad]);

        let iv = &self.key[..16];
        let mut buf = raw.clone();
        let encrypted = cbc::Encryptor::<Aes256>::new((&self.key).into(), iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, raw.len())
            .context("failed to encrypt WeCom response payload")?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted);

        let mut parts = vec![
            self.token.as_str(),
            timestamp.trim(),
            nonce.trim(),
            &encrypted_b64,
        ];
        parts.sort_unstable();
        let mut sha = Sha1::new();
        sha.update(parts.join(""));
        let signature = hex::encode(sha.finalize());

        let envelope = serde_json::json!({
            "encrypt": encrypted_b64,
            "msgsignature": signature,
            "timestamp": timestamp.trim(),
            "nonce": nonce.trim(),
        });
        Ok(envelope.to_string())
    }

    fn decrypt_json_ciphertext(&self, encrypt: &str, receive_id: &str) -> Result<String> {
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encrypt.trim())
            .context("failed to decode WeCom ciphertext")?;

        let iv = &self.key[..16];
        let mut buf = ciphertext.clone();
        let plaintext = cbc::Decryptor::<Aes256>::new((&self.key).into(), iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .context("failed to decrypt WeCom ciphertext")?;

        let unpadded = strip_wecom_padding(plaintext)?;
        if unpadded.len() < 20 {
            anyhow::bail!("decrypted WeCom payload is too short");
        }

        let msg_len =
            u32::from_be_bytes([unpadded[16], unpadded[17], unpadded[18], unpadded[19]]) as usize;
        let msg_start = 20usize;
        let msg_end = msg_start.saturating_add(msg_len);
        if msg_end > unpadded.len() {
            anyhow::bail!("decrypted WeCom payload length is invalid");
        }

        let msg = std::str::from_utf8(&unpadded[msg_start..msg_end])
            .context("decrypted WeCom payload is not utf-8")?
            .to_string();
        let from_receive_id = std::str::from_utf8(&unpadded[msg_end..])
            .context("decrypted WeCom receive_id is not utf-8")?;

        if from_receive_id != receive_id {
            anyhow::bail!("wecom receive_id mismatch");
        }

        Ok(msg)
    }

    fn decrypt_file_payload(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let iv = &self.key[..16];
        let mut buf = encrypted.to_vec();
        let plaintext = cbc::Decryptor::<Aes256>::new((&self.key).into(), iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .context("failed to decrypt WeCom attachment")?;
        Ok(strip_wecom_padding(plaintext)?.to_vec())
    }
}

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

    let response_url = payload
        .get("response_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(ToOwned::to_owned);

    Ok(ParsedInbound {
        msg_id,
        msg_type,
        chat_type,
        chat_id,
        sender_userid,
        aibot_id,
        response_url,
        raw_payload: payload,
    })
}

fn compute_scopes(cfg: &WeComRuntimeConfig, inbound: &ParsedInbound) -> ScopeDecision {
    let chat_type = inbound.chat_type.to_ascii_lowercase();
    if chat_type == "group" {
        let chat_id = inbound
            .chat_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let is_shared = cfg.group_shared_history_enabled
            && cfg
                .group_shared_history_chat_ids
                .iter()
                .any(|value| value == &chat_id);

        if is_shared {
            let scope = format!("group:{chat_id}");
            return ScopeDecision {
                conversation_scope: scope.clone(),
                execution_scope: scope,
                shared_group_history: true,
            };
        }

        let scope = format!("group:{chat_id}:user:{}", inbound.sender_userid);
        return ScopeDecision {
            conversation_scope: scope.clone(),
            execution_scope: scope,
            shared_group_history: false,
        };
    }

    let scope = format!("user:{}", inbound.sender_userid);
    ScopeDecision {
        conversation_scope: scope.clone(),
        execution_scope: scope,
        shared_group_history: false,
    }
}

impl WeComRuntime {
    fn from_config(cfg: &crate::config::WeComConfig, workspace_dir: &Path) -> Result<Self> {
        let crypto = WeComCrypto::new(&cfg.token, &cfg.encoding_aes_key)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(WECOM_HTTP_TIMEOUT_SECS))
            .build()
            .context("failed to initialize WeCom HTTP client")?;

        let normalized_fallback = cfg
            .fallback_robot_webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(ToOwned::to_owned);

        let fingerprint = format!(
            "{}|{}|{}|{}",
            cfg.token,
            cfg.encoding_aes_key,
            cfg.group_shared_history_enabled,
            normalized_fallback.as_deref().unwrap_or("")
        );

        Ok(Self {
            cfg: WeComRuntimeConfig {
                workspace_dir: workspace_dir.to_path_buf(),
                group_shared_history_enabled: cfg.group_shared_history_enabled,
                group_shared_history_chat_ids: cfg.group_shared_history_chat_ids.clone(),
                file_retention_days: cfg.file_retention_days,
                max_file_size_bytes: cfg.max_file_size_mb.saturating_mul(1024 * 1024),
                response_url_cache_per_scope: cfg.response_url_cache_per_scope.max(1),
                lock_timeout_secs: cfg.lock_timeout_secs.max(30),
                history_max_turns: cfg.history_max_turns.max(2),
                fallback_robot_webhook_url: normalized_fallback,
            },
            crypto,
            client,
            response_urls: Arc::new(Mutex::new(HashMap::new())),
            execution_locks: Arc::new(Mutex::new(HashMap::new())),
            inflight_tasks: Arc::new(Mutex::new(HashMap::new())),
            stream_states: Arc::new(Mutex::new(HashMap::new())),
            conversations: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
            fingerprint,
        })
    }

    fn cache_response_url(&self, scope: &str, msg_id: &str, url: Option<&str>) {
        let Some(url) = url.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(WECOM_RESPONSE_URL_TTL_SECS);

        let mut cache = self.response_urls.lock();
        let queue = cache.entry(scope.to_string()).or_default();
        queue.push_back(ResponseUrlEntry {
            url: url.to_string(),
            expires_at,
            received_at: now,
            msg_id: msg_id.to_string(),
        });

        while queue.len() > self.cfg.response_url_cache_per_scope {
            queue.pop_front();
        }
    }

    fn take_next_response_url(&self, scope: &str) -> Option<ResponseUrlEntry> {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        let queue = cache.get_mut(scope)?;

        queue.retain(|entry| entry.expires_at > now);
        if queue.is_empty() {
            return None;
        }

        let mut idx = 0usize;
        for i in 1..queue.len() {
            if queue[i].expires_at < queue[idx].expires_at {
                idx = i;
            }
        }

        queue.remove(idx)
    }

    fn prune_response_urls(&self) {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        cache.retain(|_, queue| {
            queue.retain(|entry| entry.expires_at > now);
            !queue.is_empty()
        });
    }

    fn prune_execution_locks(&self) {
        let now = Instant::now();
        let mut locks = self.execution_locks.lock();
        locks.retain(|_, lock| lock.expires_at > now);
    }

    fn is_execution_locked(&self, execution_scope: &str) -> bool {
        self.prune_execution_locks();
        self.execution_locks.lock().contains_key(execution_scope)
    }

    fn try_acquire_execution_lock(
        &self,
        execution_scope: &str,
        msg_id: &str,
        stream_id: &str,
    ) -> bool {
        self.prune_execution_locks();
        let now = Instant::now();
        let mut locks = self.execution_locks.lock();

        if locks.contains_key(execution_scope) {
            return false;
        }

        locks.insert(
            execution_scope.to_string(),
            ExecutionLockEntry {
                owner_msg_id: msg_id.to_string(),
                stream_id: stream_id.to_string(),
                expires_at: now + Duration::from_secs(self.cfg.lock_timeout_secs),
            },
        );
        true
    }

    fn release_execution_lock(&self, execution_scope: &str, msg_id: &str) {
        let mut locks = self.execution_locks.lock();
        if locks
            .get(execution_scope)
            .is_some_and(|lock| lock.owner_msg_id == msg_id)
        {
            locks.remove(execution_scope);
        }
    }

    fn force_release_execution_lock(&self, execution_scope: &str) {
        self.execution_locks.lock().remove(execution_scope);
    }

    fn current_stream_id_for_scope(&self, execution_scope: &str) -> Option<String> {
        self.prune_execution_locks();
        self.execution_locks
            .lock()
            .get(execution_scope)
            .map(|entry| entry.stream_id.clone())
    }

    fn register_inflight_task(
        &self,
        execution_scope: &str,
        owner_msg_id: &str,
        stream_id: &str,
        handle: JoinHandle<()>,
    ) {
        self.prune_inflight_tasks();
        self.inflight_tasks.lock().insert(
            execution_scope.to_string(),
            InflightTaskEntry {
                owner_msg_id: owner_msg_id.to_string(),
                stream_id: stream_id.to_string(),
                expires_at: Instant::now() + Duration::from_secs(self.cfg.lock_timeout_secs),
                handle,
            },
        );
    }

    fn prune_inflight_tasks(&self) {
        let now = Instant::now();
        let mut inflight = self.inflight_tasks.lock();
        let stale_scopes: Vec<String> = inflight
            .iter()
            .filter(|(_, task)| task.expires_at <= now || task.handle.is_finished())
            .map(|(scope, _)| scope.clone())
            .collect();

        for scope in stale_scopes {
            if let Some(task) = inflight.remove(&scope) {
                if !task.handle.is_finished() {
                    task.handle.abort();
                }
            }
        }
    }

    fn clear_inflight_task_if_owner(&self, execution_scope: &str, owner_msg_id: &str) {
        let mut inflight = self.inflight_tasks.lock();
        if inflight
            .get(execution_scope)
            .is_some_and(|entry| entry.owner_msg_id == owner_msg_id)
        {
            inflight.remove(execution_scope);
        }
    }

    fn abort_inflight_task(&self, execution_scope: &str) -> Option<String> {
        self.prune_inflight_tasks();
        let task = self.inflight_tasks.lock().remove(execution_scope)?;
        let stream_id = task.stream_id;
        task.handle.abort();
        Some(stream_id)
    }

    fn upsert_stream_state(
        &self,
        stream_id: &str,
        execution_scope: &str,
        conversation_scope: &str,
        owner_msg_id: &str,
        content: &str,
        finish: bool,
        images: Vec<StreamImageItem>,
    ) {
        let mut states = self.stream_states.lock();
        states.insert(
            stream_id.to_string(),
            StreamState {
                execution_scope: execution_scope.to_string(),
                conversation_scope: conversation_scope.to_string(),
                owner_msg_id: owner_msg_id.to_string(),
                content: normalize_stream_content(content),
                finish,
                images,
                expires_at: Instant::now() + Duration::from_secs(WECOM_STREAM_STATE_TTL_SECS),
            },
        );
    }

    fn update_stream_state_content(&self, stream_id: &str, content: &str, finish: bool) {
        let mut states = self.stream_states.lock();
        if let Some(state) = states.get_mut(stream_id) {
            state.content = normalize_stream_content(content);
            state.finish = finish;
            state.images = Vec::new();
            state.expires_at = Instant::now() + Duration::from_secs(WECOM_STREAM_STATE_TTL_SECS);
        }
    }

    fn update_stream_state_with_images(
        &self,
        stream_id: &str,
        content: &str,
        finish: bool,
        images: Vec<StreamImageItem>,
    ) {
        let mut states = self.stream_states.lock();
        if let Some(state) = states.get_mut(stream_id) {
            state.content = normalize_stream_content(content);
            state.finish = finish;
            state.images = images;
            state.expires_at = Instant::now() + Duration::from_secs(WECOM_STREAM_STATE_TTL_SECS);
        }
    }

    fn get_stream_state(&self, stream_id: &str) -> Option<StreamState> {
        self.prune_stream_states();
        self.stream_states.lock().get(stream_id).cloned()
    }

    fn prune_stream_states(&self) {
        let now = Instant::now();
        self.stream_states
            .lock()
            .retain(|_, state| state.expires_at > now);
    }

    fn snapshot_conversation(&self, scope: &str) -> ConversationState {
        let mut conversations = self.conversations.lock();
        if let Some(state) = conversations.get_mut(scope) {
            state.last_active_at = Instant::now();
            return state.clone();
        }
        ConversationState::default()
    }

    fn upsert_conversation(
        &self,
        scope: &str,
        static_injected: bool,
        user_turn: &str,
        assistant_turn: &str,
    ) {
        let mut conversations = self.conversations.lock();
        let state = conversations.entry(scope.to_string()).or_default();
        state.static_injected = state.static_injected || static_injected;
        state.last_active_at = Instant::now();

        state.turns.push_back(ConversationTurn {
            role: TurnRole::User,
            content: user_turn.to_string(),
        });
        state.turns.push_back(ConversationTurn {
            role: TurnRole::Assistant,
            content: assistant_turn.to_string(),
        });

        while state.turns.len() > self.cfg.history_max_turns {
            state.turns.pop_front();
        }
    }

    fn prune_conversations(&self) {
        let now = Instant::now();
        let retention = Duration::from_secs(WECOM_CONVERSATION_TTL_SECS);
        self.conversations
            .lock()
            .retain(|_, state| now.duration_since(state.last_active_at) <= retention);
    }

    async fn maybe_cleanup_files(&self) {
        self.prune_response_urls();
        self.prune_execution_locks();
        self.prune_inflight_tasks();
        self.prune_stream_states();
        self.prune_conversations();

        let now = Instant::now();
        {
            let mut last = self.last_cleanup.lock();
            if now.duration_since(*last) < Duration::from_secs(WECOM_FILE_CLEANUP_INTERVAL_SECS) {
                return;
            }
            *last = now;
        }

        let retention = Duration::from_secs((self.cfg.file_retention_days as u64) * 86_400);
        let root = self.cfg.workspace_dir.join("wecom_files");
        tokio::spawn(async move {
            cleanup_inbox_files(root, retention).await;
        });
    }

    async fn materialize_quote_attachments(&self, inbound: &mut ParsedInbound) {
        let quote_type = inbound
            .raw_payload
            .get("quote")
            .and_then(|v| v.get("msgtype"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");

        if quote_type == "image" {
            let quote_url = inbound
                .raw_payload
                .get("quote")
                .and_then(|v| v.get("image"))
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
            if let Some(url) = quote_url {
                let marker = match self
                    .download_and_store_attachment(&url, AttachmentKind::Image, inbound)
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!("WeCom quote image processing failed: {err}");
                        "[引用图片下载失败]".to_string()
                    }
                };
                if let Some(quote) = inbound.raw_payload.get_mut("quote") {
                    quote["image"] = serde_json::json!({ "local_path": marker });
                }
            }
            return;
        }

        if quote_type == "file" {
            let quote_url = inbound
                .raw_payload
                .get("quote")
                .and_then(|v| v.get("file"))
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
            if let Some(url) = quote_url {
                let marker = match self
                    .download_and_store_attachment(&url, AttachmentKind::File, inbound)
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!("WeCom quote file processing failed: {err}");
                        "[引用文件下载失败]".to_string()
                    }
                };
                if let Some(quote) = inbound.raw_payload.get_mut("quote") {
                    quote["file"] = serde_json::json!({ "local_path": marker });
                }
            }
            return;
        }

        if quote_type == "mixed" {
            let quote_images: Vec<(usize, String)> = inbound
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
                            item.get("image")
                                .and_then(|v| v.get("url"))
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .map(|url| (idx, url.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();

            if quote_images.is_empty() {
                return;
            }

            let mut results: Vec<(usize, String)> = Vec::with_capacity(quote_images.len());
            for (idx, url) in quote_images {
                let marker = match self
                    .download_and_store_attachment(&url, AttachmentKind::Image, inbound)
                    .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!("WeCom quote mixed image processing failed: {err}");
                        "[引用图片下载失败]".to_string()
                    }
                };
                results.push((idx, marker));
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
                let url = inbound
                    .raw_payload
                    .get("image")
                    .and_then(|v| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();

                if url.is_empty() {
                    return NormalizedMessage::Unsupported;
                }

                match self
                    .download_and_store_attachment(url, AttachmentKind::Image, inbound)
                    .await
                {
                    Ok(marker) => NormalizedMessage::Ready(marker),
                    Err(err) => {
                        tracing::warn!("WeCom image processing failed: {err}");
                        NormalizedMessage::Ready(
                            "[Image attachment processing failed; please continue without this image.]"
                                .to_string(),
                        )
                    }
                }
            }
            "file" => {
                let url = inbound
                    .raw_payload
                    .get("file")
                    .and_then(|v| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();

                if url.is_empty() {
                    return NormalizedMessage::Unsupported;
                }

                match self
                    .download_and_store_attachment(url, AttachmentKind::File, inbound)
                    .await
                {
                    Ok(marker) => NormalizedMessage::Ready(marker),
                    Err(err) => {
                        tracing::warn!("WeCom file processing failed: {err}");
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
                            if let Some(url) = item
                                .get("image")
                                .and_then(|v| v.get("url"))
                                .and_then(Value::as_str)
                            {
                                match self
                                    .download_and_store_attachment(
                                        url,
                                        AttachmentKind::Image,
                                        inbound,
                                    )
                                    .await
                                {
                                    Ok(marker) => text_parts.push(marker),
                                    Err(err) => {
                                        tracing::warn!(
                                            "WeCom mixed image processing failed: {err}"
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
            _ => NormalizedMessage::Unsupported,
        }
    }

    async fn download_and_store_attachment(
        &self,
        url: &str,
        kind: AttachmentKind,
        inbound: &ParsedInbound,
    ) -> Result<String> {
        if self.cfg.max_file_size_bytes == 0 {
            anyhow::bail!("WeCom max_file_size_bytes is zero");
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("failed to download WeCom attachment")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "WeCom attachment download failed: status={} body={body}",
                status
            );
        }

        if let Some(len) = response.content_length() {
            if len > self.cfg.max_file_size_bytes {
                return Ok(format!(
                    "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                    kind, len, self.cfg.max_file_size_bytes
                ));
            }
        }

        let bytes = response
            .bytes()
            .await
            .context("failed to read WeCom attachment bytes")?;

        if bytes.len() as u64 > self.cfg.max_file_size_bytes {
            return Ok(format!(
                "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                kind,
                bytes.len(),
                self.cfg.max_file_size_bytes
            ));
        }

        let decrypted = self.crypto.decrypt_file_payload(&bytes)?;

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

        let dir = self.cfg.workspace_dir.join("wecom_files");
        tokio::fs::create_dir_all(&dir)
            .await
            .context("failed to create WeCom inbox directory")?;
        let path = dir.join(file_name);

        tokio::fs::write(&path, decrypted)
            .await
            .context("failed to persist WeCom attachment")?;

        self.maybe_cleanup_files().await;

        let abs = path.canonicalize().unwrap_or(path);
        match kind {
            AttachmentKind::Image => Ok(format!("[IMAGE:{}]", abs.display())),
            AttachmentKind::File => Ok(format!("[Document: {}]", abs.display())),
        }
    }

    fn compose_input(
        &self,
        inbound: &ParsedInbound,
        scopes: &ScopeDecision,
        normalized: &str,
        prior: &ConversationState,
    ) -> ComposedInput {
        let mut blocks: Vec<String> = Vec::new();
        let include_sender_in_static = !scopes.shared_group_history;
        let quote_context = extract_quote_context(&inbound.raw_payload);

        if !prior.static_injected {
            blocks.push(wecom_static_context(
                inbound,
                scopes,
                include_sender_in_static,
            ));
        }

        let history_slice: Vec<ConversationTurn> = prior
            .turns
            .iter()
            .rev()
            .take(WECOM_HISTORY_WINDOW_TURNS)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        if !history_slice.is_empty() {
            blocks.push(format_turn_history(&history_slice));
        }

        if scopes.shared_group_history {
            blocks.push(wecom_turn_context(inbound));
        }

        if let Some(quote) = quote_context.as_deref() {
            blocks.push(quote.to_string());
        }
        blocks.push(normalized.to_string());

        let mut user_turn_for_history = normalized.to_string();
        if let Some(quote) = quote_context.as_deref() {
            user_turn_for_history = format!("{quote}\n{user_turn_for_history}");
        }
        if scopes.shared_group_history {
            user_turn_for_history =
                format!("[{}] {}", inbound.sender_userid, user_turn_for_history);
        }

        let payload = blocks.join("\n\n");
        ComposedInput {
            user_message_for_model: payload,
            user_turn_for_history,
        }
    }

    async fn send_markdown_to_url(&self, url: &str, content: &str) -> Result<()> {
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "content": content,
            }
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to send WeCom markdown")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("WeCom markdown send failed: status={} body={body}", status);
        }
        if let Err(err) = parse_wecom_business_response(&body) {
            anyhow::bail!("WeCom markdown send business failed: {err}; body={body}");
        }

        Ok(())
    }

    async fn lookup_scope_push_url(&self, state: &AppState, scope: &str) -> Option<String> {
        let key = format!("wecom_push_url::{scope}");
        let entry = state.mem.get(&key).await.ok().flatten()?;
        let candidate = entry.content.trim();
        if is_valid_robot_webhook_url(candidate) {
            Some(candidate.to_string())
        } else {
            None
        }
    }

    async fn send_text_with_fallbacks(&self, state: &AppState, scope: &str, text: &str) {
        let chunks = split_markdown_chunks(text);

        for chunk in chunks {
            let mut sent = false;

            while let Some(entry) = self.take_next_response_url(scope) {
                match self.send_markdown_to_url(&entry.url, &chunk).await {
                    Ok(()) => {
                        sent = true;
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "WeCom response_url send failed for msg_id={} age_ms={}: {}",
                            entry.msg_id,
                            entry.received_at.elapsed().as_millis(),
                            err
                        );
                    }
                }
            }

            if sent {
                continue;
            }

            if let Some(scope_push_url) = self.lookup_scope_push_url(state, scope).await {
                if let Err(err) = self.send_markdown_to_url(&scope_push_url, &chunk).await {
                    tracing::warn!("WeCom scope push webhook send failed: {err}");
                } else {
                    sent = true;
                }
            }

            if sent {
                continue;
            }

            if let Some(fallback) = self.cfg.fallback_robot_webhook_url.as_deref() {
                if is_valid_robot_webhook_url(fallback) {
                    let tagged = format!("[FallbackPush] {chunk}");
                    if let Err(err) = self.send_markdown_to_url(fallback, &tagged).await {
                        tracing::warn!("WeCom fallback push webhook send failed: {err}");
                    } else {
                        sent = true;
                    }
                }
            }

            if !sent {
                tracing::warn!(
                    "WeCom outbound dropped: no usable response_url or push webhook for scope={scope}"
                );
            }
        }
    }
}

fn resolve_runtime(state: &AppState) -> Result<Option<Arc<WeComRuntime>>> {
    let cfg_guard = state.config.lock();
    let Some(wecom_cfg) = cfg_guard.channels_config.wecom.as_ref() else {
        return Ok(None);
    };

    let runtime_key = runtime_key(state);
    let candidate = WeComRuntime::from_config(wecom_cfg, &cfg_guard.workspace_dir)?;

    let mut store = runtime_store().lock();
    if let Some(existing) = store.get(&runtime_key) {
        if existing.fingerprint == candidate.fingerprint {
            return Ok(Some(existing.clone()));
        }
    }

    let runtime = Arc::new(candidate);
    store.insert(runtime_key, runtime.clone());
    Ok(Some(runtime))
}

pub(super) async fn handle_wecom_verify(
    State(state): State<AppState>,
    Query(query): Query<WeComCallbackQuery>,
) -> impl IntoResponse {
    let runtime = match resolve_runtime(&state) {
        Ok(Some(runtime)) => runtime,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "WeCom not configured"})),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!("WeCom runtime init failed: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "WeCom runtime init failed"})),
            )
                .into_response();
        }
    };

    let Some(echostr) = query.echostr.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing echostr"})),
        )
            .into_response();
    };

    if !runtime.crypto.verify_signature(
        &query.msg_signature,
        &query.timestamp,
        &query.nonce,
        echostr,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    match runtime.crypto.decrypt_json_ciphertext(echostr, "") {
        Ok(plain) => (StatusCode::OK, plain).into_response(),
        Err(err) => {
            tracing::warn!("WeCom URL verify decrypt failed: {err}");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "decrypt failed"})),
            )
                .into_response()
        }
    }
}

pub(super) async fn handle_wecom_callback(
    State(state): State<AppState>,
    Query(query): Query<WeComCallbackQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let runtime = match resolve_runtime(&state) {
        Ok(Some(runtime)) => runtime,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "WeCom not configured"})),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!("WeCom runtime init failed: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "WeCom runtime init failed"})),
            )
                .into_response();
        }
    };

    let envelope = match serde_json::from_slice::<WeComEncryptedEnvelope>(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid encrypted payload"})),
            )
                .into_response();
        }
    };

    if !runtime.crypto.verify_signature(
        &query.msg_signature,
        &query.timestamp,
        &query.nonce,
        &envelope.encrypt,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    let plaintext = match runtime
        .crypto
        .decrypt_json_ciphertext(&envelope.encrypt, "")
    {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!("WeCom callback decrypt failed: {err}");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "decrypt failed"})),
            )
                .into_response();
        }
    };

    let payload: Value = match serde_json::from_str(&plaintext) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid callback json"})),
            )
                .into_response();
        }
    };

    let parsed = match parse_inbound_payload(payload) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!("WeCom callback parse failed: {err}");
            return (StatusCode::OK, "success".to_string()).into_response();
        }
    };

    if parsed.msg_type != "stream" && !parsed.msg_id.is_empty() {
        let key = format!("wecom_msg_{}", parsed.msg_id);
        if !state.idempotency_store.record_if_new(&key) {
            return (StatusCode::OK, "success".to_string()).into_response();
        }
    }

    let scopes = compute_scopes(&runtime.cfg, &parsed);
    runtime.cache_response_url(
        &scopes.conversation_scope,
        parsed.msg_id.as_str(),
        parsed.response_url.as_deref(),
    );
    runtime.maybe_cleanup_files().await;

    if parsed.msg_type == "stream" {
        let stream_id = parse_stream_id(&parsed.raw_payload).unwrap_or_else(next_stream_id);
        let state_snapshot = runtime.get_stream_state(&stream_id);
        let (content, finish, images) = if let Some(snapshot) = state_snapshot {
            tracing::debug!(
                "WeCom stream refresh hit: stream_id={} scope={} exec_scope={} finish={} owner={}",
                stream_id,
                snapshot.conversation_scope,
                snapshot.execution_scope,
                snapshot.finish,
                snapshot.owner_msg_id
            );
            (snapshot.content, snapshot.finish, snapshot.images)
        } else {
            ("任务已结束或不存在。".to_string(), true, Vec::new())
        };
        return match encrypt_passive_stream_reply(
            &runtime, &query, &stream_id, &content, finish, &images,
        ) {
            Ok(resp) => (StatusCode::OK, resp).into_response(),
            Err(err) => {
                tracing::error!("WeCom stream refresh encrypt failed: {err:#}");
                (StatusCode::OK, "success".to_string()).into_response()
            }
        };
    }

    if parsed.msg_type == "event" {
        let event_type =
            parse_event_type(&parsed.raw_payload).unwrap_or_else(|| "unknown".to_string());
        if event_type == "enter_chat" {
            let content = format!("你好，欢迎来找我聊天 {}", random_emoji());
            return match encrypt_passive_text_reply(&runtime, &query, &content) {
                Ok(resp) => (StatusCode::OK, resp).into_response(),
                Err(err) => {
                    tracing::error!("WeCom enter_chat reply encrypt failed: {err:#}");
                    (StatusCode::OK, "success".to_string()).into_response()
                }
            };
        }
        if event_type == "template_card_event" {
            let event_key = extract_template_card_event_key(&parsed.raw_payload)
                .unwrap_or_else(|| "-".to_string());
            tracing::info!(
                "WeCom template_card_event received: msg_id={} event_key={}",
                parsed.msg_id,
                event_key
            );
            return (StatusCode::OK, "success".to_string()).into_response();
        }
        if event_type == "feedback_event" {
            let summary = extract_feedback_event_summary(&parsed.raw_payload)
                .unwrap_or_else(|| "feedback=invalid-payload".to_string());
            tracing::info!(
                "WeCom feedback_event received: msg_id={} {}",
                parsed.msg_id,
                summary
            );
            return (StatusCode::OK, "success".to_string()).into_response();
        }

        tracing::info!(
            "WeCom event ignored: event_type={} msg_id={}",
            event_type,
            parsed.msg_id
        );
        return (StatusCode::OK, "success".to_string()).into_response();
    }

    if !is_model_supported_msgtype(&parsed.msg_type) {
        tracing::info!(
            "WeCom unsupported message ignored: msg_type={} msg_id={}",
            parsed.msg_type,
            parsed.msg_id
        );
        return (StatusCode::OK, "success".to_string()).into_response();
    }

    let stop_text = extract_stop_signal_text(&parsed).unwrap_or_default();
    if runtime.is_execution_locked(&scopes.execution_scope) {
        if contains_stop_command(&stop_text) {
            let stopped = "已停止当前消息处理。";
            if let Some(stream_id) = runtime.current_stream_id_for_scope(&scopes.execution_scope) {
                runtime.update_stream_state_content(&stream_id, stopped, true);
            }
            runtime.abort_inflight_task(&scopes.execution_scope);
            runtime.force_release_execution_lock(&scopes.execution_scope);

            let stop_reply_stream = next_stream_id();
            runtime.upsert_stream_state(
                &stop_reply_stream,
                &scopes.execution_scope,
                &scopes.conversation_scope,
                &parsed.msg_id,
                stopped,
                true,
                Vec::new(),
            );
            return match encrypt_passive_stream_reply(
                &runtime,
                &query,
                &stop_reply_stream,
                stopped,
                true,
                &[],
            ) {
                Ok(resp) => (StatusCode::OK, resp).into_response(),
                Err(err) => {
                    tracing::error!("WeCom stop reply encrypt failed: {err:#}");
                    (StatusCode::OK, "success".to_string()).into_response()
                }
            };
        }

        let busy = format!(
            "有消息正在处理中，但是多了一次回复机会！如果需要停止当前消息处理，请发送停止或者stop。{}",
            random_emoji()
        );
        let busy_stream = next_stream_id();
        runtime.upsert_stream_state(
            &busy_stream,
            &scopes.execution_scope,
            &scopes.conversation_scope,
            &parsed.msg_id,
            &busy,
            true,
            Vec::new(),
        );
        return match encrypt_passive_stream_reply(&runtime, &query, &busy_stream, &busy, true, &[])
        {
            Ok(resp) => (StatusCode::OK, resp).into_response(),
            Err(err) => {
                tracing::error!("WeCom busy reply encrypt failed: {err:#}");
                (StatusCode::OK, "success".to_string()).into_response()
            }
        };
    }

    if is_voice_without_transcript(&parsed) {
        let msg = format!("我现在无法处理语音消息 {}", random_emoji());
        let stream_id = next_stream_id();
        runtime.upsert_stream_state(
            &stream_id,
            &scopes.execution_scope,
            &scopes.conversation_scope,
            &parsed.msg_id,
            &msg,
            true,
            Vec::new(),
        );
        return match encrypt_passive_stream_reply(&runtime, &query, &stream_id, &msg, true, &[]) {
            Ok(resp) => (StatusCode::OK, resp).into_response(),
            Err(err) => {
                tracing::error!("WeCom voice fallback encrypt failed: {err:#}");
                (StatusCode::OK, "success".to_string()).into_response()
            }
        };
    }

    let stream_id = next_stream_id();
    if !runtime.try_acquire_execution_lock(&scopes.execution_scope, &parsed.msg_id, &stream_id) {
        let busy = format!(
            "有消息正在处理中，但是多了一次回复机会！如果需要停止当前消息处理，请发送停止或者stop。{}",
            random_emoji()
        );
        let busy_stream = next_stream_id();
        runtime.upsert_stream_state(
            &busy_stream,
            &scopes.execution_scope,
            &scopes.conversation_scope,
            &parsed.msg_id,
            &busy,
            true,
            Vec::new(),
        );
        return match encrypt_passive_stream_reply(&runtime, &query, &busy_stream, &busy, true, &[])
        {
            Ok(resp) => (StatusCode::OK, resp).into_response(),
            Err(err) => {
                tracing::error!("WeCom race-busy reply encrypt failed: {err:#}");
                (StatusCode::OK, "success".to_string()).into_response()
            }
        };
    }

    runtime.upsert_stream_state(
        &stream_id,
        &scopes.execution_scope,
        &scopes.conversation_scope,
        &parsed.msg_id,
        WECOM_STREAM_BOOTSTRAP_CONTENT,
        false,
        Vec::new(),
    );

    let state_clone = state.clone();
    let runtime_clone = runtime.clone();
    let parsed_clone = parsed.clone();
    let scopes_clone = scopes.clone();
    let stream_id_clone = stream_id.clone();
    let handle = tokio::spawn(async move {
        process_inbound_message(
            state_clone,
            runtime_clone,
            parsed_clone,
            scopes_clone,
            stream_id_clone,
        )
        .await;
    });
    runtime.register_inflight_task(&scopes.execution_scope, &parsed.msg_id, &stream_id, handle);

    match encrypt_passive_stream_reply(
        &runtime,
        &query,
        &stream_id,
        WECOM_STREAM_BOOTSTRAP_CONTENT,
        false,
        &[],
    ) {
        Ok(resp) => (StatusCode::OK, resp).into_response(),
        Err(err) => {
            tracing::error!("WeCom bootstrap stream encrypt failed: {err:#}");
            (StatusCode::OK, "success".to_string()).into_response()
        }
    }
}

async fn process_inbound_message(
    state: AppState,
    runtime: Arc<WeComRuntime>,
    inbound: ParsedInbound,
    scopes: ScopeDecision,
    stream_id: String,
) {
    let mut inbound = inbound;
    runtime.materialize_quote_attachments(&mut inbound).await;
    let normalized = runtime.normalize_message(&inbound).await;

    match normalized {
        NormalizedMessage::VoiceMissingTranscript => {
            let msg = format!("我现在无法处理语音消息 {}", random_emoji());
            runtime.update_stream_state_content(&stream_id, &msg, true);
        }
        NormalizedMessage::Unsupported => {
            let msg = "暂不支持该消息类型。".to_string();
            runtime.update_stream_state_content(&stream_id, &msg, true);
        }
        NormalizedMessage::Ready(content) => {
            runtime.update_stream_state_content(&stream_id, "正在调用模型生成回复...", false);

            let prior = runtime.snapshot_conversation(&scopes.conversation_scope);
            let composed = runtime.compose_input(&inbound, &scopes, &content, &prior);

            let llm_response =
                match run_gateway_chat_with_tools(&state, &composed.user_message_for_model).await {
                    Ok(text) => text,
                    Err(err) => {
                        tracing::error!("WeCom LLM execution failed: {err:#}");
                        "抱歉，我暂时无法处理这条消息。".to_string()
                    }
                };

            let (text_without_images, image_paths) = parse_image_markers(&llm_response);
            let images = prepare_stream_images(&image_paths).await;

            let (stream_content, overflow) =
                split_stream_content_and_overflow(&text_without_images);
            runtime.update_stream_state_with_images(&stream_id, &stream_content, true, images);

            runtime.upsert_conversation(
                &scopes.conversation_scope,
                true,
                &composed.user_turn_for_history,
                &text_without_images,
            );

            if let Some(extra) = overflow {
                let extra_msg = format!("[补充消息]\n{extra}");
                runtime
                    .send_text_with_fallbacks(&state, &scopes.conversation_scope, &extra_msg)
                    .await;
            }

            runtime.maybe_cleanup_files().await;
        }
    }

    runtime.release_execution_lock(&scopes.execution_scope, &inbound.msg_id);
    runtime.clear_inflight_task_if_owner(&scopes.execution_scope, &inbound.msg_id);
}

fn reply_timestamp(query: &WeComCallbackQuery) -> String {
    if query.timestamp.trim().is_empty() {
        bytes_timestamp_now().to_string()
    } else {
        query.timestamp.trim().to_string()
    }
}

fn reply_nonce(query: &WeComCallbackQuery) -> String {
    if query.nonce.trim().is_empty() {
        random_ascii_token(12)
    } else {
        query.nonce.trim().to_string()
    }
}

fn encrypt_passive_stream_reply(
    runtime: &WeComRuntime,
    query: &WeComCallbackQuery,
    stream_id: &str,
    content: &str,
    finish: bool,
    images: &[StreamImageItem],
) -> Result<String> {
    let timestamp = reply_timestamp(query);
    let nonce = reply_nonce(query);
    let payload = make_stream_payload(stream_id, content, finish, images);
    runtime
        .crypto
        .encrypt_json_ciphertext(&payload.to_string(), &nonce, &timestamp, "")
}

fn encrypt_passive_text_reply(
    runtime: &WeComRuntime,
    query: &WeComCallbackQuery,
    content: &str,
) -> Result<String> {
    let timestamp = reply_timestamp(query);
    let nonce = reply_nonce(query);
    let payload = make_text_payload(content);
    runtime
        .crypto
        .encrypt_json_ciphertext(&payload.to_string(), &nonce, &timestamp, "")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_uses_group_shared_mode_when_whitelisted() {
        let cfg = WeComRuntimeConfig {
            workspace_dir: PathBuf::from("."),
            group_shared_history_enabled: true,
            group_shared_history_chat_ids: vec!["g1".to_string()],
            file_retention_days: 3,
            max_file_size_bytes: 20 * 1024 * 1024,
            response_url_cache_per_scope: 20,
            lock_timeout_secs: 900,
            history_max_turns: 30,
            fallback_robot_webhook_url: None,
        };

        let inbound = ParsedInbound {
            msg_id: "m1".to_string(),
            msg_type: "text".to_string(),
            chat_type: "group".to_string(),
            chat_id: Some("g1".to_string()),
            sender_userid: "u1".to_string(),
            aibot_id: "b1".to_string(),
            response_url: None,
            raw_payload: serde_json::json!({}),
        };

        let scopes = compute_scopes(&cfg, &inbound);
        assert_eq!(scopes.conversation_scope, "group:g1");
        assert_eq!(scopes.execution_scope, "group:g1");
        assert!(scopes.shared_group_history);
    }

    #[test]
    fn split_markdown_chunks_preserves_large_input() {
        let input = "a".repeat(WECOM_MARKDOWN_CHUNK_BYTES * 3 + 100);
        let chunks = split_markdown_chunks(&input);
        assert!(chunks.len() >= 3);
        for chunk in chunks {
            assert!(chunk.as_bytes().len() <= WECOM_MARKDOWN_MAX_BYTES);
        }
    }

    #[test]
    fn robot_webhook_url_validation() {
        assert!(is_valid_robot_webhook_url(
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test"
        ));
        assert!(!is_valid_robot_webhook_url("http://example.com/test"));
        assert!(!is_valid_robot_webhook_url(
            "https://qyapi.weixin.qq.com/cgi-bin/message/send"
        ));
    }

    #[test]
    fn stop_command_detection_supports_cn_and_en() {
        assert!(contains_stop_command("停止"));
        assert!(contains_stop_command("Please STOP now"));
        assert!(!contains_stop_command("继续处理"));
    }

    #[test]
    fn crypto_encrypt_and_decrypt_roundtrip() {
        let crypto =
            WeComCrypto::new("token123", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG").unwrap();
        let nonce = "nonce123";
        let timestamp = "1700000000";
        let plain = r#"{"msgtype":"stream","stream":{"id":"sid","finish":false,"content":"hi"}}"#;

        let envelope = crypto
            .encrypt_json_ciphertext(plain, nonce, timestamp, "")
            .unwrap();
        let parsed: Value = serde_json::from_str(&envelope).unwrap();
        let encrypt = parsed
            .get("encrypt")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let signature = parsed
            .get("msgsignature")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        assert!(crypto.verify_signature(&signature, timestamp, nonce, &encrypt));
        let decrypted = crypto.decrypt_json_ciphertext(&encrypt, "").unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn crypto_signature_verification_matches_sorted_sha1() {
        let crypto =
            WeComCrypto::new("token123", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG").unwrap();
        let encrypt = "enc_payload";
        let timestamp = "1700000000";
        let nonce = "nonce123";

        let mut parts = vec!["token123", timestamp, nonce, encrypt];
        parts.sort_unstable();
        let mut sha = Sha1::new();
        sha.update(parts.join(""));
        let signature = hex::encode(sha.finalize());

        assert!(crypto.verify_signature(&signature, timestamp, nonce, encrypt));
    }

    #[test]
    fn parse_event_type_extracts_enter_chat() {
        let payload = serde_json::json!({
            "event": {
                "eventtype": "enter_chat"
            }
        });
        assert_eq!(parse_event_type(&payload).as_deref(), Some("enter_chat"));
    }

    #[test]
    fn extract_quote_context_from_text_quote() {
        let payload = serde_json::json!({
            "quote": {
                "msgtype": "text",
                "text": {
                    "content": "  引用内容  "
                }
            }
        });

        let quote = extract_quote_context(&payload).expect("quote should be extracted");
        assert!(quote.contains("msgtype=text"));
        assert!(quote.contains("content=引用内容"));
    }

    #[test]
    fn extract_quote_context_from_mixed_quote() {
        let payload = serde_json::json!({
            "quote": {
                "msgtype": "mixed",
                "mixed": {
                    "msg_item": [
                        {
                            "msgtype": "text",
                            "text": {
                                "content": "第一段"
                            }
                        },
                        {
                            "msgtype": "image",
                            "image": {
                                "url": "https://example.com/image.png"
                            }
                        }
                    ]
                }
            }
        });

        let quote = extract_quote_context(&payload).expect("quote should be extracted");
        assert!(quote.contains("第一段"));
        assert!(quote.contains("引用图片"));
    }

    #[test]
    fn parse_wecom_business_response_requires_zero_errcode() {
        assert!(parse_wecom_business_response(r#"{"errcode":0,"errmsg":"ok"}"#).is_ok());
        assert!(parse_wecom_business_response(r#"{"errcode":93000,"errmsg":"expired"}"#).is_err());
        assert!(parse_wecom_business_response(r#"{"errmsg":"ok"}"#).is_err());
    }

    #[test]
    fn extract_quote_context_does_not_leak_remote_media_url() {
        let payload = serde_json::json!({
            "quote": {
                "msgtype": "image",
                "image": {
                    "url": "https://example.com/tmp-sign-url"
                }
            }
        });

        let quote = extract_quote_context(&payload).expect("quote should be extracted");
        assert!(quote.contains("[引用图片]"));
        assert!(!quote.contains("example.com/tmp-sign-url"));
    }

    #[test]
    fn extract_template_card_event_key_reads_event_key() {
        let payload = serde_json::json!({
            "event": {
                "eventtype": "template_card_event",
                "template_card_event": {
                    "event_key": "button_confirm"
                }
            }
        });
        assert_eq!(
            extract_template_card_event_key(&payload).as_deref(),
            Some("button_confirm")
        );
    }

    #[test]
    fn extract_feedback_event_summary_reads_fields() {
        let payload = serde_json::json!({
            "event": {
                "eventtype": "feedback_event",
                "feedback_event": {
                    "id": "fb_1",
                    "type": 2,
                    "content": "not accurate"
                }
            }
        });
        let summary = extract_feedback_event_summary(&payload).expect("summary should exist");
        assert!(summary.contains("feedback_id=fb_1"));
        assert!(summary.contains("feedback_type=2"));
        assert!(summary.contains("content=not accurate"));
    }

    #[test]
    fn parse_image_markers_extracts_paths() {
        let input = "分析结果:\n[IMAGE:/tmp/chart.png]\n请参考。";
        let (cleaned, paths) = parse_image_markers(input);
        assert_eq!(paths, vec!["/tmp/chart.png"]);
        assert!(cleaned.contains("分析结果:"));
        assert!(cleaned.contains("请参考。"));
        assert!(!cleaned.contains("[IMAGE:"));
    }

    #[test]
    fn parse_image_markers_preserves_non_image_tags() {
        let input = "Hello [TOOL:abc] world [IMAGE:/a.jpg] end";
        let (cleaned, paths) = parse_image_markers(input);
        assert_eq!(paths, vec!["/a.jpg"]);
        assert!(cleaned.contains("[TOOL:abc]"));
        assert!(!cleaned.contains("[IMAGE:"));
    }

    #[test]
    fn parse_image_markers_no_markers() {
        let input = "No images here.";
        let (cleaned, paths) = parse_image_markers(input);
        assert_eq!(cleaned, "No images here.");
        assert!(paths.is_empty());
    }

    #[test]
    fn make_stream_payload_with_images_on_finish() {
        let imgs = vec![StreamImageItem {
            base64: "aGVsbG8=".to_string(),
            md5: "5d41402abc4b2a76b9719d911017c592".to_string(),
        }];
        let payload = make_stream_payload("sid1", "done", true, &imgs);
        let stream = payload.get("stream").expect("stream key");
        assert_eq!(stream.get("finish").and_then(Value::as_bool), Some(true));
        let msg_items = stream
            .get("msg_item")
            .and_then(Value::as_array)
            .expect("msg_item");
        assert_eq!(msg_items.len(), 1);
        assert_eq!(
            msg_items[0].get("msgtype").and_then(Value::as_str),
            Some("image")
        );
        assert_eq!(
            msg_items[0]
                .get("image")
                .and_then(|v| v.get("base64"))
                .and_then(Value::as_str),
            Some("aGVsbG8=")
        );
    }

    #[test]
    fn make_stream_payload_no_images() {
        let payload = make_stream_payload("sid2", "hello", true, &[]);
        let stream = payload.get("stream").expect("stream key");
        assert!(stream.get("msg_item").is_none());
    }

    #[test]
    fn make_stream_payload_ignores_images_when_not_finish() {
        let imgs = vec![StreamImageItem {
            base64: "aGVsbG8=".to_string(),
            md5: "abc".to_string(),
        }];
        let payload = make_stream_payload("sid3", "partial", false, &imgs);
        let stream = payload.get("stream").expect("stream key");
        assert!(stream.get("msg_item").is_none());
    }
}
