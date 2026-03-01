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
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use parking_lot::Mutex;
use rand::Rng;
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WECOM_RESPONSE_URL_TTL_SECS: u64 = 3600;
const WECOM_MARKDOWN_MAX_BYTES: usize = 20_480;
const WECOM_MARKDOWN_CHUNK_BYTES: usize = 8_000;
const WECOM_EMOJIS: &[&str] = &["🙂", "😄", "🤝", "🚀", "👌"];
const WECOM_HISTORY_WINDOW_TURNS: usize = 12;
const WECOM_FILE_CLEANUP_INTERVAL_SECS: u64 = 1800;

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
    expires_at: Instant,
}

#[derive(Debug, Clone, Default)]
struct ConversationState {
    static_injected: bool,
    turns: VecDeque<ConversationTurn>,
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
            client: reqwest::Client::new(),
            response_urls: Arc::new(Mutex::new(HashMap::new())),
            execution_locks: Arc::new(Mutex::new(HashMap::new())),
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

    fn try_acquire_execution_lock(&self, execution_scope: &str, msg_id: &str) -> bool {
        let now = Instant::now();
        let mut locks = self.execution_locks.lock();
        locks.retain(|_, lock| lock.expires_at > now);

        if locks.contains_key(execution_scope) {
            return false;
        }

        locks.insert(
            execution_scope.to_string(),
            ExecutionLockEntry {
                owner_msg_id: msg_id.to_string(),
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

    fn snapshot_conversation(&self, scope: &str) -> ConversationState {
        self.conversations
            .lock()
            .get(scope)
            .cloned()
            .unwrap_or_default()
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

    async fn maybe_cleanup_files(&self) {
        let now = Instant::now();
        {
            let mut last = self.last_cleanup.lock();
            if now.duration_since(*last) < Duration::from_secs(WECOM_FILE_CLEANUP_INTERVAL_SECS) {
                return;
            }
            *last = now;
        }

        let retention = Duration::from_secs((self.cfg.file_retention_days as u64) * 86_400);
        let root = self.cfg.workspace_dir.join(".wecom").join("inbox");

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
                        } else if item_type == "image"
                            && let Some(url) = item
                                .get("image")
                                .and_then(|v| v.get("url"))
                                .and_then(Value::as_str)
                        {
                            match self
                                .download_and_store_attachment(url, AttachmentKind::Image, inbound)
                                .await
                            {
                                Ok(marker) => text_parts.push(marker),
                                Err(err) => {
                                    tracing::warn!("WeCom mixed image processing failed: {err}");
                                    text_parts.push(
                                        "[Image attachment processing failed in mixed message.]"
                                            .to_string(),
                                    );
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

        if let Some(len) = response.content_length()
            && len > self.cfg.max_file_size_bytes
        {
            return Ok(format!(
                "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                kind, len, self.cfg.max_file_size_bytes
            ));
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
        let file_name = format!("{safe_scope}_{ts}_{}.{}", inbound.msg_id, ext);

        let dir = self.cfg.workspace_dir.join(".wecom").join("inbox");
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

        blocks.push(normalized.to_string());

        let mut user_turn_for_history = normalized.to_string();
        if scopes.shared_group_history {
            user_turn_for_history = format!("[{}] {}", inbound.sender_userid, normalized);
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

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "WeCom markdown send failed: status={} body={body}",
                response.status()
            );
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
    if let Some(existing) = store.get(&runtime_key)
        && existing.fingerprint == candidate.fingerprint
    {
        return Ok(Some(existing.clone()));
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

    if !parsed.msg_id.is_empty() {
        let key = format!("wecom_msg_{}", parsed.msg_id);
        if !state.idempotency_store.record_if_new(&key) {
            return (StatusCode::OK, "success".to_string()).into_response();
        }
    }

    let state_clone = state.clone();
    tokio::spawn(async move {
        process_inbound_message(state_clone, runtime, parsed).await;
    });

    (StatusCode::OK, "success".to_string()).into_response()
}

async fn process_inbound_message(
    state: AppState,
    runtime: Arc<WeComRuntime>,
    inbound: ParsedInbound,
) {
    let scopes = compute_scopes(&runtime.cfg, &inbound);

    runtime.cache_response_url(
        &scopes.conversation_scope,
        inbound.msg_id.as_str(),
        inbound.response_url.as_deref(),
    );

    let normalized = runtime.normalize_message(&inbound).await;

    match normalized {
        NormalizedMessage::VoiceMissingTranscript => {
            let msg = format!("我现在无法处理语音消息 {}", random_emoji());
            runtime
                .send_text_with_fallbacks(&state, &scopes.conversation_scope, &msg)
                .await;
            return;
        }
        NormalizedMessage::Unsupported => {
            tracing::info!(
                "WeCom unsupported message ignored: msg_type={} msg_id={}",
                inbound.msg_type,
                inbound.msg_id
            );
            return;
        }
        NormalizedMessage::Ready(content) => {
            if !runtime.try_acquire_execution_lock(&scopes.execution_scope, &inbound.msg_id) {
                let busy = format!("有消息正在处理中，但是多了一次回复机会！{}", random_emoji());
                runtime
                    .send_text_with_fallbacks(&state, &scopes.conversation_scope, &busy)
                    .await;
                return;
            }

            let task_result = async {
                let prior = runtime.snapshot_conversation(&scopes.conversation_scope);
                let composed = runtime.compose_input(&inbound, &scopes, &content, &prior);

                let llm_response =
                    match run_gateway_chat_with_tools(&state, &composed.user_message_for_model)
                        .await
                    {
                        Ok(text) => text,
                        Err(err) => {
                            tracing::error!("WeCom LLM execution failed: {err:#}");
                            "抱歉，我暂时无法处理这条消息。".to_string()
                        }
                    };

                runtime
                    .send_text_with_fallbacks(&state, &scopes.conversation_scope, &llm_response)
                    .await;

                runtime.upsert_conversation(
                    &scopes.conversation_scope,
                    true,
                    &composed.user_turn_for_history,
                    &llm_response,
                );

                runtime.maybe_cleanup_files().await;
            }
            .await;

            runtime.release_execution_lock(&scopes.execution_scope, &inbound.msg_id);
            task_result
        }
    }
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
}
