use super::traits::{Channel, ChannelMessage, SendMessage};
use crate::memory::Memory;
use aes::Aes256;
use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use base64::Engine as _;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5 as md5_crate;
use parking_lot::Mutex;
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Constants ────────────────────────────────────────────────────────

const WECOM_RESPONSE_URL_TTL_SECS: u64 = 3600;
const WECOM_MARKDOWN_MAX_BYTES: usize = 20_480;
const WECOM_MARKDOWN_CHUNK_BYTES: usize = 8_000;
const WECOM_EMOJIS: &[&str] = &[
    "\u{1F642}",
    "\u{1F604}",
    "\u{1F91D}",
    "\u{1F680}",
    "\u{1F44C}",
];
const WECOM_FILE_CLEANUP_INTERVAL_SECS: u64 = 1800;
const WECOM_STREAM_STATE_TTL_SECS: u64 = 7200;
const WECOM_HTTP_TIMEOUT_SECS: u64 = 60;
const WECOM_STREAM_BOOTSTRAP_CONTENT: &str =
    "\u{6b63}\u{5728}\u{5904}\u{7406}\u{4e2d}\u{ff0c}\u{8bf7}\u{7a0d}\u{5019}\u{3002}";
const WECOM_STREAM_MAX_IMAGES: usize = 10;
const WECOM_IMAGE_MAX_BYTES: usize = 10 * 1024 * 1024;

// ── Communication types (internal, for axum handler → handle_callback bridge) ──

#[derive(Debug, Deserialize)]
pub(crate) struct WeComCallbackQuery {
    pub msg_signature: String,
    pub timestamp: String,
    pub nonce: String,
    pub echostr: Option<String>,
}

/// Internal request envelope for handler → callback bridge.
struct WeComInboundRequest {
    pub query: WeComCallbackQuery,
    pub body: Bytes,
    pub reply_tx: tokio::sync::oneshot::Sender<WeComInboundResponse>,
}

/// Internal response envelope from callback → handler bridge.
struct WeComInboundResponse {
    pub status_code: u16,
    pub body: String,
}

// ── Internal types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WeComEncryptedEnvelope {
    encrypt: String,
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
    shared_group_history: bool,
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

/// Cached response_url entry with expiration tracking
#[derive(Debug, Clone)]
struct ResponseUrlEntry {
    url: String,
    expires_at: Instant,
    received_at: Instant,
    msg_id: String,
}

/// Configuration for response_url caching
#[derive(Debug, Clone)]
struct ResponseUrlCacheConfig {
    ttl_secs: u64,
    max_per_scope: usize,
}

#[derive(Clone)]
struct WeComRuntimeConfig {
    workspace_dir: PathBuf,
    file_retention_days: u32,
    max_file_size_bytes: u64,
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

#[derive(Debug, Clone)]
struct StreamState {
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

// ── WeComCrypto ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WeComCrypto {
    token: String,
    key: [u8; 32],
}

impl WeComCrypto {
    fn new(token: &str, encoding_aes_key: &str) -> Result<Self> {
        use base64::Engine;

        let raw = base64::engine::general_purpose::STANDARD
            .decode(format!("{}=", encoding_aes_key.trim()))
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(encoding_aes_key.trim())
            })
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE
                    .decode(format!("{}=", encoding_aes_key.trim()))
            })
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoding_aes_key.trim())
            })
            .context("failed to decode WeCom EncodingAESKey - tried STANDARD, STANDARD_NO_PAD, URL_SAFE variants")?;

        if raw.len() != 32 {
            anyhow::bail!(
                "invalid WeCom EncodingAESKey length: expected 32 bytes, got {}",
                raw.len()
            );
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
        let mut parts = [
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

        let mut parts = [
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

// ── WeComChannel struct ──────────────────────────────────────────────

/// WeCom (企业微信) channel — thin adapter layer.
///
/// Runs its own axum HTTP server on a dedicated port.
/// `listen()` binds the port, receives HTTP callbacks, decrypts and
/// normalizes inbound messages, then forwards them to the framework
/// via `ChannelMessage`. All LLM orchestration, conversation history,
/// and execution control are handled by the shared channel framework.
///
/// Outbound messages use a 3-layer fallback:
/// 1. response_url (cached from incoming messages, TTL 1 hour)
/// 2. scope-specific push webhook (looked up from memory)
/// 3. fallback push webhook (from config)
#[derive(Clone)]
pub struct WeComChannel {
    // Crypto
    crypto: WeComCrypto,

    // Runtime config
    cfg: WeComRuntimeConfig,

    // Listening port for independent HTTP server
    port: u16,

    // HTTP client for attachment downloads and webhook sends
    client: reqwest::Client,

    // Outbound send client (may use proxy)
    send_client: reqwest::Client,

    // Memory backend
    memory: Arc<dyn Memory>,

    // Fallback webhook
    fallback_webhook_url: Option<String>,

    // response_url cache
    response_urls: Arc<Mutex<HashMap<String, VecDeque<ResponseUrlEntry>>>>,
    cache_config: ResponseUrlCacheConfig,

    // Runtime state
    stream_states: Arc<Mutex<HashMap<String, StreamState>>>,
    last_cleanup: Arc<Mutex<Instant>>,
    idempotency: Arc<SimpleIdempotencyStore>,

    fingerprint: String,
}

impl WeComChannel {
    pub fn new(
        config: &crate::config::WeComConfig,
        workspace_dir: &Path,
        memory: Arc<dyn Memory>,
    ) -> Result<Self> {
        let crypto = WeComCrypto::new(&config.token, &config.encoding_aes_key)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(WECOM_HTTP_TIMEOUT_SECS))
            .build()
            .context("failed to initialize WeCom HTTP client")?;

        let send_client = crate::config::build_runtime_proxy_client("channel.wecom");

        let fingerprint = format!("{}|{}", config.token, config.encoding_aes_key);

        Ok(Self {
            crypto,
            cfg: WeComRuntimeConfig {
                workspace_dir: workspace_dir.to_path_buf(),
                file_retention_days: config.file_retention_days,
                max_file_size_bytes: config.max_file_size_mb.saturating_mul(1024 * 1024),
            },
            port: config.port,
            client,
            send_client,
            memory,
            fallback_webhook_url: config.fallback_robot_webhook_url.clone(),
            response_urls: Arc::new(Mutex::new(HashMap::new())),
            cache_config: ResponseUrlCacheConfig {
                ttl_secs: config.response_url_ttl_secs,
                max_per_scope: config.response_url_cache_per_scope,
            },
            stream_states: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
            idempotency: Arc::new(SimpleIdempotencyStore::new()),
            fingerprint,
        })
    }

    // ── HTTP request handler (axum → handle_callback bridge) ────────

    /// Process an HTTP request from the independent listener.
    /// Internally bridges to `handle_callback` via oneshot for minimal refactor risk.
    async fn handle_http_request(
        &self,
        query: WeComCallbackQuery,
        body: Bytes,
        tx: &tokio::sync::mpsc::Sender<ChannelMessage>,
    ) -> (StatusCode, String) {
        tracing::debug!(
            "[wecom] HTTP request received: msg_signature={} timestamp={} echostr={}",
            query.msg_signature,
            query.timestamp,
            if query.echostr.is_some() {
                "present(verify)"
            } else {
                "absent(callback)"
            }
        );

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = WeComInboundRequest {
            query,
            body,
            reply_tx,
        };

        self.handle_callback(req, tx).await;

        match reply_rx.await {
            Ok(resp) => {
                let status = StatusCode::from_u16(resp.status_code).unwrap_or(StatusCode::OK);
                tracing::debug!("[wecom] HTTP response: status={}", status.as_u16());
                (status, resp.body)
            }
            Err(_) => {
                tracing::error!("[wecom] HTTP handler: reply channel dropped unexpectedly");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        }
    }

    // ── response_url cache ───────────────────────────────────────────

    /// Cache a response_url for later use.
    pub fn cache_response_url(&self, scope: &str, msg_id: &str, url: Option<&str>) {
        let Some(url) = url.map(str::trim).filter(|v| !v.is_empty()) else {
            return;
        };

        tracing::info!(
            "WeCom: caching response_url for scope={} msg_id={}",
            scope,
            msg_id
        );

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(self.cache_config.ttl_secs);

        let mut cache = self.response_urls.lock();
        let queue = cache.entry(scope.to_string()).or_default();
        queue.push_back(ResponseUrlEntry {
            url: url.to_string(),
            expires_at,
            received_at: now,
            msg_id: msg_id.to_string(),
        });

        while queue.len() > self.cache_config.max_per_scope {
            queue.pop_front();
        }
    }

    fn take_response_url(&self, scope: &str) -> Option<ResponseUrlEntry> {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        let queue = cache.get_mut(scope)?;
        queue.retain(|entry| entry.expires_at > now);
        if queue.is_empty() {
            return None;
        }
        queue.pop_front()
    }

    fn prune_response_urls(&self) {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        cache.retain(|_, queue| {
            queue.retain(|entry| entry.expires_at > now);
            !queue.is_empty()
        });
    }

    // ── stream states ────────────────────────────────────────────────

    fn upsert_stream_state(
        &self,
        stream_id: &str,
        content: &str,
        finish: bool,
        images: Vec<StreamImageItem>,
    ) {
        let mut states = self.stream_states.lock();
        states.insert(
            stream_id.to_string(),
            StreamState {
                content: normalize_stream_content(content),
                finish,
                images,
                expires_at: Instant::now() + Duration::from_secs(WECOM_STREAM_STATE_TTL_SECS),
            },
        );
        tracing::info!(
            "WeCom: upsert stream state stream_id={} finish={}",
            stream_id,
            finish
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

    // ── file cleanup ─────────────────────────────────────────────────

    async fn maybe_cleanup_files(&self) {
        self.prune_stream_states();

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

    // ── attachment handling ──────────────────────────────────────────

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
                        log_attachment_processing_failure(
                            "WeCom quote mixed image processing failed",
                            &err,
                            inbound,
                            AttachmentKind::Image,
                            &url,
                        );
                        "[\u{5f15}\u{7528}\u{56fe}\u{7247}\u{4e0b}\u{8f7d}\u{5931}\u{8d25}]"
                            .to_string()
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
                    "[wecom] unsupported msg_type={other}, raw_payload={}",
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
                    "failed to download WeCom attachment: kind={} msg_id={} msg_type={} chat_type={} chat_id={} sender_userid={} url_target={} elapsed_ms={} timeout_secs={}",
                    kind.as_str(),
                    inbound.msg_id,
                    inbound.msg_type,
                    inbound.chat_type,
                    chat_id,
                    inbound.sender_userid,
                    url_target,
                    started.elapsed().as_millis(),
                    WECOM_HTTP_TIMEOUT_SECS
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let body_preview = truncate_for_log(&body, 512);
            anyhow::bail!(
                "WeCom attachment download failed: kind={} msg_id={} msg_type={} chat_type={} chat_id={} sender_userid={} url_target={} status={} elapsed_ms={} body_preview={}",
                kind.as_str(),
                inbound.msg_id,
                inbound.msg_type,
                inbound.chat_type,
                chat_id,
                inbound.sender_userid,
                url_target,
                status,
                started.elapsed().as_millis(),
                body_preview
            );
        }

        if let Some(len) = response.content_length() {
            if len > self.cfg.max_file_size_bytes {
                tracing::warn!(
                    msg_id = %inbound.msg_id,
                    msg_type = %inbound.msg_type,
                    chat_type = %inbound.chat_type,
                    chat_id = %chat_id,
                    sender_userid = %inbound.sender_userid,
                    attachment_kind = %kind.as_str(),
                    url_target = %url_target,
                    declared_bytes = len,
                    max_file_size_bytes = self.cfg.max_file_size_bytes,
                    elapsed_ms = started.elapsed().as_millis(),
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
                    "failed to read WeCom attachment bytes: kind={} msg_id={} msg_type={} chat_type={} chat_id={} sender_userid={} url_target={} elapsed_ms={}",
                    kind.as_str(),
                    inbound.msg_id,
                    inbound.msg_type,
                    inbound.chat_type,
                    chat_id,
                    inbound.sender_userid,
                    url_target,
                    started.elapsed().as_millis()
                )
            })?;

        if bytes.len() as u64 > self.cfg.max_file_size_bytes {
            tracing::warn!(
                msg_id = %inbound.msg_id,
                msg_type = %inbound.msg_type,
                chat_type = %inbound.chat_type,
                chat_id = %chat_id,
                sender_userid = %inbound.sender_userid,
                attachment_kind = %kind.as_str(),
                url_target = %url_target,
                actual_bytes = bytes.len(),
                max_file_size_bytes = self.cfg.max_file_size_bytes,
                elapsed_ms = started.elapsed().as_millis(),
                "WeCom attachment skipped: payload exceeds configured limit"
            );
            return Ok(format!(
                "[AttachmentTooLarge kind={:?} size={}B limit={}B]",
                kind,
                bytes.len(),
                self.cfg.max_file_size_bytes
            ));
        }

        let decrypted = self.crypto.decrypt_file_payload(&bytes).with_context(|| {
            format!(
                "failed to decrypt WeCom attachment payload: kind={} msg_id={} msg_type={} chat_type={} chat_id={} sender_userid={} url_target={} encrypted_bytes={}",
                kind.as_str(),
                inbound.msg_id,
                inbound.msg_type,
                inbound.chat_type,
                chat_id,
                inbound.sender_userid,
                url_target,
                bytes.len()
            )
        })?;
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

        let dir = self.cfg.workspace_dir.join("wecom_files");
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

        self.maybe_cleanup_files().await;

        let abs = path.canonicalize().unwrap_or(path);
        tracing::info!(
            msg_id = %inbound.msg_id,
            msg_type = %inbound.msg_type,
            chat_type = %inbound.chat_type,
            chat_id = %chat_id,
            sender_userid = %inbound.sender_userid,
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

    // ── outbound send helpers ────────────────────────────────────────

    /// Look up a scope-specific push webhook URL from memory.
    async fn lookup_scope_webhook(&self, scope: &str) -> Option<String> {
        let key = format!("wecom_push_url::{scope}");
        let entry = self.memory.get(&key).await.ok().flatten()?;
        let url = entry.content.trim();
        if is_valid_robot_webhook_url(url) {
            Some(url.to_string())
        } else {
            None
        }
    }

    /// Send content to a WeCom group-bot webhook URL (used by send()).
    async fn send_to_url(&self, url: &str, content: &str) -> Result<()> {
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "content": content,
            }
        });

        let resp = self.send_client.post(url).json(&payload).send().await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("WeCom webhook send failed: {status} \u{2014} {body}");
        }

        if let Ok(parsed) = serde_json::from_str::<Value>(&body) {
            if let Some(errcode) = parsed.get("errcode").and_then(|v| v.as_i64()) {
                if errcode != 0 {
                    let errmsg = parsed
                        .get("errmsg")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    anyhow::bail!(
                        "WeCom webhook business error: errcode={errcode} errmsg={errmsg}"
                    );
                }
            }
        }

        Ok(())
    }

    // ── encrypt helpers ──────────────────────────────────────────────

    fn encrypt_passive_stream_reply(
        &self,
        query: &WeComCallbackQuery,
        stream_id: &str,
        content: &str,
        finish: bool,
        images: &[StreamImageItem],
    ) -> Result<String> {
        let timestamp = reply_timestamp(query);
        let nonce = reply_nonce(query);
        let payload = make_stream_payload(stream_id, content, finish, images);
        self.crypto
            .encrypt_json_ciphertext(&payload.to_string(), &nonce, &timestamp, "")
    }

    fn encrypt_passive_text_reply(
        &self,
        query: &WeComCallbackQuery,
        content: &str,
    ) -> Result<String> {
        let timestamp = reply_timestamp(query);
        let nonce = reply_nonce(query);
        let payload = make_text_payload(content);
        self.crypto
            .encrypt_json_ciphertext(&payload.to_string(), &nonce, &timestamp, "")
    }

    // ── handle_callback (main routing) ───────────────────────────────

    async fn handle_callback(
        &self,
        req: WeComInboundRequest,
        tx: &tokio::sync::mpsc::Sender<ChannelMessage>,
    ) {
        let query = req.query;
        let body = req.body;
        let reply_tx = req.reply_tx;

        tracing::debug!(
            "[wecom] handle_callback: body_len={} echostr={}",
            body.len(),
            query.echostr.is_some()
        );

        // Verification request (echostr present)
        if let Some(echostr) = query.echostr.as_deref() {
            tracing::info!("[wecom] URL verification request received");
            if !self.crypto.verify_signature(
                &query.msg_signature,
                &query.timestamp,
                &query.nonce,
                echostr,
            ) {
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 401,
                    body: r#"{"error":"invalid signature"}"#.to_string(),
                });
                return;
            }
            tracing::info!("WeCom: signature verified for URL verification");

            match self.crypto.decrypt_json_ciphertext(echostr, "") {
                Ok(plain) => {
                    let _ = reply_tx.send(WeComInboundResponse {
                        status_code: 200,
                        body: plain,
                    });
                }
                Err(err) => {
                    tracing::warn!("WeCom URL verify decrypt failed: {err}");
                    let _ = reply_tx.send(WeComInboundResponse {
                        status_code: 400,
                        body: r#"{"error":"decrypt failed"}"#.to_string(),
                    });
                }
            }
            return;
        }

        // Parse encrypted envelope
        let envelope = match serde_json::from_slice::<WeComEncryptedEnvelope>(&body) {
            Ok(value) => value,
            Err(_) => {
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 400,
                    body: r#"{"error":"invalid encrypted payload"}"#.to_string(),
                });
                return;
            }
        };

        // Verify signature
        if !self.crypto.verify_signature(
            &query.msg_signature,
            &query.timestamp,
            &query.nonce,
            &envelope.encrypt,
        ) {
            let _ = reply_tx.send(WeComInboundResponse {
                status_code: 401,
                body: r#"{"error":"invalid signature"}"#.to_string(),
            });
            return;
        }
        tracing::debug!("WeCom: callback signature verified");

        // Decrypt
        let plaintext = match self.crypto.decrypt_json_ciphertext(&envelope.encrypt, "") {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!("WeCom callback decrypt failed: {err}");
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 400,
                    body: r#"{"error":"decrypt failed"}"#.to_string(),
                });
                return;
            }
        };
        tracing::debug!("WeCom: callback decrypted successfully");

        // Parse JSON payload
        let payload: Value = match serde_json::from_str(&plaintext) {
            Ok(value) => value,
            Err(_) => {
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 400,
                    body: r#"{"error":"invalid callback json"}"#.to_string(),
                });
                return;
            }
        };

        // Parse inbound
        let parsed = match parse_inbound_payload(payload) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!("WeCom callback parse failed: {err}");
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 200,
                    body: "success".to_string(),
                });
                return;
            }
        };

        // Idempotency check
        if parsed.msg_type != "stream" && !parsed.msg_id.is_empty() {
            let key = format!("wecom_msg_{}", parsed.msg_id);
            if !self.idempotency.record_if_new(&key) {
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 200,
                    body: "success".to_string(),
                });
                return;
            }
        }

        let scopes = compute_scopes(&parsed);

        // Log inbound info
        if parsed.msg_type != "stream" && parsed.msg_type != "event" {
            let preview =
                crate::util::truncate_with_ellipsis(&inbound_content_preview(&parsed), 80);
            let msg_id = if parsed.msg_id.trim().is_empty() {
                "-"
            } else {
                parsed.msg_id.as_str()
            };
            tracing::info!(
                "[wecom] from {} in {}: {} (msg_type={}, msg_id={})",
                parsed.sender_userid,
                scopes.conversation_scope,
                preview,
                parsed.msg_type,
                msg_id
            );
        }

        // Cache response_url
        self.cache_response_url(
            &scopes.conversation_scope,
            &parsed.msg_id,
            parsed.response_url.as_deref(),
        );

        self.maybe_cleanup_files().await;

        // ── Route by msg_type ────────────────────────────────────────

        // Stream refresh
        if parsed.msg_type == "stream" {
            let stream_id = parse_stream_id(&parsed.raw_payload).unwrap_or_else(next_stream_id);
            let state_snapshot = self.get_stream_state(&stream_id);
            let (content, finish, images) = if let Some(snapshot) = state_snapshot {
                tracing::info!(
                    "[wecom] stream poll: scope={} stream_id={} finish={}",
                    scopes.conversation_scope,
                    stream_id,
                    snapshot.finish
                );
                (snapshot.content, snapshot.finish, snapshot.images)
            } else {
                tracing::info!(
                    "[wecom] stream poll: scope={} stream_id={} (no active stream)",
                    scopes.conversation_scope,
                    stream_id
                );
                ("\u{4efb}\u{52a1}\u{5df2}\u{7ed3}\u{675f}\u{6216}\u{4e0d}\u{5b58}\u{5728}\u{3002}".to_string(), true, Vec::new())
            };
            let resp = match self
                .encrypt_passive_stream_reply(&query, &stream_id, &content, finish, &images)
            {
                Ok(r) => WeComInboundResponse {
                    status_code: 200,
                    body: r,
                },
                Err(err) => {
                    tracing::error!("WeCom stream refresh encrypt failed: {err:#}");
                    WeComInboundResponse {
                        status_code: 200,
                        body: "success".to_string(),
                    }
                }
            };
            let _ = reply_tx.send(resp);
            return;
        }

        // Event handling
        if parsed.msg_type == "event" {
            tracing::info!("WeCom: routing as event callback");
            let event_type =
                parse_event_type(&parsed.raw_payload).unwrap_or_else(|| "unknown".to_string());
            if event_type == "enter_chat" {
                let content = format!("\u{4f60}\u{597d}\u{ff0c}\u{6b22}\u{8fce}\u{6765}\u{627e}\u{6211}\u{804a}\u{5929} {}", random_emoji());
                let resp = match self.encrypt_passive_text_reply(&query, &content) {
                    Ok(r) => WeComInboundResponse {
                        status_code: 200,
                        body: r,
                    },
                    Err(err) => {
                        tracing::error!("WeCom enter_chat reply encrypt failed: {err:#}");
                        WeComInboundResponse {
                            status_code: 200,
                            body: "success".to_string(),
                        }
                    }
                };
                let _ = reply_tx.send(resp);
                return;
            }
            if event_type == "template_card_event" {
                let event_key = extract_template_card_event_key(&parsed.raw_payload)
                    .unwrap_or_else(|| "-".to_string());
                tracing::info!(
                    "WeCom template_card_event received: msg_id={} event_key={}",
                    parsed.msg_id,
                    event_key
                );
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 200,
                    body: "success".to_string(),
                });
                return;
            }
            if event_type == "feedback_event" {
                let summary = extract_feedback_event_summary(&parsed.raw_payload)
                    .unwrap_or_else(|| "feedback=invalid-payload".to_string());
                tracing::info!(
                    "WeCom feedback_event received: msg_id={} {}",
                    parsed.msg_id,
                    summary
                );
                let _ = reply_tx.send(WeComInboundResponse {
                    status_code: 200,
                    body: "success".to_string(),
                });
                return;
            }

            tracing::info!(
                "WeCom event ignored: event_type={} msg_id={}",
                event_type,
                parsed.msg_id
            );
            let _ = reply_tx.send(WeComInboundResponse {
                status_code: 200,
                body: "success".to_string(),
            });
            return;
        }

        // Unsupported message type
        if !is_model_supported_msgtype(&parsed.msg_type) {
            tracing::info!(
                "WeCom unsupported message ignored: msg_type={} msg_id={}",
                parsed.msg_type,
                parsed.msg_id
            );
            let _ = reply_tx.send(WeComInboundResponse {
                status_code: 200,
                body: "success".to_string(),
            });
            return;
        }

        // ── Normal message processing ────────────────────────────────

        let stop_text = extract_stop_signal_text(&parsed).unwrap_or_default();

        // Clear session: reply with confirmation stream, forward /clear to framework
        if is_clear_session_command(&stop_text) {
            let msg = "\u{4f1a}\u{8bdd}\u{5df2}\u{6e05}\u{9664}\u{ff0c}\u{5f00}\u{59cb}\u{65b0}\u{5bf9}\u{8bdd}\u{3002}";
            let clear_stream = next_stream_id();
            self.upsert_stream_state(&clear_stream, msg, true, Vec::new());
            tracing::info!(
                "WeCom session cleared: scope={} msg_id={}",
                scopes.conversation_scope,
                parsed.msg_id
            );
            let resp =
                match self.encrypt_passive_stream_reply(&query, &clear_stream, msg, true, &[]) {
                    Ok(r) => WeComInboundResponse {
                        status_code: 200,
                        body: r,
                    },
                    Err(err) => {
                        tracing::error!("WeCom clear-session reply encrypt failed: {err:#}");
                        WeComInboundResponse {
                            status_code: 200,
                            body: "success".to_string(),
                        }
                    }
                };
            let _ = reply_tx.send(resp);
            // Forward /clear to the framework so it clears conversation history
            let _ = tx
                .send(ChannelMessage {
                    id: parsed.msg_id.clone(),
                    sender: parsed.sender_userid.clone(),
                    reply_target: scopes.conversation_scope.clone(),
                    content: "/clear".to_string(),
                    channel: "wecom".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: None,
                })
                .await;
            return;
        }

        // Stop command: reply with confirmation stream, forward /new to framework
        if contains_stop_command(&stop_text) {
            let stopped =
                "\u{5df2}\u{505c}\u{6b62}\u{5f53}\u{524d}\u{6d88}\u{606f}\u{5904}\u{7406}\u{3002}";
            let stop_stream = next_stream_id();
            self.upsert_stream_state(&stop_stream, stopped, true, Vec::new());
            let resp =
                match self.encrypt_passive_stream_reply(&query, &stop_stream, stopped, true, &[]) {
                    Ok(r) => WeComInboundResponse {
                        status_code: 200,
                        body: r,
                    },
                    Err(err) => {
                        tracing::error!("WeCom stop reply encrypt failed: {err:#}");
                        WeComInboundResponse {
                            status_code: 200,
                            body: "success".to_string(),
                        }
                    }
                };
            let _ = reply_tx.send(resp);
            // Forward /new to the framework: interrupt mechanism cancels in-flight task
            let _ = tx
                .send(ChannelMessage {
                    id: parsed.msg_id.clone(),
                    sender: parsed.sender_userid.clone(),
                    reply_target: scopes.conversation_scope.clone(),
                    content: "/new".to_string(),
                    channel: "wecom".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: None,
                })
                .await;
            return;
        }

        // Voice without transcript
        if is_voice_without_transcript(&parsed) {
            let msg = format!("\u{6211}\u{73b0}\u{5728}\u{65e0}\u{6cd5}\u{5904}\u{7406}\u{8bed}\u{97f3}\u{6d88}\u{606f} {}", random_emoji());
            let stream_id = next_stream_id();
            self.upsert_stream_state(&stream_id, &msg, true, Vec::new());
            let resp = match self.encrypt_passive_stream_reply(&query, &stream_id, &msg, true, &[])
            {
                Ok(r) => WeComInboundResponse {
                    status_code: 200,
                    body: r,
                },
                Err(err) => {
                    tracing::error!("WeCom voice fallback encrypt failed: {err:#}");
                    WeComInboundResponse {
                        status_code: 200,
                        body: "success".to_string(),
                    }
                }
            };
            let _ = reply_tx.send(resp);
            return;
        }

        // ── Forward normal message to framework ──────────────────────

        // Bootstrap stream state for immediate HTTP reply
        let stream_id = next_stream_id();
        self.upsert_stream_state(
            &stream_id,
            WECOM_STREAM_BOOTSTRAP_CONTENT,
            false,
            Vec::new(),
        );

        // Reply immediately with bootstrap stream
        let resp = match self.encrypt_passive_stream_reply(
            &query,
            &stream_id,
            WECOM_STREAM_BOOTSTRAP_CONTENT,
            false,
            &[],
        ) {
            Ok(r) => WeComInboundResponse {
                status_code: 200,
                body: r,
            },
            Err(err) => {
                tracing::error!("WeCom bootstrap stream encrypt failed: {err:#}");
                WeComInboundResponse {
                    status_code: 200,
                    body: "success".to_string(),
                }
            }
        };
        let _ = reply_tx.send(resp);

        // Spawn async: materialize attachments → normalize → compose → send ChannelMessage
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
                    let msg = format!("\u{6211}\u{73b0}\u{5728}\u{65e0}\u{6cd5}\u{5904}\u{7406}\u{8bed}\u{97f3}\u{6d88}\u{606f} {}", random_emoji());
                    channel_self.update_stream_state_content(&stream_id, &msg, true);
                    return;
                }
                NormalizedMessage::Unsupported => {
                    let msg = "\u{6682}\u{4e0d}\u{652f}\u{6301}\u{8be5}\u{6d88}\u{606f}\u{7c7b}\u{578b}\u{3002}".to_string();
                    channel_self.update_stream_state_content(&stream_id, &msg, true);
                    return;
                }
                NormalizedMessage::Ready(content) => content,
            };

            let composed = compose_content_for_framework(&inbound, &content);

            tracing::info!(
                "WeCom: forwarding to framework: msg_id={} stream_id={} scope={}",
                inbound.msg_id,
                stream_id,
                scopes.conversation_scope
            );

            let _ = tx
                .send(ChannelMessage {
                    id: inbound.msg_id.clone(),
                    sender: inbound.sender_userid.clone(),
                    reply_target: scopes.conversation_scope.clone(),
                    content: composed,
                    channel: "wecom".to_string(),
                    timestamp: bytes_timestamp_now(),
                    thread_ts: Some(stream_id),
                })
                .await;
        });
    }
}

// ── Channel trait impl ───────────────────────────────────────────────

#[async_trait]
impl Channel for WeComChannel {
    fn name(&self) -> &str {
        "wecom"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let scope = &message.recipient;
        let chunks = split_markdown_chunks(&message.content);

        tracing::info!(
            "WeCom: sending message to scope={}, len={}, chunks={}",
            scope,
            message.content.len(),
            chunks.len()
        );

        self.prune_response_urls();

        for chunk in chunks {
            let mut sent = false;

            // Level 1: response_url
            while let Some(entry) = self.take_response_url(scope) {
                match self.send_to_url(&entry.url, &chunk).await {
                    Ok(()) => {
                        tracing::info!(
                            "WeCom: sent via response_url to scope={} msg_id={} age_ms={}",
                            scope,
                            entry.msg_id,
                            entry.received_at.elapsed().as_millis()
                        );
                        sent = true;
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "WeCom response_url send failed: scope={} msg_id={} age_ms={} error={}",
                            scope,
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

            // Level 2: scope-specific push webhook
            if let Some(url) = self.lookup_scope_webhook(scope).await {
                match self.send_to_url(&url, &chunk).await {
                    Ok(()) => {
                        tracing::info!("WeCom: sent via scope webhook to scope={}", scope);
                        sent = true;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "WeCom scope webhook send failed: scope={} error={}",
                            scope,
                            err
                        );
                    }
                }
            }

            if sent {
                continue;
            }

            // Level 3: fallback push webhook
            if let Some(url) = &self.fallback_webhook_url {
                if is_valid_robot_webhook_url(url) {
                    let tagged = format!("[FallbackPush] {chunk}");
                    match self.send_to_url(url, &tagged).await {
                        Ok(()) => {
                            tracing::info!("WeCom: sent via fallback webhook to scope={}", scope);
                            sent = true;
                        }
                        Err(err) => {
                            tracing::warn!(
                                "WeCom fallback webhook send failed: scope={} error={}",
                                scope,
                                err
                            );
                        }
                    }
                }
            }

            if !sent {
                tracing::warn!(
                    "WeCom outbound dropped: no usable URL for scope={} (all 3 layers failed)",
                    scope
                );
            }
        }

        Ok(())
    }

    async fn listen(&self, tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        tracing::info!(
            "[wecom] starting independent HTTP listener on port {} (fingerprint={})",
            self.port,
            self.fingerprint
        );

        let channel = Arc::new(self.clone());
        let tx = Arc::new(tx);

        // Axum route handlers as closures capturing the Arc<WeComChannel>
        let verify_channel = Arc::clone(&channel);
        let callback_channel = Arc::clone(&channel);
        let callback_tx = Arc::clone(&tx);

        let app = Router::new()
            .route(
                "/wecom",
                get(move |Query(query): Query<WeComCallbackQuery>| {
                    let ch = Arc::clone(&verify_channel);
                    async move {
                        tracing::info!("[wecom] GET /wecom — URL verification request");
                        // Verification requests don't need the tx channel
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        let req = WeComInboundRequest {
                            query,
                            body: Bytes::new(),
                            reply_tx,
                        };
                        // Dummy tx - verification only uses reply_tx
                        let (dummy_tx, _) = tokio::sync::mpsc::channel(1);
                        ch.handle_callback(req, &dummy_tx).await;
                        match reply_rx.await {
                            Ok(resp) => {
                                let status = StatusCode::from_u16(resp.status_code)
                                    .unwrap_or(StatusCode::OK);
                                (status, resp.body)
                            }
                            Err(_) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal error".to_string(),
                            ),
                        }
                    }
                }),
            )
            .route(
                "/wecom",
                post(
                    move |Query(query): Query<WeComCallbackQuery>, body: Bytes| {
                        let ch = Arc::clone(&callback_channel);
                        let tx = Arc::clone(&callback_tx);
                        async move {
                            tracing::debug!("[wecom] POST /wecom — encrypted callback");
                            ch.handle_http_request(query, body, &tx).await
                        }
                    },
                ),
            );

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        tracing::info!("[wecom] binding HTTP listener to {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| {
            format!("WeCom: failed to bind HTTP listener on port {}", self.port)
        })?;

        tracing::info!(
            "[wecom] HTTP listener started successfully on {} — ready to receive callbacks",
            listener.local_addr().unwrap_or(addr)
        );
        println!(
            "  GET  /wecom     — WeCom callback URL verification (port {})",
            self.port
        );
        println!(
            "  POST /wecom     — WeCom encrypted callback (port {})",
            self.port
        );

        axum::serve(listener, app).await?;

        tracing::info!("[wecom] HTTP listener exiting");
        Ok(())
    }

    async fn health_check(&self) -> bool {
        match &self.fallback_webhook_url {
            Some(url) => {
                let valid = is_valid_robot_webhook_url(url);
                if !valid {
                    tracing::info!(
                        "WeCom: health check failed \u{2014} invalid fallback webhook URL"
                    );
                }
                valid
            }
            None => true,
        }
    }

    fn supports_draft_updates(&self) -> bool {
        true
    }

    async fn send_draft(&self, message: &SendMessage) -> Result<Option<String>> {
        // thread_ts carries the stream_id from handle_callback
        let stream_id = message.thread_ts.as_deref().unwrap_or("");
        if stream_id.is_empty() {
            return Ok(None);
        }
        // Stream state already bootstrapped in handle_callback; return stream_id as draft ID
        Ok(Some(stream_id.to_string()))
    }

    async fn update_draft(
        &self,
        _recipient: &str,
        message_id: &str,
        content: &str,
    ) -> Result<Option<String>> {
        self.update_stream_state_content(message_id, content, false);
        Ok(None)
    }

    async fn finalize_draft(
        &self,
        _recipient: &str,
        message_id: &str,
        content: &str,
    ) -> Result<()> {
        let (text_without_images, image_paths) = parse_image_markers(content);
        let images = prepare_stream_images(&image_paths).await;

        let (stream_content, overflow) = split_stream_content_and_overflow(&text_without_images);
        self.update_stream_state_with_images(message_id, &stream_content, true, images);

        // Send overflow via webhook fallback chain
        if let Some(extra) = overflow {
            // Determine scope from stream state (recipient is the scope)
            let extra_msg = format!("[\u{8865}\u{5145}\u{6d88}\u{606f}]\n{extra}");
            let scope = _recipient;
            self.send_overflow(scope, &extra_msg).await;
        }

        Ok(())
    }

    async fn cancel_draft(&self, _recipient: &str, message_id: &str) -> Result<()> {
        self.update_stream_state_content(message_id, "", true);
        Ok(())
    }
}

// ── WeComChannel overflow helper ─────────────────────────────────────

impl WeComChannel {
    /// Send overflow message using the 3-layer fallback chain.
    async fn send_overflow(&self, scope: &str, content: &str) {
        let chunks = split_markdown_chunks(content);
        for chunk in chunks {
            let mut sent = false;

            // Level 1: response_url
            while let Some(entry) = self.take_response_url(scope) {
                match self.send_to_url(&entry.url, &chunk).await {
                    Ok(()) => {
                        tracing::info!("WeCom: overflow sent via response_url to scope={}", scope);
                        sent = true;
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "WeCom overflow response_url send failed: scope={} error={}",
                            scope,
                            err
                        );
                    }
                }
            }
            if sent {
                continue;
            }

            // Level 2: scope webhook
            if let Some(url) = self.lookup_scope_webhook(scope).await {
                match self.send_to_url(&url, &chunk).await {
                    Ok(()) => {
                        tracing::info!("WeCom: overflow sent via scope webhook to scope={}", scope);
                        sent = true;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "WeCom overflow scope webhook send failed: scope={} error={}",
                            scope,
                            err
                        );
                    }
                }
            }
            if sent {
                continue;
            }

            // Level 3: fallback webhook
            if let Some(url) = &self.fallback_webhook_url {
                if is_valid_robot_webhook_url(url) {
                    let tagged = format!("[FallbackPush] {chunk}");
                    match self.send_to_url(url, &tagged).await {
                        Ok(()) => {
                            tracing::info!(
                                "WeCom: overflow sent via fallback webhook to scope={}",
                                scope
                            );
                            sent = true;
                        }
                        Err(err) => {
                            tracing::warn!(
                                "WeCom overflow fallback webhook send failed: scope={} error={}",
                                scope,
                                err
                            );
                        }
                    }
                }
            }

            if !sent {
                tracing::warn!("WeCom overflow dropped: no usable URL for scope={}", scope);
            }
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
        .filter(|v| !v.is_empty())
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

/// Compose content for framework: quote context (if any) + normalized user text.
/// Sender prefix and static context are handled by the framework (mod.rs).
fn compose_content_for_framework(inbound: &ParsedInbound, normalized: &str) -> String {
    let quote_context = extract_quote_context(&inbound.raw_payload);
    match quote_context {
        Some(quote) => format!("{quote}\n\n{normalized}"),
        None => normalized.to_string(),
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

fn contains_stop_command(text: &str) -> bool {
    text.contains("\u{505c}\u{6b62}") || text.to_ascii_lowercase().contains("stop")
}

fn is_clear_session_command(text: &str) -> bool {
    let stripped = strip_edge_mentions(text);
    stripped.eq_ignore_ascii_case("/clear") || stripped.eq_ignore_ascii_case("/new")
}

fn strip_edge_mentions(text: &str) -> String {
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
        "stream" => "[Stream refresh callback]".to_string(),
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

fn parse_image_markers(text: &str) -> (String, Vec<String>) {
    let mut cleaned = String::new();
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("[IMAGE:") {
        cleaned.push_str(&rest[..start]);
        let after_tag = &rest[start + 7..];
        if let Some(end) = after_tag.find(']') {
            let path = after_tag[..end].trim();
            if !path.is_empty() {
                paths.push(path.to_string());
            }
            rest = &after_tag[end + 1..];
        } else {
            cleaned.push_str(&rest[start..start + 7]);
            rest = after_tag;
        }
    }
    cleaned.push_str(rest);
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
                tracing::warn!(
                    "WeCom stream image read failed: {} \u{2014} {err:#}",
                    path_str
                );
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

/// Find the largest char boundary <= `max_bytes` in `s`.
fn floor_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut pos = max_bytes;
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_uses_group_shared_mode_by_default_for_group_chat() {
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

        let scopes = compute_scopes(&inbound);
        assert_eq!(scopes.conversation_scope, "group--g1");
        assert!(scopes.shared_group_history);
    }

    #[test]
    fn split_markdown_chunks_preserves_large_input() {
        let input = "a".repeat(WECOM_MARKDOWN_CHUNK_BYTES * 3 + 100);
        let chunks = split_markdown_chunks(&input);
        assert!(chunks.len() >= 3);
        for chunk in chunks {
            assert!(chunk.len() <= WECOM_MARKDOWN_MAX_BYTES);
        }
    }

    #[test]
    fn split_markdown_chunks_small_input() {
        let input = "Hello WeCom!";
        let chunks = split_markdown_chunks(input);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "Hello WeCom!");
    }

    #[test]
    fn split_markdown_chunks_empty_input() {
        let chunks = split_markdown_chunks("");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "");
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
        assert!(!is_valid_robot_webhook_url("not-a-url"));
    }

    #[test]
    fn summarize_attachment_url_for_log_redacts_query_string() {
        let url = "https://wework.qpic.cn/wwpic/123456/0?auth=secret_token&expires=123";
        let summary = summarize_attachment_url_for_log(url);
        assert_eq!(
            summary,
            "https://wework.qpic.cn/wwpic/123456/0 (query=present)"
        );
        assert!(!summary.contains("secret_token"));
    }

    #[test]
    fn summarize_attachment_url_for_log_handles_invalid_input() {
        let summary = summarize_attachment_url_for_log("not a url");
        assert_eq!(summary, "invalid-url(len=9)");
    }

    #[test]
    fn stop_command_detection_supports_cn_and_en() {
        assert!(contains_stop_command("\u{505c}\u{6b62}"));
        assert!(contains_stop_command("Please STOP now"));
        assert!(!contains_stop_command("\u{7ee7}\u{7eed}\u{5904}\u{7406}"));
    }

    #[test]
    fn crypto_encrypt_and_decrypt_roundtrip() {
        let crypto =
            WeComCrypto::new("token123", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY").unwrap();
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
            WeComCrypto::new("token123", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY").unwrap();
        let encrypt = "enc_payload";
        let timestamp = "1700000000";
        let nonce = "nonce123";

        let mut parts = ["token123", timestamp, nonce, encrypt];
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
                    "content": "  \u{5f15}\u{7528}\u{5185}\u{5bb9}  "
                }
            }
        });

        let quote = extract_quote_context(&payload).expect("quote should be extracted");
        assert!(quote.contains("msgtype=text"));
        assert!(quote.contains("content=\u{5f15}\u{7528}\u{5185}\u{5bb9}"));
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
                                "content": "\u{7b2c}\u{4e00}\u{6bb5}"
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
        assert!(quote.contains("\u{7b2c}\u{4e00}\u{6bb5}"));
        assert!(quote.contains("\u{5f15}\u{7528}\u{56fe}\u{7247}"));
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
        assert!(quote.contains("[\u{5f15}\u{7528}\u{56fe}\u{7247}]"));
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
        let input = "\u{5206}\u{6790}\u{7ed3}\u{679c}:\n[IMAGE:/tmp/chart.png]\n\u{8bf7}\u{53c2}\u{8003}\u{3002}";
        let (cleaned, paths) = parse_image_markers(input);
        assert_eq!(paths, vec!["/tmp/chart.png"]);
        assert!(cleaned.contains("\u{5206}\u{6790}\u{7ed3}\u{679c}:"));
        assert!(cleaned.contains("\u{8bf7}\u{53c2}\u{8003}\u{3002}"));
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

    #[test]
    fn clear_session_bare_commands() {
        assert!(is_clear_session_command("/clear"));
        assert!(is_clear_session_command("/new"));
        assert!(is_clear_session_command("/CLEAR"));
        assert!(is_clear_session_command("/New"));
        assert!(is_clear_session_command("  /clear  "));
    }

    #[test]
    fn clear_session_with_mentions() {
        assert!(is_clear_session_command("@bot /clear"));
        assert!(is_clear_session_command("/clear @bot"));
        assert!(is_clear_session_command("@bot1 @bot2 /new"));
        assert!(is_clear_session_command("@bot /new @other"));
    }

    #[test]
    fn clear_session_rejects_old_and_invalid() {
        assert!(!is_clear_session_command("\u{65b0}\u{4f1a}\u{8bdd}"));
        assert!(!is_clear_session_command("clear history"));
        assert!(!is_clear_session_command("/clear now"));
        assert!(!is_clear_session_command("please /new"));
        assert!(!is_clear_session_command(""));
        assert!(!is_clear_session_command("   "));
    }

    #[test]
    fn floor_char_boundary_handles_multibyte() {
        let s = "Hello \u{4f60}\u{597d}\u{4e16}\u{754c}";
        let boundary = floor_char_boundary(s, 8);
        assert!(s.is_char_boundary(boundary));
        assert!(boundary <= 8);
        assert!(boundary == 6 || boundary == 9);
    }

    #[test]
    fn floor_char_boundary_full_string() {
        let s = "Hello";
        let boundary = floor_char_boundary(s, 100);
        assert_eq!(boundary, s.len());
    }
}
