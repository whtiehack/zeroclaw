use super::traits::{Channel, ChannelMessage, SendMessage};
use crate::memory::Memory;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// WeCom (企业微信) channel — webhook-based, push via group-bot webhook.
///
/// This channel operates in webhook mode (push-based).
/// Messages are received via the gateway's `/wecom` webhook endpoint where
/// the gateway handles AES decryption / signature verification / stream protocol.
/// The `listen` method here is a keepalive placeholder.
///
/// Outbound messages use a 3-layer fallback:
/// 1. response_url (cached from incoming messages, TTL 1 hour)
/// 2. scope-specific push webhook (looked up from memory)
/// 3. fallback push webhook (from config)
pub struct WeComChannel {
    memory: Arc<dyn Memory>,
    fallback_webhook_url: Option<String>,
    client: reqwest::Client,
    /// response_url cache: scope -> FIFO queue of response URLs
    response_urls: Arc<Mutex<HashMap<String, VecDeque<ResponseUrlEntry>>>>,
    cache_config: ResponseUrlCacheConfig,
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
    /// TTL for cached response_urls (default: 3600 seconds)
    ttl_secs: u64,
    /// Maximum entries per scope (default: 20)
    max_per_scope: usize,
}

const WECOM_MARKDOWN_MAX_BYTES: usize = 20_480;
const WECOM_MARKDOWN_CHUNK_BYTES: usize = 8_000;

impl WeComChannel {
    pub fn new(
        memory: Arc<dyn Memory>,
        fallback_webhook_url: Option<String>,
        cache_ttl_secs: u64,
        cache_max_per_scope: usize,
    ) -> Self {
        Self {
            memory,
            fallback_webhook_url,
            client: crate::config::build_runtime_proxy_client("channel.wecom"),
            response_urls: Arc::new(Mutex::new(HashMap::new())),
            cache_config: ResponseUrlCacheConfig {
                ttl_secs: cache_ttl_secs,
                max_per_scope: cache_max_per_scope,
            },
        }
    }

    /// Cache a response_url for later use (called by gateway on message receipt).
    ///
    /// The response_url is stored in a FIFO queue per scope with TTL and size limits.
    pub fn cache_response_url(&self, scope: &str, msg_id: &str, url: Option<&str>) {
        let Some(url) = url.map(str::trim).filter(|v| !v.is_empty()) else {
            return;
        };

        tracing::debug!(
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

        // Enforce size limit (FIFO eviction)
        while queue.len() > self.cache_config.max_per_scope {
            queue.pop_front();
        }
    }

    /// Take the next available response_url for a scope (FIFO, with expiration check).
    fn take_response_url(&self, scope: &str) -> Option<ResponseUrlEntry> {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        let queue = cache.get_mut(scope)?;

        // Remove expired entries
        queue.retain(|entry| entry.expires_at > now);
        if queue.is_empty() {
            return None;
        }

        // Take the oldest entry (FIFO)
        queue.pop_front()
    }

    /// Prune expired response_urls across all scopes (called periodically).
    fn prune_response_urls(&self) {
        let now = Instant::now();
        let mut cache = self.response_urls.lock();
        cache.retain(|_, queue| {
            queue.retain(|entry| entry.expires_at > now);
            !queue.is_empty()
        });
    }

    /// Parse a decrypted WeCom AI Bot callback payload into channel messages.
    ///
    /// The `payload` is the JSON value after AES decryption by the gateway.
    /// Field names follow WeCom AI Bot callback format (lowercase keys).
    pub fn parse_webhook_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let msg_type = payload
            .get("msgtype")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Only handle content-bearing message types
        if !matches!(msg_type, "text" | "voice" | "image" | "file" | "mixed") {
            return Vec::new();
        }

        let content = extract_text_content(payload, msg_type);
        if content.is_empty() {
            return Vec::new();
        }

        let sender_userid = payload
            .get("from")
            .and_then(|v| v.get("userid"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if sender_userid.is_empty() {
            return Vec::new();
        }

        let msg_id = payload
            .get("msgid")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let chat_type = payload
            .get("chattype")
            .and_then(|v| v.as_str())
            .unwrap_or("single");

        let conversation_scope = if chat_type == "group" {
            if let Some(chat_id) = payload.get("chatid").and_then(|v| v.as_str()) {
                format!("group:{chat_id}")
            } else {
                format!("user:{sender_userid}")
            }
        } else {
            format!("user:{sender_userid}")
        };

        let content_preview: String = content.chars().take(80).collect();
        tracing::info!(
            "WeCom: received {} message from {} in {}, msg_id={}, len={}",
            msg_type,
            sender_userid,
            conversation_scope,
            msg_id,
            content.len()
        );
        tracing::debug!("WeCom: content preview: {content_preview}");

        vec![ChannelMessage {
            id: msg_id,
            sender: sender_userid,
            reply_target: conversation_scope,
            content,
            channel: "wecom".to_string(),
            timestamp,
            thread_ts: None,
        }]
    }

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

    /// Send markdown content to a WeCom group-bot webhook URL.
    async fn send_to_url(&self, url: &str, content: &str) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "content": content,
            }
        });

        let resp = self.client.post(url).json(&payload).send().await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("WeCom webhook send failed: {status} — {body}");
        }

        // Check WeCom business-level error
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
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
}

#[async_trait]
impl Channel for WeComChannel {
    fn name(&self) -> &str {
        "wecom"
    }

    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        let scope = &message.recipient;
        let chunks = split_markdown_chunks(&message.content);

        tracing::info!(
            "WeCom: sending message to scope={}, len={}, chunks={}",
            scope,
            message.content.len(),
            chunks.len()
        );

        // Prune expired entries before sending
        self.prune_response_urls();

        for chunk in chunks {
            let mut sent = false;

            // Level 1: response_url (from cache, FIFO with TTL)
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

            // Level 2: scope-specific push webhook (from memory)
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

            // Level 3: fallback push webhook (from config)
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

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        // WeCom uses webhooks (push-based), not polling.
        // Messages are received via the gateway's /wecom endpoint.
        tracing::info!(
            "WeCom channel active (webhook mode). \
            Configure WeCom callback to POST to your gateway's /wecom endpoint."
        );

        // Keep the task alive — it will be cancelled when the channel shuts down
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    async fn health_check(&self) -> bool {
        // Healthy if fallback webhook is valid (or not configured at all)
        match &self.fallback_webhook_url {
            Some(url) => {
                let valid = is_valid_robot_webhook_url(url);
                if !valid {
                    tracing::debug!("WeCom: health check failed — invalid fallback webhook URL");
                }
                valid
            }
            None => true,
        }
    }
}

/// Validate that a URL is a legitimate WeCom group-bot webhook URL.
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

/// Extract text content from a WeCom payload based on message type.
fn extract_text_content(payload: &serde_json::Value, msg_type: &str) -> String {
    match msg_type {
        "text" => payload
            .get("text")
            .and_then(|v| v.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        "voice" => payload
            .get("voice")
            .and_then(|v| v.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        "mixed" => {
            let mut parts = Vec::new();
            if let Some(items) = payload
                .get("mixed")
                .and_then(|v| v.get("msg_item"))
                .and_then(|v| v.as_array())
            {
                for item in items {
                    let item_type = item
                        .get("msgtype")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if item_type == "text" {
                        if let Some(text) = item
                            .get("text")
                            .and_then(|v| v.get("content"))
                            .and_then(|v| v.as_str())
                        {
                            let trimmed = text.trim();
                            if !trimmed.is_empty() {
                                parts.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
            parts.join("\n\n")
        }
        // Image and file messages produce markers in the gateway's normalize_message;
        // the channel layer just reports an indicator.
        "image" => "[Image message]".to_string(),
        "file" => "[File message]".to_string(),
        _ => String::new(),
    }
}

/// Split markdown content into chunks for WeCom's 20 KB per-message limit.
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
            // Force split at byte boundary
            let mut remainder = current.as_str();
            while !remainder.is_empty() {
                let cut = floor_char_boundary(remainder, WECOM_MARKDOWN_CHUNK_BYTES);
                let cut = cut.max(1);
                chunks.push(remainder[..cut].to_string());
                remainder = &remainder[cut..];
            }
        }
    }

    chunks
}

/// Find the largest char boundary ≤ `max_bytes` in `s`.
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

    fn test_memory() -> Arc<dyn Memory> {
        let cfg = crate::config::MemoryConfig {
            backend: "markdown".into(),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("zeroclaw_wecom_test");
        Arc::from(crate::memory::create_memory(&cfg, &dir, None).unwrap())
    }

    fn make_channel() -> WeComChannel {
        WeComChannel::new(test_memory(), None, 3600, 20)
    }

    #[test]
    fn wecom_channel_name() {
        let ch = make_channel();
        assert_eq!(ch.name(), "wecom");
    }

    #[test]
    fn wecom_parse_text_message() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "text",
            "msgid": "msg_001",
            "chattype": "single",
            "from": { "userid": "test_user" },
            "text": { "content": "Hello WeCom!" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "test_user");
        assert_eq!(msgs[0].content, "Hello WeCom!");
        assert_eq!(msgs[0].channel, "wecom");
        assert_eq!(msgs[0].reply_target, "user:test_user");
        assert_eq!(msgs[0].id, "msg_001");
    }

    #[test]
    fn wecom_parse_group_message() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "text",
            "msgid": "msg_002",
            "chattype": "group",
            "chatid": "chat_group_1",
            "from": { "userid": "test_user" },
            "text": { "content": "Group hello" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].reply_target, "group:chat_group_1");
    }

    #[test]
    fn wecom_parse_empty_content_skipped() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "text",
            "from": { "userid": "test_user" },
            "text": { "content": "   " }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn wecom_parse_event_type_skipped() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "event",
            "event": { "eventtype": "enter_chat" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn wecom_parse_stream_type_skipped() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "stream",
            "stream": { "id": "sid1" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn wecom_parse_missing_sender_skipped() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "text",
            "text": { "content": "No sender" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn wecom_parse_voice_message() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "voice",
            "msgid": "msg_voice_1",
            "chattype": "single",
            "from": { "userid": "test_user" },
            "voice": { "content": "Transcribed text from voice" }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Transcribed text from voice");
    }

    #[test]
    fn wecom_parse_mixed_message() {
        let ch = make_channel();

        let payload = serde_json::json!({
            "msgtype": "mixed",
            "msgid": "msg_mixed_1",
            "chattype": "single",
            "from": { "userid": "test_user" },
            "mixed": {
                "msg_item": [
                    { "msgtype": "text", "text": { "content": "Part 1" } },
                    { "msgtype": "image", "image": { "url": "https://example.com/img.png" } },
                    { "msgtype": "text", "text": { "content": "Part 2" } }
                ]
            }
        });

        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].content.contains("Part 1"));
        assert!(msgs[0].content.contains("Part 2"));
    }

    #[test]
    fn wecom_robot_webhook_url_validation() {
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
    fn wecom_split_markdown_chunks_small_input() {
        let input = "Hello WeCom!";
        let chunks = split_markdown_chunks(input);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "Hello WeCom!");
    }

    #[test]
    fn wecom_split_markdown_chunks_large_input() {
        let input = "a".repeat(WECOM_MARKDOWN_CHUNK_BYTES * 3 + 100);
        let chunks = split_markdown_chunks(&input);
        assert!(chunks.len() >= 3);
        for chunk in &chunks {
            assert!(chunk.len() <= WECOM_MARKDOWN_MAX_BYTES);
        }
    }

    #[test]
    fn wecom_split_markdown_chunks_empty_input() {
        let chunks = split_markdown_chunks("");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "");
    }

    #[tokio::test]
    async fn wecom_health_check_no_fallback() {
        let ch = make_channel();
        assert!(ch.health_check().await);
    }

    #[tokio::test]
    async fn wecom_health_check_valid_fallback() {
        let ch = WeComChannel::new(
            test_memory(),
            Some("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test".to_string()),
            3600,
            20,
        );
        assert!(ch.health_check().await);
    }

    #[tokio::test]
    async fn wecom_health_check_invalid_fallback() {
        let ch = WeComChannel::new(
            test_memory(),
            Some("http://bad-url.com".to_string()),
            3600,
            20,
        );
        assert!(!ch.health_check().await);
    }

    #[test]
    fn floor_char_boundary_handles_multibyte() {
        let s = "Hello 你好世界";
        // "Hello " = 6 bytes, "你" = 3 bytes, "好" = 3 bytes, "世" = 3 bytes, "界" = 3 bytes
        // Total = 18 bytes
        let boundary = floor_char_boundary(s, 8);
        assert!(s.is_char_boundary(boundary));
        assert!(boundary <= 8);
        // Should be 6 (just "Hello ") or 9 (include "你")
        assert!(boundary == 6 || boundary == 9);
    }

    #[test]
    fn floor_char_boundary_full_string() {
        let s = "Hello";
        let boundary = floor_char_boundary(s, 100);
        assert_eq!(boundary, s.len());
    }

    #[test]
    fn wecom_cache_response_url_basic() {
        let ch = make_channel();
        ch.cache_response_url("user:alice", "msg_001", Some("https://example.com/url1"));
        ch.cache_response_url("user:alice", "msg_002", Some("https://example.com/url2"));

        // Should retrieve in FIFO order
        let entry1 = ch.take_response_url("user:alice");
        assert!(entry1.is_some());
        assert_eq!(entry1.unwrap().url, "https://example.com/url1");

        let entry2 = ch.take_response_url("user:alice");
        assert!(entry2.is_some());
        assert_eq!(entry2.unwrap().url, "https://example.com/url2");

        // Queue should be empty now
        let entry3 = ch.take_response_url("user:alice");
        assert!(entry3.is_none());
    }

    #[test]
    fn wecom_cache_response_url_ignores_empty() {
        let ch = make_channel();
        ch.cache_response_url("user:bob", "msg_001", Some(""));
        ch.cache_response_url("user:bob", "msg_002", Some("   "));
        ch.cache_response_url("user:bob", "msg_003", None);

        // All should be ignored
        let entry = ch.take_response_url("user:bob");
        assert!(entry.is_none());
    }

    #[test]
    fn wecom_cache_response_url_size_limit() {
        let ch = WeComChannel::new(test_memory(), None, 3600, 3); // max 3 entries

        for i in 1..=5 {
            ch.cache_response_url(
                "user:charlie",
                &format!("msg_{:03}", i),
                Some(&format!("https://example.com/url{}", i)),
            );
        }

        // Should only have the last 3 (FIFO eviction)
        let entry1 = ch.take_response_url("user:charlie");
        assert_eq!(entry1.unwrap().url, "https://example.com/url3");

        let entry2 = ch.take_response_url("user:charlie");
        assert_eq!(entry2.unwrap().url, "https://example.com/url4");

        let entry3 = ch.take_response_url("user:charlie");
        assert_eq!(entry3.unwrap().url, "https://example.com/url5");

        let entry4 = ch.take_response_url("user:charlie");
        assert!(entry4.is_none());
    }

    #[test]
    fn wecom_cache_response_url_ttl_expiration() {
        let ch = WeComChannel::new(test_memory(), None, 0, 20); // TTL = 0 seconds (immediate expiration)

        ch.cache_response_url("user:dave", "msg_001", Some("https://example.com/url1"));

        // Should be expired immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        let entry = ch.take_response_url("user:dave");
        assert!(entry.is_none());
    }

    #[test]
    fn wecom_prune_response_urls_removes_expired() {
        let ch = WeComChannel::new(test_memory(), None, 0, 20); // TTL = 0 seconds

        ch.cache_response_url("user:eve", "msg_001", Some("https://example.com/url1"));
        ch.cache_response_url("user:frank", "msg_002", Some("https://example.com/url2"));

        std::thread::sleep(std::time::Duration::from_millis(10));
        ch.prune_response_urls();

        // Both should be pruned
        assert!(ch.take_response_url("user:eve").is_none());
        assert!(ch.take_response_url("user:frank").is_none());
    }
}
