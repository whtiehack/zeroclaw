//! Per-conversation session scope for outbound provider headers.
//!
//! Entry points that own a conversation (channels, gateway) wrap their LLM work
//! in [`scope_session`]; OpenAI-compatible providers then substitute the current
//! session token into any `extra_headers` value containing the `{session}`
//! placeholder. Upstreams that key sticky routing or prompt caching on a session
//! header (OpenRouter `x-session-id`, CLIProxyAPI `x-session-affinity`) therefore
//! see one identity per conversation instead of one per process.
//!
//! Values without the placeholder are passed through untouched, so existing
//! static header configs keep their current behaviour.

use sha2::{Digest, Sha256};

/// Placeholder replaced with the current session token in `extra_headers` values.
pub const SESSION_PLACEHOLDER: &str = "{session}";

/// Token used when a header carries the placeholder but no session scope is
/// active (cron jobs, heartbeat, one-shot tools). Keeps the header a stable,
/// valid value instead of leaving a dangling separator.
const UNSCOPED_TOKEN: &str = "default";

/// Length of the hex-encoded session token. 16 hex chars (64 bits) keeps the
/// header short while leaving collisions irrelevant at conversation scale.
const TOKEN_HEX_LEN: usize = 16;

tokio::task_local! {
    static SESSION_TOKEN: String;
}

/// Derive a short, stable, non-identifying token from a conversation key.
///
/// Conversation keys embed channel-side user and room identifiers (for
/// `wecom_ws`: `wecom_ws_{reply_target}_{sender}`), which must not be handed to
/// third-party upstreams. Hashing keeps the value stable across restarts —
/// the key itself is deterministic — without leaking who the conversation is with.
#[must_use]
pub fn session_token_from_key(conversation_key: &str) -> String {
    let digest = Sha256::digest(conversation_key.as_bytes());
    hex::encode(digest)[..TOKEN_HEX_LEN].to_string()
}

/// Run `future` with the session token derived from `conversation_key`.
///
/// Task-locals do not cross `tokio::spawn`, so this must wrap the future that
/// actually performs the LLM calls rather than being set on a parent task.
pub async fn scope_session<F: std::future::Future>(conversation_key: &str, future: F) -> F::Output {
    SESSION_TOKEN
        .scope(session_token_from_key(conversation_key), future)
        .await
}

/// Current session token, or `None` outside a [`scope_session`].
#[must_use]
pub fn current_session_token() -> Option<String> {
    SESSION_TOKEN.try_with(Clone::clone).ok()
}

/// Substitute [`SESSION_PLACEHOLDER`] in a header value with the current session
/// token. Returns `None` when the value has no placeholder, letting callers skip
/// the allocation on the common path.
#[must_use]
pub fn substitute_session_placeholder(value: &str) -> Option<String> {
    if !value.contains(SESSION_PLACEHOLDER) {
        return None;
    }
    let token = current_session_token().unwrap_or_else(|| UNSCOPED_TOKEN.to_string());
    Some(value.replace(SESSION_PLACEHOLDER, &token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_stable_and_short() {
        let a = session_token_from_key("wecom_ws_room1_user1");
        let b = session_token_from_key("wecom_ws_room1_user1");
        assert_eq!(a, b);
        assert_eq!(a.len(), TOKEN_HEX_LEN);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn token_differs_per_conversation() {
        assert_ne!(
            session_token_from_key("wecom_ws_room1_user1"),
            session_token_from_key("wecom_ws_room1_user2")
        );
    }

    #[test]
    fn token_does_not_leak_raw_key() {
        let token = session_token_from_key("wecom_ws_room1_alice@example.com");
        assert!(!token.contains("alice"));
        assert!(!token.contains("room1"));
    }

    #[test]
    fn value_without_placeholder_is_untouched() {
        assert_eq!(substitute_session_placeholder("zeroclaw-wecom-test"), None);
    }

    #[tokio::test]
    async fn placeholder_uses_scoped_token() {
        let expected = format!(
            "zeroclaw-wecom-test-{}",
            session_token_from_key("wecom_ws_room1_user1")
        );
        let got = scope_session("wecom_ws_room1_user1", async {
            substitute_session_placeholder("zeroclaw-wecom-test-{session}")
        })
        .await;
        assert_eq!(got, Some(expected));
    }

    #[test]
    fn placeholder_outside_scope_falls_back() {
        assert_eq!(
            substitute_session_placeholder("zc-{session}"),
            Some(format!("zc-{UNSCOPED_TOKEN}"))
        );
    }
}
