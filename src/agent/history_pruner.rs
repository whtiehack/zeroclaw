use crate::providers::traits::ChatMessage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_max_tokens() -> usize {
    8192
}

fn default_keep_recent() -> usize {
    4
}

fn default_collapse() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HistoryPrunerConfig {
    /// Enable history pruning. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum estimated tokens for message history. Default: 8192.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,
    /// Keep the N most recent messages untouched. Default: 4.
    #[serde(default = "default_keep_recent")]
    pub keep_recent: usize,
    /// Collapse old tool call/result pairs into short summaries. Default: true.
    #[serde(default = "default_collapse")]
    pub collapse_tool_results: bool,
}

impl Default for HistoryPrunerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tokens: 8192,
            keep_recent: 4,
            collapse_tool_results: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneStats {
    pub messages_before: usize,
    pub messages_after: usize,
    pub collapsed_pairs: usize,
    pub dropped_messages: usize,
}

// ---------------------------------------------------------------------------
// Token estimation
// ---------------------------------------------------------------------------

fn estimate_tokens(messages: &[ChatMessage]) -> usize {
    messages.iter().map(|m| m.content.len() / 4).sum()
}

// ---------------------------------------------------------------------------
// Protected-index helpers
// ---------------------------------------------------------------------------

fn protected_indices(messages: &[ChatMessage], keep_recent: usize) -> Vec<bool> {
    let len = messages.len();
    let mut protected = vec![false; len];
    for (i, msg) in messages.iter().enumerate() {
        if msg.role == "system" {
            protected[i] = true;
        }
    }
    let recent_start = len.saturating_sub(keep_recent);
    for p in protected.iter_mut().skip(recent_start) {
        *p = true;
    }
    protected
}

// ---------------------------------------------------------------------------
// Orphan tool self-heal
// ---------------------------------------------------------------------------

/// Remove `tool`-role messages whose `tool_call_id` has no matching
/// `tool_use` / `tool_calls` entry in a preceding assistant message.
///
/// After any history truncation (drain, remove, prune) the first surviving
/// message(s) may be `tool` results whose assistant request was trimmed away.
/// The Anthropic API (and others) reject these with a 400 error.
///
/// Returns the number of messages removed.
pub fn remove_orphaned_tool_messages(messages: &mut Vec<ChatMessage>) -> usize {
    // Pass 1: Remove assistant(tool_calls) + their tool_results when the
    // assistant is preceded by another assistant. Normalization would merge
    // them, destroying structured tool_use blocks and orphaning the results.
    let mut removed = 0usize;
    let mut i = 0;
    while i < messages.len() {
        if messages[i].role == "assistant"
            && extract_assistant_tool_call_ids(&messages[i].content).is_some()
            && i > 0
            && messages[i - 1].role == "assistant"
        {
            let doomed_ids =
                extract_assistant_tool_call_ids(&messages[i].content).unwrap_or_default();
            messages.remove(i);
            removed += 1;
            while i < messages.len() && messages[i].role == "tool" {
                let dominated = match extract_tool_call_id(&messages[i].content) {
                    Some(id) => doomed_ids.iter().any(|d| d == &id),
                    None => true,
                };
                if dominated {
                    messages.remove(i);
                    removed += 1;
                } else {
                    break;
                }
            }
        } else {
            i += 1;
        }
    }

    // Pass 2: Remove remaining orphan tool messages whose tool_call_id
    // is not in the preceding assistant's structured tool_calls array.
    // A substring match on the assistant's *text* is NOT sufficient —
    // compaction summaries are instructed to preserve identifiers, so an
    // id can appear in prose without an actual tool_use block backing it
    // (see #5813).
    i = 0;
    while i < messages.len() {
        if messages[i].role != "tool" {
            i += 1;
            continue;
        }

        let assistant_idx = (0..i)
            .rev()
            .take_while(|&j| messages[j].role == "assistant" || messages[j].role == "tool")
            .find(|&j| messages[j].role == "assistant");

        let is_orphan = match assistant_idx {
            None => true,
            Some(idx) => match extract_assistant_tool_call_ids(&messages[idx].content) {
                None => true,
                Some(ids) => match extract_tool_call_id(&messages[i].content) {
                    Some(tool_call_id) => !ids.iter().any(|id| id == &tool_call_id),
                    None => false,
                },
            },
        };

        if is_orphan {
            messages.remove(i);
            removed += 1;
        } else {
            i += 1;
        }
    }
    if removed > 0 {
        tracing::warn!(
            count = removed,
            "Removed {removed} orphaned tool message(s) from history — this indicates a prior \
             tool_use/tool_result pairing inconsistency that was auto-healed"
        );
    }
    removed
}

/// Try to extract a `tool_call_id` from a tool-role message's JSON content.
///
/// Tool messages are stored as JSON like:
/// `{"content": "...", "tool_call_id": "toolu_01Abc..."}`
fn extract_tool_call_id(content: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    value
        .get("tool_call_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract the list of structured tool-call IDs an assistant message
/// is claiming to have invoked, if any. Returns `None` when the content
/// does not parse as a JSON object with a `tool_calls` array — meaning the
/// assistant has no native tool_use blocks backing any tool_results.
fn extract_assistant_tool_call_ids(content: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let arr = value.get("tool_calls")?.as_array()?;
    let ids: Vec<String> = arr
        .iter()
        .filter_map(|call| call.get("id").and_then(|v| v.as_str()).map(str::to_owned))
        .collect();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn prune_history(messages: &mut Vec<ChatMessage>, config: &HistoryPrunerConfig) -> PruneStats {
    let messages_before = messages.len();
    if !config.enabled || messages.is_empty() {
        return PruneStats {
            messages_before,
            messages_after: messages_before,
            collapsed_pairs: 0,
            dropped_messages: 0,
        };
    }

    let mut collapsed_pairs: usize = 0;

    // Phase 1 – collapse assistant+tool groups atomically.
    // An assistant message followed by one or more consecutive tool messages
    // forms an atomic group (tool_use + tool_result pairing). Collapsing only
    // part of the group would orphan tool_use blocks, causing API 400 errors
    // from providers that enforce pairing (e.g., Anthropic). See #4810.
    //
    // The group is collapsed only when *every* tool in it is unprotected —
    // the same all-or-nothing rule Phase 2 uses. If `keep_recent` protects
    // any tool in the group we skip the whole group. Partial collapse would
    // leave a protected tool behind whose parent assistant has been
    // rewritten to a summary with no "tool_calls" marker, which Phase 3's
    // orphan sweep then evicts — silently violating `keep_recent`. See
    // #5823.
    if config.collapse_tool_results {
        let mut i = 0;
        while i < messages.len() {
            let protected = protected_indices(messages, config.keep_recent);
            if messages[i].role == "assistant" && !protected[i] {
                // Count consecutive tool messages following this assistant
                // and remember whether any of them is protected.
                let mut tool_count = 0;
                let mut any_tool_protected = false;
                while i + 1 + tool_count < messages.len()
                    && messages[i + 1 + tool_count].role == "tool"
                {
                    if protected[i + 1 + tool_count] {
                        any_tool_protected = true;
                    }
                    tool_count += 1;
                }
                if tool_count > 0 && !any_tool_protected {
                    let summary =
                        format!("[Tool exchange: {tool_count} tool call(s) — results collapsed]");
                    messages[i] = ChatMessage {
                        role: "assistant".to_string(),
                        content: summary,
                    };
                    for _ in 0..tool_count {
                        messages.remove(i + 1);
                    }
                    collapsed_pairs += tool_count;
                    continue;
                }
                if tool_count > 0 {
                    // Protected tool inside the group → skip the whole
                    // group intact so Phase 3's orphan sweep has no
                    // pretext to remove those tools.
                    i += 1 + tool_count;
                    continue;
                }
            }
            i += 1;
        }
    }

    // Phase 2 – budget enforcement: drop messages to fit token budget.
    // Tool groups (assistant + consecutive tool messages) are dropped
    // atomically to preserve tool_use/tool_result pairing. See #4810.
    let mut dropped_messages: usize = 0;
    while estimate_tokens(messages) > config.max_tokens {
        let protected = protected_indices(messages, config.keep_recent);
        let mut dropped_any = false;
        let mut i = 0;
        while i < messages.len() {
            if protected[i] {
                i += 1;
                continue;
            }
            if messages[i].role == "assistant" {
                // Count following tool messages — drop as atomic group
                let mut tool_count = 0;
                while i + 1 + tool_count < messages.len()
                    && messages[i + 1 + tool_count].role == "tool"
                {
                    tool_count += 1;
                }
                if tool_count > 0 {
                    for _ in 0..=tool_count {
                        messages.remove(i);
                    }
                    dropped_messages += 1 + tool_count;
                    dropped_any = true;
                    break;
                }
            }
            // Non-tool-group message — safe to drop individually
            messages.remove(i);
            dropped_messages += 1;
            dropped_any = true;
            break;
        }
        if !dropped_any {
            break;
        }
    }

    PruneStats {
        messages_before,
        messages_after: messages.len(),
        collapsed_pairs,
        dropped_messages,
    }
}

#[cfg(test)]
mod tests;
