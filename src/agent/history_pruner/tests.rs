use super::*;

fn msg(role: &str, content: &str) -> ChatMessage {
    ChatMessage {
        role: role.to_string(),
        content: content.to_string(),
    }
}

#[test]
fn prune_disabled_is_noop() {
    let mut messages = vec![
        msg("system", "You are helpful."),
        msg("user", "Hello"),
        msg("assistant", "Hi there!"),
    ];
    let config = HistoryPrunerConfig {
        enabled: false,
        ..Default::default()
    };
    let stats = prune_history(&mut messages, &config);
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].content, "You are helpful.");
    assert_eq!(stats.messages_before, 3);
    assert_eq!(stats.messages_after, 3);
    assert_eq!(stats.collapsed_pairs, 0);
}

#[test]
fn prune_under_budget_no_change() {
    let mut messages = vec![
        msg("system", "You are helpful."),
        msg("user", "Hello"),
        msg("assistant", "Hi!"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 8192,
        keep_recent: 2,
        collapse_tool_results: false,
    };
    let stats = prune_history(&mut messages, &config);
    assert_eq!(messages.len(), 3);
    assert_eq!(stats.collapsed_pairs, 0);
    assert_eq!(stats.dropped_messages, 0);
}

#[test]
fn prune_collapses_tool_pairs() {
    let tool_result = "a".repeat(160);
    let mut messages = vec![
        msg("system", "sys"),
        msg("assistant", "calling tool X"),
        msg("tool", &tool_result),
        msg("user", "thanks"),
        msg("assistant", "done"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 100_000,
        keep_recent: 2,
        collapse_tool_results: true,
    };
    let stats = prune_history(&mut messages, &config);
    assert_eq!(stats.collapsed_pairs, 1);
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[1].role, "assistant");
    assert!(messages[1].content.contains("1 tool call(s)"));
}

#[test]
fn prune_preserves_system_and_recent() {
    let big = "x".repeat(40_000);
    let mut messages = vec![
        msg("system", "system prompt"),
        msg("user", &big),
        msg("assistant", "old reply"),
        msg("user", "recent1"),
        msg("assistant", "recent2"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 100,
        keep_recent: 2,
        collapse_tool_results: false,
    };
    let stats = prune_history(&mut messages, &config);
    assert!(messages.iter().any(|m| m.role == "system"));
    assert!(messages.iter().any(|m| m.content == "recent1"));
    assert!(messages.iter().any(|m| m.content == "recent2"));
    assert!(stats.dropped_messages > 0);
}

#[test]
fn prune_drops_oldest_when_over_budget() {
    let filler = "y".repeat(400);
    let mut messages = vec![
        msg("system", "sys"),
        msg("user", &filler),
        msg("assistant", &filler),
        msg("user", "recent-user"),
        msg("assistant", "recent-assistant"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 150,
        keep_recent: 2,
        collapse_tool_results: false,
    };
    let stats = prune_history(&mut messages, &config);
    assert!(stats.dropped_messages >= 1);
    assert_eq!(messages[0].role, "system");
    assert!(messages.iter().any(|m| m.content == "recent-user"));
    assert!(messages.iter().any(|m| m.content == "recent-assistant"));
}

#[test]
fn prune_empty_messages() {
    let mut messages: Vec<ChatMessage> = vec![];
    let config = HistoryPrunerConfig {
        enabled: true,
        ..Default::default()
    };
    let stats = prune_history(&mut messages, &config);
    assert_eq!(stats.messages_before, 0);
    assert_eq!(stats.messages_after, 0);
}

#[test]
fn prune_collapses_multi_tool_group() {
    let mut messages = vec![
        msg("system", "sys"),
        msg(
            "assistant",
            r#"{"content":null,"tool_calls":[{"id":"t1","name":"shell","arguments":"{}"},{"id":"t2","name":"web","arguments":"{}"}]}"#,
        ),
        msg("tool", r#"{"tool_call_id":"t1","content":"result1"}"#),
        msg("tool", r#"{"tool_call_id":"t2","content":"result2"}"#),
        msg("user", "thanks"),
        msg("assistant", "done"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 100_000,
        keep_recent: 2,
        collapse_tool_results: true,
    };
    let stats = prune_history(&mut messages, &config);
    assert_eq!(stats.collapsed_pairs, 2);
    // assistant(tool_calls) + 2 tool messages → 1 summary assistant
    assert_eq!(messages.len(), 4); // sys, summary, user, assistant
    assert!(messages[1].content.contains("2 tool call(s)"));
    // No tool messages remain
    assert!(!messages.iter().any(|m| m.role == "tool"));
}

#[test]
fn prune_drops_tool_group_atomically() {
    let big = "x".repeat(2000);
    let mut messages = vec![
        msg("system", "sys"),
        msg("assistant", &big),
        msg("tool", &big),
        msg("tool", &big),
        msg("user", "recent"),
        msg("assistant", "recent reply"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 50, // very low — forces drops
        keep_recent: 2,
        collapse_tool_results: false, // skip collapse, go straight to drop
    };
    let stats = prune_history(&mut messages, &config);
    assert!(stats.dropped_messages >= 3); // assistant + 2 tools dropped together
                                          // No orphaned tool messages
    for (i, m) in messages.iter().enumerate() {
        if m.role == "tool" {
            assert!(
                i > 0 && messages[i - 1].role == "assistant",
                "tool message at index {i} has no preceding assistant"
            );
        }
    }
}

#[test]
fn prune_never_orphans_tool_use() {
    // Simulate a conversation with multiple tool groups
    let filler = "y".repeat(500);
    let mut messages = vec![
        msg("system", "sys"),
        msg("user", "q1"),
        msg("assistant", &filler), // tool group 1
        msg("tool", &filler),
        msg("user", "q2"),
        msg("assistant", &filler), // tool group 2
        msg("tool", &filler),
        msg("tool", &filler),
        msg("user", "recent"),
        msg("assistant", "recent reply"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 100,
        keep_recent: 2,
        collapse_tool_results: true,
    };
    prune_history(&mut messages, &config);
    // Verify invariant: no tool message without a preceding assistant
    for (i, m) in messages.iter().enumerate() {
        if m.role == "tool" {
            assert!(
                i > 0 && messages[i - 1].role == "assistant",
                "orphaned tool message at index {i}: {:?}",
                messages.iter().map(|m| &m.role).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn prune_protects_recent_tool_groups() {
    let mut messages = vec![
        msg("system", "sys"),
        msg("user", "old"),
        msg("assistant", "old reply"),
        msg("assistant", "tool call"),
        msg("tool", "tool result"),
        msg("user", "recent"),
    ];
    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 100_000,
        keep_recent: 3, // protects last 3: tool call, tool result, recent
        collapse_tool_results: true,
    };
    let stats = prune_history(&mut messages, &config);
    // Protected tool group should not be collapsed
    assert!(messages.iter().any(|m| m.role == "tool"));
    assert_eq!(stats.collapsed_pairs, 0);
}

#[test]
fn prune_under_realistic_token_pressure_preserves_tool_pairing() {
    // Simulate 15 tool iterations with realistic content sizes
    let mut messages = vec![msg("system", "You are helpful.")];
    messages.push(msg("user", "Research this topic thoroughly"));

    // 15 tool iterations — each adds assistant(tool_calls) + tool(result)
    for i in 0..15 {
        let tool_json = format!(
            r#"{{"content":"iteration {i}","tool_calls":[{{"id":"t{i}","name":"web_search","arguments":"{{}}"}}]}}"#
        );
        messages.push(msg("assistant", &tool_json));
        // Realistic tool result size (~2K chars each)
        let result = format!(
            r#"{{"tool_call_id":"t{i}","content":"{}"}}"#,
            "x".repeat(2000)
        );
        messages.push(msg("tool", &result));
    }
    messages.push(msg("assistant", "Here's what I found..."));

    // 33 messages total: system + user + 15*(assistant+tool) + final assistant
    assert_eq!(messages.len(), 33);

    let config = HistoryPrunerConfig {
        enabled: true,
        max_tokens: 2000, // Forces pruning of older iterations
        keep_recent: 4,
        collapse_tool_results: true,
    };

    prune_history(&mut messages, &config);

    // Invariant: no orphaned tool messages after pruning
    for (i, m) in messages.iter().enumerate() {
        if m.role == "tool" {
            assert!(
                i > 0 && messages[i - 1].role == "assistant",
                "orphaned tool at index {i}: roles = {:?}",
                messages.iter().map(|m| &m.role).collect::<Vec<_>>()
            );
        }
    }
}

/// Regression test for issue #5813: a compaction summary preserves
/// identifiers by design (UUIDs, tokens, tool_call_ids). That means the
/// summary text may contain the tool_call_id of a tool_result whose
/// tool_use was dropped. The orphan detector must not be fooled by a
/// substring match on the summary — it must confirm the id appears in
/// a structured tool_calls array.
#[test]
fn orphan_tool_not_fooled_by_id_in_summary_text() {
    let summary = "[CONTEXT SUMMARY \u{2014} 4 messages compressed]\n\
         Earlier turns invoked shell with tool_calls id toolu_01Orphan \
         and returned ok.";
    let mut messages = vec![
        msg("system", "sys"),
        msg("assistant", summary),
        msg(
            "tool",
            r#"{"tool_call_id":"toolu_01Orphan","content":"stale"}"#,
        ),
        msg("user", "new question"),
    ];
    let removed = remove_orphaned_tool_messages(&mut messages);
    assert_eq!(
        removed, 1,
        "orphan must be removed even if its id is mentioned in summary text"
    );
    assert!(!messages.iter().any(|m| m.role == "tool"));
}

/// Regression for #5823:
///
/// When `keep_recent` protects the *tail* of a multi-tool group but not
/// the preceding assistant, Phase 1 used to collapse the unprotected
/// tools and rewrite the assistant to a summary that no longer contained
/// `"tool_calls"`. Phase 3's orphan sweep then classified the still-live
/// protected tool as an orphan (because the new summary does not contain
/// `"tool_calls"`) and removed it — silently violating `keep_recent`.
///
/// After the fix Phase 1 treats the group as atomic: if any tool in it
/// is protected, the entire group is left intact.
#[test]
fn prune_does_not_evict_protected_tool_when_group_straddles_keep_recent() {
    let mut messages = vec![
        msg("system", "sys"),
        msg("user", "query"),
        msg(
            "assistant",
            r#"{"content":null,"tool_calls":[
                {"id":"t1","name":"shell","arguments":"{}"},
                {"id":"t2","name":"web","arguments":"{}"}
            ]}"#,
        ),
        msg("tool", r#"{"tool_call_id":"t1","content":"first"}"#),
        msg(
            "tool",
            r#"{"tool_call_id":"t2","content":"PROTECTED second"}"#,
        ),
        msg("user", "follow up"),
        msg("assistant", "final"),
    ];

    let config = HistoryPrunerConfig {
        enabled: true,
        // Budget is well above the estimated token cost so Phase 2 does
        // not drop anything; this test isolates the Phase 1 / Phase 3
        // interaction.
        max_tokens: 100_000,
        keep_recent: 3,
        collapse_tool_results: true,
    };

    let stats = prune_history(&mut messages, &config);

    assert_eq!(stats.messages_before, 7);
    assert!(
        messages
            .iter()
            .any(|m| m.content.contains("PROTECTED second")),
        "a tool message protected by keep_recent must survive; \
         got roles {:?}",
        messages.iter().map(|m| m.role.as_str()).collect::<Vec<_>>()
    );
}
