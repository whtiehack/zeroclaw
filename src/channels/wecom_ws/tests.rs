use super::*;
use tempfile::tempdir;

#[test]
fn scope_uses_group_shared_mode_by_default_for_group_chat() {
    let inbound = ParsedInbound {
        msg_id: "m1".to_string(),
        msg_type: "text".to_string(),
        chat_type: "group".to_string(),
        chat_id: Some("g1".to_string()),
        sender_userid: "u1".to_string(),
        aibot_id: "b1".to_string(),
        raw_payload: serde_json::json!({}),
    };

    let scopes = compute_scopes(&inbound);
    assert_eq!(scopes.conversation_scope, "group--g1");
    assert!(scopes.shared_group_history);
}

#[test]
fn framework_sender_identity_uses_group_scope_for_group_chat() {
    let inbound = ParsedInbound {
        msg_id: "m1".to_string(),
        msg_type: "text".to_string(),
        chat_type: "group".to_string(),
        chat_id: Some("g1".to_string()),
        sender_userid: "u1".to_string(),
        aibot_id: "b1".to_string(),
        raw_payload: serde_json::json!({}),
    };

    let scopes = compute_scopes(&inbound);
    assert_eq!(framework_sender_identity(&inbound, &scopes), "group--g1");
}

#[test]
fn compose_content_for_framework_group_injects_sender_and_timestamp() {
    let inbound = ParsedInbound {
        msg_id: "m1".to_string(),
        msg_type: "text".to_string(),
        chat_type: "group".to_string(),
        chat_id: Some("g1".to_string()),
        sender_userid: "u1".to_string(),
        aibot_id: "b1".to_string(),
        raw_payload: serde_json::json!({}),
    };

    let scopes = compute_scopes(&inbound);
    let content = compose_content_for_framework(&inbound, &scopes, "hello");
    assert!(content.starts_with("[sender_userid=u1] ["));
    assert!(content.contains("] hello"));
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
fn stop_command_requires_slash_with_optional_mentions() {
    assert!(is_stop_runtime_command("/stop"));
    assert!(is_stop_runtime_command("/STOP"));
    assert!(is_stop_runtime_command("@bot /stop"));
    assert!(is_stop_runtime_command("/stop @bot"));
    assert!(is_stop_runtime_command(" /stop@zeroclaw "));
    assert!(!is_stop_runtime_command("stop"));
    assert!(!is_stop_runtime_command("\u{505c}\u{6b62}"));
    assert!(!is_stop_runtime_command("please /stop now"));
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
fn parse_attachment_markers_extracts_kinds() {
    let input = "\u{5206}\u{6790}\u{7ed3}\u{679c}:\n[IMAGE:/tmp/chart.png]\n[FILE:/tmp/report.pdf]\n\u{8bf7}\u{53c2}\u{8003}\u{3002}";
    let (cleaned, attachments) = parse_attachment_markers(input);
    assert_eq!(
        attachments,
        vec![
            OutboundAttachment {
                kind: OutboundAttachmentKind::Image,
                target: "/tmp/chart.png".to_string()
            },
            OutboundAttachment {
                kind: OutboundAttachmentKind::File,
                target: "/tmp/report.pdf".to_string()
            }
        ]
    );
    assert!(cleaned.contains("\u{5206}\u{6790}\u{7ed3}\u{679c}:"));
    assert!(cleaned.contains("\u{8bf7}\u{53c2}\u{8003}\u{3002}"));
    assert!(!cleaned.contains("[IMAGE:"));
}

#[test]
fn parse_attachment_markers_preserves_non_attachment_tags() {
    let input = "Hello [TOOL:abc] world [IMAGE:/a.jpg] end";
    let (cleaned, attachments) = parse_attachment_markers(input);
    assert_eq!(
        attachments,
        vec![OutboundAttachment {
            kind: OutboundAttachmentKind::Image,
            target: "/a.jpg".to_string()
        }]
    );
    assert!(cleaned.contains("[TOOL:abc]"));
    assert!(!cleaned.contains("[IMAGE:"));
}

#[test]
fn parse_attachment_markers_no_markers() {
    let input = "No images here.";
    let (cleaned, attachments) = parse_attachment_markers(input);
    assert_eq!(cleaned, "No images here.");
    assert!(attachments.is_empty());
}

#[test]
fn parse_path_only_attachment_infers_kind() {
    let attachment = parse_path_only_attachment_hint("file:///tmp/demo.mp4").expect("should parse");
    assert_eq!(attachment.kind, OutboundAttachmentKind::Video);
    assert_eq!(attachment.target, "/tmp/demo.mp4");
}

#[test]
fn sanitize_outbound_draft_content_hides_attachment_only_reply() {
    assert_eq!(
        sanitize_outbound_draft_content("[FILE:/tmp/report.pdf]"),
        WECOM_STREAM_BOOTSTRAP_CONTENT
    );
}

#[test]
fn sanitize_outbound_draft_content_preserves_multiline_text() {
    let input = (1..=25)
        .map(|idx| format!("line {idx}"))
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(sanitize_outbound_draft_content(&input), input);
}

#[test]
fn sanitize_outbound_draft_content_removes_attachment_markers_without_truncating() {
    let mut lines = (1..=21)
        .map(|idx| format!("line {idx}"))
        .collect::<Vec<_>>();
    lines.push("[FILE:/tmp/report.pdf]".to_string());
    let input = lines.join("\n");

    let expected = (1..=21)
        .map(|idx| format!("line {idx}"))
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(sanitize_outbound_draft_content(&input), expected);
}

#[test]
fn draft_state_progress_seeds_pretool_narration() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("s1".to_string(), StreamDraftState::default());

    // Model speaks before tools — normal streaming.
    let body = channel
        .note_content_update("s1", "Let me check\n")
        .expect("pre-tool content should stream");
    assert_eq!(body, "Let me check\n");

    // First progress seeds work_log with pre-tool narration.
    let wl = channel
        .note_progress_update("s1", "⏳ shell: ls\n")
        .expect("progress should render");
    assert!(
        wl.contains("Let me check"),
        "pre-tool narration should be seeded"
    );
    assert!(wl.contains("shell: ls"));
}

#[test]
fn draft_state_content_after_tools_is_pending_not_displayed() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("s2".to_string(), StreamDraftState::default());

    channel.note_progress_update("s2", "⏳ tool\n");

    // Content after tool activity goes to pending — not displayed.
    assert!(
        channel.note_content_update("s2", "Final answer").is_none(),
        "content after tool activity should return None (pending)"
    );

    // Pending content is stored.
    let state = channel.draft_states.lock();
    assert_eq!(state.get("s2").unwrap().pending_content, "Final answer");
}

#[test]
fn draft_state_pending_flushed_on_next_progress() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("s3".to_string(), StreamDraftState::default());

    channel.note_progress_update("s3", "⏳ tool1\n");
    channel.note_progress_update("s3", "✅ done\n");

    // Simulate inter-batch narration (model says something between tool batches).
    channel.note_content_update("s3", "Found it");

    // Next progress flushes pending into work_log.
    let wl = channel
        .note_progress_update("s3", "⏳ tool2\n")
        .expect("progress should render");
    assert!(
        wl.contains("Found it"),
        "pending narration should be flushed"
    );
    assert!(wl.contains("tool2"));

    // Pending is cleared.
    let state = channel.draft_states.lock();
    assert!(state.get("s3").unwrap().pending_content.is_empty());
}

#[test]
fn draft_state_content_without_tools_streams_normally() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("s4".to_string(), StreamDraftState::default());

    // No tool activity — content streams as normal accumulated text.
    let body = channel
        .note_content_update("s4", "Hello world")
        .expect("content should render normally");
    assert_eq!(body, "Hello world");

    let body2 = channel
        .note_content_update("s4", "Hello world, more text")
        .expect("accumulated content should render");
    assert_eq!(body2, "Hello world, more text");
}

#[test]
fn draft_state_final_answer_streams_after_content_reset() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("fa1".to_string(), StreamDraftState::default());

    // Simulate: pre-tool content → tool activity → inter-batch narration
    channel.note_content_update("fa1", "Let me check");
    channel.note_progress_update("fa1", "⏳ tool1\n");
    channel.note_progress_update("fa1", "✅ done\n");
    // Inter-batch narration (continuation of accumulated content)
    channel.note_content_update("fa1", "Let me checkFound it");

    // Now simulate framework Clear → accumulated resets → final answer
    // The new content does NOT start with last_content ("Let me checkFound it").
    let body = channel
        .note_content_update("fa1", "Here is the answer")
        .expect("final answer should stream");
    assert_eq!(body, "Here is the answer");

    // Verify state transitioned to final answer.
    // work_log and pending_content are kept intact for potential fallback.
    let state = channel.draft_states.lock();
    let s = state.get("fa1").unwrap();
    assert!(s.in_final_answer);
    assert!(
        !s.work_log.is_empty(),
        "work_log should be preserved for fallback"
    );
}

#[test]
fn draft_state_final_answer_continues_streaming() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("fa2".to_string(), StreamDraftState::default());

    channel.note_content_update("fa2", "Thinking...");
    channel.note_progress_update("fa2", "⏳ tool\n");

    // Trigger final answer detection.
    channel.note_content_update("fa2", "Answer part 1");

    // Subsequent content in final answer phase streams directly, no line limit.
    let body = channel
            .note_content_update("fa2", "Answer part 1\npart 2\npart 3\npart 4\npart 5\npart 6\npart 7\npart 8\npart 9\npart 10\npart 11\npart 12")
            .expect("final answer should stream without line limit");
    assert!(body.contains("part 12"), "all lines should be present");
    assert!(body.contains("part 1"), "first line should be present");
}

#[test]
fn draft_state_final_answer_fallback_on_unexpected_progress() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("fa3".to_string(), StreamDraftState::default());

    channel.note_content_update("fa3", "Pre-tool");
    channel.note_progress_update("fa3", "⏳ tool1\n");

    // Trigger final answer detection.
    channel.note_content_update("fa3", "Answer start");

    {
        let state = channel.draft_states.lock();
        assert!(state.get("fa3").unwrap().in_final_answer);
    }

    // Unexpected progress → fall back to tool-activity mode.
    let wl = channel
        .note_progress_update("fa3", "⏳ tool2\n")
        .expect("progress should render");
    assert!(wl.contains("tool2"));
    // work_log should still contain previous tool progress (preserved across false positive).
    assert!(
        wl.contains("tool1"),
        "work_log must preserve tool1 after fallback"
    );

    {
        let state = channel.draft_states.lock();
        assert!(!state.get("fa3").unwrap().in_final_answer);
    }
}

#[test]
fn draft_state_work_log_limits_to_latest_lines() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    channel
        .draft_states
        .lock()
        .insert("stream-clip".to_string(), StreamDraftState::default());

    let mut rendered = String::new();
    for n in 1..=12 {
        rendered = channel
            .note_progress_update("stream-clip", &format!("line-{n}\n"))
            .expect("progress should render");
    }

    assert_eq!(
        rendered,
        (3..=12)
            .map(|n| format!("line-{n}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
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
    assert!(is_clear_session_command("/clear@zeroclaw"));
    assert!(is_clear_session_command("/new@zeroclaw"));
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
fn runtime_routing_command_with_mentions() {
    assert_eq!(
        extract_runtime_routing_command("@bot /model gpt-5 @other"),
        Some("/model gpt-5".to_string())
    );
    assert_eq!(
        extract_runtime_routing_command("@bot /models openrouter"),
        Some("/models openrouter".to_string())
    );
    assert_eq!(
        extract_runtime_routing_command(" /MODEL@zeroclaw qwen-max "),
        Some("/MODEL@zeroclaw qwen-max".to_string())
    );
    assert_eq!(
        extract_runtime_routing_command("@bot /config @other"),
        Some("/config".to_string())
    );
    assert_eq!(
        extract_runtime_routing_command(" /CONFIG@zeroclaw "),
        Some("/CONFIG".to_string())
    );
}

#[test]
fn runtime_routing_command_rejects_non_commands() {
    assert_eq!(extract_runtime_routing_command("/new"), None);
    assert_eq!(extract_runtime_routing_command("please /model gpt-5"), None);
    assert_eq!(extract_runtime_routing_command(""), None);
}

#[test]
fn parse_scope_user() {
    let (chat_type, chatid) = parse_scope("user--zeroclaw_user").unwrap();
    assert_eq!(chat_type, 1);
    assert_eq!(chatid, "zeroclaw_user");
}

#[test]
fn parse_scope_group() {
    let (chat_type, chatid) = parse_scope("group--zeroclaw_group").unwrap();
    assert_eq!(chat_type, 2);
    assert_eq!(chatid, "zeroclaw_group");
}

#[test]
fn parse_scope_invalid() {
    assert!(parse_scope("invalid_scope").is_err());
}

fn test_inbound(chat_type: &str, chat_id: Option<&str>, sender_userid: &str) -> ParsedInbound {
    ParsedInbound {
        msg_id: "msg-1".to_string(),
        msg_type: "text".to_string(),
        chat_type: chat_type.to_string(),
        chat_id: chat_id.map(str::to_string),
        sender_userid: sender_userid.to_string(),
        aibot_id: "bot123".to_string(),
        raw_payload: serde_json::json!({
            "msgtype": "text",
            "msgid": "msg-1",
            "chattype": chat_type,
            "chatid": chat_id,
            "from": { "userid": sender_userid },
            "text": { "content": "@bot hello" }
        }),
    }
}

fn test_wecom_ws_config() -> crate::config::schema::WeComWsConfig {
    crate::config::schema::WeComWsConfig {
        bot_id: "bot123".to_string(),
        secret: "secret456".to_string(),
        allowed_users: vec![],
        allowed_groups: vec![],
        file_retention_days: 3,
        max_file_size_mb: 20,
        interrupt_on_new_message: false,
        stream_mode: StreamMode::Partial,
        draft_update_interval_ms: 300,
    }
}

fn frame_req_id(frame: &Value) -> String {
    frame
        .get("headers")
        .and_then(|headers| headers.get("req_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

#[test]
fn access_decision_denies_when_allowlists_missing() {
    let inbound = test_inbound("single", None, "zeroclaw_user");
    assert_eq!(
        evaluate_access_decision(&[], &[], &inbound),
        AccessDecision::AllowlistMissing
    );
}

#[test]
fn access_decision_allows_userid_in_single_chat() {
    let inbound = test_inbound("single", None, "zeroclaw_user");
    assert_eq!(
        evaluate_access_decision(&["zeroclaw_user".to_string()], &[], &inbound),
        AccessDecision::Allowed
    );
}

#[test]
fn access_decision_allows_group_chatid() {
    let inbound = test_inbound("group", Some("zeroclaw_group"), "zeroclaw_user");
    assert_eq!(
        evaluate_access_decision(&[], &["zeroclaw_group".to_string()], &inbound),
        AccessDecision::Allowed
    );
}

#[test]
fn access_decision_allows_wildcards() {
    let inbound = test_inbound("group", Some("zeroclaw_group"), "zeroclaw_user");
    assert_eq!(
        evaluate_access_decision(&["*".to_string()], &[], &inbound),
        AccessDecision::Allowed
    );
    assert_eq!(
        evaluate_access_decision(&[], &["*".to_string()], &inbound),
        AccessDecision::Allowed
    );
}

#[test]
fn denied_group_message_mentions_chatid_and_userid() {
    let inbound = test_inbound("group", Some("zeroclaw_group"), "zeroclaw_user");
    let text = build_access_denied_message(&inbound, AccessDecision::Denied);
    assert!(text.contains("zeroclaw_group"));
    assert!(text.contains("zeroclaw_user"));
    assert!(text.contains("allowed_groups"));
    assert!(text.contains("wecom_ws"));
}

#[test]
fn supports_draft_updates_respects_stream_mode() {
    let mut off_cfg = test_wecom_ws_config();
    off_cfg.stream_mode = StreamMode::Off;
    let off = WeComWsChannel::new(&off_cfg, Path::new("/tmp")).unwrap();
    assert!(!off.supports_draft_updates());

    let partial = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();
    assert!(partial.supports_draft_updates());
}

#[tokio::test]
async fn send_draft_returns_none_when_stream_mode_off() {
    let mut cfg = test_wecom_ws_config();
    cfg.stream_mode = StreamMode::Off;
    let channel = WeComWsChannel::new(&cfg, Path::new("/tmp")).unwrap();

    let id = channel
        .send_draft(&SendMessage::new("draft", "user--zeroclaw_user"))
        .await
        .unwrap();

    assert!(id.is_none());
}

#[tokio::test]
async fn send_with_req_id_uses_respond_msg_when_stream_mode_off() {
    let mut cfg = test_wecom_ws_config();
    cfg.stream_mode = StreamMode::Off;
    let channel = WeComWsChannel::new(&cfg, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let responder_channel = channel.clone();
    let responder = tokio::spawn(async move {
        let Some(WsOutbound::Frame(frame)) = ws_rx.recv().await else {
            panic!("expected respond_msg frame");
        };
        let req_id = frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        responder_channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": req_id },
                "errcode": 0,
                "errmsg": "ok"
            }))
            .await;
        frame
    });

    channel
        .send(
            &SendMessage::new("runtime ok", "user--zeroclaw_user")
                .in_thread(Some("req-runtime".to_string())),
        )
        .await
        .unwrap();

    let frame = responder.await.unwrap();
    assert_eq!(
        frame.get("cmd").and_then(Value::as_str),
        Some("aibot_respond_msg")
    );
    assert_eq!(
        frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str),
        Some("req-runtime")
    );
    assert_eq!(
        frame
            .pointer("/body/stream/content")
            .and_then(Value::as_str),
        Some("runtime ok")
    );
    assert_eq!(
        frame
            .pointer("/body/stream/finish")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[tokio::test]
async fn send_without_req_id_uses_send_msg() {
    let channel = WeComWsChannel::new(&test_wecom_ws_config(), Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let responder_channel = channel.clone();
    let responder = tokio::spawn(async move {
        let Some(WsOutbound::Frame(frame)) = ws_rx.recv().await else {
            panic!("expected send_msg frame");
        };
        let req_id = frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        responder_channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": req_id },
                "errcode": 0,
                "errmsg": "ok"
            }))
            .await;
        frame
    });

    channel
        .send(&SendMessage::new("hello proactive", "user--zeroclaw_user"))
        .await
        .unwrap();

    let frame = responder.await.unwrap();
    assert_eq!(
        frame.get("cmd").and_then(Value::as_str),
        Some("aibot_send_msg")
    );
    assert_eq!(
        frame
            .pointer("/body/markdown/content")
            .and_then(Value::as_str),
        Some("hello proactive")
    );
}

#[tokio::test]
async fn send_with_req_id_attachment_only_replies_sent_then_sends_attachment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("chart.png");
    tokio::fs::write(&path, b"123456").await.unwrap();
    let path_str = path.canonicalize().unwrap().display().to_string();

    let channel = WeComWsChannel::new(&test_wecom_ws_config(), dir.path()).unwrap();
    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(8);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let responder_channel = channel.clone();
    let responder = tokio::spawn(async move {
        let mut commands = Vec::new();
        let mut stream_content = None;
        let mut attachment_msgtype = None;

        while let Some(WsOutbound::Frame(frame)) = ws_rx.recv().await {
            let cmd = frame
                .get("cmd")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let req_id = frame_req_id(&frame);
            commands.push(cmd.clone());

            match cmd.as_str() {
                "aibot_respond_msg" => {
                    stream_content = frame
                        .pointer("/body/stream/content")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_upload_media_init" => {
                    assert_eq!(
                        frame.pointer("/body/type").and_then(Value::as_str),
                        Some("image")
                    );
                    assert_eq!(
                        frame.pointer("/body/filename").and_then(Value::as_str),
                        Some("chart.png")
                    );
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "body": { "upload_id": "upload-image-1" },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_upload_media_chunk" => {
                    assert_eq!(
                        frame.pointer("/body/upload_id").and_then(Value::as_str),
                        Some("upload-image-1")
                    );
                    assert_eq!(
                        frame.pointer("/body/chunk_index").and_then(Value::as_u64),
                        Some(0)
                    );
                    assert!(frame
                        .pointer("/body/base64_data")
                        .and_then(Value::as_str)
                        .is_some());
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_upload_media_finish" => {
                    assert_eq!(
                        frame.pointer("/body/upload_id").and_then(Value::as_str),
                        Some("upload-image-1")
                    );
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "body": {
                                "type": "image",
                                "media_id": "media-image-1",
                                "created_at": 1
                            },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_send_msg" => {
                    attachment_msgtype = frame
                        .pointer("/body/msgtype")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    assert_eq!(
                        frame
                            .pointer("/body/image/media_id")
                            .and_then(Value::as_str),
                        Some("media-image-1")
                    );
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                    break;
                }
                other => panic!("unexpected command: {other}"),
            }
        }

        (commands, stream_content, attachment_msgtype)
    });

    channel
        .send(
            &SendMessage::new(format!("[IMAGE:{path_str}]"), "user--zeroclaw_user")
                .in_thread(Some("req-attach".to_string())),
        )
        .await
        .unwrap();

    let (commands, stream_content, attachment_msgtype) = responder.await.unwrap();
    assert_eq!(
        commands,
        vec![
            "aibot_respond_msg",
            "aibot_upload_media_init",
            "aibot_upload_media_chunk",
            "aibot_upload_media_finish",
            "aibot_send_msg"
        ]
    );
    assert_eq!(stream_content.as_deref(), Some("\u{5df2}\u{53d1}\u{9001}"));
    assert_eq!(attachment_msgtype.as_deref(), Some("image"));
}

#[tokio::test]
async fn send_without_req_id_path_only_attachment_sends_sent_then_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("report.pdf");
    tokio::fs::write(&path, b"1234567").await.unwrap();
    let path_str = path.canonicalize().unwrap().display().to_string();

    let channel = WeComWsChannel::new(&test_wecom_ws_config(), dir.path()).unwrap();
    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(8);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let responder_channel = channel.clone();
    let responder = tokio::spawn(async move {
        let mut msgtypes = Vec::new();
        while let Some(WsOutbound::Frame(frame)) = ws_rx.recv().await {
            let cmd = frame.get("cmd").and_then(Value::as_str).unwrap_or("");
            let req_id = frame_req_id(&frame);

            match cmd {
                "aibot_send_msg" => {
                    let msgtype = frame
                        .pointer("/body/msgtype")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    msgtypes.push(msgtype.clone());
                    if msgtype == "markdown" {
                        assert_eq!(
                            frame
                                .pointer("/body/markdown/content")
                                .and_then(Value::as_str),
                            Some("\u{5df2}\u{53d1}\u{9001}")
                        );
                    } else {
                        assert_eq!(msgtype, "file");
                        assert_eq!(
                            frame.pointer("/body/file/media_id").and_then(Value::as_str),
                            Some("media-file-1")
                        );
                    }
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                    if msgtype == "file" {
                        break;
                    }
                }
                "aibot_upload_media_init" => {
                    assert_eq!(
                        frame.pointer("/body/type").and_then(Value::as_str),
                        Some("file")
                    );
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "body": { "upload_id": "upload-file-1" },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_upload_media_chunk" => {
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                "aibot_upload_media_finish" => {
                    responder_channel
                        .maybe_handle_command_response(&serde_json::json!({
                            "headers": { "req_id": req_id },
                            "body": {
                                "type": "file",
                                "media_id": "media-file-1",
                                "created_at": 1
                            },
                            "errcode": 0,
                            "errmsg": "ok"
                        }))
                        .await;
                }
                other => panic!("unexpected command: {other}"),
            }
        }

        msgtypes
    });

    channel
        .send(&SendMessage::new(path_str, "user--zeroclaw_user"))
        .await
        .unwrap();

    let msgtypes = responder.await.unwrap();
    assert_eq!(msgtypes, vec!["markdown", "file"]);
}

#[tokio::test]
async fn command_response_resolves_waiter_successfully() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (waiter, rx) = tokio::sync::oneshot::channel();
    channel
        .pending_responses
        .lock()
        .await
        .insert("req-ok".to_string(), waiter);

    assert!(
        channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": "req-ok" },
                "errcode": 0,
                "errmsg": "ok"
            }))
            .await
    );
    assert!(rx.await.unwrap().is_ok());
}

#[tokio::test]
async fn command_response_resolves_waiter_failure() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (waiter, rx) = tokio::sync::oneshot::channel();
    channel
        .pending_responses
        .lock()
        .await
        .insert("req-fail".to_string(), waiter);

    assert!(
        channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": "req-fail" },
                "errcode": 93001,
                "errmsg": "session not allowed"
            }))
            .await
    );
    let err = rx.await.unwrap().unwrap_err().to_string();
    assert!(err.contains("errcode=93001"));
    assert!(err.contains("session not allowed"));
}

#[tokio::test]
async fn command_response_consumes_registered_heartbeat_ack() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    channel.register_heartbeat_req_id("req-ping").await;

    assert!(
        channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": "req-ping" },
                "errcode": 0,
                "errmsg": "ok"
            }))
            .await
    );
    assert_eq!(channel.expected_heartbeat_ack.lock().await.as_deref(), None);
}

#[tokio::test]
async fn handle_ws_message_consumes_command_ack_without_forwarding() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (waiter, ack_rx) = tokio::sync::oneshot::channel();
    channel
        .pending_responses
        .lock()
        .await
        .insert("req-ack".to_string(), waiter);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    let should_reconnect = channel
        .handle_ws_message(
            serde_json::json!({
                "cmd": "aibot_respond_msg",
                "headers": { "req_id": "req-ack" },
                "errcode": 0,
                "errmsg": "ok"
            }),
            &tx,
        )
        .await;

    assert!(!should_reconnect);
    assert!(ack_rx.await.unwrap().is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "command ack must not be forwarded as an inbound channel message"
    );
}

#[tokio::test]
async fn clear_command_forwards_runtime_new_session_without_immediate_ws_reply() {
    let mut config = test_wecom_ws_config();
    config.allowed_users = vec!["zeroclaw_user".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(1);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-clear" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-clear",
                    "chattype": "single",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "/clear" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("clear command should be forwarded promptly")
        .expect("clear command should produce a framework message");
    assert_eq!(forwarded.content, "/new");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-clear"));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws_rx.recv())
            .await
            .is_err(),
        "clear command should not emit an immediate websocket reply"
    );
}

#[tokio::test]
async fn clear_command_ws_dispatch_does_not_block_when_framework_queue_is_full() {
    let mut config = test_wecom_ws_config();
    config.allowed_users = vec!["zeroclaw_user".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    tx.send(ChannelMessage {
        id: "prefill-clear".to_string(),
        sender: "tester".to_string(),
        reply_target: "user--zeroclaw_user".to_string(),
        content: "prefill".to_string(),
        channel: "wecom_ws".to_string(),
        timestamp: bytes_timestamp_now(),
        thread_ts: None,
        interruption_scope_id: None,
        attachments: vec![],
    })
    .await
    .unwrap();

    let should_reconnect = tokio::time::timeout(
        Duration::from_millis(100),
        channel.handle_ws_message(
            serde_json::json!({
                "cmd": "aibot_msg_callback",
                "headers": { "req_id": "req-clear-dispatch" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-clear-dispatch",
                    "chattype": "single",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "/clear" }
                }
            }),
            &tx,
        ),
    )
    .await
    .expect("clear dispatch should not block the websocket loop");

    assert!(!should_reconnect);

    let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("prefilled framework message should be readable")
        .expect("prefilled framework message should exist");
    assert_eq!(first.id, "prefill-clear");

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("clear command should forward once queue space is available")
        .expect("clear command should produce a framework message");
    assert_eq!(forwarded.content, "/new");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-clear-dispatch"));
}

#[tokio::test]
async fn group_clear_command_forwards_group_scoped_sender() {
    let mut config = test_wecom_ws_config();
    config.allowed_groups = vec!["zeroclaw_group".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(1);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-clear-group" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-clear-group",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot /clear" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("group clear command should be forwarded promptly")
        .expect("group clear command should produce a framework message");
    assert_eq!(forwarded.content, "/new");
    assert_eq!(forwarded.sender, "group--zeroclaw_group");
    assert_eq!(forwarded.reply_target, "group--zeroclaw_group");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-clear-group"));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws_rx.recv())
            .await
            .is_err(),
        "group clear command should not emit an immediate websocket reply"
    );
}

#[tokio::test]
async fn stop_command_forwards_stop_to_framework() {
    let mut config = test_wecom_ws_config();
    config.allowed_users = vec!["zeroclaw_user".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(1);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-stop" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-stop",
                    "chattype": "single",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "/stop" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("stop command should be forwarded promptly")
        .expect("stop command should produce a framework message");
    assert_eq!(forwarded.content, "/stop");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-stop"));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws_rx.recv())
            .await
            .is_err(),
        "stop command should not emit an immediate websocket reply"
    );
}

#[tokio::test]
async fn group_text_message_forwards_group_scoped_sender_and_prefixed_content() {
    let mut config = test_wecom_ws_config();
    config.allowed_groups = vec!["zeroclaw_group".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-group" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-group",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot hello" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("group message should be forwarded promptly")
        .expect("group message should produce a framework message");
    assert_eq!(forwarded.reply_target, "group--zeroclaw_group");
    assert_eq!(forwarded.sender, "group--zeroclaw_group");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-group"));
    assert!(forwarded
        .content
        .starts_with("[sender_userid=zeroclaw_user] ["));
    assert!(forwarded.content.contains("@bot hello"));
}

#[tokio::test]
async fn group_stop_command_forwards_group_scoped_sender() {
    let mut config = test_wecom_ws_config();
    config.allowed_groups = vec!["zeroclaw_group".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(1);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-stop-group" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-stop-group",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "/stop" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("group stop command should be forwarded promptly")
        .expect("group stop command should produce a framework message");
    assert_eq!(forwarded.content, "/stop");
    assert_eq!(forwarded.sender, "group--zeroclaw_group");
    assert_eq!(forwarded.reply_target, "group--zeroclaw_group");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-stop-group"));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws_rx.recv())
            .await
            .is_err(),
        "group stop command should not emit an immediate websocket reply"
    );
}

#[tokio::test]
async fn group_model_command_forwards_group_scoped_sender() {
    let mut config = test_wecom_ws_config();
    config.allowed_groups = vec!["zeroclaw_group".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-model-group" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-model-group",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot /model qwen-max" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("group model command should be forwarded promptly")
        .expect("group model command should produce a framework message");
    assert_eq!(forwarded.content, "/model qwen-max");
    assert_eq!(forwarded.sender, "group--zeroclaw_group");
    assert_eq!(forwarded.reply_target, "group--zeroclaw_group");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-model-group"));
}

#[tokio::test]
async fn group_config_command_forwards_group_scoped_sender() {
    let mut config = test_wecom_ws_config();
    config.allowed_groups = vec!["zeroclaw_group".to_string()];
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-config-group" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-config-group",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot /config" }
                }
            }),
            &tx,
        )
        .await;

    let forwarded = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("group config command should be forwarded promptly")
        .expect("group config command should produce a framework message");
    assert_eq!(forwarded.content, "/config");
    assert_eq!(forwarded.sender, "group--zeroclaw_group");
    assert_eq!(forwarded.reply_target, "group--zeroclaw_group");
    assert_eq!(forwarded.thread_ts.as_deref(), Some("req-config-group"));
}

#[tokio::test]
async fn unauthorized_group_message_replies_with_chatid_and_does_not_forward() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let responder_channel = channel.clone();
    let responder = tokio::spawn(async move {
        let Some(WsOutbound::Frame(frame)) = ws_rx.recv().await else {
            panic!("expected access-denied response frame");
        };
        let req_id = frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let content = frame
            .pointer("/body/stream/content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        responder_channel
            .maybe_handle_command_response(&serde_json::json!({
                "headers": { "req_id": req_id },
                "errcode": 0,
                "errmsg": "ok"
            }))
            .await;
        content
    });

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    channel
        .handle_msg_callback(
            serde_json::json!({
                "headers": { "req_id": "req-denied" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-denied",
                    "chattype": "group",
                    "chatid": "zeroclaw_group",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot hello" }
                }
            }),
            &tx,
        )
        .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "unauthorized message must not reach framework"
    );

    let denied = responder.await.unwrap();
    assert!(denied.contains("zeroclaw_group"));
    assert!(denied.contains("zeroclaw_user"));
    assert!(denied.contains("allowed_groups"));
}

#[tokio::test]
async fn unauthorized_message_ws_dispatch_returns_without_waiting_for_ack() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (ws_tx, mut ws_rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(ws_tx);

    let (tx, mut rx) = mpsc::channel::<ChannelMessage>(1);
    let should_reconnect = tokio::time::timeout(
        Duration::from_millis(100),
        channel.handle_ws_message(
            serde_json::json!({
                "cmd": "aibot_msg_callback",
                "headers": { "req_id": "req-denied-no-ack" },
                "body": {
                    "msgtype": "text",
                    "msgid": "msg-denied-no-ack",
                    "chattype": "single",
                    "from": { "userid": "zeroclaw_user" },
                    "text": { "content": "@bot hello" }
                }
            }),
            &tx,
        ),
    )
    .await
    .expect("access-denied dispatch should not block on websocket ack");

    assert!(!should_reconnect);

    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "unauthorized message must not reach framework"
    );

    let Some(WsOutbound::Frame(frame)) =
        tokio::time::timeout(Duration::from_millis(100), ws_rx.recv())
            .await
            .expect("access-denied reply should be queued promptly")
    else {
        panic!("expected access-denied response frame");
    };

    assert_eq!(
        frame.get("cmd").and_then(Value::as_str),
        Some("aibot_respond_msg")
    );
    assert_eq!(
        frame
            .get("headers")
            .and_then(|headers| headers.get("req_id"))
            .and_then(Value::as_str),
        Some("req-denied-no-ack")
    );
    assert!(
        frame
            .pointer("/body/stream/content")
            .and_then(Value::as_str)
            .is_some_and(|content| content.contains("allowed_users")),
        "access-denied reply should explain how to configure the allowlist"
    );
}

#[tokio::test]
async fn stream_reply_retries_data_version_conflict() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(8);
    *channel.ws_tx.lock().await = Some(tx);

    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let responder_channel = channel.clone();
    let responder_attempts = Arc::clone(&attempts);
    let responder = tokio::spawn(async move {
        while let Some(WsOutbound::Frame(frame)) = rx.recv().await {
            let attempt = responder_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let req_id = frame
                .get("headers")
                .and_then(|headers| headers.get("req_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let errcode = if attempt == 0 { 6000 } else { 0 };
            let errmsg = if errcode == 0 {
                "ok"
            } else {
                "more than one callers at the same time, data version conflict"
            };
            responder_channel
                .maybe_handle_command_response(&serde_json::json!({
                    "headers": { "req_id": req_id },
                    "errcode": errcode,
                    "errmsg": errmsg
                }))
                .await;

            if errcode == 0 {
                break;
            }
        }
    });

    channel
        .ws_send_respond_msg("req-stream", "stream-1", "hello", false)
        .await
        .unwrap();

    responder.await.unwrap();
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn stream_reply_serializes_same_req_id_updates() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(8);
    *channel.ws_tx.lock().await = Some(tx);

    let first_channel = channel.clone();
    let first = tokio::spawn(async move {
        first_channel
            .ws_send_respond_msg("req-serial", "stream-1", "first", false)
            .await
    });

    let second_channel = channel.clone();
    let second = tokio::spawn(async move {
        second_channel
            .ws_send_respond_msg("req-serial", "stream-1", "second", false)
            .await
    });

    let first_frame = tokio::time::timeout(Duration::from_millis(250), rx.recv())
        .await
        .expect("first frame should arrive")
        .expect("first frame should exist");
    let WsOutbound::Frame(first_frame) = first_frame;
    assert_eq!(
        first_frame
            .get("body")
            .and_then(|body| body.get("stream"))
            .and_then(|stream| stream.get("content"))
            .and_then(Value::as_str),
        Some("first")
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(75), rx.recv())
            .await
            .is_err(),
        "second frame should wait for the first ack"
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": "req-serial" },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;
    first.await.unwrap().unwrap();

    let second_frame = tokio::time::timeout(Duration::from_millis(250), rx.recv())
        .await
        .expect("second frame should arrive after first ack")
        .expect("second frame should exist");
    let WsOutbound::Frame(second_frame) = second_frame;
    assert_eq!(
        second_frame
            .get("body")
            .and_then(|body| body.get("stream"))
            .and_then(|stream| stream.get("content"))
            .and_then(Value::as_str),
        Some("second")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": "req-serial" },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;
    second.await.unwrap().unwrap();
}

#[tokio::test]
async fn update_draft_progress_sends_progress_body_over_stream() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-progress".to_string(), "req-progress".to_string());
    channel
        .draft_states
        .lock()
        .insert("stream-progress".to_string(), StreamDraftState::default());

    let updater = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .update_draft_progress(
                    "user--zeroclaw_user",
                    "stream-progress",
                    "⏳ shell: ls -la\n",
                )
                .await
        })
    };

    let Some(WsOutbound::Frame(frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("progress update should send one stream frame")
    else {
        panic!("expected respond_msg frame");
    };
    assert_eq!(
        frame
            .pointer("/body/stream/content")
            .and_then(Value::as_str),
        Some("⏳ shell: ls -la\n")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&frame) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;

    updater.await.unwrap().unwrap();
}

#[tokio::test]
async fn update_draft_progress_continues_after_content() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-wl".to_string(), "req-wl".to_string());
    channel
        .draft_states
        .lock()
        .insert("stream-wl".to_string(), StreamDraftState::default());

    // Send initial progress update.
    let initial_update = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .update_draft_progress("user--zeroclaw_user", "stream-wl", "⏳ shell: ls -la\n")
                .await
        })
    };
    let Some(WsOutbound::Frame(initial_frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("initial progress update should send a frame")
    else {
        panic!("expected initial respond_msg frame");
    };
    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&initial_frame) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;
    initial_update.await.unwrap().unwrap();

    // Verify tool activity flag is set.
    assert!(
        channel
            .draft_states
            .lock()
            .get("stream-wl")
            .is_some_and(|state| state.has_tool_activity),
        "progress update should mark tool activity"
    );
}

#[tokio::test]
async fn cancel_draft_sends_interrupted_message_and_finishes_stream() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-cancel".to_string(), "req-cancel".to_string());
    channel
        .draft_states
        .lock()
        .insert("stream-cancel".to_string(), StreamDraftState::default());

    let cancel = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .cancel_draft("user--zeroclaw_user", "stream-cancel")
                .await
        })
    };

    let Some(WsOutbound::Frame(frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("cancel_draft should send a websocket frame")
    else {
        panic!("expected cancel_draft respond_msg frame");
    };

    assert_eq!(
        frame
            .pointer("/body/stream/content")
            .and_then(Value::as_str),
        Some("消息已中断")
    );
    assert_eq!(
        frame
            .pointer("/body/stream/finish")
            .and_then(Value::as_bool),
        Some(true)
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&frame) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;
    cancel.await.unwrap().unwrap();

    assert!(
        channel.req_id_map.lock().get("stream-cancel").is_none(),
        "cancel_draft should drop the req_id mapping"
    );
    assert!(
        channel.draft_states.lock().get("stream-cancel").is_none(),
        "cancel_draft should clear local draft state"
    );
}

#[tokio::test]
async fn update_draft_content_after_tools_does_not_send_frame() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-pend".to_string(), "req-pend".to_string());
    channel.draft_states.lock().insert(
        "stream-pend".to_string(),
        StreamDraftState {
            has_tool_activity: true,
            work_log: "⏳ shell: ls\n".to_string(),
            ..StreamDraftState::default()
        },
    );

    // Content after tool activity should NOT send a frame (goes to pending).
    channel
        .update_draft("user--zeroclaw_user", "stream-pend", "Final answer text")
        .await
        .unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "content after tool activity should not emit a websocket frame"
    );

    assert_eq!(
        channel
            .draft_states
            .lock()
            .get("stream-pend")
            .unwrap()
            .pending_content,
        "Final answer text",
        "content delta should be buffered in pending_content"
    );
}

#[tokio::test]
async fn update_draft_stops_after_stream_expiration() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-expired".to_string(), "req-expired".to_string());

    let updater = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .update_draft("user--zeroclaw_user", "stream-expired", "partial update")
                .await
        })
    };

    let Some(WsOutbound::Frame(frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("expired draft update should send one stream frame")
    else {
        panic!("expected respond_msg frame");
    };
    assert_eq!(
        frame.get("cmd").and_then(Value::as_str),
        Some("aibot_respond_msg")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&frame) },
            "errcode": 846_608,
            "errmsg": "stream message update expired (>6 minutes), cannot update"
        }))
        .await;

    updater.await.unwrap().unwrap();

    channel
        .update_draft(
            "user--zeroclaw_user",
            "stream-expired",
            "later update should be ignored",
        )
        .await
        .unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "expired draft updates should not keep sending websocket frames"
    );
    assert!(channel.req_id_map.lock().get("stream-expired").is_none());
    assert!(channel.is_expired_stream_req_id("req-expired"));
}

#[tokio::test]
async fn finalize_draft_falls_back_to_send_msg_after_stream_expiration() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
    *channel.ws_tx.lock().await = Some(tx);
    channel
        .req_id_map
        .lock()
        .insert("stream-final".to_string(), "req-final".to_string());

    let finalizer = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .finalize_draft("user--zeroclaw_user", "stream-final", "final answer")
                .await
        })
    };

    let Some(WsOutbound::Frame(stream_frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("finalize should attempt one final stream reply first")
    else {
        panic!("expected initial respond_msg frame");
    };
    assert_eq!(
        stream_frame.get("cmd").and_then(Value::as_str),
        Some("aibot_respond_msg")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&stream_frame) },
            "errcode": 846_608,
            "errmsg": "stream message update expired (>6 minutes), cannot update"
        }))
        .await;

    let Some(WsOutbound::Frame(fallback_frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("expired finalize should fall back to a standard message")
    else {
        panic!("expected fallback send_msg frame");
    };
    assert_eq!(
        fallback_frame.get("cmd").and_then(Value::as_str),
        Some("aibot_send_msg")
    );
    assert_eq!(
        fallback_frame
            .pointer("/body/markdown/content")
            .and_then(Value::as_str),
        Some("final answer")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&fallback_frame) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;

    finalizer.await.unwrap().unwrap();
    assert!(channel.req_id_map.lock().get("stream-final").is_none());
    assert!(channel.is_expired_stream_req_id("req-final"));
}

#[tokio::test]
async fn finalize_draft_without_stream_mapping_falls_back_to_send_msg() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(2);
    *channel.ws_tx.lock().await = Some(tx);

    let finalizer = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .finalize_draft(
                    "user--zeroclaw_user",
                    "stream-missing",
                    "fallback after updater cleanup",
                )
                .await
        })
    };

    let Some(WsOutbound::Frame(frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("missing mapping should send a standard message")
    else {
        panic!("expected send_msg frame");
    };
    assert_eq!(
        frame.get("cmd").and_then(Value::as_str),
        Some("aibot_send_msg")
    );
    assert_eq!(
        frame
            .pointer("/body/markdown/content")
            .and_then(Value::as_str),
        Some("fallback after updater cleanup")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&frame) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;

    finalizer.await.unwrap().unwrap();
}

#[tokio::test]
async fn send_with_thread_req_id_falls_back_and_remembers_expiration() {
    let config = test_wecom_ws_config();
    let channel = WeComWsChannel::new(&config, Path::new("/tmp")).unwrap();

    let (tx, mut rx) = mpsc::channel::<WsOutbound>(6);
    *channel.ws_tx.lock().await = Some(tx);

    let first_send = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .send(
                    &SendMessage::new("tool update", "user--zeroclaw_user")
                        .in_thread(Some("req-tool".to_string())),
                )
                .await
        })
    };

    let Some(WsOutbound::Frame(stream_frame)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("threaded send should try stream reply before expiry is known")
    else {
        panic!("expected initial respond_msg frame");
    };
    assert_eq!(
        stream_frame.get("cmd").and_then(Value::as_str),
        Some("aibot_respond_msg")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&stream_frame) },
            "errcode": 846_608,
            "errmsg": "stream message update expired (>6 minutes), cannot update"
        }))
        .await;

    let Some(WsOutbound::Frame(first_fallback)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("expired threaded send should fall back to send_msg")
    else {
        panic!("expected fallback send_msg frame");
    };
    assert_eq!(
        first_fallback.get("cmd").and_then(Value::as_str),
        Some("aibot_send_msg")
    );
    assert_eq!(
        first_fallback
            .pointer("/body/markdown/content")
            .and_then(Value::as_str),
        Some("tool update")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&first_fallback) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;

    first_send.await.unwrap().unwrap();
    assert!(channel.is_expired_stream_req_id("req-tool"));

    let second_send = {
        let channel = channel.clone();
        tokio::spawn(async move {
            channel
                .send(
                    &SendMessage::new("tool update after expiry", "user--zeroclaw_user")
                        .in_thread(Some("req-tool".to_string())),
                )
                .await
        })
    };

    let Some(WsOutbound::Frame(second_fallback)) =
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("remembered expiry should skip further stream attempts")
    else {
        panic!("expected direct send_msg frame");
    };
    assert_eq!(
        second_fallback.get("cmd").and_then(Value::as_str),
        Some("aibot_send_msg")
    );
    assert_eq!(
        second_fallback
            .pointer("/body/markdown/content")
            .and_then(Value::as_str),
        Some("tool update after expiry")
    );

    channel
        .maybe_handle_command_response(&serde_json::json!({
            "headers": { "req_id": frame_req_id(&second_fallback) },
            "errcode": 0,
            "errmsg": "ok"
        }))
        .await;

    second_send.await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "remembered expiry should avoid extra websocket traffic"
    );
}
