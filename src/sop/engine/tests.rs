use super::*;
use crate::sop::types::SopExecutionMode;

fn manual_event() -> SopEvent {
    SopEvent {
        source: SopTriggerSource::Manual,
        topic: None,
        payload: None,
        timestamp: now_iso8601(),
    }
}

fn mqtt_event(topic: &str, payload: &str) -> SopEvent {
    SopEvent {
        source: SopTriggerSource::Mqtt,
        topic: Some(topic.into()),
        payload: Some(payload.into()),
        timestamp: now_iso8601(),
    }
}

fn test_sop(name: &str, mode: SopExecutionMode, priority: SopPriority) -> Sop {
    Sop {
        name: name.into(),
        description: format!("Test SOP: {name}"),
        version: "1.0.0".into(),
        priority,
        execution_mode: mode,
        triggers: vec![SopTrigger::Manual],
        steps: vec![
            SopStep {
                number: 1,
                title: "Step one".into(),
                body: "Do step one".into(),
                suggested_tools: vec!["shell".into()],
                requires_confirmation: false,
                kind: SopStepKind::default(),
                schema: None,
            },
            SopStep {
                number: 2,
                title: "Step two".into(),
                body: "Do step two".into(),
                suggested_tools: vec![],
                requires_confirmation: false,
                kind: SopStepKind::default(),
                schema: None,
            },
        ],
        cooldown_secs: 0,
        max_concurrent: 1,
        location: None,
        deterministic: false,
    }
}

fn engine_with_sops(sops: Vec<Sop>) -> SopEngine {
    let mut engine = SopEngine::new(SopConfig::default());
    engine.sops = sops;
    engine
}

/// Extract run_id from any SopRunAction variant.
fn extract_run_id(action: &SopRunAction) -> &str {
    match action {
        SopRunAction::ExecuteStep { run_id, .. }
        | SopRunAction::WaitApproval { run_id, .. }
        | SopRunAction::DeterministicStep { run_id, .. }
        | SopRunAction::CheckpointWait { run_id, .. }
        | SopRunAction::Completed { run_id, .. }
        | SopRunAction::Failed { run_id, .. } => run_id,
    }
}

/// Get the first active run_id from the engine (for tests with a single run).
fn first_active_run_id(engine: &SopEngine) -> String {
    engine
        .active_runs()
        .keys()
        .next()
        .expect("expected at least one active run")
        .clone()
}

// ── Trigger matching ────────────────────────────────

#[test]
fn match_manual_trigger() {
    let engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let matches = engine.match_trigger(&manual_event());
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "s1");
}

#[test]
fn no_match_for_wrong_source() {
    let engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let event = mqtt_event("sensors/temp", "{}");
    let matches = engine.match_trigger(&event);
    assert!(matches.is_empty());
}

#[test]
fn match_mqtt_trigger_exact() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "plant/pump/pressure".into(),
            condition: None,
        }],
        ..test_sop(
            "pressure-sop",
            SopExecutionMode::Auto,
            SopPriority::Critical,
        )
    };
    let engine = engine_with_sops(vec![sop]);
    let matches = engine.match_trigger(&mqtt_event("plant/pump/pressure", "87.3"));
    assert_eq!(matches.len(), 1);
}

#[test]
fn match_mqtt_wildcard_plus() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "plant/+/pressure".into(),
            condition: None,
        }],
        ..test_sop("wildcard-sop", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);
    assert_eq!(
        engine
            .match_trigger(&mqtt_event("plant/pump_3/pressure", "87"))
            .len(),
        1
    );
    assert!(engine
        .match_trigger(&mqtt_event("plant/pump_3/temperature", "50"))
        .is_empty());
}

#[test]
fn match_mqtt_wildcard_hash() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "plant/#".into(),
            condition: None,
        }],
        ..test_sop("hash-sop", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);
    assert_eq!(
        engine
            .match_trigger(&mqtt_event("plant/pump/pressure", "87"))
            .len(),
        1
    );
    assert_eq!(
        engine
            .match_trigger(&mqtt_event("plant/a/b/c/d", "x"))
            .len(),
        1
    );
}

#[test]
fn mqtt_topic_matching_edge_cases() {
    assert!(mqtt_topic_matches("a/b/c", "a/b/c"));
    assert!(!mqtt_topic_matches("a/b/c", "a/b/d"));
    assert!(!mqtt_topic_matches("a/b/c", "a/b"));
    assert!(!mqtt_topic_matches("a/b", "a/b/c"));
    assert!(mqtt_topic_matches("+/+/+", "a/b/c"));
    assert!(!mqtt_topic_matches("+/+", "a/b/c"));
    assert!(mqtt_topic_matches("#", "a/b/c"));
    assert!(mqtt_topic_matches("a/#", "a/b/c"));
    assert!(!mqtt_topic_matches("b/#", "a/b/c"));
}

// ── Webhook trigger matching ─────────────────────

#[test]
fn webhook_trigger_matches_exact_path() {
    let sop = Sop {
        triggers: vec![SopTrigger::Webhook {
            path: "/webhook".into(),
        }],
        ..test_sop("webhook-sop", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    // Exact match — should match
    let event = SopEvent {
        source: SopTriggerSource::Webhook,
        topic: Some("/webhook".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert_eq!(engine.match_trigger(&event).len(), 1);
}

#[test]
fn webhook_trigger_rejects_different_path() {
    let sop = Sop {
        triggers: vec![SopTrigger::Webhook {
            path: "/sop/deploy".into(),
        }],
        ..test_sop("deploy-sop", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    // Path /webhook does NOT match /sop/deploy
    let event = SopEvent {
        source: SopTriggerSource::Webhook,
        topic: Some("/webhook".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert!(engine.match_trigger(&event).is_empty());

    // But /sop/deploy matches /sop/deploy
    let event = SopEvent {
        source: SopTriggerSource::Webhook,
        topic: Some("/sop/deploy".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert_eq!(engine.match_trigger(&event).len(), 1);
}

// ── Cron trigger matching ─────────────────────────

#[test]
fn cron_trigger_matches_only_matching_expression() {
    let sop = Sop {
        triggers: vec![SopTrigger::Cron {
            expression: "0 */5 * * *".into(),
        }],
        ..test_sop("cron-sop", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    // Matching expression
    let event = SopEvent {
        source: SopTriggerSource::Cron,
        topic: Some("0 */5 * * *".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert_eq!(engine.match_trigger(&event).len(), 1);

    // Different expression — should NOT match
    let event = SopEvent {
        source: SopTriggerSource::Cron,
        topic: Some("0 */10 * * *".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert!(engine.match_trigger(&event).is_empty());

    // No topic — should NOT match
    let event = SopEvent {
        source: SopTriggerSource::Cron,
        topic: None,
        payload: None,
        timestamp: now_iso8601(),
    };
    assert!(engine.match_trigger(&event).is_empty());
}

// ── Condition-based trigger matching ────────────────

#[test]
fn mqtt_condition_filters_by_payload() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "sensors/pressure".into(),
            condition: Some("$.value > 85".into()),
        }],
        ..test_sop("cond-sop", SopExecutionMode::Auto, SopPriority::Critical)
    };
    let engine = engine_with_sops(vec![sop]);

    // Payload meets condition
    let matches = engine.match_trigger(&mqtt_event("sensors/pressure", r#"{"value": 90}"#));
    assert_eq!(matches.len(), 1);

    // Payload does not meet condition
    let matches = engine.match_trigger(&mqtt_event("sensors/pressure", r#"{"value": 50}"#));
    assert!(matches.is_empty());
}

#[test]
fn mqtt_no_condition_matches_any_payload() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "sensors/temp".into(),
            condition: None,
        }],
        ..test_sop("no-cond", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    let matches = engine.match_trigger(&mqtt_event("sensors/temp", "anything"));
    assert_eq!(matches.len(), 1);
}

#[test]
fn mqtt_condition_no_payload_fails_closed() {
    let sop = Sop {
        triggers: vec![SopTrigger::Mqtt {
            topic: "sensors/temp".into(),
            condition: Some("$.value > 0".into()),
        }],
        ..test_sop("no-payload", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    // Event with no payload
    let event = SopEvent {
        source: SopTriggerSource::Mqtt,
        topic: Some("sensors/temp".into()),
        payload: None,
        timestamp: now_iso8601(),
    };
    assert!(engine.match_trigger(&event).is_empty());
}

#[test]
fn peripheral_condition_filters_by_payload() {
    let sop = Sop {
        triggers: vec![SopTrigger::Peripheral {
            board: "nucleo".into(),
            signal: "pin_3".into(),
            condition: Some("> 0".into()),
        }],
        ..test_sop("periph-cond", SopExecutionMode::Auto, SopPriority::High)
    };
    let engine = engine_with_sops(vec![sop]);

    // Positive signal
    let event = SopEvent {
        source: SopTriggerSource::Peripheral,
        topic: Some("nucleo/pin_3".into()),
        payload: Some("1".into()),
        timestamp: now_iso8601(),
    };
    assert_eq!(engine.match_trigger(&event).len(), 1);

    // Zero signal — does not meet condition
    let event = SopEvent {
        source: SopTriggerSource::Peripheral,
        topic: Some("nucleo/pin_3".into()),
        payload: Some("0".into()),
        timestamp: now_iso8601(),
    };
    assert!(engine.match_trigger(&event).is_empty());
}

#[test]
fn peripheral_no_condition_matches_any() {
    let sop = Sop {
        triggers: vec![SopTrigger::Peripheral {
            board: "rpi".into(),
            signal: "gpio_5".into(),
            condition: None,
        }],
        ..test_sop("periph-nocond", SopExecutionMode::Auto, SopPriority::Normal)
    };
    let engine = engine_with_sops(vec![sop]);

    let event = SopEvent {
        source: SopTriggerSource::Peripheral,
        topic: Some("rpi/gpio_5".into()),
        payload: Some("0".into()),
        timestamp: now_iso8601(),
    };
    assert_eq!(engine.match_trigger(&event).len(), 1);
}

// ── Run lifecycle ───────────────────────────────────

#[test]
fn start_run_returns_first_step() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action);
    assert!(run_id.starts_with("run-"));
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));
    assert_eq!(engine.active_runs().len(), 1);
}

#[test]
fn start_run_unknown_sop_fails() {
    let mut engine = engine_with_sops(vec![]);
    assert!(engine.start_run("nonexistent", manual_event()).is_err());
}

#[test]
fn advance_step_to_completion() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Complete step 1
    let action = engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 1,
                status: SopStepStatus::Completed,
                output: "done".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();

    // Should get step 2
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));

    // Complete step 2
    let action = engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 2,
                status: SopStepStatus::Completed,
                output: "done".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();

    assert!(matches!(action, SopRunAction::Completed { .. }));
    assert!(engine.active_runs().is_empty());
    assert_eq!(engine.finished_runs(None).len(), 1);
}

#[test]
fn step_failure_ends_run() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    let action = engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 1,
                status: SopStepStatus::Failed,
                output: "valve stuck".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();

    assert!(
        matches!(action, SopRunAction::Failed { ref reason, .. } if reason.contains("valve stuck"))
    );
    assert!(engine.active_runs().is_empty());
}

#[test]
fn cancel_run() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    engine.cancel_run(&run_id).unwrap();
    assert!(engine.active_runs().is_empty());
    let finished = engine.finished_runs(None);
    assert_eq!(finished[0].status, SopRunStatus::Cancelled);
}

#[test]
fn cancel_unknown_run_fails() {
    let mut engine = engine_with_sops(vec![]);
    assert!(engine.cancel_run("nonexistent").is_err());
}

// ── Concurrency ─────────────────────────────────────

#[test]
fn per_sop_concurrency_limit() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    // max_concurrent = 1 by default
    engine.start_run("s1", manual_event()).unwrap();
    assert!(!engine.can_start("s1"));
    assert!(engine.start_run("s1", manual_event()).is_err());
}

#[test]
fn global_concurrency_limit() {
    let sops = vec![
        test_sop("s1", SopExecutionMode::Auto, SopPriority::Normal),
        test_sop("s2", SopExecutionMode::Auto, SopPriority::Normal),
    ];
    let mut engine = SopEngine::new(SopConfig {
        max_concurrent_total: 1,
        ..SopConfig::default()
    });
    engine.sops = sops;

    engine.start_run("s1", manual_event()).unwrap();
    assert!(!engine.can_start("s2"));
}

// ── Cooldown ────────────────────────────────────────

#[test]
fn cooldown_blocks_immediate_restart() {
    let mut sop = test_sop("s1", SopExecutionMode::Auto, SopPriority::Normal);
    sop.cooldown_secs = 3600; // 1 hour
    let mut engine = engine_with_sops(vec![sop]);

    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    // Complete both steps
    engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 1,
                status: SopStepStatus::Completed,
                output: "ok".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();
    engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 2,
                status: SopStepStatus::Completed,
                output: "ok".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();

    // Cooldown not elapsed — should block
    assert!(!engine.can_start("s1"));
}

// ── Execution modes ─────────────────────────────────

#[test]
fn auto_mode_executes_immediately() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));
}

#[test]
fn supervised_mode_waits_on_first_step() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));
}

#[test]
fn step_by_step_waits_on_every_step() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::StepByStep,
        SopPriority::Normal,
    )]);

    // Step 1: WaitApproval
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));

    // Approve step 1
    let action = engine.approve_step(&run_id).unwrap();
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));

    // Complete step 1, step 2 should also WaitApproval
    let action = engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 1,
                status: SopStepStatus::Completed,
                output: "ok".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));
}

#[test]
fn priority_based_critical_auto() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::PriorityBased,
        SopPriority::Critical,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));
}

#[test]
fn priority_based_normal_supervised() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::PriorityBased,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    // Normal + PriorityBased → Supervised → WaitApproval on step 1
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));
}

#[test]
fn requires_confirmation_overrides_auto() {
    let mut sop = test_sop("s1", SopExecutionMode::Auto, SopPriority::Critical);
    sop.steps[0].requires_confirmation = true;
    let mut engine = engine_with_sops(vec![sop]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    // Even in Auto mode, requires_confirmation forces WaitApproval
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));
}

// ── Approve ─────────────────────────────────────────

#[test]
fn approve_transitions_to_execute() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Run should be WaitingApproval
    let run = engine.active_runs().get(&run_id).unwrap();
    assert_eq!(run.status, SopRunStatus::WaitingApproval);

    // Approve
    let action = engine.approve_step(&run_id).unwrap();
    assert!(matches!(action, SopRunAction::ExecuteStep { .. }));

    let run = engine.active_runs().get(&run_id).unwrap();
    assert_eq!(run.status, SopRunStatus::Running);
}

#[test]
fn approve_non_waiting_fails() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    assert!(engine.approve_step(&run_id).is_err());
}

// ── Context formatting ──────────────────────────────

#[test]
fn step_context_includes_sop_name_and_step() {
    let sop = test_sop(
        "pump-shutdown",
        SopExecutionMode::Auto,
        SopPriority::Critical,
    );
    let run = SopRun {
        run_id: "run-001".into(),
        sop_name: "pump-shutdown".into(),
        trigger_event: manual_event(),
        status: SopRunStatus::Running,
        current_step: 1,
        total_steps: 2,
        started_at: now_iso8601(),
        completed_at: None,
        step_results: Vec::new(),
        waiting_since: None,
        llm_calls_saved: 0,
    };
    let ctx = format_step_context(&sop, &run, &sop.steps[0]);
    assert!(ctx.contains("pump-shutdown"));
    assert!(ctx.contains("Step 1 of 2"));
    assert!(ctx.contains("Step one"));
}

// ── Get run (active + finished) ─────────────────────

#[test]
fn get_run_finds_active_and_finished() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Active
    assert!(engine.get_run(&run_id).is_some());
    assert_eq!(
        engine.get_run(&run_id).unwrap().status,
        SopRunStatus::Running
    );

    // Complete
    engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 1,
                status: SopStepStatus::Completed,
                output: "ok".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();
    engine
        .advance_step(
            &run_id,
            SopStepResult {
                step_number: 2,
                status: SopStepStatus::Completed,
                output: "ok".into(),
                started_at: now_iso8601(),
                completed_at: Some(now_iso8601()),
            },
        )
        .unwrap();

    // Now finished — still findable
    assert!(engine.get_run(&run_id).is_some());
    assert_eq!(
        engine.get_run(&run_id).unwrap().status,
        SopRunStatus::Completed
    );

    // Unknown
    assert!(engine.get_run("nonexistent").is_none());
}

// ── ISO-8601 helpers ────────────────────────────────

#[test]
fn iso8601_roundtrip() {
    let ts = now_iso8601();
    let secs = parse_iso8601_secs(&ts);
    assert!(secs.is_some());
    // Should be close to current time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now.abs_diff(secs.unwrap()) < 2);
}

#[test]
fn parse_known_timestamp() {
    // 2026-01-01T00:00:00Z
    let secs = parse_iso8601_secs("2026-01-01T00:00:00Z").unwrap();
    // Jan 1 2026 = 20454 days since epoch * 86400
    assert_eq!(secs, 20454 * 86400);
}

// ── Approval timeout ─────────────────────────────────

#[test]
fn timeout_auto_approves_critical() {
    let mut engine = SopEngine::new(SopConfig {
        approval_timeout_secs: 1, // 1 second for test
        ..SopConfig::default()
    });
    let mut sop = test_sop("s1", SopExecutionMode::Supervised, SopPriority::Critical);
    // PriorityBased would auto-execute critical, so use Supervised to force WaitApproval
    sop.execution_mode = SopExecutionMode::Supervised;
    engine.set_sops_for_test(vec![sop]);

    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    assert!(matches!(action, SopRunAction::WaitApproval { .. }));

    // Manually backdate waiting_since to simulate timeout
    let run = engine.active_runs.get_mut(&run_id).unwrap();
    run.waiting_since = Some("2020-01-01T00:00:00Z".into());

    let actions = engine.check_approval_timeouts();
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], SopRunAction::ExecuteStep { .. }));
}

#[test]
fn timeout_does_not_auto_approve_normal() {
    let mut engine = SopEngine::new(SopConfig {
        approval_timeout_secs: 1,
        ..SopConfig::default()
    });
    engine.set_sops_for_test(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Normal,
    )]);

    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Backdate waiting_since
    let run = engine.active_runs.get_mut(&run_id).unwrap();
    run.waiting_since = Some("2020-01-01T00:00:00Z".into());

    // Normal priority → no auto-approve
    let actions = engine.check_approval_timeouts();
    assert!(actions.is_empty());
    // Run should still be WaitingApproval
    assert_eq!(
        engine.get_run(&run_id).unwrap().status,
        SopRunStatus::WaitingApproval
    );
}

#[test]
fn timeout_zero_disables_check() {
    let mut engine = SopEngine::new(SopConfig {
        approval_timeout_secs: 0,
        ..SopConfig::default()
    });
    engine.set_sops_for_test(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Critical,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    let run = engine.active_runs.get_mut(&run_id).unwrap();
    run.waiting_since = Some("2020-01-01T00:00:00Z".into());

    let actions = engine.check_approval_timeouts();
    assert!(actions.is_empty());
}

#[test]
fn waiting_since_set_on_wait_approval() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    let run = engine.get_run(&run_id).unwrap();
    assert_eq!(run.status, SopRunStatus::WaitingApproval);
    assert!(run.waiting_since.is_some());
}

// ── Eviction ──────────────────────────────────────

#[test]
fn max_finished_runs_evicts_oldest() {
    let mut engine = SopEngine::new(SopConfig {
        max_finished_runs: 2,
        ..SopConfig::default()
    });
    // SOP with 1 step so each run completes in one advance
    let mut sop = test_sop("s1", SopExecutionMode::Auto, SopPriority::Normal);
    sop.steps = vec![sop.steps[0].clone()];
    sop.max_concurrent = 10;
    engine.sops = vec![sop];

    // Complete 3 runs
    let mut finished_ids = Vec::new();
    for _ in 0..3 {
        let action = engine.start_run("s1", manual_event()).unwrap();
        let rid = extract_run_id(&action).to_string();
        engine
            .advance_step(
                &rid,
                SopStepResult {
                    step_number: 1,
                    status: SopStepStatus::Completed,
                    output: "ok".into(),
                    started_at: now_iso8601(),
                    completed_at: Some(now_iso8601()),
                },
            )
            .unwrap();
        finished_ids.push(rid);
    }

    // Only 2 should be kept (max_finished_runs=2)
    let finished = engine.finished_runs(None);
    assert_eq!(
        finished.len(),
        2,
        "eviction should cap at max_finished_runs"
    );
    // Oldest (first) run should be evicted, newest two remain
    assert_eq!(finished[0].run_id, finished_ids[1]);
    assert_eq!(finished[1].run_id, finished_ids[2]);
}

#[test]
fn max_finished_runs_zero_means_unlimited() {
    let mut engine = SopEngine::new(SopConfig {
        max_finished_runs: 0,
        ..SopConfig::default()
    });
    let mut sop = test_sop("s1", SopExecutionMode::Auto, SopPriority::Normal);
    sop.steps = vec![sop.steps[0].clone()];
    sop.max_concurrent = 10;
    engine.sops = vec![sop];

    for _ in 0..5 {
        let action = engine.start_run("s1", manual_event()).unwrap();
        let rid = extract_run_id(&action).to_string();
        engine
            .advance_step(
                &rid,
                SopStepResult {
                    step_number: 1,
                    status: SopStepStatus::Completed,
                    output: "ok".into(),
                    started_at: now_iso8601(),
                    completed_at: Some(now_iso8601()),
                },
            )
            .unwrap();
    }

    assert_eq!(engine.finished_runs(None).len(), 5, "zero means unlimited");
}

#[test]
fn waiting_since_cleared_on_approve() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Supervised,
        SopPriority::Normal,
    )]);
    let action = engine.start_run("s1", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();
    engine.approve_step(&run_id).unwrap();

    let run = engine.get_run(&run_id).unwrap();
    assert_eq!(run.status, SopRunStatus::Running);
    assert!(run.waiting_since.is_none());
}

// ── Deterministic execution ─────────────────────────

fn deterministic_sop(name: &str) -> Sop {
    Sop {
        name: name.into(),
        description: format!("Deterministic SOP: {name}"),
        version: "1.0.0".into(),
        priority: SopPriority::Normal,
        execution_mode: SopExecutionMode::Deterministic,
        triggers: vec![SopTrigger::Manual],
        steps: vec![
            SopStep {
                number: 1,
                title: "Step one".into(),
                body: "Do step one".into(),
                suggested_tools: vec![],
                requires_confirmation: false,
                kind: SopStepKind::Execute,
                schema: None,
            },
            SopStep {
                number: 2,
                title: "Checkpoint".into(),
                body: "Pause for approval".into(),
                suggested_tools: vec![],
                requires_confirmation: false,
                kind: SopStepKind::Checkpoint,
                schema: None,
            },
            SopStep {
                number: 3,
                title: "Step three".into(),
                body: "Final step".into(),
                suggested_tools: vec![],
                requires_confirmation: false,
                kind: SopStepKind::Execute,
                schema: None,
            },
        ],
        cooldown_secs: 0,
        max_concurrent: 1,
        location: None,
        deterministic: true,
    }
}

#[test]
fn deterministic_start_returns_deterministic_step() {
    let mut engine = engine_with_sops(vec![deterministic_sop("det-sop")]);
    let action = engine.start_run("det-sop", manual_event()).unwrap();
    assert!(
        matches!(action, SopRunAction::DeterministicStep { ref step, .. } if step.number == 1),
        "First action should be DeterministicStep for step 1"
    );
    let run_id = extract_run_id(&action).to_string();
    assert!(run_id.starts_with("det-"));
}

#[test]
fn deterministic_start_routes_through_start_run() {
    let mut engine = engine_with_sops(vec![deterministic_sop("det-sop")]);
    // start_run should auto-route to start_deterministic_run
    let action = engine.start_run("det-sop", manual_event()).unwrap();
    assert!(matches!(action, SopRunAction::DeterministicStep { .. }));
}

#[test]
fn deterministic_advance_pipes_output() {
    let mut engine = engine_with_sops(vec![deterministic_sop("det-sop")]);
    let action = engine.start_run("det-sop", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Advance step 1 with output
    let output = serde_json::json!({"result": "step1_done"});
    let action = engine
        .advance_deterministic_step(&run_id, output.clone())
        .unwrap();

    // Step 2 is a checkpoint — should pause
    assert!(
        matches!(action, SopRunAction::CheckpointWait { ref step, .. } if step.number == 2),
        "Step 2 (checkpoint) should return CheckpointWait"
    );
}

#[test]
fn deterministic_checkpoint_pauses_run() {
    let mut engine = engine_with_sops(vec![deterministic_sop("det-sop")]);
    let action = engine.start_run("det-sop", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Complete step 1
    let action = engine
        .advance_deterministic_step(&run_id, serde_json::json!({"ok": true}))
        .unwrap();

    // Should be at checkpoint
    assert!(matches!(action, SopRunAction::CheckpointWait { .. }));

    // Run should be PausedCheckpoint
    let run = engine.get_run(&run_id).unwrap();
    assert_eq!(run.status, SopRunStatus::PausedCheckpoint);
    assert!(run.waiting_since.is_some());
}

#[test]
fn deterministic_completion_tracks_savings() {
    let mut sop = deterministic_sop("det-sop");
    // Simplify: 2 execute steps, no checkpoint
    sop.steps = vec![
        SopStep {
            number: 1,
            title: "Step one".into(),
            body: "Do it".into(),
            suggested_tools: vec![],
            requires_confirmation: false,
            kind: SopStepKind::Execute,
            schema: None,
        },
        SopStep {
            number: 2,
            title: "Step two".into(),
            body: "Do it too".into(),
            suggested_tools: vec![],
            requires_confirmation: false,
            kind: SopStepKind::Execute,
            schema: None,
        },
    ];
    let mut engine = engine_with_sops(vec![sop]);

    let action = engine.start_run("det-sop", manual_event()).unwrap();
    let run_id = extract_run_id(&action).to_string();

    // Complete step 1
    let action = engine
        .advance_deterministic_step(&run_id, serde_json::json!("s1"))
        .unwrap();
    assert!(matches!(action, SopRunAction::DeterministicStep { .. }));

    // Complete step 2
    let action = engine
        .advance_deterministic_step(&run_id, serde_json::json!("s2"))
        .unwrap();
    assert!(matches!(action, SopRunAction::Completed { .. }));

    // Check savings
    let savings = engine.deterministic_savings();
    assert_eq!(savings.total_runs, 1);
    assert_eq!(savings.total_llm_calls_saved, 2);
}

#[test]
fn deterministic_non_deterministic_sop_rejected() {
    let mut engine = engine_with_sops(vec![test_sop(
        "s1",
        SopExecutionMode::Auto,
        SopPriority::Normal,
    )]);
    let result = engine.start_deterministic_run("s1", manual_event());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not in deterministic mode"));
}
