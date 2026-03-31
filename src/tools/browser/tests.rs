use super::*;

#[test]
fn normalize_domains_works() {
    let domains = vec![
        "  Example.COM  ".into(),
        "docs.example.com".into(),
        String::new(),
    ];
    let normalized = normalize_domains(domains);
    assert_eq!(normalized, vec!["example.com", "docs.example.com"]);
}

#[test]
fn extract_host_works() {
    assert_eq!(
        extract_host("https://example.com/path").unwrap(),
        "example.com"
    );
    assert_eq!(
        extract_host("https://Sub.Example.COM:8080/").unwrap(),
        "sub.example.com"
    );
}

#[test]
fn extract_host_handles_ipv6() {
    // IPv6 with brackets (required for URLs with ports)
    assert_eq!(extract_host("https://[::1]/path").unwrap(), "[::1]");
    // IPv6 with brackets and port
    assert_eq!(
        extract_host("https://[2001:db8::1]:8080/path").unwrap(),
        "[2001:db8::1]"
    );
    // IPv6 with brackets, trailing slash
    assert_eq!(extract_host("https://[fe80::1]/").unwrap(), "[fe80::1]");
}

#[test]
fn is_private_host_detects_local() {
    assert!(is_private_host("localhost"));
    assert!(is_private_host("app.localhost"));
    assert!(is_private_host("printer.local"));
    assert!(is_private_host("127.0.0.1"));
    assert!(is_private_host("192.168.1.1"));
    assert!(is_private_host("10.0.0.1"));
    assert!(!is_private_host("example.com"));
    assert!(!is_private_host("google.com"));
}

#[test]
fn is_private_host_blocks_multicast_and_reserved() {
    assert!(is_private_host("224.0.0.1")); // multicast
    assert!(is_private_host("255.255.255.255")); // broadcast
    assert!(is_private_host("100.64.0.1")); // shared address space
    assert!(is_private_host("240.0.0.1")); // reserved
    assert!(is_private_host("192.0.2.1")); // documentation
    assert!(is_private_host("198.51.100.1")); // documentation
    assert!(is_private_host("203.0.113.1")); // documentation
    assert!(is_private_host("198.18.0.1")); // benchmarking
}

#[test]
fn is_private_host_catches_ipv6() {
    assert!(is_private_host("::1"));
    assert!(is_private_host("[::1]"));
    assert!(is_private_host("0.0.0.0"));
}

#[test]
fn is_private_host_catches_mapped_ipv4() {
    // IPv4-mapped IPv6 addresses
    assert!(is_private_host("::ffff:127.0.0.1"));
    assert!(is_private_host("::ffff:10.0.0.1"));
    assert!(is_private_host("::ffff:192.168.1.1"));
}

#[test]
fn is_private_host_catches_ipv6_private_ranges() {
    // Unique-local (fc00::/7)
    assert!(is_private_host("fd00::1"));
    assert!(is_private_host("fc00::1"));
    // Link-local (fe80::/10)
    assert!(is_private_host("fe80::1"));
    // Public IPv6 should pass
    assert!(!is_private_host("2001:db8::1"));
}

#[test]
fn validate_url_blocks_ipv6_ssrf() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new(security, vec!["*".into()], None);
    assert!(tool.validate_url("https://[::1]/").is_err());
    assert!(tool.validate_url("https://[::ffff:127.0.0.1]/").is_err());
    assert!(tool
        .validate_url("https://[::ffff:10.0.0.1]:8080/")
        .is_err());
}

#[test]
fn host_matches_allowlist_exact() {
    let allowed = vec!["example.com".into()];
    assert!(host_matches_allowlist("example.com", &allowed));
    assert!(host_matches_allowlist("sub.example.com", &allowed));
    assert!(!host_matches_allowlist("notexample.com", &allowed));
}

#[test]
fn host_matches_allowlist_wildcard() {
    let allowed = vec!["*.example.com".into()];
    assert!(host_matches_allowlist("sub.example.com", &allowed));
    assert!(host_matches_allowlist("example.com", &allowed));
    assert!(!host_matches_allowlist("other.com", &allowed));
}

#[test]
fn host_matches_allowlist_star() {
    let allowed = vec!["*".into()];
    assert!(host_matches_allowlist("anything.com", &allowed));
    assert!(host_matches_allowlist("example.org", &allowed));
}

#[test]
fn browser_backend_parser_accepts_supported_values() {
    assert_eq!(
        BrowserBackendKind::parse("agent_browser").unwrap(),
        BrowserBackendKind::AgentBrowser
    );
    assert_eq!(
        BrowserBackendKind::parse("rust-native").unwrap(),
        BrowserBackendKind::RustNative
    );
    assert_eq!(
        BrowserBackendKind::parse("computer_use").unwrap(),
        BrowserBackendKind::ComputerUse
    );
    assert_eq!(
        BrowserBackendKind::parse("auto").unwrap(),
        BrowserBackendKind::Auto
    );
}

#[test]
fn browser_backend_parser_rejects_unknown_values() {
    assert!(BrowserBackendKind::parse("playwright").is_err());
}

#[test]
fn browser_tool_default_backend_is_agent_browser() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new(security, vec!["example.com".into()], None);
    assert_eq!(
        tool.configured_backend().unwrap(),
        BrowserBackendKind::AgentBrowser
    );
}

#[test]
fn browser_tool_accepts_auto_backend_config() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new_with_backend(
        security,
        vec!["example.com".into()],
        None,
        "auto".into(),
        true,
        "http://127.0.0.1:9515".into(),
        None,
        ComputerUseConfig::default(),
    );
    assert_eq!(tool.configured_backend().unwrap(), BrowserBackendKind::Auto);
}

#[test]
fn browser_tool_accepts_computer_use_backend_config() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new_with_backend(
        security,
        vec!["example.com".into()],
        None,
        "computer_use".into(),
        true,
        "http://127.0.0.1:9515".into(),
        None,
        ComputerUseConfig::default(),
    );
    assert_eq!(
        tool.configured_backend().unwrap(),
        BrowserBackendKind::ComputerUse
    );
}

#[test]
fn computer_use_endpoint_rejects_public_http_by_default() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new_with_backend(
        security,
        vec!["example.com".into()],
        None,
        "computer_use".into(),
        true,
        "http://127.0.0.1:9515".into(),
        None,
        ComputerUseConfig {
            endpoint: "http://computer-use.example.com/v1/actions".into(),
            ..ComputerUseConfig::default()
        },
    );

    assert!(tool.computer_use_endpoint_url().is_err());
}

#[test]
fn computer_use_endpoint_requires_https_for_public_remote() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new_with_backend(
        security,
        vec!["example.com".into()],
        None,
        "computer_use".into(),
        true,
        "http://127.0.0.1:9515".into(),
        None,
        ComputerUseConfig {
            endpoint: "https://computer-use.example.com/v1/actions".into(),
            allow_remote_endpoint: true,
            ..ComputerUseConfig::default()
        },
    );

    assert!(tool.computer_use_endpoint_url().is_ok());
}

#[test]
fn computer_use_coordinate_validation_applies_limits() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new_with_backend(
        security,
        vec!["example.com".into()],
        None,
        "computer_use".into(),
        true,
        "http://127.0.0.1:9515".into(),
        None,
        ComputerUseConfig {
            max_coordinate_x: Some(100),
            max_coordinate_y: Some(100),
            ..ComputerUseConfig::default()
        },
    );

    assert!(tool
        .validate_coordinate("x", 50, tool.computer_use.max_coordinate_x)
        .is_ok());
    assert!(tool
        .validate_coordinate("x", 101, tool.computer_use.max_coordinate_x)
        .is_err());
    assert!(tool
        .validate_coordinate("y", -1, tool.computer_use.max_coordinate_y)
        .is_err());
}

#[test]
fn browser_tool_name() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new(security, vec!["example.com".into()], None);
    assert_eq!(tool.name(), "browser");
}

#[test]
fn browser_tool_validates_url() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new(security, vec!["example.com".into()], None);

    // Valid
    assert!(tool.validate_url("https://example.com").is_ok());
    assert!(tool.validate_url("https://sub.example.com/path").is_ok());

    // Invalid - not in allowlist
    assert!(tool.validate_url("https://other.com").is_err());

    // Invalid - private host
    assert!(tool.validate_url("https://localhost").is_err());
    assert!(tool.validate_url("https://127.0.0.1").is_err());

    // Invalid - not https
    assert!(tool.validate_url("ftp://example.com").is_err());

    // file:// URLs blocked (local file exfiltration risk)
    assert!(tool.validate_url("file:///tmp/test.html").is_err());
}

#[test]
fn browser_tool_empty_allowlist_blocks() {
    let security = Arc::new(SecurityPolicy::default());
    let tool = BrowserTool::new(security, vec![], None);
    assert!(tool.validate_url("https://example.com").is_err());
}

#[test]
fn computer_use_only_action_detection_is_correct() {
    assert!(is_computer_use_only_action("mouse_move"));
    assert!(is_computer_use_only_action("mouse_click"));
    assert!(is_computer_use_only_action("mouse_drag"));
    assert!(is_computer_use_only_action("key_type"));
    assert!(is_computer_use_only_action("key_press"));
    assert!(is_computer_use_only_action("screen_capture"));
    assert!(!is_computer_use_only_action("open"));
    assert!(!is_computer_use_only_action("snapshot"));
}

#[test]
fn unavailable_action_error_preserves_backend_context() {
    assert_eq!(
        unavailable_action_for_backend_error("mouse_move", ResolvedBackend::AgentBrowser),
        "Action 'mouse_move' is unavailable for backend 'agent_browser'"
    );
    assert_eq!(
        unavailable_action_for_backend_error("mouse_move", ResolvedBackend::RustNative),
        "Action 'mouse_move' is unavailable for backend 'rust_native'"
    );
}

#[test]
fn recoverable_error_detection_matches_session_patterns() {
    for message in [
        "invalid session id",
        "No Such Window",
        "session not created",
        "connection reset by peer",
        "broken pipe while writing webdriver command",
        "WebDriver request timed out",
    ] {
        let err = anyhow::anyhow!(message);
        assert!(is_recoverable_rust_native_error(&err), "{message}");
    }

    let allowlist_error =
        anyhow::anyhow!("URL host 'localhost' is not in browser allowlist [example.com]");
    assert!(!is_recoverable_rust_native_error(&allowlist_error));
}

#[test]
fn non_recoverable_error_detection_rejects_policy_errors() {
    for message in [
        "Blocked by security policy",
        "URL host '127.0.0.1' is private and disallowed",
        "Action 'mouse_move' is unavailable for backend 'rust_native'",
    ] {
        let err = anyhow::anyhow!(message);
        assert!(!is_recoverable_rust_native_error(&err), "{message}");
    }
}

#[cfg(feature = "browser-native")]
#[test]
fn reset_session_is_idempotent_without_client() {
    tokio_test::block_on(async {
        let mut state = native_backend::NativeBrowserState::default();
        state.reset_session().await;
        state.reset_session().await;
    });
}

#[test]
fn ensure_browser_env_sets_home_when_missing() {
    let original_home = std::env::var_os("HOME");
    unsafe { std::env::remove_var("HOME") };

    let mut cmd = Command::new("true");
    ensure_browser_env(&mut cmd);
    // Function completes without panic — HOME and CHROMIUM_FLAGS set on cmd.

    if let Some(home) = original_home {
        unsafe { std::env::set_var("HOME", home) };
    }
}

#[test]
fn ensure_browser_env_sets_chromium_flags() {
    let original = std::env::var_os("CHROMIUM_FLAGS");
    unsafe { std::env::remove_var("CHROMIUM_FLAGS") };

    let mut cmd = Command::new("true");
    ensure_browser_env(&mut cmd);

    if let Some(val) = original {
        unsafe { std::env::set_var("CHROMIUM_FLAGS", val) };
    }
}

#[test]
fn is_service_environment_detects_invocation_id() {
    let original = std::env::var_os("INVOCATION_ID");
    unsafe { std::env::set_var("INVOCATION_ID", "test-unit-id") };

    assert!(is_service_environment());

    if let Some(val) = original {
        unsafe { std::env::set_var("INVOCATION_ID", val) };
    } else {
        unsafe { std::env::remove_var("INVOCATION_ID") };
    }
}

#[test]
fn is_service_environment_detects_journal_stream() {
    let original = std::env::var_os("JOURNAL_STREAM");
    unsafe { std::env::set_var("JOURNAL_STREAM", "8:12345") };

    assert!(is_service_environment());

    if let Some(val) = original {
        unsafe { std::env::set_var("JOURNAL_STREAM", val) };
    } else {
        unsafe { std::env::remove_var("JOURNAL_STREAM") };
    }
}

#[test]
fn is_service_environment_false_in_normal_context() {
    let inv = std::env::var_os("INVOCATION_ID");
    let journal = std::env::var_os("JOURNAL_STREAM");
    unsafe { std::env::remove_var("INVOCATION_ID") };
    unsafe { std::env::remove_var("JOURNAL_STREAM") };

    if std::env::var_os("HOME").is_some() {
        assert!(!is_service_environment());
    }

    if let Some(val) = inv {
        unsafe { std::env::set_var("INVOCATION_ID", val) };
    }
    if let Some(val) = journal {
        unsafe { std::env::set_var("JOURNAL_STREAM", val) };
    }
}

#[test]
fn windows_command_name_selection() {
    // Verify the cfg-based command name logic used in is_agent_browser_available
    // and run_command selects the correct binary name per platform.
    let cmd = if cfg!(target_os = "windows") {
        "agent-browser.cmd"
    } else {
        "agent-browser"
    };

    if cfg!(target_os = "windows") {
        assert_eq!(cmd, "agent-browser.cmd");
    } else {
        assert_eq!(cmd, "agent-browser");
    }
}
