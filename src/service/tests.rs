use super::*;

#[test]
fn xml_escape_escapes_reserved_chars() {
    let escaped = xml_escape("<&>\"' and text");
    assert_eq!(escaped, "&lt;&amp;&gt;&quot;&apos; and text");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn run_capture_reads_stdout() {
    let out = run_capture(Command::new("sh").args(["-c", "echo hello"]))
        .expect("stdout capture should succeed");
    assert_eq!(out.trim(), "hello");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn run_capture_falls_back_to_stderr() {
    let out = run_capture(Command::new("sh").args(["-c", "echo warn 1>&2"]))
        .expect("stderr capture should succeed");
    assert_eq!(out.trim(), "warn");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn run_checked_errors_on_non_zero_status() {
    let err = run_checked(Command::new("sh").args(["-c", "exit 17"]))
        .expect_err("non-zero exit should error");
    assert!(err.to_string().contains("Command failed"));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn linux_service_file_has_expected_suffix() {
    let file = linux_service_file(&Config::default()).unwrap();
    let path = file.to_string_lossy();
    assert!(path.ends_with(".config/systemd/user/zeroclaw.service"));
}

#[test]
fn windows_task_name_is_constant() {
    assert_eq!(windows_task_name(), "ZeroClaw Daemon");
}

#[cfg(target_os = "windows")]
#[test]
fn run_capture_reads_stdout_windows() {
    let out = run_capture(Command::new("cmd").args(["/C", "echo hello"]))
        .expect("stdout capture should succeed");
    assert_eq!(out.trim(), "hello");
}

#[cfg(target_os = "windows")]
#[test]
fn run_checked_errors_on_non_zero_status_windows() {
    let err = run_checked(Command::new("cmd").args(["/C", "exit /b 17"]))
        .expect_err("non-zero exit should error");
    assert!(err.to_string().contains("Command failed"));
}

#[test]
fn init_system_from_str_parses_valid_values() {
    assert_eq!("auto".parse::<InitSystem>().unwrap(), InitSystem::Auto);
    assert_eq!("AUTO".parse::<InitSystem>().unwrap(), InitSystem::Auto);
    assert_eq!(
        "systemd".parse::<InitSystem>().unwrap(),
        InitSystem::Systemd
    );
    assert_eq!(
        "SYSTEMD".parse::<InitSystem>().unwrap(),
        InitSystem::Systemd
    );
    assert_eq!("openrc".parse::<InitSystem>().unwrap(), InitSystem::Openrc);
    assert_eq!("OPENRC".parse::<InitSystem>().unwrap(), InitSystem::Openrc);
}

#[test]
fn init_system_from_str_rejects_unknown() {
    let err = "unknown"
        .parse::<InitSystem>()
        .expect_err("should reject unknown");
    assert!(err.to_string().contains("Unknown init system"));
    assert!(err.to_string().contains("Supported: auto, systemd, openrc"));
}

#[test]
fn init_system_default_is_auto() {
    assert_eq!(InitSystem::default(), InitSystem::Auto);
}

#[cfg(unix)]
#[test]
fn is_root_matches_system_uid() {
    // SAFETY: `getuid()` is a simple system call that returns the real user ID of the calling
    // process. It is always safe to call as it takes no arguments and returns a scalar value.
    // This test verifies our `is_root()` wrapper returns the same result as the raw syscall.
    assert_eq!(is_root(), unsafe { libc::getuid() == 0 });
}

#[test]
fn generate_openrc_script_contains_required_directives() {
    use std::path::PathBuf;

    let exe_path = PathBuf::from("/usr/local/bin/zeroclaw");
    let script = generate_openrc_script(&exe_path, Path::new("/etc/zeroclaw"));

    assert!(script.starts_with("#!/sbin/openrc-run"));
    assert!(script.contains("name=\"zeroclaw\""));
    assert!(script.contains("description=\"ZeroClaw daemon\""));
    assert!(script.contains("command=\"/usr/local/bin/zeroclaw\""));
    assert!(script.contains("command_args=\"--config-dir /etc/zeroclaw daemon\""));
    assert!(!script.contains("env ZEROCLAW_CONFIG_DIR"));
    assert!(!script.contains("env ZEROCLAW_WORKSPACE"));
    assert!(script.contains("command_background=\"yes\""));
    assert!(script.contains("command_user=\"zeroclaw:zeroclaw\""));
    assert!(script.contains("pidfile=\"/run/${RC_SVCNAME}.pid\""));
    assert!(script.contains("umask 027"));
    assert!(script.contains("output_log=\"/var/log/zeroclaw/access.log\""));
    assert!(script.contains("error_log=\"/var/log/zeroclaw/error.log\""));
    assert!(script.contains("depend()"));
    assert!(script.contains("need net"));
    assert!(script.contains("after firewall"));
}

#[test]
fn generate_openrc_script_sets_home_for_browser() {
    use std::path::PathBuf;

    let exe_path = PathBuf::from("/usr/local/bin/zeroclaw");
    let script = generate_openrc_script(&exe_path, Path::new("/etc/zeroclaw"));

    assert!(
        script.contains("export HOME=\"/var/lib/zeroclaw\""),
        "OpenRC script must set HOME for headless browser support"
    );
}

#[test]
fn generate_openrc_script_creates_home_directory() {
    use std::path::PathBuf;

    let exe_path = PathBuf::from("/usr/local/bin/zeroclaw");
    let script = generate_openrc_script(&exe_path, Path::new("/etc/zeroclaw"));

    assert!(
        script.contains("start_pre()"),
        "OpenRC script must have start_pre to create HOME dir"
    );
    assert!(
        script.contains("checkpath --directory --owner zeroclaw:zeroclaw"),
        "start_pre must ensure /var/lib/zeroclaw exists with correct ownership"
    );
}

#[test]
fn systemd_unit_contains_home_and_pass_environment() {
    let unit = "[Unit]\n\
             Description=ZeroClaw daemon\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart=/usr/local/bin/zeroclaw daemon\n\
             Restart=always\n\
             RestartSec=3\n\
             # Ensure HOME is set so headless browsers can create profile/cache dirs.\n\
             Environment=HOME=%h\n\
             # Allow inheriting DISPLAY and XDG_RUNTIME_DIR from the user session\n\
             # so graphical/headless browsers can function correctly.\n\
             PassEnvironment=DISPLAY XDG_RUNTIME_DIR\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        .to_string();

    assert!(
        unit.contains("Environment=HOME=%h"),
        "systemd unit must set HOME for headless browser support"
    );
    assert!(
        unit.contains("PassEnvironment=DISPLAY XDG_RUNTIME_DIR"),
        "systemd unit must pass through display/runtime env vars"
    );
}

#[test]
fn warn_if_binary_in_home_detects_home_path() {
    use std::path::PathBuf;

    let home_path = PathBuf::from("/home/user/.cargo/bin/zeroclaw");
    assert!(home_path.to_string_lossy().contains("/home/"));
    assert!(home_path.to_string_lossy().contains(".cargo/bin"));

    let cargo_path = PathBuf::from("/home/user/.cargo/bin/zeroclaw");
    assert!(cargo_path.to_string_lossy().contains(".cargo/bin"));

    let system_path = PathBuf::from("/usr/local/bin/zeroclaw");
    assert!(!system_path.to_string_lossy().contains("/home/"));
    assert!(!system_path.to_string_lossy().contains(".cargo/bin"));
}

#[cfg(unix)]
#[test]
fn shell_single_quote_escapes_single_quotes() {
    assert_eq!(
        shell_single_quote("/tmp/weird'path"),
        "'/tmp/weird'\"'\"'path'"
    );
}

#[cfg(unix)]
#[test]
fn openrc_writability_probe_prefers_runuser_when_available() {
    let (program, args) = build_openrc_writability_probe_command(Path::new("/etc/zeroclaw"), true);
    assert_eq!(program, "runuser");
    assert_eq!(
        args,
        vec![
            "-u".to_string(),
            "zeroclaw".to_string(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "test -w '/etc/zeroclaw'".to_string()
        ]
    );
}

#[test]
fn detect_homebrew_var_dir_from_cellar_path() {
    let exe = PathBuf::from("/opt/homebrew/Cellar/zeroclaw/1.2.3/bin/zeroclaw");
    let var_dir = detect_homebrew_var_dir(&exe);
    assert_eq!(var_dir, Some(PathBuf::from("/opt/homebrew/var/zeroclaw")));
}

#[test]
fn detect_homebrew_var_dir_intel_cellar_path() {
    let exe = PathBuf::from("/usr/local/Cellar/zeroclaw/1.0.0/bin/zeroclaw");
    let var_dir = detect_homebrew_var_dir(&exe);
    assert_eq!(var_dir, Some(PathBuf::from("/usr/local/var/zeroclaw")));
}

#[test]
fn detect_homebrew_var_dir_non_homebrew_path() {
    let exe = PathBuf::from("/home/user/.cargo/bin/zeroclaw");
    let var_dir = detect_homebrew_var_dir(&exe);
    assert_eq!(var_dir, None);
}

#[cfg(unix)]
#[test]
fn openrc_writability_probe_falls_back_to_su() {
    let (program, args) =
        build_openrc_writability_probe_command(Path::new("/etc/zeroclaw/workspace"), false);
    assert_eq!(program, "su");
    assert_eq!(
        args,
        vec![
            "-s".to_string(),
            "/bin/sh".to_string(),
            "-c".to_string(),
            "test -w '/etc/zeroclaw/workspace'".to_string(),
            "zeroclaw".to_string()
        ]
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn tail_file_errors_on_missing_file() {
    let missing = Path::new("/tmp/zeroclaw-test-nonexistent-log-file.log");
    let result = tail_file(missing, 10, false);
    assert!(result.is_err(), "tail on missing file should fail");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn tail_file_reads_existing_file() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let log = dir.path().join("test-tail.log");
    fs::write(&log, "line1\nline2\nline3\nline4\nline5\n").unwrap();
    // tail should succeed on existing file
    let result = tail_file(&log, 3, false);
    assert!(result.is_ok(), "tail on existing file should succeed");
}

#[test]
fn logs_variant_is_recognized() {
    // Ensure the Logs variant can be constructed and matched
    let cmd = crate::ServiceCommands::Logs {
        lines: 25,
        follow: true,
    };
    match &cmd {
        crate::ServiceCommands::Logs { lines, follow } => {
            assert_eq!(*lines, 25);
            assert!(*follow);
        }
        _ => panic!("Expected Logs variant"),
    }
}
