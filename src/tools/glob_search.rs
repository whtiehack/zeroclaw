use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::time::SystemTime;

const MAX_RESULTS: usize = 1000;

/// Translate user-friendly trailing `**` (intent: "everything under here") into
/// the strict glob-crate form `**/*`. In `rust-lang/glob`, `**` is its own
/// path component; standing alone at the end of a pattern it requires another
/// segment after it, otherwise it expands to nothing. Models reach for
/// `discord/**` first, so we normalize it transparently.
fn normalize_glob_pattern(pat: &str) -> String {
    if pat == "**" {
        return "**/*".to_string();
    }
    if let Some(prefix) = pat.strip_suffix("/**") {
        return format!("{prefix}/**/*");
    }
    pat.to_string()
}

fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if size >= GB {
        format!("{:.1} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.1} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.1} KB", size as f64 / KB as f64)
    } else {
        format!("{size} B")
    }
}

fn format_mtime(mtime: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = mtime.into();
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// Search for files by glob pattern within the workspace.
pub struct GlobSearchTool {
    security: Arc<SecurityPolicy>,
}

impl GlobSearchTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

#[async_trait]
impl Tool for GlobSearchTool {
    fn name(&self) -> &str {
        "glob_search"
    }

    fn description(&self) -> &str {
        "Search for files matching a glob pattern within the workspace. \
         Returns matching files with size and last-modified time, sorted by mtime descending (newest first). \
         Examples: '**/*.rs' (all Rust files), 'src/**/mod.rs' (all mod.rs in src)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match files, e.g. '**/*.rs', 'src/**/mod.rs'"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let pattern = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'pattern' parameter"))?;

        // Rate limit check (fast path)
        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        // Security: reject absolute paths
        if pattern.starts_with('/') || pattern.starts_with('\\') {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Absolute paths are not allowed. Use a relative glob pattern.".into()),
            });
        }

        // Security: reject path traversal
        if pattern.contains("../") || pattern.contains("..\\") || pattern == ".." {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Path traversal ('..') is not allowed in glob patterns.".into()),
            });
        }

        // Record action to consume rate limit budget
        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        // Build full pattern anchored to workspace
        let workspace = &self.security.workspace_dir;
        let normalized = normalize_glob_pattern(pattern);
        let full_pattern = workspace.join(&normalized).to_string_lossy().to_string();

        let entries = match glob::glob(&full_pattern) {
            Ok(paths) => paths,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid glob pattern: {e}")),
                });
            }
        };

        let workspace_canon = match std::fs::canonicalize(workspace) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Cannot resolve workspace directory: {e}")),
                });
            }
        };

        let mut results: Vec<(String, u64, SystemTime)> = Vec::new();
        let mut truncated = false;

        for entry in entries {
            let path = match entry {
                Ok(p) => p,
                Err(_) => continue, // skip unreadable entries
            };

            // Canonicalize to resolve symlinks, then verify still inside workspace
            let resolved = match std::fs::canonicalize(&path) {
                Ok(p) => p,
                Err(_) => continue, // skip broken symlinks / unresolvable paths
            };

            if !self.security.is_resolved_path_allowed(&resolved) {
                continue; // silently filter symlink escapes
            }

            let meta = match std::fs::metadata(&resolved) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Only include files, not directories
            if meta.is_dir() {
                continue;
            }

            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let size = meta.len();

            // Convert to workspace-relative path
            if let Ok(rel) = resolved.strip_prefix(&workspace_canon) {
                results.push((rel.to_string_lossy().to_string(), size, mtime));
            }

            if results.len() >= MAX_RESULTS {
                truncated = true;
                break;
            }
        }

        // Sort by mtime descending (newest first); same mtime → path ascending.
        results.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));

        let output = if results.is_empty() {
            format!("No files matching pattern '{pattern}' found in workspace.")
        } else {
            use std::fmt::Write;
            let mut buf = String::new();
            for (path, size, mtime) in &results {
                let _ =
                    writeln!(buf, "{path}  {size}  {mtime}", size = format_size(*size), mtime = format_mtime(*mtime));
            }
            // Trim trailing newline so the truncated/total banner is on its own line.
            if buf.ends_with('\n') {
                buf.pop();
            }
            if truncated {
                let _ = write!(
                    buf,
                    "\n\n[Results truncated: showing first {MAX_RESULTS} of more matches]"
                );
            }
            let _ = write!(buf, "\n\nTotal: {} files", results.len());
            buf
        };

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_security(workspace: PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            ..SecurityPolicy::default()
        })
    }

    fn test_security_with(
        workspace: PathBuf,
        autonomy: AutonomyLevel,
        max_actions_per_hour: u32,
    ) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy,
            workspace_dir: workspace,
            max_actions_per_hour,
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn glob_search_name_and_schema() {
        let tool = GlobSearchTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "glob_search");

        let schema = tool.parameters_schema();
        assert!(schema["properties"]["pattern"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("pattern")));
    }

    #[tokio::test]
    async fn glob_search_single_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "content").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "hello.txt"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("hello.txt"));
    }

    #[tokio::test]
    async fn glob_search_multiple_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        std::fs::write(dir.path().join("c.rs"), "").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "*.txt"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("a.txt"));
        assert!(result.output.contains("b.txt"));
        assert!(!result.output.contains("c.rs"));
    }

    #[tokio::test]
    async fn glob_search_recursive() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub/deep")).unwrap();
        std::fs::write(dir.path().join("root.txt"), "").unwrap();
        std::fs::write(dir.path().join("sub/mid.txt"), "").unwrap();
        std::fs::write(dir.path().join("sub/deep/leaf.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "**/*.txt"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("root.txt"));
        assert!(result.output.contains("mid.txt"));
        assert!(result.output.contains("leaf.txt"));
    }

    #[tokio::test]
    async fn glob_search_no_matches() {
        let dir = TempDir::new().unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool
            .execute(json!({"pattern": "*.nonexistent"}))
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.output.contains("No files matching pattern"));
    }

    #[tokio::test]
    async fn glob_search_missing_param() {
        let tool = GlobSearchTool::new(test_security(std::env::temp_dir()));
        let result = tool.execute(json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn glob_search_rejects_absolute_path() {
        let tool = GlobSearchTool::new(test_security(std::env::temp_dir()));
        let result = tool.execute(json!({"pattern": "/etc/**/*"})).await.unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Absolute paths"));
    }

    #[tokio::test]
    async fn glob_search_rejects_path_traversal() {
        let tool = GlobSearchTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"pattern": "../../../etc/passwd"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Path traversal"));
    }

    #[tokio::test]
    async fn glob_search_rejects_dotdot_only() {
        let tool = GlobSearchTool::new(test_security(std::env::temp_dir()));
        let result = tool.execute(json!({"pattern": ".."})).await.unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Path traversal"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn glob_search_filters_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().unwrap();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");

        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "leaked").unwrap();

        // Symlink inside workspace pointing outside
        symlink(outside.join("secret.txt"), workspace.join("escape.txt")).unwrap();
        // Also add a legitimate file
        std::fs::write(workspace.join("legit.txt"), "ok").unwrap();

        let tool = GlobSearchTool::new(test_security(workspace.clone()));
        let result = tool.execute(json!({"pattern": "*.txt"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("legit.txt"));
        assert!(!result.output.contains("escape.txt"));
        assert!(!result.output.contains("secret.txt"));
    }

    #[tokio::test]
    async fn glob_search_readonly_mode() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security_with(
            dir.path().to_path_buf(),
            AutonomyLevel::ReadOnly,
            20,
        ));
        let result = tool.execute(json!({"pattern": "*.txt"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("file.txt"));
    }

    #[tokio::test]
    async fn glob_search_rate_limited() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security_with(
            dir.path().to_path_buf(),
            AutonomyLevel::Supervised,
            0,
        ));
        let result = tool.execute(json!({"pattern": "*.txt"})).await.unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Rate limit"));
    }

    #[tokio::test]
    async fn glob_search_results_sorted_by_mtime_desc() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("c.txt"), "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.path().join("b.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "*.txt"})).await.unwrap();

        assert!(result.success);
        let lines: Vec<&str> = result.output.lines().collect();
        // Newest written first; each line is "path  size  mtime".
        assert!(lines.len() >= 3);
        assert!(lines[0].starts_with("b.txt"));
        assert!(lines[1].starts_with("a.txt"));
        assert!(lines[2].starts_with("c.txt"));
    }

    #[test]
    fn normalize_trailing_double_star() {
        assert_eq!(normalize_glob_pattern("discord/**"), "discord/**/*");
        assert_eq!(normalize_glob_pattern("**"), "**/*");
        assert_eq!(normalize_glob_pattern("a/b/**"), "a/b/**/*");
        // Patterns that already have content after `**` are left alone.
        assert_eq!(normalize_glob_pattern("discord/**/*"), "discord/**/*");
        assert_eq!(normalize_glob_pattern("discord/**/*.cs"), "discord/**/*.cs");
        assert_eq!(normalize_glob_pattern("discord/*"), "discord/*");
        assert_eq!(normalize_glob_pattern("*.txt"), "*.txt");
    }

    #[tokio::test]
    async fn glob_search_trailing_double_star_lists_all_files() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("top.txt"), "").unwrap();
        std::fs::write(dir.path().join("sub/leaf.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "**"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("top.txt"));
        assert!(result.output.contains("leaf.txt"));
    }

    #[tokio::test]
    async fn glob_search_output_includes_size_and_mtime() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("data.txt"), "1234567890").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool
            .execute(json!({"pattern": "data.txt"}))
            .await
            .unwrap();

        assert!(result.success);
        let first = result.output.lines().next().unwrap();
        assert!(first.starts_with("data.txt"));
        assert!(first.contains("10 B"));
        assert!(first.contains("UTC"));
    }

    #[tokio::test]
    async fn glob_search_excludes_directories() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::fs::write(dir.path().join("file.txt"), "").unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "*"})).await.unwrap();

        assert!(result.success);
        assert!(result.output.contains("file.txt"));
        assert!(!result.output.contains("subdir"));
    }

    #[tokio::test]
    async fn glob_search_invalid_pattern() {
        let dir = TempDir::new().unwrap();

        let tool = GlobSearchTool::new(test_security(dir.path().to_path_buf()));
        let result = tool.execute(json!({"pattern": "[invalid"})).await.unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("Invalid glob pattern"));
    }
}
