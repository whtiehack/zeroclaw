use super::traits::{Tool, ToolResult};
use crate::security::file_link_guard::has_multiple_hard_links;
use crate::security::sensitive_paths::is_sensitive_file_path;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

/// Move (rename) a file inside the workspace.
pub struct FileMoveTool {
    security: Arc<SecurityPolicy>,
}

impl FileMoveTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

fn sensitive_block_message(path: &str) -> String {
    format!(
        "Moving sensitive file '{path}' is blocked by policy. \
Set [autonomy].allow_sensitive_file_writes = true only when strictly necessary."
    )
}

fn hard_link_block_message(path: &Path) -> String {
    format!(
        "Moving multiply-linked file '{}' is blocked by policy \
(potential hard-link escape).",
        path.display()
    )
}

#[async_trait]
impl Tool for FileMoveTool {
    fn name(&self) -> &str {
        "file_move"
    }

    fn description(&self) -> &str {
        "Move or rename a file inside the workspace. Refuses to overwrite an existing destination, follow symlinks, or move sensitive files (e.g. .env)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Existing file path. Relative paths resolve from workspace; outside paths require policy allowlist."
                },
                "destination": {
                    "type": "string",
                    "description": "New file path. Must not already exist. Relative paths resolve from workspace; outside paths require policy allowlist."
                }
            },
            "required": ["source", "destination"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let source = args
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'source' parameter"))?;

        let destination = args
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'destination' parameter"))?;

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        if !self.security.is_path_allowed(source) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Source path not allowed by security policy: {source}")),
            });
        }
        if !self.security.is_path_allowed(destination) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Destination path not allowed by security policy: {destination}"
                )),
            });
        }

        let allow_sensitive = self.security.allow_sensitive_file_writes;
        if !allow_sensitive && is_sensitive_file_path(Path::new(source)) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(source)),
            });
        }
        if !allow_sensitive && is_sensitive_file_path(Path::new(destination)) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(destination)),
            });
        }

        let source_full = self.security.resolve_user_supplied_path(source);
        let dest_full = self.security.resolve_user_supplied_path(destination);

        // Source must exist and be a non-symlink regular file.
        let source_meta = match tokio::fs::symlink_metadata(&source_full).await {
            Ok(m) => m,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Source not found: {e}")),
                });
            }
        };
        if source_meta.file_type().is_symlink() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Refusing to move a symlink: {}",
                    source_full.display()
                )),
            });
        }
        if !source_meta.is_file() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Source is not a regular file: {}",
                    source_full.display()
                )),
            });
        }
        if has_multiple_hard_links(&source_meta) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(hard_link_block_message(&source_full)),
            });
        }

        // Resolve source to a canonical path and ensure it stays within policy.
        let resolved_source = match tokio::fs::canonicalize(&source_full).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve source path: {e}")),
                });
            }
        };
        if !self.security.is_resolved_path_allowed(&resolved_source) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    self.security
                        .resolved_path_violation_message(&resolved_source),
                ),
            });
        }
        if !allow_sensitive && is_sensitive_file_path(&resolved_source) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(
                    &resolved_source.display().to_string(),
                )),
            });
        }

        // Destination parent must be under policy. Create it if missing (mirrors file_write).
        let Some(dest_parent) = dest_full.parent() else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Invalid destination: missing parent directory".into()),
            });
        };
        tokio::fs::create_dir_all(dest_parent).await?;
        let resolved_dest_parent = match tokio::fs::canonicalize(dest_parent).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve destination path: {e}")),
                });
            }
        };
        if !self.security.is_resolved_path_allowed(&resolved_dest_parent) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    self.security
                        .resolved_path_violation_message(&resolved_dest_parent),
                ),
            });
        }

        let Some(dest_file_name) = dest_full.file_name() else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Invalid destination: missing file name".into()),
            });
        };
        let resolved_dest = resolved_dest_parent.join(dest_file_name);

        if !allow_sensitive && is_sensitive_file_path(&resolved_dest) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(
                    &resolved_dest.display().to_string(),
                )),
            });
        }

        // Refuse overwrite. Small TOCTOU window between this check and rename
        // is acceptable inside the single-tenant workspace.
        if tokio::fs::symlink_metadata(&resolved_dest).await.is_ok() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Destination already exists: {}. Delete it first if you intend to overwrite.",
                    resolved_dest.display()
                )),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        match tokio::fs::rename(&resolved_source, &resolved_dest).await {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Moved {source} → {destination}"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to move file: {e}")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_security(workspace: std::path::PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            ..SecurityPolicy::default()
        })
    }

    fn test_security_readonly(workspace: std::path::PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            workspace_dir: workspace,
            ..SecurityPolicy::default()
        })
    }

    fn test_security_rate_limited(workspace: std::path::PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            max_actions_per_hour: 0,
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn file_move_name_and_schema() {
        let tool = FileMoveTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "file_move");
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["source"].is_object());
        assert!(schema["properties"]["destination"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("source")));
        assert!(required.contains(&json!("destination")));
    }

    #[tokio::test]
    async fn file_move_renames_file() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_basic");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "hi").await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "a.txt", "destination": "b.txt"}))
            .await
            .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(!dir.join("a.txt").exists());
        let content = tokio::fs::read_to_string(dir.join("b.txt")).await.unwrap();
        assert_eq!(content, "hi");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_creates_parent() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_parent");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("src.txt"), "x").await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "src.txt", "destination": "sub/nested/dst.txt"}))
            .await
            .unwrap();
        assert!(result.success, "{:?}", result.error);
        let content = tokio::fs::read_to_string(dir.join("sub/nested/dst.txt"))
            .await
            .unwrap();
        assert_eq!(content, "x");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_refuses_overwrite() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_overwrite");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "src").await.unwrap();
        tokio::fs::write(dir.join("b.txt"), "existing").await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "a.txt", "destination": "b.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("already exists"));
        // Source untouched.
        assert_eq!(
            tokio::fs::read_to_string(dir.join("a.txt")).await.unwrap(),
            "src"
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.join("b.txt")).await.unwrap(),
            "existing"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_blocks_traversal() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_traversal");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "x").await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "a.txt", "destination": "../../etc/evil"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not allowed"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_blocks_missing_source() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_missing");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "nope.txt", "destination": "dst.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("Source not found"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_blocks_sensitive_destination() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_sensitive_dest");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("plain.txt"), "x").await.unwrap();

        let tool = FileMoveTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"source": "plain.txt", "destination": ".env"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("sensitive"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_blocks_readonly_mode() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_readonly");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "x").await.unwrap();

        let tool = FileMoveTool::new(test_security_readonly(dir.clone()));
        let result = tool
            .execute(json!({"source": "a.txt", "destination": "b.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("read-only"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_move_blocks_rate_limited() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_move_rate");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "x").await.unwrap();

        let tool = FileMoveTool::new(test_security_rate_limited(dir.clone()));
        let result = tool
            .execute(json!({"source": "a.txt", "destination": "b.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Rate limit exceeded"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_move_blocks_symlink_source() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_file_move_symlink");
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();
        tokio::fs::write(outside.join("target.txt"), "secret")
            .await
            .unwrap();
        symlink(outside.join("target.txt"), workspace.join("link.txt")).unwrap();

        let tool = FileMoveTool::new(test_security(workspace.clone()));
        let result = tool
            .execute(json!({"source": "link.txt", "destination": "moved.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("symlink"));

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_move_missing_param_errors() {
        let tool = FileMoveTool::new(test_security(std::env::temp_dir()));
        assert!(tool.execute(json!({"source": "a"})).await.is_err());
        assert!(tool.execute(json!({"destination": "b"})).await.is_err());
    }
}
