use super::traits::{Tool, ToolResult};
use crate::security::file_link_guard::has_multiple_hard_links;
use crate::security::sensitive_paths::is_sensitive_file_path;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

/// Delete a file inside the workspace.
pub struct FileDeleteTool {
    security: Arc<SecurityPolicy>,
}

impl FileDeleteTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

fn sensitive_block_message(path: &str) -> String {
    format!(
        "Deleting sensitive file '{path}' is blocked by policy. \
Set [autonomy].allow_sensitive_file_writes = true only when strictly necessary."
    )
}

fn hard_link_block_message(path: &Path) -> String {
    format!(
        "Deleting multiply-linked file '{}' is blocked by policy \
(potential hard-link escape).",
        path.display()
    )
}

#[async_trait]
impl Tool for FileDeleteTool {
    fn name(&self) -> &str {
        "file_delete"
    }

    fn description(&self) -> &str {
        "Delete a file inside the workspace. Refuses directories, symlinks, and sensitive files (e.g. .env)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to delete. Relative paths resolve from workspace; outside paths require policy allowlist."
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'path' parameter"))?;

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

        if !self.security.is_path_allowed(path) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Path not allowed by security policy: {path}")),
            });
        }

        let allow_sensitive = self.security.allow_sensitive_file_writes;
        if !allow_sensitive && is_sensitive_file_path(Path::new(path)) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(path)),
            });
        }

        let full_path = self.security.resolve_user_supplied_path(path);

        let meta = match tokio::fs::symlink_metadata(&full_path).await {
            Ok(m) => m,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Path not found: {e}")),
                });
            }
        };
        if meta.file_type().is_symlink() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Refusing to delete a symlink: {}",
                    full_path.display()
                )),
            });
        }
        if !meta.is_file() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Not a regular file (directories are not deletable): {}",
                    full_path.display()
                )),
            });
        }
        if has_multiple_hard_links(&meta) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(hard_link_block_message(&full_path)),
            });
        }

        let resolved = match tokio::fs::canonicalize(&full_path).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve path: {e}")),
                });
            }
        };
        if !self.security.is_resolved_path_allowed(&resolved) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(self.security.resolved_path_violation_message(&resolved)),
            });
        }
        if !allow_sensitive && is_sensitive_file_path(&resolved) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_block_message(&resolved.display().to_string())),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        match tokio::fs::remove_file(&resolved).await {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Deleted {path}"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to delete file: {e}")),
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
    fn file_delete_name_and_schema() {
        let tool = FileDeleteTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "file_delete");
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["path"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("path")));
    }

    #[tokio::test]
    async fn file_delete_removes_file() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_basic");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("victim.txt"), "x").await.unwrap();

        let tool = FileDeleteTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": "victim.txt"}))
            .await
            .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(!dir.join("victim.txt").exists());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_traversal() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_traversal");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileDeleteTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": "../../etc/passwd"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not allowed"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_missing() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_missing");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileDeleteTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": "nope.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not found"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_directory() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_directory");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir.join("subdir")).await.unwrap();

        let tool = FileDeleteTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": "subdir"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("regular file"));
        assert!(dir.join("subdir").exists());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_sensitive_by_default() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_sensitive");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join(".env"), "API_KEY=1").await.unwrap();

        let tool = FileDeleteTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": ".env"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("sensitive"));
        assert!(dir.join(".env").exists());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_readonly() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_readonly");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "x").await.unwrap();

        let tool = FileDeleteTool::new(test_security_readonly(dir.clone()));
        let result = tool
            .execute(json!({"path": "a.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("read-only"));
        assert!(dir.join("a.txt").exists());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_delete_blocks_rate_limited() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_delete_rate");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "x").await.unwrap();

        let tool = FileDeleteTool::new(test_security_rate_limited(dir.clone()));
        let result = tool
            .execute(json!({"path": "a.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Rate limit exceeded"));
        assert!(dir.join("a.txt").exists());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_delete_blocks_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_file_delete_symlink");
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();
        tokio::fs::write(outside.join("target.txt"), "x")
            .await
            .unwrap();
        symlink(outside.join("target.txt"), workspace.join("link.txt")).unwrap();

        let tool = FileDeleteTool::new(test_security(workspace.clone()));
        let result = tool
            .execute(json!({"path": "link.txt"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("symlink"));
        assert!(workspace.join("link.txt").exists());
        assert!(outside.join("target.txt").exists());

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_delete_missing_param_errors() {
        let tool = FileDeleteTool::new(test_security(std::env::temp_dir()));
        assert!(tool.execute(json!({})).await.is_err());
    }
}
