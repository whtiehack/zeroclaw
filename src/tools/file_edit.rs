use super::traits::{Tool, ToolResult};
use crate::security::file_link_guard::has_multiple_hard_links;
use crate::security::sensitive_paths::is_sensitive_file_path;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

/// Edit a file by applying an ordered list of `old_string` → `new_string`
/// replacements within the workspace.
///
/// Each entry in `edits` is applied sequentially against an in-memory copy.
/// Default behavior (`replace_all = false`) requires a unique match per edit,
/// falling back to whitespace-flexible line matching when exact matching
/// finds zero hits. Setting `replace_all = true` replaces every occurrence
/// (useful for renames). If any edit fails, the file is not modified.
/// Security checks mirror [`super::file_write::FileWriteTool`].
pub struct FileEditTool {
    security: Arc<SecurityPolicy>,
}

impl FileEditTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

fn sensitive_file_edit_block_message(path: &str) -> String {
    format!(
        "Editing sensitive file '{path}' is blocked by policy. \
Set [autonomy].allow_sensitive_file_writes = true only when strictly necessary."
    )
}

fn hard_link_edit_block_message(path: &Path) -> String {
    format!(
        "Editing multiply-linked file '{}' is blocked by policy \
(potential hard-link escape).",
        path.display()
    )
}

#[derive(Debug, Clone, Copy)]
struct LineSpan {
    start: usize,
    content_end: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy)]
struct MatchOutcome {
    start: usize,
    end: usize,
    used_whitespace_flex: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlexibleLineMatch {
    NoMatch,
    Unique { start: usize, end: usize },
    Ambiguous { count: usize },
}

fn normalize_line(line: &str) -> String {
    let trimmed = line.trim_end_matches([' ', '\t']);
    let mut normalized = String::with_capacity(trimmed.len());
    let mut in_whitespace_run = false;

    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_whitespace_run {
                normalized.push(' ');
                in_whitespace_run = true;
            }
        } else {
            normalized.push(ch);
            in_whitespace_run = false;
        }
    }

    normalized
}

fn compute_line_spans(content: &str) -> Vec<LineSpan> {
    let mut spans = Vec::new();
    let bytes = content.as_bytes();
    let mut line_start = 0usize;

    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            let mut content_end = idx;
            if content_end > line_start && bytes[content_end - 1] == b'\r' {
                content_end -= 1;
            }
            spans.push(LineSpan {
                start: line_start,
                content_end,
                end: idx + 1,
            });
            line_start = idx + 1;
        }
    }

    if line_start < content.len() {
        spans.push(LineSpan {
            start: line_start,
            content_end: content.len(),
            end: content.len(),
        });
    }

    spans
}

fn try_flexible_line_match(content: &str, old_string: &str) -> FlexibleLineMatch {
    let content_spans = compute_line_spans(content);
    let old_spans = compute_line_spans(old_string);

    if old_spans.is_empty() || content_spans.len() < old_spans.len() {
        return FlexibleLineMatch::NoMatch;
    }

    let normalized_old_lines: Vec<String> = old_spans
        .iter()
        .map(|span| normalize_line(&old_string[span.start..span.content_end]))
        .collect();
    let normalized_content_lines: Vec<String> = content_spans
        .iter()
        .map(|span| normalize_line(&content[span.start..span.content_end]))
        .collect();

    let mut match_count = 0usize;
    let mut matched_start_line = 0usize;
    let window_size = old_spans.len();

    for start_line in 0..=(content_spans.len() - window_size) {
        let mut window_matches = true;
        for line_offset in 0..window_size {
            if normalized_content_lines[start_line + line_offset]
                != normalized_old_lines[line_offset]
            {
                window_matches = false;
                break;
            }
        }

        if window_matches {
            match_count += 1;
            if match_count == 1 {
                matched_start_line = start_line;
            }
        }
    }

    if match_count == 0 {
        return FlexibleLineMatch::NoMatch;
    }

    if match_count > 1 {
        return FlexibleLineMatch::Ambiguous { count: match_count };
    }

    let first_span = content_spans[matched_start_line];
    let last_span = content_spans[matched_start_line + window_size - 1];
    let end = if old_string.ends_with('\n') {
        last_span.end
    } else {
        last_span.content_end
    };

    FlexibleLineMatch::Unique {
        start: first_span.start,
        end,
    }
}

fn resolve_match(content: &str, old_string: &str) -> Result<MatchOutcome, String> {
    let mut exact_matches = content.match_indices(old_string);
    if let Some((start, _)) = exact_matches.next() {
        if exact_matches.next().is_some() {
            let match_count = 2 + exact_matches.count();
            return Err(format!(
                "old_string matches {match_count} times; must match exactly once"
            ));
        }
        return Ok(MatchOutcome {
            start,
            end: start + old_string.len(),
            used_whitespace_flex: false,
        });
    }

    match try_flexible_line_match(content, old_string) {
        FlexibleLineMatch::NoMatch => Err("old_string not found in file".into()),
        FlexibleLineMatch::Ambiguous { count } => Err(format!(
            "old_string matches {count} times with whitespace flexibility; must match exactly once"
        )),
        FlexibleLineMatch::Unique { start, end } => Ok(MatchOutcome {
            start,
            end,
            used_whitespace_flex: true,
        }),
    }
}

#[async_trait]
impl Tool for FileEditTool {
    fn name(&self) -> &str {
        "file_edit"
    }

    fn description(&self) -> &str {
        "Apply one or more edits to a file in a single call. Edits are applied sequentially on an in-memory copy and committed atomically — if any edit fails, the file is not modified. Each edit defaults to a unique-match replacement (exact preferred, whitespace-flexible line matching as fallback); set `replace_all = true` to replace every occurrence (useful for renames). Sensitive files (for example .env and key material) are blocked by default."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file. Relative paths resolve from workspace; outside paths require policy allowlist."
                },
                "edits": {
                    "type": "array",
                    "minItems": 1,
                    "description": "Ordered list of edits to apply. Each edit is matched against the result of all previous edits; failure of any edit aborts the entire batch.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old_string": {
                                "type": "string",
                                "description": "Text to find. Exact matching is attempted first; if no exact match is found, whitespace-flexible line matching is attempted."
                            },
                            "new_string": {
                                "type": "string",
                                "description": "Replacement text (empty string to delete the matched text)."
                            },
                            "replace_all": {
                                "type": "boolean",
                                "default": false,
                                "description": "Replace every occurrence. When false (default) the match must be unique."
                            }
                        },
                        "required": ["old_string", "new_string"]
                    }
                }
            },
            "required": ["path", "edits"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // ── 1. Extract parameters ──────────────────────────────────
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'path' parameter"))?;

        let edits_value = args
            .get("edits")
            .ok_or_else(|| anyhow::anyhow!("Missing 'edits' parameter"))?;
        let edits_array = edits_value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("'edits' must be an array"))?;

        if edits_array.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("'edits' must contain at least one edit".into()),
            });
        }

        let mut edits: Vec<(String, String, bool)> = Vec::with_capacity(edits_array.len());
        for (idx, item) in edits_array.iter().enumerate() {
            let obj = item.as_object().ok_or_else(|| {
                anyhow::anyhow!("edits[{idx}] must be an object with old_string/new_string")
            })?;
            let old = obj
                .get("old_string")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("edits[{idx}] missing 'old_string'"))?;
            let new = obj
                .get("new_string")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("edits[{idx}] missing 'new_string'"))?;
            let replace_all = obj
                .get("replace_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if old.is_empty() {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("edits[{idx}].old_string must not be empty")),
                });
            }
            edits.push((old.to_string(), new.to_string(), replace_all));
        }

        // ── 2. Autonomy check ──────────────────────────────────────
        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        // ── 3. Rate limit check ────────────────────────────────────
        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        // ── 4. Path pre-validation ─────────────────────────────────
        if !self.security.is_path_allowed(path) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Path not allowed by security policy: {path}")),
            });
        }

        if !self.security.allow_sensitive_file_writes && is_sensitive_file_path(Path::new(path)) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_file_edit_block_message(path)),
            });
        }

        let full_path = self.security.resolve_user_supplied_path(path);

        // ── 5. Canonicalize parent ─────────────────────────────────
        let Some(parent) = full_path.parent() else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Invalid path: missing parent directory".into()),
            });
        };

        let resolved_parent = match tokio::fs::canonicalize(parent).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve file path: {e}")),
                });
            }
        };

        // ── 6. Resolved path post-validation ───────────────────────
        if !self.security.is_resolved_path_allowed(&resolved_parent) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    self.security
                        .resolved_path_violation_message(&resolved_parent),
                ),
            });
        }

        let Some(file_name) = full_path.file_name() else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Invalid path: missing file name".into()),
            });
        };

        let resolved_target = resolved_parent.join(file_name);

        if !self.security.allow_sensitive_file_writes && is_sensitive_file_path(&resolved_target) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(sensitive_file_edit_block_message(
                    &resolved_target.display().to_string(),
                )),
            });
        }

        // ── 7. Symlink check ───────────────────────────────────────
        if let Ok(meta) = tokio::fs::symlink_metadata(&resolved_target).await {
            if meta.file_type().is_symlink() {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Refusing to edit through symlink: {}",
                        resolved_target.display()
                    )),
                });
            }

            if has_multiple_hard_links(&meta) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(hard_link_edit_block_message(&resolved_target)),
                });
            }
        }

        // ── 8. Record action ───────────────────────────────────────
        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        // ── 9. Read → apply edits sequentially → write once ───────
        let mut content = match tokio::fs::read_to_string(&resolved_target).await {
            Ok(c) => c,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to read file: {e}")),
                });
            }
        };

        let mut total_replacements = 0usize;
        let mut flex_used_overall = false;

        for (idx, (old, new, replace_all)) in edits.iter().enumerate() {
            if *replace_all {
                let count = content.matches(old.as_str()).count();
                if count == 0 {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("edits[{idx}]: old_string not found in file")),
                    });
                }
                content = content.replace(old.as_str(), new.as_str());
                total_replacements += count;
            } else {
                let outcome = match resolve_match(&content, old) {
                    Ok(o) => o,
                    Err(error) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("edits[{idx}]: {error}")),
                        });
                    }
                };
                if outcome.end < outcome.start || outcome.end > content.len() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!(
                            "edits[{idx}]: internal matching error (invalid replacement range)"
                        )),
                    });
                }
                let mut next = String::with_capacity(
                    content.len() - (outcome.end - outcome.start) + new.len(),
                );
                next.push_str(&content[..outcome.start]);
                next.push_str(new);
                next.push_str(&content[outcome.end..]);
                content = next;
                total_replacements += 1;
                if outcome.used_whitespace_flex {
                    flex_used_overall = true;
                }
            }
        }

        match tokio::fs::write(&resolved_target, &content).await {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!(
                    "Edited {path}: applied {} edit{}, {} replacement{}{}",
                    edits.len(),
                    if edits.len() == 1 { "" } else { "s" },
                    total_replacements,
                    if total_replacements == 1 { "" } else { "s" },
                    if flex_used_overall {
                        " (whitespace flexibility used)"
                    } else {
                        ""
                    }
                ),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to write file: {e}")),
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

    fn test_security_with(
        workspace: std::path::PathBuf,
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

    fn test_security_allow_sensitive_writes(
        workspace: std::path::PathBuf,
        allow_sensitive_file_writes: bool,
    ) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            allow_sensitive_file_writes,
            ..SecurityPolicy::default()
        })
    }

    fn test_security_allows_outside_workspace(
        workspace: std::path::PathBuf,
    ) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            workspace_only: false,
            forbidden_paths: vec![],
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn file_edit_name() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "file_edit");
    }

    #[test]
    fn file_edit_schema_has_required_params() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["path"].is_object());
        let edits = &schema["properties"]["edits"];
        assert_eq!(edits["type"], "array");
        let item_props = &edits["items"]["properties"];
        assert!(item_props["old_string"].is_object());
        assert!(item_props["new_string"].is_object());
        assert!(item_props["replace_all"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("edits")));
    }

    #[tokio::test]
    async fn file_edit_replaces_single_match() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_single");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello world")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "hello", "new_string": "goodbye"}]
            }))
            .await
            .unwrap();

        assert!(result.success, "edit should succeed: {:?}", result.error);
        assert!(result.output.contains("1 edit"));
        assert!(result.output.contains("1 replacement"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "goodbye world");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_not_found() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_notfound");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello world")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "nonexistent", "new_string": "replacement"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not found"));

        // File should be unchanged
        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "hello world");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_indentation_difference() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_indent");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("test.txt"),
            "fn main() {\n    println!(\"hi\");\n}\n",
        )
        .await
        .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "fn main() {\n  println!(\"hi\");\n}\n", "new_string": "fn main() {\n    println!(\"hello\");\n}\n"}]
            }))
            .await
            .unwrap();

        assert!(
            result.success,
            "flexible indentation match should succeed: {:?}",
            result.error
        );
        assert!(result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "fn main() {\n    println!(\"hello\");\n}\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_tab_space_difference() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_tabs");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "alpha\n\tbeta\ngamma\n")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "alpha\n  beta\ngamma\n", "new_string": "alpha\n\tdelta\ngamma\n"}]
            }))
            .await
            .unwrap();

        assert!(result.success, "tab/space flex match should succeed");
        assert!(result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "alpha\n\tdelta\ngamma\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_trailing_whitespace_difference() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_trailing");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "line one   \nline two\t\t\n")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "line one\nline two\n", "new_string": "line one\nline 2\n"}]
            }))
            .await
            .unwrap();

        assert!(
            result.success,
            "trailing whitespace flex match should succeed"
        );
        assert!(result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "line one\nline 2\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_collapsed_spaces() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_spaces");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "let value    =    42;\n")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "let value = 42;\n", "new_string": "let value = 7;\n"}]
            }))
            .await
            .unwrap();

        assert!(result.success, "collapsed-space flex match should succeed");
        assert!(result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "let value = 7;\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_ambiguous_errors() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_ambiguous");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("test.txt"),
            "if cond {\n    work();\n}\n\nif cond {\n\twork();\n}\n",
        )
        .await
        .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "if cond {\n  work();\n}\n", "new_string": "if cond {\n  done();\n}\n"}]
            }))
            .await
            .unwrap();

        assert!(!result.success, "ambiguous flex match must fail");
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("whitespace flexibility"));
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("matches 2 times"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(
            content,
            "if cond {\n    work();\n}\n\nif cond {\n\twork();\n}\n"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_not_found_when_no_line_match() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_not_found");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "alpha\nbeta\n")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "gamma\n", "new_string": "delta\n"}]
            }))
            .await
            .unwrap();

        assert!(!result.success, "non-matching flex case should fail");
        assert!(result.error.as_deref().unwrap_or("").contains("not found"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_prefers_exact_match_over_flexible() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_exact_preference");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("test.txt"),
            "let value = 1;\nlet value    =    1;\n",
        )
        .await
        .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "let value = 1;", "new_string": "let value = 2;"}]
            }))
            .await
            .unwrap();

        assert!(result.success, "exact match should succeed");
        assert!(!result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "let value = 2;\nlet value    =    1;\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_flexible_match_preserves_trailing_newline_when_old_string_has_none() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_flex_no_trailing_nl");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "line one\n    line two\nline three\n")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "line one\n  line two\nline three", "new_string": "updated block"}]
            }))
            .await
            .unwrap();

        assert!(
            result.success,
            "flex match without trailing newline should succeed"
        );
        assert!(result.output.contains("whitespace flexibility"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "updated block\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_multiple_matches() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_multi");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "aaa bbb aaa")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "aaa", "new_string": "ccc"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("matches 2 times"));

        // File should be unchanged
        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "aaa bbb aaa");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_delete_via_empty_new_string() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_delete");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "keep remove keep")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": " remove", "new_string": ""}]
            }))
            .await
            .unwrap();

        assert!(
            result.success,
            "delete edit should succeed: {:?}",
            result.error
        );

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "keep keep");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_sensitive_file_by_default() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_sensitive_blocked");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join(".env"), "API_KEY=old")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": ".env", "edits": [{"old_string": "old", "new_string": "new"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("sensitive file"));

        let content = tokio::fs::read_to_string(dir.join(".env")).await.unwrap();
        assert_eq!(content, "API_KEY=old");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_allows_sensitive_file_when_configured() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_sensitive_allowed");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join(".env"), "API_KEY=old")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security_allow_sensitive_writes(dir.clone(), true));
        let result = tool
            .execute(json!({
                "path": ".env", "edits": [{"old_string": "old", "new_string": "new"}]
            }))
            .await
            .unwrap();

        assert!(
            result.success,
            "sensitive edit should succeed when enabled: {:?}",
            result.error
        );

        let content = tokio::fs::read_to_string(dir.join(".env")).await.unwrap();
        assert_eq!(content, "API_KEY=new");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_missing_path_param() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"old_string": "a", "new_string": "b"}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_edit_missing_edits_param() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool.execute(json!({"path": "f.txt"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_edit_edits_must_be_array() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"path": "f.txt", "edits": "not-an-array"}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_edit_edits_empty_array() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_edits_empty");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": "test.txt", "edits": []}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("at least one edit"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_edit_missing_old_string() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"path": "f.txt", "edits": [{"new_string": "b"}]}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_edit_edit_missing_new_string() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"path": "f.txt", "edits": [{"old_string": "a"}]}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_edit_rejects_empty_old_string() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_empty_old_string");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "", "new_string": "x"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("must not be empty"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "hello");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_path_traversal() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_traversal");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "../../etc/passwd", "edits": [{"old_string": "root", "new_string": "hacked"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not allowed"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_absolute_path() {
        let tool = FileEditTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({
                "path": "/etc/passwd", "edits": [{"old_string": "root", "new_string": "hacked"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn file_edit_expands_tilde_path_consistently_with_policy() {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .expect("HOME should be available for tilde expansion tests");
        let target_rel = format!("zeroclaw_tilde_edit_{}.txt", uuid::Uuid::new_v4());
        let target_path = home.join(&target_rel);
        let _ = tokio::fs::remove_file(&target_path).await;
        tokio::fs::write(&target_path, "alpha beta gamma")
            .await
            .unwrap();

        let workspace = std::env::temp_dir().join("zeroclaw_test_file_edit_tilde_workspace");
        let _ = tokio::fs::remove_dir_all(&workspace).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();

        let tool = FileEditTool::new(test_security_allows_outside_workspace(workspace.clone()));
        let result = tool
            .execute(json!({
                "path": format!("~/{}", target_rel),
                "edits": [{"old_string": "beta", "new_string": "delta"}]
            }))
            .await
            .unwrap();
        assert!(
            result.success,
            "tilde path edit should succeed when policy allows outside workspace: {:?}",
            result.error
        );

        let content = tokio::fs::read_to_string(&target_path).await.unwrap();
        assert_eq!(content, "alpha delta gamma");

        let _ = tokio::fs::remove_file(&target_path).await;
        let _ = tokio::fs::remove_dir_all(&workspace).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_edit_blocks_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_file_edit_symlink_escape");
        let workspace = root.join("workspace");
        let outside = root.join("outside");

        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();

        symlink(&outside, workspace.join("escape_dir")).unwrap();

        let tool = FileEditTool::new(test_security(workspace.clone()));
        let result = tool
            .execute(json!({
                "path": "escape_dir/target.txt", "edits": [{"old_string": "a", "new_string": "b"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("escapes workspace"));

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_edit_blocks_symlink_target_file() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join("zeroclaw_test_file_edit_symlink_target");
        let workspace = root.join("workspace");
        let outside = root.join("outside");

        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();

        tokio::fs::write(outside.join("target.txt"), "original")
            .await
            .unwrap();
        symlink(outside.join("target.txt"), workspace.join("linked.txt")).unwrap();

        let tool = FileEditTool::new(test_security(workspace.clone()));
        let result = tool
            .execute(json!({
                "path": "linked.txt", "edits": [{"old_string": "original", "new_string": "hacked"}]
            }))
            .await
            .unwrap();

        assert!(!result.success, "editing through symlink must be blocked");
        assert!(
            result.error.as_deref().unwrap_or("").contains("symlink"),
            "error should mention symlink"
        );

        let content = tokio::fs::read_to_string(outside.join("target.txt"))
            .await
            .unwrap();
        assert_eq!(content, "original", "original file must not be modified");

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_edit_blocks_hardlink_target_file() {
        let root = std::env::temp_dir().join("zeroclaw_test_file_edit_hardlink_target");
        let workspace = root.join("workspace");
        let outside = root.join("outside");

        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();

        tokio::fs::write(outside.join("target.txt"), "original")
            .await
            .unwrap();
        std::fs::hard_link(outside.join("target.txt"), workspace.join("linked.txt")).unwrap();

        let tool = FileEditTool::new(test_security(workspace.clone()));
        let result = tool
            .execute(json!({
                "path": "linked.txt", "edits": [{"old_string": "original", "new_string": "hacked"}]
            }))
            .await
            .unwrap();

        assert!(!result.success, "editing through hard link must be blocked");
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("hard-link escape"));

        let content = tokio::fs::read_to_string(outside.join("target.txt"))
            .await
            .unwrap();
        assert_eq!(content, "original", "original file must not be modified");

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_readonly_mode() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_readonly");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security_with(dir.clone(), AutonomyLevel::ReadOnly, 20));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "hello", "new_string": "world"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("read-only"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "hello");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_when_rate_limited() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_rate_limited");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "hello")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security_with(
            dir.clone(),
            AutonomyLevel::Supervised,
            0,
        ));
        let result = tool
            .execute(json!({
                "path": "test.txt", "edits": [{"old_string": "hello", "new_string": "world"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Rate limit exceeded"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "hello");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_nonexistent_file() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_nofile");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "missing.txt", "edits": [{"old_string": "a", "new_string": "b"}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Failed to read file"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_blocks_null_byte_in_path() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_null_byte");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test\0evil.txt", "edits": [{"old_string": "old", "new_string": "new"}]
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not allowed"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_batch_applies_in_order() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_batch_order");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "alpha beta gamma")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt",
                "edits": [
                    {"old_string": "alpha", "new_string": "ALPHA"},
                    {"old_string": "beta", "new_string": "BETA"},
                    {"old_string": "gamma", "new_string": "GAMMA"}
                ]
            }))
            .await
            .unwrap();

        assert!(result.success, "batch should succeed: {:?}", result.error);
        assert!(result.output.contains("3 edit"));
        assert!(result.output.contains("3 replacement"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "ALPHA BETA GAMMA");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_batch_atomic_on_failure() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_batch_atomic");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "alpha beta gamma")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        // Second edit cannot match → entire batch must abort.
        let result = tool
            .execute(json!({
                "path": "test.txt",
                "edits": [
                    {"old_string": "alpha", "new_string": "ALPHA"},
                    {"old_string": "nonexistent", "new_string": "X"},
                    {"old_string": "gamma", "new_string": "GAMMA"}
                ]
            }))
            .await
            .unwrap();

        assert!(!result.success, "batch must fail when an edit cannot match");
        assert!(result.error.as_deref().unwrap_or("").contains("edits[1]"));

        // File must remain untouched.
        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "alpha beta gamma");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_replace_all_replaces_every_occurrence() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_replace_all");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "foo bar foo baz foo")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt",
                "edits": [{"old_string": "foo", "new_string": "FOO", "replace_all": true}]
            }))
            .await
            .unwrap();

        assert!(result.success, "replace_all should succeed: {:?}", result.error);
        assert!(result.output.contains("3 replacement"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "FOO bar FOO baz FOO");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_edit_replace_all_zero_matches_errors() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_edit_replace_all_miss");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("test.txt"), "alpha beta")
            .await
            .unwrap();

        let tool = FileEditTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({
                "path": "test.txt",
                "edits": [{"old_string": "missing", "new_string": "X", "replace_all": true}]
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not found"));

        let content = tokio::fs::read_to_string(dir.join("test.txt"))
            .await
            .unwrap();
        assert_eq!(content, "alpha beta");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
