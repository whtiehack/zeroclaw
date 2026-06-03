//! Proactive notification tool for scheduled ("notify mode") cron jobs.
//!
//! Exposes `notify_user` as an agent-callable tool. In a notify-mode cron job
//! the agent's normal final reply is NOT delivered anywhere — calling this tool
//! is the only way to push a message to the user. When the agent has nothing
//! worth reporting it simply does not call the tool, so the job stays silent.
//!
//! The delivery target (channel + recipient/scope) is supplied by the cron
//! scheduler through the [`NOTIFY_TARGET`] task-local, which is set for the
//! duration of the agent run. This mirrors the `TOOL_CHOICE_OVERRIDE`
//! task-local pattern used by the agent loop.

use super::traits::{Tool, ToolResult};
use crate::channels::traits::SendMessage;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Per-run delivery context for a notify-mode cron job, set by the scheduler.
pub(crate) struct NotifyContext {
    /// Channel name to deliver through (e.g. `wecom_ws`).
    pub channel: String,
    /// Recipient/scope identifier within that channel.
    pub to: String,
    /// Number of messages delivered during the run (for silent-vs-delivered audit).
    pub delivered: AtomicUsize,
}

tokio::task_local! {
    /// Set by the cron scheduler around a notify-mode agent run; tools executing
    /// within that run read it to learn where to deliver. Absent (try_with errors)
    /// for any other run, which is how `notify_user` detects misuse.
    pub(crate) static NOTIFY_TARGET: Arc<NotifyContext>;
}

/// Agent-callable tool that delivers a message to the user during a notify-mode cron job.
pub struct NotifyUserTool {
    security: Arc<SecurityPolicy>,
}

impl NotifyUserTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

#[async_trait]
impl Tool for NotifyUserTool {
    fn name(&self) -> &str {
        "notify_user"
    }

    fn description(&self) -> &str {
        "Deliver a message to the user. In a scheduled notify-mode job this is the \
         ONLY way your output reaches anyone — your normal reply text is not sent. \
         Call it when there is something worth reporting; if there is nothing to \
         report, do not call it and the job stays silent."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The message to deliver to the user."
                }
            },
            "required": ["message"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "notify_user")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Action blocked: {e}")),
            });
        }

        let message = match args
            .get("message")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(m) => m.to_string(),
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'message' parameter".to_string()),
                });
            }
        };

        // Resolve the per-run delivery target set by the cron scheduler. Absent
        // when the tool is called outside a notify-mode job.
        let ctx = match NOTIFY_TARGET.try_with(|c| Arc::clone(c)) {
            Ok(ctx) => ctx,
            Err(_) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(
                        "notify_user is only available within a scheduled notify-mode job"
                            .to_string(),
                    ),
                });
            }
        };

        let Some(channel) = crate::channels::get_live_channel(&ctx.channel) else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("channel '{}' is not connected", ctx.channel)),
            });
        };

        if let Err(e) = channel
            .send(&SendMessage::new(message.as_str(), ctx.to.as_str()))
            .await
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("failed to deliver via '{}': {e}", ctx.channel)),
            });
        }

        ctx.delivered.fetch_add(1, Ordering::SeqCst);

        Ok(ToolResult {
            success: true,
            output: json!({
                "status": "notified",
                "channel": ctx.channel,
                "chars": message.chars().count(),
            })
            .to_string(),
            error: None,
        })
    }
}
