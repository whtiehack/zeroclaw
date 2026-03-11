use std::future::Future;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExecutionLogContext {
    pub job_id: String,
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExecutionLogFields {
    pub job_id: String,
    pub run_id: String,
    pub parent_run_id: String,
    pub depth: u32,
    pub active: bool,
}

impl Default for CronExecutionLogFields {
    fn default() -> Self {
        Self {
            job_id: "-".to_string(),
            run_id: "-".to_string(),
            parent_run_id: "-".to_string(),
            depth: 0,
            active: false,
        }
    }
}

tokio::task_local! {
    static CRON_EXECUTION_LOG_CONTEXT: CronExecutionLogContext;
}

impl CronExecutionLogContext {
    pub fn for_job(job_id: impl Into<String>) -> Self {
        let parent = current_execution_log_context();
        Self {
            job_id: job_id.into(),
            run_id: Uuid::new_v4().to_string(),
            parent_run_id: parent.as_ref().map(|ctx| ctx.run_id.clone()),
            depth: parent.map_or(0, |ctx| ctx.depth.saturating_add(1)),
        }
    }

    pub fn log_fields(&self) -> CronExecutionLogFields {
        CronExecutionLogFields {
            job_id: self.job_id.clone(),
            run_id: self.run_id.clone(),
            parent_run_id: self
                .parent_run_id
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            depth: self.depth,
            active: true,
        }
    }
}

pub async fn with_execution_log_context<F>(context: CronExecutionLogContext, future: F) -> F::Output
where
    F: Future,
{
    CRON_EXECUTION_LOG_CONTEXT.scope(context, future).await
}

pub fn current_execution_log_context() -> Option<CronExecutionLogContext> {
    CRON_EXECUTION_LOG_CONTEXT.try_with(Clone::clone).ok()
}

pub fn current_log_fields() -> CronExecutionLogFields {
    current_execution_log_context()
        .map(|ctx| ctx.log_fields())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_log_fields_default_to_placeholders() {
        let fields = current_log_fields();
        assert_eq!(fields.job_id, "-");
        assert_eq!(fields.run_id, "-");
        assert_eq!(fields.parent_run_id, "-");
        assert_eq!(fields.depth, 0);
        assert!(!fields.active);
    }

    #[tokio::test]
    async fn nested_context_tracks_parent_and_depth() {
        let root = CronExecutionLogContext::for_job("job-root");
        let root_run_id = root.run_id.clone();

        with_execution_log_context(root, async move {
            let root_fields = current_log_fields();
            assert_eq!(root_fields.job_id, "job-root");
            assert_eq!(root_fields.parent_run_id, "-");
            assert_eq!(root_fields.depth, 0);
            assert!(root_fields.active);

            let child = CronExecutionLogContext::for_job("job-child");
            assert_eq!(child.parent_run_id.as_deref(), Some(root_run_id.as_str()));
            assert_eq!(child.depth, 1);

            with_execution_log_context(child, async move {
                let child_fields = current_log_fields();
                assert_eq!(child_fields.job_id, "job-child");
                assert_eq!(child_fields.parent_run_id, root_run_id);
                assert_eq!(child_fields.depth, 1);
                assert!(child_fields.active);
            })
            .await;
        })
        .await;
    }
}
