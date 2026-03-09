use crate::memory::traits::{Memory, MemoryCategory, MemoryEntry};
use anyhow::{bail, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SCOPE_PREFIX: &str = "__zc__";
const SCOPE_SEP: char = ':';

/// Backends that cannot support scoped memory isolation.
const UNSUPPORTED_BACKENDS: &[&str] = &["markdown", "lucid", "cortex-mem"];

const RECALL_OVER_FETCH: usize = 2;

// ---------------------------------------------------------------------------
// MemoryScope — key encoding / decoding
// ---------------------------------------------------------------------------

pub struct MemoryScope {
    scope_id: String,
    scope_hash: String, // full SHA-256 hex (64 chars)
}

impl MemoryScope {
    pub fn new(scope_id: impl Into<String>) -> Self {
        let scope_id = scope_id.into();
        let mut hasher = Sha256::new();
        hasher.update(scope_id.as_bytes());
        let scope_hash = format!("{:x}", hasher.finalize());
        Self {
            scope_id,
            scope_hash,
        }
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    /// Encode a logical key into a storage key: `__zc__{hash}:{logical_key}`.
    pub fn encode_key(&self, logical_key: &str) -> String {
        format!(
            "{}{}{}{}",
            SCOPE_PREFIX, self.scope_hash, SCOPE_SEP, logical_key
        )
    }

    /// Decode a storage key that belongs to *this* scope. Returns the logical
    /// key, or `None` if the key does not match the current scope prefix.
    pub fn decode_key_for_current_scope<'a>(&self, storage_key: &'a str) -> Option<&'a str> {
        let after_prefix = storage_key.strip_prefix(SCOPE_PREFIX)?;
        let after_hash = after_prefix.strip_prefix(self.scope_hash.as_str())?;
        let logical_key = after_hash.strip_prefix(SCOPE_SEP)?;
        Some(logical_key)
    }

    /// Decode any scoped storage key regardless of which scope produced it.
    /// Returns the logical key portion, or `None` if the key is not scoped.
    /// Used for Qdrant embedding de-pollution.
    pub fn decode_any_scoped_key(storage_key: &str) -> Option<&str> {
        let after_prefix = storage_key.strip_prefix(SCOPE_PREFIX)?;
        // SHA-256 hex is always 64 chars, followed by ':'
        if after_prefix.len() < 65 {
            return None;
        }
        let sep_byte = after_prefix.as_bytes()[64];
        if sep_byte != SCOPE_SEP as u8 {
            return None;
        }
        Some(&after_prefix[65..])
    }

    /// Returns `true` if the key has the scoped prefix.
    pub fn is_scoped_key(key: &str) -> bool {
        key.starts_with(SCOPE_PREFIX)
    }
}

// ---------------------------------------------------------------------------
// ScopedMemory — Memory trait wrapper with scope isolation
// ---------------------------------------------------------------------------

pub struct ScopedMemory {
    inner: Arc<dyn Memory>,
    scope: MemoryScope,
}

impl std::fmt::Debug for ScopedMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedMemory")
            .field("backend", &self.inner.name())
            .field("scope_id", &self.scope.scope_id())
            .finish()
    }
}

impl ScopedMemory {
    /// Wrap an existing memory backend with scope isolation.
    ///
    /// Fails fast if the inner backend does not support scoped keys (markdown,
    /// lucid, cortex-mem).
    pub fn new(inner: Arc<dyn Memory>, scope_id: impl Into<String>) -> Result<Self> {
        let backend_name = inner.name();
        if UNSUPPORTED_BACKENDS.contains(&backend_name) {
            bail!(
                "ScopedMemory does not support the '{backend_name}' backend; \
                 use sqlite, postgres, qdrant, or hybrid instead"
            );
        }
        Ok(Self {
            inner,
            scope: MemoryScope::new(scope_id),
        })
    }
}

#[async_trait]
impl Memory for ScopedMemory {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        _session_id: Option<&str>, // ignored — we inject our own scope_id
    ) -> Result<()> {
        if MemoryScope::is_scoped_key(key) {
            bail!("refusing to store an already-scoped key: {key}");
        }
        let storage_key = self.scope.encode_key(key);
        self.inner
            .store(&storage_key, content, category, Some(self.scope.scope_id()))
            .await
    }

    async fn get(&self, key: &str) -> Result<Option<MemoryEntry>> {
        if MemoryScope::is_scoped_key(key) {
            bail!("refusing to get an already-scoped key: {key}");
        }
        let storage_key = self.scope.encode_key(key);
        match self.inner.get(&storage_key).await? {
            Some(mut entry) => {
                if let Some(logical) = self.scope.decode_key_for_current_scope(&entry.key) {
                    entry.key = logical.to_string();
                }
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    async fn forget(&self, key: &str) -> Result<bool> {
        if MemoryScope::is_scoped_key(key) {
            bail!("refusing to forget an already-scoped key: {key}");
        }
        let storage_key = self.scope.encode_key(key);
        self.inner.forget(&storage_key).await
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        _session_id: Option<&str>, // ignored — we inject our own scope_id
    ) -> Result<Vec<MemoryEntry>> {
        // Over-fetch to compensate for non-scoped entries that will be filtered out.
        let fetch_limit = limit.saturating_mul(RECALL_OVER_FETCH).max(limit);
        let mut entries = self
            .inner
            .recall(query, fetch_limit, Some(self.scope.scope_id()))
            .await?;

        // Filter to current scope prefix and decode keys.
        entries.retain_mut(
            |entry| match self.scope.decode_key_for_current_scope(&entry.key) {
                Some(logical) => {
                    entry.key = logical.to_string();
                    true
                }
                None => false,
            },
        );

        entries.truncate(limit);
        Ok(entries)
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        _session_id: Option<&str>, // ignored — we inject our own scope_id
    ) -> Result<Vec<MemoryEntry>> {
        let mut entries = self
            .inner
            .list(category, Some(self.scope.scope_id()))
            .await?;

        // Filter to current scope prefix and decode keys.
        entries.retain_mut(
            |entry| match self.scope.decode_key_for_current_scope(&entry.key) {
                Some(logical) => {
                    entry.key = logical.to_string();
                    true
                }
                None => false,
            },
        );

        Ok(entries)
    }

    async fn count(&self) -> Result<usize> {
        // Delegate to inner — global count, not per-scope.
        self.inner.count().await
    }

    async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    async fn reindex(
        &self,
        progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
    ) -> Result<usize> {
        self.inner.reindex(progress_callback).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::traits::MemoryCategory;

    #[test]
    fn encode_decode_roundtrip() {
        let scope = MemoryScope::new("wechat:user_123");
        let storage = scope.encode_key("user_lang");
        assert!(storage.starts_with(SCOPE_PREFIX));
        assert!(storage.ends_with(":user_lang"));
        let decoded = scope.decode_key_for_current_scope(&storage);
        assert_eq!(decoded, Some("user_lang"));
    }

    #[test]
    fn different_scopes_produce_different_storage_keys() {
        let scope_a = MemoryScope::new("scope_a");
        let scope_b = MemoryScope::new("scope_b");
        let key_a = scope_a.encode_key("user_lang");
        let key_b = scope_b.encode_key("user_lang");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn decode_rejects_other_scope() {
        let scope_a = MemoryScope::new("scope_a");
        let scope_b = MemoryScope::new("scope_b");
        let storage_b = scope_b.encode_key("user_lang");
        assert_eq!(scope_a.decode_key_for_current_scope(&storage_b), None);
    }

    #[test]
    fn decode_any_scoped_key_works_for_any_scope() {
        let scope = MemoryScope::new("any_scope_id");
        let storage = scope.encode_key("my_key");
        assert_eq!(MemoryScope::decode_any_scoped_key(&storage), Some("my_key"));
    }

    #[test]
    fn decode_any_scoped_key_returns_none_for_unscoped() {
        assert_eq!(MemoryScope::decode_any_scoped_key("plain_key"), None);
    }

    #[test]
    fn is_scoped_key_detects_prefix() {
        let scope = MemoryScope::new("test");
        let scoped = scope.encode_key("foo");
        assert!(MemoryScope::is_scoped_key(&scoped));
        assert!(!MemoryScope::is_scoped_key("foo"));
    }

    #[test]
    fn scoped_memory_rejects_unsupported_backends() {
        use crate::memory::none::NoneMemory;
        // NoneMemory has name "none" — should be accepted.
        let none_mem: Arc<dyn Memory> = Arc::new(NoneMemory::new());
        assert!(ScopedMemory::new(none_mem, "scope").is_ok());
    }

    #[test]
    fn scoped_memory_rejects_markdown_backend() {
        // We can't easily construct a MarkdownMemory without a dir, so we use
        // a mock that returns "markdown" as its name.
        struct FakeMarkdown;
        #[async_trait]
        impl Memory for FakeMarkdown {
            fn name(&self) -> &str {
                "markdown"
            }
            async fn store(
                &self,
                _: &str,
                _: &str,
                _: MemoryCategory,
                _: Option<&str>,
            ) -> Result<()> {
                Ok(())
            }
            async fn recall(&self, _: &str, _: usize, _: Option<&str>) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn get(&self, _: &str) -> Result<Option<MemoryEntry>> {
                Ok(None)
            }
            async fn list(
                &self,
                _: Option<&MemoryCategory>,
                _: Option<&str>,
            ) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn forget(&self, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn count(&self) -> Result<usize> {
                Ok(0)
            }
            async fn health_check(&self) -> bool {
                true
            }
        }
        let mem: Arc<dyn Memory> = Arc::new(FakeMarkdown);
        let err = ScopedMemory::new(mem, "scope").unwrap_err();
        assert!(err.to_string().contains("markdown"));
    }

    #[test]
    fn scoped_memory_rejects_lucid_backend() {
        struct FakeLucid;
        #[async_trait]
        impl Memory for FakeLucid {
            fn name(&self) -> &str {
                "lucid"
            }
            async fn store(
                &self,
                _: &str,
                _: &str,
                _: MemoryCategory,
                _: Option<&str>,
            ) -> Result<()> {
                Ok(())
            }
            async fn recall(&self, _: &str, _: usize, _: Option<&str>) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn get(&self, _: &str) -> Result<Option<MemoryEntry>> {
                Ok(None)
            }
            async fn list(
                &self,
                _: Option<&MemoryCategory>,
                _: Option<&str>,
            ) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn forget(&self, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn count(&self) -> Result<usize> {
                Ok(0)
            }
            async fn health_check(&self) -> bool {
                true
            }
        }
        let mem: Arc<dyn Memory> = Arc::new(FakeLucid);
        let err = ScopedMemory::new(mem, "scope").unwrap_err();
        assert!(err.to_string().contains("lucid"));
    }

    #[test]
    fn scoped_memory_rejects_cortex_mem_backend() {
        struct FakeCortex;
        #[async_trait]
        impl Memory for FakeCortex {
            fn name(&self) -> &str {
                "cortex-mem"
            }
            async fn store(
                &self,
                _: &str,
                _: &str,
                _: MemoryCategory,
                _: Option<&str>,
            ) -> Result<()> {
                Ok(())
            }
            async fn recall(&self, _: &str, _: usize, _: Option<&str>) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn get(&self, _: &str) -> Result<Option<MemoryEntry>> {
                Ok(None)
            }
            async fn list(
                &self,
                _: Option<&MemoryCategory>,
                _: Option<&str>,
            ) -> Result<Vec<MemoryEntry>> {
                Ok(vec![])
            }
            async fn forget(&self, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn count(&self) -> Result<usize> {
                Ok(0)
            }
            async fn health_check(&self) -> bool {
                true
            }
        }
        let mem: Arc<dyn Memory> = Arc::new(FakeCortex);
        let err = ScopedMemory::new(mem, "scope").unwrap_err();
        assert!(err.to_string().contains("cortex-mem"));
    }

    #[tokio::test]
    async fn scoped_memory_store_rejects_double_encoded_key() {
        use crate::memory::none::NoneMemory;
        let inner: Arc<dyn Memory> = Arc::new(NoneMemory::new());
        let scoped = ScopedMemory::new(inner, "scope").unwrap();
        let scope = MemoryScope::new("scope");
        let already_encoded = scope.encode_key("foo");
        let err = scoped
            .store(&already_encoded, "val", MemoryCategory::Core, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already-scoped"));
    }

    #[tokio::test]
    async fn scoped_memory_get_rejects_already_scoped_key() {
        use crate::memory::none::NoneMemory;
        let inner: Arc<dyn Memory> = Arc::new(NoneMemory::new());
        let scoped = ScopedMemory::new(inner, "scope").unwrap();
        let encoded = MemoryScope::new("other").encode_key("foo");
        let err = scoped.get(&encoded).await.unwrap_err();
        assert!(err.to_string().contains("already-scoped"));
    }

    #[tokio::test]
    async fn scoped_memory_forget_rejects_already_scoped_key() {
        use crate::memory::none::NoneMemory;
        let inner: Arc<dyn Memory> = Arc::new(NoneMemory::new());
        let scoped = ScopedMemory::new(inner, "scope").unwrap();
        let encoded = MemoryScope::new("other").encode_key("foo");
        let err = scoped.forget(&encoded).await.unwrap_err();
        assert!(err.to_string().contains("already-scoped"));
    }
}
