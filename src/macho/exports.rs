//! Export-trie decoder.
//!
//! Sprint 5 (this commit) holds the placeholder stub; the real walker lands
//! in the next commit of this sprint. The module exists now so `DylibFile`
//! can carry an `ExportTrie` field without circular-dependency headaches.

/// Placeholder until the walker arrives. Carries raw trie bytes so we can
/// lazily decode on demand or fall back to inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportTrie {
    raw: Vec<u8>,
}

impl ExportTrie {
    pub fn empty() -> Self {
        ExportTrie::default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        ExportTrie { raw: bytes.to_vec() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}
