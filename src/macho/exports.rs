//! Export-trie walker.
//!
//! dyld stores a dylib's exports as a compact prefix trie rooted at offset 0
//! of the `export_off / export_size` region (LC_DYLD_INFO_ONLY) or the
//! `LC_DYLD_EXPORTS_TRIE` blob. Each node is:
//!
//! ```text
//!   uleb128 terminal_size
//!   terminal_size bytes of terminal payload (when non-zero)
//!   u8      child_count
//!   child_count * (c-string edge, uleb128 child_offset)
//! ```
//!
//! Terminal payload:
//!   `uleb128 flags`
//!   then, depending on `flags`:
//!     - REEXPORT        : `uleb128 other_dylib_ordinal` + null-terminated imported_name
//!     - STUB_AND_RESOLVER: `uleb128 stub_offset` + `uleb128 resolver_offset`
//!     - otherwise       : `uleb128 address`
//!
//! The walker accumulates edge strings to produce each full exported name,
//! enforces a depth cap, and rejects cycles / out-of-bound offsets / ULEB
//! overruns with diagnostics.

use super::constants::*;
use crate::leb::read_uleb;
use crate::macho::reader::ReadError;

const MAX_DEPTH: usize = 128;

/// Terminal export kind, discriminated on the `flags` low bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    /// Regular symbol at `address`.
    Regular { address: u64 },
    /// Thread-local; `address` is the TLV descriptor offset.
    ThreadLocal { address: u64 },
    /// Absolute symbol — `address` is the final value.
    Absolute { address: u64 },
    /// Re-export of another dylib's symbol.
    Reexport {
        /// 0 = parent library (the dylib containing this entry), else one
        /// of the dylib's LC_*_DYLIB ordinals (1-based).
        ordinal: u32,
        /// Empty string means "same name as the exported name".
        imported_name: String,
    },
    /// Two addresses: the normal stub plus a resolver function that produces
    /// the final address on demand.
    StubAndResolver { stub: u64, resolver: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub name: String,
    pub flags: u64,
    pub kind: ExportKind,
}

impl ExportEntry {
    pub fn weak_def(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0
    }
}

/// The linker-side "exports view" of a dylib. Either a wire-form trie
/// (from `MH_DYLIB` via `LC_DYLD_INFO_ONLY` or `LC_DYLD_EXPORTS_TRIE`) or
/// a pre-flattened list (from a TAPI `.tbd`). Both kinds answer the same
/// two questions: `entries()` (iterate all) and `lookup(name)` (find one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exports {
    Trie(Vec<u8>),
    Flat(Vec<ExportEntry>),
}

impl Default for Exports {
    fn default() -> Self {
        Exports::empty()
    }
}

impl Exports {
    pub fn empty() -> Self {
        Exports::Flat(Vec::new())
    }

    pub fn from_trie_bytes(bytes: &[u8]) -> Self {
        Exports::Trie(bytes.to_vec())
    }

    pub fn from_entries(entries: Vec<ExportEntry>) -> Self {
        Exports::Flat(entries)
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Exports::Trie(b) => b.is_empty(),
            Exports::Flat(e) => e.is_empty(),
        }
    }

    /// Wire bytes for the trie variant; empty slice for flat.
    pub fn trie_bytes(&self) -> &[u8] {
        match self {
            Exports::Trie(b) => b,
            Exports::Flat(_) => &[],
        }
    }

    /// Decode every export. For the trie variant this walks the tree; for
    /// flat it clones the stored vec. Cycle-safe on the trie side.
    pub fn entries(&self) -> Result<Vec<ExportEntry>, ReadError> {
        match self {
            Exports::Trie(raw) => {
                if raw.is_empty() {
                    return Ok(Vec::new());
                }
                let mut out = Vec::new();
                let mut visited = std::collections::HashSet::new();
                walk(raw, 0, String::new(), &mut out, &mut visited, 0)?;
                Ok(out)
            }
            Exports::Flat(v) => Ok(v.clone()),
        }
    }

    pub fn lookup(&self, name: &str) -> Result<Option<ExportEntry>, ReadError> {
        match self {
            Exports::Trie(raw) => {
                if raw.is_empty() {
                    return Ok(None);
                }
                lookup(raw, 0, name.as_bytes(), 0)
            }
            Exports::Flat(v) => Ok(v.iter().find(|e| e.name == name).cloned()),
        }
    }
}

fn read_terminal(
    trie: &[u8],
    node_off: usize,
    accumulated: &str,
) -> Result<Option<ExportEntry>, ReadError> {
    let (terminal_size, n) = read_uleb_at(trie, node_off)?;
    if terminal_size == 0 {
        return Ok(None);
    }
    let mut cursor = node_off + n;
    let (flags, m) = read_uleb_at(trie, cursor)?;
    cursor += m;
    let kind = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let (ord, on) = read_uleb_at(trie, cursor)?;
        cursor += on;
        let imported_name = read_cstring(trie, cursor)?.to_string();
        ExportKind::Reexport {
            ordinal: ord as u32,
            imported_name,
        }
    } else if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let (stub, sn) = read_uleb_at(trie, cursor)?;
        cursor += sn;
        let (resolver, _rn) = read_uleb_at(trie, cursor)?;
        ExportKind::StubAndResolver { stub, resolver }
    } else {
        let (addr, _an) = read_uleb_at(trie, cursor)?;
        match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
            EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => ExportKind::ThreadLocal { address: addr },
            EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => ExportKind::Absolute { address: addr },
            _ => ExportKind::Regular { address: addr },
        }
    };
    Ok(Some(ExportEntry {
        name: accumulated.to_string(),
        flags,
        kind,
    }))
}

fn walk(
    trie: &[u8],
    node_off: usize,
    accumulated: String,
    out: &mut Vec<ExportEntry>,
    visited: &mut std::collections::HashSet<usize>,
    depth: usize,
) -> Result<(), ReadError> {
    if depth > MAX_DEPTH {
        return Err(ReadError::BadCmdsize {
            cmd: 0,
            cmdsize: 0,
            at_offset: node_off,
            reason: "export trie depth cap exceeded",
        });
    }
    if !visited.insert(node_off) {
        return Err(ReadError::BadCmdsize {
            cmd: 0,
            cmdsize: 0,
            at_offset: node_off,
            reason: "export trie contains a cycle",
        });
    }

    if let Some(entry) = read_terminal(trie, node_off, &accumulated)? {
        out.push(entry);
    }

    // Skip past the terminal_size + terminal payload to reach child count.
    let cursor = skip_terminal(trie, node_off)?;
    if cursor >= trie.len() {
        return Err(ReadError::Truncated {
            need: cursor + 1,
            have: trie.len(),
            context: "export trie (missing child_count byte)",
        });
    }
    let child_count = trie[cursor] as usize;
    let mut child_cursor = cursor + 1;
    for _ in 0..child_count {
        let (edge, advanced) = read_cstring_with_len(trie, child_cursor)?;
        child_cursor += advanced;
        let (child_off, off_len) = read_uleb_at(trie, child_cursor)?;
        child_cursor += off_len;
        let child_off = child_off as usize;
        if child_off >= trie.len() {
            return Err(ReadError::BadCmdsize {
                cmd: 0,
                cmdsize: 0,
                at_offset: child_cursor,
                reason: "export trie child offset out of bounds",
            });
        }
        let mut next_prefix = accumulated.clone();
        next_prefix.push_str(edge);
        walk(trie, child_off, next_prefix, out, visited, depth + 1)?;
    }

    Ok(())
}

fn lookup(
    trie: &[u8],
    node_off: usize,
    remaining: &[u8],
    depth: usize,
) -> Result<Option<ExportEntry>, ReadError> {
    if depth > MAX_DEPTH {
        return Err(ReadError::BadCmdsize {
            cmd: 0,
            cmdsize: 0,
            at_offset: node_off,
            reason: "export trie depth cap exceeded",
        });
    }
    if remaining.is_empty() {
        return read_terminal(trie, node_off, "").map(|maybe| {
            maybe.map(|mut e| {
                e.name.clear();
                e
            })
        });
    }
    // Scan children for a matching edge prefix.
    let cursor = skip_terminal(trie, node_off)?;
    if cursor >= trie.len() {
        return Ok(None);
    }
    let child_count = trie[cursor] as usize;
    let mut child_cursor = cursor + 1;
    for _ in 0..child_count {
        let (edge, advanced) = read_cstring_with_len(trie, child_cursor)?;
        child_cursor += advanced;
        let (child_off, off_len) = read_uleb_at(trie, child_cursor)?;
        child_cursor += off_len;
        let edge_bytes = edge.as_bytes();
        if remaining.len() >= edge_bytes.len() && &remaining[..edge_bytes.len()] == edge_bytes {
            return lookup(trie, child_off as usize, &remaining[edge_bytes.len()..], depth + 1);
        }
    }
    Ok(None)
}

// ---- primitives ----------------------------------------------------------

fn skip_terminal(trie: &[u8], node_off: usize) -> Result<usize, ReadError> {
    let (terminal_size, n) = read_uleb_at(trie, node_off)?;
    let end = node_off
        .checked_add(n)
        .and_then(|p| p.checked_add(terminal_size as usize))
        .ok_or(ReadError::BadCmdsize {
            cmd: 0,
            cmdsize: 0,
            at_offset: node_off,
            reason: "export trie terminal_size overflows",
        })?;
    if end > trie.len() {
        return Err(ReadError::Truncated {
            need: end,
            have: trie.len(),
            context: "export trie terminal payload",
        });
    }
    Ok(end)
}

fn read_uleb_at(trie: &[u8], off: usize) -> Result<(u64, usize), ReadError> {
    if off > trie.len() {
        return Err(ReadError::Truncated {
            need: off + 1,
            have: trie.len(),
            context: "export trie uleb",
        });
    }
    read_uleb(&trie[off..])
}

fn read_cstring(trie: &[u8], off: usize) -> Result<&str, ReadError> {
    let (s, _) = read_cstring_with_len(trie, off)?;
    Ok(s)
}

fn read_cstring_with_len(trie: &[u8], off: usize) -> Result<(&str, usize), ReadError> {
    if off >= trie.len() {
        return Err(ReadError::Truncated {
            need: off + 1,
            have: trie.len(),
            context: "export trie c-string",
        });
    }
    let nul = trie[off..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(ReadError::Truncated {
            need: trie.len() + 1,
            have: trie.len(),
            context: "export trie c-string (no terminator)",
        })?;
    let s = std::str::from_utf8(&trie[off..off + nul]).map_err(|_| ReadError::BadCmdsize {
        cmd: 0,
        cmdsize: 0,
        at_offset: off,
        reason: "export trie string is not UTF-8",
    })?;
    Ok((s, nul + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leb::write_uleb;

    /// Build a leaf terminal node (no children) with given flags+address.
    fn encode_leaf_node(flags: u64, address: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        write_uleb(flags, &mut payload);
        write_uleb(address, &mut payload);
        let mut node = Vec::new();
        write_uleb(payload.len() as u64, &mut node);
        node.extend_from_slice(&payload);
        node.push(0); // child_count = 0
        node
    }

    fn encode_root_with_children(children: &[(&str, u64)], trie_len_hint: usize) -> Vec<u8> {
        // Root has no terminal: terminal_size = 0.
        let mut node = Vec::new();
        write_uleb(0, &mut node); // terminal_size
        node.push(children.len() as u8);
        for (edge, child_off) in children {
            node.extend_from_slice(edge.as_bytes());
            node.push(0);
            write_uleb(*child_off, &mut node);
        }
        assert!(node.len() <= trie_len_hint); // sanity
        node
    }

    #[test]
    fn empty_trie_yields_no_entries() {
        let trie = Exports::empty();
        assert!(trie.entries().unwrap().is_empty());
        assert!(trie.lookup("_anything").unwrap().is_none());
    }

    #[test]
    fn single_leaf_decodes_regular_export() {
        // Root has one child edge "_foo" pointing at leaf at known offset.
        let leaf = encode_leaf_node(EXPORT_SYMBOL_FLAGS_KIND_REGULAR, 0x1000);
        // Pre-size the root so we can compute the child offset.
        let root_header_len = {
            // terminal_size=0, child_count=1, edge "_foo\0", child_off ULEB
            // We need the ULEB byte count of child_off — do a guess-and-check.
            let mut tmp = Vec::new();
            write_uleb(0, &mut tmp);
            tmp.push(1);
            tmp.extend_from_slice(b"_foo\0");
            write_uleb(0, &mut tmp); // placeholder offset, ULEB width = 1
            tmp.len()
        };
        let child_off = root_header_len as u64;
        let root = encode_root_with_children(&[("_foo", child_off)], 256);
        assert_eq!(root.len(), root_header_len);
        let mut trie_bytes = root;
        trie_bytes.extend_from_slice(&leaf);

        let trie = Exports::from_trie_bytes(&trie_bytes);
        let entries = trie.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "_foo");
        assert_eq!(entries[0].kind, ExportKind::Regular { address: 0x1000 });
    }

    #[test]
    fn reexport_terminal_decodes() {
        let mut payload = Vec::new();
        write_uleb(EXPORT_SYMBOL_FLAGS_REEXPORT, &mut payload);
        write_uleb(2, &mut payload); // ordinal
        payload.extend_from_slice(b"_target\0");
        let mut leaf = Vec::new();
        write_uleb(payload.len() as u64, &mut leaf);
        leaf.extend_from_slice(&payload);
        leaf.push(0);

        // Root points at leaf.
        let root_header_len = {
            let mut tmp = Vec::new();
            write_uleb(0, &mut tmp);
            tmp.push(1);
            tmp.extend_from_slice(b"_alias\0");
            write_uleb(0, &mut tmp);
            tmp.len()
        };
        let root = encode_root_with_children(&[("_alias", root_header_len as u64)], 256);
        let mut trie_bytes = root;
        trie_bytes.extend_from_slice(&leaf);

        let trie = Exports::from_trie_bytes(&trie_bytes);
        let entries = trie.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "_alias");
        assert_eq!(
            entries[0].kind,
            ExportKind::Reexport {
                ordinal: 2,
                imported_name: "_target".into(),
            }
        );
    }

    #[test]
    fn lookup_returns_none_for_missing_name() {
        let leaf = encode_leaf_node(EXPORT_SYMBOL_FLAGS_KIND_REGULAR, 0x40);
        let root_header_len = {
            let mut tmp = Vec::new();
            write_uleb(0, &mut tmp);
            tmp.push(1);
            tmp.extend_from_slice(b"_foo\0");
            write_uleb(0, &mut tmp);
            tmp.len()
        };
        let root = encode_root_with_children(&[("_foo", root_header_len as u64)], 256);
        let mut trie_bytes = root;
        trie_bytes.extend_from_slice(&leaf);
        let trie = Exports::from_trie_bytes(&trie_bytes);
        assert!(trie.lookup("_bar").unwrap().is_none());
        assert!(trie.lookup("_foo").unwrap().is_some());
    }

    #[test]
    fn malformed_child_offset_errors() {
        // Root claims a child at offset 1000 but trie is tiny.
        let root = encode_root_with_children(&[("_x", 1000)], 256);
        let trie = Exports::from_trie_bytes(&root);
        assert!(trie.entries().is_err());
    }
}
