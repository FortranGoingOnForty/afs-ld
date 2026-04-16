//! Mach-O string table reader.
//!
//! The string table is a contiguous blob of null-terminated bytes pointed at
//! by `LC_SYMTAB.stroff / strsize`. Every symbol's `strx` is an offset into
//! this blob; the name runs from `strx` up to (not including) the next null.
//!
//! Assemblers regularly reuse suffix bytes — two symbols whose names share a
//! common tail can point at the same sequence. afs-as does this explicitly
//! via its suffix-dedup sort. The walker here handles any strx that lands
//! between nulls, not just those aligned to the start of a name.

use std::collections::HashMap;

use crate::macho::reader::ReadError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTable {
    raw: Vec<u8>,
}

impl StringTable {
    /// Lift the string table out of a file image, owning a copy for lifetime
    /// independence from the source buffer. Both `stroff` and `strsize` come
    /// from `LC_SYMTAB`.
    pub fn from_file(file_bytes: &[u8], stroff: u32, strsize: u32) -> Result<Self, ReadError> {
        let start = stroff as usize;
        let end = start.checked_add(strsize as usize).ok_or(ReadError::Truncated {
            need: usize::MAX,
            have: file_bytes.len(),
            context: "string table (stroff + strsize overflows)",
        })?;
        if end > file_bytes.len() {
            return Err(ReadError::Truncated {
                need: end,
                have: file_bytes.len(),
                context: "string table",
            });
        }
        Ok(StringTable {
            raw: file_bytes[start..end].to_vec(),
        })
    }

    /// Construct directly from owned bytes — handy for tests and for the
    /// writer path (Sprint 14 builds a fresh table before emission).
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        StringTable { raw }
    }

    /// Raw underlying bytes; useful for byte-level round-trip tests.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Look up the null-terminated string at offset `strx`. Non-UTF-8 names
    /// return `ReadError::BadCmdsize` (re-used as the structural-error kind)
    /// with a contextual `reason`; callers never see lossy replacement bytes.
    ///
    /// `strx = 0` returns the empty string (strtabs start with a null).
    pub fn get(&self, strx: u32) -> Result<&str, ReadError> {
        let start = strx as usize;
        if start >= self.raw.len() {
            return Err(ReadError::BadCmdsize {
                cmd: 0,
                cmdsize: 0,
                at_offset: start,
                reason: "strx out of bounds",
            });
        }
        let end = start + self.raw[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(ReadError::BadCmdsize {
                cmd: 0,
                cmdsize: 0,
                at_offset: start,
                reason: "unterminated string (no null byte before end)",
            })?;
        std::str::from_utf8(&self.raw[start..end]).map_err(|_| ReadError::BadCmdsize {
            cmd: 0,
            cmdsize: 0,
            at_offset: start,
            reason: "non-UTF-8 bytes in symbol name",
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringTableBuilder {
    roots: Vec<(String, u32)>,
    offsets: HashMap<String, u32>,
}

impl StringTableBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str) {
        self.offsets.entry(name.to_string()).or_insert(0);
    }

    pub fn finish(mut self) -> (Vec<u8>, HashMap<String, u32>) {
        let mut names: Vec<String> = self.offsets.keys().cloned().collect();
        names.sort_by(|lhs, rhs| reverse_suffix_order(lhs, rhs));

        let mut raw = vec![0u8];
        for name in names {
            if let Some(offset) = self.find_suffix_offset(&name) {
                self.offsets.insert(name, offset);
                continue;
            }

            let offset = raw.len() as u32;
            raw.extend_from_slice(name.as_bytes());
            raw.push(0);
            self.roots.push((name.clone(), offset));
            self.offsets.insert(name, offset);
        }

        while !raw.len().is_multiple_of(8) {
            raw.push(0);
        }
        (raw, self.offsets)
    }

    fn find_suffix_offset(&self, name: &str) -> Option<u32> {
        self.roots.iter().find_map(|(existing, offset)| {
            if existing.ends_with(name) {
                Some(*offset + (existing.len() - name.len()) as u32)
            } else {
                None
            }
        })
    }
}

fn reverse_suffix_order(lhs: &str, rhs: &str) -> std::cmp::Ordering {
    let mut lhs_rev = lhs.bytes().rev();
    let mut rhs_rev = rhs.bytes().rev();
    loop {
        match (lhs_rev.next(), rhs_rev.next()) {
            (Some(a), Some(b)) => match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
            (Some(_), None) => return std::cmp::Ordering::Less,
            (None, Some(_)) => return std::cmp::Ordering::Greater,
            (None, None) => return lhs.cmp(rhs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tbl(bytes: &[u8]) -> StringTable {
        StringTable::from_bytes(bytes.to_vec())
    }

    #[test]
    fn empty_strx_yields_empty_string() {
        let t = tbl(b"\0");
        assert_eq!(t.get(0).unwrap(), "");
    }

    #[test]
    fn resolves_simple_name() {
        let t = tbl(b"\0_main\0_helper\0");
        assert_eq!(t.get(1).unwrap(), "_main");
        assert_eq!(t.get(7).unwrap(), "_helper");
    }

    #[test]
    fn suffix_dedup_overlap() {
        // strtab contains "_afs_array_sum\0" at offset 1; a symbol named just
        // "array_sum" (9 chars) points mid-string at offset 6.
        let mut raw = vec![0u8];
        raw.extend_from_slice(b"_afs_array_sum\0");
        let t = tbl(&raw);
        assert_eq!(t.get(1).unwrap(), "_afs_array_sum");
        assert_eq!(t.get(6).unwrap(), "array_sum");
        assert_eq!(t.get(10).unwrap(), "y_sum");
    }

    #[test]
    fn out_of_bounds_strx_errors() {
        let t = tbl(b"\0a\0");
        let err = t.get(100).unwrap_err();
        assert!(matches!(err, ReadError::BadCmdsize { reason, .. } if reason.contains("out of bounds")));
    }

    #[test]
    fn unterminated_string_errors() {
        let t = tbl(b"\0abcdef"); // no trailing null
        let err = t.get(1).unwrap_err();
        assert!(matches!(err, ReadError::BadCmdsize { reason, .. } if reason.contains("unterminated")));
    }

    #[test]
    fn non_utf8_bytes_error() {
        let t = tbl(&[0, 0xff, 0xfe, 0]);
        let err = t.get(1).unwrap_err();
        assert!(matches!(err, ReadError::BadCmdsize { reason, .. } if reason.contains("UTF-8")));
    }

    #[test]
    fn from_file_bounds_check() {
        let file = vec![0u8; 32];
        // stroff + strsize spills off the end.
        let err = StringTable::from_file(&file, 30, 10).unwrap_err();
        assert!(matches!(err, ReadError::Truncated { .. }));
    }

    #[test]
    fn from_file_copies_range() {
        let mut file = vec![0u8; 8];
        file.extend_from_slice(b"\0_main\0");
        let t = StringTable::from_file(&file, 8, 7).unwrap();
        assert_eq!(t.as_bytes(), b"\0_main\0");
        assert_eq!(t.get(1).unwrap(), "_main");
    }

    #[test]
    fn builder_dedups_suffix_names() {
        let mut builder = StringTableBuilder::new();
        builder.insert("_array_sum");
        builder.insert("_afs_array_sum");

        let (bytes, offsets) = builder.finish();
        let table = StringTable::from_bytes(bytes);
        let afs = offsets["_afs_array_sum"];
        let array = offsets["_array_sum"];

        assert_eq!(table.get(afs).unwrap(), "_afs_array_sum");
        assert_eq!(table.get(array).unwrap(), "_array_sum");
        assert_eq!(array, afs + 4);
        assert_eq!(table.as_bytes().len() % 8, 0);
    }
}
