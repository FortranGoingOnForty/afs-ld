//! Differential harness: compare afs-ld output against Apple `ld` output.
//!
//! Sprint 0 lands the diffing surface. The `link_both` function that actually
//! shells out to both linkers arrives once afs-ld can produce a real binary
//! (Sprint 18). Until then, tests exercise `diff_macho` directly against
//! synthesized byte slices.

#![allow(dead_code)]

use std::path::PathBuf;

pub struct LinkCase {
    pub name: &'static str,
    pub inputs: Vec<PathBuf>,
    pub args: Vec<String>,
}

pub struct LinkOutputs {
    pub ours: Vec<u8>,
    pub theirs: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffCategory {
    /// A diff we expect: UUID bytes, timestamps, hash-backed temp paths, etc.
    Tolerated(&'static str),
    /// Anything else. Fails the parity test.
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffChunk {
    pub offset: usize,
    pub len: usize,
    pub reason: String,
    pub category: DiffCategory,
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub tolerated: Vec<DiffChunk>,
    pub critical: Vec<DiffChunk>,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.critical.is_empty()
    }
}

/// Byte-level diff between two Mach-O images. Sprint 0 treats every byte diff
/// as Critical; later sprints layer in the tolerated-diff predicates (UUID,
/// timestamp, code-signature hashes, string-table suffix-dedup variance).
pub fn diff_macho(ours: &[u8], theirs: &[u8]) -> DiffReport {
    let mut report = DiffReport::default();

    if ours.len() != theirs.len() {
        report.critical.push(DiffChunk {
            offset: 0,
            len: ours.len().max(theirs.len()),
            reason: format!(
                "total size differs: ours = {}, theirs = {}",
                ours.len(),
                theirs.len()
            ),
            category: DiffCategory::Critical,
        });
        return report;
    }

    let mut i = 0;
    while i < ours.len() {
        if ours[i] != theirs[i] {
            let start = i;
            while i < ours.len() && ours[i] != theirs[i] {
                i += 1;
            }
            report.critical.push(DiffChunk {
                offset: start,
                len: i - start,
                reason: format!("{} byte(s) differ starting at 0x{start:x}", i - start),
                category: DiffCategory::Critical,
            });
        } else {
            i += 1;
        }
    }

    report
}

/// Placeholder for the full linker-spawning contract. Sprint 18 wires this to
/// real invocations of afs-ld and the system `ld` via `xcrun -f ld`.
pub fn link_both(_case: &LinkCase) -> LinkOutputs {
    panic!("link_both is not implemented until Sprint 18 (hello-world milestone)");
}
