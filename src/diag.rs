//! Diagnostics. Sprint 0 has the minimum surface the CLI and tests need:
//! a single `error(msg)` helper that writes a prefixed line to stderr.
//! Sprint 30 grows this into path + byte-offset + caret output mirroring
//! `afs-as/src/diag*.rs` style.

use std::io::Write;

pub fn error(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "afs-ld: error: {msg}");
}

pub fn error_verbatim(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "{msg}");
}

pub fn warning(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "afs-ld: warning: {msg}");
}
