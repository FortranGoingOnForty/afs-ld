//! Running afs-ld with no inputs must produce the exact diagnostic line
//! `afs-ld: error: no input files` on stderr and exit with code 2.
//!
//! The CLI surface grows over the next sprints but this invariant is the
//! baseline every later change must preserve.

use std::process::Command;

#[test]
fn empty_invocation_produces_no_input_files_diagnostic() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .output()
        .expect("afs-ld binary should exist and be executable");

    assert!(!out.status.success(), "afs-ld should fail on empty input");
    assert_eq!(
        out.status.code(),
        Some(2),
        "empty-input exit code must be 2 (CLI misuse / missing input)"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: error: no input files"),
        "expected the `no input files` diagnostic on stderr; got: {stderr}"
    );
}
