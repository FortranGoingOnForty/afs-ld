//! Two byte slices that differ in a non-tolerated region must surface as
//! critical diffs. Proves the harness actually notices regressions — otherwise
//! every later differential test becomes a silent false-negative generator.

mod common;

use common::harness::diff_macho;

#[test]
fn differing_bytes_surface_as_critical() {
    let ours = b"hello world".to_vec();
    let mut theirs = ours.clone();
    theirs[6] = b'W'; // capitalize the W in "world"

    let report = diff_macho(&ours, &theirs);
    assert!(!report.is_clean(), "harness missed a real byte difference");
    assert_eq!(report.critical.len(), 1);
    let chunk = &report.critical[0];
    assert_eq!(chunk.offset, 6);
    assert_eq!(chunk.len, 1);
}

#[test]
fn size_mismatch_is_critical() {
    let ours = b"short".to_vec();
    let theirs = b"considerably longer bytes".to_vec();
    let report = diff_macho(&ours, &theirs);
    assert!(!report.is_clean());
    assert!(report.critical[0].reason.contains("size differs"));
}
