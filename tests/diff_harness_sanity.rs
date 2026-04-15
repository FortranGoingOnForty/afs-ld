//! Two identical byte slices must produce zero critical diffs.

mod common;

use common::harness::diff_macho;

#[test]
fn identical_inputs_produce_zero_critical_diffs() {
    let a = b"same bytes everywhere".to_vec();
    let b = a.clone();
    let report = diff_macho(&a, &b);
    assert!(
        report.is_clean(),
        "identical inputs produced critical diffs: {:#?}",
        report.critical
    );
    assert!(report.tolerated.is_empty());
}
