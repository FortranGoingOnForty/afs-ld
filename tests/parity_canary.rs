//! Intentional-regression guardrails for Sprint 27.

mod common;

#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

use std::path::PathBuf;

use common::harness::{
    diff_macho, have_xcrun, have_xcrun_tool, link_both, load_corpus, output_section,
};

#[test]
fn mutated_text_byte_is_not_tolerated() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_corpus");
    let case = load_corpus(&root)
        .expect("load parity corpus")
        .into_iter()
        .find(|case| case.name == "hello_classic")
        .expect("hello_classic parity case");

    let outputs = link_both(&case).expect("link hello_classic with both linkers");
    let (_, mut our_text) =
        output_section(&outputs.ours, "__TEXT", "__text").expect("afs-ld __TEXT,__text");
    let (_, their_text) =
        output_section(&outputs.theirs, "__TEXT", "__text").expect("Apple __TEXT,__text");

    our_text[0] ^= 0x1;
    let report = diff_macho(&our_text, &their_text);
    assert!(
        !report.is_clean(),
        "mutated text byte should be reported as critical: {report:#?}"
    );
    assert!(
        !report.critical.is_empty(),
        "expected at least one critical diff after mutation: {report:#?}"
    );
}
