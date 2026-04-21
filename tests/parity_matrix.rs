//! Differential parity matrix against Apple `ld`.
//!
//! Sprint 27 starts with a tiny executable-only corpus so the reusable harness,
//! on-disk case format, and runtime parity path all exist before we scale up to
//! the full corpus promised by the sprint doc.

mod common;

use std::path::PathBuf;

use common::harness::{
    compare_command_ids, compare_runtime, compare_sections, have_xcrun, have_xcrun_tool,
    link_both, load_corpus,
};

#[test]
fn parity_corpus() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_corpus");
    let cases = load_corpus(&root).expect("load parity corpus");
    assert!(
        !cases.is_empty(),
        "expected at least one parity corpus case under {}",
        root.display()
    );

    for case in cases {
        let outputs = link_both(&case).unwrap_or_else(|e| {
            panic!(
                "{}: failed to link parity case from {}:\n{}",
                case.name,
                case.dir.display(),
                e
            )
        });
        compare_command_ids(&outputs.ours, &outputs.theirs, &case.ignored_load_commands)
            .unwrap_or_else(|e| panic!("{}: load-command parity failed:\n{}", case.name, e));
        compare_sections(&outputs.ours, &outputs.theirs, &case.section_checks)
            .unwrap_or_else(|e| panic!("{}: section parity failed:\n{}", case.name, e));
        if !case.runtime_args.is_empty() || case.dir.join("runtime.txt").exists() {
            compare_runtime(&outputs.our_path, &outputs.their_path, &case.runtime_args)
                .unwrap_or_else(|e| panic!("{}: runtime parity failed:\n{}", case.name, e));
        }
    }
}
