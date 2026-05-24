mod common;

use std::path::PathBuf;

use common::harness::{have_xcrun, have_xcrun_tool, link_both, load_corpus, LinkCase};

fn corpus_cases() -> Vec<LinkCase> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_corpus");
    load_corpus(&root).expect("load parity corpus")
}

fn find_case<'a>(cases: &'a [LinkCase], name: &str) -> &'a LinkCase {
    cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing parity corpus case `{name}`"))
}

fn assert_size_near(case: &LinkCase, max_ratio: f64) -> (usize, usize, f64) {
    let outputs = link_both(case).unwrap_or_else(|err| panic!("{} link failed: {err}", case.name));
    let ours = outputs.ours.len();
    let theirs = outputs.theirs.len();
    let ratio = ours as f64 / theirs as f64;
    eprintln!(
        "{} size audit: afs-ld={} Apple ld={} ratio={:.3}",
        case.name, ours, theirs, ratio
    );
    assert!(
        ratio <= max_ratio,
        "{} size drift exceeded budget: afs-ld={} Apple ld={} ratio={:.3} budget={:.3}",
        case.name,
        ours,
        theirs,
        ratio,
        max_ratio
    );
    (ours, theirs, ratio)
}

#[test]
fn hello_and_runtime_binary_sizes_stay_near_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }

    let cases = corpus_cases();
    let hello = assert_size_near(find_case(&cases, "hello_classic"), 1.20);
    let runtime = assert_size_near(find_case(&cases, "runtime_fortran_three_func_exec"), 1.20);

    assert!(hello.0 > 0 && hello.1 > 0);
    assert!(runtime.0 > hello.0);
    assert!(runtime.1 > hello.1);
}
