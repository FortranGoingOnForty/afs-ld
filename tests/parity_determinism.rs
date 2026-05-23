//! Sprint 31 parity-corpus determinism sweep.
//!
//! The earlier determinism tests use focused synthetic fixtures. Sprint 31's
//! closeout bar is stricter: every parity-corpus case must relink
//! byte-identically across repeated parallel afs-ld invocations.

mod common;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use common::harness::{
    assert_case_deterministic, have_xcrun, have_xcrun_tool, load_corpus, DeterminismReport,
    LinkCase,
};

const DEFAULT_RUNS: usize = 10;
const DEFAULT_LINK_JOBS: usize = 8;
const DEFAULT_CASE_JOBS: usize = 4;

#[test]
fn parity_corpus_outputs_are_deterministic_across_ten_parallel_runs() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_corpus");
    let cases = load_corpus(&root).expect("load parity corpus");
    assert!(
        cases.len() >= 50,
        "expected at least 50 parity corpus cases under {}, found {}",
        root.display(),
        cases.len()
    );

    let runs = run_count();
    let link_jobs = link_jobs();
    let case_reports = run_cases(cases, runs, link_jobs);
    let failures: Vec<_> = case_reports
        .iter()
        .filter_map(|(case_name, result)| result.as_ref().err().map(|error| (case_name, error)))
        .collect();

    eprintln!(
        "parity determinism: {} case(s), {runs} run(s) per case, afs-ld -j {link_jobs}",
        case_reports.len()
    );
    for (case_name, result) in &case_reports {
        if let Ok(report) = result {
            eprintln!(
                "  {case_name}: len={} hash={:016x}",
                report.len, report.hash
            );
        }
    }

    assert!(
        failures.is_empty(),
        "parity determinism failures ({} cases):\n{}",
        failures.len(),
        failures
            .into_iter()
            .map(|(name, error)| format!("[{name}] {error}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
}

fn run_cases(
    cases: Vec<LinkCase>,
    runs: usize,
    link_jobs: usize,
) -> Vec<(String, Result<DeterminismReport, String>)> {
    let case_count = cases.len();
    let case_jobs = case_jobs(case_count);
    if case_jobs <= 1 || case_count <= 1 {
        return cases
            .into_iter()
            .map(|case| {
                let name = case.name.clone();
                let result = assert_case_deterministic(&case, runs, link_jobs);
                (name, result)
            })
            .collect();
    }

    let queue = Arc::new(Mutex::new(VecDeque::from_iter(
        cases.into_iter().enumerate(),
    )));
    let results = Arc::new(Mutex::new(Vec::new()));
    thread::scope(|scope| {
        for _ in 0..case_jobs {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);
            scope.spawn(move || loop {
                let Some((index, case)) = queue
                    .lock()
                    .expect("parity determinism queue mutex poisoned")
                    .pop_front()
                else {
                    break;
                };
                let name = case.name.clone();
                let result = assert_case_deterministic(&case, runs, link_jobs);
                results
                    .lock()
                    .expect("parity determinism result mutex poisoned")
                    .push((index, name, result));
            });
        }
    });

    let mut results = results
        .lock()
        .expect("parity determinism result mutex poisoned")
        .clone();
    results.sort_by_key(|(index, _, _)| *index);
    results
        .into_iter()
        .map(|(_, name, result)| (name, result))
        .collect()
}

fn run_count() -> usize {
    std::env::var("AFS_LD_PARITY_DETERMINISM_RUNS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|runs| *runs > 0)
        .unwrap_or(DEFAULT_RUNS)
}

fn link_jobs() -> usize {
    std::env::var("AFS_LD_PARITY_DETERMINISM_LINK_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|jobs| *jobs > 0)
        .unwrap_or(DEFAULT_LINK_JOBS)
}

fn case_jobs(case_count: usize) -> usize {
    std::env::var("AFS_LD_PARITY_DETERMINISM_CASE_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|jobs| *jobs > 0)
        .unwrap_or(DEFAULT_CASE_JOBS)
        .min(case_count)
        .max(1)
}
