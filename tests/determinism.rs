//! Sprint 28 determinism guardrails.
//!
//! Parallel speedups are only safe if they never perturb the final image. This
//! test repeatedly links one synthetic-section-heavy executable and requires
//! byte-identical output across concurrent runs.

mod common;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use afs_ld::{LinkOptions, Linker, OutputKind};
use common::harness::{assemble, have_xcrun, have_xcrun_tool};

const DEFAULT_RUNS: usize = 100;

#[test]
fn repeated_parallel_links_are_byte_identical() {
    if !have_xcrun() || !have_xcrun_tool("as") {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let root = unique_temp_dir("determinism").expect("create determinism temp dir");
    let obj = root.join("input.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _main\n\
        _main:\n\
            adrp x8, _value@GOTPAGE\n\
            ldr x8, [x8, _value@GOTPAGEOFF]\n\
            ldr w0, [x8]\n\
            ret\n\
\n\
        .section __DATA,__data\n\
        .globl _value\n\
        .p2align 2\n\
        _value:\n\
            .long 7\n\
        .subsections_via_symbols\n",
        &obj,
    )
    .expect("assemble determinism fixture");

    let baseline = link_once(&obj, &root, "baseline").expect("baseline deterministic link");
    let run_count = determinism_run_count();
    let jobs = determinism_jobs(run_count);
    let queue = Arc::new(Mutex::new((0..run_count).collect::<VecDeque<_>>()));
    let errors = Arc::new(Mutex::new(Vec::new()));

    thread::scope(|scope| {
        for _ in 0..jobs {
            let queue = Arc::clone(&queue);
            let errors = Arc::clone(&errors);
            let baseline = baseline.clone();
            let root = root.clone();
            let obj = obj.clone();
            scope.spawn(move || loop {
                let Some(index) = queue
                    .lock()
                    .expect("determinism queue mutex poisoned")
                    .pop_front()
                else {
                    break;
                };
                match link_once(&obj, &root, &format!("run-{index:03}")) {
                    Ok(bytes) if bytes == baseline => {}
                    Ok(bytes) => errors
                        .lock()
                        .expect("determinism errors mutex poisoned")
                        .push(format!(
                            "run {index} differed: baseline={} bytes, output={} bytes",
                            baseline.len(),
                            bytes.len()
                        )),
                    Err(error) => errors
                        .lock()
                        .expect("determinism errors mutex poisoned")
                        .push(format!("run {index} failed: {error}")),
                }
            });
        }
    });

    let errors = errors
        .lock()
        .expect("determinism errors mutex poisoned")
        .clone();
    assert!(
        errors.is_empty(),
        "parallel deterministic links diverged:\n{}",
        errors.join("\n")
    );

    let _ = fs::remove_dir_all(root);
}

fn link_once(obj: &Path, root: &Path, run_name: &str) -> Result<Vec<u8>, String> {
    let dir = root.join(run_name);
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let out = dir.join("deterministic.out");
    let opts = LinkOptions {
        inputs: vec![obj.to_path_buf()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).map_err(|e| format!("link {}: {e}", out.display()))?;
    fs::read(&out).map_err(|e| format!("read {}: {e}", out.display()))
}

fn determinism_run_count() -> usize {
    std::env::var("AFS_LD_DETERMINISM_RUNS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|runs| *runs > 0)
        .unwrap_or(DEFAULT_RUNS)
}

fn determinism_jobs(run_count: usize) -> usize {
    std::env::var("AFS_LD_DETERMINISM_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|jobs| *jobs > 0)
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
        })
        .min(run_count)
        .max(1)
}

fn unique_temp_dir(name: &str) -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock error: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("afs-ld-{name}-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}
