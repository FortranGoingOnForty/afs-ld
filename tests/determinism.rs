//! Sprint 28 determinism guardrails.
//!
//! Parallel speedups are only safe if they never perturb the final image. This
//! test repeatedly links a multi-object executable and requires byte-identical
//! output across concurrent runs.

mod common;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    let main_obj = root.join("main.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _main\n\
        _main:\n\
            bl _helper\n\
            adrp x8, _value@GOTPAGE\n\
            ldr x8, [x8, _value@GOTPAGEOFF]\n\
            ldr w0, [x8]\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &main_obj,
    )
    .expect("assemble determinism main fixture");
    let helper_obj = root.join("helper.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _helper\n\
        _helper:\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &helper_obj,
    )
    .expect("assemble determinism helper fixture");
    let data_obj = root.join("data.o");
    assemble(
        "\
        .section __DATA,__data\n\
        .globl _value\n\
        .p2align 2\n\
        _value:\n\
            .long 7\n\
\n\
        .subsections_via_symbols\n",
        &data_obj,
    )
    .expect("assemble determinism data fixture");

    let inputs = vec![main_obj, helper_obj, data_obj];
    assert_repeated_links_identical(inputs, &root, "objects");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn repeated_parallel_archive_fetches_are_byte_identical() {
    if !have_xcrun() || !have_xcrun_tool("as") {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let root = unique_temp_dir("archive-determinism").expect("create archive determinism temp dir");
    let main_obj = root.join("main.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _main\n\
        _main:\n\
            bl _helper_a\n\
            bl _helper_b\n\
            mov w0, #0\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &main_obj,
    )
    .expect("assemble archive determinism main fixture");
    let helper_a_obj = root.join("helper_a.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _helper_a\n\
        _helper_a:\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &helper_a_obj,
    )
    .expect("assemble archive determinism helper_a fixture");
    let helper_b_obj = root.join("helper_b.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _helper_b\n\
        _helper_b:\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &helper_b_obj,
    )
    .expect("assemble archive determinism helper_b fixture");
    let unused_obj = root.join("unused.o");
    assemble(
        "\
        .section __TEXT,__text,regular,pure_instructions\n\
        .globl _unused\n\
        _unused:\n\
            ret\n\
\n\
        .subsections_via_symbols\n",
        &unused_obj,
    )
    .expect("assemble archive determinism unused fixture");

    let archive_path = root.join("libhelpers.a");
    if let Err(error) = archive(&[helper_a_obj, helper_b_obj, unused_obj], &archive_path) {
        eprintln!("skipping: archive failed: {error}");
        let _ = fs::remove_dir_all(root);
        return;
    }

    assert_repeated_links_identical(vec![main_obj, archive_path], &root, "archive");

    let _ = fs::remove_dir_all(root);
}

fn assert_repeated_links_identical(inputs: Vec<PathBuf>, root: &Path, label: &str) {
    let baseline = link_once(&inputs, root, &format!("{label}-baseline"))
        .expect("baseline deterministic link");
    let serial = link_once_with_jobs(&inputs, root, &format!("{label}-serial"), Some(1))
        .expect("single-worker deterministic link");
    assert_eq!(
        serial, baseline,
        "{label}: single-worker link differed from default parallel link"
    );
    let run_count = determinism_run_count();
    let jobs = determinism_jobs(run_count);
    let queue = Arc::new(Mutex::new((0..run_count).collect::<VecDeque<_>>()));
    let errors = Arc::new(Mutex::new(Vec::new()));

    thread::scope(|scope| {
        for _ in 0..jobs {
            let queue = Arc::clone(&queue);
            let errors = Arc::clone(&errors);
            let baseline = baseline.clone();
            let inputs = inputs.clone();
            scope.spawn(move || loop {
                let Some(index) = queue
                    .lock()
                    .expect("determinism queue mutex poisoned")
                    .pop_front()
                else {
                    break;
                };
                match link_once(&inputs, root, &format!("{label}-run-{index:03}")) {
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
}

fn link_once(inputs: &[PathBuf], root: &Path, run_name: &str) -> Result<Vec<u8>, String> {
    link_once_with_jobs(inputs, root, run_name, None)
}

fn link_once_with_jobs(
    inputs: &[PathBuf],
    root: &Path,
    run_name: &str,
    jobs: Option<usize>,
) -> Result<Vec<u8>, String> {
    let dir = root.join(run_name);
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let out = dir.join("deterministic.out");
    let opts = LinkOptions {
        inputs: inputs.to_vec(),
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        jobs,
        ..LinkOptions::default()
    };
    Linker::run(&opts).map_err(|e| format!("link {}: {e}", out.display()))?;
    fs::read(&out).map_err(|e| format!("read {}: {e}", out.display()))
}

fn archive(objects: &[PathBuf], out: &Path) -> Result<(), String> {
    let output = Command::new("libtool")
        .arg("-static")
        .arg("-o")
        .arg(out)
        .args(objects)
        .output()
        .map_err(|e| format!("spawn libtool: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "libtool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
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
