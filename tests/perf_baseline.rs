use std::path::{Path, PathBuf};
use std::time::Duration;

mod common;

use afs_ld::{LinkOptions, LinkProfile, Linker};
use common::harness::{assemble, have_xcrun, have_xcrun_tool, scratch, sdk_path, sdk_version};

fn find_runtime_archive() -> Option<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for profile in ["debug", "release"] {
        let candidate = workspace
            .join("target")
            .join(profile)
            .join("libarmfortas_rt.a");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn executable_opts(inputs: Vec<PathBuf>, output: PathBuf) -> LinkOptions {
    LinkOptions {
        inputs,
        output: Some(output),
        syslibroot: sdk_path().map(PathBuf::from),
        platform_version: sdk_version().map(|v| {
            let parsed = afs_ld::macho::tbd::parse_version(&v);
            afs_ld::PlatformVersion {
                minos: parsed,
                sdk: parsed,
            }
        }),
        library_names: vec!["System".into()],
        ..LinkOptions::default()
    }
}

fn assert_profile_basics(name: &str, profile: &LinkProfile) {
    eprintln!(
        "{name}: total={:?} parse={:?} resolve={:?} atomize={:?} layout={:?} synth={:?} (linkedit={:?} unwind={:?}) reloc={:?} write={:?}",
        profile.total_wall,
        profile.phases.input_parsing,
        profile.phases.symbol_resolution,
        profile.phases.atomization,
        profile.phases.layout,
        profile.phases.synth_sections,
        profile.phases.synth_linkedit_finalize,
        profile.phases.synth_unwind,
        profile.phases.reloc_apply,
        profile.phases.write_output,
    );
    assert!(profile.output.is_file(), "{name}: output file missing");
    assert!(
        profile.total_wall >= profile.phases.accounted_total(),
        "{name}: accounted phases exceeded total wall time"
    );
    assert!(
        profile.phases.accounted_total() > Duration::ZERO,
        "{name}: all phase timings were zero"
    );
    assert!(
        profile.phases.synth_sections
            >= profile.phases.synth_linkedit_finalize + profile.phases.synth_unwind,
        "{name}: synth subphases exceeded synth total"
    );
}

#[test]
fn hello_world_profile_reports_baseline_timings() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }

    let obj = scratch("perf-hello.o");
    let out = scratch("perf-hello.out");
    assemble(
        "\
        .text\n\
        .globl _main\n\
        .p2align 2\n\
        _main:\n\
            mov w0, #0\n\
            ret\n",
        &obj,
    )
    .expect("assemble hello");

    let profile = Linker::run_profiled(&executable_opts(vec![obj], out)).expect("profile hello");
    assert_profile_basics("hello", &profile);

    if let Ok(limit_ms) = std::env::var("AFS_LD_HELLO_BUDGET_MS") {
        let limit = Duration::from_millis(limit_ms.parse().expect("parse hello budget"));
        assert!(
            profile.total_wall <= limit,
            "hello baseline exceeded budget: {:?} > {:?}",
            profile.total_wall,
            limit
        );
    }
}

#[test]
fn runtime_link_profile_reports_baseline_timings() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(runtime) = find_runtime_archive() else {
        eprintln!("skipping: libarmfortas_rt.a not built");
        return;
    };

    let obj = scratch("perf-runtime.o");
    let out = scratch("perf-runtime.out");
    assemble(
        "\
        .text\n\
        .globl _main\n\
        .p2align 2\n\
        _main:\n\
            stp x29, x30, [sp, #-16]!\n\
            mov x29, sp\n\
            bl _afs_program_init\n\
            bl _afs_program_finalize\n\
            mov w0, #0\n\
            ldp x29, x30, [sp], #16\n\
            ret\n",
        &obj,
    )
    .expect("assemble runtime");

    let profile = Linker::run_profiled(&executable_opts(vec![obj, runtime], out))
        .expect("profile runtime link");
    assert_profile_basics("runtime", &profile);

    if let Ok(limit_ms) = std::env::var("AFS_LD_RUNTIME_BUDGET_MS") {
        let limit = Duration::from_millis(limit_ms.parse().expect("parse runtime budget"));
        assert!(
            profile.total_wall <= limit,
            "runtime baseline exceeded budget: {:?} > {:?}",
            profile.total_wall,
            limit
        );
    }
}
