use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

mod common;

use afs_ld::{LinkOptions, LinkProfile, Linker};
use common::harness::{
    assemble, have_tool, have_xcrun, have_xcrun_tool, scratch, sdk_path, sdk_version,
};

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

fn runtime_archive_fixture() -> Result<PathBuf, String> {
    if let Some(runtime) = find_runtime_archive() {
        return Ok(runtime);
    }
    build_synthetic_runtime_archive()
}

fn build_synthetic_runtime_archive() -> Result<PathBuf, String> {
    if !have_tool("libtool") {
        return Err("libtool unavailable".into());
    }

    let members = [
        ("init", "_afs_program_init"),
        ("finalize", "_afs_program_finalize"),
        ("write_i32", "_afs_write_i32"),
        ("write_f64", "_afs_write_f64"),
        ("write_newline", "_afs_write_newline"),
        ("read_i32", "_afs_read_i32"),
        ("alloc", "_afs_alloc"),
        ("dealloc", "_afs_dealloc"),
        ("bounds_check", "_afs_bounds_check"),
        ("stop", "_afs_stop"),
        ("date_and_time", "_afs_date_and_time"),
        ("cpu_time", "_afs_cpu_time"),
        ("random_seed", "_afs_random_seed"),
        ("random_number", "_afs_random_number"),
        ("open_unit", "_afs_open_unit"),
        ("close_unit", "_afs_close_unit"),
    ];
    let mut objects = Vec::with_capacity(members.len());
    for (stem, symbol) in members {
        let obj = scratch(&format!("perf-runtime-{stem}.o"));
        let src = format!(
            "\
            .text\n\
            .globl {symbol}\n\
            .p2align 2\n\
            {symbol}:\n\
                ret\n\
            .subsections_via_symbols\n",
        );
        assemble(&src, &obj)?;
        objects.push(obj);
    }

    let archive = scratch("libafs-perf-runtime.a");
    let _ = fs::remove_file(&archive);
    let output = Command::new("libtool")
        .args(["-static", "-o"])
        .arg(&archive)
        .args(&objects)
        .output()
        .map_err(|e| format!("spawn libtool archive: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "libtool archive failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(archive)
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
        "{name}: total={:?} parse={:?} resolve={:?} atomize={:?} layout={:?} (entry={:?} dead={:?} icf={:?} synth_plan={:?} build={:?} thunks={:?}) synth={:?} (linkedit={:?}: symbols={:?} [locals={:?} globals={:?} strtab={:?}] dyld={:?} [bind={:?} rebase={:?} export={:?}] metadata={:?} codesig={:?}; unwind={:?}) reloc={:?} write={:?} [image={:?} file={:?} linkmap={:?} perms={:?}]",
        profile.total_wall,
        profile.phases.input_parsing,
        profile.phases.symbol_resolution,
        profile.phases.atomization,
        profile.phases.layout,
        profile.phases.layout_entry_lookup,
        profile.phases.layout_dead_strip,
        profile.phases.layout_icf,
        profile.phases.layout_synthetic_plan,
        profile.phases.layout_build,
        profile.phases.layout_thunk_plan,
        profile.phases.synth_sections,
        profile.phases.synth_linkedit_finalize,
        profile.phases.synth_linkedit_symbol_plan,
        profile.phases.synth_linkedit_symbol_plan_locals,
        profile.phases.synth_linkedit_symbol_plan_globals,
        profile.phases.synth_linkedit_symbol_plan_strtab,
        profile.phases.synth_linkedit_dyld_info,
        profile.phases.synth_linkedit_dyld_bind,
        profile.phases.synth_linkedit_dyld_rebase,
        profile.phases.synth_linkedit_dyld_export,
        profile.phases.synth_linkedit_metadata_tables,
        profile.phases.synth_linkedit_code_signature,
        profile.phases.synth_unwind,
        profile.phases.reloc_apply,
        profile.phases.write_output,
        profile.phases.write_image_build,
        profile.phases.write_file,
        profile.phases.write_link_map,
        profile.phases.write_permissions,
    );
    eprintln!(
        "{name}: input read={:?} object={:?} archive={:?} dylib={:?} tbd_decode={:?} tbd_materialize={:?} reloc_cache={:?}",
        profile.phases.input_read,
        profile.phases.input_object_parse,
        profile.phases.input_archive_parse,
        profile.phases.input_dylib_parse,
        profile.phases.input_tbd_decode,
        profile.phases.input_tbd_materialize,
        profile.phases.input_reloc_parse,
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
    let input_subphase_total = profile.phases.input_read
        + profile.phases.input_object_parse
        + profile.phases.input_archive_parse
        + profile.phases.input_dylib_parse
        + profile.phases.input_tbd_decode
        + profile.phases.input_tbd_materialize
        + profile.phases.input_reloc_parse;
    // Input subphases are summed worker-time once object parsing is parallel,
    // so they can legitimately exceed the wall-clock input parsing bucket.
    assert!(
        input_subphase_total > Duration::ZERO,
        "{name}: all input subphase timings were zero"
    );
    assert!(
        profile.phases.layout
            >= profile.phases.layout_entry_lookup
                + profile.phases.layout_dead_strip
                + profile.phases.layout_icf
                + profile.phases.layout_synthetic_plan
                + profile.phases.layout_build
                + profile.phases.layout_thunk_plan,
        "{name}: layout subphases exceeded layout total"
    );
    assert!(
        profile.phases.synth_sections
            >= profile.phases.synth_linkedit_finalize + profile.phases.synth_unwind,
        "{name}: synth subphases exceeded synth total"
    );
    assert!(
        profile.phases.synth_linkedit_finalize
            >= profile.phases.synth_linkedit_symbol_plan
                + profile.phases.synth_linkedit_dyld_info
                + profile.phases.synth_linkedit_metadata_tables
                + profile.phases.synth_linkedit_code_signature,
        "{name}: linkedit subphases exceeded linkedit total"
    );
    assert!(
        profile.phases.synth_linkedit_symbol_plan
            >= profile.phases.synth_linkedit_symbol_plan_locals
                + profile.phases.synth_linkedit_symbol_plan_globals
                + profile.phases.synth_linkedit_symbol_plan_strtab,
        "{name}: symbol-plan subphases exceeded symbol-plan total"
    );
    assert!(
        profile.phases.synth_linkedit_dyld_info
            >= profile.phases.synth_linkedit_dyld_bind
                + profile.phases.synth_linkedit_dyld_rebase
                + profile.phases.synth_linkedit_dyld_export,
        "{name}: dyld-info subphases exceeded dyld-info total"
    );
    assert!(
        profile.phases.write_output
            >= profile.phases.write_image_build
                + profile.phases.write_file
                + profile.phases.write_link_map
                + profile.phases.write_permissions,
        "{name}: write subphases exceeded write total"
    );
}

#[test]
fn bench_hello_world_profile_reports_baseline_timings() {
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
fn bench_runtime_link_profile_reports_baseline_timings() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let runtime = match runtime_archive_fixture() {
        Ok(runtime) => runtime,
        Err(reason) => {
            eprintln!("skipping: {reason}");
            return;
        }
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

#[test]
fn bench_fortsh_fixture_profile_reports_baseline_timings() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(inputs_file) = std::env::var_os("AFS_LD_FORTSH_INPUTS_FILE").map(PathBuf::from) else {
        eprintln!("skipping: set AFS_LD_FORTSH_INPUTS_FILE to a newline-delimited input list");
        return;
    };

    let mut inputs: Vec<PathBuf> = fs::read_to_string(&inputs_file)
        .unwrap_or_else(|e| panic!("read {}: {e}", inputs_file.display()))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(PathBuf::from)
        .collect();
    let runtime = runtime_archive_fixture().expect("fortsh profile runtime archive");
    inputs.push(runtime);

    let out = scratch("perf-fortsh.out");
    let profile = Linker::run_profiled(&executable_opts(inputs, out)).expect("profile fortsh link");
    assert_profile_basics("fortsh", &profile);

    if let Ok(limit_ms) = std::env::var("AFS_LD_FORTSH_BUDGET_MS") {
        let limit = Duration::from_millis(limit_ms.parse().expect("parse fortsh budget"));
        assert!(
            profile.total_wall <= limit,
            "fortsh baseline exceeded budget: {:?} > {:?}",
            profile.total_wall,
            limit
        );
    }
}
