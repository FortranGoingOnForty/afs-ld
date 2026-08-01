use std::fs;
#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

mod common;

use afs_ld::{LinkOptions, LinkProfile, Linker};
use common::artifacts::workspace_artifact;
use common::harness::{
    assemble, have_tool, have_xcrun, have_xcrun_tool, scratch, sdk_path, sdk_version,
};

const WARM_SAMPLES: usize = 11;
const REQUIRED_BUDGET_PASSES: usize = 9;

fn performance_prerequisites_available() -> bool {
    if have_xcrun() && have_xcrun_tool("ld") {
        return true;
    }

    if std::env::var_os("AFS_LD_REQUIRE_PERF_PREREQUISITES").is_some() {
        panic!("required performance-test prerequisites are unavailable");
    }
    harness_skip!("xcrun as/ld unavailable");
    false
}

fn build_synthetic_runtime_archive() -> Result<PathBuf, String> {
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
        "{name}: total={:?} parse={:?} resolve={:?} atomize={:?} layout={:?} (entry={:?} dead={:?} icf={:?} synth_plan={:?} build={:?} thunks={:?}) synth={:?} (linkedit={:?}: symbols={:?} [locals={:?} globals={:?} strtab={:?}] dyld={:?} [bind={:?} rebase={:?} export={:?}] metadata={:?} codesig={:?}; unwind={:?}) reloc={:?} write={:?}",
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
}

fn budget_pass_count(samples: &[Duration], limit: Duration) -> usize {
    samples.iter().filter(|sample| **sample <= limit).count()
}

fn assert_warm_budget(name: &str, env_name: &str, inputs: &[PathBuf], output_stem: &str) {
    let Ok(limit_ms) = std::env::var(env_name) else {
        return;
    };
    let limit = Duration::from_millis(limit_ms.parse().expect("parse performance budget"));
    let mut profiles = Vec::with_capacity(WARM_SAMPLES);
    for sample in 1..=WARM_SAMPLES {
        let label = format!("{name} warm sample {sample}");
        let output = scratch(&format!("{output_stem}-warm-{sample}.out"));
        let profile = Linker::run_profiled(&executable_opts(inputs.to_vec(), output))
            .unwrap_or_else(|error| panic!("profile {label}: {error}"));
        assert_profile_basics(&label, &profile);
        profiles.push(profile);
    }

    let mut totals: Vec<_> = profiles.iter().map(|profile| profile.total_wall).collect();
    totals.sort_unstable();
    let mut tbd_decode: Vec<_> = profiles
        .iter()
        .map(|profile| profile.phases.input_tbd_decode)
        .collect();
    tbd_decode.sort_unstable();
    let passes = budget_pass_count(&totals, limit);
    let median = totals[WARM_SAMPLES / 2];
    let p90 = totals[WARM_SAMPLES * 9 / 10];
    eprintln!(
        "{name}: warm budget passes={passes}/{WARM_SAMPLES} limit={limit:?} min={:?} median={median:?} p90={p90:?} max={:?} tbd_decode_median={:?}",
        totals[0],
        totals[WARM_SAMPLES - 1],
        tbd_decode[WARM_SAMPLES / 2],
    );
    assert!(
        passes >= REQUIRED_BUDGET_PASSES,
        "{name}: only {passes}/{WARM_SAMPLES} warm samples met {limit:?}; min={:?} median={median:?} p90={p90:?} max={:?}",
        totals[0],
        totals[WARM_SAMPLES - 1],
    );
}

#[test]
fn bench_hello_world_profile_reports_baseline_timings() {
    if !performance_prerequisites_available() {
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

    let profile =
        Linker::run_profiled(&executable_opts(vec![obj.clone()], out)).expect("profile hello");
    assert_profile_basics("hello", &profile);
    assert_warm_budget(
        "hello",
        "AFS_LD_HELLO_BUDGET_MS",
        std::slice::from_ref(&obj),
        "perf-hello",
    );
}

#[test]
fn bench_runtime_link_profile_reports_baseline_timings() {
    if !performance_prerequisites_available() {
        return;
    }
    let runtime = match workspace_artifact("libarmfortas_rt.a") {
        Some(runtime) => runtime,
        None if !have_tool("libtool") => {
            harness_skip!("libtool unavailable");
            return;
        }
        None => require_fixture!(
            "synthetic runtime archive",
            build_synthetic_runtime_archive()
        ),
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

    let inputs = vec![obj, runtime];
    let profile =
        Linker::run_profiled(&executable_opts(inputs.clone(), out)).expect("profile runtime link");
    assert_profile_basics("runtime", &profile);
    assert_warm_budget(
        "runtime",
        "AFS_LD_RUNTIME_BUDGET_MS",
        &inputs,
        "perf-runtime",
    );
}

#[test]
fn warm_budget_tolerates_at_most_two_slow_samples() {
    let limit = Duration::from_millis(150);
    let mut samples = vec![limit; REQUIRED_BUDGET_PASSES];
    samples.extend([Duration::from_millis(151); 2]);
    assert_eq!(budget_pass_count(&samples, limit), REQUIRED_BUDGET_PASSES);

    samples[0] = Duration::from_millis(151);
    assert_eq!(
        budget_pass_count(&samples, limit),
        REQUIRED_BUDGET_PASSES - 1
    );
}
