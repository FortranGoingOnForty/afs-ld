use std::fs;
use std::path::PathBuf;
use std::process::Command;

use afs_ld::macho::constants::LC_UUID;
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand};

const EXPECTED_HELP: &str = include_str!("snapshots/help.txt");

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sdk_path() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn minimal_main_src() -> &'static str {
    r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#
}

fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-cli-diag-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-cli-diag-{}-{name}", std::process::id()))
}

fn assemble_minimal_main(name: &str) -> Result<PathBuf, String> {
    let obj = scratch(name);
    assemble(minimal_main_src(), &obj)?;
    Ok(obj)
}

fn assert_flag_errors(flag: &str, expected: &str, name: &str) {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main(&format!("{name}.o")) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch(&format!("{name}.out"));
    let out = Command::new(exe)
        .arg(flag)
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(!out.status.success(), "{flag} should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected),
        "missing expected `{expected}` in stderr:\n{stderr}"
    );
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

fn archive(objects: &[&PathBuf], out: &PathBuf) -> Result<(), String> {
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

#[test]
fn help_flag_prints_usage_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--help")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "help should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.as_ref(), EXPECTED_HELP);
    assert!(
        out.stderr.is_empty(),
        "help should not write to stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_flag_prints_version_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "version should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        format!("afs-ld {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn no_uuid_flag_omits_uuid_load_command() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("no-uuid-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("no-uuid.out");
    let out = Command::new(exe)
        .arg("-no_uuid")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-no_uuid link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = fs::read(&out_path).expect("read linked output");
    let header = parse_header(&bytes).expect("parse header");
    let commands = parse_commands(&header, &bytes).expect("parse commands");
    assert!(
        commands.iter().all(|cmd| match cmd {
            LoadCommand::Raw { cmd, .. } => *cmd != LC_UUID,
            _ => true,
        }),
        "expected -no_uuid output to omit LC_UUID"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn strip_debug_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("strip-debug-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("strip-debug.out");
    let out = Command::new(exe)
        .arg("-S")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-S link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-S` requested"),
        "expected -S warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn objc_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("objc-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("objc.out");
    let out = Command::new(exe)
        .arg("-ObjC")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-ObjC link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-ObjC` requested"),
        "expected -ObjC warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn relocatable_flag_errors_loudly() {
    assert_flag_errors(
        "-r",
        "`-r` relocatable output is not yet supported",
        "relocatable",
    );
}

#[test]
fn bundle_flag_errors_loudly() {
    assert_flag_errors("-bundle", "`-bundle` output is not yet supported", "bundle");
}

#[test]
fn dead_strip_flag_errors_loudly() {
    assert_flag_errors(
        "-dead_strip",
        "`-dead_strip` is not yet supported",
        "dead-strip",
    );
}

#[test]
fn icf_safe_flag_errors_loudly() {
    assert_flag_errors("-icf=safe", "`-icf=safe` is not yet supported", "icf-safe");
}

#[test]
fn fixup_chains_flag_errors_loudly() {
    assert_flag_errors(
        "-fixup_chains",
        "`-fixup_chains` is not yet supported",
        "fixup-chains",
    );
}

#[test]
fn undefined_symbol_diagnostic_is_not_double_prefixed() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-o")
        .arg(scratch("missing.out"))
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: error: undefined symbol: _missing"),
        "missing expected undefined-symbol diagnostic:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: error: afs-ld: error:"),
        "diagnostic was double-prefixed:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
}

#[test]
fn undefined_warning_mode_links_and_warns_once() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-warning.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out_path = scratch("missing-warning.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("warning")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined warning should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: undefined symbol: _missing"),
        "missing expected undefined-symbol warning:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: warning: afs-ld: warning:"),
        "warning diagnostic was double-prefixed:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn undefined_suppress_mode_links_silently() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-suppress.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out_path = scratch("missing-suppress.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("suppress")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined suppress should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("undefined symbol: _missing"),
        "expected -undefined suppress to omit undefined diagnostic:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn trace_flag_prints_loaded_inputs_and_archive_members() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("trace-main.o");
    let helper_obj = scratch("trace-helper.o");
    let archive_path = scratch("libtracehelpers.a");
    let out_path = scratch("trace.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(main_src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(helper_src, &helper_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = archive(&[&helper_obj], &archive_path) {
        eprintln!("skipping: archive failed: {e}");
        let _ = fs::remove_file(main_obj);
        let _ = fs::remove_file(helper_obj);
        return;
    }

    let out = Command::new(exe)
        .arg("-t")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&archive_path)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "trace link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("afs-ld: loading {}", main_obj.display())),
        "missing main object trace:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("afs-ld: loading {}", archive_path.display())),
        "missing archive trace:\n{stderr}"
    );
    assert!(
        stderr.contains("libtracehelpers.a("),
        "missing fetched archive member trace:\n{stderr}"
    );

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(archive_path);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_root_entry_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-root-main.o");
    let out_path = scratch("why-live-root.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_main")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_main is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_transitive_symbol_chain() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-main.o");
    let helper_obj = scratch("why-live-helper.o");
    let leaf_obj = scratch("why-live-leaf.o");
    let out_path = scratch("why-live.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            bl _leaf
            ret
        .subsections_via_symbols
    "#;
    let leaf_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _leaf
        _leaf:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(main_src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(helper_src, &helper_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        return;
    }
    if let Err(e) = assemble(leaf_src, &leaf_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        let _ = fs::remove_file(helper_obj);
        return;
    }

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_leaf")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&helper_obj)
        .arg(&leaf_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_leaf is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_leaf is reachable from _helper"));
    assert!(stdout.contains("_helper is reachable from _main"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(leaf_obj);
    let _ = fs::remove_file(out_path);
}
