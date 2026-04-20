use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
    assert!(stdout.contains("Usage: afs-ld [options] <inputs...>"));
    assert!(stdout.contains("-map <path>"));
    assert!(stdout.contains("-t, -trace"));
    assert!(stdout.contains("-v, --version"));
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
    assert_eq!(stdout.trim(), format!("afs-ld {}", env!("CARGO_PKG_VERSION")));
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
