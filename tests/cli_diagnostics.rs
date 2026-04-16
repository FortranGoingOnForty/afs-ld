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
