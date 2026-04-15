//! Sprint 5 real-world gate: build a tiny dylib with `clang`, parse it via
//! `DylibFile`, and confirm:
//!
//! - `install_name` is what `-install_name` requested;
//! - the exported symbol surfaces in the trie;
//! - at least one `LC_LOAD_DYLIB` dependency is present (every clang-linked
//!   dylib picks up libSystem).
//!
//! Skipped if `xcrun clang` isn't available or fails for any reason.

use std::path::PathBuf;
use std::process::Command;

use afs_ld::macho::dylib::DylibFile;
use afs_ld::macho::exports::ExportKind;

fn build_test_dylib(src: &str, out: &PathBuf) -> Result<(), String> {
    let mut child = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "clang",
            "-x",
            "c",
            "-arch",
            "arm64",
            "-shared",
            "-o",
        ])
        .arg(out)
        .arg("-install_name")
        .arg("@rpath/libafsldtest.dylib")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(src.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "clang failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[test]
fn small_clang_dylib_parses_and_exports_function() {
    let which = Command::new("xcrun").arg("-f").arg("clang").output();
    if !matches!(which, Ok(o) if o.status.success()) {
        eprintln!("skipping: xcrun clang unavailable");
        return;
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let out_path = std::env::temp_dir().join(format!(
        "afs-ld-dylib-{}-{}.dylib",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let src = r#"
        int afsld_answer(int x) { return x + 42; }
    "#;
    if let Err(e) = build_test_dylib(src, &out_path) {
        eprintln!("skipping: clang could not build test dylib: {e}");
        return;
    }

    let bytes = std::fs::read(&out_path).expect("read test dylib");
    let dy = DylibFile::parse(&out_path, &bytes).expect("parse test dylib");

    assert_eq!(dy.install_name, "@rpath/libafsldtest.dylib");

    // clang-linked dylibs pull libSystem in as a Normal dependency.
    assert!(
        dy.dependencies
            .iter()
            .any(|d| d.install_name.contains("libSystem")),
        "expected a libSystem dependency; got {:?}",
        dy.dependencies
    );

    let entries = dy.exports.entries().expect("decode exports");
    let name = "_afsld_answer";
    let found = entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
        let exported: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        panic!("expected {name} in exports; got {exported:?}")
    });
    assert!(matches!(found.kind, ExportKind::Regular { .. }));

    let _ = std::fs::remove_file(&out_path);
}
