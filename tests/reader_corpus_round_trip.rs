//! Sprint 1 corpus gate.
//!
//! Assembles every `afs-as/tests/corpus/*.s` fixture with `xcrun as`, parses
//! the resulting Mach-O with our reader, re-emits the header + load-command
//! region, and asserts byte-level equality. Proves the reader lost no bits
//! decoding the load commands afs-as emits in practice.
//!
//! Section bodies, symbols, strings, and relocations are still untouched by
//! Sprint 1; we only round-trip the header + `sizeofcmds` region.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afs_ld::macho::reader::{parse_commands, parse_header, write_commands, write_header, HEADER_SIZE};

fn corpus_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is afs-ld/; afs-as is a sibling submodule in armfortas.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("afs-as")
        .join("tests")
        .join("corpus")
}

fn assemble(src: &Path, obj: &Path) -> Result<(), String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(src)
        .arg("-o")
        .arg(obj)
        .output()
        .map_err(|e| format!("failed to spawn xcrun: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "xcrun as failed on {}: {}",
            src.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[test]
fn every_afs_as_corpus_s_round_trips() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!(
            "skipping: corpus not found at {} (run from the armfortas workspace)",
            corpus.display()
        );
        return;
    }

    let which = Command::new("xcrun").arg("-f").arg("as").output();
    if !matches!(which, Ok(o) if o.status.success()) {
        eprintln!("skipping: xcrun as not available");
        return;
    }

    let scratch = tempdir();
    let mut fixture_count = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let mut entries: Vec<PathBuf> = fs::read_dir(&corpus)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "s").unwrap_or(false))
        .collect();
    entries.sort();

    for src in entries {
        fixture_count += 1;
        let obj_name = format!(
            "{}.o",
            src.file_stem().and_then(|s| s.to_str()).unwrap_or("fixture")
        );
        let obj = scratch.join(&obj_name);

        if let Err(e) = assemble(&src, &obj) {
            failures.push(format!("{}: assemble failed: {e}", src.display()));
            continue;
        }

        let bytes = match fs::read(&obj) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: read-back failed: {e}", src.display()));
                continue;
            }
        };

        let hdr = match parse_header(&bytes) {
            Ok(h) => h,
            Err(e) => {
                failures.push(format!("{}: parse_header: {e}", src.display()));
                continue;
            }
        };

        let cmds = match parse_commands(&hdr, &bytes) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("{}: parse_commands: {e}", src.display()));
                continue;
            }
        };

        let mut out = Vec::with_capacity(HEADER_SIZE + hdr.sizeofcmds as usize);
        write_header(&hdr, &mut out);
        write_commands(&cmds, &mut out);

        let cmds_end = HEADER_SIZE + hdr.sizeofcmds as usize;
        if out.as_slice() != &bytes[..cmds_end] {
            let delta = first_diff(&out, &bytes[..cmds_end]);
            failures.push(format!(
                "{}: re-emit mismatch at offset 0x{delta:x}",
                src.display()
            ));
        }
    }

    assert!(fixture_count > 0, "no .s fixtures found in {}", corpus.display());
    assert!(
        failures.is_empty(),
        "{} of {} corpus fixtures failed:\n{}",
        failures.len(),
        fixture_count,
        failures.join("\n")
    );
}

fn first_diff(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()))
}

fn tempdir() -> PathBuf {
    let base = std::env::temp_dir().join(format!("afs-ld-corpus-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("create scratch dir");
    base
}
