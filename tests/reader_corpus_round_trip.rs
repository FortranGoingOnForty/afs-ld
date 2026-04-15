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

use afs_ld::input::ObjectFile;
use afs_ld::macho::reader::{parse_commands, parse_header, write_commands, write_header, HEADER_SIZE};
use afs_ld::symbol::{write_nlist_table, NLIST_SIZE};

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

/// Sprint 2 gate: every corpus fixture must parse fully via `ObjectFile`,
/// and the nlist + string-table regions must survive a byte-level round-trip.
#[test]
fn every_afs_as_corpus_object_parses_fully() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("skipping: corpus not found at {}", corpus.display());
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
        let obj_path = scratch.join(format!(
            "{}.o",
            src.file_stem().and_then(|s| s.to_str()).unwrap_or("fixture")
        ));

        if let Err(e) = assemble(&src, &obj_path) {
            failures.push(format!("{}: assemble: {e}", src.display()));
            continue;
        }

        let bytes = match fs::read(&obj_path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: read: {e}", src.display()));
                continue;
            }
        };

        let obj = match ObjectFile::parse(&obj_path, &bytes) {
            Ok(o) => o,
            Err(e) => {
                failures.push(format!("{}: ObjectFile::parse: {e}", src.display()));
                continue;
            }
        };

        // Every symbol name must resolve via the string table.
        for (i, sym) in obj.symbols.iter().enumerate() {
            if let Err(e) = obj.symbol_name(sym) {
                failures.push(format!(
                    "{}: symbol[{i}].strx={} does not resolve: {e}",
                    src.display(),
                    sym.strx()
                ));
                break;
            }
        }

        // Section count and n_sect references — every SECT symbol should
        // reference a valid 1-based section index.
        for (i, sym) in obj.symbols.iter().enumerate() {
            if sym.stab_kind().is_some() {
                continue; // stab n_sect has a different meaning
            }
            if sym.kind() == afs_ld::symbol::SymKind::Sect
                && obj.section_for_symbol(sym).is_none()
            {
                failures.push(format!(
                    "{}: symbol[{i}] has SECT kind but n_sect={} is out of range ({} sections)",
                    src.display(),
                    sym.sect_idx(),
                    obj.sections.len()
                ));
                break;
            }
        }

        // Byte-level round-trip of the nlist region.
        if let Some(symtab) = obj.symtab {
            let mut reemitted = Vec::with_capacity(obj.symbols.len() * NLIST_SIZE);
            write_nlist_table(&obj.symbols, &mut reemitted);
            let want = &bytes
                [symtab.symoff as usize..symtab.symoff as usize + symtab.nsyms as usize * NLIST_SIZE];
            if reemitted != want {
                failures.push(format!(
                    "{}: nlist region re-emit mismatch (symoff=0x{:x} nsyms={})",
                    src.display(),
                    symtab.symoff,
                    symtab.nsyms
                ));
                continue;
            }

            // Byte-level equality of the string-table blob.
            let strtab_want = &bytes
                [symtab.stroff as usize..symtab.stroff as usize + symtab.strsize as usize];
            if obj.strings.as_bytes() != strtab_want {
                failures.push(format!(
                    "{}: strtab byte mismatch (stroff=0x{:x} strsize={})",
                    src.display(),
                    symtab.stroff,
                    symtab.strsize
                ));
            }
        }
    }

    assert!(fixture_count > 0, "no fixtures found");
    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed Sprint 2 invariants:\n{}",
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
