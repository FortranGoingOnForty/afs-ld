//! Sprint 8 gate: exercise the full resolution pipeline against real
//! Mach-O inputs produced by `xcrun as` / `ar`.
//!
//! The scenarios:
//!
//!   1. Two objects with a cross-reference. Seeding alone resolves the
//!      inner reference — no fetch required.
//!
//!   2. One archive whose member defines a symbol the second object
//!      references. Seeding creates a `LazyArchive` slot; the second
//!      object's `Undefined` insertion triggers `PendingArchiveFetch`;
//!      `drain_fetches` pulls the member and seeds it.
//!
//!   3. One deliberately-missing symbol. Classification surfaces it as
//!      an error under the default `-undefined` treatment, and the
//!      formatted diagnostic contains a `referenced by` line and a
//!      did-you-mean hint for a near-misspelling of an existing name.
//!
//! Skipped if `xcrun` or `ar` aren't available on PATH.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use afs_ld::resolve::{
    classify_unresolved, drain_fetches, format_undefined_diagnostic, seed_all, Inputs, Symbol,
    SymbolTable, UndefinedTreatment,
};

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_ar() -> bool {
    Command::new("ar")
        .arg("-V")
        .output()
        .map(|_| true)
        .unwrap_or(false)
        || Command::new("xcrun")
            .args(["--sdk", "macosx", "-f", "ar"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

fn assemble(src_text: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-resolve-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src_text).map_err(|e| format!("write .s: {e}"))?;
    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }
    let _ = fs::remove_file(&tmp);
    Ok(())
}

fn pack_archive(members: &[&PathBuf], out: &PathBuf) -> Result<(), String> {
    let _ = fs::remove_file(out);
    let status = Command::new("ar")
        .arg("rcs")
        .arg(out)
        .args(members)
        .output()
        .map_err(|e| format!("spawn ar: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "ar rcs failed: {}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }
    Ok(())
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-resolve-{}-{}", std::process::id(), name))
}

#[test]
fn resolve_pipeline_pulls_archive_member_and_flags_missing() {
    if !have_xcrun() || !have_ar() {
        eprintln!("skipping: xcrun as / ar unavailable");
        return;
    }

    // Object A: defines `_main`, references `_helper` (in B), `_archive_sym`
    // (in archive), and `_missing` (nowhere).
    let a_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            bl _archive_sym
            bl _missing
            ret
    "#;
    // Object B: defines `_helper`.
    let b_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
    "#;
    // Object C (archive member): defines `_archive_sym`.
    let c_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _archive_sym
        _archive_sym:
            ret
    "#;

    let a_o = scratch("a.o");
    let b_o = scratch("b.o");
    let c_o = scratch("c.o");
    let libtest = scratch("libtest.a");

    for (src, out) in [(a_src, &a_o), (b_src, &b_o), (c_src, &c_o)] {
        if let Err(e) = assemble(src, out) {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    }
    if let Err(e) = pack_archive(&[&c_o], &libtest) {
        eprintln!("skipping: archive build failed: {e}");
        return;
    }

    // Register the inputs with the resolver.
    let mut inputs = Inputs::new();
    let a_id = inputs
        .add_object(a_o.clone(), fs::read(&a_o).unwrap(), 0)
        .unwrap();
    inputs
        .add_object(b_o.clone(), fs::read(&b_o).unwrap(), 1)
        .unwrap();
    let archive_id = inputs
        .add_archive(libtest.clone(), fs::read(&libtest).unwrap(), 2)
        .unwrap();
    let _ = archive_id;

    // Seed + drain + classify.
    let mut table = SymbolTable::new();
    let seed_report = seed_all(&inputs, &mut table).expect("seed_all");
    assert!(
        seed_report.duplicates.is_empty(),
        "unexpected duplicates in seeding: {:?}",
        seed_report.duplicates
    );
    let drain_report = drain_fetches(&mut inputs, &mut table, seed_report.pending_fetches, 1)
        .expect("drain_fetches");
    assert!(
        drain_report.fetched_members >= 1,
        "expected at least one archive member fetched; got {}",
        drain_report.fetched_members
    );

    // _archive_sym should now be Defined (pulled from the archive).
    let arch_sym = table.intern("_archive_sym");
    let (_, resolved) = table.resolve_chain(arch_sym).unwrap();
    assert!(
        matches!(resolved, Symbol::Defined { .. }),
        "_archive_sym should resolve to Defined after fetch; got {resolved:?}"
    );

    // _main should be Defined (from A).
    let main_sym = table.intern("_main");
    let (_, m) = table.resolve_chain(main_sym).unwrap();
    assert!(matches!(m, Symbol::Defined { .. }));

    // Classify unresolved under Error treatment.
    let classification = classify_unresolved(&mut table, UndefinedTreatment::Error);
    let missing = table.intern("_missing");
    assert!(
        classification.errors.iter().any(|u| u.name == missing),
        "_missing should surface as an error; got {:?}",
        classification.errors
    );

    // Format the diagnostic and check it carries the referrer and hints.
    let text = format_undefined_diagnostic(
        &table,
        &inputs,
        &seed_report.referrers,
        &classification.errors,
    );
    assert!(text.contains("undefined symbol: _missing"), "{text}");
    assert!(
        text.contains(&format!("referenced by {}", a_o.display())),
        "expected referrer chain to cite A's path; got:\n{text}"
    );

    // Cleanup.
    let _ = fs::remove_file(&a_o);
    let _ = fs::remove_file(&b_o);
    let _ = fs::remove_file(&c_o);
    let _ = fs::remove_file(&libtest);
    let _ = a_id; // silence unused
}

#[test]
fn levenshtein_hint_suggests_close_match() {
    use afs_ld::resolve::{did_you_mean, Symbol, SymbolTable};
    let mut t = SymbolTable::new();
    let n = t.intern("_afs_program_init");
    t.insert(Symbol::Defined {
        name: n,
        origin: afs_ld::resolve::InputId(0),
        atom: afs_ld::resolve::AtomId(0),
        value: 0,
        weak: false,
        private_extern: false,
        no_dead_strip: false,
    })
    .unwrap();
    let hints = did_you_mean(&t, "_afs_prgram_init", 3, 3);
    assert!(
        hints.iter().any(|h| h == "_afs_program_init"),
        "expected did-you-mean to suggest _afs_program_init; got {hints:?}"
    );
}
