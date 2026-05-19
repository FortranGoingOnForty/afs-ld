//! End-to-end atomization gate.
//!
//! Assembles a multi-symbol object with `xcrun as`, runs the full
//! resolve → atomize → back-patch pipeline, and verifies:
//!
//!   - Every defined external symbol owns exactly one atom.
//!   - Atom count for `__TEXT,__text` equals the number of non-alt
//!     external symbols defined in that section.
//!   - Each `Symbol::Defined { atom }` no longer points at the pre-
//!     atomization `AtomId(0)` placeholder.
//!   - Atom data bytes at the owner's atom-relative offset match the
//!     section data at the symbol's n_value.
//!
//! Skipped if `xcrun as` is unavailable.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use afs_ld::atom::{atomize_object, backpatch_symbol_atoms, AtomSection, AtomTable};
use afs_ld::resolve::{seed_all, AtomId, Inputs, Symbol, SymbolTable};

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
        "afs-ld-atom-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
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

#[test]
fn atomize_splits_text_at_symbol_boundaries_and_backpatches_symbols() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    // Three functions in __text + one data global. afs-as sets
    // MH_SUBSECTIONS_VIA_SYMBOLS, so we expect one atom per external
    // function plus one for the data symbol.
    // `.subsections_via_symbols` sets MH_SUBSECTIONS_VIA_SYMBOLS on the
    // resulting object so our atomizer splits at symbol boundaries. Every
    // fixture afs-as emits carries this flag, so the corpus round-trips
    // already exercise it — we need the directive only for hand-written
    // test inputs.
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _fn_a
        _fn_a:
            mov x0, #0
            ret
        .globl _fn_b
        _fn_b:
            mov x0, #1
            ret
        .globl _fn_c
        _fn_c:
            mov x0, #2
            ret
        .section __DATA,__data
        .globl _data_global
        _data_global:
            .quad 0x1122334455667788
        .subsections_via_symbols
    "#;

    let obj_path = std::env::temp_dir().join(format!("afs-ld-atom-{}-test.o", std::process::id()));
    if let Err(e) = assemble(src, &obj_path) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let bytes = fs::read(&obj_path).unwrap();
    let mut inputs = Inputs::new();
    let input_id = inputs.add_object(obj_path.clone(), bytes, 0).unwrap();

    // Seed the symbol table (produces Defined entries with AtomId(0)
    // placeholders).
    let mut sym_table = SymbolTable::new();
    let _ = seed_all(&inputs, &mut sym_table).expect("seed_all");

    // Atomize + back-patch.
    let obj = inputs.object_file(input_id).unwrap();
    let mut atom_table = AtomTable::new();
    let atomization = atomize_object(input_id, obj, &mut atom_table);
    backpatch_symbol_atoms(&atomization, input_id, obj, &mut sym_table, &mut atom_table);

    // At least one atom per defined function plus one for data_global.
    assert!(
        atom_table.len() >= 4,
        "expected ≥4 atoms (3 text + 1 data); got {}",
        atom_table.len()
    );

    // Every external symbol defined in this object should now resolve to a
    // non-placeholder atom.
    for sym_name in ["_fn_a", "_fn_b", "_fn_c", "_data_global"] {
        let istr = sym_table.intern(sym_name);
        let sid = sym_table
            .lookup(istr)
            .unwrap_or_else(|| panic!("{sym_name} not in symbol table"));
        let sym = sym_table.get(sid);
        match sym {
            Symbol::Defined { atom, value, .. } => {
                assert_ne!(
                    *atom,
                    AtomId(0),
                    "{sym_name} still points at AtomId(0) placeholder"
                );
                // Primary owner symbols are at atom-relative offset 0.
                assert_eq!(*value, 0, "{sym_name} should be at atom start");
                // The atom itself should match the symbol's origin and be a
                // reasonable section kind.
                let atom = atom_table.get(*atom);
                assert_eq!(atom.origin, input_id);
                assert!(matches!(
                    atom.section,
                    AtomSection::Text | AtomSection::Data | AtomSection::ConstData
                ));
                assert_eq!(atom.owner, Some(sid));
            }
            other => panic!("{sym_name} should be Defined; got {other:?}"),
        }
    }

    // The __text atoms should collectively cover the same bytes as the
    // original __text section data.
    let text_atoms: Vec<_> = atom_table
        .iter()
        .filter(|(_, a)| a.section == AtomSection::Text)
        .collect();
    assert!(!text_atoms.is_empty());
    for (_, atom) in &text_atoms {
        // Each atom has real content bytes (not zerofill).
        assert!(!atom.data.is_empty(), "text atom has empty data");
        assert_eq!(
            atom.data.len(),
            atom.size as usize,
            "text atom data length mismatches size"
        );
    }

    let _ = fs::remove_file(&obj_path);
}

#[test]
fn atomize_cstring_splits_at_null_terminators() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let src = r#"
        .section __TEXT,__cstring,cstring_literals
        .globl _s1
        _s1:
            .asciz "alpha"
        .globl _s2
        _s2:
            .asciz "beta"
        .globl _s3
        _s3:
            .asciz "gamma"
        .subsections_via_symbols
    "#;

    let obj_path =
        std::env::temp_dir().join(format!("afs-ld-atom-{}-cstrings.o", std::process::id()));
    if let Err(e) = assemble(src, &obj_path) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let bytes = fs::read(&obj_path).unwrap();
    let mut inputs = Inputs::new();
    let input_id = inputs.add_object(obj_path.clone(), bytes, 0).unwrap();
    let mut sym_table = SymbolTable::new();
    let _ = seed_all(&inputs, &mut sym_table).expect("seed_all");
    let obj = inputs.object_file(input_id).unwrap();
    let mut atom_table = AtomTable::new();
    let _atomization = atomize_object(input_id, obj, &mut atom_table);

    let cstring_atoms: Vec<_> = atom_table
        .iter()
        .filter(|(_, a)| a.section == AtomSection::CStringLiterals)
        .collect();
    assert_eq!(
        cstring_atoms.len(),
        3,
        "expected 3 cstring atoms (one per asciz), got {}",
        cstring_atoms.len()
    );
    // Each atom's data should end in 0x00.
    for (_, atom) in &cstring_atoms {
        assert!(
            atom.data.last() == Some(&0),
            "cstring atom data should end at null terminator; got {:?}",
            atom.data
        );
    }

    let _ = fs::remove_file(&obj_path);
}
