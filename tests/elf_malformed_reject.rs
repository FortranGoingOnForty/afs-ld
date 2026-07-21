//! Audit L8: the ELF readers must reject malformed or truncated input with a
//! diagnostic, never panic on an out-of-bounds slice. Before the fix,
//! `parse_shared` silently substituted a 24-byte stride for a zero `.dynsym`
//! entsize and indexed `&bytes[..]` with unchecked section offsets/sizes; a
//! crafted (or corrupt) `.so` would panic the linker instead of erroring.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use afs_ld::elf::{link_dynamic_exec, link_static_exec, parse_rel, parse_shared};

const ET_REL: u16 = 1;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;
const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;
const R_X86_64_PLT32: u32 = 4;
const VALID_SO_DYNSTR_OFF: usize = 256;
const VALID_SO_DYNSYM_OFF: usize = 264;
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Offset of section header `i` within a file whose section table starts at 64.
fn sh(i: usize) -> usize {
    64 + i * 64
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn temp_path(label: &str) -> PathBuf {
    let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "afs_ld_elf_input_{}_{}_{}",
        std::process::id(),
        label,
        id
    ))
}

fn section_name_offset(table: &[u8], name: &[u8]) -> u32 {
    table
        .windows(name.len())
        .position(|candidate| candidate == name)
        .expect("section name must be present") as u32
}

struct RelocFixture {
    bytes: Vec<u8>,
    symtab_header: usize,
    rela_header: usize,
    rela_entry: usize,
}

/// A complete ET_REL object with one call relocation from `_start` to
/// `target`. Tests vary one relocation-related field at a time.
fn valid_relocatable() -> RelocFixture {
    let shstr = b"\0.shstrtab\0.strtab\0.symtab\0.text\0.rela.text\0";
    let strtab = b"\0_start\0target\0";
    let shstr_off = sh(6);
    let strtab_off = shstr_off + shstr.len();
    let symtab_off = align_up(strtab_off + strtab.len(), 8);
    let text_off = align_up(symtab_off + 3 * 24, 16);
    let rela_off = align_up(text_off + 6, 8);
    let mut b = vec![0u8; rela_off + 24];

    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    w16(&mut b, 16, ET_REL);
    w16(&mut b, 18, EM_X86_64);
    w64(&mut b, 40, 64);
    w16(&mut b, 52, 64);
    w16(&mut b, 58, 64);
    w16(&mut b, 60, 6);
    w16(&mut b, 62, 1);

    b[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
    b[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);

    // SH[1] = .shstrtab
    w32(&mut b, sh(1), section_name_offset(shstr, b".shstrtab"));
    w32(&mut b, sh(1) + 4, SHT_STRTAB);
    w64(&mut b, sh(1) + 24, shstr_off as u64);
    w64(&mut b, sh(1) + 32, shstr.len() as u64);
    w64(&mut b, sh(1) + 48, 1);

    // SH[2] = .strtab
    w32(&mut b, sh(2), section_name_offset(shstr, b".strtab"));
    w32(&mut b, sh(2) + 4, SHT_STRTAB);
    w64(&mut b, sh(2) + 24, strtab_off as u64);
    w64(&mut b, sh(2) + 32, strtab.len() as u64);
    w64(&mut b, sh(2) + 48, 1);

    // SH[3] = .symtab
    w32(&mut b, sh(3), section_name_offset(shstr, b".symtab"));
    w32(&mut b, sh(3) + 4, SHT_SYMTAB);
    w64(&mut b, sh(3) + 24, symtab_off as u64);
    w64(&mut b, sh(3) + 32, (3 * 24) as u64);
    w32(&mut b, sh(3) + 40, 2);
    w32(&mut b, sh(3) + 44, 1);
    w64(&mut b, sh(3) + 48, 8);
    w64(&mut b, sh(3) + 56, 24);

    // SH[4] = .text
    w32(&mut b, sh(4), section_name_offset(shstr, b".text"));
    w32(&mut b, sh(4) + 4, SHT_PROGBITS);
    w64(&mut b, sh(4) + 8, SHF_ALLOC | SHF_EXECINSTR);
    w64(&mut b, sh(4) + 24, text_off as u64);
    w64(&mut b, sh(4) + 32, 6);
    w64(&mut b, sh(4) + 48, 16);

    // SH[5] = .rela.text
    w32(&mut b, sh(5), section_name_offset(shstr, b".rela.text"));
    w32(&mut b, sh(5) + 4, SHT_RELA);
    w64(&mut b, sh(5) + 24, rela_off as u64);
    w64(&mut b, sh(5) + 32, 24);
    w32(&mut b, sh(5) + 40, 3);
    w32(&mut b, sh(5) + 44, 4);
    w64(&mut b, sh(5) + 48, 8);
    w64(&mut b, sh(5) + 56, 24);

    // .symtab[1] = global function `_start` at .text+0.
    let start = symtab_off + 24;
    w32(&mut b, start, 1);
    b[start + 4] = (1 << 4) | 2;
    w16(&mut b, start + 6, 4);
    w64(&mut b, start + 16, 5);

    // .symtab[2] = global function `target` at .text+5.
    let target = symtab_off + 48;
    w32(&mut b, target, 8);
    b[target + 4] = (1 << 4) | 2;
    w16(&mut b, target + 6, 4);
    w64(&mut b, target + 8, 5);
    w64(&mut b, target + 16, 1);

    b[text_off..text_off + 6].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xc3]);
    w64(&mut b, rela_off, 1);
    w64(&mut b, rela_off + 8, ((2u64) << 32) | R_X86_64_PLT32 as u64);
    w64(&mut b, rela_off + 16, (-4i64) as u64);

    RelocFixture {
        bytes: b,
        symtab_header: sh(3),
        rela_header: sh(5),
        rela_entry: rela_off,
    }
}

fn assert_error_contains(error: impl std::fmt::Display, expected: &[&str]) {
    let message = error.to_string();
    for token in expected {
        assert!(message.contains(token), "expected {token:?} in {message:?}");
    }
}

fn write_fixture(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write ELF fixture");
}

/// A well-formed minimal shared object: null / .dynstr / .dynsym, exporting
/// one global function `foo`. Mutating a single field of a clone drives each
/// malformed case, so the failures are attributable to that field alone.
fn valid_so() -> Vec<u8> {
    // 64 header + 3*64 section headers + 5 dynstr + 48 dynsym = 312 bytes.
    let mut b = vec![0u8; VALID_SO_DYNSYM_OFF + 48];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // ELFDATA2LSB
    w16(&mut b, 16, ET_DYN);
    w16(&mut b, 18, EM_X86_64);
    w64(&mut b, 40, 64); // e_shoff
    w16(&mut b, 58, 64); // e_shentsize
    w16(&mut b, 60, 3); // e_shnum
    w16(&mut b, 62, 1); // e_shstrndx (unused by parse_shared; kept in range)

    // SH[1] = .dynstr
    w32(&mut b, sh(1) + 4, SHT_STRTAB);
    w64(&mut b, sh(1) + 24, VALID_SO_DYNSTR_OFF as u64);
    w64(&mut b, sh(1) + 32, 5); // size

    // SH[2] = .dynsym, linked to .dynstr (section 1)
    w32(&mut b, sh(2) + 4, SHT_DYNSYM);
    w64(&mut b, sh(2) + 24, VALID_SO_DYNSYM_OFF as u64);
    w64(&mut b, sh(2) + 32, 48); // size = 2 * 24
    w32(&mut b, sh(2) + 40, 1); // sh_link -> .dynstr
    w64(&mut b, sh(2) + 56, 24); // sh_entsize

    // .dynstr: "\0foo\0"
    b[VALID_SO_DYNSTR_OFF + 1..VALID_SO_DYNSTR_OFF + 4].copy_from_slice(b"foo");

    // .dynsym[1] = global func foo (entry 0 is the null symbol)
    let e = VALID_SO_DYNSYM_OFF + 24;
    w32(&mut b, e, 1); // st_name -> "foo"
    b[e + 4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
    w16(&mut b, e + 6, 1); // st_shndx = defined (non-UNDEF)
    w64(&mut b, e + 8, 0x1000); // st_value
    b
}

/// A relocatable object with null / .shstrtab / .strtab / .symtab. The second
/// symtab entry deliberately has st_name=255 against an 8-byte .strtab.
fn relocatable_with_bad_sym_name() -> Vec<u8> {
    let shstr = b"\0.shstrtab\0.strtab\0.symtab\0";
    let shstr_off = sh(4);
    let strtab_off = shstr_off + shstr.len();
    let symtab_off = strtab_off + 8;
    let mut b = vec![0u8; symtab_off + 48];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    w16(&mut b, 16, ET_REL);
    w16(&mut b, 18, EM_X86_64);
    w64(&mut b, 40, 64);
    w16(&mut b, 58, 64);
    w16(&mut b, 60, 4);
    w16(&mut b, 62, 1);

    b[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // SH[1] = .shstrtab
    w32(&mut b, sh(1), 1);
    w32(&mut b, sh(1) + 4, SHT_STRTAB);
    w64(&mut b, sh(1) + 24, shstr_off as u64);
    w64(&mut b, sh(1) + 32, shstr.len() as u64);

    // SH[2] = .strtab, only 8 bytes long.
    w32(&mut b, sh(2), 11);
    w32(&mut b, sh(2) + 4, SHT_STRTAB);
    w64(&mut b, sh(2) + 24, strtab_off as u64);
    w64(&mut b, sh(2) + 32, 8);

    // SH[3] = .symtab, linked to .strtab.
    w32(&mut b, sh(3), 19);
    w32(&mut b, sh(3) + 4, SHT_SYMTAB);
    w64(&mut b, sh(3) + 24, symtab_off as u64);
    w64(&mut b, sh(3) + 32, 48);
    w32(&mut b, sh(3) + 40, 2);
    w64(&mut b, sh(3) + 56, 24);

    b[strtab_off + 1..strtab_off + 3].copy_from_slice(b"ok");
    w32(&mut b, symtab_off + 24, 255);
    b
}

#[test]
fn valid_shared_object_parses() {
    let lib = parse_shared("good.so", &valid_so()).expect("skeleton must parse");
    assert!(lib.exports.contains_key("foo"), "foo should export");
}

#[test]
fn shared_object_section_table_out_of_range_errors() {
    let mut b = valid_so();
    w64(&mut b, 40, 0xffff_0000); // e_shoff past EOF
    let e = parse_shared("bad.so", &b).unwrap_err();
    assert!(format!("{e:?}").contains("out of range"), "got {e:?}");
}

#[test]
fn shared_object_zero_dynsym_entsize_errors() {
    // The exact silent-fallback the audit named: entsize 0 used to become 24.
    let mut b = valid_so();
    w64(&mut b, sh(2) + 56, 0);
    let e = parse_shared("bad.so", &b).unwrap_err();
    assert!(format!("{e:?}").contains("entry size"), "got {e:?}");
}

#[test]
fn shared_object_dynsym_link_out_of_range_errors() {
    let mut b = valid_so();
    w32(&mut b, sh(2) + 40, 99); // sh_link beyond shnum
    let e = parse_shared("bad.so", &b).unwrap_err();
    assert!(format!("{e:?}").contains("out of range"), "got {e:?}");
}

#[test]
fn shared_object_dynsym_data_past_eof_errors() {
    let mut b = valid_so();
    w64(&mut b, sh(2) + 24, 0xffff_0000); // .dynsym offset past EOF
    let e = parse_shared("bad.so", &b).unwrap_err();
    assert!(format!("{e:?}").contains("out of range"), "got {e:?}");
}

#[test]
fn shared_object_dynstr_data_past_eof_errors() {
    let mut b = valid_so();
    w64(&mut b, sh(1) + 24, 0xffff_0000); // .dynstr offset past EOF
    let e = parse_shared("bad.so", &b).unwrap_err();
    assert!(format!("{e:?}").contains("out of range"), "got {e:?}");
}

#[test]
fn shared_object_dynsym_name_past_dynstr_errors() {
    let mut b = valid_so();
    w32(&mut b, VALID_SO_DYNSYM_OFF + 24, 255);
    let e = parse_shared("bad.so", &b).unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains(".dynstr") && msg.contains("out of range"),
        "got {msg}"
    );
}

#[test]
fn truncated_shared_object_errors() {
    let full = valid_so();
    // Any prefix shorter than the section table must fail cleanly, not panic.
    for cut in [64usize, 100, 200, 260, full.len() - 1] {
        let e = parse_shared("trunc.so", &full[..cut]);
        assert!(e.is_err(), "prefix of {cut} bytes must be rejected");
    }
}

/// The parse_rel L8 guards mirror parse_shared: a relocatable object with a
/// section table past EOF must error rather than index out of bounds.
#[test]
fn relocatable_section_table_out_of_range_errors() {
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    w16(&mut b, 16, ET_REL);
    w16(&mut b, 18, EM_X86_64);
    w64(&mut b, 40, 0xffff_0000); // e_shoff past EOF
    w16(&mut b, 58, 64);
    w16(&mut b, 60, 4); // e_shnum
    w16(&mut b, 62, 1); // e_shstrndx
    let e = parse_rel("bad.o", &b).unwrap_err();
    assert!(format!("{e:?}").contains("out of range"), "got {e:?}");
}

#[test]
fn relocatable_symbol_name_past_strtab_errors() {
    let e = parse_rel("bad.o", &relocatable_with_bad_sym_name()).unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains(".strtab") && msg.contains("out of range"),
        "got {msg}"
    );
}

#[test]
fn valid_relocation_parses_and_links() {
    let fixture = valid_relocatable();
    let object = parse_rel("good.o", &fixture.bytes).expect("valid object must parse");
    link_static_exec(std::slice::from_ref(&object), "_start", false).expect("valid static link");
    link_dynamic_exec(
        std::slice::from_ref(&object),
        &[],
        "_start",
        "/nonexistent/ld.so",
        false,
    )
    .expect("valid dynamic link");
}

#[test]
fn relocation_symbol_index_out_of_range_errors() {
    let mut fixture = valid_relocatable();
    w64(
        &mut fixture.bytes,
        fixture.rela_entry + 8,
        ((u32::MAX as u64) << 32) | R_X86_64_PLT32 as u64,
    );
    let error = parse_rel("bad-symbol.o", &fixture.bytes).unwrap_err();
    assert_error_contains(error, &["bad-symbol.o", ".text", "relocation 0", "r_sym"]);
}

#[test]
fn relocation_target_index_out_of_range_errors() {
    let mut fixture = valid_relocatable();
    w32(&mut fixture.bytes, fixture.rela_header + 44, 6);
    let error = parse_rel("bad-target.o", &fixture.bytes).unwrap_err();
    assert_error_contains(error, &["bad-target.o", ".rela.text", "target", "index 6"]);
}

#[test]
fn relocation_symbol_table_link_out_of_range_errors() {
    let mut fixture = valid_relocatable();
    w32(&mut fixture.bytes, fixture.rela_header + 40, 99);
    let error = parse_rel("bad-link.o", &fixture.bytes).unwrap_err();
    assert_error_contains(error, &["bad-link.o", ".rela.text", "symbol table", "99"]);
}

#[test]
fn relocation_entry_size_too_small_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.rela_header + 56, 16);
    let error = parse_rel("bad-entsize.o", &fixture.bytes).unwrap_err();
    assert_error_contains(error, &["bad-entsize.o", ".rela.text", "entry size", "16"]);
}

#[test]
fn symbol_entry_size_too_small_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.symtab_header + 56, 16);
    let error = parse_rel("bad-sym-entsize.o", &fixture.bytes).unwrap_err();
    assert_error_contains(error, &["bad-sym-entsize.o", ".symtab", "entry size", "16"]);
}

#[test]
fn symbol_table_size_not_multiple_of_entry_size_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.symtab_header + 32, 73);
    let error = parse_rel("bad-sym-size.o", &fixture.bytes).unwrap_err();
    assert_error_contains(
        error,
        &["bad-sym-size.o", ".symtab", "size 73", "entry size 24"],
    );
}

#[test]
fn relocation_table_size_not_multiple_of_entry_size_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.rela_header + 32, 25);
    let error = parse_rel("bad-rela-size.o", &fixture.bytes).unwrap_err();
    assert_error_contains(
        error,
        &["bad-rela-size.o", ".rela.text", "size 25", "entry size 24"],
    );
}

#[test]
fn relocation_offset_out_of_range_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.rela_entry, 0x10_0000);
    let error = parse_rel("bad-offset.o", &fixture.bytes).unwrap_err();
    assert_error_contains(
        error,
        &["bad-offset.o", ".text", "relocation 0", "r_offset"],
    );
}

#[test]
fn relocation_write_crossing_section_end_errors() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, fixture.rela_entry, 3);
    let error = parse_rel("crossing-offset.o", &fixture.bytes).unwrap_err();
    assert_error_contains(
        error,
        &["crossing-offset.o", ".text", "relocation 0", "r_offset"],
    );
}

#[test]
fn relocations_for_unretained_targets_are_still_validated() {
    let mut fixture = valid_relocatable();
    w64(&mut fixture.bytes, sh(4) + 8, 0);
    w64(
        &mut fixture.bytes,
        fixture.rela_entry + 8,
        ((u32::MAX as u64) << 32) | R_X86_64_PLT32 as u64,
    );
    let error = parse_rel("dropped-target.o", &fixture.bytes).unwrap_err();
    assert_error_contains(
        error,
        &["dropped-target.o", ".text", "relocation 0", "r_sym"],
    );
}

fn assert_direct_link_rejects(object: afs_ld::elf::ElfObject, field: &str) {
    let static_error = link_static_exec(std::slice::from_ref(&object), "_start", false)
        .expect_err("static link must reject invalid relocation metadata");
    assert_error_contains(static_error, &["direct.o", ".text", "relocation 0", field]);

    let dynamic_error = link_dynamic_exec(
        std::slice::from_ref(&object),
        &[],
        "_start",
        "/nonexistent/ld.so",
        false,
    )
    .expect_err("dynamic link must reject invalid relocation metadata");
    assert_error_contains(dynamic_error, &["direct.o", ".text", "relocation 0", field]);
}

#[test]
fn direct_link_apis_reject_invalid_relocation_symbol_index() {
    let fixture = valid_relocatable();
    let mut object = parse_rel("direct.o", &fixture.bytes).expect("valid object must parse");
    object.sections[0].relas[0].sym = u32::MAX;
    assert_direct_link_rejects(object, "r_sym");
}

#[test]
fn direct_link_apis_reject_invalid_relocation_offset() {
    let fixture = valid_relocatable();
    let mut object = parse_rel("direct.o", &fixture.bytes).expect("valid object must parse");
    object.sections[0].relas[0].offset = 0x10_0000;
    assert_direct_link_rejects(object, "r_offset");
}

#[test]
fn direct_link_apis_reject_invalid_symbol_section_index() {
    let fixture = valid_relocatable();
    let mut object = parse_rel("direct.o", &fixture.bytes).expect("valid object must parse");
    object.symbols[1].section = Some(usize::MAX);

    let static_error = link_static_exec(std::slice::from_ref(&object), "_start", false)
        .expect_err("static link must reject invalid symbol metadata");
    assert_error_contains(
        static_error,
        &[
            "direct.o",
            "symbol 1",
            "section index",
            &usize::MAX.to_string(),
        ],
    );

    let dynamic_error = link_dynamic_exec(
        std::slice::from_ref(&object),
        &[],
        "_start",
        "/nonexistent/ld.so",
        false,
    )
    .expect_err("dynamic link must reject invalid symbol metadata");
    assert_error_contains(
        dynamic_error,
        &[
            "direct.o",
            "symbol 1",
            "section index",
            &usize::MAX.to_string(),
        ],
    );
}

#[test]
fn cli_rejects_malformed_relocations_deterministically() {
    let bad_symbol = {
        let mut fixture = valid_relocatable();
        w64(
            &mut fixture.bytes,
            fixture.rela_entry + 8,
            ((u32::MAX as u64) << 32) | R_X86_64_PLT32 as u64,
        );
        fixture.bytes
    };
    let bad_offset = {
        let mut fixture = valid_relocatable();
        w64(&mut fixture.bytes, fixture.rela_entry, 0x10_0000);
        fixture.bytes
    };
    let bad_target = {
        let mut fixture = valid_relocatable();
        w32(&mut fixture.bytes, fixture.rela_header + 44, 6);
        fixture.bytes
    };

    let cases = [
        (
            "bad_symbol",
            bad_symbol,
            &[".text", "relocation 0", "r_sym"] as &[&str],
        ),
        (
            "bad_offset",
            bad_offset,
            &[".text", "relocation 0", "r_offset"],
        ),
        (
            "bad_target",
            bad_target,
            &[".rela.text", "target", "index 6"],
        ),
    ];

    for (label, bytes, expected) in cases {
        let input = temp_path(&format!("{label}.o"));
        write_fixture(&input, &bytes);

        for dynamic in [false, true] {
            let mode = if dynamic { "dynamic" } else { "static" };
            let output = temp_path(&format!("{label}_{mode}.out"));
            let run = || {
                let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
                command
                    .arg("-o")
                    .arg(&output)
                    .arg(&input)
                    .env("RUST_BACKTRACE", "1");
                if dynamic {
                    command.args(["--dynamic-linker", "/nonexistent/ld.so"]);
                }
                command.output().expect("run afs-ld")
            };

            let first = run();
            assert_eq!(
                first.status.code(),
                Some(1),
                "{label} {mode} status; stderr: {}",
                String::from_utf8_lossy(&first.stderr)
            );
            assert!(!output.exists(), "{label} {mode} created output");

            let second = run();
            assert_eq!(
                second.status.code(),
                Some(1),
                "{label} {mode} repeat status; stderr: {}",
                String::from_utf8_lossy(&second.stderr)
            );
            assert!(!output.exists(), "{label} {mode} repeat created output");
            assert_eq!(
                first.stderr, second.stderr,
                "{label} {mode} diagnostic changed between runs"
            );

            let stderr = String::from_utf8_lossy(&first.stderr);
            assert!(
                stderr.contains(&input.display().to_string()),
                "{label} {mode} diagnostic omitted input path: {stderr}"
            );
            for token in expected {
                assert!(
                    stderr.contains(token),
                    "{label} {mode} diagnostic omitted {token:?}: {stderr}"
                );
            }
            let lowercase = stderr.to_ascii_lowercase();
            assert!(
                !lowercase.contains("panic") && !lowercase.contains("backtrace"),
                "{label} {mode} exposed a panic/backtrace: {stderr}"
            );
        }

        std::fs::remove_file(input).expect("remove ELF fixture");
    }
}
