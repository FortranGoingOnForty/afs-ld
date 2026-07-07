//! Audit L8: the ELF readers must reject malformed or truncated input with a
//! diagnostic, never panic on an out-of-bounds slice. Before the fix,
//! `parse_shared` silently substituted a 24-byte stride for a zero `.dynsym`
//! entsize and indexed `&bytes[..]` with unchecked section offsets/sizes; a
//! crafted (or corrupt) `.so` would panic the linker instead of erroring.

use afs_ld::elf::{parse_rel, parse_shared};

const ET_REL: u16 = 1;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;

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

/// A well-formed minimal shared object: null / .dynstr / .dynsym, exporting
/// one global function `foo`. Mutating a single field of a clone drives each
/// malformed case, so the failures are attributable to that field alone.
fn valid_so() -> Vec<u8> {
    // 64 header + 3*64 section headers + 5 dynstr + 48 dynsym = 312 bytes.
    let dynstr_off = 256usize;
    let dynsym_off = 264usize;
    let mut b = vec![0u8; dynsym_off + 48];
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
    w64(&mut b, sh(1) + 24, dynstr_off as u64);
    w64(&mut b, sh(1) + 32, 5); // size

    // SH[2] = .dynsym, linked to .dynstr (section 1)
    w32(&mut b, sh(2) + 4, SHT_DYNSYM);
    w64(&mut b, sh(2) + 24, dynsym_off as u64);
    w64(&mut b, sh(2) + 32, 48); // size = 2 * 24
    w32(&mut b, sh(2) + 40, 1); // sh_link -> .dynstr
    w64(&mut b, sh(2) + 56, 24); // sh_entsize

    // .dynstr: "\0foo\0"
    b[dynstr_off + 1..dynstr_off + 4].copy_from_slice(b"foo");

    // .dynsym[1] = global func foo (entry 0 is the null symbol)
    let e = dynsym_off + 24;
    w32(&mut b, e, 1); // st_name -> "foo"
    b[e + 4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
    w16(&mut b, e + 6, 1); // st_shndx = defined (non-UNDEF)
    w64(&mut b, e + 8, 0x1000); // st_value
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
