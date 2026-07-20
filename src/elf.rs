//! x86_64 ELF linking (x16 arc): ET_REL reader and a static ET_EXEC
//! writer. Rung 1 scope: freestanding executables from relocatable
//! objects — no libc, no dynamic section, no TLS. The reader/writer
//! discipline mirrors the Mach-O side: hand-rolled wire structs,
//! loud errors, byte-deterministic output.
//!
//! Relocation set (measured against the armfortas corpus): R_X86_64_
//! 64/32/32S/PC32/PLT32. PLT32 in a static link with the target
//! defined resolves exactly like PC32 — there is no PLT.

use std::collections::{HashMap, HashSet};

pub const EM_X86_64: u16 = 62;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
/// `.eh_frame` on x86_64 (SHF_ALLOC unwind data). gcc/clang/rustc stamp
/// it as this, not SHT_PROGBITS; the output section is emitted PROGBITS.
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;

/// Non-default (hidden) bit in a `.gnu.version` entry.
const VERSYM_HIDDEN: u16 = 0x8000;
/// Reserved `.gnu.version` indices: local symbol, and the base (global)
/// version. Assigned version indices start at 2.
const VER_NDX_GLOBAL: u16 = 1;

pub const ET_DYN: u16 = 3;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
/// `.dynamic` tag: shared-object name.
pub const DT_SONAME: i64 = 14;

/// `st_info` symbol type for an indirect (ifunc) function.
pub const STT_GNU_IFUNC: u8 = 10;

pub const R_X86_64_IRELATIVE: u32 = 37;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_TLS: u64 = 0x400;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TLSGD: u32 = 19;
pub const R_X86_64_TLSLD: u32 = 20;
pub const R_X86_64_DTPOFF32: u32 = 21;
pub const R_X86_64_GOTTPOFF: u32 = 22;
pub const R_X86_64_TPOFF32: u32 = 23;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

const PT_TLS: u32 = 7;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
/// Points the unwinder at `.eh_frame_hdr` (its binary-search table).
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;

// `.dynamic` tags used by the dynamic executable writer.
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_FLAGS: i64 = 30;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const DF_BIND_NOW: u64 = 0x8;

/// Symbols the linker itself provides, bracketing the matching output
/// section (an empty range when the section is absent). The index into
/// this slice is the pseudo symbol paired with [`LINKER_MARK`].
const LINKER_SYMS: &[&str] = &[
    "__preinit_array_start",
    "__preinit_array_end",
    "__init_array_start",
    "__init_array_end",
    "__fini_array_start",
    "__fini_array_end",
    "__rela_iplt_start",
    "__rela_iplt_end",
    "__ehdr_start",
    "_GLOBAL_OFFSET_TABLE_",
    "__bss_start",
    "_edata",
    "_end",
];
/// Sentinel object index marking a linker-provided pseudo definition;
/// the paired symbol index is an offset into [`LINKER_SYMS`].
const LINKER_MARK: usize = usize::MAX;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const BASE_VADDR: u64 = 0x400000;
const PAGE: u64 = 0x1000;

#[derive(Debug)]
pub struct ElfError(pub String);

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ElfError> {
    Err(ElfError(msg.into()))
}

/// Bounds-checked `bytes[off .. off+len]`, or a diagnostic naming the input
/// and the region. The ELF readers indexed raw section/table offsets
/// directly, so a truncated or malformed object panicked with a slice
/// out-of-bounds instead of reporting the bad file (audit L8).
fn subslice<'a>(
    bytes: &'a [u8],
    off: usize,
    len: usize,
    name: &str,
    what: &str,
) -> Result<&'a [u8], ElfError> {
    match off.checked_add(len) {
        Some(end) if end <= bytes.len() => Ok(&bytes[off..end]),
        _ => err(format!(
            "{name}: {what} out of range (offset {off:#x}, len {len:#x}, file size {:#x})",
            bytes.len()
        )),
    }
}

/// EI_OSABI byte for the ELF being produced. The kernel image activator uses
/// it to pick syscall semantics: FreeBSD wants `ELFOSABI_FREEBSD` (9), Linux
/// and generic SysV want `ELFOSABI_NONE` (0). The output runs on the host
/// afs-ld runs on, so this is a host property — but it must reflect the
/// running kernel, not the OS afs-ld was *compiled* for. On this dev box
/// afs-ld is sometimes built as a Linux binary under the FreeBSD linuxulator;
/// a compile-time `cfg!(target_os)` would then brand a FreeBSD-hosted output
/// as OSABI 0 and the native kernel would misread it. The FreeBSD run-time
/// linker `/libexec/ld-elf.so.1` is present on a FreeBSD host (native or
/// linuxulator) and absent on Linux, so it is the reliable runtime signal
/// (audit L9). Deterministic for a given host, so the byte-identical link
/// invariant holds.
fn host_osabi() -> u8 {
    if std::path::Path::new("/libexec/ld-elf.so.1").exists() {
        9 // ELFOSABI_FREEBSD
    } else {
        0 // ELFOSABI_NONE (Linux / generic SysV)
    }
}

/// Encode the 4 bytes of an absolute 32-bit relocation, erroring on overflow
/// rather than silently dropping the high bits. `R_X86_64_32` is unsigned and
/// must fit `u32`; `R_X86_64_32S` is signed and must fit `i32`. Shared by the
/// static and dynamic relocation appliers so the range checks can never drift
/// apart again — the dynamic path had lost the check and truncated silently
/// (audit L4).
fn encode_abs32(value: i64, signed: bool, p: u64) -> Result<[u8; 4], ElfError> {
    if signed {
        if value < i32::MIN as i64 || value > i32::MAX as i64 {
            return err(format!("R_X86_64_32S overflow at {:#x}", p));
        }
        Ok((value as i32).to_le_bytes())
    } else {
        if value < 0 || value > u32::MAX as i64 {
            return err(format!("R_X86_64_32 overflow at {:#x}", p));
        }
        Ok((value as u32).to_le_bytes())
    }
}

// ---- ET_REL model ----

#[derive(Debug, Clone)]
pub struct Rela {
    pub offset: u64,
    pub sym: u32,
    pub r_type: u32,
    pub addend: i64,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addralign: u64,
    pub data: Vec<u8>,
    pub nobits_size: u64,
    pub relas: Vec<Rela>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub bind: u8,
    /// `st_info & 0xf`: STT_FUNC, STT_OBJECT, STT_GNU_IFUNC, ...
    pub typ: u8,
    pub shndx: u16,
    /// Object-local section index remapped to `sections` index for
    /// ordinary sections; SHN_* specials keep their meaning via shndx.
    pub section: Option<usize>,
    pub value: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct ElfObject {
    pub name: String,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

fn ru16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn ru32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn ru64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

fn cstr(tab: &[u8], off: usize, name: &str, table: &str) -> Result<String, ElfError> {
    if off >= tab.len() {
        return err(format!(
            "{}: {} string offset {:#x} out of range (table size {:#x})",
            name,
            table,
            off,
            tab.len()
        ));
    }
    let end = tab[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(tab.len());
    Ok(String::from_utf8_lossy(&tab[off..end]).into_owned())
}

/// Parse an ET_REL object. Section indices in symbols are remapped to
/// the returned `sections` vector; RELA tables are attached to their
/// target sections with symtab indices left as-is (the `symbols` vec
/// preserves symtab order).
pub fn parse_rel(name: &str, bytes: &[u8]) -> Result<ElfObject, ElfError> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return err(format!("{}: not an ELF file", name));
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return err(format!("{}: not ELF64 little-endian", name));
    }
    if ru16(bytes, 16) != ET_REL {
        return err(format!("{}: not a relocatable object", name));
    }
    if ru16(bytes, 18) != EM_X86_64 {
        return err(format!("{}: not x86_64", name));
    }
    let shoff = ru64(bytes, 40) as usize;
    let shentsize = ru16(bytes, 58) as usize;
    let shnum = ru16(bytes, 60) as usize;
    let shstrndx = ru16(bytes, 62) as usize;
    if shoff == 0 || shnum == 0 {
        return err(format!("{}: no section headers", name));
    }
    if shentsize < 64 {
        return err(format!(
            "{}: section header entry size {} too small",
            name, shentsize
        ));
    }
    if shstrndx >= shnum {
        return err(format!(
            "{}: section-header string-table index out of range",
            name
        ));
    }
    // Validate the whole section-header table lies within the file so `sh(i)`
    // for i in 0..shnum never indexes past the end (audit L8).
    match shnum
        .checked_mul(shentsize)
        .and_then(|n| shoff.checked_add(n))
    {
        Some(end) if end <= bytes.len() => {}
        _ => return err(format!("{}: section header table out of range", name)),
    }
    let sh = |i: usize| -> &[u8] { &bytes[shoff + i * shentsize..shoff + (i + 1) * shentsize] };
    let shstr_off = ru64(sh(shstrndx), 24) as usize;
    let shstr_size = ru64(sh(shstrndx), 32) as usize;
    let shstr = subslice(
        bytes,
        shstr_off,
        shstr_size,
        name,
        "section-header string table",
    )?;

    // First pass: raw headers.
    struct Raw {
        name: String,
        sh_type: u32,
        flags: u64,
        off: usize,
        size: usize,
        link: usize,
        info: usize,
        align: u64,
        entsize: usize,
    }
    let mut raws = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let h = sh(i);
        raws.push(Raw {
            name: cstr(
                shstr,
                ru32(h, 0) as usize,
                name,
                "section-header string table",
            )?,
            sh_type: ru32(h, 4),
            flags: ru64(h, 8),
            off: ru64(h, 24) as usize,
            size: ru64(h, 32) as usize,
            link: ru32(h, 40) as usize,
            info: ru32(h, 44) as usize,
            align: ru64(h, 48).max(1),
            entsize: ru64(h, 56) as usize,
        });
    }

    // Keep ALLOC PROGBITS/NOBITS sections; remap indices.
    let mut sections = Vec::new();
    let mut remap: HashMap<usize, usize> = HashMap::new();
    for (i, r) in raws.iter().enumerate() {
        let keep = matches!(
            r.sh_type,
            SHT_PROGBITS
                | SHT_NOBITS
                | SHT_INIT_ARRAY
                | SHT_FINI_ARRAY
                | SHT_PREINIT_ARRAY
                | SHT_X86_64_UNWIND
        ) && (r.flags & SHF_ALLOC) != 0;
        if !keep {
            continue;
        }
        remap.insert(i, sections.len());
        sections.push(Section {
            name: r.name.clone(),
            sh_type: r.sh_type,
            sh_flags: r.flags,
            sh_addralign: r.align,
            data: if r.sh_type == SHT_NOBITS {
                Vec::new()
            } else {
                subslice(
                    bytes,
                    r.off,
                    r.size,
                    name,
                    &format!("section '{}' data", r.name),
                )?
                .to_vec()
            },
            nobits_size: if r.sh_type == SHT_NOBITS {
                r.size as u64
            } else {
                0
            },
            relas: Vec::new(),
        });
    }

    // Symbols.
    let mut symbols = Vec::new();
    let symtab = raws.iter().position(|r| r.sh_type == SHT_SYMTAB);
    if let Some(si) = symtab {
        let r = &raws[si];
        if r.entsize == 0 {
            return err(format!("{}: .symtab has zero entry size", name));
        }
        let Some(strtab) = raws.get(r.link) else {
            return err(format!(
                "{}: .symtab links to a nonexistent string table",
                name
            ));
        };
        let strdat = subslice(bytes, strtab.off, strtab.size, name, ".strtab")?;
        let n = r.size / r.entsize;
        // The whole symbol table must fit; each entry is 24 bytes.
        subslice(bytes, r.off, n.saturating_mul(24), name, ".symtab")?;
        for k in 0..n {
            let e = &bytes[r.off + k * 24..r.off + (k + 1) * 24];
            let shndx = ru16(e, 6);
            symbols.push(Symbol {
                name: cstr(strdat, ru32(e, 0) as usize, name, ".strtab")?,
                bind: e[4] >> 4,
                typ: e[4] & 0xf,
                shndx,
                section: remap.get(&(shndx as usize)).copied(),
                value: ru64(e, 8),
                size: ru64(e, 16),
            });
        }
    }

    // RELA tables onto their targets.
    for r in raws.iter().filter(|r| r.sh_type == SHT_RELA) {
        let Some(&target) = remap.get(&r.info) else {
            continue; // relocations for a dropped section (.eh_frame etc.)
        };
        if r.entsize == 0 {
            return err(format!(
                "{}: RELA section '{}' has zero entry size",
                name, r.name
            ));
        }
        let n = r.size / r.entsize;
        subslice(
            bytes,
            r.off,
            n.saturating_mul(24),
            name,
            &format!("RELA '{}'", r.name),
        )?;
        for k in 0..n {
            let e = &bytes[r.off + k * 24..r.off + (k + 1) * 24];
            let info = ru64(e, 8);
            sections[target].relas.push(Rela {
                offset: ru64(e, 0),
                sym: (info >> 32) as u32,
                r_type: (info & 0xffff_ffff) as u32,
                addend: ru64(e, 16) as i64,
            });
        }
    }

    Ok(ElfObject {
        name: name.to_string(),
        sections,
        symbols,
    })
}

// ---- Shared-object reader (for dynamic linking) ----

/// One symbol a shared object exports.
#[derive(Debug, Clone)]
pub struct Export {
    /// Symbol version (`""` when unversioned). Populated in a later rung.
    pub version: String,
    /// STT_FUNC (PLT-callable) vs a data object (GLOB_DAT).
    pub func: bool,
}

/// A parsed shared object: its runtime name, the symbols it exports, and
/// the symbols it references undefined (which the executable may have to
/// define and export back so the loader can bind them).
#[derive(Debug)]
pub struct SharedLib {
    pub soname: String,
    pub exports: HashMap<String, Export>,
    /// Undefined dynamic-symbol names, in dynsym order (deterministic).
    pub undefs: Vec<String>,
}

/// Read an ET_DYN shared object's SONAME and exported dynamic symbols
/// via its section headers (which `ld`-produced `.so`s always carry).
pub fn parse_shared(name: &str, bytes: &[u8]) -> Result<SharedLib, ElfError> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return err(format!("{}: not an ELF file", name));
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return err(format!("{}: not ELF64 little-endian", name));
    }
    if ru16(bytes, 16) != ET_DYN {
        return err(format!("{}: not a shared object", name));
    }
    let shoff = ru64(bytes, 40) as usize;
    let shentsize = ru16(bytes, 58) as usize;
    let shnum = ru16(bytes, 60) as usize;
    if shoff == 0 || shnum == 0 {
        return err(format!("{}: shared object has no section headers", name));
    }
    if shentsize < 64 {
        return err(format!(
            "{}: section header entry size {} too small",
            name, shentsize
        ));
    }
    match shnum
        .checked_mul(shentsize)
        .and_then(|n| shoff.checked_add(n))
    {
        Some(end) if end <= bytes.len() => {}
        _ => return err(format!("{}: section header table out of range", name)),
    }
    let sh = |i: usize| -> &[u8] { &bytes[shoff + i * shentsize..shoff + (i + 1) * shentsize] };

    // Locate .dynsym (with its linked string table), .dynamic, and the
    // version sections (.gnu.version / .gnu.version_d) so exported
    // symbols carry their default version.
    let mut dynsym: Option<(usize, usize, usize, usize)> = None; // off,size,link,entsize
    let mut dynamic: Option<(usize, usize)> = None; // off,size
    let mut versym_off: Option<usize> = None;
    let mut verdef: Option<(usize, usize)> = None; // off,size
    for i in 0..shnum {
        let h = sh(i);
        match ru32(h, 4) {
            SHT_DYNSYM => {
                dynsym = Some((
                    ru64(h, 24) as usize,
                    ru64(h, 32) as usize,
                    ru32(h, 40) as usize,
                    ru64(h, 56) as usize,
                ));
            }
            SHT_DYNAMIC => dynamic = Some((ru64(h, 24) as usize, ru64(h, 32) as usize)),
            SHT_GNU_VERSYM => versym_off = Some(ru64(h, 24) as usize),
            SHT_GNU_VERDEF => verdef = Some((ru64(h, 24) as usize, ru64(h, 32) as usize)),
            _ => {}
        }
    }
    let Some((soff, ssize, slink, sent)) = dynsym else {
        return err(format!("{}: shared object has no .dynsym", name));
    };
    if slink >= shnum {
        return err(format!("{}: .dynsym link {} out of range", name, slink));
    }
    let link_h = sh(slink);
    let stroff = ru64(link_h, 24) as usize;
    let strsz = ru64(link_h, 32) as usize;
    let dynstr = subslice(bytes, stroff, strsz, name, ".dynstr")?;

    // SONAME from .dynamic, else the file's own name.
    let mut soname = String::new();
    if let Some((doff, dsz)) = dynamic {
        let dyn_tab = subslice(bytes, doff, dsz, name, ".dynamic")?;
        for k in 0..dsz / 16 {
            let e = &dyn_tab[k * 16..(k + 1) * 16];
            let tag = ru64(e, 0) as i64;
            if tag == 0 {
                break;
            }
            if tag == DT_SONAME {
                soname = cstr(dynstr, ru64(e, 8) as usize, name, ".dynstr")?;
            }
        }
    }
    if soname.is_empty() {
        soname = std::path::Path::new(name)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.to_string());
    }

    // Version index -> version name, from .gnu.version_d. Indices 0/1 are
    // reserved (local, base); real versions start at 2.
    let mut verdef_names: HashMap<u16, String> = HashMap::new();
    if let Some((doff, dsz)) = verdef {
        let mut p = doff;
        let end = doff.saturating_add(dsz).min(bytes.len());
        while p + 20 <= end {
            let cnt = ru16(&bytes[p..], 6);
            let aux = ru32(&bytes[p..], 12) as usize;
            let vd_next = ru32(&bytes[p..], 16) as usize;
            let ndx = ru16(&bytes[p..], 4);
            if cnt >= 1 && p + aux + 8 <= end {
                let vda_name = ru32(&bytes[p + aux..], 0) as usize;
                verdef_names.insert(ndx, cstr(dynstr, vda_name, name, ".dynstr")?);
            }
            if vd_next == 0 {
                break;
            }
            p += vd_next;
        }
    }

    // A real Elf64_Sym is 24 bytes; anything smaller makes the per-entry read
    // overrun the table. The old code silently substituted 24 for a zero
    // entsize, masking a malformed input.
    if sent < 24 {
        return err(format!(
            "{}: .dynsym entry size {} invalid (need >= 24)",
            name, sent
        ));
    }
    let sym_tab = subslice(bytes, soff, ssize, name, ".dynsym")?;
    let mut exports: HashMap<String, Export> = HashMap::new();
    let mut is_default_export: HashMap<String, bool> = HashMap::new();
    let mut undefs: Vec<String> = Vec::new();
    let nsyms = ssize / sent;
    for k in 0..nsyms {
        let e = &sym_tab[k * sent..k * sent + 24];
        let shndx = ru16(e, 6);
        let bind = e[4] >> 4;
        let typ = e[4] & 0xf;
        let nm = cstr(dynstr, ru32(e, 0) as usize, name, ".dynstr")?;
        if nm.is_empty() {
            continue;
        }
        // An undefined non-local dynsym is something this library needs
        // the executable (or another library) to provide.
        if shndx == SHN_UNDEF {
            if bind != STB_LOCAL {
                undefs.push(nm);
            }
            continue;
        }
        if bind == STB_LOCAL {
            continue;
        }
        // Version + default-ness from .gnu.version (one u16 per dynsym).
        let (version, default) = match versym_off {
            Some(vo) if vo + k * 2 + 2 <= bytes.len() => {
                let raw = ru16(&bytes[vo + k * 2..], 0);
                let idx = raw & !VERSYM_HIDDEN;
                if idx >= 2 {
                    (
                        verdef_names.get(&idx).cloned().unwrap_or_default(),
                        raw & VERSYM_HIDDEN == 0,
                    )
                } else {
                    (String::new(), true)
                }
            }
            _ => (String::new(), true),
        };
        // Prefer the default-versioned definition when a name repeats:
        // replace only when the new def is default and the stored isn't.
        let prev_default = is_default_export.get(&nm).copied().unwrap_or(false);
        if exports.contains_key(&nm) && (prev_default || !default) {
            continue;
        }
        is_default_export.insert(nm.clone(), default);
        exports.insert(
            nm,
            Export {
                version,
                func: typ == STT_FUNC || typ == STT_GNU_IFUNC,
            },
        );
    }
    Ok(SharedLib {
        soname,
        exports,
        undefs,
    })
}

// ---- Static layout + link ----

struct OutSec {
    name: String,
    flags: u64,
    align: u64,
    data: Vec<u8>,
    bss_size: u64,
    vaddr: u64,
    file_off: u64,
    is_bss: bool,
}

/// (object index, section index) -> (output section, offset within it)
type Placement = HashMap<(usize, usize), (usize, u64)>;

/// (object index, symbol index) for an allocated SHN_COMMON definition
/// -> (output section, offset within it).
type CommonPlacement = HashMap<(usize, usize), (usize, u64)>;

/// A synthesized GOT slot. `Addr` holds a symbol's final address
/// (`None` = an unsatisfied weak reference, i.e. 0); `TpOff` holds a
/// TLS symbol's TP-relative offset for the initial-exec model.
enum GotEntry {
    Addr(Option<(usize, usize)>),
    TpOff((usize, usize)),
}

/// A `.got` slot in a dynamic executable, sized before layout and filled
/// after. `GlobDat` is a runtime import (loader writes the address via an
/// `R_X86_64_GLOB_DAT` in `.rela.dyn`); `Defined` holds an in-image
/// symbol's absolute address (non-PIE, known at link time); `Zero` is an
/// unsatisfied weak reference.
enum GotSlot {
    GlobDat(u32),
    Defined(usize, usize),
    TpOff(usize, usize),
    Zero,
}

fn output_rank(flags: u64, is_bss: bool) -> u32 {
    if flags & SHF_EXECINSTR != 0 {
        0
    } else if flags & SHF_WRITE == 0 {
        1 // rodata
    } else if !is_bss {
        2 // data
    } else {
        3 // bss
    }
}

/// A library archive (`.a`) offered for lazy member selection. The raw
/// bytes are the whole `ar` container; members are parsed as ELF only
/// when pulled to satisfy an undefined symbol.
pub struct Library {
    /// Display name retained in diagnostics and public API output.
    pub name: String,
    /// Filesystem location used to resolve external GNU-thin members.
    pub path: std::path::PathBuf,
    pub bytes: Vec<u8>,
}

/// Ordered static-link input. Objects load when encountered; archives
/// are searched lazily against the undefined set that exists at that
/// point. Group markers request GNU ld-style repeated scans within the
/// delimited range.
pub enum LinkInput {
    Object(ElfObject),
    Archive(Library),
    GroupStart,
    GroupEnd,
}

/// Ordered dynamic-link input. Shared libraries contribute their exports
/// only when encountered, so earlier archives are not suppressed by later
/// `.so` files.
pub enum DynamicLinkInput {
    Object(ElfObject),
    Archive(Library),
    Shared(SharedLib),
    GroupStart,
    GroupEnd,
}

struct ArchiveInput {
    lib: Library,
    pulled: HashSet<u64>,
}

enum StaticInput {
    Object(Option<ElfObject>),
    Archive(ArchiveInput),
    GroupStart,
    GroupEnd,
}

enum DynamicInput {
    Object(Option<ElfObject>),
    Archive(ArchiveInput),
    Shared(Option<SharedLib>),
    GroupStart,
    GroupEnd,
}

/// The base of a versioned symbol name (`foo@V` or `foo@@V` -> `foo`);
/// `None` for an unversioned name.
fn version_base(name: &str) -> Option<&str> {
    name.find('@').map(|at| &name[..at])
}

/// The only FDE pointer encoding we decode: `DW_EH_PE_pcrel |
/// DW_EH_PE_sdata4`. It is what gcc/clang/rustc emit on x86_64 and the
/// only shape an `R_X86_64_PC32` relocation on the initial-location
/// field can produce, so a CIE declaring anything else is a hard error
/// rather than a silently-wrong PC.
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;

/// One FDE, for the `.eh_frame_hdr` search table: its function start PC
/// and the file offset of the FDE record within `.eh_frame`.
struct FdeEntry {
    pc: u64,
    fde_off: u64,
}

/// Extract the FDE pointer encoding a CIE advertises through its
/// augmentation (`DW_EH_PE_absptr` = 0 when it carries no `R`). `content`
/// is the offset of the CIE id; `rec_end` bounds the record.
fn cie_fde_encoding(eh: &[u8], content: usize, rec_end: usize) -> Result<u8, ElfError> {
    let slice_uleb = |p: usize| -> Result<usize, ElfError> {
        let (_, n) = crate::leb::read_uleb(&eh[p..rec_end])
            .map_err(|_| ElfError(".eh_frame: bad ULEB in CIE".into()))?;
        Ok(p + n)
    };
    let mut p = content + 4; // past the CIE id
    if p >= rec_end {
        return err(".eh_frame: CIE truncated at version");
    }
    let version = eh[p];
    p += 1;
    let aug_start = p;
    while p < rec_end && eh[p] != 0 {
        p += 1;
    }
    if p >= rec_end {
        return err(".eh_frame: unterminated CIE augmentation string");
    }
    let aug = eh[aug_start..p].to_vec();
    p += 1; // past NUL
    p = slice_uleb(p)?; // code alignment factor
    let (_, n) = crate::leb::read_sleb(&eh[p..rec_end])
        .map_err(|_| ElfError(".eh_frame: bad SLEB in CIE".into()))?;
    p += n; // data alignment factor
    if version >= 3 {
        p = slice_uleb(p)?; // return-address register (ULEB)
    } else {
        p += 1; // return-address register (single byte)
    }
    if aug.first() != Some(&b'z') {
        return Ok(0); // DW_EH_PE_absptr
    }
    p = slice_uleb(p)?; // augmentation data length
    for &c in &aug[1..] {
        match c {
            b'R' => {
                if p >= rec_end {
                    return err(".eh_frame: CIE 'R' augmentation missing its byte");
                }
                return Ok(eh[p]);
            }
            b'L' => p += 1, // LSDA encoding byte
            b'P' => {
                // personality encoding byte, then a pointer of that size.
                if p >= rec_end {
                    return err(".eh_frame: CIE 'P' augmentation truncated");
                }
                let penc = eh[p];
                p += 1;
                p += match penc & 0x07 {
                    0x00 => 8, // absptr
                    0x02 => 2, // udata2
                    0x03 => 4, // udata4
                    0x04 => 8, // udata8
                    _ => return err(".eh_frame: unsupported personality encoding"),
                };
            }
            _ => return err(".eh_frame: unsupported CIE augmentation char"),
        }
    }
    Ok(0)
}

/// Parse a linked `.eh_frame` (relocations already applied) into its FDE
/// entries. `eh_vaddr` is the section's final virtual address; each FDE's
/// initial-location field then holds a pcrel `sdata4` whose target PC is
/// `field_vaddr + value`.
fn parse_eh_frame_fdes(eh: &[u8], eh_vaddr: u64) -> Result<Vec<FdeEntry>, ElfError> {
    let mut cie_enc: HashMap<u64, u8> = HashMap::new();
    let mut fdes = Vec::new();
    let mut off = 0usize;
    while off + 4 <= eh.len() {
        let len = ru32(eh, off) as usize;
        if len == 0 {
            break; // CIE-id terminator
        }
        if len == 0xffff_ffff {
            return err(".eh_frame: 64-bit DWARF length unsupported");
        }
        let content = off + 4;
        let rec_end = content
            .checked_add(len)
            .filter(|&e| e <= eh.len())
            .ok_or_else(|| ElfError(".eh_frame: record length runs past the section".into()))?;
        if content + 4 > eh.len() {
            return err(".eh_frame: record truncated at id");
        }
        let id = ru32(eh, content);
        if id == 0 {
            cie_enc.insert(off as u64, cie_fde_encoding(eh, content, rec_end)?);
        } else {
            // cie_pointer is a backward offset from its own field to the
            // owning CIE record.
            let cie_off = (content as u64)
                .checked_sub(id as u64)
                .ok_or_else(|| ElfError(".eh_frame: FDE CIE pointer underflows".into()))?;
            let enc = *cie_enc
                .get(&cie_off)
                .ok_or_else(|| ElfError(".eh_frame: FDE references an unknown CIE".into()))?;
            if enc != DW_EH_PE_PCREL_SDATA4 {
                return err(format!(
                    ".eh_frame: FDE pointer encoding {enc:#04x} unsupported (only pcrel|sdata4)"
                ));
            }
            let il = content + 4; // initial_location, right after cie_pointer
            if il + 4 > eh.len() {
                return err(".eh_frame: FDE truncated before initial_location");
            }
            let rel = ru32(eh, il) as i32 as i64;
            let pc = ((eh_vaddr + il as u64) as i64 + rel) as u64;
            fdes.push(FdeEntry {
                pc,
                fde_off: off as u64,
            });
        }
        off = rec_end;
    }
    Ok(fdes)
}

/// Build the `.eh_frame_hdr` contents: the 12-byte header (version,
/// pcrel|sdata4 `eh_frame_ptr`, udata4 `fde_count`, datarel|sdata4 table
/// encoding) followed by the FDE search table — `(pc, fde)` pairs each
/// datarel `sdata4`, sorted by PC — that the unwinder binary-searches.
/// `hdr_vaddr`/`eh_vaddr` are the final addresses of the two sections.
fn build_eh_frame_hdr(eh: &[u8], eh_vaddr: u64, hdr_vaddr: u64) -> Result<Vec<u8>, ElfError> {
    let mut fdes = parse_eh_frame_fdes(eh, eh_vaddr)?;
    fdes.sort_by_key(|f| f.pc);
    let datarel = |v: u64| -> Result<i32, ElfError> {
        i32::try_from(v as i64 - hdr_vaddr as i64)
            .map_err(|_| ElfError(".eh_frame_hdr: table entry out of sdata4 range".into()))
    };
    let mut out = Vec::with_capacity(12 + fdes.len() * 8);
    out.push(1); // version
    out.push(DW_EH_PE_PCREL_SDATA4); // eh_frame_ptr encoding
    out.push(0x03); // fde_count encoding: DW_EH_PE_udata4
    out.push(0x3b); // table encoding: DW_EH_PE_datarel | DW_EH_PE_sdata4
                    // eh_frame_ptr: pcrel sdata4 to the start of .eh_frame, relative to
                    // its own field (hdr_vaddr + 4).
    let eh_ptr = i32::try_from(eh_vaddr as i64 - (hdr_vaddr as i64 + 4))
        .map_err(|_| ElfError(".eh_frame_hdr: eh_frame_ptr out of sdata4 range".into()))?;
    out.extend_from_slice(&eh_ptr.to_le_bytes());
    out.extend_from_slice(&(fdes.len() as u32).to_le_bytes());
    for f in &fdes {
        out.extend_from_slice(&datarel(f.pc)?.to_le_bytes());
        out.extend_from_slice(&datarel(eh_vaddr + f.fde_off)?.to_le_bytes());
    }
    Ok(out)
}

/// Names a symtab entry defines (global/weak, section-bound, non-empty).
/// A versioned definition (`foo@@V`) also answers the plain base `foo`,
/// so a later reference to `foo` counts as satisfied.
fn defined_names(obj: &ElfObject, out: &mut HashSet<String>) {
    for sym in &obj.symbols {
        if sym.name.is_empty() || sym.bind == STB_LOCAL || sym.shndx == SHN_UNDEF {
            continue;
        }
        out.insert(sym.name.clone());
        if let Some(base) = version_base(&sym.name) {
            out.insert(base.to_string());
        }
    }
}

/// Resolve a symbol name to its defining member's header offset in an
/// archive, tolerant of symbol versioning: an exact hit wins, else a
/// default-version (`name@@V`) entry, else any versioned (`name@V`).
fn armap_offset(ar: &crate::archive::Archive, name: &str) -> Option<u64> {
    let si = ar.symbol_index()?;
    if let Some(o) = si.first_defining_offset(name) {
        return Some(o);
    }
    let mut any = None;
    for e in &si.entries {
        let Some(at) = e.name.find('@') else { continue };
        if &e.name[..at] != name {
            continue;
        }
        if e.name[at..].starts_with("@@") {
            return Some(e.member_header_offset);
        }
        any.get_or_insert(e.member_header_offset);
    }
    any
}

/// Strong-undefined names an object references, in first-seen order,
/// skipping any already defined. Weak-undefined does not pull archive
/// members (it resolves to 0 if left unsatisfied).
fn undefined_demand(objects: &[ElfObject], defined: &HashSet<String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut demand = Vec::new();
    for obj in objects {
        for sym in &obj.symbols {
            if sym.shndx != SHN_UNDEF
                || sym.bind != STB_GLOBAL
                || sym.name.is_empty()
                || defined.contains(&sym.name)
                || LINKER_SYMS.contains(&sym.name.as_str())
            {
                continue;
            }
            if seen.insert(sym.name.clone()) {
                demand.push(sym.name.clone());
            }
        }
    }
    demand
}

fn common_align(sym: &Symbol) -> u64 {
    sym.value.max(1)
}

fn prefer_common_symbol(new_sym: &Symbol, old_sym: &Symbol) -> bool {
    new_sym.size > old_sym.size
        || (new_sym.size == old_sym.size && common_align(new_sym) > common_align(old_sym))
}

fn resolve_defined_identity(
    objects: &[ElfObject],
    globals: &HashMap<String, (usize, usize)>,
    oi: usize,
    si: usize,
) -> (usize, usize) {
    let sym = &objects[oi].symbols[si];
    if sym.shndx == SHN_COMMON && sym.bind != STB_LOCAL {
        globals.get(&sym.name).copied().unwrap_or((oi, si))
    } else {
        (oi, si)
    }
}

fn ensure_common_bss(
    outs: &mut Vec<OutSec>,
    out_index: &mut HashMap<String, usize>,
) -> Result<usize, ElfError> {
    if let Some(&idx) = out_index.get(".bss") {
        if !outs[idx].is_bss {
            return err("section '.bss' is PROGBITS but COMMON allocation needs NOBITS .bss");
        }
        return Ok(idx);
    }
    outs.push(OutSec {
        name: ".bss".to_string(),
        flags: SHF_ALLOC | SHF_WRITE,
        align: 1,
        data: Vec::new(),
        bss_size: 0,
        vaddr: 0,
        file_off: 0,
        is_bss: true,
    });
    let idx = outs.len() - 1;
    out_index.insert(".bss".to_string(), idx);
    Ok(idx)
}

fn place_common_symbols(
    objects: &[ElfObject],
    globals: &HashMap<String, (usize, usize)>,
    outs: &mut Vec<OutSec>,
    out_index: &mut HashMap<String, usize>,
) -> Result<CommonPlacement, ElfError> {
    let mut common_place = HashMap::new();
    let mut allocated = HashSet::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sym) in obj.symbols.iter().enumerate() {
            if sym.shndx != SHN_COMMON {
                continue;
            }
            let def = resolve_defined_identity(objects, globals, oi, si);
            if def != (oi, si) || !allocated.insert(def) {
                continue;
            }
            let idx = ensure_common_bss(outs, out_index)?;
            let align = common_align(sym);
            let out = &mut outs[idx];
            out.align = out.align.max(align);
            let cursor = next_multiple(out.bss_size, align);
            out.bss_size = cursor + sym.size;
            common_place.insert(def, (idx, cursor));
        }
    }
    Ok(common_place)
}

/// Resolve the defined globals across all input objects into
/// `name -> (object index, symbol index)`.
///
/// Coalescing: a strong definition beats a weak one regardless of order;
/// two strong definitions of one name are an error; a duplicate weak is
/// ignored. Then version aliasing lets a default-version definition
/// (`foo@@V`) answer the plain base `foo`, and a non-default (`foo@V`)
/// answer it only when nothing else does; an explicit unversioned
/// definition always wins.
///
/// Deterministic by construction: among competing versioned definitions
/// the base winner is the earliest in link order (object index, then
/// symbol index), never HashMap iteration order — the byte-determinism
/// gate depends on this.
fn resolve_globals(objects: &[ElfObject]) -> Result<HashMap<String, (usize, usize)>, ElfError> {
    let mut globals: HashMap<String, (usize, usize)> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sym) in obj.symbols.iter().enumerate() {
            if sym.name.is_empty() || sym.bind == STB_LOCAL || sym.shndx == SHN_UNDEF {
                continue;
            }
            match globals.get(&sym.name) {
                None => {
                    globals.insert(sym.name.clone(), (oi, si));
                }
                Some(&(poi, psi)) => {
                    let prev = &objects[poi].symbols[psi];
                    match (prev.shndx == SHN_COMMON, sym.shndx == SHN_COMMON) {
                        (true, true) => {
                            if prefer_common_symbol(sym, prev) {
                                globals.insert(sym.name.clone(), (oi, si));
                            }
                        }
                        (true, false) => {
                            if sym.bind == STB_GLOBAL {
                                globals.insert(sym.name.clone(), (oi, si));
                            }
                        }
                        (false, true) => {
                            if prev.bind == STB_WEAK {
                                globals.insert(sym.name.clone(), (oi, si));
                            }
                        }
                        (false, false) => match (prev.bind, sym.bind) {
                            (STB_WEAK, STB_GLOBAL) => {
                                globals.insert(sym.name.clone(), (oi, si));
                            }
                            (STB_GLOBAL, STB_WEAK) => {}
                            (STB_GLOBAL, STB_GLOBAL) => {
                                return err(format!(
                                    "duplicate symbol '{}' in {} and {}",
                                    sym.name, objects[poi].name, obj.name
                                ));
                            }
                            _ => {}
                        },
                    }
                }
            }
        }
    }

    // Version aliasing. Collect the versioned definitions and apply them
    // in a fixed order — default (`@@`) versions first, then by link
    // order — so the base winner never depends on HashMap iteration. An
    // explicit unversioned definition already in `globals` is left
    // untouched by `or_insert`.
    let mut versioned: Vec<(bool, usize, usize, String)> = Vec::new();
    for (full, &(oi, si)) in &globals {
        let Some(at) = full.find('@') else { continue };
        let is_default = full[at..].starts_with("@@");
        versioned.push((is_default, oi, si, full[..at].to_string()));
    }
    // `true` sorts before `false` via reverse on the flag; ties break by
    // link order (object, then symbol index).
    versioned.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    for (_is_default, oi, si, base) in versioned {
        globals.entry(base).or_insert((oi, si));
    }

    Ok(globals)
}

fn static_state(input: LinkInput) -> StaticInput {
    match input {
        LinkInput::Object(obj) => StaticInput::Object(Some(obj)),
        LinkInput::Archive(lib) => StaticInput::Archive(ArchiveInput {
            lib,
            pulled: HashSet::new(),
        }),
        LinkInput::GroupStart => StaticInput::GroupStart,
        LinkInput::GroupEnd => StaticInput::GroupEnd,
    }
}

fn dynamic_state(input: DynamicLinkInput) -> DynamicInput {
    match input {
        DynamicLinkInput::Object(obj) => DynamicInput::Object(Some(obj)),
        DynamicLinkInput::Archive(lib) => DynamicInput::Archive(ArchiveInput {
            lib,
            pulled: HashSet::new(),
        }),
        DynamicLinkInput::Shared(lib) => DynamicInput::Shared(Some(lib)),
        DynamicLinkInput::GroupStart => DynamicInput::GroupStart,
        DynamicLinkInput::GroupEnd => DynamicInput::GroupEnd,
    }
}

fn add_object(obj: ElfObject, objects: &mut Vec<ElfObject>, defined: &mut HashSet<String>) {
    defined_names(&obj, defined);
    objects.push(obj);
}

fn scan_archive(
    input: &mut ArchiveInput,
    objects: &mut Vec<ElfObject>,
    defined: &mut HashSet<String>,
    mode: &str,
) -> Result<bool, ElfError> {
    use crate::archive::Archive as ArContainer;

    let archive = ArContainer::open(input.lib.path.clone(), &input.lib.bytes)
        .map_err(|e| ElfError(format!("{}: {}", input.lib.name, e)))?;
    let mut pulled_any = false;
    loop {
        let demand = undefined_demand(objects, defined);
        let mut changed = false;
        for name in &demand {
            let Some(off) = armap_offset(&archive, name) else {
                continue;
            };
            if !input.pulled.insert(off) {
                continue;
            }
            let member = archive.member_at_offset(off).ok_or_else(|| {
                ElfError(format!(
                    "{}: symbol index points at offset {:#x} with no member",
                    input.lib.name, off
                ))
            })?;
            let loaded = archive
                .load_member(member)
                .map_err(|error| ElfError(format!("ELF {mode} link: {error}")))?;
            let obj = parse_rel(
                &loaded.logical_path.to_string_lossy(),
                loaded.bytes.as_ref(),
            )?;
            add_object(obj, objects, defined);
            changed = true;
            pulled_any = true;
        }
        if !changed {
            break;
        }
    }
    Ok(pulled_any)
}

fn find_static_group_end(
    inputs: &[StaticInput],
    start: usize,
    end: usize,
) -> Result<usize, ElfError> {
    let mut depth = 0usize;
    for (i, input) in inputs.iter().enumerate().take(end).skip(start) {
        match input {
            StaticInput::GroupStart => depth += 1,
            StaticInput::GroupEnd if depth == 0 => return Ok(i),
            StaticInput::GroupEnd => depth -= 1,
            _ => {}
        }
    }
    err("ELF link has --start-group without matching --end-group")
}

fn process_static_range(
    inputs: &mut [StaticInput],
    start: usize,
    end: usize,
    objects: &mut Vec<ElfObject>,
    defined: &mut HashSet<String>,
) -> Result<bool, ElfError> {
    let mut changed = false;
    let mut i = start;
    while i < end {
        if matches!(inputs[i], StaticInput::GroupStart) {
            let group_end = find_static_group_end(inputs, i + 1, end)?;
            loop {
                let pass_changed =
                    process_static_range(inputs, i + 1, group_end, objects, defined)?;
                if !pass_changed {
                    break;
                }
                changed = true;
            }
            i = group_end + 1;
            continue;
        }
        if matches!(inputs[i], StaticInput::GroupEnd) {
            return err("ELF link has --end-group without matching --start-group");
        }
        match &mut inputs[i] {
            StaticInput::Object(obj) => {
                if let Some(obj) = obj.take() {
                    add_object(obj, objects, defined);
                    changed = true;
                }
            }
            StaticInput::Archive(archive) => {
                changed |= scan_archive(archive, objects, defined, "static")?;
            }
            StaticInput::GroupStart | StaticInput::GroupEnd => unreachable!(),
        }
        i += 1;
    }
    Ok(changed)
}

/// Link ordered objects and library archives into a static ET_EXEC.
/// Explicit objects load when encountered; archives are searched once
/// left-to-right unless bracketed by group markers, where the group is
/// rescanned until no new members are needed.
pub fn link_static(
    inputs: Vec<LinkInput>,
    entry: &str,
    eh_frame_hdr: bool,
) -> Result<Vec<u8>, ElfError> {
    let mut inputs: Vec<StaticInput> = inputs.into_iter().map(static_state).collect();
    let mut objects = Vec::new();
    let mut defined = HashSet::new();
    let end = inputs.len();
    process_static_range(&mut inputs, 0, end, &mut objects, &mut defined)?;

    link_static_exec(&objects, entry, eh_frame_hdr)
}

/// Link relocatable objects into a static ET_EXEC image. Explicit
/// objects only — undefined strong globals are an error; use
/// [`link_static`] to pull definitions from library archives. Undefined
/// *weak* references resolve to 0. `eh_frame_hdr` requests the
/// `.eh_frame_hdr` + PT_GNU_EH_FRAME unwind index (GNU `--eh-frame-hdr`);
/// `.eh_frame` itself is retained regardless.
pub fn link_static_exec(
    objects: &[ElfObject],
    entry: &str,
    eh_frame_hdr: bool,
) -> Result<Vec<u8>, ElfError> {
    // ---- Merge input sections by (name, flags) in first-seen order,
    // ranked text / rodata / data / bss for segment assignment.
    let mut outs: Vec<OutSec> = Vec::new();
    let mut out_index: HashMap<String, usize> = HashMap::new();
    let mut place: Placement = HashMap::new();

    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            // TLS sections do not join the normal segment layout; they
            // form the PT_TLS initialization image, handled below.
            if sec.sh_flags & SHF_TLS != 0 {
                continue;
            }
            // Init/fini arrays merge priority-ordered in a separate pass
            // so their bracket symbols cover every contribution.
            if array_kind(&sec.name).is_some() {
                continue;
            }
            let is_bss = sec.sh_type == SHT_NOBITS;
            let key = sec.name.clone();
            let idx = *out_index.entry(key).or_insert_with(|| {
                outs.push(OutSec {
                    name: sec.name.clone(),
                    flags: sec.sh_flags,
                    align: 1,
                    data: Vec::new(),
                    bss_size: 0,
                    vaddr: 0,
                    file_off: 0,
                    is_bss,
                });
                outs.len() - 1
            });
            let out = &mut outs[idx];
            if out.is_bss != is_bss {
                return err(format!(
                    "section '{}' is NOBITS in some objects and PROGBITS in others",
                    sec.name
                ));
            }
            out.align = out.align.max(sec.sh_addralign);
            let cursor = if is_bss {
                let c = next_multiple(out.bss_size, sec.sh_addralign);
                out.bss_size = c + sec.nobits_size;
                c
            } else {
                let c = next_multiple(out.data.len() as u64, sec.sh_addralign);
                out.data.resize(c as usize, 0);
                out.data.extend_from_slice(&sec.data);
                c
            };
            place.insert((oi, si), (idx, cursor));
        }
    }

    // ---- Global symbol resolution and COMMON allocation. SHN_COMMON is
    // a tentative definition: coalesced globally, then allocated as zeroed
    // storage in .bss before layout.
    let globals = resolve_globals(objects)?;
    let common_place = place_common_symbols(objects, &globals, &mut outs, &mut out_index)?;

    // ---- Init/fini arrays: merge each kind priority-ordered into one
    // output section so __{init,fini,preinit}_array_{start,end} bracket
    // every constructor/destructor.
    for base in [".preinit_array", ".init_array", ".fini_array"] {
        let mut parts: Vec<(u64, usize, usize, usize)> = Vec::new(); // (prio, oi, si, orig_idx)
        for (oi, obj) in objects.iter().enumerate() {
            for (si, sec) in obj.sections.iter().enumerate() {
                if let Some((b, prio)) = array_kind(&sec.name) {
                    if b == base {
                        parts.push((prio, oi, si, parts.len()));
                    }
                }
            }
        }
        if parts.is_empty() {
            continue;
        }
        // Stable order: priority ascending, ties keep input order.
        parts.sort_by_key(|&(prio, _, _, orig)| (prio, orig));
        let mut align = 8u64;
        for &(_, oi, si, _) in &parts {
            align = align.max(objects[oi].sections[si].sh_addralign);
        }
        let idx = outs.len();
        outs.push(OutSec {
            name: base.to_string(),
            flags: SHF_ALLOC | SHF_WRITE,
            align,
            data: Vec::new(),
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        for &(_, oi, si, _) in &parts {
            let sec = &objects[oi].sections[si];
            let c = next_multiple(outs[idx].data.len() as u64, sec.sh_addralign);
            outs[idx].data.resize(c as usize, 0);
            outs[idx].data.extend_from_slice(&sec.data);
            place.insert((oi, si), (idx, c));
        }
    }

    // ---- TLS block (variant II, local-exec). Concatenate every .tdata
    // (the initialized image) then every .tbss (zero template past it);
    // each TLS symbol gets a block offset. The thread pointer sits just
    // past the block, so a symbol's TP-relative offset is
    // block_off - align_up(memsz, align) — negative, as x86_64 expects.
    let mut tls_data: Vec<u8> = Vec::new();
    let mut tls_align: u64 = 1;
    let mut tls_place: HashMap<(usize, usize), u64> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS == 0 || sec.sh_type == SHT_NOBITS {
                continue;
            }
            tls_align = tls_align.max(sec.sh_addralign);
            let c = next_multiple(tls_data.len() as u64, sec.sh_addralign);
            tls_data.resize(c as usize, 0);
            tls_data.extend_from_slice(&sec.data);
            tls_place.insert((oi, si), c);
        }
    }
    let tls_bss_base = tls_data.len() as u64;
    let mut tls_bss: u64 = 0;
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS == 0 || sec.sh_type != SHT_NOBITS {
                continue;
            }
            tls_align = tls_align.max(sec.sh_addralign);
            let c = next_multiple(tls_bss, sec.sh_addralign);
            tls_place.insert((oi, si), tls_bss_base + c);
            tls_bss = c + sec.nobits_size;
        }
    }
    let tls_memsz = tls_bss_base + tls_bss;
    let tls_neg_base = next_multiple(tls_memsz, tls_align) as i64;
    let has_tls = tls_memsz > 0;
    // The init image is a normal RW chunk PT_TLS overlays; .tbss adds no
    // process memory (it is a per-thread template). Anchor PT_TLS on a
    // synthetic section so it has a file offset and vaddr even for a
    // .tbss-only program.
    let tls_out: Option<usize> = if has_tls {
        let name = if tls_data.is_empty() {
            ".tbss"
        } else {
            ".tdata"
        };
        outs.push(OutSec {
            name: name.to_string(),
            flags: SHF_ALLOC | SHF_WRITE | SHF_TLS,
            align: tls_align,
            data: std::mem::take(&mut tls_data),
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        Some(outs.len() - 1)
    } else {
        None
    };

    // Reference -> definition identity. None means an unsatisfied weak
    // reference (address 0). Depends only on `globals`, so it is valid
    // before layout — the GOT pre-scan uses it.
    let resolve_def = |oi: usize, si: usize| -> Result<Option<(usize, usize)>, ElfError> {
        let sym = &objects[oi].symbols[si];
        if sym.shndx != SHN_UNDEF {
            return Ok(Some(resolve_defined_identity(objects, &globals, oi, si)));
        }
        if let Some(&d) = globals.get(&sym.name) {
            return Ok(Some(d));
        }
        if let Some(idx) = LINKER_SYMS.iter().position(|&n| n == sym.name) {
            return Ok(Some((LINKER_MARK, idx)));
        }
        if sym.bind == STB_WEAK {
            return Ok(None);
        }
        err(format!(
            "undefined symbol '{}' (referenced from {})",
            sym.name, objects[oi].name
        ))
    };

    // TLS reference -> TP-relative offset (tpoff). GNU ld resolves
    // undefined weak TLS local-exec references to zero; glibc uses this
    // for optional locale TLS state in static links.
    let tls_offset = |oi: usize, si: usize| -> Result<i64, ElfError> {
        let Some((doi, dsi)) = resolve_def(oi, si)? else {
            return Ok(0);
        };
        let d = &objects[doi].symbols[dsi];
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("TLS symbol '{}' has no section", d.name)))?;
        let block_off = *tls_place
            .get(&(doi, sec))
            .ok_or_else(|| ElfError(format!("TLS symbol '{}' is not in a TLS section", d.name)))?;
        Ok(block_off as i64 + d.value as i64 - tls_neg_base)
    };

    // ---- GOT synthesis. Each GOTPCREL-family reference gets an 8-byte
    // slot holding the target's final address; each GOTTPOFF (TLS IE)
    // reference gets a slot holding the target's tpoff. Slots are
    // deduplicated per kind; unsatisfied weak address references share
    // one zero slot. A static link could relax these loads, but a real
    // slot is uniformly correct and keeps the reloc arms simple.
    let mut got_entries: Vec<GotEntry> = Vec::new();
    let mut got_addr_of: HashMap<(usize, usize), usize> = HashMap::new();
    let mut got_addr_weak0: Option<usize> = None;
    let mut got_tpoff_of: HashMap<(usize, usize), usize> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for sec in &obj.sections {
            for r in &sec.relas {
                if is_gotpcrel(r.r_type) {
                    match resolve_def(oi, r.sym as usize)? {
                        Some(d) => {
                            got_addr_of.entry(d).or_insert_with(|| {
                                got_entries.push(GotEntry::Addr(Some(d)));
                                got_entries.len() - 1
                            });
                        }
                        None => {
                            if got_addr_weak0.is_none() {
                                got_entries.push(GotEntry::Addr(None));
                                got_addr_weak0 = Some(got_entries.len() - 1);
                            }
                        }
                    }
                } else if r.r_type == R_X86_64_GOTTPOFF {
                    let d = resolve_def(oi, r.sym as usize)?.ok_or_else(|| {
                        ElfError(format!(
                            "TLS IE relocation against undefined symbol in {}",
                            obj.name
                        ))
                    })?;
                    got_tpoff_of.entry(d).or_insert_with(|| {
                        got_entries.push(GotEntry::TpOff(d));
                        got_entries.len() - 1
                    });
                }
            }
        }
    }
    let got_out: Option<usize> = if got_entries.is_empty() {
        None
    } else {
        outs.push(OutSec {
            name: ".got".to_string(),
            flags: SHF_ALLOC | SHF_WRITE,
            align: 8,
            data: vec![0u8; got_entries.len() * 8],
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        Some(outs.len() - 1)
    };
    let got_addr_slot = |def: Option<(usize, usize)>| -> usize {
        match def {
            Some(d) => got_addr_of[&d],
            None => got_addr_weak0.unwrap(),
        }
    };

    // ---- IFUNC / IPLT synthesis. FreeBSD's amd64 string/memory
    // routines are STT_GNU_IFUNC: a reference resolves to an IPLT stub
    // (`jmp *slot`) whose GOT.PLT slot the static startup fills by
    // running the resolver (an R_X86_64_IRELATIVE the csu applies over
    // __rela_iplt_start..__rela_iplt_end).
    let mut iplt_of: HashMap<(usize, usize), usize> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for sec in &obj.sections {
            for r in &sec.relas {
                // Only defined ifuncs matter here; a symbol that fails to
                // resolve (e.g. a suppressed __tls_get_addr) surfaces its
                // error later in the apply loop, if at all.
                if let Ok(Some(d)) = resolve_def(oi, r.sym as usize) {
                    if d.0 != LINKER_MARK && objects[d.0].symbols[d.1].typ == STT_GNU_IFUNC {
                        let next = iplt_of.len();
                        iplt_of.entry(d).or_insert(next);
                    }
                }
            }
        }
    }
    let n_iplt = iplt_of.len();
    let (iplt_out, gotplt_out, relaplt_out) = if n_iplt == 0 {
        (None, None, None)
    } else {
        outs.push(OutSec {
            name: ".iplt".to_string(),
            flags: SHF_ALLOC | SHF_EXECINSTR,
            align: 16,
            data: vec![0u8; n_iplt * 16],
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        let iplt = outs.len() - 1;
        outs.push(OutSec {
            name: ".got.plt".to_string(),
            flags: SHF_ALLOC | SHF_WRITE,
            align: 8,
            data: vec![0u8; n_iplt * 8],
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        let gotplt = outs.len() - 1;
        outs.push(OutSec {
            name: ".rela.plt".to_string(),
            flags: SHF_ALLOC,
            align: 8,
            data: vec![0u8; n_iplt * 24],
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        (Some(iplt), Some(gotplt), Some(outs.len() - 1))
    };

    // ---- .eh_frame_hdr: `.eh_frame` is now retained (rodata); when
    // `--eh-frame-hdr` is requested, synthesize the binary-search header
    // the unwinder expects. Sized from the FDE count now (structure is
    // reloc-invariant); filled once addresses are fixed. Both land in the
    // RX/rodata segment.
    let eh_frame_idx = if eh_frame_hdr {
        outs.iter()
            .position(|o| o.name == ".eh_frame" && !o.data.is_empty())
    } else {
        None
    };
    let eh_hdr_idx = match eh_frame_idx {
        Some(ei) => {
            let n_fde = parse_eh_frame_fdes(&outs[ei].data, 0)?.len();
            outs.push(OutSec {
                name: ".eh_frame_hdr".to_string(),
                flags: SHF_ALLOC,
                align: 4,
                data: vec![0u8; 12 + n_fde * 8],
                bss_size: 0,
                vaddr: 0,
                file_off: 0,
                is_bss: false,
            });
            Some(outs.len() - 1)
        }
        None => None,
    };

    // Deterministic segment order: text, rodata, data, bss (synthetic
    // GOT/TLS sections included).
    let mut order: Vec<usize> = (0..outs.len()).collect();
    order.sort_by_key(|&i| (output_rank(outs[i].flags, outs[i].is_bss), i));

    // ---- Layout: one RX PT_LOAD covering ehdr+phdrs+text/rodata, one
    // RW PT_LOAD for data+bss, plus PT_TLS when the program has thread
    // locals. (rodata shares the RX segment at rung 1 — matches what
    // lld does with a small freestanding input closely enough for
    // behavioral parity.)
    let ehsize = 64u64;
    // 2 PT_LOAD + PT_GNU_STACK marker, plus PT_TLS / PT_GNU_EH_FRAME when
    // present. PT_GNU_STACK (non-exec) is required so Linux does not fall
    // back to READ_IMPLIES_EXEC and grant an executable stack (audit L9);
    // the dynamic path already emits it.
    let phnum = 3u64 + if has_tls { 1 } else { 0 } + if eh_hdr_idx.is_some() { 1 } else { 0 };
    let phsize = 56 * phnum;
    let mut cursor_file = ehsize + phsize;
    let mut cursor_vaddr = BASE_VADDR + cursor_file;

    let mut rw_start_idx = None;
    for (pos, &i) in order.iter().enumerate() {
        let is_rw = outs[i].flags & SHF_WRITE != 0 || outs[i].is_bss;
        if is_rw && rw_start_idx.is_none() {
            rw_start_idx = Some(pos);
            // Start the RW segment on a fresh page, congruent offsets.
            cursor_file = next_multiple(cursor_file, PAGE);
            cursor_vaddr = next_multiple(cursor_vaddr, PAGE);
        }
        let o = &mut outs[i];
        let a = o.align.max(1);
        cursor_file = next_multiple(cursor_file, a);
        cursor_vaddr = next_multiple(cursor_vaddr, a);
        o.file_off = cursor_file;
        o.vaddr = cursor_vaddr;
        if o.is_bss {
            cursor_vaddr += o.bss_size;
        } else {
            cursor_file += o.data.len() as u64;
            cursor_vaddr += o.data.len() as u64;
        }
    }

    // Snapshot vaddrs so address resolution doesn't borrow the section
    // vector while relocations mutate it.
    let out_vaddrs: Vec<u64> = outs.iter().map(|o| o.vaddr).collect();

    // Linker-provided symbol addresses. Absent sections yield an empty
    // range at the image's end so bracket loops iterate zero times.
    let anchor = order
        .iter()
        .map(|&i| {
            out_vaddrs[i]
                + if outs[i].is_bss {
                    outs[i].bss_size
                } else {
                    outs[i].data.len() as u64
                }
        })
        .max()
        .unwrap_or(BASE_VADDR);
    let bounds = |name: &str| -> Option<(u64, u64)> {
        outs.iter()
            .enumerate()
            .find(|(_, o)| o.name == name)
            .map(|(i, o)| {
                let sz = if o.is_bss {
                    o.bss_size
                } else {
                    o.data.len() as u64
                };
                (out_vaddrs[i], out_vaddrs[i] + sz)
            })
    };
    let (pre_s, pre_e) = bounds(".preinit_array").unwrap_or((anchor, anchor));
    let (ini_s, ini_e) = bounds(".init_array").unwrap_or((anchor, anchor));
    let (fin_s, fin_e) = bounds(".fini_array").unwrap_or((anchor, anchor));
    let (rip_s, rip_e) = bounds(".rela.plt").unwrap_or((anchor, anchor));
    let got_base = bounds(".got").map(|(s, _)| s).unwrap_or(anchor);
    let bss_start = order
        .iter()
        .find(|&&i| outs[i].is_bss)
        .map(|&i| out_vaddrs[i])
        .unwrap_or(anchor);
    let edata = order
        .iter()
        .filter(|&&i| !outs[i].is_bss && outs[i].flags & SHF_WRITE != 0)
        .map(|&i| out_vaddrs[i] + outs[i].data.len() as u64)
        .max()
        .unwrap_or(anchor);
    // Parallel to LINKER_SYMS.
    let linker_addr: [u64; 13] = [
        pre_s, pre_e, ini_s, ini_e, fin_s, fin_e, rip_s, rip_e, BASE_VADDR, got_base, bss_start,
        edata, anchor,
    ];

    // Raw definition address, bypassing ifunc indirection (used for the
    // IRELATIVE resolver addend).
    let raw_addr = |doi: usize, dsi: usize| -> Result<u64, ElfError> {
        let d = &objects[doi].symbols[dsi];
        if d.shndx == SHN_ABS {
            return Ok(d.value);
        }
        if d.shndx == SHN_COMMON {
            let &(out_idx, base) = common_place
                .get(&(doi, dsi))
                .ok_or_else(|| ElfError(format!("unplaced COMMON symbol '{}'", d.name)))?;
            return Ok(out_vaddrs[out_idx] + base);
        }
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("symbol '{}' has no section", d.name)))?;
        let &(out_idx, sec_base) = place
            .get(&(doi, sec))
            .ok_or_else(|| ElfError(format!("unplaced section for symbol '{}'", d.name)))?;
        Ok(out_vaddrs[out_idx] + sec_base + d.value)
    };
    // Reference address: linker pseudo-symbols and ifunc stubs first,
    // then the ordinary definition address. Unsatisfied weak -> 0.
    let sym_vaddr = |oi: usize, si: usize| -> Result<u64, ElfError> {
        // `oi` may already be a resolved definition rather than a raw
        // reference: a GOT/GOT.PLT slot built for a linker-defined symbol
        // (`_end`, `__bss_start`, …) carries `(LINKER_MARK, idx)`. Short-
        // circuit before resolve_def, which would index objects[LINKER_MARK]
        // and panic on a GOTPCREL against such a symbol (audit L7).
        if oi == LINKER_MARK {
            return Ok(linker_addr[si]);
        }
        let (doi, dsi) = match resolve_def(oi, si)? {
            Some(d) => d,
            None => return Ok(0),
        };
        if doi == LINKER_MARK {
            return Ok(linker_addr[dsi]);
        }
        if objects[doi].symbols[dsi].typ == STT_GNU_IFUNC {
            if let Some(&idx) = iplt_of.get(&(doi, dsi)) {
                return Ok(out_vaddrs[iplt_out.unwrap()] + (idx * 16) as u64);
            }
        }
        raw_addr(doi, dsi)
    };

    // Fill IPLT stubs, their GOT.PLT slots, and the IRELATIVE table the
    // static startup applies.
    if let (Some(ii), Some(gi), Some(ri)) = (iplt_out, gotplt_out, relaplt_out) {
        let iplt_base = out_vaddrs[ii];
        let gotplt_base = out_vaddrs[gi];
        let mut entries: Vec<((usize, usize), usize)> =
            iplt_of.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by_key(|&(_, v)| v);
        for (def, idx) in entries {
            let slot_addr = gotplt_base + (idx * 8) as u64;
            let stub_addr = iplt_base + (idx * 16) as u64;
            let resolver = raw_addr(def.0, def.1)?;
            // jmp *slot(%rip) ; nop-padded to 16 bytes.
            let disp = (slot_addr as i64 - (stub_addr as i64 + 6)) as i32;
            let so = idx * 16;
            outs[ii].data[so] = 0xff;
            outs[ii].data[so + 1] = 0x25;
            outs[ii].data[so + 2..so + 6].copy_from_slice(&disp.to_le_bytes());
            for b in outs[ii].data[so + 6..so + 16].iter_mut() {
                *b = 0x90;
            }
            // GOT.PLT slot: the resolver installs the real address; seed
            // with the resolver so a pre-startup call still lands somewhere
            // valid.
            let go = idx * 8;
            outs[gi].data[go..go + 8].copy_from_slice(&resolver.to_le_bytes());
            // RELA IRELATIVE: r_offset = slot, r_info = IRELATIVE, r_addend
            // = resolver.
            let ro = idx * 24;
            outs[ri].data[ro..ro + 8].copy_from_slice(&slot_addr.to_le_bytes());
            outs[ri].data[ro + 8..ro + 16]
                .copy_from_slice(&(R_X86_64_IRELATIVE as u64).to_le_bytes());
            outs[ri].data[ro + 16..ro + 24].copy_from_slice(&(resolver as i64).to_le_bytes());
        }
    }

    // Fill GOT slots now that every definition has a final address /
    // tpoff.
    if let Some(gi) = got_out {
        for (slot, entry) in got_entries.iter().enumerate() {
            let val: u64 = match entry {
                GotEntry::Addr(Some((doi, dsi))) => sym_vaddr(*doi, *dsi)?,
                GotEntry::Addr(None) => 0,
                GotEntry::TpOff((doi, dsi)) => tls_offset(*doi, *dsi)? as u64,
            };
            let off = slot * 8;
            outs[gi].data[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    // Pre-pass: a TLSGD/TLSLD sequence is relaxed to local-exec in
    // place, which overwrites the paired `call __tls_get_addr` and its
    // PLT32 relocation. Collect those paired reloc offsets so the apply
    // loop skips them (they may precede the TLS reloc in the table).
    let mut suppressed: HashSet<(usize, usize, u64)> = HashSet::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            for r in &sec.relas {
                match r.r_type {
                    R_X86_64_TLSGD => {
                        suppressed.insert((oi, si, r.offset + 8));
                    }
                    R_X86_64_TLSLD => {
                        suppressed.insert((oi, si, r.offset + 5));
                    }
                    _ => {}
                }
            }
        }
    }

    // ---- Apply relocations into the merged section bytes.
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            let (out_idx, base) = if let Some(&placed) = place.get(&(oi, si)) {
                placed
            } else if sec.sh_flags & SHF_TLS != 0 && sec.sh_type != SHT_NOBITS {
                let out_idx = tls_out.ok_or_else(|| {
                    ElfError(format!(
                        "relocations in TLS section '{}' ({}) have no PT_TLS image",
                        sec.name, obj.name
                    ))
                })?;
                let base = *tls_place.get(&(oi, si)).ok_or_else(|| {
                    ElfError(format!(
                        "TLS section '{}' ({}) is unplaced",
                        sec.name, obj.name
                    ))
                })?;
                (out_idx, base)
            } else {
                if !sec.relas.is_empty() {
                    return err(format!(
                        "relocations in unplaced section '{}' ({}) are unsupported",
                        sec.name, obj.name
                    ));
                }
                continue;
            };
            for r in &sec.relas {
                if suppressed.contains(&(oi, si, r.offset)) {
                    continue;
                }
                // TLS symbols live in the TLS block, not the section
                // placement map, so resolve their address only for
                // non-TLS relocations.
                let is_tls = matches!(
                    r.r_type,
                    R_X86_64_TPOFF32
                        | R_X86_64_GOTTPOFF
                        | R_X86_64_TLSGD
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
                        | R_X86_64_DTPOFF64
                );
                let s = if is_tls {
                    0
                } else {
                    sym_vaddr(oi, r.sym as usize)?
                };
                let p = out_vaddrs[out_idx] + base + r.offset;
                let spot = (base + r.offset) as usize;
                match r.r_type {
                    R_X86_64_64 => {
                        let v = (s as i64 + r.addend) as u64;
                        outs[out_idx].data[spot..spot + 8].copy_from_slice(&v.to_le_bytes());
                    }
                    R_X86_64_32 => {
                        let bytes = encode_abs32(s as i64 + r.addend, false, p)?;
                        outs[out_idx].data[spot..spot + 4].copy_from_slice(&bytes);
                    }
                    R_X86_64_32S => {
                        let bytes = encode_abs32(s as i64 + r.addend, true, p)?;
                        outs[out_idx].data[spot..spot + 4].copy_from_slice(&bytes);
                    }
                    // Static link, target defined: PLT32 == PC32.
                    R_X86_64_PC32 | R_X86_64_PLT32 => {
                        let v = s as i64 + r.addend - p as i64;
                        if v < i32::MIN as i64 || v > i32::MAX as i64 {
                            return err(format!("PC32 overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as i32).to_le_bytes());
                    }
                    // GOT-relative load of the target's address: patch the
                    // displacement to point at the target's GOT slot.
                    t if is_gotpcrel(t) => {
                        let def = resolve_def(oi, r.sym as usize)?;
                        let ga = out_vaddrs[got_out.unwrap()] + (got_addr_slot(def) * 8) as u64;
                        let v = ga as i64 + r.addend - p as i64;
                        if v < i32::MIN as i64 || v > i32::MAX as i64 {
                            return err(format!("GOTPCREL displacement overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as i32).to_le_bytes());
                    }
                    // TLS local-exec: the offset is a signed constant from
                    // the thread pointer.
                    R_X86_64_TPOFF32 | R_X86_64_DTPOFF32 => {
                        let v = tls_offset(oi, r.sym as usize)? + r.addend;
                        if v < i32::MIN as i64 || v > i32::MAX as i64 {
                            return err(format!("TLS offset overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as i32).to_le_bytes());
                    }
                    R_X86_64_DTPOFF64 => {
                        let v = tls_offset(oi, r.sym as usize)? + r.addend;
                        outs[out_idx].data[spot..spot + 8].copy_from_slice(&v.to_le_bytes());
                    }
                    // TLS initial-exec: load the tpoff from a GOT slot.
                    R_X86_64_GOTTPOFF => {
                        let d = resolve_def(oi, r.sym as usize)?
                            .ok_or_else(|| ElfError("TLS IE against undefined symbol".into()))?;
                        let ga = out_vaddrs[got_out.unwrap()] + (got_tpoff_of[&d] * 8) as u64;
                        let v = ga as i64 + r.addend - p as i64;
                        if v < i32::MIN as i64 || v > i32::MAX as i64 {
                            return err(format!("GOTTPOFF displacement overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as i32).to_le_bytes());
                    }
                    // TLS general/local dynamic: relax the __tls_get_addr
                    // call sequence to local-exec in place.
                    R_X86_64_TLSGD => {
                        let tp = tls_offset(oi, r.sym as usize)? + r.addend;
                        relax_tlsgd_to_le(&mut outs[out_idx].data, base + r.offset, tp)?;
                    }
                    R_X86_64_TLSLD => {
                        relax_tlsld_to_le(&mut outs[out_idx].data, base + r.offset)?;
                    }
                    other => {
                        return err(format!(
                            "relocation type {} is out of rung-2 scope (IFUNC pending)",
                            other
                        ))
                    }
                }
            }
        }
    }

    // ---- Fill .eh_frame_hdr now that .eh_frame carries its relocated
    // FDE PCs and both sections have final addresses.
    if let (Some(ei), Some(hi)) = (eh_frame_idx, eh_hdr_idx) {
        let hdr = build_eh_frame_hdr(&outs[ei].data, out_vaddrs[ei], out_vaddrs[hi])?;
        debug_assert_eq!(hdr.len(), outs[hi].data.len());
        outs[hi].data = hdr;
    }

    // ---- Entry.
    let &(eoi, esi) = globals
        .get(entry)
        .ok_or_else(|| ElfError(format!("entry symbol '{}' not defined", entry)))?;
    let e_entry = sym_vaddr(eoi, esi)?;

    // ---- Emit: ehdr, 2 phdrs, section bytes, then section headers
    // (null + mapped sections + .shstrtab) for inspectability.
    let rw_pos = rw_start_idx.unwrap_or(order.len());
    let rx_end = order[..rw_pos]
        .iter()
        .map(|&i| outs[i].file_off + outs[i].data.len() as u64)
        .max()
        .unwrap_or(ehsize + phsize);
    let rw_file_start = order
        .get(rw_pos)
        .map(|&i| outs[i].file_off & !(PAGE - 1))
        .unwrap_or(0);
    let rw_file_end = order[rw_pos..]
        .iter()
        .map(|&i| outs[i].file_off + outs[i].data.len() as u64)
        .max()
        .unwrap_or(rw_file_start);
    let rw_vaddr_start = order
        .get(rw_pos)
        .map(|&i| outs[i].vaddr & !(PAGE - 1))
        .unwrap_or(0);
    let rw_mem_end = order[rw_pos..]
        .iter()
        .map(|&i| {
            outs[i].vaddr
                + if outs[i].is_bss {
                    outs[i].bss_size
                } else {
                    outs[i].data.len() as u64
                }
        })
        .max()
        .unwrap_or(rw_vaddr_start);

    let mut image = vec![0u8; rx_end as usize];
    // ELF header.
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // 64-bit
    image[5] = 1; // little-endian
    image[6] = 1; // EV_CURRENT
    image[7] = host_osabi();
    image[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&e_entry.to_le_bytes());
    image[32..40].copy_from_slice(&ehsize.to_le_bytes()); // phoff
    image[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
    image[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
    image[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

    // Program headers: RX PT_LOAD, RW PT_LOAD, then PT_TLS if present.
    let mut ph = Vec::new();
    let phdr =
        |p_type: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64| {
            let mut e = Vec::with_capacity(56);
            e.extend_from_slice(&p_type.to_le_bytes());
            e.extend_from_slice(&flags.to_le_bytes());
            e.extend_from_slice(&off.to_le_bytes());
            e.extend_from_slice(&vaddr.to_le_bytes());
            e.extend_from_slice(&vaddr.to_le_bytes()); // paddr
            e.extend_from_slice(&filesz.to_le_bytes());
            e.extend_from_slice(&memsz.to_le_bytes());
            e.extend_from_slice(&align.to_le_bytes());
            e
        };
    ph.extend(phdr(
        PT_LOAD,
        PF_R | PF_X,
        0,
        BASE_VADDR,
        rx_end,
        rx_end,
        PAGE,
    ));
    if rw_pos < order.len() {
        ph.extend(phdr(
            PT_LOAD,
            PF_R | PF_W,
            rw_file_start,
            rw_vaddr_start,
            rw_file_end - rw_file_start,
            rw_mem_end - rw_vaddr_start,
            PAGE,
        ));
    } else {
        // An empty RW segment at the end of the RX image keeps the base
        // phdr count at 2 for layout determinism.
        ph.extend(phdr(
            PT_LOAD,
            PF_R | PF_W,
            rx_end,
            BASE_VADDR + rx_end,
            0,
            0,
            PAGE,
        ));
    }
    if let Some(ti) = tls_out {
        let tls_file_off = outs[ti].file_off;
        let tls_vaddr = outs[ti].vaddr;
        let tls_filesz = outs[ti].data.len() as u64;
        ph.extend(phdr(
            PT_TLS,
            PF_R,
            tls_file_off,
            tls_vaddr,
            tls_filesz,
            tls_memsz,
            tls_align,
        ));
    }
    if let Some(hi) = eh_hdr_idx {
        let len = outs[hi].data.len() as u64;
        ph.extend(phdr(
            PT_GNU_EH_FRAME,
            PF_R,
            outs[hi].file_off,
            outs[hi].vaddr,
            len,
            len,
            4,
        ));
    }
    // Non-executable stack marker (RW, no PF_X). Its absence makes Linux
    // grant an executable stack via READ_IMPLIES_EXEC.
    ph.extend(phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0));
    image[64..64 + ph.len()].copy_from_slice(&ph);

    // Section bytes.
    for &i in &order {
        let o = &outs[i];
        if o.is_bss {
            continue;
        }
        let start = o.file_off as usize;
        if image.len() < start + o.data.len() {
            image.resize(start + o.data.len(), 0);
        }
        image[start..start + o.data.len()].copy_from_slice(&o.data);
    }
    if (image.len() as u64) < rw_file_end {
        image.resize(rw_file_end as usize, 0);
    }

    // Section headers for inspectability: null + mapped + .shstrtab.
    let mut shstr: Vec<u8> = vec![0];
    let name_off = |s: &str, shstr: &mut Vec<u8>| -> u32 {
        let off = shstr.len() as u32;
        shstr.extend_from_slice(s.as_bytes());
        shstr.push(0);
        off
    };
    let mut shdrs: Vec<[u8; 64]> = vec![[0u8; 64]];
    for &i in &order {
        let o = &outs[i];
        let mut h = [0u8; 64];
        let n = name_off(&o.name, &mut shstr);
        h[0..4].copy_from_slice(&n.to_le_bytes());
        h[4..8].copy_from_slice(&(if o.is_bss { SHT_NOBITS } else { SHT_PROGBITS }).to_le_bytes());
        h[8..16].copy_from_slice(&o.flags.to_le_bytes());
        h[16..24].copy_from_slice(&o.vaddr.to_le_bytes());
        h[24..32].copy_from_slice(&o.file_off.to_le_bytes());
        h[32..40].copy_from_slice(
            &(if o.is_bss {
                o.bss_size
            } else {
                o.data.len() as u64
            })
            .to_le_bytes(),
        );
        h[48..56].copy_from_slice(&o.align.to_le_bytes());
        shdrs.push(h);
    }
    let shstr_name = name_off(".shstrtab", &mut shstr);
    let shstr_off = image.len() as u64;
    image.extend_from_slice(&shstr);
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&shstr_name.to_le_bytes());
    h[4..8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
    h[24..32].copy_from_slice(&shstr_off.to_le_bytes());
    h[32..40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
    h[48..56].copy_from_slice(&1u64.to_le_bytes());
    shdrs.push(h);

    while !image.len().is_multiple_of(8) {
        image.push(0);
    }
    let shoff = image.len() as u64;
    for h in &shdrs {
        image.extend_from_slice(h);
    }
    image[40..48].copy_from_slice(&shoff.to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
    image[60..62].copy_from_slice(&(shdrs.len() as u16).to_le_bytes());
    image[62..64].copy_from_slice(&((shdrs.len() - 1) as u16).to_le_bytes()); // shstrndx

    Ok(image)
}

/// SysV ELF hash (for the `.hash` section the dynamic loader walks).
fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

fn find_dynamic_group_end(
    inputs: &[DynamicInput],
    start: usize,
    end: usize,
) -> Result<usize, ElfError> {
    let mut depth = 0usize;
    for (i, input) in inputs.iter().enumerate().take(end).skip(start) {
        match input {
            DynamicInput::GroupStart => depth += 1,
            DynamicInput::GroupEnd if depth == 0 => return Ok(i),
            DynamicInput::GroupEnd => depth -= 1,
            _ => {}
        }
    }
    err("ELF link has --start-group without matching --end-group")
}

fn process_dynamic_range(
    inputs: &mut [DynamicInput],
    start: usize,
    end: usize,
    objects: &mut Vec<ElfObject>,
    defined: &mut HashSet<String>,
    shared: &mut Vec<SharedLib>,
) -> Result<bool, ElfError> {
    let mut changed = false;
    let mut i = start;
    while i < end {
        if matches!(inputs[i], DynamicInput::GroupStart) {
            let group_end = find_dynamic_group_end(inputs, i + 1, end)?;
            loop {
                let pass_changed =
                    process_dynamic_range(inputs, i + 1, group_end, objects, defined, shared)?;
                if !pass_changed {
                    break;
                }
                changed = true;
            }
            i = group_end + 1;
            continue;
        }
        if matches!(inputs[i], DynamicInput::GroupEnd) {
            return err("ELF link has --end-group without matching --start-group");
        }
        match &mut inputs[i] {
            DynamicInput::Object(obj) => {
                if let Some(obj) = obj.take() {
                    add_object(obj, objects, defined);
                    changed = true;
                }
            }
            DynamicInput::Archive(archive) => {
                changed |= scan_archive(archive, objects, defined, "dynamic")?;
            }
            DynamicInput::Shared(lib) => {
                if let Some(lib) = lib.take() {
                    defined.extend(lib.exports.keys().cloned());
                    shared.push(lib);
                    changed = true;
                }
            }
            DynamicInput::GroupStart | DynamicInput::GroupEnd => unreachable!(),
        }
        i += 1;
    }
    Ok(changed)
}

/// Link ordered inputs into a dynamically-linked ET_EXEC that runs under
/// `interp`. Archives are searched at their command-line position and
/// shared libraries satisfy imports only after they are encountered.
pub fn link_dynamic(
    inputs: Vec<DynamicLinkInput>,
    entry: &str,
    interp: &str,
    eh_frame_hdr: bool,
) -> Result<Vec<u8>, ElfError> {
    let mut inputs: Vec<DynamicInput> = inputs.into_iter().map(dynamic_state).collect();
    let mut objects = Vec::new();
    let mut defined = HashSet::new();
    let mut shared = Vec::new();
    let end = inputs.len();
    process_dynamic_range(&mut inputs, 0, end, &mut objects, &mut defined, &mut shared)?;

    link_dynamic_exec(&objects, &shared, entry, interp, eh_frame_hdr)
}

pub fn link_dynamic_exec(
    objects: &[ElfObject],
    shared: &[SharedLib],
    entry: &str,
    interp: &str,
    eh_frame_hdr: bool,
) -> Result<Vec<u8>, ElfError> {
    const DBASE: u64 = 0x20_0000;

    // ---- Merge input sections (text/rodata/data/bss). Init/fini arrays
    // merge priority-ordered in a separate pass so their bracket symbols
    // cover every contribution. TLS sections form the PT_TLS template.
    let mut outs: Vec<OutSec> = Vec::new();
    let mut out_index: HashMap<String, usize> = HashMap::new();
    let mut place: Placement = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS != 0 || array_kind(&sec.name).is_some() {
                continue;
            }
            let is_bss = sec.sh_type == SHT_NOBITS;
            let idx = *out_index.entry(sec.name.clone()).or_insert_with(|| {
                outs.push(OutSec {
                    name: sec.name.clone(),
                    flags: sec.sh_flags,
                    align: 1,
                    data: Vec::new(),
                    bss_size: 0,
                    vaddr: 0,
                    file_off: 0,
                    is_bss,
                });
                outs.len() - 1
            });
            let out = &mut outs[idx];
            if out.is_bss != is_bss {
                return err(format!(
                    "section '{}' is NOBITS in some objects and PROGBITS in others",
                    sec.name
                ));
            }
            out.align = out.align.max(sec.sh_addralign);
            let cursor = if is_bss {
                let c = next_multiple(out.bss_size, sec.sh_addralign);
                out.bss_size = c + sec.nobits_size;
                c
            } else {
                let c = next_multiple(out.data.len() as u64, sec.sh_addralign);
                out.data.resize(c as usize, 0);
                out.data.extend_from_slice(&sec.data);
                c
            };
            place.insert((oi, si), (idx, cursor));
        }
    }

    // ---- Resolve defined globals: weak/strong coalescing plus
    // deterministic version aliasing (see resolve_globals), then allocate
    // coalesced COMMON storage into .bss before layout.
    let globals = resolve_globals(objects)?;
    let common_place = place_common_symbols(objects, &globals, &mut outs, &mut out_index)?;

    for base in [".preinit_array", ".init_array", ".fini_array"] {
        let mut parts: Vec<(u64, usize, usize, usize)> = Vec::new();
        for (oi, obj) in objects.iter().enumerate() {
            for (si, sec) in obj.sections.iter().enumerate() {
                if let Some((b, prio)) = array_kind(&sec.name) {
                    if b == base {
                        parts.push((prio, oi, si, parts.len()));
                    }
                }
            }
        }
        if parts.is_empty() {
            continue;
        }
        parts.sort_by_key(|&(prio, _, _, orig)| (prio, orig));
        let mut align = 8u64;
        for &(_, oi, si, _) in &parts {
            align = align.max(objects[oi].sections[si].sh_addralign);
        }
        let idx = outs.len();
        outs.push(OutSec {
            name: base.to_string(),
            flags: SHF_ALLOC | SHF_WRITE,
            align,
            data: Vec::new(),
            bss_size: 0,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        for &(_, oi, si, _) in &parts {
            let sec = &objects[oi].sections[si];
            let c = next_multiple(outs[idx].data.len() as u64, sec.sh_addralign);
            outs[idx].data.resize(c as usize, 0);
            outs[idx].data.extend_from_slice(&sec.data);
            place.insert((oi, si), (idx, c));
        }
    }

    let mut tls_data: Vec<u8> = Vec::new();
    let mut tls_align: u64 = 1;
    let mut tls_place: HashMap<(usize, usize), u64> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS == 0 || sec.sh_type == SHT_NOBITS {
                continue;
            }
            tls_align = tls_align.max(sec.sh_addralign);
            let c = next_multiple(tls_data.len() as u64, sec.sh_addralign);
            tls_data.resize(c as usize, 0);
            tls_data.extend_from_slice(&sec.data);
            tls_place.insert((oi, si), c);
        }
    }
    let tls_bss_base = tls_data.len() as u64;
    let mut tls_bss: u64 = 0;
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS == 0 || sec.sh_type != SHT_NOBITS {
                continue;
            }
            tls_align = tls_align.max(sec.sh_addralign);
            let c = next_multiple(tls_bss, sec.sh_addralign);
            tls_place.insert((oi, si), tls_bss_base + c);
            tls_bss = c + sec.nobits_size;
        }
    }
    let tls_memsz = tls_bss_base + tls_bss;
    let tls_neg_base = next_multiple(tls_memsz, tls_align) as i64;
    let tls_out = if tls_memsz > 0 {
        let name = if tls_data.is_empty() {
            ".tbss"
        } else {
            ".tdata"
        };
        outs.push(OutSec {
            name: name.to_string(),
            flags: SHF_ALLOC | SHF_WRITE | SHF_TLS,
            align: tls_align,
            data: std::mem::take(&mut tls_data),
            bss_size: tls_bss,
            vaddr: 0,
            file_off: 0,
            is_bss: false,
        });
        Some(outs.len() - 1)
    } else {
        None
    };

    let tls_def = |oi: usize, si: usize| -> Result<(usize, usize), ElfError> {
        let sym = &objects[oi].symbols[si];
        if sym.shndx != SHN_UNDEF {
            return Ok(resolve_defined_identity(objects, &globals, oi, si));
        }
        if let Some(&d) = globals.get(&sym.name) {
            return Ok(d);
        }
        err(format!(
            "TLS relocation against undefined symbol '{}' in {}",
            sym.name, objects[oi].name
        ))
    };
    let tls_offset = |oi: usize, si: usize| -> Result<i64, ElfError> {
        let (doi, dsi) = tls_def(oi, si)?;
        let d = &objects[doi].symbols[dsi];
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("TLS symbol '{}' has no section", d.name)))?;
        let block_off = *tls_place
            .get(&(doi, sec))
            .ok_or_else(|| ElfError(format!("TLS symbol '{}' is not in a TLS section", d.name)))?;
        Ok(block_off as i64 + d.value as i64 - tls_neg_base)
    };

    // ---- Imports: undefined strong globals a shared library exports.
    // Function imports get a PLT slot (JUMP_SLOT); data imports get a
    // GOT slot (GLOB_DAT). Each import records its owning library and the
    // default version the library binds it to (empty when unversioned).
    let mut imports: Vec<String> = Vec::new();
    let mut import_lib: Vec<usize> = Vec::new();
    let mut import_ver: Vec<String> = Vec::new();
    let mut import_is_func: Vec<bool> = Vec::new();
    let mut import_index: HashMap<String, usize> = HashMap::new();
    let mut used_lib = vec![false; shared.len()];
    for obj in objects {
        for sym in &obj.symbols {
            if sym.shndx != SHN_UNDEF
                || sym.bind != STB_GLOBAL
                || sym.name.is_empty()
                || LINKER_SYMS.contains(&sym.name.as_str())
                || sym.name == "__tls_get_addr"
                || globals.contains_key(&sym.name)
                || import_index.contains_key(&sym.name)
            {
                continue;
            }
            let Some(li) = shared
                .iter()
                .position(|l| l.exports.contains_key(&sym.name))
            else {
                return err(format!(
                    "undefined symbol '{}' (referenced from {}) — not exported by any shared object",
                    sym.name, obj.name
                ));
            };
            let export = &shared[li].exports[&sym.name];
            used_lib[li] = true;
            import_index.insert(sym.name.clone(), imports.len());
            import_lib.push(li);
            import_ver.push(export.version.clone());
            import_is_func.push(export.func);
            imports.push(sym.name.clone());
        }
    }
    let n_imp = imports.len();

    // Function imports drive the PLT; `func_slot[i]` is the k-th function
    // import's dense PLT/`.got.plt` slot (data imports have None).
    let mut func_slot: Vec<Option<usize>> = vec![None; n_imp];
    let mut n_func = 0usize;
    for i in 0..n_imp {
        if import_is_func[i] {
            func_slot[i] = Some(n_func);
            n_func += 1;
        }
    }
    // No function imports ⇒ no PLT/.got.plt/.rela.plt at all (a data-only
    // dynamic executable), matching what a reference linker emits.
    let has_plt = n_func > 0;

    // Canonical PLT (audit L6): when a non-PIE executable takes the address
    // of a function defined in a shared object, `&func` must have one
    // identity on both sides of the .so boundary. The psABI ("Function
    // Addresses") resolves this by giving the import's .dynsym entry a
    // non-zero st_value pointing at the executable's own PLT stub, while
    // keeping st_shndx=SHN_UNDEF. A plain `call func@plt` (R_X86_64_PLT32)
    // does not need this; any other relocation against a function import is
    // a direct address-take that does.
    let mut addr_taken = vec![false; n_imp];
    for obj in objects.iter() {
        for sec in &obj.sections {
            for r in &sec.relas {
                if r.r_type == R_X86_64_PLT32 {
                    continue;
                }
                let sym = &obj.symbols[r.sym as usize];
                if sym.shndx != SHN_UNDEF {
                    continue;
                }
                if let Some(&ii) = import_index.get(&sym.name) {
                    if import_is_func[ii] {
                        addr_taken[ii] = true;
                    }
                }
            }
        }
    }

    // ---- GOT pre-pass: one `.got` slot per distinct GOTPCREL target.
    // Imports become GLOB_DAT (loader fills); in-image symbols hold their
    // absolute address. Sizes the `.got`/`.rela.dyn` sections before
    // layout; contents are filled once addresses are known.
    let got_key = |oi: usize, r: &Rela| -> Result<(String, GotSlot), ElfError> {
        let sym = &objects[oi].symbols[r.sym as usize];
        if sym.shndx == SHN_UNDEF {
            if let Some(&ii) = import_index.get(&sym.name) {
                Ok((format!("i:{}", sym.name), GotSlot::GlobDat((ii as u32) + 1)))
            } else if let Some(&(doi, dsi)) = globals.get(&sym.name) {
                Ok((format!("d:{doi}:{dsi}"), GotSlot::Defined(doi, dsi)))
            } else if let Some(idx) = LINKER_SYMS.iter().position(|&n| n == sym.name) {
                Ok((format!("l:{idx}"), GotSlot::Defined(LINKER_MARK, idx)))
            } else if sym.bind == STB_WEAK {
                Ok((format!("w:{}", sym.name), GotSlot::Zero))
            } else {
                err(format!("undefined symbol '{}' (GOTPCREL)", sym.name))
            }
        } else {
            let (doi, dsi) = resolve_defined_identity(objects, &globals, oi, r.sym as usize);
            Ok((format!("d:{doi}:{dsi}"), GotSlot::Defined(doi, dsi)))
        }
    };
    let mut got_slot_of: HashMap<String, usize> = HashMap::new();
    let mut got_kind: Vec<GotSlot> = Vec::new();
    for (oi, obj) in objects.iter().enumerate() {
        for sec in &obj.sections {
            for r in &sec.relas {
                if is_gotpcrel(r.r_type) {
                    let (key, kind) = got_key(oi, r)?;
                    if let std::collections::hash_map::Entry::Vacant(e) = got_slot_of.entry(key) {
                        e.insert(got_kind.len());
                        got_kind.push(kind);
                    }
                } else if r.r_type == R_X86_64_GOTTPOFF {
                    let (doi, dsi) = tls_def(oi, r.sym as usize)?;
                    let key = format!("t:{doi}:{dsi}");
                    if let std::collections::hash_map::Entry::Vacant(e) = got_slot_of.entry(key) {
                        e.insert(got_kind.len());
                        got_kind.push(GotSlot::TpOff(doi, dsi));
                    }
                }
            }
        }
    }
    let n_got = got_kind.len();
    let got_size = (n_got * 8) as u64;
    let n_glob_dat = got_kind
        .iter()
        .filter(|k| matches!(k, GotSlot::GlobDat(_)))
        .count();
    let reladyn_size = (n_glob_dat * 24) as u64;

    // ---- Version requirements. Assign a `.gnu.version` index (>=2) per
    // distinct (library, version) among versioned imports, in first-seen
    // order; `import_vidx[i]` is the index a versioned import references.
    let mut import_vidx: Vec<u16> = vec![0; n_imp];
    // (library index, version name) for each distinct requirement.
    let mut ver_reqs: Vec<(usize, String)> = Vec::new();
    let mut next_vidx: u16 = 2;
    for i in 0..n_imp {
        if import_ver[i].is_empty() {
            continue;
        }
        let key = (import_lib[i], import_ver[i].clone());
        let idx = match ver_reqs.iter().position(|r| *r == key) {
            Some(j) => (j as u16) + 2,
            None => {
                ver_reqs.push(key);
                let idx = next_vidx;
                next_vidx += 1;
                idx
            }
        };
        import_vidx[i] = idx;
    }
    let versioned = !ver_reqs.is_empty();

    // ---- Exe exports. A symbol the executable defines that a used
    // shared library references undefined must appear as a DEFINED
    // .dynsym entry, so the loader binds the library's reference back to
    // the executable (e.g. crt1.o's `environ`/`__progname`, which libc
    // needs). Driven by library-undef order for determinism.
    let mut export_names: Vec<String> = Vec::new();
    let mut export_def: Vec<(usize, usize)> = Vec::new(); // (obj, sym) of the definition
    {
        let mut seen: HashSet<String> = HashSet::new();
        for (li, lib) in shared.iter().enumerate() {
            if !used_lib[li] {
                continue;
            }
            for u in &lib.undefs {
                if seen.contains(u) {
                    continue;
                }
                if let Some(&(doi, dsi)) = globals.get(u) {
                    seen.insert(u.clone());
                    export_names.push(u.clone());
                    export_def.push((doi, dsi));
                }
            }
        }
    }
    let n_exp = export_names.len();

    // ---- Build .dynstr (soname + import name strings) and note offsets.
    let mut dynstr: Vec<u8> = vec![0];
    let str_off = |s: &str, dynstr: &mut Vec<u8>| -> u32 {
        let off = dynstr.len() as u32;
        dynstr.extend_from_slice(s.as_bytes());
        dynstr.push(0);
        off
    };
    let mut needed_offsets: Vec<u32> = Vec::new();
    let mut soname_off: Vec<u32> = vec![0; shared.len()];
    for (li, lib) in shared.iter().enumerate() {
        if used_lib[li] {
            let off = str_off(&lib.soname, &mut dynstr);
            soname_off[li] = off;
            needed_offsets.push(off);
        }
    }
    let import_name_off: Vec<u32> = imports.iter().map(|n| str_off(n, &mut dynstr)).collect();
    // Version-name strings (parallel to ver_reqs) for VERNEED.
    let ver_name_off: Vec<u32> = ver_reqs
        .iter()
        .map(|(_, ver)| str_off(ver, &mut dynstr))
        .collect();
    let export_name_off: Vec<u32> = export_names
        .iter()
        .map(|n| str_off(n, &mut dynstr))
        .collect();

    // ---- .dynsym: null, then UND imports (FUNC/OBJECT), then DEFINED
    // exports. Export st_value is patched once addresses are known;
    // st_shndx=SHN_ABS (non-PIE — the value is already the final address).
    let n_dynsym = 1 + n_imp + n_exp;
    let mut dynsym = vec![0u8; n_dynsym * 24];
    for (i, &noff) in import_name_off.iter().enumerate() {
        let e = (i + 1) * 24;
        let styp = if import_is_func[i] {
            STT_FUNC
        } else {
            STT_OBJECT
        };
        dynsym[e..e + 4].copy_from_slice(&noff.to_le_bytes());
        dynsym[e + 4] = (STB_GLOBAL << 4) | styp; // st_info
                                                  // st_other=0, st_shndx=0 (UND), value/size=0 already zeroed.
    }
    for (j, &(doi, dsi)) in export_def.iter().enumerate() {
        let e = (1 + n_imp + j) * 24;
        let sym = &objects[doi].symbols[dsi];
        dynsym[e..e + 4].copy_from_slice(&export_name_off[j].to_le_bytes());
        dynsym[e + 4] = (STB_GLOBAL << 4) | sym.typ; // st_info
        dynsym[e + 6..e + 8].copy_from_slice(&SHN_ABS.to_le_bytes()); // st_shndx
        dynsym[e + 16..e + 24].copy_from_slice(&sym.size.to_le_bytes()); // st_size
                                                                         // st_value (e+8..e+16) patched post-layout.
    }

    // The name for .dynsym index i (1-based, imports then exports).
    let dynsym_name = |i: usize| -> &str {
        if i <= n_imp {
            &imports[i - 1]
        } else {
            &export_names[i - 1 - n_imp]
        }
    };

    // ---- .hash (SysV): buckets + chains over every named .dynsym entry.
    let nbucket = (n_dynsym.max(1)) as u32;
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chain = vec![0u32; n_dynsym];
    for (si, c) in chain.iter_mut().enumerate().skip(1) {
        let b = (elf_hash(dynsym_name(si).as_bytes()) % nbucket) as usize;
        *c = buckets[b];
        buckets[b] = si as u32;
    }
    let mut hash: Vec<u8> = Vec::new();
    hash.extend_from_slice(&nbucket.to_le_bytes());
    hash.extend_from_slice(&(n_dynsym as u32).to_le_bytes());
    for b in &buckets {
        hash.extend_from_slice(&b.to_le_bytes());
    }
    for c in &chain {
        hash.extend_from_slice(&c.to_le_bytes());
    }

    // ---- .gnu.version (VERSYM): one u16 per .dynsym entry. Versioned
    // imports carry their assigned index; everything else (unversioned
    // imports, defined exports) is the global base version.
    let mut versym: Vec<u8> = Vec::new();
    if versioned {
        versym.extend_from_slice(&0u16.to_le_bytes()); // null entry
        for &vidx in &import_vidx {
            let vx = if vidx != 0 { vidx } else { VER_NDX_GLOBAL };
            versym.extend_from_slice(&vx.to_le_bytes());
        }
        for _ in 0..n_exp {
            versym.extend_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
        }
    }

    // ---- .gnu.version_r (VERNEED): one Verneed per library that has a
    // version requirement, each with a Vernaux per distinct version.
    let mut verneed: Vec<u8> = Vec::new();
    let mut verneed_count: u32 = 0;
    if versioned {
        let mut libs_with_ver: Vec<usize> = Vec::new();
        for (li, _) in &ver_reqs {
            if !libs_with_ver.contains(li) {
                libs_with_ver.push(*li);
            }
        }
        verneed_count = libs_with_ver.len() as u32;
        for (vi, &li) in libs_with_ver.iter().enumerate() {
            let aux_idxs: Vec<usize> = (0..ver_reqs.len())
                .filter(|&j| ver_reqs[j].0 == li)
                .collect();
            let last_vn = vi + 1 == libs_with_ver.len();
            let vn_next = if last_vn {
                0u32
            } else {
                (16 + aux_idxs.len() * 16) as u32
            };
            verneed.extend_from_slice(&1u16.to_le_bytes()); // vn_version
            verneed.extend_from_slice(&(aux_idxs.len() as u16).to_le_bytes()); // vn_cnt
            verneed.extend_from_slice(&soname_off[li].to_le_bytes()); // vn_file
            verneed.extend_from_slice(&16u32.to_le_bytes()); // vn_aux
            verneed.extend_from_slice(&vn_next.to_le_bytes()); // vn_next
            for (ai, &j) in aux_idxs.iter().enumerate() {
                let last_aux = ai + 1 == aux_idxs.len();
                let vna_next = if last_aux { 0u32 } else { 16u32 };
                let vidx = (j as u16) + 2;
                verneed.extend_from_slice(&elf_hash(ver_reqs[j].1.as_bytes()).to_le_bytes()); // vna_hash
                verneed.extend_from_slice(&0u16.to_le_bytes()); // vna_flags
                verneed.extend_from_slice(&vidx.to_le_bytes()); // vna_other
                verneed.extend_from_slice(&ver_name_off[j].to_le_bytes()); // vna_name
                verneed.extend_from_slice(&vna_next.to_le_bytes()); // vna_next
            }
        }
    }

    // Section byte sizes now known; build .interp, size .plt/.got.plt/
    // .rela.plt/.dynamic (contents filled after vaddrs are assigned).
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let plt_size = if has_plt {
        ((n_func + 1) * 16) as u64
    } else {
        0
    }; // PLT0 + stub/func
    let gotplt_size = if has_plt {
        ((n_func + 3) * 8) as u64
    } else {
        0
    }; // 3 reserved + func
    let relaplt_size = (n_func * 24) as u64;
    let n_needed = needed_offsets.len();
    // .dynamic entry count: NEEDED* + base tags (HASH/STRTAB/SYMTAB/STRSZ/
    // SYMENT/FLAGS) + PLT tags (PLTGOT/PLTRELSZ/PLTREL/JMPREL, only with a
    // PLT) + versioning tags (VERSYM/VERNEED/VERNEEDNUM) + .rela.dyn tags
    // (RELA/RELASZ/RELAENT) + NULL.
    let n_base_dyn = 6;
    let n_plt_dyn = if has_plt { 4 } else { 0 };
    let n_ver_dyn = if versioned { 3 } else { 0 };
    let n_reladyn_dyn = if reladyn_size > 0 { 3 } else { 0 };
    let dynamic_count = n_needed + n_base_dyn + n_plt_dyn + n_ver_dyn + n_reladyn_dyn + 1;
    let dynamic_size = (dynamic_count * 16) as u64;

    // ---- Layout. Fixed section order across three load segments.
    // `.eh_frame` (now retained) gets a synthesized `.eh_frame_hdr` +
    // PT_GNU_EH_FRAME when `--eh-frame-hdr` is requested; size it here
    // (structure is reloc-invariant) so phnum and the RO layout account
    // for it.
    let eh_frame_idx = if eh_frame_hdr {
        outs.iter()
            .position(|o| o.name == ".eh_frame" && !o.data.is_empty())
    } else {
        None
    };
    let eh_hdr_size = match eh_frame_idx {
        Some(ei) => 12 + parse_eh_frame_fdes(&outs[ei].data, 0)?.len() as u64 * 8,
        None => 0,
    };
    let ehsize = 64u64;
    // 3 LOAD + INTERP + DYNAMIC + GNU_STACK, plus PT_TLS /
    // GNU_EH_FRAME when present.
    let phnum = 6u64 + if tls_out.is_some() { 1 } else { 0 } + if eh_hdr_size > 0 { 1 } else { 0 };
    let phsize = 56 * phnum;

    // Metadata region (PF_R): synthetic sections in a fixed order.
    let mut v = DBASE + ehsize + phsize;
    let mut fo = ehsize + phsize;
    let place_ro = |sz: u64, align: u64, v: &mut u64, fo: &mut u64| -> (u64, u64) {
        *v = next_multiple(*v, align);
        *fo = next_multiple(*fo, align);
        let a = (*v, *fo);
        *v += sz;
        *fo += sz;
        a
    };
    let (interp_v, interp_fo) = place_ro(interp_bytes.len() as u64, 1, &mut v, &mut fo);
    let (dynsym_v, dynsym_fo) = place_ro(dynsym.len() as u64, 8, &mut v, &mut fo);
    let (hash_v, hash_fo) = place_ro(hash.len() as u64, 8, &mut v, &mut fo);
    let (dynstr_v, dynstr_fo) = place_ro(dynstr.len() as u64, 1, &mut v, &mut fo);
    let (versym_v, versym_fo) = place_ro(versym.len() as u64, 2, &mut v, &mut fo);
    let (verneed_v, verneed_fo) = place_ro(verneed.len() as u64, 4, &mut v, &mut fo);
    let (reladyn_v, reladyn_fo) = place_ro(reladyn_size, 8, &mut v, &mut fo);
    let (relaplt_v, relaplt_fo) = place_ro(relaplt_size, 8, &mut v, &mut fo);
    let (eh_hdr_v, eh_hdr_fo) = if eh_hdr_size > 0 {
        let (vv, ff) = place_ro(eh_hdr_size, 4, &mut v, &mut fo);
        (Some(vv), Some(ff))
    } else {
        (None, None)
    };
    // Merged rodata (read-only, non-writable, non-exec) joins the RO seg.
    let ro_order: Vec<usize> = (0..outs.len())
        .filter(|&i| outs[i].flags & SHF_EXECINSTR == 0 && outs[i].flags & SHF_WRITE == 0)
        .collect();
    for &i in &ro_order {
        let (vv, ff) = place_ro(outs[i].data.len() as u64, outs[i].align, &mut v, &mut fo);
        outs[i].vaddr = vv;
        outs[i].file_off = ff;
    }
    let ro_end_v = v;
    let ro_end_fo = fo;

    // Executable region (PF_R|PF_X) on a new page.
    v = next_multiple(ro_end_v, PAGE);
    fo = next_multiple(ro_end_fo, PAGE);
    // Keep file offset congruent to vaddr mod PAGE.
    let text_order: Vec<usize> = (0..outs.len())
        .filter(|&i| outs[i].flags & SHF_EXECINSTR != 0)
        .collect();
    let rx_start_v = v;
    let rx_start_fo = fo;
    for &i in &text_order {
        outs[i].vaddr = next_multiple(v, outs[i].align);
        outs[i].file_off = rx_start_fo + (outs[i].vaddr - rx_start_v);
        v = outs[i].vaddr + outs[i].data.len() as u64;
    }
    v = next_multiple(v, 16);
    let plt_v = v;
    let plt_fo = rx_start_fo + (plt_v - rx_start_v);
    v += plt_size;
    let rx_end_v = v;

    // Writable region (PF_R|PF_W) on a new page.
    v = next_multiple(rx_end_v, PAGE);
    let rw_start_v = v;
    let rw_start_fo = next_multiple(plt_fo + plt_size, PAGE);
    let data_order: Vec<usize> = (0..outs.len())
        .filter(|&i| outs[i].flags & SHF_WRITE != 0 && !outs[i].is_bss)
        .collect();
    for &i in &data_order {
        outs[i].vaddr = next_multiple(v, outs[i].align);
        outs[i].file_off = rw_start_fo + (outs[i].vaddr - rw_start_v);
        v = outs[i].vaddr + outs[i].data.len() as u64;
    }
    let rw_file_end = rw_start_fo + (next_multiple(v, 8) - rw_start_v);
    v = next_multiple(v, 8);
    let got_v = v;
    let got_fo = rw_start_fo + (got_v - rw_start_v);
    v += got_size;
    v = next_multiple(v, 8);
    let gotplt_v = v;
    let gotplt_fo = rw_start_fo + (gotplt_v - rw_start_v);
    v += gotplt_size;
    v = next_multiple(v, 8);
    let dynamic_v = v;
    let dynamic_fo = rw_start_fo + (dynamic_v - rw_start_v);
    v += dynamic_size;
    let rw_data_end_v = v; // end of file-backed RW
                           // .bss (nobits) after the file-backed RW content.
    let bss_order: Vec<usize> = (0..outs.len()).filter(|&i| outs[i].is_bss).collect();
    for &i in &bss_order {
        outs[i].vaddr = next_multiple(v, outs[i].align.max(1));
        v = outs[i].vaddr + outs[i].bss_size;
    }
    let rw_mem_end_v = v;
    let rw_file_end = rw_file_end
        .max(got_fo + got_size)
        .max(gotplt_fo + gotplt_size)
        .max(dynamic_fo + dynamic_size);

    // Function import k resolves to its PLT stub (PLT0 is slot 0, funcs
    // 1..); its lazy `.got.plt` slot is k+3 (3 reserved). A `.got` slot
    // (data imports, GOTPCREL targets) is addressed by slot index.
    let plt_stub = |func_k: usize| plt_v + ((func_k + 1) * 16) as u64;
    let gotplt_slot = |func_k: usize| gotplt_v + ((func_k + 3) * 8) as u64;
    let got_slot_v = |slot: usize| got_v + (slot * 8) as u64;
    // `_GLOBAL_OFFSET_TABLE_` base: .got.plt when there's a PLT (its slot 0
    // holds _DYNAMIC), otherwise the plain .got.
    let got_base = if has_plt { gotplt_v } else { got_v };

    // ---- Address resolver (vaddr snapshot avoids borrowing `outs`
    // while the relocation loop mutates it).
    let out_vaddrs: Vec<u64> = outs.iter().map(|o| o.vaddr).collect();
    let anchor = rw_mem_end_v;
    let bounds = |name: &str| -> Option<(u64, u64)> {
        outs.iter()
            .enumerate()
            .find(|(_, o)| o.name == name)
            .map(|(i, o)| {
                let sz = if o.is_bss {
                    o.bss_size
                } else {
                    o.data.len() as u64
                };
                (out_vaddrs[i], out_vaddrs[i] + sz)
            })
    };
    let (pre_s, pre_e) = bounds(".preinit_array").unwrap_or((anchor, anchor));
    let (ini_s, ini_e) = bounds(".init_array").unwrap_or((anchor, anchor));
    let (fin_s, fin_e) = bounds(".fini_array").unwrap_or((anchor, anchor));
    let (rip_s, rip_e) = if relaplt_size > 0 {
        (relaplt_v, relaplt_v + relaplt_size)
    } else {
        (anchor, anchor)
    };
    let bss_start = bss_order.first().map(|&i| out_vaddrs[i]).unwrap_or(anchor);
    let linker_addr: [u64; 13] = [
        pre_s,
        pre_e,
        ini_s,
        ini_e,
        fin_s,
        fin_e,
        rip_s,
        rip_e,
        DBASE,
        got_base,
        bss_start,
        rw_data_end_v,
        rw_mem_end_v,
    ];
    let sym_vaddr = |oi: usize, si: usize| -> Result<u64, ElfError> {
        if oi == LINKER_MARK {
            return Ok(linker_addr[si]);
        }
        let sym = &objects[oi].symbols[si];
        let (doi, dsi) = if sym.shndx == SHN_UNDEF {
            if sym.name == "_GLOBAL_OFFSET_TABLE_" {
                return Ok(got_base);
            } else if let Some(idx) = LINKER_SYMS.iter().position(|&n| n == sym.name) {
                return Ok(linker_addr[idx]);
            } else if let Some(&d) = globals.get(&sym.name) {
                d
            } else if let Some(&ii) = import_index.get(&sym.name) {
                return match func_slot[ii] {
                    Some(k) => Ok(plt_stub(k)),
                    // A data import referenced directly (not via GOT) would
                    // need an R_X86_64_COPY relocation — a later rung.
                    None => err(format!(
                        "direct reference to data import '{}' needs a COPY relocation (later rung)",
                        sym.name
                    )),
                };
            } else if sym.bind == STB_WEAK {
                return Ok(0);
            } else {
                return err(format!("undefined symbol '{}'", sym.name));
            }
        } else {
            resolve_defined_identity(objects, &globals, oi, si)
        };
        let d = &objects[doi].symbols[dsi];
        if d.shndx == SHN_ABS {
            return Ok(d.value);
        }
        if d.shndx == SHN_COMMON {
            let &(oidx, base) = common_place
                .get(&(doi, dsi))
                .ok_or_else(|| ElfError(format!("unplaced COMMON symbol '{}'", d.name)))?;
            return Ok(out_vaddrs[oidx] + base);
        }
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("symbol '{}' has no section", d.name)))?;
        let &(oidx, base) = place
            .get(&(doi, sec))
            .ok_or_else(|| ElfError(format!("unplaced section for '{}'", d.name)))?;
        Ok(out_vaddrs[oidx] + base + d.value)
    };

    let mut suppressed: HashSet<(usize, usize, u64)> = HashSet::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            for r in &sec.relas {
                match r.r_type {
                    R_X86_64_TLSGD => {
                        suppressed.insert((oi, si, r.offset + 8));
                    }
                    R_X86_64_TLSLD => {
                        suppressed.insert((oi, si, r.offset + 5));
                    }
                    _ => {}
                }
            }
        }
    }

    // ---- Apply relocations into the merged section bytes.
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            let (out_idx, base) = if let Some(&placed) = place.get(&(oi, si)) {
                placed
            } else if sec.sh_flags & SHF_TLS != 0 && sec.sh_type != SHT_NOBITS {
                let out_idx = tls_out.ok_or_else(|| {
                    ElfError(format!(
                        "relocations in TLS section '{}' ({}) have no PT_TLS image",
                        sec.name, obj.name
                    ))
                })?;
                let base = *tls_place.get(&(oi, si)).ok_or_else(|| {
                    ElfError(format!(
                        "TLS section '{}' ({}) is unplaced",
                        sec.name, obj.name
                    ))
                })?;
                (out_idx, base)
            } else {
                if !sec.relas.is_empty() {
                    return err(format!(
                        "relocations in unplaced section '{}' ({}) are unsupported",
                        sec.name, obj.name
                    ));
                }
                continue;
            };
            for r in &sec.relas {
                if suppressed.contains(&(oi, si, r.offset)) {
                    continue;
                }
                let p = out_vaddrs[out_idx] + base + r.offset;
                let spot = (base + r.offset) as usize;
                // GOTPCREL targets resolve to a `.got` slot, not the symbol.
                if is_gotpcrel(r.r_type) {
                    let (key, _) = got_key(oi, r)?;
                    let slot = got_slot_of[&key];
                    let val = got_slot_v(slot) as i64 + r.addend - p as i64;
                    if !(i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                        return err(format!("GOTPCREL overflow at {:#x}", p));
                    }
                    outs[out_idx].data[spot..spot + 4].copy_from_slice(&(val as i32).to_le_bytes());
                    continue;
                }
                if r.r_type == R_X86_64_GOTTPOFF {
                    let (doi, dsi) = tls_def(oi, r.sym as usize)?;
                    let slot = got_slot_of[&format!("t:{doi}:{dsi}")];
                    let val = got_slot_v(slot) as i64 + r.addend - p as i64;
                    if !(i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                        return err(format!("GOTTPOFF overflow at {:#x}", p));
                    }
                    outs[out_idx].data[spot..spot + 4].copy_from_slice(&(val as i32).to_le_bytes());
                    continue;
                }
                let is_tls = matches!(
                    r.r_type,
                    R_X86_64_TPOFF32
                        | R_X86_64_TLSGD
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
                        | R_X86_64_DTPOFF64
                );
                let s = if is_tls {
                    0
                } else {
                    sym_vaddr(oi, r.sym as usize)?
                };
                match r.r_type {
                    R_X86_64_64 => {
                        let val = (s as i64 + r.addend) as u64;
                        outs[out_idx].data[spot..spot + 8].copy_from_slice(&val.to_le_bytes());
                    }
                    R_X86_64_32 => {
                        let bytes = encode_abs32(s as i64 + r.addend, false, p)?;
                        outs[out_idx].data[spot..spot + 4].copy_from_slice(&bytes);
                    }
                    R_X86_64_32S => {
                        let bytes = encode_abs32(s as i64 + r.addend, true, p)?;
                        outs[out_idx].data[spot..spot + 4].copy_from_slice(&bytes);
                    }
                    R_X86_64_PC32 | R_X86_64_PLT32 => {
                        let val = s as i64 + r.addend - p as i64;
                        if !(i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                            return err(format!("PC32 overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(val as i32).to_le_bytes());
                    }
                    R_X86_64_TPOFF32 | R_X86_64_DTPOFF32 => {
                        let val = tls_offset(oi, r.sym as usize)? + r.addend;
                        if !(i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                            return err(format!("TLS offset overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(val as i32).to_le_bytes());
                    }
                    R_X86_64_DTPOFF64 => {
                        let val = tls_offset(oi, r.sym as usize)? + r.addend;
                        outs[out_idx].data[spot..spot + 8].copy_from_slice(&val.to_le_bytes());
                    }
                    R_X86_64_TLSGD => {
                        let tp = tls_offset(oi, r.sym as usize)? + r.addend;
                        relax_tlsgd_to_le(&mut outs[out_idx].data, base + r.offset, tp)?;
                    }
                    R_X86_64_TLSLD => {
                        relax_tlsld_to_le(&mut outs[out_idx].data, base + r.offset)?;
                    }
                    other => {
                        return err(format!(
                            "relocation type {} is out of the dynamic-link scope",
                            other
                        ))
                    }
                }
            }
        }
    }

    // ---- .eh_frame_hdr contents: .eh_frame now carries its relocated
    // FDE PCs and both sections have final addresses.
    let eh_hdr_bytes = match (eh_frame_idx, eh_hdr_v) {
        (Some(ei), Some(hv)) => build_eh_frame_hdr(&outs[ei].data, outs[ei].vaddr, hv)?,
        _ => Vec::new(),
    };

    // ---- Build .plt. PLT0 pushes GOT[1] and jumps GOT[2]; each stub
    // jumps through its GOT.PLT slot, else falls to the lazy trampoline.
    let disp = |from_end: u64, to: u64| (to as i64 - from_end as i64) as i32;
    let mut plt = vec![0u8; plt_size as usize];
    let mut gotplt = vec![0u8; gotplt_size as usize];
    if has_plt {
        // PLT0: ff 35 <gotplt+8> ; ff 25 <gotplt+16> ; nop nop nop nop
        plt[0] = 0xff;
        plt[1] = 0x35;
        plt[2..6].copy_from_slice(&disp(plt_v + 6, gotplt_v + 8).to_le_bytes());
        plt[6] = 0xff;
        plt[7] = 0x25;
        plt[8..12].copy_from_slice(&disp(plt_v + 12, gotplt_v + 16).to_le_bytes());
        plt[12..16].copy_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
        for &fs in &func_slot {
            let Some(k) = fs else { continue };
            let o = (k + 1) * 16;
            let stub = plt_v + o as u64;
            let slot = gotplt_slot(k);
            // jmp *slot(%rip)
            plt[o] = 0xff;
            plt[o + 1] = 0x25;
            plt[o + 2..o + 6].copy_from_slice(&disp(stub + 6, slot).to_le_bytes());
            // push $k (the .rela.plt index)
            plt[o + 6] = 0x68;
            plt[o + 7..o + 11].copy_from_slice(&(k as u32).to_le_bytes());
            // jmp PLT0
            plt[o + 11] = 0xe9;
            plt[o + 12..o + 16].copy_from_slice(&disp(stub + 16, plt_v).to_le_bytes());
        }
        // .got.plt: [0]=&_DYNAMIC, [1]=[2]=0, [3+k]=stub push insn.
        gotplt[0..8].copy_from_slice(&dynamic_v.to_le_bytes());
        for &fs in &func_slot {
            let Some(k) = fs else { continue };
            let slot = (k + 3) * 8;
            gotplt[slot..slot + 8].copy_from_slice(&(plt_stub(k) + 6).to_le_bytes());
        }
    }

    // ---- Build .rela.plt: one JUMP_SLOT per function import.
    let mut relaplt = vec![0u8; relaplt_size as usize];
    for (i, &fs) in func_slot.iter().enumerate() {
        let Some(k) = fs else { continue };
        let e = k * 24;
        relaplt[e..e + 8].copy_from_slice(&gotplt_slot(k).to_le_bytes());
        let info = ((i as u64 + 1) << 32) | R_X86_64_JUMP_SLOT as u64; // dynsym index i+1
        relaplt[e + 8..e + 16].copy_from_slice(&info.to_le_bytes());
        // addend 0.
    }

    // ---- Build .got and .rela.dyn. Data imports (and address-taken
    // function imports) get a GLOB_DAT the loader fills; in-image
    // GOTPCREL targets hold their absolute address directly (non-PIE).
    let mut got = vec![0u8; got_size as usize];
    for (slot, kind) in got_kind.iter().enumerate() {
        let val = match kind {
            GotSlot::GlobDat(_) | GotSlot::Zero => 0,
            GotSlot::Defined(doi, dsi) => sym_vaddr(*doi, *dsi)?,
            GotSlot::TpOff(doi, dsi) => tls_offset(*doi, *dsi)? as u64,
        };
        got[slot * 8..slot * 8 + 8].copy_from_slice(&val.to_le_bytes());
    }
    let mut reladyn = vec![0u8; reladyn_size as usize];
    {
        let mut e = 0;
        for (slot, kind) in got_kind.iter().enumerate() {
            if let GotSlot::GlobDat(dynidx) = kind {
                reladyn[e..e + 8].copy_from_slice(&got_slot_v(slot).to_le_bytes());
                let info = ((*dynidx as u64) << 32) | R_X86_64_GLOB_DAT as u64;
                reladyn[e + 8..e + 16].copy_from_slice(&info.to_le_bytes());
                e += 24; // addend 0
            }
        }
    }

    // Patch exported symbols' st_value now that addresses are resolved.
    for (j, &(doi, dsi)) in export_def.iter().enumerate() {
        let e = (1 + n_imp + j) * 24;
        let addr = sym_vaddr(doi, dsi)?;
        dynsym[e + 8..e + 16].copy_from_slice(&addr.to_le_bytes());
    }

    // Canonical-PLT st_value (audit L6): point each address-taken function
    // import at its own PLT stub. st_shndx stays SHN_UNDEF, so the exe's
    // JUMP_SLOT (resolved with need_def) still binds to the real definition
    // in the shared object — no self-referential loop. Every non-PLT
    // reference (from the exe or another library) instead binds to this
    // stub, giving `&func` a single identity across the boundary.
    for i in 0..n_imp {
        if addr_taken[i] {
            if let Some(k) = func_slot[i] {
                let e = (i + 1) * 24;
                dynsym[e + 8..e + 16].copy_from_slice(&plt_stub(k).to_le_bytes());
            }
        }
    }

    // ---- Build .dynamic.
    let mut dynamic: Vec<u8> = Vec::with_capacity(dynamic_size as usize);
    let dyn_push = |tag: i64, val: u64, d: &mut Vec<u8>| {
        d.extend_from_slice(&tag.to_le_bytes());
        d.extend_from_slice(&val.to_le_bytes());
    };
    for &noff in &needed_offsets {
        dyn_push(DT_NEEDED, noff as u64, &mut dynamic);
    }
    dyn_push(DT_HASH, hash_v, &mut dynamic);
    dyn_push(DT_STRTAB, dynstr_v, &mut dynamic);
    dyn_push(DT_SYMTAB, dynsym_v, &mut dynamic);
    dyn_push(DT_STRSZ, dynstr.len() as u64, &mut dynamic);
    dyn_push(DT_SYMENT, 24, &mut dynamic);
    if has_plt {
        dyn_push(DT_PLTGOT, gotplt_v, &mut dynamic);
        dyn_push(DT_PLTRELSZ, relaplt_size, &mut dynamic);
        dyn_push(DT_PLTREL, DT_RELA as u64, &mut dynamic);
        dyn_push(DT_JMPREL, relaplt_v, &mut dynamic);
    }
    dyn_push(DT_FLAGS, DF_BIND_NOW, &mut dynamic);
    if reladyn_size > 0 {
        dyn_push(DT_RELA, reladyn_v, &mut dynamic);
        dyn_push(DT_RELASZ, reladyn_size, &mut dynamic);
        dyn_push(DT_RELAENT, 24, &mut dynamic);
    }
    if versioned {
        dyn_push(DT_VERSYM, versym_v, &mut dynamic);
        dyn_push(DT_VERNEED, verneed_v, &mut dynamic);
        dyn_push(DT_VERNEEDNUM, verneed_count as u64, &mut dynamic);
    }
    dyn_push(DT_NULL, 0, &mut dynamic);

    let e_entry = {
        let &(eoi, esi) = globals
            .get(entry)
            .ok_or_else(|| ElfError(format!("entry symbol '{}' not defined", entry)))?;
        sym_vaddr(eoi, esi)?
    };

    // ---- Emit the image.
    let total_file = rw_file_end;
    let mut image = vec![0u8; total_file as usize];
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[7] = host_osabi();
    image[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&e_entry.to_le_bytes());
    image[32..40].copy_from_slice(&ehsize.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

    // Program headers.
    let mut ph = Vec::new();
    let mut phdr = |t: u32, fl: u32, off: u64, va: u64, fsz: u64, msz: u64, al: u64| {
        ph.extend_from_slice(&t.to_le_bytes());
        ph.extend_from_slice(&fl.to_le_bytes());
        ph.extend_from_slice(&off.to_le_bytes());
        ph.extend_from_slice(&va.to_le_bytes());
        ph.extend_from_slice(&va.to_le_bytes());
        ph.extend_from_slice(&fsz.to_le_bytes());
        ph.extend_from_slice(&msz.to_le_bytes());
        ph.extend_from_slice(&al.to_le_bytes());
    };
    phdr(
        PT_INTERP,
        PF_R,
        interp_fo,
        interp_v,
        interp_bytes.len() as u64,
        interp_bytes.len() as u64,
        1,
    );
    phdr(PT_LOAD, PF_R, 0, DBASE, ro_end_fo, ro_end_fo, PAGE);
    phdr(
        PT_LOAD,
        PF_R | PF_X,
        rx_start_fo,
        rx_start_v,
        (plt_fo + plt_size) - rx_start_fo,
        rx_end_v - rx_start_v,
        PAGE,
    );
    phdr(
        PT_LOAD,
        PF_R | PF_W,
        rw_start_fo,
        rw_start_v,
        rw_file_end - rw_start_fo,
        rw_mem_end_v - rw_start_v,
        PAGE,
    );
    phdr(
        PT_DYNAMIC,
        PF_R | PF_W,
        dynamic_fo,
        dynamic_v,
        dynamic_size,
        dynamic_size,
        8,
    );
    if let Some(ti) = tls_out {
        let o = &outs[ti];
        phdr(
            PT_TLS,
            PF_R,
            o.file_off,
            o.vaddr,
            o.data.len() as u64,
            o.data.len() as u64 + o.bss_size,
            o.align.max(1),
        );
    }
    if let (Some(hv), Some(hfo)) = (eh_hdr_v, eh_hdr_fo) {
        let len = eh_hdr_bytes.len() as u64;
        phdr(PT_GNU_EH_FRAME, PF_R, hfo, hv, len, len, 4);
    }
    phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0);
    image[64..64 + ph.len()].copy_from_slice(&ph);

    // Write metadata sections.
    let put = |img: &mut [u8], off: u64, bytes: &[u8]| {
        img[off as usize..off as usize + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut image, interp_fo, &interp_bytes);
    put(&mut image, dynsym_fo, &dynsym);
    put(&mut image, hash_fo, &hash);
    put(&mut image, dynstr_fo, &dynstr);
    if versioned {
        put(&mut image, versym_fo, &versym);
        put(&mut image, verneed_fo, &verneed);
    }
    if reladyn_size > 0 {
        put(&mut image, reladyn_fo, &reladyn);
    }
    put(&mut image, relaplt_fo, &relaplt);
    put(&mut image, plt_fo, &plt);
    if got_size > 0 {
        put(&mut image, got_fo, &got);
    }
    put(&mut image, gotplt_fo, &gotplt);
    put(&mut image, dynamic_fo, &dynamic);
    if let Some(hfo) = eh_hdr_fo {
        put(&mut image, hfo, &eh_hdr_bytes);
    }
    let _ = rw_data_end_v;

    // Write merged object sections (skip bss).
    for o in &outs {
        if o.is_bss {
            continue;
        }
        put(&mut image, o.file_off, &o.data);
    }

    // ---- Section header table (not loaded; for readelf/gdb/objdump).
    // Built in ascending-file-offset order so cross-references resolve to
    // fixed indices: .dynstr and .dynsym sit at known positions, and
    // .got.plt's index (for .rela.plt's sh_info) is tracked as we go.
    let mut shstr: Vec<u8> = vec![0];
    let mut shdrs: Vec<[u8; 64]> = Vec::new();
    #[allow(clippy::too_many_arguments)]
    fn mk(
        shstr: &mut Vec<u8>,
        shdrs: &mut Vec<[u8; 64]>,
        name: &str,
        typ: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
        link: u32,
        info: u32,
        align: u64,
        entsize: u64,
    ) -> usize {
        let noff = shstr.len() as u32;
        if !name.is_empty() {
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
        }
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(&(if name.is_empty() { 0 } else { noff }).to_le_bytes());
        h[4..8].copy_from_slice(&typ.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&addr.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..44].copy_from_slice(&link.to_le_bytes());
        h[44..48].copy_from_slice(&info.to_le_bytes());
        h[48..56].copy_from_slice(&align.to_le_bytes());
        h[56..64].copy_from_slice(&entsize.to_le_bytes());
        shdrs.push(h);
        shdrs.len() - 1
    }
    // [0] NULL, then the fixed-position synthetic sections.
    mk(&mut shstr, &mut shdrs, "", 0, 0, 0, 0, 0, 0, 0, 0, 0);
    mk(
        &mut shstr,
        &mut shdrs,
        ".interp",
        SHT_PROGBITS,
        SHF_ALLOC,
        interp_v,
        interp_fo,
        interp_bytes.len() as u64,
        0,
        0,
        1,
        0,
    );
    let dynsym_idx = mk(
        &mut shstr,
        &mut shdrs,
        ".dynsym",
        SHT_DYNSYM,
        SHF_ALLOC,
        dynsym_v,
        dynsym_fo,
        dynsym.len() as u64,
        0,
        1,
        8,
        24,
    ) as u32;
    // .dynsym.link → .dynstr; patched once .dynstr's index is known.
    mk(
        &mut shstr,
        &mut shdrs,
        ".hash",
        SHT_HASH,
        SHF_ALLOC,
        hash_v,
        hash_fo,
        hash.len() as u64,
        dynsym_idx,
        0,
        8,
        4,
    );
    let dynstr_idx = mk(
        &mut shstr,
        &mut shdrs,
        ".dynstr",
        SHT_STRTAB,
        SHF_ALLOC,
        dynstr_v,
        dynstr_fo,
        dynstr.len() as u64,
        0,
        0,
        1,
        0,
    ) as u32;
    shdrs[dynsym_idx as usize][40..44].copy_from_slice(&dynstr_idx.to_le_bytes());
    // Version sections, in file-offset order (only when versioned).
    if versioned {
        mk(
            &mut shstr,
            &mut shdrs,
            ".gnu.version",
            SHT_GNU_VERSYM,
            SHF_ALLOC,
            versym_v,
            versym_fo,
            versym.len() as u64,
            dynsym_idx,
            0,
            2,
            2,
        );
        mk(
            &mut shstr,
            &mut shdrs,
            ".gnu.version_r",
            SHT_GNU_VERNEED,
            SHF_ALLOC,
            verneed_v,
            verneed_fo,
            verneed.len() as u64,
            dynstr_idx,
            verneed_count,
            4,
            0,
        );
    }
    if reladyn_size > 0 {
        mk(
            &mut shstr,
            &mut shdrs,
            ".rela.dyn",
            SHT_RELA,
            SHF_ALLOC,
            reladyn_v,
            reladyn_fo,
            reladyn_size,
            dynsym_idx,
            0,
            8,
            24,
        );
    }
    // .rela.plt.info → .got.plt; patched once .got.plt's index is known.
    // The whole PLT trio is present only with function imports.
    let relaplt_idx = if has_plt {
        Some(mk(
            &mut shstr,
            &mut shdrs,
            ".rela.plt",
            SHT_RELA,
            SHF_ALLOC | SHF_INFO_LINK,
            relaplt_v,
            relaplt_fo,
            relaplt_size,
            dynsym_idx,
            0,
            8,
            24,
        ))
    } else {
        None
    };
    if let (Some(hv), Some(hfo)) = (eh_hdr_v, eh_hdr_fo) {
        mk(
            &mut shstr,
            &mut shdrs,
            ".eh_frame_hdr",
            SHT_PROGBITS,
            SHF_ALLOC,
            hv,
            hfo,
            eh_hdr_bytes.len() as u64,
            0,
            0,
            4,
            0,
        );
    }
    for &i in &ro_order {
        let o = &outs[i];
        mk(
            &mut shstr,
            &mut shdrs,
            &o.name,
            SHT_PROGBITS,
            o.flags,
            o.vaddr,
            o.file_off,
            o.data.len() as u64,
            0,
            0,
            o.align,
            0,
        );
    }
    for &i in &text_order {
        let o = &outs[i];
        mk(
            &mut shstr,
            &mut shdrs,
            &o.name,
            SHT_PROGBITS,
            o.flags,
            o.vaddr,
            o.file_off,
            o.data.len() as u64,
            0,
            0,
            o.align,
            0,
        );
    }
    if has_plt {
        mk(
            &mut shstr,
            &mut shdrs,
            ".plt",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            plt_v,
            plt_fo,
            plt_size,
            0,
            0,
            16,
            16,
        );
    }
    for &i in &data_order {
        let o = &outs[i];
        mk(
            &mut shstr,
            &mut shdrs,
            &o.name,
            SHT_PROGBITS,
            o.flags,
            o.vaddr,
            o.file_off,
            o.data.len() as u64,
            0,
            0,
            o.align,
            0,
        );
    }
    if got_size > 0 {
        mk(
            &mut shstr,
            &mut shdrs,
            ".got",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_WRITE,
            got_v,
            got_fo,
            got_size,
            0,
            0,
            8,
            8,
        );
    }
    if has_plt {
        let gotplt_idx = mk(
            &mut shstr,
            &mut shdrs,
            ".got.plt",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_WRITE,
            gotplt_v,
            gotplt_fo,
            gotplt_size,
            0,
            0,
            8,
            8,
        ) as u32;
        if let Some(ri) = relaplt_idx {
            shdrs[ri][44..48].copy_from_slice(&gotplt_idx.to_le_bytes());
        }
    }
    mk(
        &mut shstr,
        &mut shdrs,
        ".dynamic",
        SHT_DYNAMIC,
        SHF_ALLOC | SHF_WRITE,
        dynamic_v,
        dynamic_fo,
        dynamic_size,
        dynstr_idx,
        0,
        8,
        16,
    );
    for &i in &bss_order {
        let o = &outs[i];
        mk(
            &mut shstr,
            &mut shdrs,
            &o.name,
            SHT_NOBITS,
            o.flags,
            o.vaddr,
            o.vaddr,
            o.bss_size,
            0,
            0,
            o.align.max(1),
            0,
        );
    }
    // .shstrtab last; its own name is the final string, so reserve the
    // index before appending the shstrtab bytes.
    let shstrtab_idx = shdrs.len() as u32;
    let shstrtab_off = image.len() as u64;
    // Append the shstrtab's own name, then the section itself.
    mk(
        &mut shstr,
        &mut shdrs,
        ".shstrtab",
        SHT_STRTAB,
        0,
        0,
        shstrtab_off,
        0,
        0,
        0,
        1,
        0,
    );
    shdrs[shstrtab_idx as usize][32..40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
    image.extend_from_slice(&shstr);

    while !image.len().is_multiple_of(8) {
        image.push(0);
    }
    let shoff = image.len() as u64;
    for h in &shdrs {
        image.extend_from_slice(h);
    }
    image[40..48].copy_from_slice(&shoff.to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    image[60..62].copy_from_slice(&(shdrs.len() as u16).to_le_bytes());
    image[62..64].copy_from_slice(&(shstrtab_idx as u16).to_le_bytes());

    Ok(image)
}

fn next_multiple(v: u64, a: u64) -> u64 {
    let a = a.max(1);
    v.div_ceil(a) * a
}

/// If `name` is an init/fini/preinit array (with optional `.NNN`
/// priority), the base section name and its priority. Unnumbered arrays
/// run last (priority u64::MAX), matching the GNU linker convention.
fn array_kind(name: &str) -> Option<(&'static str, u64)> {
    for base in [".init_array", ".fini_array", ".preinit_array"] {
        if name == base {
            return Some((base, u64::MAX));
        }
        if let Some(rest) = name.strip_prefix(base) {
            if let Some(num) = rest.strip_prefix('.') {
                return Some((base, num.parse::<u64>().unwrap_or(u64::MAX)));
            }
        }
    }
    None
}

fn is_gotpcrel(t: u32) -> bool {
    matches!(
        t,
        R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX
    )
}

/// Relax a general-dynamic TLS sequence to local-exec in place. The
/// reloc marks the disp32 of `leaq x@tlsgd(%rip),%rdi`; the 16-byte
/// sequence starting 4 bytes earlier becomes
/// `movq %fs:0,%rax; leaq x@tpoff(%rax),%rax` (psABI TLS transition).
fn relax_tlsgd_to_le(data: &mut [u8], reloc_off: u64, tpoff: i64) -> Result<(), ElfError> {
    if !(i32::MIN as i64..=i32::MAX as i64).contains(&tpoff) {
        return err(format!("TLS GD offset overflow at {:#x}", reloc_off));
    }
    let ro = reloc_off as usize;
    if ro < 4 || ro + 12 > data.len() {
        return err(format!("TLS GD sequence out of bounds at {:#x}", reloc_off));
    }
    let start = ro - 4;
    if data[start..start + 4] != [0x66, 0x48, 0x8d, 0x3d] {
        return err(format!(
            "unexpected TLS GD prologue at {:#x}: {:02x?}",
            reloc_off,
            &data[start..start + 4]
        ));
    }
    // movq %fs:0,%rax ; leaq <disp32>(%rax),%rax
    let le: [u8; 12] = [
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x80,
    ];
    data[start..start + 12].copy_from_slice(&le);
    data[start + 12..start + 16].copy_from_slice(&(tpoff as i32).to_le_bytes());
    Ok(())
}

/// Relax a local-dynamic TLS sequence to local-exec in place. The reloc
/// marks the disp32 of `leaq x@tlsld(%rip),%rdi`; the 12-byte sequence
/// starting 3 bytes earlier becomes `movq %fs:0,%rax` (prefix-padded).
/// Paired DTPOFF relocations then patch as local-exec offsets.
fn relax_tlsld_to_le(data: &mut [u8], reloc_off: u64) -> Result<(), ElfError> {
    let ro = reloc_off as usize;
    if ro < 3 || ro + 9 > data.len() {
        return err(format!("TLS LD sequence out of bounds at {:#x}", reloc_off));
    }
    let start = ro - 3;
    if data[start..start + 3] != [0x48, 0x8d, 0x3d] {
        return err(format!(
            "unexpected TLS LD prologue at {:#x}: {:02x?}",
            reloc_off,
            &data[start..start + 3]
        ));
    }
    // data16 data16 data16 movq %fs:0,%rax
    let le: [u8; 12] = [
        0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    data[start..start + 12].copy_from_slice(&le);
    Ok(())
}

#[cfg(test)]
mod abs32_reloc_tests {
    use super::*;

    #[test]
    fn r32_unsigned_range() {
        // In range: 0 and u32::MAX both encode.
        assert_eq!(encode_abs32(0, false, 0).unwrap(), [0, 0, 0, 0]);
        assert_eq!(
            encode_abs32(u32::MAX as i64, false, 0).unwrap(),
            [0xff, 0xff, 0xff, 0xff]
        );
        // Out of range: negative and > u32::MAX are errors, not truncation.
        assert!(encode_abs32(-1, false, 0).is_err());
        assert!(encode_abs32(u32::MAX as i64 + 1, false, 0).is_err());
    }

    #[test]
    fn r32s_signed_range() {
        // In range: i32::MIN..=i32::MAX encode.
        assert_eq!(
            encode_abs32(i32::MIN as i64, true, 0).unwrap(),
            (i32::MIN).to_le_bytes()
        );
        assert_eq!(
            encode_abs32(i32::MAX as i64, true, 0).unwrap(),
            (i32::MAX).to_le_bytes()
        );
        // Just outside i32 on both ends is an error.
        assert!(encode_abs32(i32::MAX as i64 + 1, true, 0).is_err());
        assert!(encode_abs32(i32::MIN as i64 - 1, true, 0).is_err());
    }

    #[test]
    fn overflow_message_names_the_kind_and_offset() {
        let e = encode_abs32(1 << 40, false, 0xdead).unwrap_err();
        assert!(e.to_string().contains("R_X86_64_32 overflow"));
        assert!(e.to_string().contains("0xdead"));
        let e = encode_abs32(1 << 40, true, 0xbeef).unwrap_err();
        assert!(e.to_string().contains("R_X86_64_32S overflow"));
    }
}

#[cfg(test)]
mod resolve_globals_tests {
    use super::*;

    /// A defined (non-special) section index for synthetic symbols.
    const DEF: u16 = 1;

    fn sym(name: &str, bind: u8, shndx: u16) -> Symbol {
        Symbol {
            name: name.to_string(),
            bind,
            typ: 0,
            shndx,
            section: if shndx == DEF { Some(0) } else { None },
            value: 0,
            size: 0,
        }
    }

    fn common(name: &str, size: u64, align: u64) -> Symbol {
        Symbol {
            name: name.to_string(),
            bind: STB_GLOBAL,
            typ: STT_OBJECT,
            shndx: SHN_COMMON,
            section: None,
            value: align,
            size,
        }
    }

    fn obj(name: &str, symbols: Vec<Symbol>) -> ElfObject {
        ElfObject {
            name: name.to_string(),
            sections: Vec::new(),
            symbols,
        }
    }

    #[test]
    fn strong_beats_weak_regardless_of_order() {
        // Weak first, strong second: the strong def wins (audit L1 — the
        // old dynamic path took the first definition and kept the weak).
        let objs = vec![
            obj("a.o", vec![sym("foo", STB_WEAK, DEF)]),
            obj("b.o", vec![sym("foo", STB_GLOBAL, DEF)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (1, 0));

        // Strong first, weak second: the strong def keeps winning.
        let objs = vec![
            obj("a.o", vec![sym("foo", STB_GLOBAL, DEF)]),
            obj("b.o", vec![sym("foo", STB_WEAK, DEF)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (0, 0));
    }

    #[test]
    fn duplicate_strong_is_an_error() {
        let objs = vec![
            obj("a.o", vec![sym("foo", STB_GLOBAL, DEF)]),
            obj("b.o", vec![sym("foo", STB_GLOBAL, DEF)]),
        ];
        assert!(resolve_globals(&objs).is_err());
    }

    #[test]
    fn strong_definition_beats_common() {
        let objs = vec![
            obj("a.o", vec![common("foo", 64, 16)]),
            obj("b.o", vec![sym("foo", STB_GLOBAL, DEF)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (1, 0));

        let objs = vec![
            obj("a.o", vec![sym("foo", STB_GLOBAL, DEF)]),
            obj("b.o", vec![common("foo", 64, 16)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (0, 0));
    }

    #[test]
    fn common_coalesces_to_largest_size_then_alignment() {
        let objs = vec![
            obj("a.o", vec![common("foo", 8, 32)]),
            obj("b.o", vec![common("foo", 16, 8)]),
            obj("c.o", vec![common("bar", 8, 4)]),
            obj("d.o", vec![common("bar", 8, 16)]),
        ];
        let globals = resolve_globals(&objs).unwrap();
        assert_eq!(globals["foo"], (1, 0));
        assert_eq!(globals["bar"], (3, 0));
    }

    #[test]
    fn default_version_beats_nondefault_for_base() {
        // Non-default first, default second: the default answers `foo`.
        let objs = vec![
            obj("a.o", vec![sym("foo@V1", STB_GLOBAL, DEF)]),
            obj("b.o", vec![sym("foo@@V2", STB_GLOBAL, DEF)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (1, 0));
    }

    #[test]
    fn explicit_unversioned_wins_over_alias() {
        // A plain `foo` definition must not be overwritten by a `foo@@V`
        // alias, whichever order they appear in.
        let objs = vec![
            obj("a.o", vec![sym("foo@@V", STB_GLOBAL, DEF)]),
            obj("b.o", vec![sym("foo", STB_GLOBAL, DEF)]),
        ];
        assert_eq!(resolve_globals(&objs).unwrap()["foo"], (1, 0));
    }

    #[test]
    fn base_alias_winner_is_deterministic() {
        // Two competing non-default versions of one base with no default
        // and no explicit unversioned def: the base must resolve to the
        // earliest-link-order definition on every run, independent of
        // HashMap iteration order (audit L2). Fresh objects each pass so
        // each `globals` HashMap gets a different seed.
        let build = || {
            vec![
                obj("a.o", vec![sym("foo@V1", STB_GLOBAL, DEF)]),
                obj("b.o", vec![sym("foo@V2", STB_GLOBAL, DEF)]),
            ]
        };
        assert_eq!(resolve_globals(&build()).unwrap()["foo"], (0, 0));
        for _ in 0..64 {
            assert_eq!(resolve_globals(&build()).unwrap()["foo"], (0, 0));
        }
    }
}

#[cfg(test)]
mod eh_frame_hdr_tests {
    use super::*;

    /// A real "zR" CIE from `cc -O1` on x86_64: version 1, augmentation
    /// "zR", FDE pointer encoding 0x1b (pcrel|sdata4) at byte 16.
    const CIE: [u8; 24] = [
        0x14, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x7a, 0x52, 0x00, 0x01, 0x78, 0x10, 0x01, 0x1b, 0x0c,
        0x07, 0x08, 0x90, 0x01, 0x00, 0x00,
    ];

    /// A 32-byte FDE at record offset `at` whose function starts at `pc`,
    /// given the section's final vaddr (so the pcrel field can be filled
    /// as a linked `.eh_frame` would carry it).
    fn fde(at: usize, pc: u64, eh_vaddr: u64) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[0..4].copy_from_slice(&0x1cu32.to_le_bytes()); // length
        f[4..8].copy_from_slice(&((at as u32) + 4).to_le_bytes()); // cie_ptr -> CIE at 0
        let field_vaddr = eh_vaddr + at as u64 + 8;
        let rel = (pc as i64 - field_vaddr as i64) as i32;
        f[8..12].copy_from_slice(&rel.to_le_bytes()); // initial_location (pcrel)
        f[12..16].copy_from_slice(&16u32.to_le_bytes()); // address_range
        f // aug_len byte + CFI left zero (nops); parser skips by length
    }

    #[test]
    fn parses_fdes_and_builds_sorted_hdr() {
        let eh_vaddr = 0x2000u64;
        let hdr_vaddr = 0x1000u64;
        let mut eh = CIE.to_vec();
        let f1 = eh.len();
        eh.extend_from_slice(&fde(f1, 0x1500, eh_vaddr)); // higher PC first
        let f2 = eh.len();
        eh.extend_from_slice(&fde(f2, 0x1100, eh_vaddr)); // lower PC second
        eh.extend_from_slice(&0u32.to_le_bytes()); // terminator

        let fdes = parse_eh_frame_fdes(&eh, eh_vaddr).unwrap();
        let pcs: Vec<u64> = fdes.iter().map(|f| f.pc).collect();
        assert_eq!(pcs.len(), 2);
        assert!(pcs.contains(&0x1500) && pcs.contains(&0x1100));

        let hdr = build_eh_frame_hdr(&eh, eh_vaddr, hdr_vaddr).unwrap();
        assert_eq!(&hdr[0..4], &[1, 0x1b, 0x03, 0x3b]);
        let eh_ptr = i32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        assert_eq!(eh_ptr as i64, eh_vaddr as i64 - (hdr_vaddr as i64 + 4));
        assert_eq!(u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]), 2);
        // Table is sorted by PC: entry 0 is the lower PC.
        let e0 = i32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        let e1 = i32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
        assert_eq!(e0 as i64, 0x1100i64 - hdr_vaddr as i64);
        assert_eq!(e1 as i64, 0x1500i64 - hdr_vaddr as i64);
        assert_eq!(hdr.len(), 12 + 2 * 8);
    }

    #[test]
    fn rejects_unsupported_fde_encoding() {
        // Flip the CIE FDE-encoding byte to absptr — must error, not
        // silently misread an 8-byte field as 4.
        let mut cie = CIE;
        cie[16] = 0x00;
        let mut eh = cie.to_vec();
        let at = eh.len();
        eh.extend_from_slice(&fde(at, 0x1200, 0x2000));
        eh.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_eh_frame_fdes(&eh, 0x2000).is_err());
    }

    #[test]
    fn empty_eh_frame_yields_empty_table() {
        let hdr = build_eh_frame_hdr(&[], 0x2000, 0x1000).unwrap();
        assert_eq!(u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]), 0);
        assert_eq!(hdr.len(), 12);
    }
}
