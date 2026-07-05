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

pub const ET_DYN: u16 = 3;
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
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_FLAGS: i64 = 30;
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

fn cstr(tab: &[u8], off: usize) -> String {
    let end = tab[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(tab.len());
    String::from_utf8_lossy(&tab[off..end]).into_owned()
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
    let sh = |i: usize| -> &[u8] { &bytes[shoff + i * shentsize..shoff + (i + 1) * shentsize] };
    let shstr_off = ru64(sh(shstrndx), 24) as usize;
    let shstr_size = ru64(sh(shstrndx), 32) as usize;
    let shstr = &bytes[shstr_off..shstr_off + shstr_size];

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
            name: cstr(shstr, ru32(h, 0) as usize),
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
            SHT_PROGBITS | SHT_NOBITS | SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY
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
                bytes[r.off..r.off + r.size].to_vec()
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
        let strtab = &raws[r.link];
        let strdat = &bytes[strtab.off..strtab.off + strtab.size];
        let n = r.size.checked_div(r.entsize).unwrap_or(0);
        for k in 0..n {
            let e = &bytes[r.off + k * 24..r.off + (k + 1) * 24];
            let shndx = ru16(e, 6);
            symbols.push(Symbol {
                name: cstr(strdat, ru32(e, 0) as usize),
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
        let n = r.size.checked_div(r.entsize).unwrap_or(0);
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

/// A parsed shared object: its runtime name and the symbols it exports.
#[derive(Debug)]
pub struct SharedLib {
    pub soname: String,
    pub exports: HashMap<String, Export>,
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
    let sh = |i: usize| -> &[u8] { &bytes[shoff + i * shentsize..shoff + (i + 1) * shentsize] };

    // Locate .dynsym (with its linked string table) and .dynamic.
    let mut dynsym: Option<(usize, usize, usize, usize)> = None; // off,size,link,entsize
    let mut dynamic: Option<(usize, usize)> = None; // off,size
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
            _ => {}
        }
    }
    let Some((soff, ssize, slink, sent)) = dynsym else {
        return err(format!("{}: shared object has no .dynsym", name));
    };
    let link_h = sh(slink);
    let stroff = ru64(link_h, 24) as usize;
    let strsz = ru64(link_h, 32) as usize;
    let dynstr = &bytes[stroff..stroff + strsz];

    // SONAME from .dynamic, else the file's own name.
    let mut soname = String::new();
    if let Some((doff, dsz)) = dynamic {
        for k in 0..dsz / 16 {
            let e = &bytes[doff + k * 16..doff + (k + 1) * 16];
            let tag = ru64(e, 0) as i64;
            if tag == 0 {
                break;
            }
            if tag == DT_SONAME {
                soname = cstr(dynstr, ru64(e, 8) as usize);
            }
        }
    }
    if soname.is_empty() {
        soname = std::path::Path::new(name)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.to_string());
    }

    let sent = if sent == 0 { 24 } else { sent };
    let mut exports = HashMap::new();
    for k in 0..ssize / sent {
        let e = &bytes[soff + k * sent..soff + k * sent + 24];
        let shndx = ru16(e, 6);
        let bind = e[4] >> 4;
        let typ = e[4] & 0xf;
        if shndx == SHN_UNDEF || bind == STB_LOCAL {
            continue;
        }
        let nm = cstr(dynstr, ru32(e, 0) as usize);
        if nm.is_empty() {
            continue;
        }
        exports.entry(nm).or_insert(Export {
            version: String::new(),
            func: typ == STT_FUNC,
        });
    }
    Ok(SharedLib { soname, exports })
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

/// A synthesized GOT slot. `Addr` holds a symbol's final address
/// (`None` = an unsatisfied weak reference, i.e. 0); `TpOff` holds a
/// TLS symbol's TP-relative offset for the initial-exec model.
enum GotEntry {
    Addr(Option<(usize, usize)>),
    TpOff((usize, usize)),
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
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The base of a versioned symbol name (`foo@V` or `foo@@V` -> `foo`);
/// `None` for an unversioned name.
fn version_base(name: &str) -> Option<&str> {
    name.find('@').map(|at| &name[..at])
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
fn armap_offset(ar: &crate::archive::Archive, name: &str) -> Option<u32> {
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

/// Link relocatable objects plus library archives into a static
/// ET_EXEC. Explicit objects load unconditionally, in order; archive
/// members load lazily, pulled to satisfy strong-undefined symbols and
/// iterated to a fixed point (global `--start-group` semantics, so
/// mutually-referencing archives resolve regardless of order). The
/// first archive to define a symbol wins.
pub fn link_static(
    mut objects: Vec<ElfObject>,
    libs: &[Library],
    entry: &str,
) -> Result<Vec<u8>, ElfError> {
    use crate::archive::Archive as ArContainer;

    let archives: Vec<ArContainer> = libs
        .iter()
        .map(|l| {
            ArContainer::open(l.name.clone(), &l.bytes)
                .map_err(|e| ElfError(format!("{}: {}", l.name, e)))
        })
        .collect::<Result<_, _>>()?;

    let mut defined: HashSet<String> = HashSet::new();
    for obj in &objects {
        defined_names(obj, &mut defined);
    }
    let mut pulled: Vec<HashSet<usize>> = vec![HashSet::new(); archives.len()];

    loop {
        let demand = undefined_demand(&objects, &defined);
        let mut changed = false;
        for name in &demand {
            for (ai, ar) in archives.iter().enumerate() {
                let Some(off) = armap_offset(ar, name) else {
                    continue;
                };
                // First archive to define the symbol wins; stop scanning
                // once found whether or not its member is freshly pulled.
                if pulled[ai].insert(off as usize) {
                    let member = ar.member_at_offset(off).ok_or_else(|| {
                        ElfError(format!(
                            "{}: symbol index points at offset {:#x} with no member",
                            libs[ai].name, off
                        ))
                    })?;
                    if member.body.is_empty() {
                        return err(format!(
                            "{}({}): thin-archive members are out of scope for ELF static linking",
                            libs[ai].name, member.name
                        ));
                    }
                    let logical = format!("{}({})", libs[ai].name, member.name);
                    let obj = parse_rel(&logical, member.body)?;
                    defined_names(&obj, &mut defined);
                    objects.push(obj);
                    changed = true;
                }
                break;
            }
        }
        if !changed {
            break;
        }
    }

    link_static_exec(&objects, entry)
}

/// Link relocatable objects into a static ET_EXEC image. Explicit
/// objects only — undefined strong globals are an error; use
/// [`link_static`] to pull definitions from library archives. Undefined
/// *weak* references resolve to 0.
pub fn link_static_exec(objects: &[ElfObject], entry: &str) -> Result<Vec<u8>, ElfError> {
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
        let name = if tls_data.is_empty() { ".tbss" } else { ".tdata" };
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

    // ---- Global symbol resolution.
    // name -> (object, symbol index); strong duplicates are errors,
    // weak yields to strong.
    let mut globals: HashMap<String, (usize, usize)> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sym) in obj.symbols.iter().enumerate() {
            if sym.name.is_empty() || sym.bind == STB_LOCAL || sym.shndx == SHN_UNDEF {
                continue;
            }
            if sym.shndx == SHN_COMMON {
                return err(format!(
                    "{}: COMMON symbol '{}' — COMMON allocation lands in rung 2",
                    obj.name, sym.name
                ));
            }
            match globals.get(&sym.name) {
                None => {
                    globals.insert(sym.name.clone(), (oi, si));
                }
                Some(&(poi, psi)) => {
                    let prev = &objects[poi].symbols[psi];
                    match (prev.bind, sym.bind) {
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
                    }
                }
            }
        }
    }

    // Version aliasing: a default-version definition (`foo@@V`) answers
    // the plain base `foo`; a non-default (`foo@V`) answers it only if
    // nothing else does. An explicit unversioned definition always wins.
    let mut base_default: HashMap<String, (usize, usize)> = HashMap::new();
    let mut base_other: HashMap<String, (usize, usize)> = HashMap::new();
    for (full, &def) in &globals {
        let Some(at) = full.find('@') else { continue };
        let base = full[..at].to_string();
        if full[at..].starts_with("@@") {
            base_default.entry(base).or_insert(def);
        } else {
            base_other.entry(base).or_insert(def);
        }
    }
    for (base, def) in base_default.into_iter().chain(base_other) {
        globals.entry(base).or_insert(def);
    }

    // Reference -> definition identity. None means an unsatisfied weak
    // reference (address 0). Depends only on `globals`, so it is valid
    // before layout — the GOT pre-scan uses it.
    let resolve_def = |oi: usize, si: usize| -> Result<Option<(usize, usize)>, ElfError> {
        let sym = &objects[oi].symbols[si];
        if sym.shndx != SHN_UNDEF {
            return Ok(Some((oi, si)));
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

    // TLS reference -> TP-relative offset (tpoff). Undefined-weak TLS is
    // not meaningful; treat it as an error.
    let tls_offset = |oi: usize, si: usize| -> Result<i64, ElfError> {
        let (doi, dsi) = resolve_def(oi, si)?.ok_or_else(|| {
            ElfError(format!(
                "TLS relocation against undefined symbol in {}",
                objects[oi].name
            ))
        })?;
        let d = &objects[doi].symbols[dsi];
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("TLS symbol '{}' has no section", d.name)))?;
        let block_off = *tls_place.get(&(doi, sec)).ok_or_else(|| {
            ElfError(format!("TLS symbol '{}' is not in a TLS section", d.name))
        })?;
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
    let phnum = 2u64 + if has_tls { 1 } else { 0 };
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
        .map(|&i| out_vaddrs[i] + if outs[i].is_bss { outs[i].bss_size } else { outs[i].data.len() as u64 })
        .max()
        .unwrap_or(BASE_VADDR);
    let bounds = |name: &str| -> Option<(u64, u64)> {
        outs.iter().enumerate().find(|(_, o)| o.name == name).map(|(i, o)| {
            let sz = if o.is_bss { o.bss_size } else { o.data.len() as u64 };
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
    let linker_addr: [u64; 12] = [
        pre_s, pre_e, ini_s, ini_e, fin_s, fin_e, rip_s, rip_e, got_base, bss_start, edata, anchor,
    ];

    // Raw definition address, bypassing ifunc indirection (used for the
    // IRELATIVE resolver addend).
    let raw_addr = |doi: usize, dsi: usize| -> Result<u64, ElfError> {
        let d = &objects[doi].symbols[dsi];
        if d.shndx == SHN_ABS {
            return Ok(d.value);
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
            // TLS sections form the PT_TLS image and are not in the
            // normal placement map; they carry no relocations we apply.
            let Some(&(out_idx, base)) = place.get(&(oi, si)) else {
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
                        let v = s as i64 + r.addend;
                        if v < 0 || v > u32::MAX as i64 {
                            return err(format!("R_X86_64_32 overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as u32).to_le_bytes());
                    }
                    R_X86_64_32S => {
                        let v = s as i64 + r.addend;
                        if v < i32::MIN as i64 || v > i32::MAX as i64 {
                            return err(format!("R_X86_64_32S overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(v as i32).to_le_bytes());
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
                        outs[out_idx].data[spot..spot + 8]
                            .copy_from_slice(&v.to_le_bytes());
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
        .map(|&i| outs[i].vaddr + if outs[i].is_bss { outs[i].bss_size } else { outs[i].data.len() as u64 })
        .max()
        .unwrap_or(rw_vaddr_start);

    let mut image = vec![0u8; rx_end as usize];
    // ELF header.
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // 64-bit
    image[5] = 1; // little-endian
    image[6] = 1; // EV_CURRENT
    image[7] = if cfg!(target_os = "freebsd") { 9 } else { 0 };
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
    ph.extend(phdr(PT_LOAD, PF_R | PF_X, 0, BASE_VADDR, rx_end, rx_end, PAGE));
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
        ph.extend(phdr(PT_LOAD, PF_R | PF_W, rx_end, BASE_VADDR + rx_end, 0, 0, PAGE));
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
        h[4..8].copy_from_slice(
            &(if o.is_bss { SHT_NOBITS } else { SHT_PROGBITS }).to_le_bytes(),
        );
        h[8..16].copy_from_slice(&o.flags.to_le_bytes());
        h[16..24].copy_from_slice(&o.vaddr.to_le_bytes());
        h[24..32].copy_from_slice(&o.file_off.to_le_bytes());
        h[32..40].copy_from_slice(
            &(if o.is_bss { o.bss_size } else { o.data.len() as u64 }).to_le_bytes(),
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

/// Link relocatable objects into a dynamically-linked ET_EXEC that runs
/// under `interp`, importing undefined functions from `shared`. Rung-3a
/// scope: non-PIE, eager binding, function imports via PLT/JUMP_SLOT —
/// no data imports (GLOB_DAT), TLS, or symbol versioning yet.
pub fn link_dynamic_exec(
    objects: &[ElfObject],
    shared: &[SharedLib],
    entry: &str,
    interp: &str,
) -> Result<Vec<u8>, ElfError> {
    const DBASE: u64 = 0x20_0000;

    // ---- Merge input sections (text/rodata/data/bss). Init arrays and
    // TLS are out of 3a scope and error loudly.
    let mut outs: Vec<OutSec> = Vec::new();
    let mut out_index: HashMap<String, usize> = HashMap::new();
    let mut place: Placement = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & SHF_TLS != 0 || array_kind(&sec.name).is_some() {
                return err(format!(
                    "section '{}' (TLS/init-array) is out of rung-3a scope",
                    sec.name
                ));
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

    // ---- Resolve defined globals.
    let mut globals: HashMap<String, (usize, usize)> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sym) in obj.symbols.iter().enumerate() {
            if sym.name.is_empty() || sym.bind == STB_LOCAL || sym.shndx == SHN_UNDEF {
                continue;
            }
            globals.entry(sym.name.clone()).or_insert((oi, si));
        }
    }

    // ---- Imports: undefined strong globals a shared library exports.
    // Functions get a PLT slot; anything else is out of 3a scope.
    let mut imports: Vec<String> = Vec::new();
    let mut import_index: HashMap<String, usize> = HashMap::new();
    let mut used_lib = vec![false; shared.len()];
    for obj in objects {
        for sym in &obj.symbols {
            if sym.shndx != SHN_UNDEF
                || sym.bind != STB_GLOBAL
                || sym.name.is_empty()
                || globals.contains_key(&sym.name)
                || import_index.contains_key(&sym.name)
            {
                continue;
            }
            let Some(li) = shared.iter().position(|l| l.exports.contains_key(&sym.name)) else {
                return err(format!(
                    "undefined symbol '{}' (referenced from {}) — not exported by any shared object",
                    sym.name, obj.name
                ));
            };
            if !shared[li].exports[&sym.name].func {
                return err(format!(
                    "data import '{}' (GLOB_DAT) is out of rung-3a scope",
                    sym.name
                ));
            }
            used_lib[li] = true;
            import_index.insert(sym.name.clone(), imports.len());
            imports.push(sym.name.clone());
        }
    }
    let n_imp = imports.len();

    // ---- Build .dynstr (soname + import name strings) and note offsets.
    let mut dynstr: Vec<u8> = vec![0];
    let str_off = |s: &str, dynstr: &mut Vec<u8>| -> u32 {
        let off = dynstr.len() as u32;
        dynstr.extend_from_slice(s.as_bytes());
        dynstr.push(0);
        off
    };
    let mut needed_offsets: Vec<u32> = Vec::new();
    for (li, lib) in shared.iter().enumerate() {
        if used_lib[li] {
            needed_offsets.push(str_off(&lib.soname, &mut dynstr));
        }
    }
    let import_name_off: Vec<u32> = imports
        .iter()
        .map(|n| str_off(n, &mut dynstr))
        .collect();

    // ---- .dynsym: null entry then one UND FUNC per import.
    let n_dynsym = n_imp + 1;
    let mut dynsym = vec![0u8; n_dynsym * 24];
    for (i, &noff) in import_name_off.iter().enumerate() {
        let e = (i + 1) * 24;
        dynsym[e..e + 4].copy_from_slice(&noff.to_le_bytes());
        dynsym[e + 4] = (STB_GLOBAL << 4) | STT_FUNC; // st_info
        // st_other=0, st_shndx=0 (UND), value/size=0 already zeroed.
    }

    // ---- .hash (SysV): buckets + chains over .dynsym.
    let nbucket = (n_dynsym.max(1)) as u32;
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chain = vec![0u32; n_dynsym];
    for (i, name) in imports.iter().enumerate() {
        let si = (i + 1) as u32;
        let b = (elf_hash(name.as_bytes()) % nbucket) as usize;
        chain[si as usize] = buckets[b];
        buckets[b] = si;
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

    // Section byte sizes now known; build .interp, size .plt/.got.plt/
    // .rela.plt/.dynamic (contents filled after vaddrs are assigned).
    let mut interp_bytes = interp.as_bytes().to_vec();
    interp_bytes.push(0);
    let plt_size = ((n_imp + 1) * 16) as u64; // PLT0 + one stub per import
    let gotplt_size = ((n_imp + 3) * 8) as u64; // 3 reserved + one per import
    let relaplt_size = (n_imp * 24) as u64;
    let n_needed = needed_offsets.len();
    // .dynamic entry count: NEEDED* + the fixed tags + NULL.
    let dyn_fixed = [
        DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_PLTGOT, DT_PLTRELSZ, DT_PLTREL,
        DT_JMPREL, DT_FLAGS,
    ];
    let dynamic_count = n_needed + dyn_fixed.len() + 1; // +NULL
    let dynamic_size = (dynamic_count * 16) as u64;

    // ---- Layout. Fixed section order across three load segments.
    let ehsize = 64u64;
    let phnum = 6u64; // 3 LOAD + INTERP + DYNAMIC + GNU_STACK
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
    let (relaplt_v, relaplt_fo) = place_ro(relaplt_size, 8, &mut v, &mut fo);
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
    let rw_file_end = rw_file_end.max(gotplt_fo + gotplt_size).max(dynamic_fo + dynamic_size);

    // Import n resolves to its PLT stub (PLT0 is index 0, imports 1..).
    let plt_stub = |imp_idx: usize| plt_v + ((imp_idx + 1) * 16) as u64;
    let gotplt_slot = |imp_idx: usize| gotplt_v + ((imp_idx + 3) * 8) as u64;

    // ---- Address resolver (vaddr snapshot avoids borrowing `outs`
    // while the relocation loop mutates it).
    let out_vaddrs: Vec<u64> = outs.iter().map(|o| o.vaddr).collect();
    let sym_vaddr = |oi: usize, si: usize| -> Result<u64, ElfError> {
        let sym = &objects[oi].symbols[si];
        let (doi, dsi) = if sym.shndx == SHN_UNDEF {
            if let Some(&d) = globals.get(&sym.name) {
                d
            } else if let Some(&ii) = import_index.get(&sym.name) {
                return Ok(plt_stub(ii));
            } else if sym.bind == STB_WEAK {
                return Ok(0);
            } else {
                return err(format!("undefined symbol '{}'", sym.name));
            }
        } else {
            (oi, si)
        };
        let d = &objects[doi].symbols[dsi];
        if d.shndx == SHN_ABS {
            return Ok(d.value);
        }
        let sec = d
            .section
            .ok_or_else(|| ElfError(format!("symbol '{}' has no section", d.name)))?;
        let &(oidx, base) = place
            .get(&(doi, sec))
            .ok_or_else(|| ElfError(format!("unplaced section for '{}'", d.name)))?;
        Ok(out_vaddrs[oidx] + base + d.value)
    };

    // ---- Apply relocations into the merged section bytes.
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            let &(out_idx, base) = &place[&(oi, si)];
            for r in &sec.relas {
                let s = sym_vaddr(oi, r.sym as usize)?;
                let p = out_vaddrs[out_idx] + base + r.offset;
                let spot = (base + r.offset) as usize;
                match r.r_type {
                    R_X86_64_64 => {
                        let val = (s as i64 + r.addend) as u64;
                        outs[out_idx].data[spot..spot + 8].copy_from_slice(&val.to_le_bytes());
                    }
                    R_X86_64_32 => {
                        let val = s as i64 + r.addend;
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(val as u32).to_le_bytes());
                    }
                    R_X86_64_32S => {
                        let val = s as i64 + r.addend;
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(val as i32).to_le_bytes());
                    }
                    R_X86_64_PC32 | R_X86_64_PLT32 => {
                        let val = s as i64 + r.addend - p as i64;
                        if !(i32::MIN as i64..=i32::MAX as i64).contains(&val) {
                            return err(format!("PC32 overflow at {:#x}", p));
                        }
                        outs[out_idx].data[spot..spot + 4]
                            .copy_from_slice(&(val as i32).to_le_bytes());
                    }
                    other => {
                        return err(format!(
                            "relocation type {} is out of rung-3a scope",
                            other
                        ))
                    }
                }
            }
        }
    }

    // ---- Build .plt. PLT0 pushes GOT[1] and jumps GOT[2]; each stub
    // jumps through its GOT.PLT slot, else falls to the lazy trampoline.
    let mut plt = vec![0u8; plt_size as usize];
    // PLT0: ff 35 <gotplt+8> ; ff 25 <gotplt+16> ; nop nop nop nop
    let disp = |from_end: u64, to: u64| (to as i64 - from_end as i64) as i32;
    plt[0] = 0xff;
    plt[1] = 0x35;
    plt[2..6].copy_from_slice(&disp(plt_v + 6, gotplt_v + 8).to_le_bytes());
    plt[6] = 0xff;
    plt[7] = 0x25;
    plt[8..12].copy_from_slice(&disp(plt_v + 12, gotplt_v + 16).to_le_bytes());
    plt[12..16].copy_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
    for i in 0..n_imp {
        let o = (i + 1) * 16;
        let stub = plt_v + o as u64;
        let slot = gotplt_slot(i);
        // jmp *slot(%rip)
        plt[o] = 0xff;
        plt[o + 1] = 0x25;
        plt[o + 2..o + 6].copy_from_slice(&disp(stub + 6, slot).to_le_bytes());
        // push $i
        plt[o + 6] = 0x68;
        plt[o + 7..o + 11].copy_from_slice(&(i as u32).to_le_bytes());
        // jmp PLT0
        plt[o + 11] = 0xe9;
        plt[o + 12..o + 16].copy_from_slice(&disp(stub + 16, plt_v).to_le_bytes());
    }

    // ---- Build .got.plt: [0]=&_DYNAMIC, [1]=[2]=0, [3+i]=stub push insn.
    let mut gotplt = vec![0u8; gotplt_size as usize];
    gotplt[0..8].copy_from_slice(&dynamic_v.to_le_bytes());
    for i in 0..n_imp {
        let slot = (i + 3) * 8;
        gotplt[slot..slot + 8].copy_from_slice(&(plt_stub(i) + 6).to_le_bytes());
    }

    // ---- Build .rela.plt: one JUMP_SLOT per import.
    let mut relaplt = vec![0u8; relaplt_size as usize];
    for i in 0..n_imp {
        let e = i * 24;
        relaplt[e..e + 8].copy_from_slice(&gotplt_slot(i).to_le_bytes());
        let info = ((i as u64 + 1) << 32) | R_X86_64_JUMP_SLOT as u64;
        relaplt[e + 8..e + 16].copy_from_slice(&info.to_le_bytes());
        // addend 0.
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
    dyn_push(DT_PLTGOT, gotplt_v, &mut dynamic);
    dyn_push(DT_PLTRELSZ, relaplt_size, &mut dynamic);
    dyn_push(DT_PLTREL, DT_RELA as u64, &mut dynamic);
    dyn_push(DT_JMPREL, relaplt_v, &mut dynamic);
    dyn_push(DT_FLAGS, DF_BIND_NOW, &mut dynamic);
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
    image[7] = if cfg!(target_os = "freebsd") { 9 } else { 0 };
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
    phdr(PT_INTERP, PF_R, interp_fo, interp_v, interp_bytes.len() as u64, interp_bytes.len() as u64, 1);
    phdr(PT_LOAD, PF_R, 0, DBASE, ro_end_fo, ro_end_fo, PAGE);
    phdr(PT_LOAD, PF_R | PF_X, rx_start_fo, rx_start_v, (plt_fo + plt_size) - rx_start_fo, rx_end_v - rx_start_v, PAGE);
    phdr(PT_LOAD, PF_R | PF_W, rw_start_fo, rw_start_v, rw_file_end - rw_start_fo, rw_mem_end_v - rw_start_v, PAGE);
    phdr(PT_DYNAMIC, PF_R | PF_W, dynamic_fo, dynamic_v, dynamic_size, dynamic_size, 8);
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
    put(&mut image, relaplt_fo, &relaplt);
    put(&mut image, plt_fo, &plt);
    put(&mut image, gotplt_fo, &gotplt);
    put(&mut image, dynamic_fo, &dynamic);
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
    mk(&mut shstr, &mut shdrs, ".interp", SHT_PROGBITS, SHF_ALLOC, interp_v, interp_fo, interp_bytes.len() as u64, 0, 0, 1, 0);
    let dynsym_idx =
        mk(&mut shstr, &mut shdrs, ".dynsym", SHT_DYNSYM, SHF_ALLOC, dynsym_v, dynsym_fo, dynsym.len() as u64, 0, 1, 8, 24) as u32;
    // .dynsym.link → .dynstr; patched once .dynstr's index is known.
    mk(&mut shstr, &mut shdrs, ".hash", SHT_HASH, SHF_ALLOC, hash_v, hash_fo, hash.len() as u64, dynsym_idx, 0, 8, 4);
    let dynstr_idx =
        mk(&mut shstr, &mut shdrs, ".dynstr", SHT_STRTAB, SHF_ALLOC, dynstr_v, dynstr_fo, dynstr.len() as u64, 0, 0, 1, 0) as u32;
    shdrs[dynsym_idx as usize][40..44].copy_from_slice(&dynstr_idx.to_le_bytes());
    // .rela.plt.info → .got.plt; patched once .got.plt's index is known.
    let relaplt_idx = mk(
        &mut shstr, &mut shdrs, ".rela.plt", SHT_RELA, SHF_ALLOC | SHF_INFO_LINK, relaplt_v, relaplt_fo,
        relaplt_size, dynsym_idx, 0, 8, 24,
    );
    for &i in &ro_order {
        let o = &outs[i];
        mk(&mut shstr, &mut shdrs, &o.name, SHT_PROGBITS, o.flags, o.vaddr, o.file_off, o.data.len() as u64, 0, 0, o.align, 0);
    }
    for &i in &text_order {
        let o = &outs[i];
        mk(&mut shstr, &mut shdrs, &o.name, SHT_PROGBITS, o.flags, o.vaddr, o.file_off, o.data.len() as u64, 0, 0, o.align, 0);
    }
    mk(&mut shstr, &mut shdrs, ".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, plt_v, plt_fo, plt_size, 0, 0, 16, 16);
    for &i in &data_order {
        let o = &outs[i];
        mk(&mut shstr, &mut shdrs, &o.name, SHT_PROGBITS, o.flags, o.vaddr, o.file_off, o.data.len() as u64, 0, 0, o.align, 0);
    }
    let gotplt_idx =
        mk(&mut shstr, &mut shdrs, ".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, gotplt_v, gotplt_fo, gotplt_size, 0, 0, 8, 8) as u32;
    shdrs[relaplt_idx][44..48].copy_from_slice(&gotplt_idx.to_le_bytes());
    mk(&mut shstr, &mut shdrs, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_v, dynamic_fo, dynamic_size, dynstr_idx, 0, 8, 16);
    for &i in &bss_order {
        let o = &outs[i];
        mk(&mut shstr, &mut shdrs, &o.name, SHT_NOBITS, o.flags, o.vaddr, o.vaddr, o.bss_size, 0, 0, o.align.max(1), 0);
    }
    // .shstrtab last; its own name is the final string, so reserve the
    // index before appending the shstrtab bytes.
    let shstrtab_idx = shdrs.len() as u32;
    let shstrtab_off = image.len() as u64;
    // Append the shstrtab's own name, then the section itself.
    mk(&mut shstr, &mut shdrs, ".shstrtab", SHT_STRTAB, 0, 0, shstrtab_off, 0, 0, 0, 1, 0);
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
