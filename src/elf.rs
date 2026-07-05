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
pub const SHT_NOBITS: u32 = 8;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;

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
        let keep = matches!(r.sh_type, SHT_PROGBITS | SHT_NOBITS) && (r.flags & SHF_ALLOC) != 0;
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

/// Names a symtab entry defines (global/weak, section-bound, non-empty).
fn defined_names(obj: &ElfObject, out: &mut HashSet<String>) {
    for sym in &obj.symbols {
        if sym.name.is_empty() || sym.bind == STB_LOCAL || sym.shndx == SHN_UNDEF {
            continue;
        }
        out.insert(sym.name.clone());
    }
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
                let Some(off) = ar
                    .symbol_index()
                    .and_then(|si| si.first_defining_offset(name))
                else {
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
    // Deterministic segment order: text, rodata, data, bss.
    let mut order: Vec<usize> = (0..outs.len()).collect();
    order.sort_by_key(|&i| (output_rank(outs[i].flags, outs[i].is_bss), i));

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

    // ---- Layout: one RX PT_LOAD covering ehdr+phdrs+text/rodata,
    // one RW PT_LOAD for data+bss. (rodata shares the RX segment at
    // rung 1 — matches what lld does with a small freestanding
    // input's defaults closely enough for behavioral parity.)
    let ehsize = 64u64;
    let phnum = 2u64;
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

    // Symbol address resolver (vaddr snapshot avoids borrowing
    // `outs` inside the mutating relocation loop).
    let out_vaddrs: Vec<u64> = outs.iter().map(|o| o.vaddr).collect();
    let sym_vaddr = |oi: usize, si: usize| -> Result<u64, ElfError> {
        let sym = &objects[oi].symbols[si];
        let resolved: (usize, usize) = if sym.shndx == SHN_UNDEF {
            match globals.get(&sym.name) {
                Some(&(doi, dsi)) => (doi, dsi),
                // A weak reference with no definition is legal — it
                // resolves to the absolute address 0. Strong undefined
                // is a real error.
                None if sym.bind == STB_WEAK => return Ok(0),
                None => {
                    return err(format!(
                        "undefined symbol '{}' (referenced from {})",
                        sym.name, objects[oi].name
                    ))
                }
            }
        } else {
            (oi, si)
        };
        let d = &objects[resolved.0].symbols[resolved.1];
        if d.shndx == SHN_ABS {
            return Ok(d.value);
        }
        let Some(sec) = d.section else {
            return err(format!("symbol '{}' has no section", d.name));
        };
        let &(out_idx, sec_base) = place
            .get(&(resolved.0, sec))
            .ok_or_else(|| ElfError(format!("unplaced section for symbol '{}'", d.name)))?;
        Ok(out_vaddrs[out_idx] + sec_base + d.value)
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
                    other => {
                        return err(format!(
                            "relocation type {} is out of rung-1 scope (GOT/TLS land in rung 2)",
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

    // PT_LOAD RX: file [0, rx_end) at BASE_VADDR.
    let mut ph = Vec::new();
    let phdr = |p_type: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64| {
        let mut e = Vec::with_capacity(56);
        e.extend_from_slice(&p_type.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&vaddr.to_le_bytes());
        e.extend_from_slice(&vaddr.to_le_bytes()); // paddr
        e.extend_from_slice(&filesz.to_le_bytes());
        e.extend_from_slice(&memsz.to_le_bytes());
        e.extend_from_slice(&PAGE.to_le_bytes());
        e
    };
    ph.extend(phdr(PT_LOAD, PF_R | PF_X, 0, BASE_VADDR, rx_end, rx_end));
    if rw_pos < order.len() {
        ph.extend(phdr(
            PT_LOAD,
            PF_R | PF_W,
            rw_file_start,
            rw_vaddr_start,
            rw_file_end - rw_file_start,
            rw_mem_end - rw_vaddr_start,
        ));
    } else {
        // Keep phnum fixed at 2 for layout determinism: an empty RW
        // segment at the end of the RX image.
        ph.extend(phdr(PT_LOAD, PF_R | PF_W, rx_end, BASE_VADDR + rx_end, 0, 0));
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

fn next_multiple(v: u64, a: u64) -> u64 {
    let a = a.max(1);
    v.div_ceil(a) * a
}
