//! Linker-side section model.
//!
//! Sprint 2 introduces the `SectionKind` taxonomy the linker reasons about
//! post-parse — code vs data vs zerofill vs TLS vs literals plus the Apple
//! markers (`__compact_unwind`, `__eh_frame`, GOT/stubs/lazy-pointer)
//! identified by sectname because the type nibble alone is ambiguous.
//!
//! Later sprints layer `InputSection` (atomized content) and
//! `OutputSection` / `OutputSegment` (layout model) on top of this module.

use std::collections::HashMap;

use crate::atom::{AtomSection, AtomTable};
use crate::macho::constants::*;
use crate::macho::reader::{name16_str, ReadError, Section64Header};
use crate::resolve::{AtomId, SymbolId, SymbolTable};
use crate::OutputKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Regular code with `S_ATTR_PURE_INSTRUCTIONS` set.
    Text,
    /// Regular data (`S_REGULAR` with none of the attribute markers).
    Data,
    /// `__TEXT,__const` — immutable data.
    ConstData,
    /// `__TEXT,__cstring` (`S_CSTRING_LITERALS`).
    CStringLiterals,
    Literal4,
    Literal8,
    Literal16,
    /// BSS-style uninitialized storage (`S_ZEROFILL`).
    ZeroFill,
    /// > 4 GiB BSS — rare, not used by armfortas today.
    GbZeroFill,
    /// Coalesced (`S_COALESCED`) — per-function weak-def model.
    Coalesced,
    /// Thread-local initialized data.
    ThreadLocalRegular,
    /// Thread-local zerofill.
    ThreadLocalZeroFill,
    /// TLV descriptors (`S_THREAD_LOCAL_VARIABLES`).
    ThreadLocalVariables,
    /// TLV init function pointers.
    ThreadLocalInitPointers,
    /// `__TEXT,__compact_unwind` (`S_REGULAR` + `S_ATTR_DEBUG`).
    CompactUnwind,
    /// `__TEXT,__eh_frame` (`S_COALESCED` + specific attribute bits).
    EhFrame,
    /// Non-lazy symbol pointers — typically `__DATA_CONST,__got`.
    NonLazySymbolPointers,
    /// Lazy symbol pointers — typically `__DATA,__la_symbol_ptr`.
    LazySymbolPointers,
    /// Symbol stubs — typically `__TEXT,__stubs`.
    SymbolStubs,
    /// Any other regular section not otherwise classified.
    Regular,
    /// Unknown section type nibble; carries the nibble for diagnostics.
    Unknown(u8),
}

/// Classify a section by its segment name, section name, and wire `flags`.
pub fn classify_section(segname: &str, sectname: &str, flags: u32) -> SectionKind {
    let ty = flags & SECTION_TYPE_MASK;
    match ty {
        S_ZEROFILL => SectionKind::ZeroFill,
        S_GB_ZEROFILL => SectionKind::GbZeroFill,
        S_CSTRING_LITERALS => SectionKind::CStringLiterals,
        S_4BYTE_LITERALS => SectionKind::Literal4,
        S_8BYTE_LITERALS => SectionKind::Literal8,
        S_16BYTE_LITERALS => SectionKind::Literal16,
        S_NON_LAZY_SYMBOL_POINTERS => SectionKind::NonLazySymbolPointers,
        S_LAZY_SYMBOL_POINTERS => SectionKind::LazySymbolPointers,
        S_SYMBOL_STUBS => SectionKind::SymbolStubs,
        S_COALESCED => {
            if sectname == "__eh_frame" {
                SectionKind::EhFrame
            } else {
                SectionKind::Coalesced
            }
        }
        S_THREAD_LOCAL_REGULAR => SectionKind::ThreadLocalRegular,
        S_THREAD_LOCAL_ZEROFILL => SectionKind::ThreadLocalZeroFill,
        S_THREAD_LOCAL_VARIABLES => SectionKind::ThreadLocalVariables,
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => SectionKind::ThreadLocalInitPointers,
        S_REGULAR => classify_regular(segname, sectname, flags),
        _ => SectionKind::Unknown(ty as u8),
    }
}

fn classify_regular(segname: &str, sectname: &str, flags: u32) -> SectionKind {
    if flags & S_ATTR_DEBUG != 0 && sectname == "__compact_unwind" {
        return SectionKind::CompactUnwind;
    }
    if flags & S_ATTR_PURE_INSTRUCTIONS != 0 {
        return SectionKind::Text;
    }
    if segname == "__TEXT" && sectname == "__const" {
        return SectionKind::ConstData;
    }
    SectionKind::Data
}

/// True if the section holds no bytes in the file (size is virtual).
pub fn is_zerofill(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::ZeroFill | SectionKind::GbZeroFill | SectionKind::ThreadLocalZeroFill
    )
}

/// True if the section carries ARM64 instructions.
pub fn is_executable(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::Text | SectionKind::SymbolStubs | SectionKind::Coalesced
    )
}

// ---------------------------------------------------------------------------
// InputSection — the linker-side model for one input .o's section.
// ---------------------------------------------------------------------------

/// A single input-file section with its decoded header, kind, content slice,
/// and raw relocation bytes. Relocation decoding happens in Sprint 3; here we
/// preserve the wire bytes unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSection {
    pub segname: String,
    pub sectname: String,
    pub kind: SectionKind,
    pub addr: u64,
    pub size: u64,
    pub align_pow2: u32,
    pub flags: u32,
    pub offset: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    /// File-backed bytes of the section. Empty for zerofill/TLS-zerofill/GB.
    pub data: Vec<u8>,
    /// Raw 8-byte relocation_info entries (`nreloc × 8` bytes). Decoded in
    /// Sprint 3; owned here so later passes can reinterpret without
    /// re-reading the source file.
    pub raw_relocs: Vec<u8>,
}

impl InputSection {
    /// Lift an `InputSection` out of a file image using the decoded section
    /// header to locate its content and relocation bytes.
    pub fn from_header(hdr: &Section64Header, file_bytes: &[u8]) -> Result<Self, ReadError> {
        let segname = name16_str(&hdr.segname);
        let sectname = name16_str(&hdr.sectname);
        let kind = classify_section(&segname, &sectname, hdr.flags);

        let data = if is_zerofill(kind) {
            Vec::new()
        } else {
            let start = hdr.offset as usize;
            let end = start
                .checked_add(hdr.size as usize)
                .ok_or(ReadError::Truncated {
                    need: usize::MAX,
                    have: file_bytes.len(),
                    context: "section content (offset + size overflows)",
                })?;
            if end > file_bytes.len() {
                return Err(ReadError::Truncated {
                    need: end,
                    have: file_bytes.len(),
                    context: "section content",
                });
            }
            file_bytes[start..end].to_vec()
        };

        let raw_relocs = if hdr.nreloc == 0 {
            Vec::new()
        } else {
            let start = hdr.reloff as usize;
            let total = (hdr.nreloc as usize)
                .checked_mul(8)
                .ok_or(ReadError::Truncated {
                    need: usize::MAX,
                    have: file_bytes.len(),
                    context: "section relocs (nreloc × 8 overflows)",
                })?;
            let end = start.checked_add(total).ok_or(ReadError::Truncated {
                need: usize::MAX,
                have: file_bytes.len(),
                context: "section relocs (reloff + size overflows)",
            })?;
            if end > file_bytes.len() {
                return Err(ReadError::Truncated {
                    need: end,
                    have: file_bytes.len(),
                    context: "section relocs",
                });
            }
            file_bytes[start..end].to_vec()
        };

        Ok(InputSection {
            segname,
            sectname,
            kind,
            addr: hdr.addr,
            size: hdr.size,
            align_pow2: hdr.align,
            flags: hdr.flags,
            offset: hdr.offset,
            reloff: hdr.reloff,
            nreloc: hdr.nreloc,
            reserved1: hdr.reserved1,
            reserved2: hdr.reserved2,
            reserved3: hdr.reserved3,
            data,
            raw_relocs,
        })
    }
}

// ---------------------------------------------------------------------------
// Output layout model — Sprint 10.
// ---------------------------------------------------------------------------

pub const PAGE_SIZE: u64 = 16 * 1024;
pub const PAGEZERO_SIZE: u64 = 0x1_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputSectionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot {
    bits: u32,
}

impl Prot {
    pub const NONE: Self = Self { bits: 0 };
    pub const READ: Self = Self { bits: 1 };
    pub const WRITE: Self = Self { bits: 2 };
    pub const EXECUTE: Self = Self { bits: 4 };

    pub fn bits(self) -> u32 {
        self.bits
    }
}

impl std::ops::BitOr for Prot {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSegment {
    pub name: String,
    pub sections: Vec<OutputSectionId>,
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub init_prot: Prot,
    pub max_prot: Prot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSection {
    pub segment: String,
    pub name: String,
    pub kind: SectionKind,
    pub align_pow2: u8,
    pub flags: u32,
    pub atoms: Vec<AtomId>,
    pub addr: u64,
    pub size: u64,
    pub file_off: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: OutputKind,
    pub segments: Vec<OutputSegment>,
    pub sections: Vec<OutputSection>,
}

pub fn build_empty_layout(kind: OutputKind) -> Layout {
    build_layout(kind, &AtomTable::new(), &SymbolTable::new())
}

pub fn build_layout(kind: OutputKind, atoms: &AtomTable, symbols: &SymbolTable) -> Layout {
    let mut groups = Vec::<SectionBuildGroup>::new();
    let mut by_key = HashMap::<(&'static str, &'static str), usize>::new();

    for (atom_id, atom) in atoms.iter() {
        let spec = output_section_spec(atom.section);
        let idx = *by_key.entry((spec.segment, spec.name)).or_insert_with(|| {
            groups.push(SectionBuildGroup {
                spec,
                atoms: Vec::new(),
            });
            groups.len() - 1
        });
        groups[idx].atoms.push(atom_id);
    }

    for group in &mut groups {
        group.atoms.sort_by(|a, b| compare_atoms(*a, *b, atoms, symbols));
    }

    groups.sort_by(|a, b| {
        (
            a.spec.segment_order,
            a.spec.section_order,
            a.spec.segment,
            a.spec.name,
        )
            .cmp(&(
                b.spec.segment_order,
                b.spec.section_order,
                b.spec.segment,
                b.spec.name,
            ))
    });

    let mut sections = Vec::with_capacity(groups.len());
    for group in groups {
        let (align_pow2, size) = measure_output_section(&group.atoms, atoms);
        sections.push(OutputSection {
            segment: group.spec.segment.to_string(),
            name: group.spec.name.to_string(),
            kind: group.spec.kind,
            align_pow2,
            flags: group.spec.flags,
            atoms: group.atoms,
            addr: 0,
            size,
            file_off: 0,
        });
    }

    let segments = build_output_segments(kind, &sections);
    Layout {
        kind,
        segments,
        sections,
    }
}

pub fn assign_layout(layout: &mut Layout, header_and_cmds_size: u64, linkedit_size: u64) {
    let mut next_vm = if layout.kind == OutputKind::Executable {
        PAGEZERO_SIZE
    } else {
        0
    };
    let mut next_file = 0u64;

    for segment in &mut layout.segments {
        match segment.name.as_str() {
            "__PAGEZERO" => {
                segment.vm_addr = 0;
                segment.vm_size = PAGEZERO_SIZE;
                segment.file_off = 0;
                segment.file_size = 0;
            }
            "__LINKEDIT" => {
                segment.vm_addr = align_to(next_vm, PAGE_SIZE);
                segment.file_off = align_to(next_file, PAGE_SIZE);
                segment.vm_size = if linkedit_size == 0 {
                    0
                } else {
                    align_to(linkedit_size, PAGE_SIZE)
                };
                segment.file_size = linkedit_size;
                next_vm = segment.vm_addr + segment.vm_size;
                next_file = segment.file_off + segment.file_size;
            }
            _ => {
                segment.vm_addr = next_vm;
                segment.file_off = next_file;

                let prefix = if segment.name == "__TEXT" {
                    header_and_cmds_size
                } else {
                    0
                };
                let mut vm_cursor = prefix;
                let mut file_cursor = prefix;

                for sec_id in &segment.sections {
                    let section = &mut layout.sections[sec_id.0 as usize];
                    let align = 1u64 << section.align_pow2;
                    vm_cursor = align_to(vm_cursor, align);
                    section.addr = segment.vm_addr + vm_cursor;

                    if is_zerofill(section.kind) {
                        section.file_off = segment.file_off + file_cursor;
                        vm_cursor += section.size;
                    } else {
                        file_cursor = align_to(file_cursor, align);
                        vm_cursor = vm_cursor.max(file_cursor);
                        section.file_off = segment.file_off + file_cursor;
                        vm_cursor += section.size;
                        file_cursor += section.size;
                    }
                }

                segment.file_size = prefix.max(file_cursor);
                segment.vm_size = if prefix.max(vm_cursor) == 0 {
                    0
                } else {
                    align_to(prefix.max(vm_cursor), PAGE_SIZE)
                };
                next_vm = align_to(segment.vm_addr + segment.vm_size, PAGE_SIZE);
                next_file = align_to(segment.file_off + segment.file_size, PAGE_SIZE);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OutputSectionSpec {
    segment: &'static str,
    name: &'static str,
    kind: SectionKind,
    flags: u32,
    segment_order: u8,
    section_order: u8,
}

#[derive(Debug)]
struct SectionBuildGroup {
    spec: OutputSectionSpec,
    atoms: Vec<AtomId>,
}

fn build_output_segments(kind: OutputKind, sections: &[OutputSection]) -> Vec<OutputSegment> {
    let mut ids_by_segment: HashMap<&str, Vec<OutputSectionId>> = HashMap::new();
    for (idx, section) in sections.iter().enumerate() {
        ids_by_segment
            .entry(section.segment.as_str())
            .or_default()
            .push(OutputSectionId(idx as u32));
    }

    let mut out = Vec::new();
    if kind == OutputKind::Executable {
        out.push(OutputSegment {
            name: "__PAGEZERO".into(),
            sections: Vec::new(),
            vm_addr: 0,
            vm_size: 0,
            file_off: 0,
            file_size: 0,
            init_prot: Prot::NONE,
            max_prot: Prot::NONE,
        });
    }

    for (name, init_prot, max_prot, always_present) in [
        (
            "__TEXT",
            Prot::READ | Prot::EXECUTE,
            Prot::READ | Prot::EXECUTE,
            true,
        ),
        (
            "__DATA_CONST",
            Prot::READ,
            Prot::READ | Prot::WRITE,
            false,
        ),
        (
            "__DATA",
            Prot::READ | Prot::WRITE,
            Prot::READ | Prot::WRITE,
            false,
        ),
        ("__LINKEDIT", Prot::READ, Prot::READ, true),
    ] {
        let sections = ids_by_segment.remove(name).unwrap_or_default();
        if !always_present && sections.is_empty() {
            continue;
        }
        out.push(OutputSegment {
            name: name.into(),
            sections,
            vm_addr: 0,
            vm_size: 0,
            file_off: 0,
            file_size: 0,
            init_prot,
            max_prot,
        });
    }

    out
}

fn compare_atoms(
    a: AtomId,
    b: AtomId,
    atoms: &AtomTable,
    symbols: &SymbolTable,
) -> std::cmp::Ordering {
    let a_atom = atoms.get(a);
    let b_atom = atoms.get(b);
    (a_atom.origin.0, a_atom.input_offset)
        .cmp(&(b_atom.origin.0, b_atom.input_offset))
        .then_with(|| owner_name(a_atom.owner, symbols).cmp(owner_name(b_atom.owner, symbols)))
}

fn owner_name(owner: Option<SymbolId>, symbols: &SymbolTable) -> &str {
    match owner {
        Some(id) => symbols.interner.resolve(symbols.get(id).name()),
        None => "",
    }
}

fn measure_output_section(atom_ids: &[AtomId], atoms: &AtomTable) -> (u8, u64) {
    let mut align_pow2 = 0u8;
    let mut size = 0u64;
    for atom_id in atom_ids {
        let atom = atoms.get(*atom_id);
        align_pow2 = align_pow2.max(atom.align_pow2);
        size = align_to(size, 1u64 << atom.align_pow2);
        size += atom.size as u64;
    }
    (align_pow2, size)
}

fn output_section_spec(section: AtomSection) -> OutputSectionSpec {
    match section {
        AtomSection::Text | AtomSection::Coalesced => OutputSectionSpec {
            segment: "__TEXT",
            name: "__text",
            kind: if matches!(section, AtomSection::Coalesced) {
                SectionKind::Coalesced
            } else {
                SectionKind::Text
            },
            flags: if matches!(section, AtomSection::Coalesced) {
                S_COALESCED
            } else {
                S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
            },
            segment_order: 1,
            section_order: 0,
        },
        AtomSection::SymbolStubs => OutputSectionSpec {
            segment: "__TEXT",
            name: "__stubs",
            kind: SectionKind::SymbolStubs,
            flags: S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            segment_order: 1,
            section_order: 1,
        },
        AtomSection::CStringLiterals => OutputSectionSpec {
            segment: "__TEXT",
            name: "__cstring",
            kind: SectionKind::CStringLiterals,
            flags: S_CSTRING_LITERALS,
            segment_order: 1,
            section_order: 3,
        },
        AtomSection::ConstData => OutputSectionSpec {
            segment: "__TEXT",
            name: "__const",
            kind: SectionKind::ConstData,
            flags: S_REGULAR,
            segment_order: 1,
            section_order: 4,
        },
        AtomSection::Literal4 => OutputSectionSpec {
            segment: "__TEXT",
            name: "__literal4",
            kind: SectionKind::Literal4,
            flags: S_4BYTE_LITERALS,
            segment_order: 1,
            section_order: 5,
        },
        AtomSection::Literal8 => OutputSectionSpec {
            segment: "__TEXT",
            name: "__literal8",
            kind: SectionKind::Literal8,
            flags: S_8BYTE_LITERALS,
            segment_order: 1,
            section_order: 6,
        },
        AtomSection::Literal16 => OutputSectionSpec {
            segment: "__TEXT",
            name: "__literal16",
            kind: SectionKind::Literal16,
            flags: S_16BYTE_LITERALS,
            segment_order: 1,
            section_order: 7,
        },
        AtomSection::CompactUnwind => OutputSectionSpec {
            segment: "__TEXT",
            name: "__unwind_info",
            kind: SectionKind::CompactUnwind,
            flags: S_REGULAR | S_ATTR_DEBUG,
            segment_order: 1,
            section_order: 8,
        },
        AtomSection::EhFrame => OutputSectionSpec {
            segment: "__TEXT",
            name: "__eh_frame",
            kind: SectionKind::EhFrame,
            flags: S_COALESCED,
            segment_order: 1,
            section_order: 9,
        },
        AtomSection::NonLazySymbolPointers => OutputSectionSpec {
            segment: "__DATA_CONST",
            name: "__got",
            kind: SectionKind::NonLazySymbolPointers,
            flags: S_NON_LAZY_SYMBOL_POINTERS,
            segment_order: 2,
            section_order: 0,
        },
        AtomSection::Data | AtomSection::Other => OutputSectionSpec {
            segment: "__DATA",
            name: "__data",
            kind: if matches!(section, AtomSection::Other) {
                SectionKind::Regular
            } else {
                SectionKind::Data
            },
            flags: S_REGULAR,
            segment_order: 3,
            section_order: 1,
        },
        AtomSection::LazySymbolPointers => OutputSectionSpec {
            segment: "__DATA",
            name: "__la_symbol_ptr",
            kind: SectionKind::LazySymbolPointers,
            flags: S_LAZY_SYMBOL_POINTERS,
            segment_order: 3,
            section_order: 0,
        },
        AtomSection::ThreadLocalVariables => OutputSectionSpec {
            segment: "__DATA",
            name: "__thread_vars",
            kind: SectionKind::ThreadLocalVariables,
            flags: S_THREAD_LOCAL_VARIABLES,
            segment_order: 3,
            section_order: 2,
        },
        AtomSection::ThreadLocalInitPointers => OutputSectionSpec {
            segment: "__DATA",
            name: "__thread_ptrs",
            kind: SectionKind::ThreadLocalInitPointers,
            flags: S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
            segment_order: 3,
            section_order: 3,
        },
        AtomSection::ThreadLocalData => OutputSectionSpec {
            segment: "__DATA",
            name: "__thread_data",
            kind: SectionKind::ThreadLocalRegular,
            flags: S_THREAD_LOCAL_REGULAR,
            segment_order: 3,
            section_order: 4,
        },
        AtomSection::ThreadLocalBss => OutputSectionSpec {
            segment: "__DATA",
            name: "__thread_bss",
            kind: SectionKind::ThreadLocalZeroFill,
            flags: S_THREAD_LOCAL_ZEROFILL,
            segment_order: 3,
            section_order: 5,
        },
        AtomSection::ZeroFill => OutputSectionSpec {
            segment: "__DATA",
            name: "__bss",
            kind: SectionKind::ZeroFill,
            flags: S_ZEROFILL,
            segment_order: 3,
            section_order: 6,
        },
    }
}

fn align_to(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
    use crate::resolve::{AtomId, InputId, SymbolTable};

    #[test]
    fn classify_text_section() {
        let k = classify_section(
            "__TEXT",
            "__text",
            S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
        );
        assert_eq!(k, SectionKind::Text);
        assert!(is_executable(k));
    }

    #[test]
    fn classify_cstring_literals() {
        assert_eq!(
            classify_section("__TEXT", "__cstring", S_CSTRING_LITERALS),
            SectionKind::CStringLiterals
        );
    }

    #[test]
    fn classify_zerofill() {
        let k = classify_section("__DATA", "__bss", S_ZEROFILL);
        assert_eq!(k, SectionKind::ZeroFill);
        assert!(is_zerofill(k));
    }

    #[test]
    fn classify_const_data() {
        assert_eq!(
            classify_section("__TEXT", "__const", S_REGULAR),
            SectionKind::ConstData
        );
    }

    #[test]
    fn classify_regular_data() {
        assert_eq!(
            classify_section("__DATA", "__data", S_REGULAR),
            SectionKind::Data
        );
    }

    #[test]
    fn classify_compact_unwind() {
        let flags = S_REGULAR | S_ATTR_DEBUG;
        assert_eq!(
            classify_section("__TEXT", "__compact_unwind", flags),
            SectionKind::CompactUnwind
        );
    }

    #[test]
    fn classify_eh_frame_vs_coalesced() {
        assert_eq!(
            classify_section("__TEXT", "__eh_frame", S_COALESCED),
            SectionKind::EhFrame
        );
        assert_eq!(
            classify_section("__TEXT", "__weak_text", S_COALESCED),
            SectionKind::Coalesced
        );
    }

    #[test]
    fn classify_tls_family() {
        assert_eq!(
            classify_section("__DATA", "__thread_data", S_THREAD_LOCAL_REGULAR),
            SectionKind::ThreadLocalRegular
        );
        assert_eq!(
            classify_section("__DATA", "__thread_bss", S_THREAD_LOCAL_ZEROFILL),
            SectionKind::ThreadLocalZeroFill
        );
        assert_eq!(
            classify_section("__DATA", "__thread_vars", S_THREAD_LOCAL_VARIABLES),
            SectionKind::ThreadLocalVariables
        );
    }

    #[test]
    fn classify_got_and_stubs() {
        assert_eq!(
            classify_section("__DATA_CONST", "__got", S_NON_LAZY_SYMBOL_POINTERS),
            SectionKind::NonLazySymbolPointers
        );
        assert_eq!(
            classify_section("__TEXT", "__stubs", S_SYMBOL_STUBS),
            SectionKind::SymbolStubs
        );
        assert_eq!(
            classify_section("__DATA", "__la_symbol_ptr", S_LAZY_SYMBOL_POINTERS),
            SectionKind::LazySymbolPointers
        );
    }

    #[test]
    fn unknown_type_nibble_preserved() {
        let weird = 0xFFu32;
        assert_eq!(
            classify_section("__WEIRD", "__weird", weird),
            SectionKind::Unknown(0xFF)
        );
    }

    fn synth_atom(origin: InputId, input_offset: u32, size: u32, section: AtomSection) -> Atom {
        Atom {
            id: AtomId(0),
            origin,
            input_section: 1,
            section,
            input_offset,
            size,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            relocs: Vec::new(),
            data: vec![0; size as usize],
            flags: AtomFlags::NONE,
            parent_of: None,
        }
    }

    #[test]
    fn empty_executable_layout_has_pagezero_text_and_linkedit() {
        let mut layout = build_empty_layout(OutputKind::Executable);
        assign_layout(&mut layout, 0x300, 0);

        let names: Vec<_> = layout.segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["__PAGEZERO", "__TEXT", "__LINKEDIT"]);

        let text = layout
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .expect("__TEXT");
        assert_eq!(text.vm_addr, PAGEZERO_SIZE);
        assert_eq!(text.file_off, 0);
        assert_eq!(text.file_size, 0x300);
        assert_eq!(text.vm_size, PAGE_SIZE);
    }

    #[test]
    fn empty_dylib_layout_starts_text_at_zero() {
        let mut layout = build_empty_layout(OutputKind::Dylib);
        assign_layout(&mut layout, 0x280, 0);

        let names: Vec<_> = layout.segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["__TEXT", "__LINKEDIT"]);

        let text = layout
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .expect("__TEXT");
        assert_eq!(text.vm_addr, 0);
        assert_eq!(text.file_off, 0);
        assert_eq!(text.file_size, 0x280);
    }

    #[test]
    fn build_layout_orders_atoms_by_origin_then_offset() {
        let mut atoms = AtomTable::new();
        let b = atoms.push(synth_atom(InputId(1), 0, 4, AtomSection::Data));
        let c = atoms.push(synth_atom(InputId(0), 8, 4, AtomSection::Data));
        let a = atoms.push(synth_atom(InputId(0), 0, 4, AtomSection::Data));

        let layout = build_layout(OutputKind::Executable, &atoms, &SymbolTable::new());
        let data = layout
            .sections
            .iter()
            .find(|s| s.segment == "__DATA" && s.name == "__data")
            .expect("__DATA,__data");

        assert_eq!(data.atoms, vec![a, c, b]);
        assert_eq!(data.size, 12);
    }
}
