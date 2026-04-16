//! Linker-side section model.
//!
//! Sprint 2 introduces the `SectionKind` taxonomy the linker reasons about
//! post-parse — code vs data vs zerofill vs TLS vs literals plus the Apple
//! markers (`__compact_unwind`, `__eh_frame`, GOT/stubs/lazy-pointer)
//! identified by sectname because the type nibble alone is ambiguous.
//!
//! Later sprints layer `InputSection` (atomized content) and
//! `OutputSection` / `OutputSegment` (layout model) on top of this module.

use crate::macho::constants::*;
use crate::macho::reader::{name16_str, ReadError, Section64Header};
use crate::resolve::AtomId;

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
            let end = start.checked_add(hdr.size as usize).ok_or(ReadError::Truncated {
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
            let total = (hdr.nreloc as usize).checked_mul(8).ok_or(ReadError::Truncated {
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
// Output layout model — populated by Sprint 10's layout pass.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputSectionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot(u32);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXECUTE: Prot = Prot(4);
    pub const READ_ONLY: Prot = Prot(Self::READ.0);
    pub const READ_WRITE: Prot = Prot(Self::READ.0 | Self::WRITE.0);
    pub const READ_EXECUTE: Prot = Prot(Self::READ.0 | Self::EXECUTE.0);

    pub fn bits(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputAtom {
    pub atom: AtomId,
    pub offset: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSection {
    pub segment: String,
    pub name: String,
    pub kind: SectionKind,
    pub align_pow2: u8,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    pub atoms: Vec<OutputAtom>,
    pub synthetic_data: Vec<u8>,
    pub addr: u64,
    pub size: u64,
    pub file_off: u64,
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

impl OutputSection {
    pub fn is_zerofill(&self) -> bool {
        is_zerofill(self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
