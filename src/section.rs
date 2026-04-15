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
