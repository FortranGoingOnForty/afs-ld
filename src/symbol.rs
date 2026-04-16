//! Symbol-table reader.
//!
//! Decodes 16-byte `nlist_64` records and exposes them via `InputSymbol`,
//! which keeps the raw wire bytes for byte-level round-trip and layers rich
//! accessors (kind, externness, weak flags, common size/alignment, library
//! ordinal, indirect aliased-name strx) on top.
//!
//! Sprint 2 scope: parse/encode + classification. The name-resolution step
//! that turns `strx` into `&str` lives on `ObjectFile` once `StringTable`
//! lands alongside this module.

use crate::macho::constants::*;
use crate::macho::reader::{u32_le, u64_le, ReadError};

/// Size of one `nlist_64` on the wire.
pub const NLIST_SIZE: usize = 16;

/// 16-byte `nlist_64` — exact wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawNlist {
    pub strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

impl RawNlist {
    pub fn parse(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.len() < NLIST_SIZE {
            return Err(ReadError::Truncated {
                need: NLIST_SIZE,
                have: bytes.len(),
                context: "nlist_64",
            });
        }
        Ok(RawNlist {
            strx: u32_le(&bytes[0..4]),
            n_type: bytes[4],
            n_sect: bytes[5],
            n_desc: u16::from_le_bytes([bytes[6], bytes[7]]),
            n_value: u64_le(&bytes[8..16]),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.strx.to_le_bytes());
        out.push(self.n_type);
        out.push(self.n_sect);
        out.extend_from_slice(&self.n_desc.to_le_bytes());
        out.extend_from_slice(&self.n_value.to_le_bytes());
    }
}

/// Coarse classification of an `nlist_64` based on its `n_type & N_TYPE` bits.
/// Stab (debug) entries sit alongside this in `InputSymbol::stab_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKind {
    Undef,
    Abs,
    Sect,
    Indirect,
}

/// Linker-side view of one symbol. Carries the raw nlist for round-trip and
/// a set of accessors that decode its semantic meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputSymbol {
    pub raw: RawNlist,
}

impl InputSymbol {
    pub fn from_raw(raw: RawNlist) -> Self {
        InputSymbol { raw }
    }

    pub fn strx(&self) -> u32 {
        self.raw.strx
    }

    pub fn sect_idx(&self) -> u8 {
        self.raw.n_sect
    }

    pub fn value(&self) -> u64 {
        self.raw.n_value
    }

    /// If this is a stabs debug entry, return the stab kind byte; else `None`.
    pub fn stab_kind(&self) -> Option<u8> {
        if self.raw.n_type & N_STAB != 0 {
            Some(self.raw.n_type)
        } else {
            None
        }
    }

    /// Classify the non-stab kind. For stab entries callers should first check
    /// `stab_kind()` and treat the result as opaque.
    pub fn kind(&self) -> SymKind {
        match self.raw.n_type & N_TYPE {
            N_UNDF => SymKind::Undef,
            N_ABS => SymKind::Abs,
            N_SECT => SymKind::Sect,
            N_INDR => SymKind::Indirect,
            // `N_PBUD` (0xc) is obsolete; treat as Undef to keep matching total.
            _ => SymKind::Undef,
        }
    }

    pub fn is_ext(&self) -> bool {
        self.raw.n_type & N_EXT != 0
    }

    pub fn is_private_ext(&self) -> bool {
        self.raw.n_type & N_PEXT != 0
    }

    pub fn weak_ref(&self) -> bool {
        self.raw.n_desc & N_WEAK_REF != 0
    }

    pub fn weak_def(&self) -> bool {
        self.raw.n_desc & N_WEAK_DEF != 0
    }

    pub fn no_dead_strip(&self) -> bool {
        self.raw.n_desc & N_NO_DEAD_STRIP != 0
    }

    /// True for symbols marked as an alternate entry point for their
    /// section's preceding atom. Atomization folds these into the
    /// owning atom's `alt_entries` list instead of splitting at them.
    pub fn alt_entry(&self) -> bool {
        self.raw.n_desc & N_ALT_ENTRY != 0
    }

    /// True iff this is an external undefined symbol with a non-zero size —
    /// the Mach-O convention for "common" tentative definitions.
    pub fn is_common(&self) -> bool {
        self.kind() == SymKind::Undef && self.is_ext() && self.raw.n_value > 0
    }

    /// Size (in bytes) of a common symbol; `None` if not common.
    pub fn common_size(&self) -> Option<u64> {
        self.is_common().then_some(self.raw.n_value)
    }

    /// Log-2 alignment of a common symbol, encoded in `n_desc` bits 8..11.
    /// `None` if the symbol is not common.
    pub fn common_align_pow2(&self) -> Option<u8> {
        self.is_common()
            .then_some(((self.raw.n_desc >> 8) & 0x0f) as u8)
    }

    /// Two-level-namespace library ordinal from an undefined symbol's
    /// `n_desc` high byte. `None` for non-undefined symbols and common
    /// symbols (common uses those bits for alignment).
    pub fn library_ordinal(&self) -> Option<u8> {
        if self.kind() == SymKind::Undef && !self.is_common() {
            Some((self.raw.n_desc >> 8) as u8)
        } else {
            None
        }
    }

    /// For `N_INDR` aliases: `n_value` holds a strx into the string table
    /// naming the target symbol.
    pub fn indirect_target_strx(&self) -> Option<u32> {
        if self.kind() == SymKind::Indirect {
            Some(self.raw.n_value as u32)
        } else {
            None
        }
    }
}

/// Parse `nsyms` consecutive nlist entries starting at `symoff` bytes into the
/// file image. Errors on truncation or an out-of-bounds offset.
pub fn parse_nlist_table(
    file_bytes: &[u8],
    symoff: u32,
    nsyms: u32,
) -> Result<Vec<InputSymbol>, ReadError> {
    let start = symoff as usize;
    let total = (nsyms as usize)
        .checked_mul(NLIST_SIZE)
        .ok_or(ReadError::Truncated {
            need: usize::MAX,
            have: file_bytes.len(),
            context: "symbol table (nsyms × 16 overflows)",
        })?;
    let end = start.checked_add(total).ok_or(ReadError::Truncated {
        need: usize::MAX,
        have: file_bytes.len(),
        context: "symbol table (symoff + size overflows)",
    })?;
    if end > file_bytes.len() {
        return Err(ReadError::Truncated {
            need: end,
            have: file_bytes.len(),
            context: "symbol table (nlist region)",
        });
    }
    let mut out = Vec::with_capacity(nsyms as usize);
    for i in 0..nsyms as usize {
        let off = start + i * NLIST_SIZE;
        out.push(InputSymbol::from_raw(RawNlist::parse(
            &file_bytes[off..off + NLIST_SIZE],
        )?));
    }
    Ok(out)
}

/// Serialize a symbol table back to wire form (nsyms × 16 contiguous bytes).
pub fn write_nlist_table(syms: &[InputSymbol], out: &mut Vec<u8>) {
    for s in syms {
        s.raw.write(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlist(strx: u32, n_type: u8, n_sect: u8, n_desc: u16, n_value: u64) -> RawNlist {
        RawNlist {
            strx,
            n_type,
            n_sect,
            n_desc,
            n_value,
        }
    }

    #[test]
    fn raw_nlist_round_trips_byte_equal() {
        let raw = nlist(42, N_SECT | N_EXT, 3, N_WEAK_DEF, 0x1_0000_0040);
        let mut buf = Vec::new();
        raw.write(&mut buf);
        assert_eq!(buf.len(), NLIST_SIZE);
        let back = RawNlist::parse(&buf).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn classify_extern_text_symbol() {
        let sym = InputSymbol::from_raw(nlist(10, N_SECT | N_EXT, 1, 0, 0x100));
        assert_eq!(sym.kind(), SymKind::Sect);
        assert!(sym.is_ext());
        assert!(!sym.is_private_ext());
        assert!(!sym.is_common());
        assert_eq!(sym.library_ordinal(), None);
    }

    #[test]
    fn classify_local_symbol() {
        let sym = InputSymbol::from_raw(nlist(20, N_SECT, 2, 0, 0x200));
        assert_eq!(sym.kind(), SymKind::Sect);
        assert!(!sym.is_ext());
    }

    #[test]
    fn classify_undef_import() {
        let sym = InputSymbol::from_raw(nlist(30, N_UNDF | N_EXT, 0, 3 << 8, 0));
        assert_eq!(sym.kind(), SymKind::Undef);
        assert!(sym.is_ext());
        assert!(!sym.is_common());
        assert_eq!(sym.library_ordinal(), Some(3));
    }

    #[test]
    fn classify_common_symbol() {
        // UNDF + EXT + size 16, alignment 2^3 = 8.
        let n_desc = (3u16) << 8;
        let sym = InputSymbol::from_raw(nlist(40, N_UNDF | N_EXT, 0, n_desc, 16));
        assert!(sym.is_common());
        assert_eq!(sym.common_size(), Some(16));
        assert_eq!(sym.common_align_pow2(), Some(3));
        assert_eq!(sym.library_ordinal(), None);
    }

    #[test]
    fn classify_weak_def() {
        let sym = InputSymbol::from_raw(nlist(50, N_SECT | N_EXT, 1, N_WEAK_DEF, 0x400));
        assert!(sym.weak_def());
        assert!(!sym.weak_ref());
    }

    #[test]
    fn classify_weak_ref_import() {
        let sym = InputSymbol::from_raw(nlist(60, N_UNDF | N_EXT, 0, N_WEAK_REF | (1 << 8), 0));
        assert_eq!(sym.kind(), SymKind::Undef);
        assert!(sym.weak_ref());
        assert_eq!(sym.library_ordinal(), Some(1));
    }

    #[test]
    fn classify_private_extern() {
        let sym = InputSymbol::from_raw(nlist(70, N_SECT | N_EXT | N_PEXT, 1, 0, 0x800));
        assert!(sym.is_ext());
        assert!(sym.is_private_ext());
    }

    #[test]
    fn classify_absolute() {
        let sym = InputSymbol::from_raw(nlist(80, N_ABS | N_EXT, 0, 0, 0xDEAD_BEEF));
        assert_eq!(sym.kind(), SymKind::Abs);
        assert!(sym.is_ext());
    }

    #[test]
    fn classify_indirect_alias() {
        // `n_value` carries the strx of the aliased name.
        let sym = InputSymbol::from_raw(nlist(90, N_INDR | N_EXT, 0, 0, 123));
        assert_eq!(sym.kind(), SymKind::Indirect);
        assert_eq!(sym.indirect_target_strx(), Some(123));
    }

    #[test]
    fn classify_stab_entry_preserved() {
        // Stab entry — the whole n_type byte encodes the stab kind.
        let stab_type: u8 = 0x24; // N_FUN
        let sym = InputSymbol::from_raw(nlist(100, stab_type, 1, 0, 0x1000));
        assert_eq!(sym.stab_kind(), Some(stab_type));
    }

    #[test]
    fn symtab_round_trip_byte_equal() {
        let syms = vec![
            InputSymbol::from_raw(nlist(1, N_SECT | N_EXT, 1, 0, 0x100)),
            InputSymbol::from_raw(nlist(2, N_UNDF | N_EXT, 0, 1 << 8, 0)),
            InputSymbol::from_raw(nlist(3, N_ABS, 0, 0, 42)),
        ];

        // Plant them at offset 8 into a synthetic file image.
        let mut image = vec![0u8; 8];
        write_nlist_table(&syms, &mut image);
        assert_eq!(image.len(), 8 + 3 * NLIST_SIZE);

        let parsed = parse_nlist_table(&image, 8, 3).unwrap();
        assert_eq!(parsed, syms);
    }

    #[test]
    fn symtab_truncation_errors() {
        // Ask for 2 symbols but only 16 bytes available (one fits, second doesn't).
        let image = vec![0u8; 16];
        let err = parse_nlist_table(&image, 0, 2).unwrap_err();
        assert!(matches!(err, ReadError::Truncated { .. }));
    }
}
