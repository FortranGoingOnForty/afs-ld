//! Atomization model.
//!
//! An **atom** is the linker's fundamental unit of output layout,
//! dead-stripping, and ICF. Each input section is split into one or more
//! atoms; output sections are concatenations of atoms. Every
//! `Symbol::Defined` owns exactly one atom (except `.alt_entry` chain
//! symbols which fold into a predecessor's atom).
//!
//! afs-as always sets `MH_SUBSECTIONS_VIA_SYMBOLS`, so in practice text and
//! data sections split at symbol boundaries; literal sections
//! (`__cstring`, `__literal*`) split at content boundaries; zerofill and
//! TLS sections split per-symbol. The full ruleset lives in
//! [`atomize_input_section`].
//!
//! Later passes reference atoms via `AtomId` (Sprint 7's opaque handle).
//! This module hands out ids via `AtomTable::push`; `AtomId(0)` is a
//! pre-existing sentinel meaning "no atom bound yet" (used by
//! `Symbol::Defined { atom }` before atomization back-patches it).

use std::collections::HashMap;

use crate::resolve::{AtomId, InputId, SymbolId};
use crate::section::SectionKind;

/// Which conceptual output section family this atom belongs to. Sprint 10
/// turns these into real `__TEXT,__text` / `__DATA,__data` etc. placements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtomSection {
    Text,
    Data,
    ConstData,
    CStringLiterals,
    Literal4,
    Literal8,
    Literal16,
    ZeroFill,
    ThreadLocalData,
    ThreadLocalBss,
    ThreadLocalVariables,
    ThreadLocalInitPointers,
    Coalesced,
    CompactUnwind,
    EhFrame,
    SymbolStubs,
    NonLazySymbolPointers,
    LazySymbolPointers,
    /// Section kind we don't have specialized layout for yet. Layout still
    /// works (output section keyed by segname/sectname) but downstream
    /// passes treat it opaquely.
    Other,
}

impl AtomSection {
    pub fn from_section_kind(kind: SectionKind) -> Self {
        match kind {
            SectionKind::Text => AtomSection::Text,
            SectionKind::Data => AtomSection::Data,
            SectionKind::ConstData => AtomSection::ConstData,
            SectionKind::CStringLiterals => AtomSection::CStringLiterals,
            SectionKind::Literal4 => AtomSection::Literal4,
            SectionKind::Literal8 => AtomSection::Literal8,
            SectionKind::Literal16 => AtomSection::Literal16,
            SectionKind::ZeroFill | SectionKind::GbZeroFill => AtomSection::ZeroFill,
            SectionKind::ThreadLocalRegular => AtomSection::ThreadLocalData,
            SectionKind::ThreadLocalZeroFill => AtomSection::ThreadLocalBss,
            SectionKind::ThreadLocalVariables => AtomSection::ThreadLocalVariables,
            SectionKind::ThreadLocalInitPointers => AtomSection::ThreadLocalInitPointers,
            SectionKind::Coalesced => AtomSection::Coalesced,
            SectionKind::CompactUnwind => AtomSection::CompactUnwind,
            SectionKind::EhFrame => AtomSection::EhFrame,
            SectionKind::SymbolStubs => AtomSection::SymbolStubs,
            SectionKind::NonLazySymbolPointers => AtomSection::NonLazySymbolPointers,
            SectionKind::LazySymbolPointers => AtomSection::LazySymbolPointers,
            SectionKind::Regular | SectionKind::Unknown(_) => AtomSection::Other,
        }
    }

    pub fn is_zerofill(self) -> bool {
        matches!(
            self,
            AtomSection::ZeroFill | AtomSection::ThreadLocalBss
        )
    }

    pub fn is_literal(self) -> bool {
        matches!(
            self,
            AtomSection::CStringLiterals
                | AtomSection::Literal4
                | AtomSection::Literal8
                | AtomSection::Literal16
        )
    }
}

/// Bit-packed boolean attributes. Fields intentionally narrow — each bit
/// carries clear linker-visible meaning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AtomFlags {
    bits: u32,
}

impl AtomFlags {
    pub const NONE: AtomFlags = AtomFlags { bits: 0 };
    pub const NO_DEAD_STRIP: u32 = 1 << 0;
    pub const WEAK_DEF: u32 = 1 << 1;
    pub const THREAD_LOCAL: u32 = 1 << 2;
    pub const LITERAL: u32 = 1 << 3;
    pub const PURE_INSTRUCTIONS: u32 = 1 << 4;
    pub const ADDRESS_TAKEN: u32 = 1 << 5; // set during reloc scan (Sprint 24's ICF gate)

    pub fn has(self, bit: u32) -> bool {
        self.bits & bit != 0
    }

    pub fn with(mut self, bit: u32) -> Self {
        self.bits |= bit;
        self
    }

    pub fn set(&mut self, bit: u32) {
        self.bits |= bit;
    }

    pub fn bits(self) -> u32 {
        self.bits
    }
}

/// A symbol that resolves to a point inside another atom via `.alt_entry`.
/// Used for the `_start` / `_main` pattern where a secondary entry point
/// aliases into the middle of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltEntry {
    pub symbol: SymbolId,
    /// Byte offset into the containing atom where this alt entry points.
    pub offset_within_atom: u32,
}

/// One atom. Dead-stripping, ICF, and layout all work in terms of atoms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atom {
    pub id: AtomId,
    pub origin: InputId,
    /// 1-based section index within `origin`'s Mach-O section list.
    pub input_section: u8,
    pub section: AtomSection,
    /// Offset within the input section where this atom's content starts.
    pub input_offset: u32,
    /// Byte size. For zerofill atoms, this is virtual; `data` is empty.
    pub size: u32,
    /// log2 of required alignment. Inherited from the containing section.
    pub align_pow2: u8,
    /// Primary defining symbol, if any. Locals that split a section at
    /// `MH_SUBSECTIONS_VIA_SYMBOLS` boundaries but have no matching
    /// `Symbol::Defined` (rare; happens for unnamed atoms inside literal
    /// sections) leave this `None`.
    pub owner: Option<SymbolId>,
    /// `.alt_entry` chain — symbols aliased into this atom.
    pub alt_entries: Vec<AltEntry>,
    /// File-backed content, empty for zerofill.
    pub data: Vec<u8>,
    pub flags: AtomFlags,
    /// For compact-unwind and eh_frame atoms: the function atom whose
    /// lifetime this metadata atom shares. Sprint 23 (dead-strip) uses
    /// this to keep unwind metadata live iff the function is live.
    pub parent_of: Option<AtomId>,
}

/// Registry of all atoms in the link. `push` hands out stable `AtomId`s;
/// `get` / `get_mut` index into the table.
#[derive(Debug, Default)]
pub struct AtomTable {
    atoms: Vec<Atom>,
}

impl AtomTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign an id to `atom` (overwriting any prior `id` field) and
    /// store it. Returns the new handle.
    pub fn push(&mut self, mut atom: Atom) -> AtomId {
        // Skip id 0 — `AtomId(0)` is the pre-atomization placeholder for
        // `Symbol::Defined { atom }` slots seeded before atomization runs.
        let id = AtomId((self.atoms.len() as u32) + 1);
        atom.id = id;
        self.atoms.push(atom);
        id
    }

    pub fn get(&self, id: AtomId) -> &Atom {
        &self.atoms[(id.0 - 1) as usize]
    }

    pub fn get_mut(&mut self, id: AtomId) -> &mut Atom {
        &mut self.atoms[(id.0 - 1) as usize]
    }

    pub fn len(&self) -> usize {
        self.atoms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (AtomId, &Atom)> {
        self.atoms
            .iter()
            .enumerate()
            .map(|(i, a)| (AtomId((i + 1) as u32), a))
    }

    /// Group atoms by `(origin, input_section)`, preserving insertion
    /// order within each group. Sprint 10's layout pass walks this
    /// grouping to preserve input ordering within output sections.
    pub fn by_input_section(&self) -> HashMap<(InputId, u8), Vec<AtomId>> {
        let mut out: HashMap<(InputId, u8), Vec<AtomId>> = HashMap::new();
        for (id, atom) in self.iter() {
            out.entry((atom.origin, atom.input_section)).or_default().push(id);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_text_atom(origin: InputId, sect: u8, off: u32, size: u32) -> Atom {
        Atom {
            id: AtomId(0), // will be overwritten by push
            origin,
            input_section: sect,
            section: AtomSection::Text,
            input_offset: off,
            size,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0u8; size as usize],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        }
    }

    #[test]
    fn push_assigns_stable_one_based_ids_and_roundtrips_via_get() {
        let mut t = AtomTable::new();
        let a = t.push(make_text_atom(InputId(0), 1, 0, 16));
        let b = t.push(make_text_atom(InputId(0), 1, 16, 8));
        assert_eq!(a.0, 1);
        assert_eq!(b.0, 2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(a).input_offset, 0);
        assert_eq!(t.get(b).input_offset, 16);
    }

    #[test]
    fn id_zero_is_reserved_as_placeholder() {
        // `Symbol::Defined { atom: AtomId(0) }` is the pre-atomization
        // sentinel; any real atom must have id >= 1.
        let mut t = AtomTable::new();
        let id = t.push(make_text_atom(InputId(0), 1, 0, 1));
        assert_ne!(id, AtomId(0));
        assert_eq!(id, AtomId(1));
    }

    #[test]
    fn atom_section_from_section_kind_covers_all_variants() {
        assert_eq!(
            AtomSection::from_section_kind(SectionKind::Text),
            AtomSection::Text
        );
        assert_eq!(
            AtomSection::from_section_kind(SectionKind::CStringLiterals),
            AtomSection::CStringLiterals
        );
        assert_eq!(
            AtomSection::from_section_kind(SectionKind::CompactUnwind),
            AtomSection::CompactUnwind
        );
        assert_eq!(
            AtomSection::from_section_kind(SectionKind::ZeroFill),
            AtomSection::ZeroFill
        );
        assert!(AtomSection::from_section_kind(SectionKind::ZeroFill).is_zerofill());
        assert!(AtomSection::from_section_kind(SectionKind::CStringLiterals).is_literal());
        assert!(!AtomSection::from_section_kind(SectionKind::Text).is_literal());
    }

    #[test]
    fn atom_flags_bitwise() {
        let f = AtomFlags::default()
            .with(AtomFlags::NO_DEAD_STRIP)
            .with(AtomFlags::WEAK_DEF);
        assert!(f.has(AtomFlags::NO_DEAD_STRIP));
        assert!(f.has(AtomFlags::WEAK_DEF));
        assert!(!f.has(AtomFlags::THREAD_LOCAL));
    }

    #[test]
    fn by_input_section_groups_by_origin_and_section_index() {
        let mut t = AtomTable::new();
        let a = t.push(make_text_atom(InputId(0), 1, 0, 4));
        let b = t.push(make_text_atom(InputId(0), 1, 4, 4));
        let c = t.push(make_text_atom(InputId(1), 1, 0, 4));
        let grouped = t.by_input_section();
        assert_eq!(grouped.get(&(InputId(0), 1)).unwrap(), &vec![a, b]);
        assert_eq!(grouped.get(&(InputId(1), 1)).unwrap(), &vec![c]);
    }
}
