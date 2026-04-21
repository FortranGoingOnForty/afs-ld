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

use crate::input::ObjectFile;
use crate::macho::constants::MH_SUBSECTIONS_VIA_SYMBOLS;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent};
use crate::resolve::{AtomId, InputId, SymbolId, SymbolTable};
use crate::section::{InputSection, SectionKind};
use crate::symbol::{InputSymbol, SymKind};

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
            SectionKind::ThreadLocalVariablePointers => AtomSection::ThreadLocalVariables,
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
        matches!(self, AtomSection::ZeroFill | AtomSection::ThreadLocalBss)
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
            out.entry((atom.origin, atom.input_section))
                .or_default()
                .push(id);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Atomization pass.
// ---------------------------------------------------------------------------

/// Per-object atomization output. Back-patching `Symbol::Defined.atom`
/// walks `owner_by_sym`; Sprint 23's dead-strip reads `alt_entries_by_sym`
/// when computing the live graph.
#[derive(Debug, Default)]
pub struct ObjectAtomization {
    pub atoms: Vec<AtomId>,
    /// `(symbol_index_in_object → atom that owns it)`. Populated for every
    /// external/private-extern SECT symbol that started a new atom.
    pub owner_by_sym: Vec<(usize, AtomId)>,
    /// `(symbol_index_in_object → (containing_atom, offset_within_atom))`.
    /// Populated for `.alt_entry` symbols that folded into an existing atom.
    pub alt_entries_by_sym: Vec<(usize, AtomId, u32)>,
}

/// Atomize every section in `obj`, pushing into `table`. The caller
/// typically walks every input in sequence and merges results.
pub fn atomize_object(
    input_id: InputId,
    obj: &ObjectFile,
    table: &mut AtomTable,
) -> ObjectAtomization {
    let subsections_via_symbols = obj.header.flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0;
    let mut out = ObjectAtomization::default();

    for (sect_idx_zero, sect) in obj.sections.iter().enumerate() {
        let sect_idx_one = (sect_idx_zero + 1) as u8;
        // Gather symbols targeting this section and translate their
        // `n_value` (absolute address in the object's layout) into
        // in-section offsets by subtracting the section's `addr`.
        //
        // Only external / private-extern / alt-entry symbols count as
        // subsection boundaries. Locals like `ltmp0` often sit at the
        // same offset as an adjacent external (they're compiler-generated
        // anchors for PC-relative addressing); splitting at them would
        // produce zero-size atoms. This matches ld64's pragmatic reading
        // of MH_SUBSECTIONS_VIA_SYMBOLS.
        let mut syms: Vec<(usize, &InputSymbol, u32)> = obj
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.stab_kind().is_none()
                    && s.kind() == SymKind::Sect
                    && s.sect_idx() == sect_idx_one
                    && (s.is_ext() || s.is_private_ext() || s.alt_entry())
            })
            .map(|(i, s)| {
                let offset = s.value().saturating_sub(sect.addr) as u32;
                (i, s, offset)
            })
            .collect();
        syms.sort_by_key(|(_, _, off)| *off);

        atomize_regular_section(
            input_id,
            sect_idx_one,
            sect,
            &syms,
            subsections_via_symbols,
            table,
            &mut out,
        );
    }

    // Post-pass: wire metadata atoms to the function atoms whose lifetime
    // they track, so dead-strip can prune unwind surfaces precisely.
    link_unwind_parents(input_id, obj, table, &out);
    link_eh_frame_parents(input_id, obj, table, &out);

    out
}

/// Walk `__compact_unwind` atoms; for each, find its `function_start`
/// reloc (at record offset 0), resolve the referent to a function atom
/// within this same input, and set `parent_of`. External-symbol relocs
/// (e.g. `__compact_unwind` referencing a function in another object)
/// are left with `parent_of = None` and wired by Sprint 17's unwind
/// synthesis pass, which has the full atom table.
fn link_unwind_parents(
    input_id: InputId,
    obj: &ObjectFile,
    table: &mut AtomTable,
    out: &ObjectAtomization,
) {
    let Some((cu_idx_zero, cu_sect)) = obj
        .sections
        .iter()
        .enumerate()
        .find(|(_, s)| s.kind == SectionKind::CompactUnwind)
    else {
        return;
    };
    let cu_idx_one = (cu_idx_zero + 1) as u8;

    let raws = match parse_raw_relocs(&cu_sect.raw_relocs, 0, cu_sect.nreloc) {
        Ok(r) => r,
        Err(_) => return,
    };
    let fused = match parse_relocs(&raws) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Index atoms produced by this object for (section, offset) lookup.
    let mut atom_index: HashMap<(u8, u32), AtomId> = HashMap::new();
    for id in &out.atoms {
        let a = table.get(*id);
        atom_index.insert((a.input_section, a.input_offset), *id);
    }

    // For each compact_unwind atom, find its first reloc.
    for id in &out.atoms {
        let atom = table.get(*id);
        if atom.input_section != cu_idx_one {
            continue;
        }
        let record_start = atom.input_offset;
        let Some(r) = fused.iter().find(|r| r.offset == record_start) else {
            continue;
        };
        let parent = match r.referent {
            Referent::Section(sect_idx) => {
                // The 8-byte `function_start` field holds the target's
                // in-section offset. For ARM64_RELOC_UNSIGNED, that byte
                // window carries the addend directly.
                if atom.data.len() >= 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&atom.data[0..8]);
                    let target_offset = u64::from_le_bytes(buf) as u32;
                    atom_index.get(&(sect_idx, target_offset)).copied()
                } else {
                    None
                }
            }
            Referent::Symbol(_) => None,
        };
        if let Some(parent_id) = parent {
            table.get_mut(*id).parent_of = Some(parent_id);
        }
    }
    let _ = input_id; // reserved for cross-object lookup in Sprint 17
}

/// Replace every `Symbol::Defined { atom: AtomId(0), ... }` seeded before
/// atomization with the real atom handle and atom-relative offset.
/// Silently skips symbols that have no matching entry (e.g. those that
/// were replaced by a strong definition elsewhere before atomization ran).
pub fn backpatch_symbol_atoms(
    atomization: &ObjectAtomization,
    input_id: InputId,
    obj: &ObjectFile,
    sym_table: &mut SymbolTable,
    atom_table: &mut AtomTable,
) {
    use crate::resolve::Symbol;

    for (sym_idx, atom_id) in &atomization.owner_by_sym {
        let input_sym = &obj.symbols[*sym_idx];
        let Ok(name_str) = obj.symbol_name(input_sym) else {
            continue;
        };
        let istr = sym_table.intern(name_str);
        let Some(sid) = sym_table.lookup(istr) else {
            continue;
        };
        // Primary owner symbols sit at atom boundary → atom-relative 0.
        if let Symbol::Defined { origin, .. } = sym_table.get(sid) {
            if *origin == input_id {
                sym_table.bind_atom(sid, *atom_id, 0);
                atom_table.get_mut(*atom_id).owner = Some(sid);
            }
        }
    }

    for (sym_idx, atom_id, local_off) in &atomization.alt_entries_by_sym {
        let input_sym = &obj.symbols[*sym_idx];
        let Ok(name_str) = obj.symbol_name(input_sym) else {
            continue;
        };
        let istr = sym_table.intern(name_str);
        let Some(sid) = sym_table.lookup(istr) else {
            continue;
        };
        if let Symbol::Defined { origin, .. } = sym_table.get(sid) {
            if *origin == input_id {
                sym_table.bind_atom(sid, *atom_id, *local_off as u64);
                // Update the atom's alt_entries with the resolver-side
                // SymbolId (we stored the InputSymbol index during
                // atomization; now we know the real handle).
                let atom = atom_table.get_mut(*atom_id);
                for alt in &mut atom.alt_entries {
                    if alt.symbol == SymbolId(*sym_idx as u32)
                        && alt.offset_within_atom == *local_off
                    {
                        alt.symbol = sid;
                    }
                }
            }
        }
    }
}

/// Split one section into atoms according to the `MH_SUBSECTIONS_VIA_SYMBOLS`
/// invariant plus `.alt_entry` folding. Literal and unwind specialization
/// lands in follow-up commits; this function's fallback is "one atom per
/// section" for sections the subsections flag doesn't split.
#[allow(clippy::too_many_arguments)]
fn atomize_regular_section(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    subsections_via_symbols: bool,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    let kind = sect.kind;
    let atom_section = AtomSection::from_section_kind(kind);

    // Without the subsections flag, every section becomes one atom — the
    // linker-side equivalent of Apple-style monolithic sections.
    if !subsections_via_symbols {
        let atom = build_section_atom(input_id, section_idx, sect, atom_section);
        let id = table.push(atom);
        out.atoms.push(id);
        for (sym_idx, _sym, off) in syms {
            out.alt_entries_by_sym.push((*sym_idx, id, *off));
        }
        return;
    }

    // Zerofill: splitting happens per symbol (each tentative common-style
    // slot gets its own atom). If no symbols defined, emit a single atom.
    if atom_section.is_zerofill() {
        atomize_zerofill(input_id, section_idx, sect, syms, atom_section, table, out);
        return;
    }

    // Literal sections split on content boundaries (null for `__cstring`,
    // fixed-size chunks for `__literal4/8/16`) independent of symbol
    // labels. Sprint 24's ICF uses the per-atom content for dedup.
    if atom_section.is_literal() {
        atomize_literal_section(input_id, section_idx, sect, syms, atom_section, table, out);
        return;
    }

    // `__compact_unwind` is a fixed-layout array of 32-byte records; each
    // record becomes its own atom with `parent_of` wired to the function
    // atom it describes (linked post-hoc in `link_unwind_parents`).
    if atom_section == AtomSection::CompactUnwind {
        atomize_compact_unwind(input_id, section_idx, sect, syms, atom_section, table, out);
        return;
    }

    if atom_section == AtomSection::EhFrame {
        atomize_eh_frame(input_id, section_idx, sect, atom_section, table, out);
        return;
    }

    // With subsections_via_symbols and at least one split point, walk the
    // sorted symbols and emit one atom per non-alt_entry boundary.
    if syms.is_empty() {
        let atom = build_section_atom(input_id, section_idx, sect, atom_section);
        let id = table.push(atom);
        out.atoms.push(id);
        return;
    }

    // If there's content before the first symbol, carve a head atom
    // (unowned). afs-as emits a leading symbol in practice so this is
    // typically zero bytes, but the fallback keeps the byte-flow intact.
    let first_offset = syms[0].2;
    if first_offset > 0 {
        let head = build_slice_atom(
            input_id,
            section_idx,
            sect,
            atom_section,
            0,
            first_offset,
            None,
            &[],
        );
        let head_id = table.push(head);
        out.atoms.push(head_id);
    }

    // Walk symbol boundaries.
    let section_size = sect.size as u32;
    let mut i = 0;
    while i < syms.len() {
        let (primary_idx, primary, atom_offset) = syms[i];
        let next_real_boundary = find_next_non_alt_entry(syms, i + 1)
            .map(|j| syms[j].2)
            .unwrap_or(section_size);
        let size = next_real_boundary.saturating_sub(atom_offset);

        // Collect alt_entries that fall into [atom_offset, atom_offset+size).
        let mut alts: Vec<AltEntry> = Vec::new();
        let mut alt_folded: Vec<(usize, u32)> = Vec::new();
        for (alt_idx, alt_sym, alt_off) in syms.iter().skip(i + 1) {
            if *alt_off >= atom_offset + size {
                break;
            }
            if !alt_sym.alt_entry() {
                break;
            }
            let local = *alt_off - atom_offset;
            alts.push(AltEntry {
                symbol: SymbolId(*alt_idx as u32),
                offset_within_atom: local,
            });
            alt_folded.push((*alt_idx, local));
        }

        let atom = build_slice_atom(
            input_id,
            section_idx,
            sect,
            atom_section,
            atom_offset,
            size,
            Some(primary),
            &alts,
        );
        let id = table.push(atom);
        out.atoms.push(id);
        out.owner_by_sym.push((primary_idx, id));
        for (alt_idx, local_off) in alt_folded {
            out.alt_entries_by_sym.push((alt_idx, id, local_off));
        }

        // Advance past the primary and its folded alt_entries.
        i = find_next_non_alt_entry(syms, i + 1).unwrap_or(syms.len());
    }
}

/// Split a literal section into atoms. `__cstring` splits at null-byte
/// terminators (variable-length); `__literal4/8/16` split at fixed-width
/// boundaries. Owner symbols attach at exact offsets where a symbol
/// points.
fn atomize_literal_section(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    match atom_section {
        AtomSection::CStringLiterals => {
            atomize_cstring(input_id, section_idx, sect, syms, atom_section, table, out)
        }
        AtomSection::Literal4 => atomize_fixed_literal(
            input_id,
            section_idx,
            sect,
            syms,
            4,
            atom_section,
            table,
            out,
        ),
        AtomSection::Literal8 => atomize_fixed_literal(
            input_id,
            section_idx,
            sect,
            syms,
            8,
            atom_section,
            table,
            out,
        ),
        AtomSection::Literal16 => atomize_fixed_literal(
            input_id,
            section_idx,
            sect,
            syms,
            16,
            atom_section,
            table,
            out,
        ),
        _ => unreachable!("atomize_literal_section called with non-literal kind"),
    }
}

fn atomize_cstring(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    let mut offset = 0usize;
    while offset < sect.data.len() {
        let relative_nul = sect.data[offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sect.data.len() - offset);
        let end = offset + relative_nul + 1;
        let end = end.min(sect.data.len());
        let data = sect.data[offset..end].to_vec();
        let size = (end - offset) as u32;

        let owner_entry = syms.iter().find(|(_, _, off)| *off as usize == offset);
        let owner_idx = owner_entry.map(|(i, _, _)| *i);

        let mut flags = AtomFlags::default().with(AtomFlags::LITERAL);
        if let Some((_, sym, _)) = owner_entry {
            flags.set(symbol_flags(sym).bits());
        }

        let atom = Atom {
            id: AtomId(0),
            origin: input_id,
            input_section: section_idx,
            section: atom_section,
            input_offset: offset as u32,
            size,
            align_pow2: sect.align_pow2 as u8,
            owner: None,
            alt_entries: Vec::new(),
            data,
            flags,
            parent_of: None,
        };
        let id = table.push(atom);
        out.atoms.push(id);
        if let Some(idx) = owner_idx {
            out.owner_by_sym.push((idx, id));
        }
        offset = end;
    }
}

#[allow(clippy::too_many_arguments)]
fn atomize_fixed_literal(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    chunk_size: usize,
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    let section_size = sect.size as usize;
    let mut offset = 0usize;
    while offset < section_size {
        let end = (offset + chunk_size).min(section_size);
        let data_end = end.min(sect.data.len());
        let data = if offset < data_end {
            sect.data[offset..data_end].to_vec()
        } else {
            Vec::new()
        };
        let size = (end - offset) as u32;

        let owner_entry = syms.iter().find(|(_, _, off)| *off as usize == offset);
        let owner_idx = owner_entry.map(|(i, _, _)| *i);

        let mut flags = AtomFlags::default().with(AtomFlags::LITERAL);
        if let Some((_, sym, _)) = owner_entry {
            flags.set(symbol_flags(sym).bits());
        }

        let atom = Atom {
            id: AtomId(0),
            origin: input_id,
            input_section: section_idx,
            section: atom_section,
            input_offset: offset as u32,
            size,
            align_pow2: sect.align_pow2 as u8,
            owner: None,
            alt_entries: Vec::new(),
            data,
            flags,
            parent_of: None,
        };
        let id = table.push(atom);
        out.atoms.push(id);
        if let Some(idx) = owner_idx {
            out.owner_by_sym.push((idx, id));
        }
        offset = end;
    }
}

/// Split `__compact_unwind` into 32-byte atoms (one per record).
/// `parent_of` is filled in post-hoc by `link_unwind_parents` once all
/// sections of this object have been atomized.
fn atomize_compact_unwind(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    const RECORD: usize = 32;
    let section_size = sect.size as usize;
    let mut offset = 0usize;
    while offset < section_size {
        let end = (offset + RECORD).min(section_size);
        let data = sect.data[offset..end.min(sect.data.len())].to_vec();
        let size = (end - offset) as u32;

        let owner_idx = syms
            .iter()
            .find(|(_, _, off)| *off as usize == offset)
            .map(|(i, _, _)| *i);

        let atom = Atom {
            id: AtomId(0),
            origin: input_id,
            input_section: section_idx,
            section: atom_section,
            input_offset: offset as u32,
            size,
            align_pow2: sect.align_pow2 as u8,
            owner: None,
            alt_entries: Vec::new(),
            data,
            flags: AtomFlags::default(),
            parent_of: None, // filled by link_unwind_parents
        };
        let id = table.push(atom);
        out.atoms.push(id);
        if let Some(idx) = owner_idx {
            out.owner_by_sym.push((idx, id));
        }
        offset = end;
    }
}

/// Split `__eh_frame` into DWARF CFI records so dead-strip can retain only
/// the live FDEs and their shared CIEs.
fn atomize_eh_frame(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    let mut offset = 0usize;
    while offset < sect.data.len() {
        let Some(size) = eh_frame_record_size(&sect.data, offset) else {
            let atom = build_section_atom(input_id, section_idx, sect, atom_section);
            let id = table.push(atom);
            out.atoms.push(id);
            return;
        };

        let end = (offset + size).min(sect.data.len());
        let atom = Atom {
            id: AtomId(0),
            origin: input_id,
            input_section: section_idx,
            section: atom_section,
            input_offset: offset as u32,
            size: (end - offset) as u32,
            align_pow2: (sect.align_pow2 as u8).min(2),
            owner: None,
            alt_entries: Vec::new(),
            data: sect.data[offset..end].to_vec(),
            flags: AtomFlags::default(),
            parent_of: None,
        };
        let id = table.push(atom);
        out.atoms.push(id);
        offset = end;
    }
}

fn eh_frame_record_size(data: &[u8], offset: usize) -> Option<usize> {
    let length_end = offset.checked_add(4)?;
    let length_bytes: [u8; 4] = data.get(offset..length_end)?.try_into().ok()?;
    let length = u32::from_le_bytes(length_bytes);
    if length == 0 {
        return Some(4);
    }
    if length == u32::MAX {
        return None;
    }
    let size = 4usize.checked_add(length as usize)?;
    (offset + size <= data.len()).then_some(size)
}

fn eh_frame_cie_pointer(atom: &Atom) -> Option<u32> {
    (atom.section == AtomSection::EhFrame && atom.data.len() >= 8).then(|| {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&atom.data[4..8]);
        u32::from_le_bytes(buf)
    })
}

fn resolve_function_parent(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: crate::reloc::Reloc,
    atom_index: &HashMap<(u8, u32), AtomId>,
    field_offset: usize,
) -> Option<AtomId> {
    match reloc.referent {
        Referent::Section(sect_idx) => {
            let end = field_offset.checked_add(8)?;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(atom.data.get(field_offset..end)?);
            let target_offset = u64::from_le_bytes(buf) as u32;
            atom_index.get(&(sect_idx, target_offset)).copied()
        }
        Referent::Symbol(sym_idx) => {
            let input_sym = obj.symbols.get(sym_idx as usize)?;
            (input_sym.kind() == SymKind::Sect)
                .then(|| {
                    let target_offset = input_sym.value().saturating_sub(
                        obj.sections
                            .get(input_sym.sect_idx().saturating_sub(1) as usize)
                            .map(|section| section.addr)
                            .unwrap_or(0),
                    ) as u32;
                    atom_index
                        .get(&(input_sym.sect_idx(), target_offset))
                        .copied()
                })
                .flatten()
        }
    }
}

fn link_eh_frame_parents(
    input_id: InputId,
    obj: &ObjectFile,
    table: &mut AtomTable,
    out: &ObjectAtomization,
) {
    let Some((eh_idx_zero, eh_sect)) = obj
        .sections
        .iter()
        .enumerate()
        .find(|(_, s)| s.kind == SectionKind::EhFrame)
    else {
        return;
    };
    let eh_idx_one = (eh_idx_zero + 1) as u8;

    let raws = match parse_raw_relocs(&eh_sect.raw_relocs, 0, eh_sect.nreloc) {
        Ok(r) => r,
        Err(_) => return,
    };
    let fused = match parse_relocs(&raws) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut atom_index: HashMap<(u8, u32), AtomId> = HashMap::new();
    for id in &out.atoms {
        let a = table.get(*id);
        atom_index.insert((a.input_section, a.input_offset), *id);
    }

    for id in &out.atoms {
        let atom = table.get(*id);
        if atom.input_section != eh_idx_one {
            continue;
        }
        let Some(cie_pointer) = eh_frame_cie_pointer(atom) else {
            continue;
        };
        if cie_pointer == 0 {
            continue;
        }
        let Some(reloc) = fused.iter().find(|r| r.offset == atom.input_offset + 8) else {
            continue;
        };
        if let Some(parent_id) = resolve_function_parent(obj, atom, *reloc, &atom_index, 8) {
            table.get_mut(*id).parent_of = Some(parent_id);
        }
    }
    let _ = input_id;
}

fn atomize_zerofill(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    syms: &[(usize, &InputSymbol, u32)],
    atom_section: AtomSection,
    table: &mut AtomTable,
    out: &mut ObjectAtomization,
) {
    if syms.is_empty() {
        let atom = build_section_atom(input_id, section_idx, sect, atom_section);
        let id = table.push(atom);
        out.atoms.push(id);
        return;
    }
    let section_size = sect.size as u32;
    for (i, (sym_idx, sym, start)) in syms.iter().enumerate() {
        let start = *start;
        let end = syms
            .get(i + 1)
            .map(|(_, _, off)| *off)
            .unwrap_or(section_size);
        let size = end.saturating_sub(start);
        let atom = Atom {
            id: AtomId(0),
            origin: input_id,
            input_section: section_idx,
            section: atom_section,
            input_offset: start,
            size,
            align_pow2: sect.align_pow2 as u8,
            owner: Some(SymbolId(*sym_idx as u32)),
            alt_entries: Vec::new(),
            data: Vec::new(), // zerofill
            flags: symbol_flags(sym),
            parent_of: None,
        };
        let id = table.push(atom);
        out.atoms.push(id);
        out.owner_by_sym.push((*sym_idx, id));
    }
}

fn build_section_atom(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    atom_section: AtomSection,
) -> Atom {
    let data = if atom_section.is_zerofill() {
        Vec::new()
    } else {
        sect.data.clone()
    };
    let mut flags = AtomFlags::default();
    if sect.kind == SectionKind::Text {
        flags.set(AtomFlags::PURE_INSTRUCTIONS);
    }
    Atom {
        id: AtomId(0),
        origin: input_id,
        input_section: section_idx,
        section: atom_section,
        input_offset: 0,
        size: sect.size as u32,
        align_pow2: sect.align_pow2 as u8,
        owner: None,
        alt_entries: Vec::new(),
        data,
        flags,
        parent_of: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_slice_atom(
    input_id: InputId,
    section_idx: u8,
    sect: &InputSection,
    atom_section: AtomSection,
    offset: u32,
    size: u32,
    owner: Option<&InputSymbol>,
    alt_entries: &[AltEntry],
) -> Atom {
    let data = if atom_section.is_zerofill() {
        Vec::new()
    } else {
        let start = offset as usize;
        let end = (offset + size) as usize;
        sect.data[start..end.min(sect.data.len())].to_vec()
    };
    let mut flags = AtomFlags::default();
    if sect.kind == SectionKind::Text {
        flags.set(AtomFlags::PURE_INSTRUCTIONS);
    }
    if let Some(sym) = owner {
        flags.set(symbol_flags(sym).bits());
    }
    Atom {
        id: AtomId(0),
        origin: input_id,
        input_section: section_idx,
        section: atom_section,
        input_offset: offset,
        size,
        align_pow2: sect.align_pow2 as u8,
        // owner is wired at back-patch time via `backpatch_symbol_atoms`;
        // atomization doesn't know the resolver-side SymbolId yet.
        owner: None,
        alt_entries: alt_entries.to_vec(),
        data,
        flags,
        parent_of: None,
    }
}

fn symbol_flags(sym: &InputSymbol) -> AtomFlags {
    let mut f = AtomFlags::default();
    if sym.no_dead_strip() {
        f.set(AtomFlags::NO_DEAD_STRIP);
    }
    if sym.weak_def() {
        f.set(AtomFlags::WEAK_DEF);
    }
    f
}

/// Find the next non-alt_entry symbol starting from index `i`. Returns the
/// index (into `syms`), or `None` if every remaining symbol is an alt
/// entry.
fn find_next_non_alt_entry(syms: &[(usize, &InputSymbol, u32)], from: usize) -> Option<usize> {
    syms.iter()
        .enumerate()
        .skip(from)
        .find(|(_, (_, s, _))| !s.alt_entry())
        .map(|(i, _)| i)
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
