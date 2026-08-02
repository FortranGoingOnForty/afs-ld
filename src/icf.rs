use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
use crate::layout::{output_section_key, LayoutInput, SectionKey};
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind, RelocLength};
use crate::resolve::{AtomId, InputId, Symbol, SymbolId, SymbolTable};
use crate::symbol::SymKind;

#[derive(Debug, Clone, Default)]
pub struct IcfPlan {
    kept_atoms: HashSet<AtomId>,
    redirects: HashMap<AtomId, AtomId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedSymbol {
    pub name: String,
    pub winner: String,
    pub file_index: usize,
}

impl IcfPlan {
    pub fn kept_atoms(&self) -> &HashSet<AtomId> {
        &self.kept_atoms
    }

    pub fn redirects(&self) -> &HashMap<AtomId, AtomId> {
        &self.redirects
    }

    pub fn folded_symbols(
        &self,
        atom_table: &AtomTable,
        sym_table: &SymbolTable,
        layout_inputs: &[LayoutInput<'_>],
    ) -> Vec<FoldedSymbol> {
        let file_index_by_input: HashMap<InputId, usize> = layout_inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (input.id, idx + 1))
            .collect();
        let mut out = Vec::new();
        for (&loser, &winner) in &self.redirects {
            let winner = canonical_atom(winner, &self.redirects);
            let Some(winner_symbol) = representative_symbol(atom_table.get(winner)) else {
                continue;
            };
            let winner_name = symbol_name(sym_table, winner_symbol);
            for symbol_id in atom_symbols(atom_table.get(loser)) {
                let Symbol::Defined { origin, .. } = sym_table.get(symbol_id) else {
                    continue;
                };
                let name = symbol_name(sym_table, symbol_id);
                if name == winner_name {
                    continue;
                }
                out.push(FoldedSymbol {
                    name,
                    winner: winner_name.clone(),
                    file_index: file_index_by_input.get(origin).copied().unwrap_or(0),
                });
            }
        }
        out.sort_by(|lhs, rhs| {
            lhs.name
                .cmp(&rhs.name)
                .then_with(|| lhs.winner.cmp(&rhs.winner))
                .then_with(|| lhs.file_index.cmp(&rhs.file_index))
        });
        out.dedup_by(|lhs, rhs| {
            lhs.name == rhs.name && lhs.winner == rhs.winner && lhs.file_index == rhs.file_index
        });
        out
    }
}

#[derive(Debug, Clone)]
pub struct IcfError(String);

impl fmt::Display for IcfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ICF error: {}", self.0)
    }
}

impl std::error::Error for IcfError {}

pub fn fold_safe(
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &mut AtomTable,
    sym_table: &mut SymbolTable,
    live_atoms: Option<&HashSet<AtomId>>,
) -> Result<IcfPlan, IcfError> {
    let resolved_by_name = resolved_symbol_map(sym_table);
    let reloc_cache = reloc_cache(layout_inputs)?;
    let output_sections = output_section_cache(layout_inputs);

    mark_address_taken(
        layout_inputs,
        atom_table,
        sym_table,
        &resolved_by_name,
        &reloc_cache,
    );

    let mut kept_atoms = live_atoms.cloned().unwrap_or_else(|| {
        atom_table
            .iter()
            .map(|(atom_id, _)| atom_id)
            .collect::<HashSet<_>>()
    });
    let mut redirects = HashMap::new();

    let order_by_input: HashMap<InputId, (usize, Option<u64>)> = layout_inputs
        .iter()
        .map(|input| (input.id, (input.load_order, input.archive_member_offset)))
        .collect();

    loop {
        let mut buckets: HashMap<FoldKey, Vec<AtomId>> = HashMap::new();
        for (atom_id, atom) in atom_table.iter() {
            if !kept_atoms.contains(&atom_id) {
                continue;
            }
            if !is_foldable_atom(atom, sym_table) {
                continue;
            }
            let relocs = reloc_cache
                .get(&(atom.origin, atom.input_section))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let Some(reloc_sig) = reloc_signature_for_atom(
                atom,
                relocs,
                layout_inputs,
                sym_table,
                &resolved_by_name,
                &redirects,
            ) else {
                continue;
            };
            let output_section = output_sections
                .get(&(atom.origin, atom.input_section))
                .cloned()
                .ok_or_else(|| {
                    IcfError(format!(
                        "atom {atom_id:?} references missing input {:?} section {}",
                        atom.origin, atom.input_section
                    ))
                })?;
            buckets
                .entry(FoldKey::from_atom(atom, output_section, reloc_sig))
                .or_default()
                .push(atom_id);
        }

        let mut changed = false;
        for atom_ids in buckets.into_values() {
            if atom_ids.len() < 2 {
                continue;
            }
            let winner = *atom_ids
                .iter()
                .min_by_key(|atom_id| {
                    fold_order_key(atom_table.get(**atom_id), &order_by_input, **atom_id)
                })
                .expect("bucket is non-empty");
            for loser in atom_ids {
                if loser == winner {
                    continue;
                }
                redirects.insert(loser, winner);
                kept_atoms.remove(&loser);
                rebind_folded_symbols(sym_table, atom_table.get(loser), winner);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    rebind_symbols_to_canonical_winners(sym_table, &redirects);

    Ok(IcfPlan {
        kept_atoms,
        redirects,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FoldKey {
    output_section: SectionKey,
    section: AtomSection,
    size: u32,
    align_pow2: u8,
    flags: u32,
    data: Vec<u8>,
    relocs: Vec<FoldReloc>,
}

impl FoldKey {
    fn from_atom(atom: &Atom, output_section: SectionKey, relocs: Vec<FoldReloc>) -> Self {
        Self {
            output_section,
            section: atom.section,
            size: atom.size,
            align_pow2: atom.align_pow2,
            flags: atom.flags.bits() & !AtomFlags::ADDRESS_TAKEN,
            data: atom.data.clone(),
            relocs,
        }
    }
}

fn output_section_cache(layout_inputs: &[LayoutInput<'_>]) -> HashMap<(InputId, u8), SectionKey> {
    let mut out = HashMap::new();
    for input in layout_inputs {
        for (section_idx_zero, section) in input.object.sections.iter().enumerate() {
            out.insert(
                (input.id, (section_idx_zero + 1) as u8),
                output_section_key(section),
            );
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FoldReloc {
    offset: u32,
    kind: RelocKind,
    length: RelocLength,
    pcrel: bool,
    referent: FoldReferent,
    addend: i64,
    subtrahend: Option<FoldReferent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FoldReferent {
    Atom(AtomId),
    Absolute(u64),
    Symbol(SymbolId),
    LocalSymbol { input: InputId, symbol: u32 },
    Section { input: InputId, section: u8 },
}

fn fold_order_key(
    atom: &Atom,
    order_by_input: &HashMap<InputId, (usize, Option<u64>)>,
    atom_id: AtomId,
) -> (usize, u64, u32, u32) {
    let (load_order, archive_member_offset) = order_by_input
        .get(&atom.origin)
        .copied()
        .unwrap_or((usize::MAX, None));
    (
        load_order,
        archive_member_offset.unwrap_or(0),
        atom.input_offset,
        atom_id.0,
    )
}

fn is_foldable_atom(atom: &Atom, sym_table: &SymbolTable) -> bool {
    if !matches!(
        atom.section,
        AtomSection::Text
            | AtomSection::ConstData
            | AtomSection::CStringLiterals
            | AtomSection::Literal16
    ) {
        return false;
    }
    if atom.flags.has(AtomFlags::NO_DEAD_STRIP) || atom.flags.has(AtomFlags::ADDRESS_TAKEN) {
        return false;
    }
    !atom_symbols(atom).any(|symbol| {
        matches!(
            sym_table.get(symbol),
            Symbol::Defined {
                private_extern: false,
                ..
            }
        )
    })
}

fn rebind_folded_symbols(sym_table: &mut SymbolTable, atom: &Atom, winner: AtomId) {
    if let Some(owner) = atom.owner {
        let value = match sym_table.get(owner) {
            Symbol::Defined { value, .. } => *value,
            _ => 0,
        };
        sym_table.bind_atom(owner, winner, value);
    }
    for alt in &atom.alt_entries {
        let value = match sym_table.get(alt.symbol) {
            Symbol::Defined { value, .. } => *value,
            _ => alt.offset_within_atom as u64,
        };
        sym_table.bind_atom(alt.symbol, winner, value);
    }
}

fn rebind_symbols_to_canonical_winners(
    sym_table: &mut SymbolTable,
    redirects: &HashMap<AtomId, AtomId>,
) {
    let updates: Vec<(SymbolId, AtomId, u64)> = sym_table
        .iter()
        .filter_map(|(symbol_id, symbol)| match symbol {
            Symbol::Defined { atom, value, .. } if atom.0 != 0 => {
                let canonical = canonical_atom(*atom, redirects);
                (canonical != *atom).then_some((symbol_id, canonical, *value))
            }
            _ => None,
        })
        .collect();
    for (symbol_id, atom, value) in updates {
        sym_table.bind_atom(symbol_id, atom, value);
    }
}

fn resolved_symbol_map(sym_table: &SymbolTable) -> HashMap<String, SymbolId> {
    let mut out = HashMap::new();
    for (symbol_id, symbol) in sym_table.iter() {
        let resolved_id = sym_table
            .resolve_chain(symbol.name())
            .map(|(resolved_id, _)| resolved_id)
            .unwrap_or(symbol_id);
        out.insert(
            sym_table.interner.resolve(symbol.name()).to_string(),
            resolved_id,
        );
    }
    out
}

fn reloc_cache(
    layout_inputs: &[LayoutInput<'_>],
) -> Result<HashMap<(InputId, u8), Vec<Reloc>>, IcfError> {
    let mut out = HashMap::new();
    for input in layout_inputs {
        for (section_idx_zero, section) in input.object.sections.iter().enumerate() {
            if section.raw_relocs.is_empty() {
                continue;
            }
            let raws = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc)
                .map_err(|err| IcfError(format!("{}: {err}", input.object.path.display())))?;
            let relocs = parse_relocs(&raws)
                .map_err(|err| IcfError(format!("{}: {err}", input.object.path.display())))?;
            out.insert((input.id, (section_idx_zero + 1) as u8), relocs);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn mark_address_taken(
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &mut AtomTable,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    reloc_cache: &HashMap<(InputId, u8), Vec<Reloc>>,
) {
    let atom_index = IcfAtomIndex::new(atom_table);
    let mut address_taken = HashSet::new();
    for input in layout_inputs {
        for (section_idx_zero, source_section) in input.object.sections.iter().enumerate() {
            let input_section = (section_idx_zero + 1) as u8;
            let Some(relocs) = reloc_cache.get(&(input.id, input_section)) else {
                continue;
            };
            for reloc in relocs {
                if !marks_address_taken(reloc.kind) {
                    continue;
                }
                for referent in std::iter::once(reloc.referent).chain(reloc.subtrahend) {
                    address_taken.extend(target_atoms_for_reloc(
                        input.id,
                        input.object,
                        source_section,
                        *reloc,
                        referent,
                        sym_table,
                        resolved_by_name,
                        &atom_index,
                    ));
                }
            }
        }
    }
    for target_atom in address_taken {
        atom_table
            .get_mut(target_atom)
            .flags
            .set(AtomFlags::ADDRESS_TAKEN);
    }
}

fn marks_address_taken(kind: RelocKind) -> bool {
    matches!(
        kind,
        RelocKind::Unsigned
            | RelocKind::Subtractor
            | RelocKind::Page21
            | RelocKind::PageOff12
            | RelocKind::PointerToGot
            | RelocKind::GotLoadPage21
            | RelocKind::GotLoadPageOff12
            | RelocKind::TlvpLoadPage21
            | RelocKind::TlvpLoadPageOff12
    )
}

fn relocs_for_atom<'a>(relocs: &'a [Reloc], atom: &Atom) -> impl Iterator<Item = Reloc> + 'a {
    let start = atom.input_offset;
    let end = atom.input_offset.saturating_add(atom.size);
    relocs.iter().copied().filter(move |reloc| {
        let reloc_end = reloc
            .offset
            .saturating_add(reloc.length.byte_width() as u32);
        reloc.offset >= start && reloc_end <= end
    })
}

fn reloc_signature_for_atom(
    atom: &Atom,
    relocs: &[Reloc],
    layout_inputs: &[LayoutInput<'_>],
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    redirects: &HashMap<AtomId, AtomId>,
) -> Option<Vec<FoldReloc>> {
    let objects_by_input: HashMap<InputId, &crate::input::ObjectFile> = layout_inputs
        .iter()
        .map(|input| (input.id, input.object))
        .collect();
    let object = objects_by_input.get(&atom.origin)?;
    relocs_for_atom(relocs, atom)
        .map(|reloc| {
            Some(FoldReloc {
                offset: reloc.offset.saturating_sub(atom.input_offset),
                kind: reloc.kind,
                length: reloc.length,
                pcrel: reloc.pcrel,
                referent: normalize_referent(
                    atom.origin,
                    object,
                    reloc.referent,
                    sym_table,
                    resolved_by_name,
                    redirects,
                )?,
                addend: reloc.addend,
                subtrahend: match reloc.subtrahend {
                    Some(referent) => Some(normalize_referent(
                        atom.origin,
                        object,
                        referent,
                        sym_table,
                        resolved_by_name,
                        redirects,
                    )?),
                    None => None,
                },
            })
        })
        .collect()
}

fn normalize_referent(
    input: InputId,
    object: &crate::input::ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    redirects: &HashMap<AtomId, AtomId>,
) -> Option<FoldReferent> {
    match referent {
        Referent::Symbol(sym_idx) => {
            let input_sym = object.symbols.get(sym_idx as usize)?;
            if !input_sym.participates_in_global_resolution() {
                return match input_sym.kind() {
                    SymKind::Abs => Some(FoldReferent::Absolute(input_sym.value())),
                    _ => Some(FoldReferent::LocalSymbol {
                        input,
                        symbol: sym_idx,
                    }),
                };
            }
            let name = object.symbol_name(input_sym).ok()?;
            let &symbol_id = resolved_by_name.get(name)?;
            match sym_table.get(symbol_id) {
                Symbol::Defined { atom, .. } if atom.0 != 0 => {
                    Some(FoldReferent::Atom(canonical_atom(*atom, redirects)))
                }
                Symbol::Absolute { value, .. } => Some(FoldReferent::Absolute(*value)),
                _ => Some(FoldReferent::Symbol(symbol_id)),
            }
        }
        Referent::Section(section) => Some(FoldReferent::Section { input, section }),
    }
}

fn canonical_atom(atom_id: AtomId, redirects: &HashMap<AtomId, AtomId>) -> AtomId {
    let mut current = atom_id;
    while let Some(&next) = redirects.get(&current) {
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn representative_symbol(atom: &Atom) -> Option<SymbolId> {
    atom.owner
        .or_else(|| atom.alt_entries.first().map(|alt| alt.symbol))
}

fn atom_symbols(atom: &Atom) -> impl Iterator<Item = SymbolId> + '_ {
    atom.owner
        .into_iter()
        .chain(atom.alt_entries.iter().map(|alt| alt.symbol))
}

fn symbol_name(sym_table: &SymbolTable, symbol_id: SymbolId) -> String {
    sym_table
        .interner
        .resolve(sym_table.get(symbol_id).name())
        .to_string()
}

#[derive(Debug, Clone, Copy)]
struct IcfAtomRange {
    atom: AtomId,
    start: u32,
    end: u32,
}

#[derive(Debug, Default)]
struct IcfInputSectionAtoms {
    ranges: Vec<IcfAtomRange>,
    ordered_non_overlapping: bool,
}

#[derive(Debug, Default)]
struct IcfAtomIndex {
    sections: HashMap<(InputId, u8), IcfInputSectionAtoms>,
}

impl IcfAtomIndex {
    fn new(atom_table: &AtomTable) -> Self {
        let mut sections = HashMap::<(InputId, u8), IcfInputSectionAtoms>::new();
        for (atom_id, atom) in atom_table.iter() {
            sections
                .entry((atom.origin, atom.input_section))
                .or_default()
                .ranges
                .push(IcfAtomRange {
                    atom: atom_id,
                    start: atom.input_offset,
                    end: atom.input_offset.saturating_add(atom.size),
                });
        }
        for section in sections.values_mut() {
            section.ranges.sort_by_key(|range| (range.start, range.end));
            section.ordered_non_overlapping = section
                .ranges
                .windows(2)
                .all(|pair| pair[0].end <= pair[1].start);
        }
        Self { sections }
    }

    fn target_or_all(&self, input: InputId, section: u8, offset: u32) -> Vec<AtomId> {
        let Some(atoms) = self.sections.get(&(input, section)) else {
            return Vec::new();
        };
        if !atoms.ordered_non_overlapping {
            let mut candidates: Vec<AtomId> = atoms
                .ranges
                .iter()
                .filter(|range| {
                    (range.start <= offset && offset < range.end)
                        || (range.start == offset && range.end == offset)
                })
                .map(|range| range.atom)
                .collect();
            if candidates.is_empty() {
                candidates.extend(
                    atoms
                        .ranges
                        .iter()
                        .filter(|range| range.end == offset)
                        .map(|range| range.atom),
                );
            }
            return if candidates.is_empty() {
                self.all(input, section)
            } else {
                candidates
            };
        }

        let candidate = atoms.ranges.partition_point(|range| range.start <= offset);
        if let Some(range) = candidate
            .checked_sub(1)
            .and_then(|index| atoms.ranges.get(index))
        {
            if (range.start <= offset && offset < range.end)
                || (range.start == offset && range.end == offset)
            {
                return vec![range.atom];
            }
        }

        let boundary = atoms.ranges.partition_point(|range| range.end < offset);
        if let Some(range) = atoms
            .ranges
            .get(boundary)
            .filter(|range| range.end == offset)
        {
            return vec![range.atom];
        }
        self.all(input, section)
    }

    fn all(&self, input: InputId, section: u8) -> Vec<AtomId> {
        self.sections
            .get(&(input, section))
            .map(|atoms| atoms.ranges.iter().map(|range| range.atom).collect())
            .unwrap_or_default()
    }
}

#[allow(clippy::too_many_arguments)]
fn target_atoms_for_reloc(
    input: InputId,
    object: &crate::input::ObjectFile,
    source_section: &crate::section::InputSection,
    reloc: Reloc,
    referent: Referent,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    atom_index: &IcfAtomIndex,
) -> Vec<AtomId> {
    match referent {
        Referent::Symbol(sym_idx) => {
            let Some(input_sym) = object.symbols.get(sym_idx as usize) else {
                return Vec::new();
            };
            if input_sym.kind() == SymKind::Sect && !input_sym.participates_in_global_resolution() {
                let Some(target_section) = object.section_for_symbol(input_sym) else {
                    return Vec::new();
                };
                let Some(base_offset) = input_sym.value().checked_sub(target_section.addr) else {
                    return atom_index.all(input, input_sym.sect_idx());
                };
                let target_offset = if reloc.kind == RelocKind::Subtractor {
                    u32::try_from(base_offset).ok()
                } else {
                    relocation_target_offset(base_offset, source_section, reloc)
                };
                return target_offset
                    .map(|offset| atom_index.target_or_all(input, input_sym.sect_idx(), offset))
                    .unwrap_or_else(|| atom_index.all(input, input_sym.sect_idx()));
            }
            let Some(name) = object.symbol_name(input_sym).ok() else {
                return Vec::new();
            };
            let Some(&symbol_id) = resolved_by_name.get(name) else {
                return Vec::new();
            };
            match sym_table.get(symbol_id) {
                Symbol::Defined { atom, .. } if atom.0 != 0 => vec![*atom],
                _ => Vec::new(),
            }
        }
        Referent::Section(section) => {
            if reloc.kind == RelocKind::Subtractor {
                return atom_index.all(input, section);
            }
            relocation_target_offset(0, source_section, reloc)
                .map(|offset| atom_index.target_or_all(input, section, offset))
                .unwrap_or_else(|| atom_index.all(input, section))
        }
    }
}

fn relocation_target_offset(
    base_offset: u64,
    source_section: &crate::section::InputSection,
    reloc: Reloc,
) -> Option<u32> {
    let implicit_addend = match reloc.kind {
        RelocKind::Unsigned | RelocKind::PointerToGot => {
            read_icf_implicit_addend(source_section, reloc)?
        }
        _ => 0,
    };
    let offset = i128::from(base_offset)
        .checked_add(i128::from(reloc.addend))?
        .checked_add(i128::from(implicit_addend))?;
    u32::try_from(offset).ok()
}

fn read_icf_implicit_addend(
    source_section: &crate::section::InputSection,
    reloc: Reloc,
) -> Option<i64> {
    let start = reloc.offset as usize;
    let end = start.checked_add(reloc.length.byte_width())?;
    let bytes = source_section.data.get(start..end)?;
    match reloc.length {
        RelocLength::Word => Some(i32::from_le_bytes(bytes.try_into().ok()?) as i64),
        RelocLength::Quad => Some(i64::from_le_bytes(bytes.try_into().ok()?)),
        RelocLength::Byte | RelocLength::Half => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::atom::AltEntry;
    use crate::input::ObjectFile;
    use crate::layout::Layout;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_MAGIC_64, MH_OBJECT, N_EXT, N_SECT, N_UNDF,
        S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_ATTR_STRIP_STATIC_SYMS,
        S_CSTRING_LITERALS, S_REGULAR,
    };
    use crate::macho::reader::MachHeader64;
    use crate::reloc::{write_raw_relocs, write_relocs};
    use crate::section::{InputSection, SectionKind};
    use crate::string_table::StringTable;
    use crate::symbol::{InputSymbol, RawNlist};
    use crate::OutputKind;

    fn section_reloc_object(
        path: &str,
        text_size: u64,
        relocs: &[Reloc],
        data_value: u64,
    ) -> ObjectFile {
        let raw_relocs = write_relocs(relocs).unwrap();
        let mut reloc_bytes = Vec::new();
        write_raw_relocs(&raw_relocs, &mut reloc_bytes);
        ObjectFile {
            path: PathBuf::from(path),
            header: MachHeader64 {
                magic: MH_MAGIC_64,
                cputype: CPU_TYPE_ARM64,
                cpusubtype: CPU_SUBTYPE_ARM64_ALL,
                filetype: MH_OBJECT,
                ncmds: 0,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            },
            commands: Vec::new(),
            sections: vec![
                InputSection {
                    segname: "__TEXT".into(),
                    sectname: "__text".into(),
                    kind: SectionKind::Text,
                    addr: 0,
                    size: text_size,
                    align_pow2: 3,
                    flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                    offset: 0,
                    reloff: 0,
                    nreloc: raw_relocs.len() as u32,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    data: vec![0; text_size as usize],
                    raw_relocs: reloc_bytes,
                },
                InputSection {
                    segname: "__DATA".into(),
                    sectname: "__data".into(),
                    kind: SectionKind::Data,
                    addr: text_size,
                    size: 8,
                    align_pow2: 3,
                    flags: S_REGULAR,
                    offset: 0,
                    reloff: 0,
                    nreloc: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    data: data_value.to_le_bytes().to_vec(),
                    raw_relocs: Vec::new(),
                },
            ],
            symbols: Vec::new(),
            strings: StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        }
    }

    fn foldable_atom(origin: InputId, input_offset: u32) -> Atom {
        Atom {
            id: AtomId(0),
            origin,
            input_section: 1,
            section: AtomSection::Text,
            input_offset,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        }
    }

    fn const_sections_object(path: &str, sections: &[(&str, u32)]) -> ObjectFile {
        assert_eq!(sections.len(), 2);
        let mut object = section_reloc_object(path, 8, &[], 0x1122_3344_5566_7788);
        for (index, (section, (segment, flags))) in
            object.sections.iter_mut().zip(sections.iter()).enumerate()
        {
            section.segname = (*segment).into();
            section.sectname = "__const".into();
            section.kind = SectionKind::ConstData;
            section.addr = (index * 8) as u64;
            section.flags = *flags;
            section.data = 0x1122_3344_5566_7788u64.to_le_bytes().to_vec();
        }
        object
    }

    fn foldable_const_atom(origin: InputId, input_section: u8) -> Atom {
        Atom {
            id: AtomId(0),
            origin,
            input_section,
            section: AtomSection::ConstData,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: 0x1122_3344_5566_7788u64.to_le_bytes().to_vec(),
            flags: AtomFlags::default(),
            parent_of: None,
        }
    }

    fn foldable_cstring_atom(input_offset: u32) -> Atom {
        Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 2,
            section: AtomSection::CStringLiterals,
            input_offset,
            size: 4,
            align_pow2: 0,
            owner: None,
            alt_entries: Vec::new(),
            data: b"dup\0".to_vec(),
            flags: AtomFlags::default(),
            parent_of: None,
        }
    }

    fn local_literal_reference_object() -> ObjectFile {
        let relocs = [
            Reloc {
                offset: 0,
                kind: RelocKind::Unsigned,
                length: RelocLength::Quad,
                pcrel: false,
                referent: Referent::Section(2),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 8,
                kind: RelocKind::Unsigned,
                length: RelocLength::Quad,
                pcrel: false,
                referent: Referent::Section(2),
                addend: 0,
                subtrahend: None,
            },
        ];
        let mut object = section_reloc_object("local-literal.o", 16, &relocs, 0);
        object.sections[0].segname = "__DATA".into();
        object.sections[0].sectname = "__const".into();
        object.sections[0].kind = SectionKind::ConstData;
        object.sections[0].flags = S_REGULAR;
        object.sections[0].data[8..16].copy_from_slice(&4u64.to_le_bytes());
        object.sections[1].segname = "__TEXT".into();
        object.sections[1].sectname = "__cstring".into();
        object.sections[1].kind = SectionKind::CStringLiterals;
        object.sections[1].flags = S_CSTRING_LITERALS;
        object.sections[1].data = b"dup\0dup\0".to_vec();
        object
    }

    fn local_symbol_literal_reference_object() -> ObjectFile {
        let relocs = [
            Reloc {
                offset: 0,
                kind: RelocKind::Unsigned,
                length: RelocLength::Quad,
                pcrel: false,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 8,
                kind: RelocKind::Unsigned,
                length: RelocLength::Quad,
                pcrel: false,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
        ];
        let raw_relocs = write_relocs(&relocs).unwrap();
        let mut reloc_bytes = Vec::new();
        write_raw_relocs(&raw_relocs, &mut reloc_bytes);
        let mut object = local_literal_reference_object();
        object.sections[0].raw_relocs = reloc_bytes;
        object.symbols = vec![InputSymbol::from_raw(RawNlist {
            strx: 1,
            n_type: N_SECT,
            n_sect: 2,
            n_desc: 0,
            n_value: object.sections[1].addr,
        })];
        object.strings = StringTable::from_bytes(b"\0Lliteral\0".to_vec());
        object
    }

    fn defined_symbol(
        symbols: &mut SymbolTable,
        name: &str,
        atom: AtomId,
        private_extern: bool,
    ) -> SymbolId {
        let name = symbols.intern(name);
        symbols
            .insert(Symbol::Defined {
                name,
                origin: InputId(0),
                atom,
                value: 0,
                weak: false,
                private_extern,
                no_dead_strip: false,
            })
            .unwrap();
        symbols.lookup(name).unwrap()
    }

    fn section_reloc(offset: u32) -> Reloc {
        Reloc {
            offset,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        }
    }

    fn subtractor_reference_object(path: &str, minuend: &str, subtrahend: &str) -> ObjectFile {
        let reloc = Reloc {
            offset: 0,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: Some(Referent::Symbol(1)),
        };
        let mut object = section_reloc_object(path, 8, &[reloc], 0);
        let mut strings = vec![0];
        object.symbols = [minuend, subtrahend]
            .into_iter()
            .map(|name| {
                let strx = strings.len() as u32;
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
                InputSymbol::from_raw(RawNlist {
                    strx,
                    n_type: N_UNDF | N_EXT,
                    n_sect: 0,
                    n_desc: 0,
                    n_value: 0,
                })
            })
            .collect();
        object.strings = StringTable::from_bytes(strings);
        object
    }

    #[test]
    fn safe_icf_keeps_both_cross_object_subtractor_operands_distinct() {
        let objects = [
            section_reloc_object("minuend.o", 8, &[], 0),
            section_reloc_object("subtrahend.o", 8, &[], 0),
            subtractor_reference_object("difference.o", "_minuend", "_subtrahend"),
        ];
        let inputs = [
            LayoutInput {
                id: InputId(0),
                object: &objects[0],
                load_order: 0,
                archive_member_offset: None,
            },
            LayoutInput {
                id: InputId(1),
                object: &objects[1],
                load_order: 1,
                archive_member_offset: None,
            },
            LayoutInput {
                id: InputId(2),
                object: &objects[2],
                load_order: 2,
                archive_member_offset: None,
            },
        ];
        let mut atoms = AtomTable::new();
        let minuend = atoms.push(foldable_atom(InputId(0), 0));
        let subtrahend = atoms.push(foldable_atom(InputId(1), 0));
        let mut symbols = SymbolTable::new();
        for (name, origin, atom) in [
            ("_minuend", InputId(0), minuend),
            ("_subtrahend", InputId(1), subtrahend),
        ] {
            let name = symbols.intern(name);
            symbols
                .insert(Symbol::Defined {
                    name,
                    origin,
                    atom,
                    value: 0,
                    weak: false,
                    private_extern: true,
                    no_dead_strip: false,
                })
                .unwrap();
        }

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(atoms.get(minuend).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(atoms.get(subtrahend).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(plan.redirects().is_empty());
        assert!(plan.kept_atoms().contains(&minuend));
        assert!(plan.kept_atoms().contains(&subtrahend));
    }

    #[test]
    fn safe_icf_keeps_section_relative_literal_pointer_targets_distinct() {
        let object = local_literal_reference_object();
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        let first = atoms.push(foldable_cstring_atom(0));
        let second = atoms.push(foldable_cstring_atom(4));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(atoms.get(first).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(atoms.get(second).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(plan.redirects().is_empty());
        assert!(plan.kept_atoms().contains(&first));
        assert!(plan.kept_atoms().contains(&second));
    }

    #[test]
    fn safe_icf_keeps_local_symbol_literal_pointer_targets_distinct() {
        let object = local_symbol_literal_reference_object();
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        let first = atoms.push(foldable_cstring_atom(0));
        let second = atoms.push(foldable_cstring_atom(4));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(atoms.get(first).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(atoms.get(second).flags.has(AtomFlags::ADDRESS_TAKEN));
        assert!(plan.redirects().is_empty());
        assert!(plan.kept_atoms().contains(&first));
        assert!(plan.kept_atoms().contains(&second));
    }

    #[test]
    fn icf_normalization_does_not_rebind_local_symbol_to_global_collision() {
        let object = local_symbol_literal_reference_object();
        let mut symbols = SymbolTable::new();
        let global = AtomId(77);
        defined_symbol(&mut symbols, "Lliteral", global, false);
        let resolved_by_name = resolved_symbol_map(&symbols);

        let normalized = normalize_referent(
            InputId(0),
            &object,
            Referent::Symbol(0),
            &symbols,
            &resolved_by_name,
            &HashMap::new(),
        );

        assert_eq!(
            normalized,
            Some(FoldReferent::LocalSymbol {
                input: InputId(0),
                symbol: 0,
            })
        );
    }

    #[test]
    fn section_referents_from_different_objects_do_not_fold() {
        let objects = [
            section_reloc_object("a.o", 8, &[section_reloc(0)], 1),
            section_reloc_object("b.o", 8, &[section_reloc(0)], 2),
        ];
        let inputs = [
            LayoutInput {
                id: InputId(0),
                object: &objects[0],
                load_order: 0,
                archive_member_offset: None,
            },
            LayoutInput {
                id: InputId(1),
                object: &objects[1],
                load_order: 1,
                archive_member_offset: None,
            },
        ];
        let mut atoms = AtomTable::new();
        let first = atoms.push(foldable_atom(InputId(0), 0));
        let second = atoms.push(foldable_atom(InputId(1), 0));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(plan.kept_atoms().contains(&first));
        assert!(plan.kept_atoms().contains(&second));
        assert!(plan.redirects().is_empty());
    }

    #[test]
    fn matching_section_referents_in_one_object_still_fold() {
        let object = section_reloc_object("same.o", 16, &[section_reloc(0), section_reloc(8)], 1);
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        atoms.push(foldable_atom(InputId(0), 0));
        atoms.push(foldable_atom(InputId(0), 8));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert_eq!(plan.redirects().len(), 1);
        assert_eq!(plan.kept_atoms().len(), 1);
    }

    #[test]
    fn safe_icf_keeps_identical_constants_in_distinct_output_protection_domains() {
        let object = const_sections_object(
            "protection-domains.o",
            &[("__TEXT", S_REGULAR), ("__DATA", S_REGULAR)],
        );
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        let text = atoms.push(foldable_const_atom(InputId(0), 1));
        let data = atoms.push(foldable_const_atom(InputId(0), 2));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(plan.kept_atoms().contains(&text));
        assert!(plan.kept_atoms().contains(&data));
        assert!(plan.redirects().is_empty());

        let layout = Layout::build_with_synthetics_filtered(
            OutputKind::Dylib,
            &inputs,
            &atoms,
            0,
            None,
            Some(plan.kept_atoms()),
        );
        assert!(layout
            .sections
            .iter()
            .any(|section| { section.segment == "__TEXT" && section.name == "__const" }));
        assert!(layout
            .sections
            .iter()
            .any(|section| { section.segment == "__DATA_CONST" && section.name == "__const" }));
    }

    #[test]
    fn safe_icf_folds_identical_constants_with_same_effective_output_section() {
        let object = const_sections_object(
            "mapped-domain.o",
            &[("__DATA", S_REGULAR), ("__DATA_CONST", S_REGULAR)],
        );
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        atoms.push(foldable_const_atom(InputId(0), 1));
        atoms.push(foldable_const_atom(InputId(0), 2));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert_eq!(plan.redirects().len(), 1);
        assert_eq!(plan.kept_atoms().len(), 1);
    }

    #[test]
    fn safe_icf_keeps_identical_constants_with_incompatible_section_attributes() {
        let object = const_sections_object(
            "section-attributes.o",
            &[
                ("__TEXT", S_REGULAR),
                ("__TEXT", S_REGULAR | S_ATTR_STRIP_STATIC_SYMS),
            ],
        );
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        let plain = atoms.push(foldable_const_atom(InputId(0), 1));
        let strip_static = atoms.push(foldable_const_atom(InputId(0), 2));
        let mut symbols = SymbolTable::new();

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(plan.kept_atoms().contains(&plain));
        assert!(plan.kept_atoms().contains(&strip_static));
        assert!(plan.redirects().is_empty());
    }

    #[test]
    fn public_same_address_alias_prevents_safe_fold() {
        let object = section_reloc_object("aliases.o", 16, &[], 0);
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut atoms = AtomTable::new();
        let private_only = atoms.push(foldable_atom(InputId(0), 0));
        let public_alias = atoms.push(foldable_atom(InputId(0), 8));
        let mut symbols = SymbolTable::new();
        let private_only_owner = defined_symbol(&mut symbols, "_private_only", private_only, true);
        let public = defined_symbol(&mut symbols, "_public", public_alias, false);
        let private_alias = defined_symbol(&mut symbols, "_private_alias", public_alias, true);
        atoms.get_mut(private_only).owner = Some(private_only_owner);
        atoms.get_mut(public_alias).owner = Some(private_alias);
        atoms.get_mut(public_alias).alt_entries.push(AltEntry {
            symbol: public,
            offset_within_atom: 0,
        });

        let plan = fold_safe(&inputs, &mut atoms, &mut symbols, None).unwrap();

        assert!(plan.redirects().is_empty());
        assert!(plan.kept_atoms().contains(&private_only));
        assert!(plan.kept_atoms().contains(&public_alias));
        assert!(matches!(
            symbols.get(public),
            Symbol::Defined { atom, .. } if *atom == public_alias
        ));
    }
}
