use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
use crate::layout::LayoutInput;
use crate::reloc::{
    parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind, RelocLength,
};
use crate::resolve::{AtomId, InputId, Symbol, SymbolId, SymbolTable};

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

    let order_by_input: HashMap<InputId, (usize, Option<u32>)> = layout_inputs
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
            buckets
                .entry(FoldKey::from_atom(atom, reloc_sig))
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
    section: AtomSection,
    size: u32,
    align_pow2: u8,
    flags: u32,
    data: Vec<u8>,
    relocs: Vec<FoldReloc>,
}

impl FoldKey {
    fn from_atom(atom: &Atom, relocs: Vec<FoldReloc>) -> Self {
        Self {
            section: atom.section,
            size: atom.size,
            align_pow2: atom.align_pow2,
            flags: atom.flags.bits() & !AtomFlags::ADDRESS_TAKEN,
            data: atom.data.clone(),
            relocs,
        }
    }
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
    Symbol(SymbolId),
    Section(u8),
}

fn fold_order_key(
    atom: &Atom,
    order_by_input: &HashMap<InputId, (usize, Option<u32>)>,
    atom_id: AtomId,
) -> (usize, u32, u32, u32) {
    let (load_order, archive_member_offset) =
        order_by_input.get(&atom.origin).copied().unwrap_or((usize::MAX, None));
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
    !matches!(
        atom.owner.map(|owner| sym_table.get(owner)),
        Some(Symbol::Defined {
            private_extern: false,
            ..
        })
    )
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
        out.insert(
            sym_table.interner.resolve(symbol.name()).to_string(),
            symbol_id,
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
    for input in layout_inputs {
        for (section_idx_zero, _section) in input.object.sections.iter().enumerate() {
            let input_section = (section_idx_zero + 1) as u8;
            let Some(relocs) = reloc_cache.get(&(input.id, input_section)) else {
                continue;
            };
            for reloc in relocs {
                if !marks_address_taken(reloc.kind) {
                    continue;
                }
                for target_atom in target_atoms_for_reloc(
                    input.object,
                    reloc.referent,
                    sym_table,
                    resolved_by_name,
                ) {
                    atom_table
                        .get_mut(target_atom)
                        .flags
                        .set(AtomFlags::ADDRESS_TAKEN);
                }
            }
        }
    }
}

fn marks_address_taken(kind: RelocKind) -> bool {
    matches!(
        kind,
        RelocKind::Unsigned
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
        let reloc_end = reloc.offset.saturating_add(reloc.length.byte_width() as u32);
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
                    object,
                    reloc.referent,
                    sym_table,
                    resolved_by_name,
                    redirects,
                )?,
                addend: reloc.addend,
                subtrahend: match reloc.subtrahend {
                    Some(referent) => Some(normalize_referent(
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
    object: &crate::input::ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    redirects: &HashMap<AtomId, AtomId>,
) -> Option<FoldReferent> {
    match referent {
        Referent::Symbol(sym_idx) => {
            let input_sym = object.symbols.get(sym_idx as usize)?;
            let name = object.symbol_name(input_sym).ok()?;
            let &symbol_id = resolved_by_name.get(name)?;
            match sym_table.get(symbol_id) {
                Symbol::Defined { atom, .. } if atom.0 != 0 => {
                    Some(FoldReferent::Atom(canonical_atom(*atom, redirects)))
                }
                _ => Some(FoldReferent::Symbol(symbol_id)),
            }
        }
        Referent::Section(section) => Some(FoldReferent::Section(section)),
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
    sym_table.interner.resolve(sym_table.get(symbol_id).name()).to_string()
}

fn target_atoms_for_reloc(
    object: &crate::input::ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
) -> Vec<AtomId> {
    match referent {
        Referent::Symbol(sym_idx) => {
            let Some(input_sym) = object.symbols.get(sym_idx as usize) else {
                return Vec::new();
            };
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
        Referent::Section(_) => Vec::new(),
    }
}
