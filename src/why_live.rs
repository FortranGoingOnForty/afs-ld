use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use crate::atom::{Atom, AtomSection, AtomTable};
use crate::icf::FoldedSymbol;
use crate::input::ObjectFile;
use crate::layout::LayoutInput;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent};
use crate::resolve::{AtomId, InputId, Symbol, SymbolId, SymbolTable};
use crate::symbol::SymKind;
use crate::symbol_visibility::SymbolVisibilityPolicy;
use crate::{LinkOptions, OutputKind};

#[derive(Debug, Clone)]
enum RootReason {
    Entry(String),
    NoDeadStrip,
    ExportedDylib,
}

impl RootReason {
    fn describe(&self, symbol: &str) -> String {
        match self {
            RootReason::Entry(entry) => format!("{symbol} is in -e {entry} (GC root)"),
            RootReason::NoDeadStrip => format!("{symbol} is marked N_NO_DEAD_STRIP (GC root)"),
            RootReason::ExportedDylib => format!("{symbol} is exported from the dylib (GC root)"),
        }
    }
}

#[derive(Debug, Clone)]
enum LiveCause {
    Root(RootReason),
    ReferencedBy(AtomId),
    ParentOf(AtomId),
    RefersToLive(AtomId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadStrippedSymbol {
    pub name: String,
    pub file_index: usize,
}

#[derive(Debug, Clone)]
pub struct DeadStripAnalysis {
    live_atoms: HashSet<AtomId>,
    causes: HashMap<AtomId, LiveCause>,
    resolved_by_name: HashMap<String, SymbolId>,
    atom_symbols: HashMap<AtomId, Vec<SymbolId>>,
}

impl DeadStripAnalysis {
    pub(crate) fn build(
        opts: &LinkOptions,
        visibility: &SymbolVisibilityPolicy,
        layout_inputs: &[LayoutInput<'_>],
        atom_table: &AtomTable,
        sym_table: &SymbolTable,
        entry_symbol: Option<SymbolId>,
    ) -> Self {
        let resolved_by_name = resolved_symbol_map(sym_table);
        let atom_symbols = atom_symbol_sets(atom_table);
        let roots = root_atoms(opts, visibility, atom_table, sym_table, entry_symbol);
        let forward_edges =
            build_forward_edges(layout_inputs, atom_table, sym_table, &resolved_by_name);
        let parent_edges = parent_edges(atom_table);
        let live_support_edges = live_support_edges(atom_table, &forward_edges);

        let mut live_atoms = HashSet::new();
        let mut causes = HashMap::new();
        let mut worklist = VecDeque::new();
        for (atom_id, reason) in roots {
            if live_atoms.insert(atom_id) {
                causes.insert(atom_id, LiveCause::Root(reason));
                worklist.push_back(atom_id);
            }
        }

        while let Some(atom_id) = worklist.pop_front() {
            if let Some(children) = parent_edges.get(&atom_id) {
                for &child in children {
                    if live_atoms.insert(child) {
                        causes.insert(child, LiveCause::ParentOf(atom_id));
                        worklist.push_back(child);
                    }
                }
            }
            if let Some(targets) = forward_edges.get(&atom_id) {
                for &target in targets {
                    if live_atoms.insert(target) {
                        causes.insert(target, LiveCause::ReferencedBy(atom_id));
                        worklist.push_back(target);
                    }
                }
            }
            if let Some(supporters) = live_support_edges.get(&atom_id) {
                for &supporter in supporters {
                    if live_atoms.insert(supporter) {
                        causes.insert(supporter, LiveCause::RefersToLive(atom_id));
                        worklist.push_back(supporter);
                    }
                }
            }
        }

        Self {
            live_atoms,
            causes,
            resolved_by_name,
            atom_symbols,
        }
    }

    pub fn live_atoms(&self) -> &HashSet<AtomId> {
        &self.live_atoms
    }

    pub fn dead_stripped_symbols(
        &self,
        atom_table: &AtomTable,
        sym_table: &SymbolTable,
        layout_inputs: &[LayoutInput<'_>],
    ) -> Vec<DeadStrippedSymbol> {
        let file_index_by_input: HashMap<InputId, usize> = layout_inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (input.id, idx + 1))
            .collect();
        let mut out = Vec::new();
        for (atom_id, _atom) in atom_table.iter() {
            if self.live_atoms.contains(&atom_id) {
                continue;
            }
            let Some(symbols) = self.atom_symbols.get(&atom_id) else {
                continue;
            };
            for &symbol_id in symbols {
                let Symbol::Defined { origin, .. } = sym_table.get(symbol_id) else {
                    continue;
                };
                out.push(DeadStrippedSymbol {
                    name: self.symbol_name(sym_table, symbol_id),
                    file_index: file_index_by_input.get(origin).copied().unwrap_or(0),
                });
            }
        }
        out.sort_by(|lhs, rhs| {
            lhs.name
                .cmp(&rhs.name)
                .then(lhs.file_index.cmp(&rhs.file_index))
        });
        out.dedup_by(|lhs, rhs| lhs.name == rhs.name && lhs.file_index == rhs.file_index);
        out
    }

    fn symbol_name(&self, sym_table: &SymbolTable, symbol_id: SymbolId) -> String {
        sym_table
            .interner
            .resolve(sym_table.get(symbol_id).name())
            .to_string()
    }

    fn atom_name(&self, sym_table: &SymbolTable, atom_id: AtomId) -> String {
        self.atom_symbols
            .get(&atom_id)
            .and_then(|symbols| symbols.first().copied())
            .map(|symbol_id| self.symbol_name(sym_table, symbol_id))
            .unwrap_or_else(|| format!("<atom {:?}>", atom_id))
    }

    fn is_live_symbol(&self, sym_table: &SymbolTable, symbol_id: SymbolId) -> bool {
        match sym_table.get(symbol_id) {
            Symbol::Defined { atom, .. } if atom.0 != 0 => self.live_atoms.contains(atom),
            Symbol::Absolute { .. } => true,
            _ => false,
        }
    }

    fn format_symbol_explanation(
        &self,
        sym_table: &SymbolTable,
        requested_symbol: SymbolId,
    ) -> String {
        let requested_name = self.symbol_name(sym_table, requested_symbol);
        if !self.is_live_symbol(sym_table, requested_symbol) {
            return format!("{requested_name} is not live (dead-stripped)\n");
        }
        if matches!(sym_table.get(requested_symbol), Symbol::Absolute { .. }) {
            return format!("{requested_name} is absolute and is not subject to dead stripping\n");
        }

        let Symbol::Defined { atom, .. } = sym_table.get(requested_symbol) else {
            return format!("{requested_name} is not backed by a dead-strip eligible input atom\n");
        };
        let mut out = String::new();
        writeln!(&mut out, "{requested_name} is live because:").unwrap();

        let mut cursor = *atom;
        let mut first = true;
        loop {
            let Some(cause) = self.causes.get(&cursor).cloned() else {
                writeln!(
                    &mut out,
                    "  no reachability chain from a known GC root was found"
                )
                .unwrap();
                break;
            };
            match cause {
                LiveCause::Root(reason) => {
                    let name = if first {
                        requested_name.as_str()
                    } else {
                        &self.atom_name(sym_table, cursor)
                    };
                    writeln!(&mut out, "  {}", reason.describe(name)).unwrap();
                    break;
                }
                LiveCause::ReferencedBy(parent) => {
                    let child_name = if first {
                        requested_name.as_str()
                    } else {
                        &self.atom_name(sym_table, cursor)
                    };
                    writeln!(
                        &mut out,
                        "  {child_name} is reachable from {}",
                        self.atom_name(sym_table, parent)
                    )
                    .unwrap();
                    cursor = parent;
                }
                LiveCause::ParentOf(parent) => {
                    let child_name = if first {
                        requested_name.as_str()
                    } else {
                        &self.atom_name(sym_table, cursor)
                    };
                    writeln!(
                        &mut out,
                        "  {child_name} is reachable via unwind parent from {}",
                        self.atom_name(sym_table, parent)
                    )
                    .unwrap();
                    cursor = parent;
                }
                LiveCause::RefersToLive(target) => {
                    let source_name = if first {
                        requested_name.as_str()
                    } else {
                        &self.atom_name(sym_table, cursor)
                    };
                    writeln!(
                        &mut out,
                        "  {source_name} is retained because it references live {}",
                        self.atom_name(sym_table, target)
                    )
                    .unwrap();
                    cursor = target;
                }
            }
            first = false;
        }

        out
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WhyLiveState<'a> {
    dead_strip: Option<&'a DeadStripAnalysis>,
    folded_symbols: &'a [FoldedSymbol],
}

impl<'a> WhyLiveState<'a> {
    pub(crate) fn new(
        dead_strip: Option<&'a DeadStripAnalysis>,
        folded_symbols: &'a [FoldedSymbol],
    ) -> Self {
        Self {
            dead_strip,
            folded_symbols,
        }
    }
}

pub(crate) fn format_explanations(
    opts: &LinkOptions,
    visibility: &SymbolVisibilityPolicy,
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    sym_table: &SymbolTable,
    entry_symbol: Option<SymbolId>,
    state: WhyLiveState<'_>,
) -> Result<Option<String>, String> {
    if opts.why_live.is_empty() {
        return Ok(None);
    }

    let folded_by_name: HashMap<&str, &str> = state
        .folded_symbols
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol.winner.as_str()))
        .collect();

    if let Some(dead_strip) = state.dead_strip {
        let mut out = String::new();
        for (idx, requested) in opts.why_live.iter().enumerate() {
            let winner = folded_by_name
                .get(requested.as_str())
                .copied()
                .unwrap_or(requested.as_str());
            let Some(&target) = dead_strip.resolved_by_name.get(winner) else {
                return Err(format!("`-why_live` symbol `{requested}` was not found"));
            };
            if idx > 0 {
                out.push('\n');
            }
            if winner != requested {
                writeln!(&mut out, "{requested} was folded to {winner} by -icf=safe").unwrap();
            }
            out.push_str(&dead_strip.format_symbol_explanation(sym_table, target));
        }
        return Ok(Some(out));
    }

    let graph = WhyLiveGraph::build(
        opts,
        visibility,
        layout_inputs,
        atom_table,
        sym_table,
        entry_symbol,
    );
    let mut out = String::new();
    for (idx, requested) in opts.why_live.iter().enumerate() {
        let winner = folded_by_name
            .get(requested.as_str())
            .copied()
            .unwrap_or(requested.as_str());
        let Some(&target) = graph.resolved_by_name.get(winner) else {
            return Err(format!("`-why_live` symbol `{requested}` was not found"));
        };
        if idx > 0 {
            out.push('\n');
        }
        if winner != requested {
            writeln!(&mut out, "{requested} was folded to {winner} by -icf=safe").unwrap();
        }
        let target_name = graph.symbol_name(target);
        writeln!(&mut out, "{target_name} is live because:").unwrap();
        writeln!(
            &mut out,
            "  note: -dead_strip was not requested; showing the current reachability roots"
        )
        .unwrap();
        if let Some(reason) = graph.roots.get(&target) {
            writeln!(&mut out, "  {}", reason.describe(&target_name)).unwrap();
            continue;
        }
        if let Some(path) = graph.find_chain(target) {
            for pair in path.windows(2).rev() {
                let parent = graph.symbol_name(pair[0]);
                let child = graph.symbol_name(pair[1]);
                writeln!(&mut out, "  {child} is reachable from {parent}").unwrap();
            }
            let root = path[0];
            let root_name = graph.symbol_name(root);
            writeln!(
                &mut out,
                "  {}",
                graph
                    .roots
                    .get(&root)
                    .expect("root path starts from a root")
                    .describe(&root_name)
            )
            .unwrap();
        } else {
            writeln!(
                &mut out,
                "  no reachability chain from a known GC root was found; linked inputs are currently retained as loaded"
            )
            .unwrap();
        }
    }
    Ok(Some(out))
}

struct WhyLiveGraph<'a> {
    sym_table: &'a SymbolTable,
    resolved_by_name: HashMap<String, SymbolId>,
    roots: HashMap<SymbolId, RootReason>,
    reverse_edges: HashMap<SymbolId, Vec<SymbolId>>,
}

impl<'a> WhyLiveGraph<'a> {
    fn build(
        opts: &LinkOptions,
        visibility: &SymbolVisibilityPolicy,
        layout_inputs: &[LayoutInput<'_>],
        atom_table: &AtomTable,
        sym_table: &'a SymbolTable,
        entry_symbol: Option<SymbolId>,
    ) -> Self {
        let resolved_by_name = resolved_symbol_map(sym_table);
        let roots = root_symbols(opts, visibility, atom_table, sym_table, entry_symbol);
        let reverse_edges = build_reverse_edges(layout_inputs, atom_table, &resolved_by_name);
        Self {
            sym_table,
            resolved_by_name,
            roots,
            reverse_edges,
        }
    }

    fn symbol_name(&self, symbol_id: SymbolId) -> String {
        self.sym_table
            .interner
            .resolve(self.sym_table.get(symbol_id).name())
            .to_string()
    }

    fn find_chain(&self, target: SymbolId) -> Option<Vec<SymbolId>> {
        let mut queue = VecDeque::from([target]);
        let mut seen = HashSet::from([target]);
        let mut next_toward_target = HashMap::<SymbolId, SymbolId>::new();

        while let Some(current) = queue.pop_front() {
            let Some(predecessors) = self.reverse_edges.get(&current) else {
                continue;
            };
            for &pred in predecessors {
                if !seen.insert(pred) {
                    continue;
                }
                next_toward_target.insert(pred, current);
                if self.roots.contains_key(&pred) {
                    let mut path = vec![pred];
                    let mut cursor = pred;
                    while let Some(&next) = next_toward_target.get(&cursor) {
                        path.push(next);
                        if next == target {
                            break;
                        }
                        cursor = next;
                    }
                    return Some(path);
                }
                queue.push_back(pred);
            }
        }

        None
    }
}

fn resolved_symbol_map(sym_table: &SymbolTable) -> HashMap<String, SymbolId> {
    let mut out = HashMap::new();
    for (symbol_id, symbol) in sym_table.iter() {
        let name = sym_table.interner.resolve(symbol.name()).to_string();
        let resolved = sym_table
            .resolve_chain(symbol.name())
            .map(|(resolved_id, _)| resolved_id)
            .unwrap_or(symbol_id);
        out.insert(name, resolved);
    }
    out
}

fn root_symbols(
    opts: &LinkOptions,
    visibility: &SymbolVisibilityPolicy,
    atom_table: &AtomTable,
    sym_table: &SymbolTable,
    entry_symbol: Option<SymbolId>,
) -> HashMap<SymbolId, RootReason> {
    let mut roots = HashMap::new();
    if let Some(entry_symbol) = entry_symbol {
        roots.insert(
            entry_symbol,
            RootReason::Entry(symbol_name(sym_table, entry_symbol)),
        );
    }
    for (symbol_id, symbol) in sym_table.iter() {
        match symbol {
            Symbol::Defined {
                atom,
                no_dead_strip: true,
                ..
            } if symbol_no_dead_strip_is_root(atom_table, *atom) => {
                roots.entry(symbol_id).or_insert(RootReason::NoDeadStrip);
            }
            Symbol::Absolute {
                no_dead_strip: true,
                ..
            } => {
                roots.entry(symbol_id).or_insert(RootReason::NoDeadStrip);
            }
            Symbol::Defined { .. }
                if is_exported_dylib_symbol(opts, visibility, sym_table, symbol) =>
            {
                roots.entry(symbol_id).or_insert(RootReason::ExportedDylib);
            }
            Symbol::Absolute { .. }
                if is_exported_dylib_symbol(opts, visibility, sym_table, symbol) =>
            {
                roots.entry(symbol_id).or_insert(RootReason::ExportedDylib);
            }
            Symbol::Alias { name, .. }
                if is_exported_dylib_symbol(opts, visibility, sym_table, symbol) =>
            {
                if let Ok((target_id, target)) = sym_table.resolve_chain(*name) {
                    if matches!(target, Symbol::Defined { .. } | Symbol::Absolute { .. }) {
                        roots.entry(target_id).or_insert(RootReason::ExportedDylib);
                    }
                }
            }
            _ => {}
        }
    }
    roots
}

fn root_atoms(
    opts: &LinkOptions,
    visibility: &SymbolVisibilityPolicy,
    atom_table: &AtomTable,
    sym_table: &SymbolTable,
    entry_symbol: Option<SymbolId>,
) -> HashMap<AtomId, RootReason> {
    let mut roots = HashMap::new();
    if let Some(entry_symbol) = entry_symbol {
        if let Symbol::Defined { atom, .. } = sym_table.get(entry_symbol) {
            if atom.0 != 0 {
                roots.insert(
                    *atom,
                    RootReason::Entry(symbol_name(sym_table, entry_symbol)),
                );
            }
        }
    }

    for (atom_id, atom) in atom_table.iter() {
        if atom.flags.has(crate::atom::AtomFlags::NO_DEAD_STRIP) {
            roots.entry(atom_id).or_insert(RootReason::NoDeadStrip);
        }
    }

    for (_, symbol) in sym_table.iter() {
        match symbol {
            Symbol::Defined {
                atom,
                no_dead_strip: true,
                ..
            } if atom.0 != 0 && symbol_no_dead_strip_is_root(atom_table, *atom) => {
                roots.entry(*atom).or_insert(RootReason::NoDeadStrip);
            }
            Symbol::Defined { atom, .. }
                if atom.0 != 0 && is_exported_dylib_symbol(opts, visibility, sym_table, symbol) =>
            {
                roots.entry(*atom).or_insert(RootReason::ExportedDylib);
            }
            Symbol::Alias { name, .. }
                if is_exported_dylib_symbol(opts, visibility, sym_table, symbol) =>
            {
                if let Ok((_, Symbol::Defined { atom, .. })) = sym_table.resolve_chain(*name) {
                    if atom.0 != 0 {
                        roots.entry(*atom).or_insert(RootReason::ExportedDylib);
                    }
                }
            }
            _ => {}
        }
    }

    roots
}

fn is_exported_dylib_symbol(
    opts: &LinkOptions,
    visibility: &SymbolVisibilityPolicy,
    sym_table: &SymbolTable,
    symbol: &Symbol,
) -> bool {
    if opts.kind != OutputKind::Dylib {
        return false;
    }
    let private_extern = match symbol {
        Symbol::Defined { private_extern, .. }
        | Symbol::Absolute { private_extern, .. }
        | Symbol::Alias { private_extern, .. } => *private_extern,
        _ => return false,
    };
    !private_extern && !visibility.hides(sym_table.interner.resolve(symbol.name()))
}

fn symbol_no_dead_strip_is_root(atom_table: &AtomTable, atom_id: AtomId) -> bool {
    atom_id.0 == 0
        || !atom_table
            .get(atom_id)
            .flags
            .has(crate::atom::AtomFlags::LIVE_SUPPORT)
}

fn build_reverse_edges(
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    resolved_by_name: &HashMap<String, SymbolId>,
) -> HashMap<SymbolId, Vec<SymbolId>> {
    let atom_index = AtomOffsetIndex::new(atom_table);
    let atom_symbols = atom_symbol_sets(atom_table);
    let mut edge_set = HashSet::<(SymbolId, SymbolId)>::new();

    for input in layout_inputs {
        for (section_idx_zero, section) in input.object.sections.iter().enumerate() {
            if section.raw_relocs.is_empty() {
                continue;
            }
            let Ok(raws) = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc) else {
                continue;
            };
            let Ok(relocs) = parse_relocs(&raws) else {
                continue;
            };
            let input_section = (section_idx_zero + 1) as u8;
            for reloc in relocs {
                let Some(source_atom) = atom_index.find(input.id, input_section, reloc.offset)
                else {
                    continue;
                };
                let Some(source_symbols) = atom_symbols.get(&source_atom) else {
                    continue;
                };
                let Some(target_symbols) =
                    target_symbols_for_reloc(input.object, reloc.referent, resolved_by_name)
                else {
                    continue;
                };
                for &source in source_symbols {
                    for &target in &target_symbols {
                        if source != target {
                            edge_set.insert((target, source));
                        }
                    }
                }
            }
        }
    }

    let mut reverse_edges = HashMap::<SymbolId, Vec<SymbolId>>::new();
    for (target, source) in edge_set {
        reverse_edges.entry(target).or_default().push(source);
    }
    for predecessors in reverse_edges.values_mut() {
        predecessors.sort_by_key(|sid| sid.0);
    }
    reverse_edges
}

fn build_forward_edges(
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
) -> HashMap<AtomId, Vec<AtomId>> {
    let atom_index = AtomOffsetIndex::new(atom_table);
    let mut edge_set = HashSet::<(AtomId, AtomId)>::new();

    for input in layout_inputs {
        for (section_idx_zero, section) in input.object.sections.iter().enumerate() {
            if section.raw_relocs.is_empty() {
                continue;
            }
            let Ok(raws) = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc) else {
                continue;
            };
            let Ok(relocs) = parse_relocs(&raws) else {
                continue;
            };
            let input_section = (section_idx_zero + 1) as u8;
            for reloc in relocs {
                let Some(source_atom) = atom_index.find(input.id, input_section, reloc.offset)
                else {
                    continue;
                };
                for target_atom in target_atoms_for_reloc(
                    input.id,
                    input.object,
                    atom_table.get(source_atom),
                    reloc,
                    reloc.referent,
                    reloc.subtrahend,
                    sym_table,
                    resolved_by_name,
                    &atom_index,
                ) {
                    if source_atom != target_atom {
                        edge_set.insert((source_atom, target_atom));
                    }
                }
            }
        }
    }

    for (atom_id, atom) in atom_table.iter() {
        if atom.section != AtomSection::EhFrame {
            continue;
        }
        let Some(cie_atom) = eh_frame_cie_atom(&atom_index, atom) else {
            continue;
        };
        if atom_id != cie_atom {
            edge_set.insert((atom_id, cie_atom));
        }
    }

    let mut forward_edges = HashMap::<AtomId, Vec<AtomId>>::new();
    for (source, target) in edge_set {
        forward_edges.entry(source).or_default().push(target);
    }
    for targets in forward_edges.values_mut() {
        targets.sort_by_key(|aid| aid.0);
    }
    forward_edges
}

fn parent_edges(atom_table: &AtomTable) -> HashMap<AtomId, Vec<AtomId>> {
    let mut out = HashMap::<AtomId, Vec<AtomId>>::new();
    for (atom_id, atom) in atom_table.iter() {
        if let Some(parent) = atom.parent_of {
            out.entry(parent).or_default().push(atom_id);
        }
    }
    for children in out.values_mut() {
        children.sort_by_key(|aid| aid.0);
    }
    out
}

fn live_support_edges(
    atom_table: &AtomTable,
    forward_edges: &HashMap<AtomId, Vec<AtomId>>,
) -> HashMap<AtomId, Vec<AtomId>> {
    let mut out = HashMap::<AtomId, Vec<AtomId>>::new();
    for (source, atom) in atom_table.iter() {
        if !atom.flags.has(crate::atom::AtomFlags::LIVE_SUPPORT) {
            continue;
        }
        for &target in forward_edges.get(&source).into_iter().flatten() {
            if atom_table
                .get(target)
                .flags
                .has(crate::atom::AtomFlags::LIVE_SUPPORT)
            {
                continue;
            }
            out.entry(target).or_default().push(source);
        }
    }
    for sources in out.values_mut() {
        sources.sort_by_key(|aid| aid.0);
        sources.dedup();
    }
    out
}

fn atom_symbol_sets(atom_table: &AtomTable) -> HashMap<crate::resolve::AtomId, Vec<SymbolId>> {
    let mut out = HashMap::new();
    for (atom_id, atom) in atom_table.iter() {
        let mut symbols = Vec::new();
        if let Some(owner) = atom.owner {
            symbols.push(owner);
        }
        for alt in &atom.alt_entries {
            symbols.push(alt.symbol);
        }
        symbols.sort_by_key(|sid| sid.0);
        symbols.dedup();
        if !symbols.is_empty() {
            out.insert(atom_id, symbols);
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct IndexedAtom {
    id: AtomId,
    start: u32,
    end: u32,
}

impl IndexedAtom {
    fn contains(self, offset: u32) -> bool {
        self.start <= offset && offset < self.end
    }
}

#[derive(Debug, Default)]
struct InputSectionAtomIndex {
    atoms: Vec<IndexedAtom>,
    ordered_non_overlapping: bool,
}

/// Relocation-to-atom lookup for why-live and dead-strip graph construction.
///
/// Normal atomization emits each input section in non-overlapping offset
/// order, so a relocation lookup is a binary search. Keep the original scan
/// as a defensive fallback for synthetic or malformed internal atom tables;
/// correctness must not depend on that construction invariant.
#[derive(Debug, Default)]
struct AtomOffsetIndex {
    sections: HashMap<(InputId, u8), InputSectionAtomIndex>,
}

impl AtomOffsetIndex {
    fn new(atom_table: &AtomTable) -> Self {
        let mut sections = HashMap::<(InputId, u8), InputSectionAtomIndex>::new();
        for (id, atom) in atom_table.iter() {
            let section = sections
                .entry((atom.origin, atom.input_section))
                .or_default();
            let end = atom.input_offset.saturating_add(atom.size);
            section.atoms.push(IndexedAtom {
                id,
                start: atom.input_offset,
                end,
            });
        }
        for section in sections.values_mut() {
            section.ordered_non_overlapping = section
                .atoms
                .windows(2)
                .all(|pair| pair[0].start <= pair[1].start && pair[0].end <= pair[1].start);
        }
        Self { sections }
    }

    fn find(&self, input_id: InputId, input_section: u8, offset: u32) -> Option<AtomId> {
        self.find_with_probe(input_id, input_section, offset, || {})
    }

    fn find_with_probe(
        &self,
        input_id: InputId,
        input_section: u8,
        offset: u32,
        mut probe: impl FnMut(),
    ) -> Option<AtomId> {
        let section = self.sections.get(&(input_id, input_section))?;
        if !section.ordered_non_overlapping {
            return section
                .atoms
                .iter()
                .find_map(|atom| {
                    probe();
                    atom.contains(offset).then_some(atom.id)
                })
                .or_else(|| {
                    section.atoms.iter().find_map(|atom| {
                        probe();
                        (atom.end == offset).then_some(atom.id)
                    })
                });
        }

        let candidate = section.atoms.partition_point(|atom| {
            probe();
            atom.start <= offset
        });
        if let Some(atom) = candidate
            .checked_sub(1)
            .and_then(|index| section.atoms.get(index))
        {
            probe();
            if atom.contains(offset) {
                return Some(atom.id);
            }
        }

        // Ends are nondecreasing under the section invariant. This second
        // binary search preserves the legacy rule that an otherwise
        // unmatched end boundary belongs to the first atom ending there.
        let boundary = section.atoms.partition_point(|atom| {
            probe();
            atom.end < offset
        });
        section
            .atoms
            .get(boundary)
            .and_then(|atom| (atom.end == offset).then_some(atom.id))
    }

    fn atom_ids(&self, input_id: InputId, input_section: u8) -> Vec<AtomId> {
        self.sections
            .get(&(input_id, input_section))
            .map(|section| section.atoms.iter().map(|atom| atom.id).collect())
            .unwrap_or_default()
    }
}

#[allow(clippy::too_many_arguments)]
fn target_atoms_for_reloc(
    input_id: InputId,
    object: &ObjectFile,
    source_atom: &Atom,
    reloc: crate::reloc::Reloc,
    referent: Referent,
    subtrahend: Option<Referent>,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    atom_index: &AtomOffsetIndex,
) -> Vec<AtomId> {
    if source_atom.section == AtomSection::EhFrame
        && reloc.offset == source_atom.input_offset.saturating_add(8)
    {
        // The FDE initial-location field is a PC-relative relocation. LLVM
        // may spell an interior function as a base symbol plus an implicit
        // addend, so following the named referent would retain the wrong atom.
        // Atomization has already evaluated that expression into parent_of.
        if let Some(parent) = source_atom.parent_of {
            return vec![parent];
        }
    }

    let mut out = referent_atoms(
        input_id,
        object,
        source_atom,
        reloc,
        referent,
        sym_table,
        resolved_by_name,
        atom_index,
    );
    if let Some(subtrahend) = subtrahend {
        out.extend(referent_atoms(
            input_id,
            object,
            source_atom,
            reloc,
            subtrahend,
            sym_table,
            resolved_by_name,
            atom_index,
        ));
    }
    out.sort_by_key(|aid| aid.0);
    out.dedup();
    out
}

#[allow(clippy::too_many_arguments)]
fn referent_atoms(
    input_id: InputId,
    object: &ObjectFile,
    source_atom: &Atom,
    reloc: crate::reloc::Reloc,
    referent: Referent,
    sym_table: &SymbolTable,
    resolved_by_name: &HashMap<String, SymbolId>,
    atom_index: &AtomOffsetIndex,
) -> Vec<AtomId> {
    match referent {
        Referent::Symbol(symbol_index) => {
            let Some(input_sym) = object.symbols.get(symbol_index as usize) else {
                return Vec::new();
            };
            if input_sym.kind() == SymKind::Sect && !input_sym.participates_in_global_resolution() {
                let Some(section) = object.section_for_symbol(input_sym) else {
                    return Vec::new();
                };
                let Some(section_offset) = input_sym.value().checked_sub(section.addr) else {
                    return Vec::new();
                };
                let Ok(section_offset) = u32::try_from(section_offset) else {
                    return Vec::new();
                };
                return atom_index
                    .find(input_id, input_sym.sect_idx(), section_offset)
                    .into_iter()
                    .collect();
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
        Referent::Section(section_index) => {
            if let Some(atom_id) =
                section_referent_atom(input_id, source_atom, reloc, section_index, atom_index)
            {
                vec![atom_id]
            } else {
                atom_index.atom_ids(input_id, section_index)
            }
        }
    }
}

fn section_referent_atom(
    input_id: InputId,
    source_atom: &Atom,
    reloc: crate::reloc::Reloc,
    section_index: u8,
    atom_index: &AtomOffsetIndex,
) -> Option<AtomId> {
    if source_atom.section == AtomSection::CompactUnwind
        && reloc.offset == source_atom.input_offset
        && source_atom.data.len() >= 8
    {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&source_atom.data[..8]);
        let target_offset = u64::from_le_bytes(buf) as u32;
        return atom_index.find(input_id, section_index, target_offset);
    }
    None
}

fn eh_frame_cie_atom(atom_index: &AtomOffsetIndex, atom: &Atom) -> Option<AtomId> {
    if atom.section != AtomSection::EhFrame || atom.data.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&atom.data[4..8]);
    let cie_delta = u32::from_le_bytes(buf);
    if cie_delta == 0 {
        return None;
    }
    let cie_offset = atom.input_offset.checked_add(4)?.checked_sub(cie_delta)?;
    atom_index.find(atom.origin, atom.input_section, cie_offset)
}

fn target_symbols_for_reloc(
    object: &ObjectFile,
    referent: Referent,
    resolved_by_name: &HashMap<String, SymbolId>,
) -> Option<Vec<SymbolId>> {
    let Referent::Symbol(symbol_index) = referent else {
        return None;
    };
    let input_sym = object.symbols.get(symbol_index as usize)?;
    if !input_sym.participates_in_global_resolution() {
        return None;
    }
    let name = object.symbol_name(input_sym).ok()?;
    resolved_by_name.get(name).copied().map(|sid| vec![sid])
}

fn symbol_name(sym_table: &SymbolTable, symbol_id: SymbolId) -> String {
    sym_table
        .interner
        .resolve(sym_table.get(symbol_id).name())
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::atom::AtomFlags;
    use crate::input::ObjectFile;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_MAGIC_64, MH_OBJECT, N_SECT, S_REGULAR,
    };
    use crate::macho::reader::MachHeader64;
    use crate::reloc::{write_raw_relocs, write_relocs, Reloc, RelocKind, RelocLength};
    use crate::section::{InputSection, SectionKind};
    use crate::string_table::StringTable;
    use crate::symbol::{InputSymbol, RawNlist};

    fn bare_test_atom() -> Atom {
        Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 1,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE,
            parent_of: None,
        }
    }

    fn test_offset_atom(input: InputId, section: u8, offset: u32, size: u32) -> Atom {
        Atom {
            origin: input,
            input_section: section,
            input_offset: offset,
            size,
            data: vec![0; size.min(8) as usize],
            ..bare_test_atom()
        }
    }

    #[test]
    fn atom_offset_lookup_preserves_containment_and_end_boundary_rules() {
        let mut atoms = AtomTable::new();
        let first = atoms.push(test_offset_atom(InputId(7), 2, 0, 4));
        let second = atoms.push(test_offset_atom(InputId(7), 2, 4, 4));
        let after_gap = atoms.push(test_offset_atom(InputId(7), 2, 12, 4));
        atoms.push(test_offset_atom(InputId(7), 2, 16, 0));
        let zero_sized = atoms.push(test_offset_atom(InputId(7), 3, 20, 0));
        let saturated = atoms.push(test_offset_atom(InputId(8), 1, u32::MAX - 2, 8));
        let index = AtomOffsetIndex::new(&atoms);

        let find = |input, section, offset| index.find(input, section, offset);
        assert_eq!(find(InputId(7), 2, 0), Some(first));
        assert_eq!(find(InputId(7), 2, 3), Some(first));
        assert_eq!(find(InputId(7), 2, 4), Some(second));
        assert_eq!(find(InputId(7), 2, 8), Some(second));
        assert_eq!(find(InputId(7), 2, 9), None);
        assert_eq!(find(InputId(7), 2, 12), Some(after_gap));
        assert_eq!(find(InputId(7), 2, 16), Some(after_gap));
        assert_eq!(find(InputId(7), 3, 20), Some(zero_sized));
        assert_eq!(find(InputId(8), 1, u32::MAX - 1), Some(saturated));
        assert_eq!(find(InputId(8), 1, u32::MAX), Some(saturated));
        assert_eq!(find(InputId(99), 1, 0), None);
    }

    #[test]
    fn atom_offset_lookup_preserves_legacy_order_for_noncanonical_overlaps() {
        let mut atoms = AtomTable::new();
        let first = atoms.push(test_offset_atom(InputId(9), 1, 4, 8));
        atoms.push(test_offset_atom(InputId(9), 1, 0, 8));
        let index = AtomOffsetIndex::new(&atoms);

        assert_eq!(index.find(InputId(9), 1, 6), Some(first));
    }

    #[test]
    fn atom_offset_lookup_uses_logarithmic_probes() {
        const ATOM_COUNT: u32 = 16_384;
        let mut atoms = AtomTable::new();
        let mut expected = AtomId(0);
        for index in 0..ATOM_COUNT {
            expected = atoms.push(test_offset_atom(InputId(11), 4, index * 4, 4));
        }
        let index = AtomOffsetIndex::new(&atoms);

        let mut interior_probes = 0;
        let found = index.find_with_probe(InputId(11), 4, (ATOM_COUNT - 1) * 4 + 2, || {
            interior_probes += 1;
        });

        assert_eq!(found, Some(expected));
        assert!(
            interior_probes <= 32,
            "indexed interior lookup should inspect at most 32 atoms, inspected {interior_probes}"
        );

        let mut boundary_probes = 0;
        let found = index.find_with_probe(InputId(11), 4, ATOM_COUNT * 4, || {
            boundary_probes += 1;
        });

        assert_eq!(found, Some(expected));
        assert!(
            boundary_probes <= 32,
            "indexed end-boundary lookup should inspect at most 32 atoms, inspected {boundary_probes}"
        );
    }

    fn alias_roots_private_target(private_alias: bool, exported_symbols: &[&str]) -> (bool, bool) {
        let mut atoms = AtomTable::new();
        let target_atom = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 4,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0xc0, 0x03, 0x5f, 0xd6],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let mut symbols = SymbolTable::new();
        let target_name = symbols.intern("_target");
        symbols
            .insert(Symbol::Defined {
                name: target_name,
                origin: InputId(0),
                atom: target_atom,
                value: 0,
                weak: false,
                private_extern: true,
                no_dead_strip: false,
            })
            .unwrap();
        let target_symbol = symbols.lookup(target_name).unwrap();
        let alias_name = symbols.intern("_alias");
        symbols
            .insert(Symbol::Alias {
                name: alias_name,
                aliased: target_name,
                origin: InputId(0),
                private_extern: private_alias,
            })
            .unwrap();
        let opts = LinkOptions {
            kind: OutputKind::Dylib,
            exported_symbols: exported_symbols
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            ..LinkOptions::default()
        };
        let visibility = SymbolVisibilityPolicy::from_opts(&opts).unwrap();

        (
            root_symbols(&opts, &visibility, &atoms, &symbols, None).contains_key(&target_symbol),
            root_atoms(&opts, &visibility, &atoms, &symbols, None).contains_key(&target_atom),
        )
    }

    #[test]
    fn dylib_alias_roots_follow_alias_visibility() {
        assert_eq!(alias_roots_private_target(false, &[]), (true, true));
        assert_eq!(alias_roots_private_target(true, &[]), (false, false));
        assert_eq!(
            alias_roots_private_target(false, &["_different_alias"]),
            (false, false)
        );
    }

    #[test]
    fn dylib_roots_respect_export_policy() {
        let mut atoms = AtomTable::new();
        let kept_atom = atoms.push(Atom {
            input_offset: 0,
            ..bare_test_atom()
        });
        let hidden_atom = atoms.push(Atom {
            input_offset: 8,
            ..bare_test_atom()
        });
        let blocked_atom = atoms.push(Atom {
            input_offset: 16,
            ..bare_test_atom()
        });
        let forced_atom = atoms.push(Atom {
            input_offset: 24,
            ..bare_test_atom()
        });
        let mut symbols = SymbolTable::new();
        for (name, atom) in [
            ("_kept", kept_atom),
            ("_hidden", hidden_atom),
            ("_blocked", blocked_atom),
        ] {
            let name = symbols.intern(name);
            symbols
                .insert(Symbol::Defined {
                    name,
                    origin: InputId(0),
                    atom,
                    value: 0,
                    weak: false,
                    private_extern: false,
                    no_dead_strip: false,
                })
                .unwrap();
        }
        let forced_name = symbols.intern("_forced");
        symbols
            .insert(Symbol::Defined {
                name: forced_name,
                origin: InputId(0),
                atom: forced_atom,
                value: 0,
                weak: false,
                private_extern: false,
                no_dead_strip: true,
            })
            .unwrap();
        let opts = LinkOptions {
            kind: OutputKind::Dylib,
            exported_symbols: vec!["_kept".into(), "_blocked".into()],
            unexported_symbols: vec!["_blocked".into()],
            ..LinkOptions::default()
        };
        let visibility = SymbolVisibilityPolicy::from_opts(&opts).unwrap();

        let atom_roots = root_atoms(&opts, &visibility, &atoms, &symbols, None);
        let symbol_roots = root_symbols(&opts, &visibility, &atoms, &symbols, None);
        let symbol_id = |name| {
            symbol_roots.contains_key(&symbols.lookup_str(name).expect("fixture symbol exists"))
        };

        assert!(atom_roots.contains_key(&kept_atom));
        assert!(!atom_roots.contains_key(&hidden_atom));
        assert!(!atom_roots.contains_key(&blocked_atom));
        assert!(atom_roots.contains_key(&forced_atom));
        assert!(symbol_id("_kept"));
        assert!(!symbol_id("_hidden"));
        assert!(!symbol_id("_blocked"));
        assert!(symbol_id("_forced"));
    }

    fn live_support_result(
        target_is_root: bool,
        support_symbol_no_dead_strip: bool,
    ) -> (bool, bool, bool) {
        let relocs = [Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        }];
        let raw_relocs = write_relocs(&relocs).unwrap();
        let mut reloc_bytes = Vec::new();
        write_raw_relocs(&raw_relocs, &mut reloc_bytes);
        let section = |name: &str, raw_relocs: Vec<u8>| InputSection {
            segname: "__DATA".into(),
            sectname: name.into(),
            kind: SectionKind::Data,
            addr: 0,
            size: 8,
            align_pow2: 3,
            flags: S_REGULAR,
            offset: 0,
            reloff: 0,
            nreloc: (raw_relocs.len() / 8) as u32,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: vec![0; 8],
            raw_relocs,
        };
        let object = ObjectFile {
            path: PathBuf::from("live-support.o"),
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
                section("__support", reloc_bytes),
                section("__target", Vec::new()),
            ],
            symbols: Vec::new(),
            strings: StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };
        let mut atoms = AtomTable::new();
        let support = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 1,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE.with(AtomFlags::LIVE_SUPPORT),
            parent_of: None,
        });
        let target = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 2,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: if target_is_root {
                AtomFlags::NONE.with(AtomFlags::NO_DEAD_STRIP)
            } else {
                AtomFlags::NONE
            },
            parent_of: None,
        });
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let mut symbols = SymbolTable::new();
        let support_symbol = if support_symbol_no_dead_strip {
            let support_name = symbols.intern("_support");
            symbols
                .insert(Symbol::Defined {
                    name: support_name,
                    origin: InputId(0),
                    atom: support,
                    value: 0,
                    weak: false,
                    private_extern: true,
                    no_dead_strip: true,
                })
                .unwrap();
            symbols.lookup(support_name)
        } else {
            None
        };
        let analysis = DeadStripAnalysis::build(
            &LinkOptions::default(),
            &SymbolVisibilityPolicy::default(),
            &inputs,
            &atoms,
            &symbols,
            None,
        );

        (
            analysis.live_atoms().contains(&support),
            analysis.live_atoms().contains(&target),
            support_symbol.is_some_and(|symbol| {
                root_symbols(
                    &LinkOptions::default(),
                    &SymbolVisibilityPolicy::default(),
                    &atoms,
                    &symbols,
                    None,
                )
                .contains_key(&symbol)
            }),
        )
    }

    #[test]
    fn live_support_atom_is_kept_when_its_target_is_live() {
        assert_eq!(live_support_result(true, false), (true, true, false));
    }

    #[test]
    fn live_support_atom_is_not_an_unconditional_root() {
        assert_eq!(live_support_result(false, false), (false, false, false));
    }

    #[test]
    fn live_support_ignores_symbol_no_dead_strip() {
        assert_eq!(live_support_result(false, true), (false, false, false));
    }

    #[test]
    fn live_support_preserves_section_no_dead_strip() {
        let mut atoms = AtomTable::new();
        let atom = atoms.push(Atom {
            flags: AtomFlags::NONE
                .with(AtomFlags::NO_DEAD_STRIP)
                .with(AtomFlags::LIVE_SUPPORT),
            ..bare_test_atom()
        });

        let roots = root_atoms(
            &LinkOptions::default(),
            &SymbolVisibilityPolicy::default(),
            &atoms,
            &SymbolTable::new(),
            None,
        );
        assert!(roots.contains_key(&atom));
    }

    #[test]
    fn live_support_does_not_reverse_through_shared_support_atoms() {
        let mut atoms = AtomTable::new();
        let first_fde = atoms.push(Atom {
            flags: AtomFlags::NONE.with(AtomFlags::LIVE_SUPPORT),
            ..bare_test_atom()
        });
        let second_fde = atoms.push(Atom {
            flags: AtomFlags::NONE.with(AtomFlags::LIVE_SUPPORT),
            ..bare_test_atom()
        });
        let cie = atoms.push(Atom {
            flags: AtomFlags::NONE.with(AtomFlags::LIVE_SUPPORT),
            ..bare_test_atom()
        });
        let function = atoms.push(bare_test_atom());
        let forward = HashMap::from([(first_fde, vec![function, cie]), (second_fde, vec![cie])]);

        let reverse = live_support_edges(&atoms, &forward);
        assert_eq!(reverse.get(&function), Some(&vec![first_fde]));
        assert!(!reverse.contains_key(&cie));
    }

    #[test]
    fn local_section_symbol_relocation_keeps_target_atom() {
        let relocs = [Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        }];
        let raw_relocs = write_relocs(&relocs).unwrap();
        let mut reloc_bytes = Vec::new();
        write_raw_relocs(&raw_relocs, &mut reloc_bytes);
        let section = |name: &str, raw_relocs: Vec<u8>| InputSection {
            segname: "__DATA".into(),
            sectname: name.into(),
            kind: SectionKind::Data,
            addr: 0,
            size: 8,
            align_pow2: 3,
            flags: S_REGULAR,
            offset: 0,
            reloff: 0,
            nreloc: (raw_relocs.len() / 8) as u32,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: vec![0; 8],
            raw_relocs,
        };
        let object = ObjectFile {
            path: PathBuf::from("local-section-symbol.o"),
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
                section("__source", reloc_bytes),
                section("__target", Vec::new()),
            ],
            symbols: vec![InputSymbol::from_raw(RawNlist {
                strx: 1,
                n_type: N_SECT,
                n_sect: 2,
                n_desc: 0,
                n_value: 0,
            })],
            strings: StringTable::from_bytes(b"\0Ltarget\0".to_vec()),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };
        let mut atoms = AtomTable::new();
        let source = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 1,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE.with(AtomFlags::NO_DEAD_STRIP),
            parent_of: None,
        });
        let target = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(0),
            input_section: 2,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let global_collision = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(1),
            input_section: 1,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let mut symbols = SymbolTable::new();
        let collision_name = symbols.intern("Ltarget");
        symbols
            .insert(Symbol::Defined {
                name: collision_name,
                origin: InputId(1),
                atom: global_collision,
                value: 0,
                weak: false,
                private_extern: false,
                no_dead_strip: false,
            })
            .unwrap();
        let resolved_by_name = resolved_symbol_map(&symbols);
        assert_eq!(
            target_symbols_for_reloc(&object, Referent::Symbol(0), &resolved_by_name),
            None
        );
        let inputs = [LayoutInput {
            id: InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let analysis = DeadStripAnalysis::build(
            &LinkOptions::default(),
            &SymbolVisibilityPolicy::default(),
            &inputs,
            &atoms,
            &symbols,
            None,
        );

        assert!(analysis.live_atoms().contains(&source));
        assert!(analysis.live_atoms().contains(&target));
        assert!(!analysis.live_atoms().contains(&global_collision));
    }
}
