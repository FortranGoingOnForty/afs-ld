use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use crate::atom::AtomTable;
use crate::input::ObjectFile;
use crate::layout::LayoutInput;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent};
use crate::resolve::{Symbol, SymbolId, SymbolTable};
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

pub fn format_explanations(
    opts: &LinkOptions,
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    sym_table: &SymbolTable,
    entry_symbol: Option<SymbolId>,
) -> Result<Option<String>, String> {
    if opts.why_live.is_empty() {
        return Ok(None);
    }

    let graph = WhyLiveGraph::build(opts, layout_inputs, atom_table, sym_table, entry_symbol);
    let mut out = String::new();
    for (idx, requested) in opts.why_live.iter().enumerate() {
        let Some(&target) = graph.resolved_by_name.get(requested) else {
            return Err(format!("`-why_live` symbol `{requested}` was not found"));
        };
        if idx > 0 {
            out.push('\n');
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
        layout_inputs: &[LayoutInput<'_>],
        atom_table: &AtomTable,
        sym_table: &'a SymbolTable,
        entry_symbol: Option<SymbolId>,
    ) -> Self {
        let resolved_by_name = resolved_symbol_map(sym_table);
        let roots = root_symbols(opts, sym_table, entry_symbol);
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
        let resolved = match symbol {
            Symbol::Alias { name, .. } => sym_table
                .resolve_chain(*name)
                .map(|(resolved_id, _)| resolved_id)
                .unwrap_or(symbol_id),
            _ => symbol_id,
        };
        out.insert(name, resolved);
    }
    out
}

fn root_symbols(
    opts: &LinkOptions,
    sym_table: &SymbolTable,
    entry_symbol: Option<SymbolId>,
) -> HashMap<SymbolId, RootReason> {
    let mut roots = HashMap::new();
    if let Some(entry_symbol) = entry_symbol {
        roots.insert(entry_symbol, RootReason::Entry(symbol_name(sym_table, entry_symbol)));
    }
    for (symbol_id, symbol) in sym_table.iter() {
        match symbol {
            Symbol::Defined {
                no_dead_strip: true,
                ..
            } => {
                roots.entry(symbol_id).or_insert(RootReason::NoDeadStrip);
            }
            Symbol::Defined {
                private_extern: false,
                ..
            } if opts.kind == OutputKind::Dylib => {
                roots.entry(symbol_id).or_insert(RootReason::ExportedDylib);
            }
            _ => {}
        }
    }
    roots
}

fn build_reverse_edges(
    layout_inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    resolved_by_name: &HashMap<String, SymbolId>,
) -> HashMap<SymbolId, Vec<SymbolId>> {
    let atoms_by_input_section = atom_table.by_input_section();
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
                let Some(source_atom) = find_atom_for_offset(
                    atom_table,
                    &atoms_by_input_section,
                    input.id,
                    input_section,
                    reloc.offset,
                ) else {
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

fn find_atom_for_offset(
    atom_table: &AtomTable,
    atoms_by_input_section: &HashMap<(crate::resolve::InputId, u8), Vec<crate::resolve::AtomId>>,
    input_id: crate::resolve::InputId,
    input_section: u8,
    offset: u32,
) -> Option<crate::resolve::AtomId> {
    atoms_by_input_section
        .get(&(input_id, input_section))
        .and_then(|ids| {
            ids.iter().find_map(|atom_id| {
                let atom = atom_table.get(*atom_id);
                let start = atom.input_offset;
                let end = atom.input_offset.saturating_add(atom.size);
                (start <= offset && offset < end).then_some(*atom_id)
            })
        })
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
    let name = object.symbol_name(input_sym).ok()?;
    resolved_by_name.get(name).copied().map(|sid| vec![sid])
}

fn symbol_name(sym_table: &SymbolTable, symbol_id: SymbolId) -> String {
    sym_table
        .interner
        .resolve(sym_table.get(symbol_id).name())
        .to_string()
}
