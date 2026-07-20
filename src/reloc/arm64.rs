use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::thread;

use crate::atom::{Atom, AtomSection, AtomTable};
use crate::input::ObjectFile;
use crate::layout::{ExtraOutputSection, ExtraSectionAnchor, Layout, LayoutInput};
use crate::macho::writer::LinkEditPlan;
use crate::reloc::{ParsedRelocCache, Referent, Reloc, RelocKind, RelocLength};
use crate::resolve::{InputId, Symbol, SymbolId, SymbolTable};
use crate::section::{OutputAtom, OutputSection, SectionKind};
use crate::symbol::{InputSymbol, SymKind};
use crate::synth::stubs::{STUB_HELPER_ENTRY_SIZE, STUB_HELPER_HEADER_SIZE, STUB_SIZE};
use crate::synth::tlv::THREAD_VARIABLE_DESCRIPTOR_SIZE;
use crate::synth::SyntheticPlan;
use crate::{LinkOptions, ThunkMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocError {
    pub input: PathBuf,
    pub atom: crate::resolve::AtomId,
    pub atom_offset: u32,
    pub kind: RelocKind,
    pub referent: String,
    pub detail: String,
}

impl fmt::Display for RelocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: relocation {:?} at atom {:?}+0x{:x} against {}: {}",
            self.input.display(),
            self.kind,
            self.atom,
            self.atom_offset,
            self.referent,
            self.detail
        )
    }
}

impl std::error::Error for RelocError {}

struct ResolveView<'a> {
    sym_table: &'a SymbolTable,
    symbol_name_index: &'a HashMap<String, SymbolId>,
    atom_table: &'a AtomTable,
    atom_addrs: &'a HashMap<crate::resolve::AtomId, u64>,
    atoms_by_input_section: &'a HashMap<(InputId, u8), Vec<crate::resolve::AtomId>>,
    section_addrs: &'a HashMap<(InputId, u8), u64>,
    stub_addrs: &'a HashMap<SymbolId, u64>,
    got_addrs: &'a HashMap<SymbolId, u64>,
    thread_pointer_addrs: &'a HashMap<SymbolId, u64>,
    lazy_pointer_addrs: &'a HashMap<SymbolId, u64>,
    stub_helper_entry_addrs: &'a HashMap<SymbolId, u64>,
    stub_helper_header_addr: Option<u64>,
    dyld_private_addr: Option<u64>,
    icf_redirects: Option<&'a HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
}

struct SyntheticAddressMaps {
    stub_addrs: HashMap<SymbolId, u64>,
    got_addrs: HashMap<SymbolId, u64>,
    thread_pointer_addrs: HashMap<SymbolId, u64>,
    lazy_pointer_addrs: HashMap<SymbolId, u64>,
    stub_helper_entry_addrs: HashMap<SymbolId, u64>,
    stub_helper_header_addr: Option<u64>,
    dyld_private_addr: Option<u64>,
}

pub struct ApplyLayoutPlan<'a> {
    pub synthetic_plan: Option<&'a SyntheticPlan>,
    pub thunk_plan: Option<&'a ThunkPlan>,
    pub linkedit: &'a LinkEditPlan,
    pub icf_redirects: Option<&'a HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
    pub parsed_relocs: &'a ParsedRelocCache,
    pub parallel_jobs: usize,
}

struct InputSectionResolveCtx<'a> {
    obj: &'a ObjectFile,
    atom: &'a Atom,
    kind: RelocKind,
    referent: &'a str,
}

struct RegularRelocContext<'a> {
    input_map: &'a HashMap<InputId, &'a ObjectFile>,
    atoms: &'a AtomTable,
    resolve: &'a ResolveView<'a>,
    thunk_plan: Option<&'a ThunkPlan>,
    thunk_addrs: Option<&'a HashMap<usize, u64>>,
    parsed_relocs: &'a ParsedRelocCache,
}

const THUNK_SIZE: u64 = 12;
const BR_X16: u32 = 0xd61f_0200;
const BRANCH26_MAX_FORWARD_DELTA_BYTES: u64 = ((1u64 << 25) - 1) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BranchTargetKey {
    Symbol(SymbolId),
    Stub(SymbolId),
    InputSectionOffset {
        origin: InputId,
        input_section: u8,
        input_offset: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ThunkBucketKey {
    island: usize,
    target: BranchTargetKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThunkIsland {
    segment: String,
    after_atom: crate::resolve::AtomId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThunkEntry {
    island: usize,
    slot_in_island: usize,
    target: BranchTargetKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThunkPlan {
    redirects: HashMap<(crate::resolve::AtomId, u32), usize>,
    islands: Vec<ThunkIsland>,
    entries: Vec<ThunkEntry>,
}

impl ThunkPlan {
    pub fn split_after_atoms(&self) -> Vec<crate::resolve::AtomId> {
        self.islands
            .iter()
            .map(|island| island.after_atom)
            .collect()
    }

    pub fn output_sections(&self) -> Vec<ExtraOutputSection> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut counts = vec![0usize; self.islands.len()];
        for entry in &self.entries {
            counts[entry.island] += 1;
        }
        let mut sections = Vec::new();
        for (island, island_desc) in self.islands.iter().enumerate() {
            let count = counts[island];
            if count == 0 {
                continue;
            }
            sections.push(ExtraOutputSection {
                after_section: Some(ExtraSectionAnchor::AfterAtom(island_desc.after_atom)),
                section: OutputSection {
                    segment: island_desc.segment.clone(),
                    name: "__thunks".into(),
                    kind: SectionKind::Text,
                    align_pow2: 2,
                    flags: crate::macho::constants::S_REGULAR
                        | crate::macho::constants::S_ATTR_PURE_INSTRUCTIONS
                        | crate::macho::constants::S_ATTR_SOME_INSTRUCTIONS,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    atoms: Vec::new(),
                    synthetic_offset: 0,
                    synthetic_data: vec![0; count * THUNK_SIZE as usize],
                    addr: 0,
                    size: (count as u64) * THUNK_SIZE,
                    file_off: 0,
                },
            });
        }
        sections
    }

    fn redirect_for(&self, atom: crate::resolve::AtomId, atom_offset: u32) -> Option<usize> {
        self.redirects.get(&(atom, atom_offset)).copied()
    }

    fn thunk_addrs(&self, layout: &Layout) -> HashMap<usize, u64> {
        let bases: HashMap<_, _> = self
            .islands
            .iter()
            .enumerate()
            .filter_map(|(island_idx, island)| {
                find_thunk_section_index(layout, island)
                    .map(|section_idx| (island_idx, layout.sections[section_idx].addr))
            })
            .collect();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                bases
                    .get(&entry.island)
                    .copied()
                    .map(|base| (index, base + (entry.slot_in_island as u64) * THUNK_SIZE))
            })
            .collect()
    }
}

pub fn apply_layout(
    layout: &mut Layout,
    inputs: &[LayoutInput<'_>],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
    plan: ApplyLayoutPlan<'_>,
) -> Result<(), RelocError> {
    let input_map: HashMap<InputId, &ObjectFile> = inputs
        .iter()
        .map(|input| (input.id, input.object))
        .collect();
    let atom_addrs = atom_address_map(layout);
    let atoms_by_input_section = atoms.by_input_section();
    let section_addrs = input_section_address_map(layout, atoms);
    let synth_addrs = synthetic_address_maps(layout, plan.synthetic_plan);
    let symbol_name_index = build_symbol_name_index(sym_table);
    let resolve = ResolveView {
        sym_table,
        symbol_name_index: &symbol_name_index,
        atom_table: atoms,
        atom_addrs: &atom_addrs,
        atoms_by_input_section: &atoms_by_input_section,
        section_addrs: &section_addrs,
        stub_addrs: &synth_addrs.stub_addrs,
        got_addrs: &synth_addrs.got_addrs,
        thread_pointer_addrs: &synth_addrs.thread_pointer_addrs,
        lazy_pointer_addrs: &synth_addrs.lazy_pointer_addrs,
        stub_helper_entry_addrs: &synth_addrs.stub_helper_entry_addrs,
        stub_helper_header_addr: synth_addrs.stub_helper_header_addr,
        dyld_private_addr: synth_addrs.dyld_private_addr,
        icf_redirects: plan.icf_redirects,
    };
    let thunk_addrs = plan
        .thunk_plan
        .map(|thunk_plan| thunk_plan.thunk_addrs(layout));

    let regular_ctx = RegularRelocContext {
        input_map: &input_map,
        atoms,
        resolve: &resolve,
        thunk_plan: plan.thunk_plan,
        thunk_addrs: thunk_addrs.as_ref(),
        parsed_relocs: plan.parsed_relocs,
    };
    apply_regular_relocs(layout, &regular_ctx, plan.parallel_jobs)?;

    if let Some(thunk_plan) = plan.thunk_plan {
        synthesize_thunk_section(layout, thunk_plan, &resolve)?;
    }

    if let Some(synthetic_plan) = plan.synthetic_plan {
        synthesize_thread_variable_section(
            layout,
            synthetic_plan,
            atoms,
            &input_map,
            plan.parsed_relocs,
            &resolve,
        )?;
        synthesize_got_section(layout, synthetic_plan, &resolve)?;
        synthesize_stub_section(layout, synthetic_plan, &resolve)?;
        synthesize_lazy_pointer_section(layout, synthetic_plan, &resolve)?;
        synthesize_stub_helper_section(layout, synthetic_plan, &resolve, plan.linkedit)?;
    }

    Ok(())
}

fn apply_regular_relocs(
    layout: &mut Layout,
    ctx: &RegularRelocContext<'_>,
    parallel_jobs: usize,
) -> Result<(), RelocError> {
    let parallel_jobs = parallel_jobs.max(1);
    for out_section in &mut layout.sections {
        let atom_count = out_section.atoms.len();
        if parallel_jobs == 1 || atom_count < 2 {
            apply_regular_atom_chunk(&mut out_section.atoms, ctx)?;
            continue;
        }

        let job_count = parallel_jobs.min(atom_count).max(1);
        let chunk_size = atom_count.div_ceil(job_count);
        thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in out_section.atoms.chunks_mut(chunk_size) {
                handles.push(scope.spawn(move || apply_regular_atom_chunk(chunk, ctx)));
            }
            for handle in handles {
                handle.join().expect("relocation worker panicked")?;
            }
            Ok::<(), RelocError>(())
        })?;
    }
    Ok(())
}

fn apply_regular_atom_chunk(
    placed_atoms: &mut [OutputAtom],
    ctx: &RegularRelocContext<'_>,
) -> Result<(), RelocError> {
    for placed in placed_atoms {
        let atom = ctx.atoms.get(placed.atom);
        if atom.size == 0 || placed.data.is_empty() {
            continue;
        }
        let obj = ctx.input_map.get(&atom.origin).ok_or_else(|| {
            reloc_error(
                atom,
                &PathBuf::from("<missing object>"),
                0,
                RelocKind::Unsigned,
                "object",
                "missing parsed object".to_string(),
            )
        })?;
        patch_eh_frame_cie_pointer(&mut placed.data, atom, ctx.resolve)?;
        let relocs = ctx
            .parsed_relocs
            .get(&(atom.origin, atom.input_section))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for reloc in relocs_for_atom(relocs, atom) {
            apply_one(
                &mut placed.data,
                atom,
                obj,
                reloc,
                ctx.resolve,
                ctx.thunk_plan,
                ctx.thunk_addrs,
            )?;
        }
    }
    Ok(())
}

fn patch_eh_frame_cie_pointer(
    bytes: &mut [u8],
    atom: &Atom,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    if atom.section != AtomSection::EhFrame || bytes.len() < 8 {
        return Ok(());
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[4..8]);
    let cie_delta = u32::from_le_bytes(buf);
    if cie_delta == 0 {
        return Ok(());
    }

    let cie_offset = atom
        .input_offset
        .checked_add(4)
        .and_then(|value| value.checked_sub(cie_delta))
        .ok_or_else(|| {
            reloc_error(
                atom,
                &PathBuf::from("<eh_frame>"),
                4,
                RelocKind::Unsigned,
                "__eh_frame CIE pointer",
                "invalid CIE back-pointer".to_string(),
            )
        })?;
    let cie_atom = resolve
        .atoms_by_input_section
        .get(&(atom.origin, atom.input_section))
        .and_then(|atom_ids| {
            atom_ids.iter().find_map(|atom_id| {
                let candidate = resolve.atom_table.get(*atom_id);
                let start = candidate.input_offset;
                let end = candidate.input_offset.saturating_add(candidate.size);
                (start <= cie_offset && cie_offset < end).then_some(*atom_id)
            })
        })
        .and_then(|atom_id| resolve.atom_addrs.get(&atom_id).copied())
        .ok_or_else(|| {
            reloc_error(
                atom,
                &PathBuf::from("<eh_frame>"),
                4,
                RelocKind::Unsigned,
                "__eh_frame CIE pointer",
                "eh_frame CIE atom is missing from the final layout".to_string(),
            )
        })?;
    let fde_field = resolve.atom_addrs.get(&atom.id).copied().ok_or_else(|| {
        reloc_error(
            atom,
            &PathBuf::from("<eh_frame>"),
            4,
            RelocKind::Unsigned,
            "__eh_frame CIE pointer",
            "eh_frame atom is missing a final address".to_string(),
        )
    })? + 4;
    let rewritten = fde_field.wrapping_sub(cie_atom) as u32;
    bytes[4..8].copy_from_slice(&rewritten.to_le_bytes());
    Ok(())
}

fn relocs_for_atom<'a>(relocs: &'a [Reloc], atom: &Atom) -> impl Iterator<Item = Reloc> + 'a {
    let start = atom.input_offset;
    let end = atom.input_offset + atom.size;
    relocs.iter().copied().filter(move |reloc| {
        let reloc_end = reloc.offset + reloc.length.byte_width() as u32;
        reloc.offset >= start && reloc_end <= end
    })
}

fn atom_address_map(layout: &Layout) -> HashMap<crate::resolve::AtomId, u64> {
    let mut out = HashMap::new();
    for section in &layout.sections {
        for placed in &section.atoms {
            out.insert(placed.atom, section.addr + placed.offset);
        }
    }
    out
}

fn input_section_address_map(layout: &Layout, atoms: &AtomTable) -> HashMap<(InputId, u8), u64> {
    let mut out = HashMap::new();
    for section in &layout.sections {
        for placed in &section.atoms {
            let atom = atoms.get(placed.atom);
            out.entry((atom.origin, atom.input_section))
                .or_insert(section.addr);
        }
    }
    out
}

fn atom_output_segment_map(layout: &Layout) -> HashMap<crate::resolve::AtomId, String> {
    let mut out = HashMap::new();
    for section in &layout.sections {
        for placed in &section.atoms {
            out.insert(placed.atom, section.segment.clone());
        }
    }
    out
}

fn synthetic_address_maps(
    layout: &Layout,
    synthetic_plan: Option<&SyntheticPlan>,
) -> SyntheticAddressMaps {
    let Some(plan) = synthetic_plan else {
        return SyntheticAddressMaps {
            stub_addrs: HashMap::new(),
            got_addrs: HashMap::new(),
            thread_pointer_addrs: HashMap::new(),
            lazy_pointer_addrs: HashMap::new(),
            stub_helper_entry_addrs: HashMap::new(),
            stub_helper_header_addr: None,
            dyld_private_addr: None,
        };
    };

    let mut stub_addrs = HashMap::new();
    if let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__TEXT" && section.name == "__stubs")
    {
        for (idx, entry) in plan.stubs.entries.iter().enumerate() {
            stub_addrs.insert(entry.symbol, section.addr + (idx as u64) * STUB_SIZE as u64);
        }
    }

    let mut got_addrs = HashMap::new();
    if let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA_CONST" && section.name == "__got")
    {
        for (idx, entry) in plan.got.entries.iter().enumerate() {
            got_addrs.insert(entry.symbol, section.addr + (idx as u64) * 8);
        }
    }

    let mut thread_pointer_addrs = HashMap::new();
    if let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA" && section.name == "__thread_ptrs")
    {
        for (idx, entry) in plan.thread_pointers.entries.iter().enumerate() {
            thread_pointer_addrs.insert(entry.symbol, section.addr + (idx as u64) * 8);
        }
    }

    let mut lazy_pointer_addrs = HashMap::new();
    if let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA" && section.name == "__la_symbol_ptr")
    {
        for (idx, entry) in plan.lazy_pointers.entries.iter().enumerate() {
            lazy_pointer_addrs.insert(entry.symbol, section.addr + (idx as u64) * 8);
        }
    }

    let mut stub_helper_entry_addrs = HashMap::new();
    let mut stub_helper_header_addr = None;
    if let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__TEXT" && section.name == "__stub_helper")
    {
        stub_helper_header_addr = Some(section.addr);
        for (idx, entry) in plan.lazy_pointers.entries.iter().enumerate() {
            stub_helper_entry_addrs.insert(
                entry.symbol,
                section.addr
                    + STUB_HELPER_HEADER_SIZE as u64
                    + (idx as u64) * STUB_HELPER_ENTRY_SIZE as u64,
            );
        }
    }

    let dyld_private_addr = layout
        .sections
        .iter()
        .find(|section| {
            section.segment == "__DATA"
                && section.name == "__data"
                && section.synthetic_data.len() >= crate::synth::stubs::DYLD_PRIVATE_SIZE as usize
        })
        .map(|section| section.addr + section.synthetic_offset);

    SyntheticAddressMaps {
        stub_addrs,
        got_addrs,
        thread_pointer_addrs,
        lazy_pointer_addrs,
        stub_helper_entry_addrs,
        stub_helper_header_addr,
        dyld_private_addr,
    }
}

pub struct ThunkPlanningContext<'a> {
    pub layout: &'a Layout,
    pub inputs: &'a [LayoutInput<'a>],
    pub atoms: &'a AtomTable,
    pub sym_table: &'a SymbolTable,
    pub synthetic_plan: Option<&'a SyntheticPlan>,
    pub icf_redirects: Option<&'a HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
    pub parsed_relocs: &'a ParsedRelocCache,
}

pub fn plan_thunks(
    opts: &LinkOptions,
    ctx: ThunkPlanningContext<'_>,
) -> Result<Option<ThunkPlan>, RelocError> {
    if opts.thunks == ThunkMode::None {
        return Ok(None);
    }

    let ThunkPlanningContext {
        layout,
        inputs,
        atoms,
        sym_table,
        synthetic_plan,
        icf_redirects,
        parsed_relocs,
    } = ctx;

    if opts.thunks == ThunkMode::Safe && layout_fits_branch26_span(layout) {
        return Ok(None);
    }

    let input_map: HashMap<InputId, &ObjectFile> = inputs
        .iter()
        .map(|input| (input.id, input.object))
        .collect();
    let atom_addrs = atom_address_map(layout);
    let atom_segments = atom_output_segment_map(layout);
    let atoms_by_input_section = atoms.by_input_section();
    let section_addrs = input_section_address_map(layout, atoms);
    let synth_addrs = synthetic_address_maps(layout, synthetic_plan);
    let symbol_name_index = build_symbol_name_index(sym_table);
    let resolve = ResolveView {
        sym_table,
        symbol_name_index: &symbol_name_index,
        atom_table: atoms,
        atom_addrs: &atom_addrs,
        atoms_by_input_section: &atoms_by_input_section,
        section_addrs: &section_addrs,
        stub_addrs: &synth_addrs.stub_addrs,
        got_addrs: &synth_addrs.got_addrs,
        thread_pointer_addrs: &synth_addrs.thread_pointer_addrs,
        lazy_pointer_addrs: &synth_addrs.lazy_pointer_addrs,
        stub_helper_entry_addrs: &synth_addrs.stub_helper_entry_addrs,
        stub_helper_header_addr: synth_addrs.stub_helper_header_addr,
        dyld_private_addr: synth_addrs.dyld_private_addr,
        icf_redirects,
    };

    let mut redirects = HashMap::new();
    let mut island_index: HashMap<crate::resolve::AtomId, usize> = HashMap::new();
    let mut index: HashMap<ThunkBucketKey, usize> = HashMap::new();
    let mut islands: Vec<ThunkIsland> = Vec::new();
    let mut entries: Vec<ThunkEntry> = Vec::new();
    for (atom_id, atom) in atoms.iter() {
        let Some(obj) = input_map.get(&atom.origin) else {
            continue;
        };
        let relocs = parsed_relocs
            .get(&(atom.origin, atom.input_section))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for reloc in relocs_for_atom(relocs, atom) {
            if reloc.kind != RelocKind::Branch26 {
                continue;
            }
            let local_offset = reloc.offset.saturating_sub(atom.input_offset);
            let Some(place) = resolve.atom_addrs.get(&atom.id).copied() else {
                continue;
            };
            let Some(caller_segment) = atom_segments.get(&atom.id).cloned() else {
                continue;
            };
            let place = place + local_offset as u64;
            let target_key = resolve_branch_target_key(obj, atom, reloc, &resolve)?;
            let target = resolve_branch_target_from_key(obj, atom, reloc, target_key, &resolve)?;
            let needs_thunk = match opts.thunks {
                ThunkMode::None => false,
                ThunkMode::Safe => !branch26_in_range(place, target),
                ThunkMode::All => true,
            };
            if !needs_thunk {
                continue;
            }
            let island = if let Some(&existing) = island_index.get(&atom_id) {
                existing
            } else {
                let next = islands.len();
                islands.push(ThunkIsland {
                    segment: caller_segment.clone(),
                    after_atom: atom_id,
                });
                island_index.insert(atom_id, next);
                next
            };
            let bucket_key = ThunkBucketKey {
                island,
                target: target_key,
            };
            let thunk_index = if let Some(&existing) = index.get(&bucket_key) {
                existing
            } else {
                let next = entries.len();
                let slot_in_island = entries
                    .iter()
                    .filter(|entry| entry.island == island)
                    .count();
                entries.push(ThunkEntry {
                    island,
                    slot_in_island,
                    target: target_key,
                });
                index.insert(bucket_key, next);
                next
            };
            redirects.insert((atom_id, local_offset), thunk_index);
        }
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ThunkPlan {
            redirects,
            islands,
            entries,
        }))
    }
}

fn apply_one(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
    thunk_plan: Option<&ThunkPlan>,
    thunk_addrs: Option<&HashMap<usize, u64>>,
) -> Result<(), RelocError> {
    let local_offset = reloc.offset.checked_sub(atom.input_offset).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            reloc.offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "relocation lands before atom start".to_string(),
        )
    })?;
    let place = resolve.atom_addrs.get(&atom.id).copied().ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "atom missing final address".to_string(),
        )
    })? + local_offset as u64;
    match reloc.kind {
        RelocKind::Unsigned => {
            if dylib_import_symbol_id(obj, reloc.referent, resolve).is_some() {
                if direct_import_bind_supported(reloc) {
                    clear_direct_import_slot(bytes, atom, obj, local_offset, reloc)
                } else {
                    Err(reloc_error(
                        atom,
                        &obj.path,
                        local_offset,
                        reloc.kind,
                        &describe_referent(obj, reloc.referent),
                        "direct dylib imports currently require a 64-bit UNSIGNED pointer slot"
                            .to_string(),
                    ))
                }
            } else {
                patch_unsigned(
                    bytes,
                    atom,
                    obj,
                    local_offset,
                    reloc,
                    resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?,
                )
            }
        }
        RelocKind::Subtractor => patch_subtractor(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?,
            resolve,
        ),
        RelocKind::Branch26 => {
            let target = if let Some(plan) = thunk_plan {
                if let Some(index) = plan.redirect_for(atom.id, local_offset) {
                    thunk_addrs
                        .and_then(|addrs| addrs.get(&index).copied())
                        .ok_or_else(|| {
                            reloc_error(
                                atom,
                                &obj.path,
                                local_offset,
                                reloc.kind,
                                &describe_referent(obj, reloc.referent),
                                "thunk section missing final address".to_string(),
                            )
                        })?
                } else {
                    resolve_branch_target(obj, atom, reloc, resolve)?
                }
            } else {
                resolve_branch_target(obj, atom, reloc, resolve)?
            };
            patch_branch26(bytes, atom, obj, local_offset, reloc, place, target)
        }
        RelocKind::Page21 => patch_page21(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?,
        ),
        RelocKind::PageOff12 => patch_pageoff12(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?,
        ),
        RelocKind::GotLoadPage21 => patch_page21(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            if got_reloc_relaxes_locally(obj, reloc, resolve) {
                resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?
            } else {
                resolve_got_target(obj, atom, reloc, resolve)?
            },
        ),
        RelocKind::GotLoadPageOff12 => {
            let target = if got_reloc_relaxes_locally(obj, reloc, resolve) {
                resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)?
            } else {
                resolve_got_target(obj, atom, reloc, resolve)?
            };
            if got_reloc_relaxes_locally(obj, reloc, resolve) {
                patch_got_pageoff12_relaxed(bytes, atom, obj, local_offset, reloc, target)
            } else {
                patch_pageoff12(bytes, atom, obj, local_offset, reloc, target)
            }
        }
        RelocKind::PointerToGot => patch_unsigned(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_got_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::TlvpLoadPage21 => patch_page21(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            resolve_tlvp_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::TlvpLoadPageOff12 => {
            let target = resolve_tlvp_pageoff_target(obj, atom, reloc, resolve)?;
            if dylib_import_symbol_id(obj, reloc.referent, resolve).is_some() {
                patch_pageoff12(bytes, atom, obj, local_offset, reloc, target)
            } else {
                patch_tlvp_pageoff12(bytes, atom, obj, local_offset, reloc, target)
            }
        }
    }
}

fn resolve_branch_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    let key = resolve_branch_target_key(obj, atom, reloc, resolve)?;
    resolve_branch_target_from_key(obj, atom, reloc, key, resolve)
}

fn resolve_branch_target_key(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<BranchTargetKey, RelocError> {
    if let Some(symbol_id) = dylib_import_symbol_id(obj, reloc.referent, resolve) {
        return Ok(BranchTargetKey::Stub(symbol_id));
    }
    match reloc.referent {
        Referent::Section(section_idx) => Ok(BranchTargetKey::InputSectionOffset {
            origin: atom.origin,
            input_section: section_idx,
            input_offset: 0,
        }),
        Referent::Symbol(sym_idx) => {
            let input_sym = obj.symbols.get(sym_idx as usize).ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    0,
                    reloc.kind,
                    &format!("symbol #{sym_idx}"),
                    "symbol index is out of range".to_string(),
                )
            })?;
            if let Ok(name) = obj.symbol_name(input_sym) {
                if let Some(symbol_id) = resolve.symbol_name_index.get(name).copied() {
                    return Ok(BranchTargetKey::Symbol(symbol_id));
                }
            }
            match input_sym.kind() {
                SymKind::Sect => {
                    let section = obj.section_for_symbol(input_sym).ok_or_else(|| {
                        reloc_error(
                            atom,
                            &obj.path,
                            0,
                            reloc.kind,
                            &describe_input_symbol(obj, input_sym),
                            "section-backed symbol did not resolve to an input section".to_string(),
                        )
                    })?;
                    Ok(BranchTargetKey::InputSectionOffset {
                        origin: atom.origin,
                        input_section: input_sym.sect_idx(),
                        input_offset: input_sym.value().saturating_sub(section.addr) as u32,
                    })
                }
                SymKind::Abs => Err(reloc_error(
                    atom,
                    &obj.path,
                    0,
                    reloc.kind,
                    &describe_input_symbol(obj, input_sym),
                    "absolute BRANCH26 targets are not supported".to_string(),
                )),
                SymKind::Undef => Err(reloc_error(
                    atom,
                    &obj.path,
                    0,
                    reloc.kind,
                    &describe_input_symbol(obj, input_sym),
                    "symbol remained undefined at relocation time".to_string(),
                )),
                SymKind::Indirect => Err(reloc_error(
                    atom,
                    &obj.path,
                    0,
                    reloc.kind,
                    &describe_input_symbol(obj, input_sym),
                    "indirect BRANCH26 targets are not yet supported".to_string(),
                )),
            }
        }
    }
}

fn resolve_branch_target_from_key(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    key: BranchTargetKey,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match key {
        BranchTargetKey::Symbol(symbol_id) => match resolve.sym_table.get(symbol_id) {
            Symbol::Defined {
                atom: target_atom,
                value,
                ..
            } => resolve
                .atom_addrs
                .get(&canonical_atom(*target_atom, resolve.icf_redirects))
                .copied()
                .map(|addr| addr + *value)
                .ok_or_else(|| {
                    reloc_error(
                        atom,
                        &obj.path,
                        reloc.offset.saturating_sub(atom.input_offset),
                        reloc.kind,
                        &describe_referent(obj, reloc.referent),
                        "target atom missing final address".to_string(),
                    )
                }),
            Symbol::DylibImport { .. } => Err(reloc_error(
                atom,
                &obj.path,
                reloc.offset.saturating_sub(atom.input_offset),
                reloc.kind,
                &describe_referent(obj, reloc.referent),
                "dylib import is missing synthetic stub".to_string(),
            )),
            other => Err(reloc_error(
                atom,
                &obj.path,
                reloc.offset.saturating_sub(atom.input_offset),
                reloc.kind,
                &describe_referent(obj, reloc.referent),
                format!("symbol resolved to unsupported state {:?}", other.kind()),
            )),
        },
        BranchTargetKey::Stub(symbol_id) => {
            resolve.stub_addrs.get(&symbol_id).copied().ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    reloc.offset.saturating_sub(atom.input_offset),
                    reloc.kind,
                    &describe_referent(obj, reloc.referent),
                    "dylib import is missing synthetic stub".to_string(),
                )
            })
        }
        BranchTargetKey::InputSectionOffset {
            origin,
            input_section,
            input_offset,
        } => resolve_input_section_offset(
            origin,
            input_section,
            input_offset,
            InputSectionResolveCtx {
                obj,
                atom,
                kind: reloc.kind,
                referent: &describe_referent(obj, reloc.referent),
            },
            resolve,
        ),
    }
}

fn branch26_in_range(place: u64, target: u64) -> bool {
    let delta = target.wrapping_sub(place) as i64;
    delta & 0b11 == 0 && fits_signed(delta >> 2, 26)
}

fn layout_fits_branch26_span(layout: &Layout) -> bool {
    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;
    for section in &layout.sections {
        if section.segment == "__LINKEDIT" || section.size == 0 {
            continue;
        }
        min_addr = min_addr.min(section.addr);
        max_addr = max_addr.max(section.addr.saturating_add(section.size));
    }
    min_addr == u64::MAX || max_addr.saturating_sub(min_addr) <= BRANCH26_MAX_FORWARD_DELTA_BYTES
}

fn synthesize_thunk_section(
    layout: &mut Layout,
    plan: &ThunkPlan,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for entry in &plan.entries {
        *counts.entry(entry.island).or_insert(0usize) += 1;
    }
    for (island_idx, island) in plan.islands.iter().enumerate() {
        let expected_len = counts.get(&island_idx).copied().unwrap_or(0) * THUNK_SIZE as usize;
        let section_idx = find_thunk_section_index(layout, island).ok_or_else(|| RelocError {
            input: PathBuf::from("<synthetic thunks>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: (island_idx as u32) * THUNK_SIZE as u32,
            kind: RelocKind::Branch26,
            referent: "thunk section".to_string(),
            detail: format!(
                "missing thunk section for island after {},{}",
                island.segment, island.after_atom.0
            ),
        })?;
        let section = &mut layout.sections[section_idx];
        if section.synthetic_data.len() != expected_len {
            section.synthetic_data.resize(expected_len, 0);
        }
    }
    for (idx, entry) in plan.entries.iter().enumerate() {
        let island = &plan.islands[entry.island];
        let section_idx = find_thunk_section_index(layout, island).ok_or_else(|| RelocError {
            input: PathBuf::from("<synthetic thunks>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: (idx as u32) * THUNK_SIZE as u32,
            kind: RelocKind::Branch26,
            referent: "thunk section".to_string(),
            detail: format!(
                "missing thunk section for island after {},{}",
                island.segment, island.after_atom.0
            ),
        })?;
        let section = &mut layout.sections[section_idx];
        let thunk_addr = section.addr + (entry.slot_in_island as u64) * THUNK_SIZE;
        let target = match entry.target {
            BranchTargetKey::Symbol(symbol_id) => match resolve.sym_table.get(symbol_id) {
                Symbol::Defined { atom, value, .. } => resolve
                    .atom_addrs
                    .get(&canonical_atom(*atom, resolve.icf_redirects))
                    .copied()
                    .map(|addr| addr + *value),
                _ => None,
            },
            BranchTargetKey::Stub(symbol_id) => resolve.stub_addrs.get(&symbol_id).copied(),
            BranchTargetKey::InputSectionOffset {
                origin,
                input_section,
                input_offset,
            } => resolve_input_section_offset_simple(origin, input_section, input_offset, resolve),
        }
        .ok_or_else(|| RelocError {
            input: PathBuf::from("<synthetic thunks>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: (idx as u32) * THUNK_SIZE as u32,
            kind: RelocKind::Branch26,
            referent: "thunk target".to_string(),
            detail: "missing final target address".to_string(),
        })?;
        let adrp = encode_adrp_reg(16, thunk_addr, target, "thunk target")?;
        let add = encode_add_x_reg_pageoff(16, target, "thunk target")?;
        let start = entry.slot_in_island * THUNK_SIZE as usize;
        section.synthetic_data[start..start + 4].copy_from_slice(&adrp.to_le_bytes());
        section.synthetic_data[start + 4..start + 8].copy_from_slice(&add.to_le_bytes());
        section.synthetic_data[start + 8..start + 12].copy_from_slice(&BR_X16.to_le_bytes());
    }
    Ok(())
}

fn find_thunk_section_index(layout: &Layout, island: &ThunkIsland) -> Option<usize> {
    layout
        .sections
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(idx, section)| {
            let prev = &layout.sections[idx - 1];
            (prev.segment == island.segment
                && prev
                    .atoms
                    .last()
                    .map(|placed| placed.atom == island.after_atom)
                    .unwrap_or(false)
                && section.segment == island.segment
                && section.name == "__thunks")
                .then_some(idx)
        })
}

fn resolve_got_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    let Some(symbol_id) = symbol_referent_id(obj, reloc.referent, resolve) else {
        return Err(reloc_error(
            atom,
            &obj.path,
            reloc.offset.saturating_sub(atom.input_offset),
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "GOT relocations require a symbol target".to_string(),
        ));
    };
    resolve.got_addrs.get(&symbol_id).copied().ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            reloc.offset.saturating_sub(atom.input_offset),
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "symbol is missing synthetic GOT slot".to_string(),
        )
    })
}

fn got_reloc_relaxes_locally(obj: &ObjectFile, reloc: Reloc, resolve: &ResolveView<'_>) -> bool {
    match symbol_referent_id(obj, reloc.referent, resolve) {
        Some(symbol_id) => match resolve.sym_table.get(symbol_id) {
            Symbol::DylibImport { .. } => false,
            Symbol::Defined { .. } => true,
            _ => true,
        },
        None => true,
    }
}

fn resolve_tlvp_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    if let Some(symbol_id) = dylib_import_symbol_id(obj, reloc.referent, resolve) {
        return resolve
            .thread_pointer_addrs
            .get(&symbol_id)
            .copied()
            .ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    reloc.offset.saturating_sub(atom.input_offset),
                    reloc.kind,
                    &describe_referent(obj, reloc.referent),
                    "dylib import is missing synthetic thread-pointer slot".to_string(),
                )
            });
    }
    resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)
}

fn resolve_tlvp_pageoff_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    if dylib_import_symbol_id(obj, reloc.referent, resolve).is_some() {
        return resolve_tlvp_target(obj, atom, reloc, resolve);
    }
    resolve_referent(obj, atom, reloc.kind, reloc.referent, resolve)
}

fn resolve_referent(
    obj: &ObjectFile,
    atom: &Atom,
    kind: RelocKind,
    referent: Referent,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match referent {
        Referent::Section(section_idx) => resolve
            .section_addrs
            .get(&(atom.origin, section_idx))
            .copied()
            .ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    0,
                    kind,
                    &format!("section #{section_idx}"),
                    "referenced input section was not laid out".to_string(),
                )
            }),
        Referent::Symbol(sym_idx) => {
            resolve_symbol_referent(obj, atom, kind, sym_idx as usize, resolve)
        }
    }
}

fn resolve_symbol_referent(
    obj: &ObjectFile,
    atom: &Atom,
    kind: RelocKind,
    sym_idx: usize,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    let input_sym = obj.symbols.get(sym_idx).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            0,
            kind,
            &format!("symbol #{sym_idx}"),
            "symbol index is out of range".to_string(),
        )
    })?;

    if let Ok(name) = obj.symbol_name(input_sym) {
        if let Some(symbol_id) = resolve.symbol_name_index.get(name).copied() {
            return resolve_global_symbol(
                obj,
                atom,
                kind,
                name,
                resolve.sym_table.get(symbol_id),
                resolve,
            );
        }
    }

    resolve_input_symbol(obj, atom, kind, input_sym, resolve)
}

fn dylib_import_symbol_id(
    obj: &ObjectFile,
    referent: Referent,
    resolve: &ResolveView<'_>,
) -> Option<SymbolId> {
    let symbol_id = symbol_referent_id(obj, referent, resolve)?;
    matches!(resolve.sym_table.get(symbol_id), Symbol::DylibImport { .. }).then_some(symbol_id)
}

fn symbol_referent_id(
    obj: &ObjectFile,
    referent: Referent,
    resolve: &ResolveView<'_>,
) -> Option<SymbolId> {
    let Referent::Symbol(sym_idx) = referent else {
        return None;
    };
    let input_sym = obj.symbols.get(sym_idx as usize)?;
    let name = obj.symbol_name(input_sym).ok()?;
    resolve.symbol_name_index.get(name).copied()
}

fn build_symbol_name_index(sym_table: &SymbolTable) -> HashMap<String, SymbolId> {
    sym_table
        .iter()
        .map(|(symbol_id, symbol)| {
            let resolved_id = sym_table
                .resolve_chain(symbol.name())
                .map(|(resolved_id, _)| resolved_id)
                .unwrap_or(symbol_id);
            (
                sym_table.interner.resolve(symbol.name()).to_string(),
                resolved_id,
            )
        })
        .collect()
}

fn resolve_global_symbol(
    obj: &ObjectFile,
    atom: &Atom,
    kind: RelocKind,
    name: &str,
    symbol: &Symbol,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match symbol {
        Symbol::Defined {
            atom: target_atom,
            value,
            ..
        } => resolve
            .atom_addrs
            .get(target_atom)
            .copied()
            .map(|addr| addr + *value)
            .ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    0,
                    kind,
                    name,
                    "target atom missing final address".to_string(),
                )
            }),
        Symbol::DylibImport { .. } => Err(reloc_error(
            atom,
            &obj.path,
            0,
            kind,
            name,
            "direct dylib import reference must use GOT/stub/TLV machinery or a bound pointer slot"
                .to_string(),
        )),
        other => Err(reloc_error(
            atom,
            &obj.path,
            0,
            kind,
            name,
            format!("symbol resolved to unsupported state {:?}", other.kind()),
        )),
    }
}

fn resolve_input_symbol(
    obj: &ObjectFile,
    atom: &Atom,
    kind: RelocKind,
    input_sym: &InputSymbol,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    resolve_input_symbol_at_origin(atom.origin, obj, atom, kind, input_sym, resolve)
}

fn resolve_input_symbol_at_origin(
    origin: InputId,
    obj: &ObjectFile,
    atom: &Atom,
    kind: RelocKind,
    input_sym: &InputSymbol,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match input_sym.kind() {
        SymKind::Abs => Ok(input_sym.value()),
        SymKind::Sect => {
            let section = obj.section_for_symbol(input_sym).ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    0,
                    kind,
                    &describe_input_symbol(obj, input_sym),
                    "section-backed symbol did not resolve to an input section".to_string(),
                )
            })?;
            let section_offset = input_sym.value().saturating_sub(section.addr) as u32;
            resolve_input_section_offset(
                origin,
                input_sym.sect_idx(),
                section_offset,
                InputSectionResolveCtx {
                    obj,
                    atom,
                    kind,
                    referent: &describe_input_symbol(obj, input_sym),
                },
                resolve,
            )
        }
        SymKind::Undef => Err(reloc_error(
            atom,
            &obj.path,
            0,
            kind,
            &describe_input_symbol(obj, input_sym),
            "symbol remained undefined at relocation time".to_string(),
        )),
        SymKind::Indirect => Err(reloc_error(
            atom,
            &obj.path,
            0,
            kind,
            &describe_input_symbol(obj, input_sym),
            "indirect symbol relocations are not yet implemented".to_string(),
        )),
    }
}

fn resolve_input_section_offset(
    origin: InputId,
    input_section: u8,
    input_offset: u32,
    ctx: InputSectionResolveCtx<'_>,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    if let Some(atom_ids) = resolve.atoms_by_input_section.get(&(origin, input_section)) {
        if let Some((target_atom, delta)) = atom_ids.iter().find_map(|atom_id| {
            let candidate = resolve.atom_table.get(*atom_id);
            let start = candidate.input_offset;
            let end = candidate.input_offset.saturating_add(candidate.size);
            if start <= input_offset && input_offset < end {
                Some((*atom_id, input_offset - start))
            } else if input_offset == end {
                Some((*atom_id, candidate.size))
            } else {
                None
            }
        }) {
            let target_atom = canonical_atom(target_atom, resolve.icf_redirects);
            let atom_addr = resolve
                .atom_addrs
                .get(&target_atom)
                .copied()
                .ok_or_else(|| {
                    reloc_error(
                        ctx.atom,
                        &ctx.obj.path,
                        0,
                        ctx.kind,
                        ctx.referent,
                        "section-backed symbol's containing atom is missing a final address"
                            .to_string(),
                    )
                })?;
            return Ok(atom_addr + delta as u64);
        }
    }

    let section_addr = resolve
        .section_addrs
        .get(&(origin, input_section))
        .copied()
        .ok_or_else(|| {
            reloc_error(
                ctx.atom,
                &ctx.obj.path,
                0,
                ctx.kind,
                ctx.referent,
                "section-backed symbol's output section is missing".to_string(),
            )
        })?;
    Ok(section_addr + input_offset as u64)
}

fn resolve_input_section_offset_simple(
    origin: InputId,
    input_section: u8,
    input_offset: u32,
    resolve: &ResolveView<'_>,
) -> Option<u64> {
    if let Some(atom_ids) = resolve.atoms_by_input_section.get(&(origin, input_section)) {
        if let Some((target_atom, delta)) = atom_ids.iter().find_map(|atom_id| {
            let candidate = resolve.atom_table.get(*atom_id);
            let start = candidate.input_offset;
            let end = candidate.input_offset.saturating_add(candidate.size);
            if start <= input_offset && input_offset < end {
                Some((*atom_id, input_offset - start))
            } else if input_offset == end {
                Some((*atom_id, candidate.size))
            } else {
                None
            }
        }) {
            let target_atom = canonical_atom(target_atom, resolve.icf_redirects);
            return resolve
                .atom_addrs
                .get(&target_atom)
                .copied()
                .map(|addr| addr + delta as u64);
        }
    }
    resolve
        .section_addrs
        .get(&(origin, input_section))
        .copied()
        .map(|section_addr| section_addr + input_offset as u64)
}

fn canonical_atom(
    atom_id: crate::resolve::AtomId,
    redirects: Option<&HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
) -> crate::resolve::AtomId {
    let Some(redirects) = redirects else {
        return atom_id;
    };
    let mut current = atom_id;
    while let Some(&next) = redirects.get(&current) {
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn patch_unsigned(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    target: u64,
) -> Result<(), RelocError> {
    let implicit_addend = read_implicit_addend(
        bytes,
        local_offset,
        reloc.length,
        atom,
        obj,
        reloc.kind,
        reloc.referent,
    )?;
    let value = target
        .wrapping_add_signed(reloc.addend)
        .wrapping_add_signed(implicit_addend);
    match reloc.length {
        RelocLength::Word => write_u32(
            bytes,
            local_offset,
            value as u32,
            atom,
            obj,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
        ),
        RelocLength::Quad => write_u64(
            bytes,
            local_offset,
            value,
            atom,
            obj,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
        ),
        other => Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("unsupported UNSIGNED width {:?}", other),
        )),
    }
}

fn direct_import_bind_supported(reloc: Reloc) -> bool {
    matches!(reloc.length, RelocLength::Quad) && !reloc.pcrel && reloc.subtrahend.is_none()
}

fn clear_direct_import_slot(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
) -> Result<(), RelocError> {
    write_u64(
        bytes,
        local_offset,
        0,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn patch_subtractor(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    minuend: u64,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let subtrahend = resolve_referent(
        obj,
        atom,
        reloc.kind,
        reloc.subtrahend.ok_or_else(|| {
            reloc_error(
                atom,
                &obj.path,
                local_offset,
                reloc.kind,
                &describe_referent(obj, reloc.referent),
                "SUBTRACTOR reloc missing subtrahend pair".to_string(),
            )
        })?,
        resolve,
    )?;
    let implicit_addend = read_implicit_addend(
        bytes,
        local_offset,
        reloc.length,
        atom,
        obj,
        reloc.kind,
        reloc.referent,
    )?;
    let value = minuend
        .wrapping_sub(subtrahend)
        .wrapping_add_signed(reloc.addend);
    let value = value.wrapping_add_signed(implicit_addend);
    match reloc.length {
        RelocLength::Word => write_u32(
            bytes,
            local_offset,
            value as u32,
            atom,
            obj,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
        ),
        RelocLength::Quad => write_u64(
            bytes,
            local_offset,
            value,
            atom,
            obj,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
        ),
        other => Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("unsupported SUBTRACTOR width {:?}", other),
        )),
    }
}

fn patch_branch26(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    place: u64,
    target: u64,
) -> Result<(), RelocError> {
    let delta = target.wrapping_add_signed(reloc.addend).wrapping_sub(place) as i64;
    if delta & 0b11 != 0 {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("branch target delta 0x{delta:x} is not 4-byte aligned"),
        ));
    }
    let imm = delta >> 2;
    if !fits_signed(imm, 26) {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("branch target is out of BRANCH26 range (delta {delta:#x})"),
        ));
    }
    let insn = read_u32(
        bytes,
        local_offset,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )?;
    let imm26 = (imm as u32) & 0x03ff_ffff;
    write_u32(
        bytes,
        local_offset,
        (insn & !0x03ff_ffff) | imm26,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn patch_page21(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    place: u64,
    target: u64,
) -> Result<(), RelocError> {
    let delta = page(target.wrapping_add_signed(reloc.addend)).wrapping_sub(page(place)) as i64;
    let imm = delta >> 12;
    if !fits_signed(imm, 21) {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("page delta is out of PAGE21 range ({delta:#x})"),
        ));
    }
    let insn = read_u32(
        bytes,
        local_offset,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )?;
    let encoded = (imm as u32) & 0x1f_ffff;
    let immlo = encoded & 0x3;
    let immhi = (encoded >> 2) & 0x7ffff;
    let patched = (insn & !((0x3 << 29) | (0x7ffff << 5))) | (immlo << 29) | (immhi << 5);
    write_u32(
        bytes,
        local_offset,
        patched,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn patch_pageoff12(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    target: u64,
) -> Result<(), RelocError> {
    let pageoff = target.wrapping_add_signed(reloc.addend) & 0xfff;
    let insn = read_u32(
        bytes,
        local_offset,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )?;
    let imm = if is_add_immediate(insn) {
        pageoff
    } else {
        let shift = pageoff_load_store_shift(insn);
        let scale = 1u64 << shift;
        if !pageoff.is_multiple_of(scale) {
            return Err(reloc_error(
                atom,
                &obj.path,
                local_offset,
                reloc.kind,
                &describe_referent(obj, reloc.referent),
                format!("page offset 0x{pageoff:x} is not aligned for scaled load/store"),
            ));
        }
        pageoff >> shift
    };
    if imm > 0xfff {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("pageoff immediate 0x{imm:x} exceeds 12 bits"),
        ));
    }
    let patched = (insn & !(0xfff << 10)) | ((imm as u32) << 10);
    write_u32(
        bytes,
        local_offset,
        patched,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn pageoff_load_store_shift(insn: u32) -> u64 {
    if is_simd_fp_pageoff(insn) {
        simd_fp_pageoff_shift(insn)
    } else {
        ((insn >> 30) & 0b11) as u64
    }
}

fn is_simd_fp_pageoff(insn: u32) -> bool {
    ((insn >> 24) & 0b111) == 0b101
}

fn simd_fp_pageoff_shift(insn: u32) -> u64 {
    let size = ((insn >> 30) & 0b11) as u64;
    let opc = ((insn >> 22) & 0b11) as u64;
    if size == 0 && (opc & 0b10) != 0 {
        4
    } else {
        size
    }
}

fn read_implicit_addend(
    bytes: &[u8],
    local_offset: u32,
    length: RelocLength,
    atom: &Atom,
    obj: &ObjectFile,
    kind: RelocKind,
    referent: Referent,
) -> Result<i64, RelocError> {
    match length {
        RelocLength::Word => Ok(read_u32(
            bytes,
            local_offset,
            atom,
            obj,
            kind,
            &describe_referent(obj, referent),
        )? as i32 as i64),
        RelocLength::Quad => Ok(read_u64(
            bytes,
            local_offset,
            atom,
            obj,
            kind,
            &describe_referent(obj, referent),
        )? as i64),
        other => Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            kind,
            &describe_referent(obj, referent),
            format!("unsupported implicit addend width {:?}", other),
        )),
    }
}

fn patch_tlvp_pageoff12(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    target: u64,
) -> Result<(), RelocError> {
    let pageoff = target.wrapping_add_signed(reloc.addend) & 0xfff;
    if pageoff > 0xfff {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("pageoff immediate 0x{pageoff:x} exceeds 12 bits"),
        ));
    }

    let insn = read_u32(
        bytes,
        local_offset,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )?;
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let patched = 0x9100_0000 | ((pageoff as u32) << 10) | (rn << 5) | rd;
    write_u32(
        bytes,
        local_offset,
        patched,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn patch_got_pageoff12_relaxed(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    target: u64,
) -> Result<(), RelocError> {
    let pageoff = target.wrapping_add_signed(reloc.addend) & 0xfff;
    if pageoff > 0xfff {
        return Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            format!("pageoff immediate 0x{pageoff:x} exceeds 12 bits"),
        ));
    }

    let insn = read_u32(
        bytes,
        local_offset,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )?;
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let patched = 0x9100_0000 | ((pageoff as u32) << 10) | (rn << 5) | rd;
    write_u32(
        bytes,
        local_offset,
        patched,
        atom,
        obj,
        reloc.kind,
        &describe_referent(obj, reloc.referent),
    )
}

fn synthesize_thread_variable_section(
    layout: &mut Layout,
    plan: &SyntheticPlan,
    atoms: &AtomTable,
    input_map: &HashMap<InputId, &ObjectFile>,
    reloc_cache: &HashMap<(InputId, u8), Vec<Reloc>>,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let Some(_bootstrap_symbol) = plan.tlv_bootstrap_symbol else {
        return Ok(());
    };
    let Some(template_base) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA" && section.name == "__thread_data")
        .map(|section| section.addr)
        .or_else(|| {
            layout
                .sections
                .iter()
                .find(|section| section.segment == "__DATA" && section.name == "__thread_bss")
                .map(|section| section.addr)
        })
    else {
        return Ok(());
    };
    let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__DATA" && section.name == "__thread_vars")
    else {
        return Ok(());
    };

    for placed in &mut section.atoms {
        let atom = atoms.get(placed.atom);
        let obj = input_map.get(&atom.origin).ok_or_else(|| RelocError {
            input: PathBuf::from("<missing object>"),
            atom: placed.atom,
            atom_offset: 0,
            kind: RelocKind::Unsigned,
            referent: "__thread_vars".to_string(),
            detail: "missing parsed object for TLV descriptor atom".to_string(),
        })?;
        let relocs = reloc_cache
            .get(&(atom.origin, atom.input_section))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if placed.size % THREAD_VARIABLE_DESCRIPTOR_SIZE as u64 != 0 {
            return Err(RelocError {
                input: PathBuf::from("<synthetic tlv>"),
                atom: placed.atom,
                atom_offset: 0,
                kind: RelocKind::Unsigned,
                referent: "__thread_vars".to_string(),
                detail: format!(
                    "TLV descriptor atom has unexpected size 0x{:x}",
                    placed.size
                ),
            });
        }

        for descriptor_offset in
            (0..placed.size as usize).step_by(THREAD_VARIABLE_DESCRIPTOR_SIZE as usize)
        {
            let descriptor_offset_u32 = descriptor_offset as u32;
            let start = descriptor_offset;
            let end = start + THREAD_VARIABLE_DESCRIPTOR_SIZE as usize;
            let descriptor = placed.data.get_mut(start..end).ok_or_else(|| RelocError {
                input: PathBuf::from("<synthetic tlv>"),
                atom: placed.atom,
                atom_offset: descriptor_offset as u32,
                kind: RelocKind::Unsigned,
                referent: "__thread_vars".to_string(),
                detail: "TLV descriptor lands outside atom bytes".to_string(),
            })?;

            descriptor[0..8].fill(0);
            let init_addr = resolve_tlv_init_address(
                descriptor,
                atom,
                obj,
                relocs,
                descriptor_offset_u32,
                input_map,
                resolve,
            )?;
            if init_addr < template_base {
                return Err(RelocError {
                    input: PathBuf::from("<synthetic tlv>"),
                    atom: placed.atom,
                    atom_offset: descriptor_offset as u32 + 16,
                    kind: RelocKind::Unsigned,
                    referent: "__thread_vars".to_string(),
                    detail: format!(
                        "TLV init address 0x{init_addr:x} lands before TLS template base 0x{template_base:x}"
                    ),
                });
            }
            let init_offset = init_addr - template_base;
            descriptor[16..24].copy_from_slice(&init_offset.to_le_bytes());
        }
    }

    Ok(())
}

fn resolve_tlv_init_address(
    descriptor: &[u8],
    atom: &Atom,
    obj: &ObjectFile,
    relocs: &[Reloc],
    descriptor_offset: u32,
    input_map: &HashMap<InputId, &ObjectFile>,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    for owner in descriptor_owner_symbols(obj, atom, descriptor_offset) {
        if let Some(init_addr) = resolve_named_tlv_init(owner, atom, input_map, resolve)? {
            return Ok(init_addr);
        }
    }

    let field_offset = atom.input_offset + descriptor_offset + 16;
    if let Some(reloc) = relocs_for_atom(relocs, atom).find(|reloc| reloc.offset == field_offset) {
        let target = resolve_tlv_descriptor_referent(obj, atom, reloc, resolve)?;
        return Ok(target.wrapping_add_signed(reloc.addend));
    }

    Ok(u64::from_le_bytes(
        descriptor[16..24]
            .try_into()
            .expect("8-byte descriptor tail"),
    ))
}

fn descriptor_owner_symbols<'a>(
    obj: &'a ObjectFile,
    atom: &'a Atom,
    descriptor_offset: u32,
) -> impl Iterator<Item = &'a InputSymbol> + 'a {
    let descriptor_start = atom.input_offset as u64 + descriptor_offset as u64;
    obj.symbols.iter().filter(move |input_sym| {
        input_sym.kind() == SymKind::Sect
            && input_sym.sect_idx() == atom.input_section
            && obj.section_for_symbol(input_sym).is_some_and(|section| {
                input_sym.value().saturating_sub(section.addr) == descriptor_start
            })
    })
}

fn matching_tlv_init_symbol<'a>(
    obj: &'a ObjectFile,
    owner: &InputSymbol,
) -> Result<Option<&'a InputSymbol>, RelocError> {
    let owner_name = match obj.symbol_name(owner) {
        Ok(name) => name,
        Err(_) => return Ok(None),
    };
    let init_name = format!("{owner_name}$tlv$init");
    Ok(obj.symbols.iter().find(|input_sym| {
        obj.symbol_name(input_sym)
            .is_ok_and(|name| name == init_name)
    }))
}

fn resolve_named_tlv_init(
    owner: &InputSymbol,
    atom: &Atom,
    input_map: &HashMap<InputId, &ObjectFile>,
    resolve: &ResolveView<'_>,
) -> Result<Option<u64>, RelocError> {
    for (&origin, obj) in input_map {
        let Some(init_symbol) = matching_tlv_init_symbol(obj, owner)? else {
            continue;
        };
        return Ok(Some(resolve_input_symbol_at_origin(
            origin,
            obj,
            atom,
            RelocKind::Unsigned,
            init_symbol,
            resolve,
        )?));
    }
    Ok(None)
}

fn resolve_tlv_descriptor_referent(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match reloc.referent {
        Referent::Section(section_idx) => resolve
            .section_addrs
            .get(&(atom.origin, section_idx))
            .copied()
            .ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    reloc.offset.saturating_sub(atom.input_offset),
                    reloc.kind,
                    &format!("section #{section_idx}"),
                    "TLV descriptor referent section was not laid out".to_string(),
                )
            }),
        Referent::Symbol(sym_idx) => {
            let input_sym = obj.symbols.get(sym_idx as usize).ok_or_else(|| {
                reloc_error(
                    atom,
                    &obj.path,
                    reloc.offset.saturating_sub(atom.input_offset),
                    reloc.kind,
                    &format!("symbol #{sym_idx}"),
                    "TLV descriptor symbol index is out of range".to_string(),
                )
            })?;
            resolve_input_symbol_at_origin(atom.origin, obj, atom, reloc.kind, input_sym, resolve)
        }
    }
}

fn synthesize_got_section(
    layout: &mut Layout,
    plan: &SyntheticPlan,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__DATA_CONST" && section.name == "__got")
    else {
        return Ok(());
    };

    for (idx, entry) in plan.got.entries.iter().enumerate() {
        let start = idx * 8;
        let end = start + 8;
        let value = match resolve.sym_table.get(entry.symbol) {
            Symbol::DylibImport { .. } => 0,
            Symbol::Defined {
                atom: target_atom,
                value,
                ..
            } => {
                resolve
                    .atom_addrs
                    .get(target_atom)
                    .copied()
                    .ok_or_else(|| RelocError {
                        input: PathBuf::from("<synthetic got>"),
                        atom: crate::resolve::AtomId(0),
                        atom_offset: start as u32,
                        kind: RelocKind::PointerToGot,
                        referent: format!("symbol {:?}", entry.symbol),
                        detail: "defined GOT target is missing final address".to_string(),
                    })?
                    + *value
            }
            other => {
                return Err(RelocError {
                    input: PathBuf::from("<synthetic got>"),
                    atom: crate::resolve::AtomId(0),
                    atom_offset: start as u32,
                    kind: RelocKind::PointerToGot,
                    referent: format!("symbol {:?}", entry.symbol),
                    detail: format!(
                        "synthetic GOT currently does not support symbol kind {:?}",
                        other.kind()
                    ),
                });
            }
        };
        section.synthetic_data[start..end].copy_from_slice(&value.to_le_bytes());
    }

    Ok(())
}

fn synthesize_stub_section(
    layout: &mut Layout,
    plan: &SyntheticPlan,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__TEXT" && section.name == "__stubs")
    else {
        return Ok(());
    };

    for (idx, entry) in plan.stubs.entries.iter().enumerate() {
        let start = idx * STUB_SIZE as usize;
        let end = start + STUB_SIZE as usize;
        let stub_addr = section.addr + (idx as u64) * STUB_SIZE as u64;
        let lazy_addr = resolve
            .lazy_pointer_addrs
            .get(&entry.symbol)
            .copied()
            .ok_or_else(|| RelocError {
                input: PathBuf::from("<synthetic stubs>"),
                atom: crate::resolve::AtomId(0),
                atom_offset: start as u32,
                kind: RelocKind::Branch26,
                referent: format!("symbol {:?}", entry.symbol),
                detail: "synthetic stub is missing lazy pointer target".to_string(),
            })?;
        let bytes = encode_stub(stub_addr, lazy_addr)?;
        section.synthetic_data[start..end].copy_from_slice(&bytes);
    }

    Ok(())
}

fn synthesize_lazy_pointer_section(
    layout: &mut Layout,
    plan: &SyntheticPlan,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__DATA" && section.name == "__la_symbol_ptr")
    else {
        return Ok(());
    };

    for (idx, entry) in plan.lazy_pointers.entries.iter().enumerate() {
        let start = idx * 8;
        let end = start + 8;
        let helper_addr = resolve
            .stub_helper_entry_addrs
            .get(&entry.symbol)
            .copied()
            .ok_or_else(|| RelocError {
                input: PathBuf::from("<synthetic lazy pointers>"),
                atom: crate::resolve::AtomId(0),
                atom_offset: start as u32,
                kind: RelocKind::Unsigned,
                referent: format!("symbol {:?}", entry.symbol),
                detail: "lazy pointer is missing stub helper target".to_string(),
            })?;
        section.synthetic_data[start..end].copy_from_slice(&helper_addr.to_le_bytes());
    }

    Ok(())
}

fn synthesize_stub_helper_section(
    layout: &mut Layout,
    plan: &SyntheticPlan,
    resolve: &ResolveView<'_>,
    linkedit: &LinkEditPlan,
) -> Result<(), RelocError> {
    let Some(binder_symbol) = plan.binder_symbol else {
        return Ok(());
    };
    let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__TEXT" && section.name == "__stub_helper")
    else {
        return Ok(());
    };

    let header_addr = resolve.stub_helper_header_addr.ok_or_else(|| RelocError {
        input: PathBuf::from("<synthetic stub helper>"),
        atom: crate::resolve::AtomId(0),
        atom_offset: 0,
        kind: RelocKind::Branch26,
        referent: "__stub_helper".to_string(),
        detail: "stub helper section missing final address".to_string(),
    })?;
    let dyld_private_addr = resolve.dyld_private_addr.ok_or_else(|| RelocError {
        input: PathBuf::from("<synthetic stub helper>"),
        atom: crate::resolve::AtomId(0),
        atom_offset: 0,
        kind: RelocKind::Unsigned,
        referent: "__dyld_private".to_string(),
        detail: "dyld-private slot missing final address".to_string(),
    })?;
    let binder_got_addr = resolve
        .got_addrs
        .get(&binder_symbol)
        .copied()
        .ok_or_else(|| RelocError {
            input: PathBuf::from("<synthetic stub helper>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 0,
            kind: RelocKind::GotLoadPage21,
            referent: "dyld_stub_binder".to_string(),
            detail: "binder GOT slot missing final address".to_string(),
        })?;

    let header = encode_stub_helper_header(header_addr, dyld_private_addr, binder_got_addr)?;
    section.synthetic_data[..STUB_HELPER_HEADER_SIZE as usize].copy_from_slice(&header);

    for (idx, entry) in plan.lazy_pointers.entries.iter().enumerate() {
        let start = STUB_HELPER_HEADER_SIZE as usize + idx * STUB_HELPER_ENTRY_SIZE as usize;
        let end = start + STUB_HELPER_ENTRY_SIZE as usize;
        let entry_addr = resolve
            .stub_helper_entry_addrs
            .get(&entry.symbol)
            .copied()
            .ok_or_else(|| RelocError {
                input: PathBuf::from("<synthetic stub helper>"),
                atom: crate::resolve::AtomId(0),
                atom_offset: start as u32,
                kind: RelocKind::Branch26,
                referent: format!("symbol {:?}", entry.symbol),
                detail: "stub helper entry missing final address".to_string(),
            })?;
        let lazy_bind_offset =
            linkedit
                .lazy_bind_offset(entry.symbol)
                .ok_or_else(|| RelocError {
                    input: PathBuf::from("<synthetic stub helper>"),
                    atom: crate::resolve::AtomId(0),
                    atom_offset: start as u32,
                    kind: RelocKind::Unsigned,
                    referent: format!("symbol {:?}", entry.symbol),
                    detail: "lazy bind offset missing for stub helper entry".to_string(),
                })?;
        let bytes = encode_stub_helper_entry(entry_addr, header_addr, lazy_bind_offset)?;
        section.synthetic_data[start..end].copy_from_slice(&bytes);
    }

    Ok(())
}

fn encode_stub(
    stub_addr: u64,
    lazy_pointer_addr: u64,
) -> Result<[u8; STUB_SIZE as usize], RelocError> {
    let adrp = encode_adrp_reg(16, stub_addr, lazy_pointer_addr, "lazy pointer")?;
    let ldr = encode_ldr_x_reg_pageoff(16, lazy_pointer_addr, "lazy pointer")?;
    let br = 0xd61f0200u32;

    let mut out = [0u8; STUB_SIZE as usize];
    out[0..4].copy_from_slice(&adrp.to_le_bytes());
    out[4..8].copy_from_slice(&ldr.to_le_bytes());
    out[8..12].copy_from_slice(&br.to_le_bytes());
    Ok(out)
}

fn encode_stub_helper_header(
    header_addr: u64,
    dyld_private_addr: u64,
    binder_got_addr: u64,
) -> Result<[u8; STUB_HELPER_HEADER_SIZE as usize], RelocError> {
    let mut out = [0u8; STUB_HELPER_HEADER_SIZE as usize];
    let words = [
        encode_adrp_reg(17, header_addr, dyld_private_addr, "__dyld_private")?,
        encode_add_x_reg_pageoff(17, dyld_private_addr, "__dyld_private")?,
        encode_stp_x16_x17_sp_preindex(),
        encode_adrp_reg(
            16,
            header_addr + 12,
            binder_got_addr,
            "dyld_stub_binder@GOT",
        )?,
        encode_ldr_x_reg_pageoff(16, binder_got_addr, "dyld_stub_binder@GOT")?,
        0xd61f0200u32,
    ];
    for (idx, word) in words.iter().enumerate() {
        let start = idx * 4;
        out[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

fn encode_stub_helper_entry(
    entry_addr: u64,
    header_addr: u64,
    lazy_bind_offset: u32,
) -> Result<[u8; STUB_HELPER_ENTRY_SIZE as usize], RelocError> {
    let mut out = [0u8; STUB_HELPER_ENTRY_SIZE as usize];
    let ldr = encode_ldr_w16_literal_plus8();
    let branch = encode_branch26(entry_addr + 4, header_addr, "__stub_helper header")?;
    out[0..4].copy_from_slice(&ldr.to_le_bytes());
    out[4..8].copy_from_slice(&branch.to_le_bytes());
    out[8..12].copy_from_slice(&lazy_bind_offset.to_le_bytes());
    Ok(out)
}

fn encode_adrp_reg(reg: u8, place: u64, target: u64, referent: &str) -> Result<u32, RelocError> {
    let delta = page(target).wrapping_sub(page(place)) as i64;
    let imm = delta >> 12;
    if !fits_signed(imm, 21) {
        return Err(RelocError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 0,
            kind: RelocKind::Page21,
            referent: format!("{referent} @ {target:#x}"),
            detail: format!("page delta is out of PAGE21 range ({delta:#x})"),
        });
    }

    let encoded = (imm as u32) & 0x1f_ffff;
    let immlo = encoded & 0x3;
    let immhi = (encoded >> 2) & 0x7ffff;
    Ok(0x9000_0000 | (immlo << 29) | (immhi << 5) | reg as u32)
}

fn encode_ldr_x_reg_pageoff(reg: u8, target: u64, referent: &str) -> Result<u32, RelocError> {
    let low = target & 0xfff;
    if low & 0b111 != 0 {
        return Err(RelocError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 4,
            kind: RelocKind::PageOff12,
            referent: format!("{referent} @ {target:#x}"),
            detail: format!("lazy pointer page offset {low:#x} is not 8-byte aligned"),
        });
    }
    let imm12 = ((low >> 3) as u32) & 0xfff;
    Ok(0xf940_0000 | (imm12 << 10) | ((reg as u32) << 5) | reg as u32)
}

fn encode_add_x_reg_pageoff(reg: u8, target: u64, referent: &str) -> Result<u32, RelocError> {
    let low = target & 0xfff;
    if low > 0xfff {
        return Err(RelocError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 4,
            kind: RelocKind::PageOff12,
            referent: format!("{referent} @ {target:#x}"),
            detail: format!("pageoff immediate 0x{low:x} exceeds 12 bits"),
        });
    }
    Ok(0x9100_0000 | ((low as u32) << 10) | ((reg as u32) << 5) | reg as u32)
}

fn encode_stp_x16_x17_sp_preindex() -> u32 {
    let imm7 = ((-2i8 as u8) & 0x7f) as u32;
    0xa980_0000 | (imm7 << 15) | (17 << 10) | (31 << 5) | 16
}

fn encode_ldr_w16_literal_plus8() -> u32 {
    0x1800_0050
}

fn encode_branch26(place: u64, target: u64, referent: &str) -> Result<u32, RelocError> {
    let delta = target.wrapping_sub(place) as i64;
    if delta & 0b11 != 0 {
        return Err(RelocError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 0,
            kind: RelocKind::Branch26,
            referent: referent.to_string(),
            detail: format!("branch target delta 0x{delta:x} is not 4-byte aligned"),
        });
    }
    let imm = delta >> 2;
    if !fits_signed(imm, 26) {
        return Err(RelocError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            atom_offset: 0,
            kind: RelocKind::Branch26,
            referent: referent.to_string(),
            detail: format!("branch target is out of BRANCH26 range (delta {delta:#x})"),
        });
    }
    Ok(0x1400_0000 | ((imm as u32) & 0x03ff_ffff))
}

fn read_u32(
    bytes: &[u8],
    offset: u32,
    atom: &Atom,
    obj: &ObjectFile,
    kind: RelocKind,
    referent: &str,
) -> Result<u32, RelocError> {
    let start = offset as usize;
    let end = start + 4;
    let slice = bytes.get(start..end).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            offset,
            kind,
            referent,
            "relocation write would run past the atom bytes".to_string(),
        )
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u32,
    atom: &Atom,
    obj: &ObjectFile,
    kind: RelocKind,
    referent: &str,
) -> Result<u64, RelocError> {
    let start = offset as usize;
    let end = start + 8;
    let slice = bytes.get(start..end).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            offset,
            kind,
            referent,
            "relocation write would run past the atom bytes".to_string(),
        )
    })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn write_u32(
    bytes: &mut [u8],
    offset: u32,
    value: u32,
    atom: &Atom,
    obj: &ObjectFile,
    kind: RelocKind,
    referent: &str,
) -> Result<(), RelocError> {
    let start = offset as usize;
    let end = start + 4;
    let slice = bytes.get_mut(start..end).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            offset,
            kind,
            referent,
            "relocation write would run past the atom bytes".to_string(),
        )
    })?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(
    bytes: &mut [u8],
    offset: u32,
    value: u64,
    atom: &Atom,
    obj: &ObjectFile,
    kind: RelocKind,
    referent: &str,
) -> Result<(), RelocError> {
    let start = offset as usize;
    let end = start + 8;
    let slice = bytes.get_mut(start..end).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            offset,
            kind,
            referent,
            "relocation write would run past the atom bytes".to_string(),
        )
    })?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn is_add_immediate(insn: u32) -> bool {
    (insn & 0x1f00_0000) == 0x1100_0000
}

fn page(value: u64) -> u64 {
    value & !0xfff
}

fn fits_signed(value: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    value >= min && value <= max
}

fn describe_referent(obj: &ObjectFile, referent: Referent) -> String {
    match referent {
        Referent::Section(idx) => format!("section #{idx}"),
        Referent::Symbol(sym_idx) => obj
            .symbols
            .get(sym_idx as usize)
            .map(|sym| describe_input_symbol(obj, sym))
            .unwrap_or_else(|| format!("symbol #{sym_idx}")),
    }
}

fn describe_input_symbol(obj: &ObjectFile, input_sym: &InputSymbol) -> String {
    obj.symbol_name(input_sym)
        .map(str::to_string)
        .unwrap_or_else(|_| format!("symbol@strx{}", input_sym.strx()))
}

fn reloc_error(
    atom: &Atom,
    path: &std::path::Path,
    atom_offset: u32,
    kind: RelocKind,
    referent: &str,
    detail: String,
) -> RelocError {
    RelocError {
        input: path.to_path_buf(),
        atom: atom.id,
        atom_offset,
        kind,
        referent: referent.to_string(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::atom::{AtomFlags, AtomSection};
    use crate::input::ObjectFile;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_MAGIC_64, MH_OBJECT, N_EXT, N_SECT,
        S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_REGULAR,
    };
    use crate::macho::reader::MachHeader64;
    use crate::reloc::{write_raw_relocs, write_relocs};
    use crate::resolve::{InsertOutcome, Symbol, SymbolTable};
    use crate::section::InputSection;
    use crate::string_table::StringTable;
    use crate::symbol::{InputSymbol, RawNlist};
    use crate::OutputKind;

    #[test]
    fn branch26_patches_low_bits() {
        let insn = 0x9400_0000u32;
        let delta = 0x40i64;
        let imm = ((delta >> 2) as u32) & 0x03ff_ffff;
        let patched = (insn & !0x03ff_ffff) | imm;
        assert_eq!(patched, 0x9400_0010);
    }

    #[test]
    fn page21_encodes_immhi_and_immlo() {
        let insn = 0x9000_0000u32;
        let imm = 0x12345u32;
        let immlo = imm & 0x3;
        let immhi = (imm >> 2) & 0x7ffff;
        let patched = (insn & !((0x3 << 29) | (0x7ffff << 5))) | (immlo << 29) | (immhi << 5);
        assert_eq!(patched & (0x3 << 29), immlo << 29);
        assert_eq!(patched & (0x7ffff << 5), immhi << 5);
    }

    #[test]
    fn add_immediate_pageoff_is_unscaled() {
        let insn = 0x9100_0000u32;
        assert!(is_add_immediate(insn));
        let patched = (insn & !(0xfff << 10)) | (0xabc << 10);
        assert_eq!((patched >> 10) & 0xfff, 0xabc);
    }

    #[test]
    fn load_store_pageoff_uses_size_scaling() {
        let insn = 0xf940_0000u32;
        assert!(!is_add_immediate(insn));
        let shift = pageoff_load_store_shift(insn);
        assert_eq!(shift, 0b11);
        let pageoff = 0x3f8u64;
        let imm = pageoff >> shift;
        let patched = (insn & !(0xfff << 10)) | ((imm as u32) << 10);
        assert_eq!((patched >> 10) & 0xfff, 0x7f);
    }

    #[test]
    fn simd_q_pageoff_uses_16_byte_scaling() {
        let insn = 0x3dc0_0100u32;
        assert!(!is_add_immediate(insn));
        assert!(is_simd_fp_pageoff(insn));
        let shift = pageoff_load_store_shift(insn);
        assert_eq!(shift, 4);
        let pageoff = 0x690u64;
        let imm = pageoff >> shift;
        let patched = (insn & !(0xfff << 10)) | ((imm as u32) << 10);
        assert_eq!((patched >> 10) & 0xfff, 0x69);
        assert_eq!(patched, 0x3dc1_a500);
    }

    #[test]
    fn signed_fit_helper_matches_branch_range() {
        assert!(fits_signed((1 << 25) - 1, 26));
        assert!(fits_signed(-(1 << 25), 26));
        assert!(!fits_signed(1 << 25, 26));
        assert!(!fits_signed(-(1 << 25) - 1, 26));
    }

    #[test]
    fn branch26_span_fast_path_rejects_only_large_non_linkedit_images() {
        let small = Layout {
            kind: OutputKind::Executable,
            segments: Vec::new(),
            sections: vec![
                output_section("__TEXT", "__text", 0x1_0000_0000, 0x100),
                output_section("__DATA", "__data", 0x1_0001_0000, 0x100),
                output_section("__LINKEDIT", "__linkedit", 0x1_8000_0000, 0x1000),
            ],
        };
        assert!(layout_fits_branch26_span(&small));

        let large = Layout {
            kind: OutputKind::Executable,
            segments: Vec::new(),
            sections: vec![
                output_section("__TEXT", "__text", 0x1_0000_0000, 0x100),
                output_section(
                    "__DATA",
                    "__data",
                    0x1_0000_0000 + BRANCH26_MAX_FORWARD_DELTA_BYTES + 1,
                    0x100,
                ),
            ],
        };
        assert!(!layout_fits_branch26_span(&large));
    }

    #[test]
    fn thunk_plan_splits_monolithic_text_section_into_multiple_islands() {
        let gap = 0x0900_0000u32;
        let caller2_offset = 4 + gap;
        let target_offset = 8 + gap * 2;
        let raw_relocs = branch26_raw_relocs(&[0, caller2_offset]);
        let object = thunk_test_object(raw_relocs, target_offset as u64, target_offset as u64 + 4);

        let mut atoms = AtomTable::new();
        let caller1 = atoms.push(test_atom(0, 4));
        atoms.push(test_atom(4, gap));
        let caller2 = atoms.push(test_atom(caller2_offset, 4));
        atoms.push(test_atom(caller2_offset + 4, gap));
        let target = atoms.push(test_atom(target_offset, 4));

        let mut sym_table = SymbolTable::new();
        let target_name = sym_table.intern("_target");
        let insert = sym_table
            .insert(Symbol::Defined {
                name: target_name,
                origin: crate::resolve::InputId(0),
                atom: target,
                value: 0,
                weak: false,
                private_extern: false,
                no_dead_strip: false,
            })
            .unwrap();
        assert!(matches!(insert, InsertOutcome::Inserted(_)));

        let inputs = [LayoutInput {
            id: crate::resolve::InputId(0),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let opts = LinkOptions {
            kind: OutputKind::Executable,
            ..LinkOptions::default()
        };
        let base_layout = Layout::build(OutputKind::Executable, &inputs, &atoms, 0);
        let parsed_relocs = crate::macho::writer::build_parsed_reloc_cache(&inputs).unwrap();
        let plan = plan_thunks(
            &opts,
            ThunkPlanningContext {
                layout: &base_layout,
                inputs: &inputs,
                atoms: &atoms,
                sym_table: &sym_table,
                synthetic_plan: None,
                icf_redirects: None,
                parsed_relocs: &parsed_relocs,
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            plan.redirect_for(caller1, 0),
            Some(0),
            "expected first caller to use its own thunk"
        );
        assert_eq!(
            plan.redirect_for(caller2, 0),
            Some(1),
            "expected second caller to use its own thunk"
        );

        let rebuilt = Layout::build_with_synthetics_and_extra_filtered(
            OutputKind::Executable,
            &inputs,
            &atoms,
            0,
            None,
            None,
            crate::layout::ExtraLayoutSections {
                extra_sections: &plan.output_sections(),
                split_after_atoms: &plan.split_after_atoms(),
            },
        );
        let text_section_count = rebuilt
            .sections
            .iter()
            .filter(|section| section.segment == "__TEXT" && section.name == "__text")
            .count();
        let thunk_section_count = rebuilt
            .sections
            .iter()
            .filter(|section| section.segment == "__TEXT" && section.name == "__thunks")
            .count();
        assert_eq!(
            text_section_count, 3,
            "expected the monolithic text section to split around the two caller atoms"
        );
        assert_eq!(
            thunk_section_count, 2,
            "expected one thunk island per far caller atom"
        );
        let text_sequence: Vec<_> = rebuilt
            .sections
            .iter()
            .filter(|section| section.segment == "__TEXT")
            .map(|section| section.name.as_str())
            .collect();
        assert_eq!(
            text_sequence,
            vec!["__text", "__thunks", "__text", "__thunks", "__text"]
        );

        let replan = plan_thunks(
            &opts,
            ThunkPlanningContext {
                layout: &rebuilt,
                inputs: &inputs,
                atoms: &atoms,
                sym_table: &sym_table,
                synthetic_plan: None,
                icf_redirects: None,
                parsed_relocs: &parsed_relocs,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            replan, plan,
            "expected thunk planning to converge once the intra-section islands exist"
        );
    }

    fn branch26_raw_relocs(offsets: &[u32]) -> Vec<u8> {
        let relocs: Vec<_> = offsets
            .iter()
            .copied()
            .map(|offset| crate::reloc::Reloc {
                offset,
                kind: RelocKind::Branch26,
                length: RelocLength::Word,
                pcrel: true,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            })
            .collect();
        let raws = write_relocs(&relocs).unwrap();
        let mut out = Vec::new();
        write_raw_relocs(&raws, &mut out);
        out
    }

    fn output_section(segment: &str, name: &str, addr: u64, size: u64) -> OutputSection {
        OutputSection {
            segment: segment.into(),
            name: name.into(),
            kind: SectionKind::Text,
            align_pow2: 2,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            atoms: Vec::new(),
            synthetic_offset: 0,
            synthetic_data: Vec::new(),
            addr,
            size,
            file_off: 0,
        }
    }

    fn thunk_test_object(raw_relocs: Vec<u8>, target_offset: u64, section_size: u64) -> ObjectFile {
        let strings = b"\0_target\0".to_vec();
        ObjectFile {
            path: PathBuf::from("/tmp/thunk-plan.o"),
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
            sections: vec![InputSection {
                segname: "__TEXT".into(),
                sectname: "__text".into(),
                kind: crate::section::SectionKind::Text,
                addr: 0,
                size: section_size,
                align_pow2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                offset: 0,
                reloff: 0,
                nreloc: (raw_relocs.len() / 8) as u32,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                data: Vec::new(),
                raw_relocs,
            }],
            symbols: vec![InputSymbol::from_raw(RawNlist {
                strx: 1,
                n_type: N_SECT | N_EXT,
                n_sect: 1,
                n_desc: 0,
                n_value: target_offset,
            })],
            strings: StringTable::from_bytes(strings),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        }
    }

    fn test_atom(input_offset: u32, size: u32) -> Atom {
        Atom {
            id: crate::resolve::AtomId(0),
            origin: crate::resolve::InputId(0),
            input_section: 1,
            section: AtomSection::Text,
            input_offset,
            size,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: Vec::new(),
            flags: AtomFlags::NONE,
            parent_of: None,
        }
    }
}
