use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::atom::{Atom, AtomTable};
use crate::input::ObjectFile;
use crate::layout::{Layout, LayoutInput};
use crate::macho::writer::LinkEditPlan;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind, RelocLength};
use crate::resolve::{InputId, Symbol, SymbolId, SymbolTable};
use crate::synth::stubs::{STUB_HELPER_ENTRY_SIZE, STUB_HELPER_HEADER_SIZE, STUB_SIZE};
use crate::synth::SyntheticPlan;
use crate::symbol::{InputSymbol, SymKind};

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
    atom_addrs: &'a HashMap<crate::resolve::AtomId, u64>,
    section_addrs: &'a HashMap<(InputId, u8), u64>,
    stub_addrs: &'a HashMap<SymbolId, u64>,
    got_addrs: &'a HashMap<SymbolId, u64>,
    lazy_pointer_addrs: &'a HashMap<SymbolId, u64>,
    stub_helper_entry_addrs: &'a HashMap<SymbolId, u64>,
    stub_helper_header_addr: Option<u64>,
    dyld_private_addr: Option<u64>,
}

struct SyntheticAddressMaps {
    stub_addrs: HashMap<SymbolId, u64>,
    got_addrs: HashMap<SymbolId, u64>,
    lazy_pointer_addrs: HashMap<SymbolId, u64>,
    stub_helper_entry_addrs: HashMap<SymbolId, u64>,
    stub_helper_header_addr: Option<u64>,
    dyld_private_addr: Option<u64>,
}

pub fn apply_layout(
    layout: &mut Layout,
    inputs: &[LayoutInput<'_>],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
    synthetic_plan: Option<&SyntheticPlan>,
    linkedit: &LinkEditPlan,
) -> Result<(), RelocError> {
    let input_map: HashMap<InputId, &ObjectFile> =
        inputs.iter().map(|input| (input.id, input.object)).collect();
    let mut reloc_cache: HashMap<(InputId, u8), Vec<Reloc>> = HashMap::new();
    for input in inputs {
        for (sect_idx, section) in input.object.sections.iter().enumerate() {
            let relocs = if section.nreloc == 0 {
                Vec::new()
            } else {
                let raws =
                    parse_raw_relocs(&section.raw_relocs, 0, section.nreloc).map_err(|err| {
                        RelocError {
                            input: input.object.path.clone(),
                            atom: crate::resolve::AtomId(0),
                            atom_offset: 0,
                            kind: RelocKind::Unsigned,
                            referent: format!("section {},{}", section.segname, section.sectname),
                            detail: err.to_string(),
                        }
                    })?;
                parse_relocs(&raws).map_err(|err| RelocError {
                    input: input.object.path.clone(),
                    atom: crate::resolve::AtomId(0),
                    atom_offset: 0,
                    kind: RelocKind::Unsigned,
                    referent: format!("section {},{}", section.segname, section.sectname),
                    detail: err.to_string(),
                })?
            };
            reloc_cache.insert((input.id, (sect_idx + 1) as u8), relocs);
        }
    }

    let atom_addrs = atom_address_map(layout);
    let section_addrs = input_section_address_map(layout, atoms);
    let synth_addrs = synthetic_address_maps(layout, synthetic_plan);
    let resolve = ResolveView {
        sym_table,
        atom_addrs: &atom_addrs,
        section_addrs: &section_addrs,
        stub_addrs: &synth_addrs.stub_addrs,
        got_addrs: &synth_addrs.got_addrs,
        lazy_pointer_addrs: &synth_addrs.lazy_pointer_addrs,
        stub_helper_entry_addrs: &synth_addrs.stub_helper_entry_addrs,
        stub_helper_header_addr: synth_addrs.stub_helper_header_addr,
        dyld_private_addr: synth_addrs.dyld_private_addr,
    };

    for out_section in &mut layout.sections {
        for placed in &mut out_section.atoms {
            let atom = atoms.get(placed.atom);
            if atom.size == 0 || placed.data.is_empty() {
                continue;
            }
            let obj = input_map
                .get(&atom.origin)
                .ok_or_else(|| reloc_error(atom, &PathBuf::from("<missing object>"), 0, RelocKind::Unsigned, "object", "missing parsed object".to_string()))?;
            let relocs = reloc_cache
                .get(&(atom.origin, atom.input_section))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for reloc in relocs_for_atom(relocs, atom) {
                apply_one(
                    &mut placed.data,
                    atom,
                    obj,
                    reloc,
                    &resolve,
                )?;
            }
        }
    }

    if let Some(plan) = synthetic_plan {
        synthesize_stub_section(layout, plan, &resolve)?;
        synthesize_lazy_pointer_section(layout, plan, &resolve)?;
        synthesize_stub_helper_section(layout, plan, &resolve, linkedit)?;
    }

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

fn input_section_address_map(
    layout: &Layout,
    atoms: &AtomTable,
) -> HashMap<(InputId, u8), u64> {
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

fn synthetic_address_maps(
    layout: &Layout,
    synthetic_plan: Option<&SyntheticPlan>,
) -> SyntheticAddressMaps {
    let Some(plan) = synthetic_plan else {
        return SyntheticAddressMaps {
            stub_addrs: HashMap::new(),
            got_addrs: HashMap::new(),
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
        lazy_pointer_addrs,
        stub_helper_entry_addrs,
        stub_helper_header_addr,
        dyld_private_addr,
    }
}

fn apply_one(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<(), RelocError> {
    let local_offset = reloc
        .offset
        .checked_sub(atom.input_offset)
        .ok_or_else(|| reloc_error(atom, &obj.path, reloc.offset, reloc.kind, &describe_referent(obj, reloc.referent), "relocation lands before atom start".to_string()))?;
    let place = resolve
        .atom_addrs
        .get(&atom.id)
        .copied()
        .ok_or_else(|| reloc_error(atom, &obj.path, local_offset, reloc.kind, &describe_referent(obj, reloc.referent), "atom missing final address".to_string()))?
        + local_offset as u64;
    match reloc.kind {
        RelocKind::Unsigned => patch_unsigned(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_referent(obj, atom, reloc.referent, resolve)?,
        ),
        RelocKind::Subtractor => patch_subtractor(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_referent(obj, atom, reloc.referent, resolve)?,
            resolve,
        ),
        RelocKind::Branch26 => patch_branch26(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            resolve_branch_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::Page21 => patch_page21(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            resolve_referent(obj, atom, reloc.referent, resolve)?,
        ),
        RelocKind::PageOff12 => patch_pageoff12(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_referent(obj, atom, reloc.referent, resolve)?,
        ),
        RelocKind::GotLoadPage21 => patch_page21(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            place,
            resolve_got_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::GotLoadPageOff12 => patch_pageoff12(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_got_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::PointerToGot => patch_unsigned(
            bytes,
            atom,
            obj,
            local_offset,
            reloc,
            resolve_got_target(obj, atom, reloc, resolve)?,
        ),
        RelocKind::TlvpLoadPage21 | RelocKind::TlvpLoadPageOff12 => Err(reloc_error(
            atom,
            &obj.path,
            local_offset,
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "not yet implemented (planned for Sprint 12/13)".to_string(),
        )),
    }
}

fn resolve_branch_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    if let Some(symbol_id) = dylib_import_symbol_id(obj, reloc.referent, resolve.sym_table) {
        return resolve.stub_addrs.get(&symbol_id).copied().ok_or_else(|| {
            reloc_error(
                atom,
                &obj.path,
                reloc.offset.saturating_sub(atom.input_offset),
                reloc.kind,
                &describe_referent(obj, reloc.referent),
                "dylib import is missing synthetic stub".to_string(),
            )
        });
    }
    resolve_referent(obj, atom, reloc.referent, resolve)
}

fn resolve_got_target(
    obj: &ObjectFile,
    atom: &Atom,
    reloc: Reloc,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    let Some(symbol_id) = dylib_import_symbol_id(obj, reloc.referent, resolve.sym_table) else {
        return Err(reloc_error(
            atom,
            &obj.path,
            reloc.offset.saturating_sub(atom.input_offset),
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "GOT relocations currently require a dylib import target".to_string(),
        ));
    };
    resolve.got_addrs.get(&symbol_id).copied().ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            reloc.offset.saturating_sub(atom.input_offset),
            reloc.kind,
            &describe_referent(obj, reloc.referent),
            "dylib import is missing synthetic GOT slot".to_string(),
        )
    })
}

fn resolve_referent(
    obj: &ObjectFile,
    atom: &Atom,
    referent: Referent,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    match referent {
        Referent::Section(section_idx) => resolve.section_addrs.get(&(atom.origin, section_idx)).copied().ok_or_else(|| {
            reloc_error(
                atom,
                &obj.path,
                0,
                RelocKind::Unsigned,
                &format!("section #{section_idx}"),
                "referenced input section was not laid out".to_string(),
            )
        }),
        Referent::Symbol(sym_idx) => resolve_symbol_referent(
            obj,
            atom,
            sym_idx as usize,
            resolve,
        ),
    }
}

fn resolve_symbol_referent(
    obj: &ObjectFile,
    atom: &Atom,
    sym_idx: usize,
    resolve: &ResolveView<'_>,
) -> Result<u64, RelocError> {
    let input_sym = obj.symbols.get(sym_idx).ok_or_else(|| {
        reloc_error(
            atom,
            &obj.path,
            0,
            RelocKind::Unsigned,
            &format!("symbol #{sym_idx}"),
            "symbol index is out of range".to_string(),
        )
    })?;

    if let Ok(name) = obj.symbol_name(input_sym) {
        if let Some((_, symbol)) = resolve
            .sym_table
            .iter()
            .find(|(_, symbol)| resolve.sym_table.interner.resolve(symbol.name()) == name)
        {
            return resolve_global_symbol(obj, atom, name, symbol, resolve);
        }
    }

    resolve_input_symbol(obj, atom, input_sym, resolve)
}

fn dylib_import_symbol_id(
    obj: &ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
) -> Option<SymbolId> {
    let Referent::Symbol(sym_idx) = referent else {
        return None;
    };
    let input_sym = obj.symbols.get(sym_idx as usize)?;
    let name = obj.symbol_name(input_sym).ok()?;
    let (symbol_id, symbol) = sym_table
        .iter()
        .find(|(_, symbol)| sym_table.interner.resolve(symbol.name()) == name)?;
    matches!(symbol, Symbol::DylibImport { .. }).then_some(symbol_id)
}

fn resolve_global_symbol(
    obj: &ObjectFile,
    atom: &Atom,
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
                    RelocKind::Unsigned,
                    name,
                    "target atom missing final address".to_string(),
                )
            }),
        Symbol::DylibImport { .. } => Ok(0),
        other => Err(reloc_error(
            atom,
            &obj.path,
            0,
            RelocKind::Unsigned,
            name,
            format!("symbol resolved to unsupported state {:?}", other.kind()),
        )),
    }
}

fn resolve_input_symbol(
    obj: &ObjectFile,
    atom: &Atom,
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
                    RelocKind::Unsigned,
                    &describe_input_symbol(obj, input_sym),
                    "section-backed symbol did not resolve to an input section".to_string(),
                )
            })?;
            let section_addr = resolve
                .section_addrs
                .get(&(atom.origin, input_sym.sect_idx()))
                .copied()
                .ok_or_else(|| {
                    reloc_error(
                        atom,
                        &obj.path,
                        0,
                        RelocKind::Unsigned,
                        &describe_input_symbol(obj, input_sym),
                        "section-backed symbol's output section is missing".to_string(),
                    )
                })?;
            Ok(section_addr + input_sym.value().saturating_sub(section.addr))
        }
        SymKind::Undef => Err(reloc_error(
            atom,
            &obj.path,
            0,
            RelocKind::Unsigned,
            &describe_input_symbol(obj, input_sym),
            "symbol remained undefined at relocation time".to_string(),
        )),
        SymKind::Indirect => Err(reloc_error(
            atom,
            &obj.path,
            0,
            RelocKind::Unsigned,
            &describe_input_symbol(obj, input_sym),
            "indirect symbol relocations are not yet implemented".to_string(),
        )),
    }
}

fn patch_unsigned(
    bytes: &mut [u8],
    atom: &Atom,
    obj: &ObjectFile,
    local_offset: u32,
    reloc: Reloc,
    target: u64,
) -> Result<(), RelocError> {
    let value = target.wrapping_add_signed(reloc.addend);
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
    let value = minuend
        .wrapping_sub(subtrahend)
        .wrapping_add_signed(reloc.addend);
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
    let delta = target
        .wrapping_add_signed(reloc.addend)
        .wrapping_sub(place) as i64;
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
    let insn = read_u32(bytes, local_offset, atom, obj, reloc.kind, &describe_referent(obj, reloc.referent))?;
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
    let insn = read_u32(bytes, local_offset, atom, obj, reloc.kind, &describe_referent(obj, reloc.referent))?;
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
    let insn = read_u32(bytes, local_offset, atom, obj, reloc.kind, &describe_referent(obj, reloc.referent))?;
    let imm = if is_add_immediate(insn) {
        pageoff
    } else {
        let shift = ((insn >> 30) & 0b11) as u64;
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
        let start =
            STUB_HELPER_HEADER_SIZE as usize + idx * STUB_HELPER_ENTRY_SIZE as usize;
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
        let lazy_bind_offset = linkedit.lazy_bind_offset(entry.symbol).ok_or_else(|| RelocError {
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

fn encode_stub(stub_addr: u64, lazy_pointer_addr: u64) -> Result<[u8; STUB_SIZE as usize], RelocError> {
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
        encode_adrp_reg(16, header_addr + 12, binder_got_addr, "dyld_stub_binder@GOT")?,
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

fn encode_adrp_reg(
    reg: u8,
    place: u64,
    target: u64,
    referent: &str,
) -> Result<u32, RelocError> {
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
        let shift = (insn >> 30) & 0b11;
        assert_eq!(shift, 0b11);
        let pageoff = 0x3f8u64;
        let imm = pageoff >> shift;
        let patched = (insn & !(0xfff << 10)) | ((imm as u32) << 10);
        assert_eq!((patched >> 10) & 0xfff, 0x7f);
    }

    #[test]
    fn signed_fit_helper_matches_branch_range() {
        assert!(fits_signed((1 << 25) - 1, 26));
        assert!(fits_signed(-(1 << 25), 26));
        assert!(!fits_signed(1 << 25, 26));
        assert!(!fits_signed(-(1 << 25) - 1, 26));
    }
}
