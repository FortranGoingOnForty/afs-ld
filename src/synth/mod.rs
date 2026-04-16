pub mod code_sig;
pub mod dyld_info;
pub mod got;
pub mod stubs;
pub mod tlv;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::atom::{Atom, AtomSection, AtomTable};
use crate::input::ObjectFile;
use crate::layout::LayoutInput;
use crate::macho::constants::{
    S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_LAZY_SYMBOL_POINTERS,
    S_NON_LAZY_SYMBOL_POINTERS, S_REGULAR, S_SYMBOL_STUBS,
    S_THREAD_LOCAL_VARIABLE_POINTERS,
};
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind, RelocLength};
use crate::resolve::{AtomId, DylibId, DylibInput, InputId, InsertOutcome, Symbol, SymbolId, SymbolTable};
use crate::section::{OutputSection, SectionKind};

use self::got::GotSection;
use self::stubs::{
    LazyPointerSection, StubsSection, DYLD_PRIVATE_SIZE, STUB_HELPER_ENTRY_SIZE,
    STUB_HELPER_HEADER_SIZE,
};
use self::tlv::{ThreadPointerSection, THREAD_POINTER_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticPlan {
    pub got: GotSection,
    pub stubs: StubsSection,
    pub lazy_pointers: LazyPointerSection,
    pub thread_pointers: ThreadPointerSection,
    pub direct_binds: Vec<DirectBind>,
    pub binder_symbol: Option<SymbolId>,
    pub tlv_bootstrap_symbol: Option<SymbolId>,
    pub needs_dyld_private: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectBind {
    pub atom: AtomId,
    pub atom_offset: u32,
    pub symbol: SymbolId,
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthError {
    pub input: PathBuf,
    pub atom: crate::resolve::AtomId,
    pub reloc_offset: u32,
    pub kind: RelocKind,
    pub detail: String,
}

impl fmt::Display for SynthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: synthetic planning for {:?} at atom {:?}+0x{:x}: {}",
            self.input.display(),
            self.kind,
            self.atom,
            self.reloc_offset,
            self.detail
        )
    }
}

impl std::error::Error for SynthError {}

impl SyntheticPlan {
    pub fn build(
        inputs: &[LayoutInput<'_>],
        atoms: &AtomTable,
        sym_table: &mut SymbolTable,
        dylibs: &[DylibInput],
    ) -> Result<Self, SynthError> {
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
                            SynthError {
                                input: input.object.path.clone(),
                                atom: crate::resolve::AtomId(0),
                                reloc_offset: 0,
                                kind: RelocKind::Unsigned,
                                detail: err.to_string(),
                            }
                        })?;
                    parse_relocs(&raws).map_err(|err| SynthError {
                        input: input.object.path.clone(),
                        atom: crate::resolve::AtomId(0),
                        reloc_offset: 0,
                        kind: RelocKind::Unsigned,
                        detail: err.to_string(),
                    })?
                };
                reloc_cache.insert((input.id, (sect_idx + 1) as u8), relocs);
            }
        }

        let mut got = GotSection::default();
        let mut stubs = StubsSection::default();
        let mut lazy_pointers = LazyPointerSection::default();
        let mut thread_pointers = ThreadPointerSection::default();
        let mut direct_binds = Vec::new();

        for (atom_id, atom) in atoms.iter() {
            let obj = input_map.get(&atom.origin).ok_or_else(|| SynthError {
                input: PathBuf::from("<missing object>"),
                atom: atom_id,
                reloc_offset: 0,
                kind: RelocKind::Unsigned,
                detail: "missing parsed object".to_string(),
            })?;
            let relocs = reloc_cache
                .get(&(atom.origin, atom.input_section))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for reloc in relocs_for_atom(relocs, atom) {
                match reloc.kind {
                    RelocKind::Unsigned => {
                        // `__thread_vars` descriptors carry their own dedicated
                        // bind encoding later in the writer; don't double-count
                        // those dylib imports as generic bound pointer slots.
                        if matches!(atom.section, AtomSection::ThreadLocalVariables) {
                            continue;
                        }
                        let Some(symbol_id) = dylib_import_referent(obj, reloc.referent, sym_table)
                        else {
                            continue;
                        };
                        if direct_import_bind_supported(reloc) {
                            direct_binds.push(DirectBind {
                                atom: atom_id,
                                atom_offset: reloc.offset.saturating_sub(atom.input_offset),
                                symbol: symbol_id,
                                addend: reloc.addend,
                            });
                        }
                    }
                    RelocKind::GotLoadPage21
                    | RelocKind::GotLoadPageOff12
                    | RelocKind::PointerToGot => {
                        let Some(symbol_id) = dylib_import_referent(obj, reloc.referent, sym_table)
                        else {
                            continue;
                        };
                        got.intern(symbol_id, dylib_import_is_weak(sym_table, symbol_id));
                    }
                    RelocKind::Branch26 => {
                        let Some(symbol_id) = dylib_import_referent(obj, reloc.referent, sym_table)
                        else {
                            continue;
                        };
                        let dylib = match sym_table.get(symbol_id) {
                            Symbol::DylibImport { dylib, .. } => *dylib,
                            _ => continue,
                        };
                        stubs.intern(symbol_id, dylib, dylib_import_is_weak(sym_table, symbol_id));
                        lazy_pointers
                            .intern(symbol_id, dylib, dylib_import_is_weak(sym_table, symbol_id));
                    }
                    RelocKind::TlvpLoadPage21 | RelocKind::TlvpLoadPageOff12 => {
                        if let Some(symbol_id) = symbol_referent_id(obj, reloc.referent, sym_table)
                        {
                            if tlv_symbol_needs_got(sym_table, symbol_id) {
                                got.intern(symbol_id, dylib_import_is_weak(sym_table, symbol_id));
                            } else if tlv_symbol_needs_thread_pointer(sym_table, symbol_id) {
                                thread_pointers.intern(symbol_id);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        sort_symbol_indexed_entries(
            &mut got.entries,
            &mut got.index,
            |entry| entry.symbol,
            sym_table,
        );
        sort_symbol_indexed_entries(
            &mut stubs.entries,
            &mut stubs.index,
            |entry| entry.symbol,
            sym_table,
        );
        sort_symbol_indexed_entries(
            &mut lazy_pointers.entries,
            &mut lazy_pointers.index,
            |entry| entry.symbol,
            sym_table,
        );
        sort_symbol_indexed_entries(
            &mut thread_pointers.entries,
            &mut thread_pointers.index,
            |entry| entry.symbol,
            sym_table,
        );

        let mut binder_symbol = None;
        let mut tlv_bootstrap_symbol = None;
        let mut needs_dyld_private = false;
        if !stubs.entries.is_empty() {
            let binder = ensure_stub_helper_support(sym_table, dylibs, &mut got)?;
            binder_symbol = Some(binder);
            needs_dyld_private = true;
        }
        if !thread_pointers.entries.is_empty() || inputs_have_tlv_descriptors(inputs) {
            tlv_bootstrap_symbol = ensure_tlv_support(sym_table, dylibs)?;
        }

        Ok(SyntheticPlan {
            got,
            stubs,
            lazy_pointers,
            thread_pointers,
            direct_binds,
            binder_symbol,
            tlv_bootstrap_symbol,
            needs_dyld_private,
        })
    }

    pub fn output_sections(&self) -> Vec<OutputSection> {
        let mut out = Vec::new();
        if !self.stubs.entries.is_empty() {
            out.push(OutputSection {
                segment: "__TEXT".into(),
                name: "__stubs".into(),
                kind: SectionKind::SymbolStubs,
                align_pow2: 2,
                flags: S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: stubs::STUB_SIZE,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![0; self.stubs.entries.len() * stubs::STUB_SIZE as usize],
                addr: 0,
                size: (self.stubs.entries.len() as u64) * stubs::STUB_SIZE as u64,
                file_off: 0,
            });
        }
        if self.binder_symbol.is_some() {
            out.push(OutputSection {
                segment: "__TEXT".into(),
                name: "__stub_helper".into(),
                kind: SectionKind::Text,
                align_pow2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![
                    0;
                    STUB_HELPER_HEADER_SIZE as usize
                        + self.lazy_pointers.entries.len() * STUB_HELPER_ENTRY_SIZE as usize
                ],
                addr: 0,
                size: STUB_HELPER_HEADER_SIZE as u64
                    + (self.lazy_pointers.entries.len() as u64) * STUB_HELPER_ENTRY_SIZE as u64,
                file_off: 0,
            });
        }
        if !self.got.entries.is_empty() {
            out.push(OutputSection {
                segment: "__DATA_CONST".into(),
                name: "__got".into(),
                kind: SectionKind::NonLazySymbolPointers,
                align_pow2: 3,
                flags: S_NON_LAZY_SYMBOL_POINTERS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![0; self.got.entries.len() * 8],
                addr: 0,
                size: (self.got.entries.len() as u64) * 8,
                file_off: 0,
            });
        }
        if self.needs_dyld_private {
            out.push(OutputSection {
                segment: "__DATA".into(),
                name: "__data".into(),
                kind: SectionKind::Data,
                align_pow2: 3,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![0; DYLD_PRIVATE_SIZE as usize],
                addr: 0,
                size: DYLD_PRIVATE_SIZE as u64,
                file_off: 0,
            });
        }
        if !self.lazy_pointers.entries.is_empty() {
            out.push(OutputSection {
                segment: "__DATA".into(),
                name: "__la_symbol_ptr".into(),
                kind: SectionKind::LazySymbolPointers,
                align_pow2: 3,
                flags: S_LAZY_SYMBOL_POINTERS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![0; self.lazy_pointers.entries.len() * 8],
                addr: 0,
                size: (self.lazy_pointers.entries.len() as u64) * 8,
                file_off: 0,
            });
        }
        if !self.thread_pointers.entries.is_empty() {
            out.push(OutputSection {
                segment: "__DATA".into(),
                name: "__thread_ptrs".into(),
                kind: SectionKind::ThreadLocalVariablePointers,
                align_pow2: 3,
                flags: S_THREAD_LOCAL_VARIABLE_POINTERS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: Vec::new(),
                synthetic_offset: 0,
                synthetic_data: vec![0; self.thread_pointers.entries.len() * THREAD_POINTER_SIZE as usize],
                addr: 0,
                size: (self.thread_pointers.entries.len() as u64) * THREAD_POINTER_SIZE as u64,
                file_off: 0,
            });
        }
        out
    }
}

fn sort_symbol_indexed_entries<T, F>(
    entries: &mut [T],
    index: &mut HashMap<SymbolId, usize>,
    symbol_of: F,
    sym_table: &SymbolTable,
) where
    F: Fn(&T) -> SymbolId,
{
    entries.sort_by(|lhs, rhs| {
        let lhs_name = sym_table.interner.resolve(sym_table.get(symbol_of(lhs)).name());
        let rhs_name = sym_table.interner.resolve(sym_table.get(symbol_of(rhs)).name());
        lhs_name.cmp(rhs_name)
    });
    index.clear();
    for (idx, entry) in entries.iter().enumerate() {
        index.insert(symbol_of(entry), idx);
    }
}

fn relocs_for_atom<'a>(relocs: &'a [Reloc], atom: &Atom) -> impl Iterator<Item = Reloc> + 'a {
    let start = atom.input_offset;
    let end = atom.input_offset + atom.size;
    relocs.iter().copied().filter(move |reloc| {
        let reloc_end = reloc.offset + reloc.width_for_planning();
        reloc.offset >= start && reloc_end <= end
    })
}

trait RelocPlanningWidth {
    fn width_for_planning(self) -> u32;
}

impl RelocPlanningWidth for Reloc {
    fn width_for_planning(self) -> u32 {
        match self.kind {
            RelocKind::Subtractor => 8,
            _ => match self.length {
                crate::reloc::RelocLength::Byte => 1,
                crate::reloc::RelocLength::Half => 2,
                crate::reloc::RelocLength::Word => 4,
                crate::reloc::RelocLength::Quad => 8,
            },
        }
    }
}

fn dylib_import_referent(
    obj: &ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
) -> Option<SymbolId> {
    let symbol_id = symbol_referent_id(obj, referent, sym_table)?;
    matches!(sym_table.get(symbol_id), Symbol::DylibImport { .. }).then_some(symbol_id)
}

fn symbol_referent_id(
    obj: &ObjectFile,
    referent: Referent,
    sym_table: &SymbolTable,
) -> Option<SymbolId> {
    let Referent::Symbol(sym_idx) = referent else {
        return None;
    };
    let input_sym = obj.symbols.get(sym_idx as usize)?;
    let name = obj.symbol_name(input_sym).ok()?;
    let (symbol_id, _) = sym_table
        .iter()
        .find(|(_, symbol)| sym_table.interner.resolve(symbol.name()) == name)?;
    Some(symbol_id)
}

fn dylib_import_is_weak(sym_table: &SymbolTable, symbol_id: SymbolId) -> bool {
    matches!(
        sym_table.get(symbol_id),
        Symbol::DylibImport {
            weak_import: true,
            ..
        }
    )
}

fn tlv_symbol_needs_thread_pointer(sym_table: &SymbolTable, symbol_id: SymbolId) -> bool {
    matches!(sym_table.get(symbol_id), Symbol::LazyArchive { .. } | Symbol::LazyObject { .. })
}

fn tlv_symbol_needs_got(sym_table: &SymbolTable, symbol_id: SymbolId) -> bool {
    matches!(sym_table.get(symbol_id), Symbol::DylibImport { .. })
}

fn direct_import_bind_supported(reloc: Reloc) -> bool {
    matches!(reloc.length, RelocLength::Quad) && !reloc.pcrel && reloc.subtrahend.is_none()
}

fn inputs_have_tlv_descriptors(inputs: &[LayoutInput<'_>]) -> bool {
    inputs.iter().any(|input| {
        input
            .object
            .sections
            .iter()
            .any(|section| section.kind == SectionKind::ThreadLocalVariables)
    })
}

fn ensure_stub_helper_support(
    sym_table: &mut SymbolTable,
    dylibs: &[DylibInput],
    got: &mut GotSection,
) -> Result<SymbolId, SynthError> {
    let (libsystem_id, libsystem) = find_libsystem_input(dylibs)
        .ok_or_else(|| SynthError {
            input: PathBuf::from("<synthetic stubs>"),
            atom: crate::resolve::AtomId(0),
            reloc_offset: 0,
            kind: RelocKind::Branch26,
            detail: "stub helper requires a libSystem dylib/TBD input for `dyld_stub_binder`"
                .to_string(),
        })?;

    let name = sym_table.intern("dyld_stub_binder");
    let symbol_id = if let Some(id) = sym_table.lookup(name) {
        match sym_table.get(id) {
            Symbol::DylibImport { .. } => id,
            other => {
                return Err(SynthError {
                    input: PathBuf::from("<synthetic stubs>"),
                    atom: crate::resolve::AtomId(0),
                    reloc_offset: 0,
                    kind: RelocKind::Branch26,
                    detail: format!(
                        "`dyld_stub_binder` already exists as unsupported symbol kind {:?}",
                        other.kind()
                    ),
                });
            }
        }
    } else {
        match sym_table
            .insert(Symbol::DylibImport {
                name,
                dylib: DylibId(libsystem_id as u32),
                ordinal: libsystem.ordinal,
                weak_import: false,
            })
            .map_err(|err| SynthError {
                input: PathBuf::from("<synthetic stubs>"),
                atom: crate::resolve::AtomId(0),
                reloc_offset: 0,
                kind: RelocKind::Branch26,
                detail: format!("{err:?}"),
            })? {
            InsertOutcome::Inserted(id)
            | InsertOutcome::Kept(id)
            | InsertOutcome::PendingArchiveFetch { id, .. }
            | InsertOutcome::PendingObjectLoad { id, .. }
            | InsertOutcome::CommonCoalesced { id }
            | InsertOutcome::Replaced { id, .. } => id,
        }
    };

    got.intern(symbol_id, false);
    Ok(symbol_id)
}

fn ensure_tlv_support(
    sym_table: &mut SymbolTable,
    dylibs: &[DylibInput],
) -> Result<Option<SymbolId>, SynthError> {
    let Some((libsystem_id, libsystem)) = find_libsystem_input(dylibs) else {
        return Ok(None);
    };

    let name = sym_table.intern("__tlv_bootstrap");
    let symbol_id = if let Some(id) = sym_table.lookup(name) {
        match sym_table.get(id) {
            Symbol::DylibImport { .. } => id,
            other => {
                return Err(SynthError {
                    input: PathBuf::from("<synthetic tlv>"),
                    atom: crate::resolve::AtomId(0),
                    reloc_offset: 0,
                    kind: RelocKind::TlvpLoadPage21,
                    detail: format!(
                        "`__tlv_bootstrap` already exists as unsupported symbol kind {:?}",
                        other.kind()
                    ),
                });
            }
        }
    } else {
        match sym_table
            .insert(Symbol::DylibImport {
                name,
                dylib: DylibId(libsystem_id as u32),
                ordinal: libsystem.ordinal,
                weak_import: false,
            })
            .map_err(|err| SynthError {
                input: PathBuf::from("<synthetic tlv>"),
                atom: crate::resolve::AtomId(0),
                reloc_offset: 0,
                kind: RelocKind::TlvpLoadPage21,
                detail: format!("{err:?}"),
            })? {
            InsertOutcome::Inserted(id)
            | InsertOutcome::Kept(id)
            | InsertOutcome::PendingArchiveFetch { id, .. }
            | InsertOutcome::PendingObjectLoad { id, .. }
            | InsertOutcome::CommonCoalesced { id }
            | InsertOutcome::Replaced { id, .. } => id,
        }
    };

    Ok(Some(symbol_id))
}

fn find_libsystem_input(dylibs: &[DylibInput]) -> Option<(usize, &DylibInput)> {
    dylibs
        .iter()
        .enumerate()
        .find(|(_, dylib)| dylib.load_install_name == "/usr/lib/libSystem.B.dylib")
        .or_else(|| {
            dylibs
                .iter()
                .enumerate()
                .find(|(_, dylib)| dylib.load_install_name.contains("libSystem"))
        })
        .or_else(|| {
            dylibs
                .iter()
                .enumerate()
                .find(|(_, dylib)| dylib.path.to_string_lossy().contains("libSystem.tbd"))
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
    use crate::input::ObjectFile;
    use crate::layout::LayoutInput;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_DYLIB, MH_MAGIC_64, MH_OBJECT, N_EXT, N_UNDF,
        S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_REGULAR,
    };
    use crate::macho::dylib::DylibFile;
    use crate::macho::exports::Exports;
    use crate::macho::reader::{LoadCommand, MachHeader64};
    use crate::reloc::{write_raw_relocs, write_relocs, Referent, Reloc, RelocKind, RelocLength};
    use crate::resolve::{DylibId, DylibInput, InputId, Symbol, SymbolTable};
    use crate::section::{InputSection, SectionKind};
    use crate::string_table::StringTable;
    use crate::symbol::{InputSymbol, RawNlist};

    use super::*;

    #[test]
    fn synthetic_plan_collects_got_and_stub_needs_for_imports() {
        let mut sym_table = SymbolTable::new();
        let name = sym_table.intern("_printf");
        let input_id = InputId(0);
        sym_table
            .insert(Symbol::DylibImport {
                name,
                dylib: DylibId(2),
                ordinal: 3,
                weak_import: false,
            })
            .unwrap();

        let relocs = vec![
            Reloc {
                offset: 0,
                kind: RelocKind::Branch26,
                length: RelocLength::Word,
                pcrel: true,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 4,
                kind: RelocKind::GotLoadPage21,
                length: RelocLength::Word,
                pcrel: true,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 8,
                kind: RelocKind::GotLoadPageOff12,
                length: RelocLength::Word,
                pcrel: false,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
        ];
        let raw_relocs = encode_raw_relocs(&relocs);
        let object = synth_object("_printf", raw_relocs);

        let mut atoms = AtomTable::new();
        atoms.push(Atom {
            id: crate::resolve::AtomId(0),
            origin: input_id,
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 12,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 12],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        });
        let dylibs = vec![libsystem_input()];

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &mut sym_table,
            &dylibs,
        )
        .unwrap();

        assert_eq!(plan.got.entries.len(), 2);
        assert_eq!(plan.stubs.entries.len(), 1);
        assert_eq!(plan.lazy_pointers.entries.len(), 1);
        assert!(plan.thread_pointers.entries.is_empty());
        assert!(plan.direct_binds.is_empty());
        assert!(plan.binder_symbol.is_some());
        assert!(plan.tlv_bootstrap_symbol.is_none());
        assert!(plan.needs_dyld_private);
        assert_eq!(plan.stubs.entries[0].dylib, DylibId(2));
        assert_eq!(plan.lazy_pointers.entries[0].symbol, plan.stubs.entries[0].symbol);
    }

    #[test]
    fn synthetic_plan_ignores_defined_targets() {
        let mut sym_table = SymbolTable::new();
        let name = sym_table.intern("_local");
        let input_id = InputId(0);
        sym_table
            .insert(Symbol::Defined {
                name,
                origin: input_id,
                atom: crate::resolve::AtomId(1),
                value: 0,
                weak: false,
                private_extern: false,
                no_dead_strip: false,
            })
            .unwrap();

        let relocs = vec![Reloc {
            offset: 0,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        }];
        let object = synth_object("_local", encode_raw_relocs(&relocs));

        let mut atoms = AtomTable::new();
        atoms.push(Atom {
            id: crate::resolve::AtomId(0),
            origin: input_id,
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 4,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 4],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        });

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &mut sym_table,
            &[],
        )
        .unwrap();
        assert!(plan.got.entries.is_empty());
        assert!(plan.stubs.entries.is_empty());
        assert!(plan.lazy_pointers.entries.is_empty());
        assert!(plan.thread_pointers.entries.is_empty());
        assert!(plan.binder_symbol.is_none());
        assert!(plan.tlv_bootstrap_symbol.is_none());
        assert!(!plan.needs_dyld_private);
    }

    #[test]
    fn synthetic_plan_keeps_local_tlvp_on_descriptors() {
        let mut sym_table = SymbolTable::new();
        let name = sym_table.intern("_tlsvar");
        let input_id = InputId(0);
        sym_table
            .insert(Symbol::Defined {
                name,
                origin: input_id,
                atom: crate::resolve::AtomId(1),
                value: 0,
                weak: false,
                private_extern: false,
                no_dead_strip: false,
            })
            .unwrap();

        let relocs = vec![
            Reloc {
                offset: 0,
                kind: RelocKind::TlvpLoadPage21,
                length: RelocLength::Word,
                pcrel: true,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 4,
                kind: RelocKind::TlvpLoadPageOff12,
                length: RelocLength::Word,
                pcrel: false,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
        ];
        let object = tlvp_object("_tlsvar", encode_raw_relocs(&relocs));

        let mut atoms = AtomTable::new();
        atoms.push(Atom {
            id: crate::resolve::AtomId(0),
            origin: input_id,
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 8,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        });

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &mut sym_table,
            &[libsystem_input()],
        )
        .unwrap();

        assert!(plan.thread_pointers.entries.is_empty());
        assert!(plan.binder_symbol.is_none());
        assert!(plan.tlv_bootstrap_symbol.is_some());

        let sections = plan.output_sections();
        assert!(sections
            .iter()
            .all(|section| !(section.segment == "__DATA" && section.name == "__thread_ptrs")));
    }

    #[test]
    fn synthetic_plan_routes_imported_tlvp_through_got() {
        let mut sym_table = SymbolTable::new();
        let name = sym_table.intern("_ext_tls");
        let input_id = InputId(0);
        let import = match sym_table
            .insert(Symbol::DylibImport {
                name,
                dylib: DylibId(0),
                ordinal: 2,
                weak_import: false,
            })
            .unwrap()
        {
            crate::resolve::InsertOutcome::Inserted(id) => id,
            other => panic!("unexpected insert outcome: {other:?}"),
        };

        let relocs = vec![
            Reloc {
                offset: 0,
                kind: RelocKind::TlvpLoadPage21,
                length: RelocLength::Word,
                pcrel: true,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
            Reloc {
                offset: 4,
                kind: RelocKind::TlvpLoadPageOff12,
                length: RelocLength::Word,
                pcrel: false,
                referent: Referent::Symbol(0),
                addend: 0,
                subtrahend: None,
            },
        ];
        let object = synth_object("_ext_tls", encode_raw_relocs(&relocs));

        let mut atoms = AtomTable::new();
        atoms.push(Atom {
            id: crate::resolve::AtomId(0),
            origin: input_id,
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 12,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 12],
            flags: AtomFlags::default().with(AtomFlags::PURE_INSTRUCTIONS),
            parent_of: None,
        });

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &mut sym_table,
            &[libsystem_input()],
        )
        .unwrap();

        assert_eq!(plan.got.entries.len(), 1);
        assert_eq!(plan.got.entries[0].symbol, import);
        assert!(plan.thread_pointers.entries.is_empty());
        assert!(plan.direct_binds.is_empty());
        assert!(plan.tlv_bootstrap_symbol.is_none());
    }

    #[test]
    fn synthetic_plan_collects_direct_import_bind_sites() {
        let mut sym_table = SymbolTable::new();
        let name = sym_table.intern("_ext_data");
        let input_id = InputId(0);
        let import = match sym_table
            .insert(Symbol::DylibImport {
                name,
                dylib: DylibId(0),
                ordinal: 2,
                weak_import: false,
            })
            .unwrap()
        {
            crate::resolve::InsertOutcome::Inserted(id) => id,
            other => panic!("unexpected insert outcome: {other:?}"),
        };

        let relocs = vec![Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        }];
        let object = synth_object("_ext_data", encode_raw_relocs(&relocs));

        let mut atoms = AtomTable::new();
        let atom_id = atoms.push(Atom {
            id: crate::resolve::AtomId(0),
            origin: input_id,
            input_section: 1,
            section: AtomSection::Data,
            input_offset: 0,
            size: 8,
            align_pow2: 3,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::default(),
            parent_of: None,
        });

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &mut sym_table,
            &[libsystem_input()],
        )
        .unwrap();

        assert!(plan.got.entries.is_empty());
        assert_eq!(plan.direct_binds.len(), 1);
        assert_eq!(plan.direct_binds[0].atom, atom_id);
        assert_eq!(plan.direct_binds[0].atom_offset, 0);
        assert_eq!(plan.direct_binds[0].symbol, import);
    }

    fn libsystem_input() -> DylibInput {
        DylibInput {
            path: PathBuf::from("/tmp/libSystem.tbd"),
            load_install_name: "/usr/lib/libSystem.B.dylib".into(),
            load_current_version: 0,
            load_compatibility_version: 0,
            file: DylibFile {
                path: PathBuf::from("/tmp/libSystem.tbd"),
                header: MachHeader64 {
                    magic: MH_MAGIC_64,
                    cputype: CPU_TYPE_ARM64,
                    cpusubtype: CPU_SUBTYPE_ARM64_ALL,
                    filetype: MH_DYLIB,
                    ncmds: 0,
                    sizeofcmds: 0,
                    flags: 0,
                    reserved: 0,
                },
                commands: Vec::<LoadCommand>::new(),
                install_name: "/usr/lib/libSystem.B.dylib".into(),
                current_version: 0,
                compatibility_version: 0,
                dependencies: Vec::new(),
                rpaths: Vec::new(),
                symtab: None,
                exports: Exports::empty(),
            },
            ordinal: 1,
        }
    }

    fn encode_raw_relocs(relocs: &[Reloc]) -> Vec<u8> {
        let raws = write_relocs(relocs).unwrap();
        let mut bytes = Vec::new();
        write_raw_relocs(&raws, &mut bytes);
        bytes
    }

    fn synth_object(symbol_name: &str, raw_relocs: Vec<u8>) -> ObjectFile {
        let mut strings = vec![0];
        let strx = strings.len() as u32;
        strings.extend_from_slice(symbol_name.as_bytes());
        strings.push(0);
        ObjectFile {
            path: PathBuf::from("/tmp/synth-got.o"),
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
                kind: SectionKind::Text,
                addr: 0,
                size: 12,
                align_pow2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                offset: 0,
                reloff: 0,
                nreloc: (raw_relocs.len() / 8) as u32,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                data: vec![0; 12],
                raw_relocs,
            }],
            symbols: vec![InputSymbol::from_raw(RawNlist {
                strx,
                n_type: N_UNDF | N_EXT,
                n_sect: 0,
                n_desc: 0,
                n_value: 0,
            })],
            strings: StringTable::from_bytes(strings),
            symtab: None,
            dysymtab: None,
            data_in_code: Vec::new(),
        }
    }

    fn tlvp_object(symbol_name: &str, raw_relocs: Vec<u8>) -> ObjectFile {
        let mut strings = vec![0];
        let strx = strings.len() as u32;
        strings.extend_from_slice(symbol_name.as_bytes());
        strings.push(0);
        ObjectFile {
            path: PathBuf::from("/tmp/synth-tlv.o"),
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
                    size: 8,
                    align_pow2: 2,
                    flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                    offset: 0,
                    reloff: 0,
                    nreloc: (raw_relocs.len() / 8) as u32,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    data: vec![0; 8],
                    raw_relocs,
                },
                InputSection {
                    segname: "__DATA".into(),
                    sectname: "__thread_vars".into(),
                    kind: SectionKind::ThreadLocalVariables,
                    addr: 0,
                    size: 24,
                    align_pow2: 3,
                    flags: crate::macho::constants::S_THREAD_LOCAL_VARIABLES,
                    offset: 0,
                    reloff: 0,
                    nreloc: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    data: vec![0; 24],
                    raw_relocs: Vec::new(),
                },
                InputSection {
                    segname: "__DATA".into(),
                    sectname: "__thread_data".into(),
                    kind: SectionKind::ThreadLocalRegular,
                    addr: 0,
                    size: 8,
                    align_pow2: 3,
                    flags: crate::macho::constants::S_THREAD_LOCAL_REGULAR,
                    offset: 0,
                    reloff: 0,
                    nreloc: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    data: vec![0; 8],
                    raw_relocs: Vec::new(),
                },
            ],
            symbols: vec![InputSymbol::from_raw(RawNlist {
                strx,
                n_type: N_EXT | crate::macho::constants::N_SECT,
                n_sect: 2,
                n_desc: 0,
                n_value: 0,
            })],
            strings: StringTable::from_bytes(strings),
            symtab: None,
            dysymtab: None,
            data_in_code: Vec::new(),
        }
    }
}
