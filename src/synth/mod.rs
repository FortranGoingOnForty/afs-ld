pub mod got;
pub mod stubs;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::atom::{Atom, AtomTable};
use crate::input::ObjectFile;
use crate::layout::LayoutInput;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind};
use crate::resolve::{InputId, Symbol, SymbolId, SymbolTable};

use self::got::GotSection;
use self::stubs::{LazyPointerSection, StubsSection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticPlan {
    pub got: GotSection,
    pub stubs: StubsSection,
    pub lazy_pointers: LazyPointerSection,
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
        sym_table: &SymbolTable,
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
                let Some(symbol_id) = dylib_import_referent(obj, reloc.referent, sym_table) else {
                    continue;
                };
                let dylib = match sym_table.get(symbol_id) {
                    Symbol::DylibImport { dylib, .. } => *dylib,
                    _ => continue,
                };
                match reloc.kind {
                    RelocKind::GotLoadPage21
                    | RelocKind::GotLoadPageOff12
                    | RelocKind::PointerToGot => {
                        got.intern(symbol_id, dylib_import_is_weak(sym_table, symbol_id));
                    }
                    RelocKind::Branch26 => {
                        stubs.intern(symbol_id, dylib, dylib_import_is_weak(sym_table, symbol_id));
                        lazy_pointers
                            .intern(symbol_id, dylib, dylib_import_is_weak(sym_table, symbol_id));
                    }
                    RelocKind::TlvpLoadPage21 | RelocKind::TlvpLoadPageOff12 => {}
                    _ => {}
                }
            }
        }

        Ok(SyntheticPlan {
            got,
            stubs,
            lazy_pointers,
        })
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

fn dylib_import_is_weak(sym_table: &SymbolTable, symbol_id: SymbolId) -> bool {
    matches!(
        sym_table.get(symbol_id),
        Symbol::DylibImport {
            weak_import: true,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
    use crate::input::ObjectFile;
    use crate::layout::LayoutInput;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_MAGIC_64, MH_OBJECT, N_EXT, N_UNDF,
        S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_REGULAR,
    };
    use crate::macho::reader::MachHeader64;
    use crate::reloc::{write_raw_relocs, write_relocs, Referent, Reloc, RelocKind, RelocLength};
    use crate::resolve::{DylibId, InputId, Symbol, SymbolTable};
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

        let plan = SyntheticPlan::build(
            &[LayoutInput {
                id: input_id,
                object: &object,
            }],
            &atoms,
            &sym_table,
        )
        .unwrap();

        assert_eq!(plan.got.entries.len(), 1);
        assert_eq!(plan.stubs.entries.len(), 1);
        assert_eq!(plan.lazy_pointers.entries.len(), 1);
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
            &sym_table,
        )
        .unwrap();
        assert!(plan.got.entries.is_empty());
        assert!(plan.stubs.entries.is_empty());
        assert!(plan.lazy_pointers.entries.is_empty());
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
        }
    }
}
