//! Sprint 10 output layout.
//!
//! Groups atoms into output sections, orders them deterministically, and
//! assigns segment VM/file ranges once the final Mach-O header size is known.

use std::collections::{HashMap, HashSet};

use crate::atom::AtomTable;
use crate::input::ObjectFile;
use crate::macho::constants::SG_READ_ONLY;
use crate::resolve::{AtomId, InputId};
use crate::section::{
    is_zerofill, InputSection, OutputAtom, OutputSection, OutputSectionId, OutputSegment, Prot,
};
use crate::synth::SyntheticPlan;
use crate::OutputKind;

pub const PAGE_SIZE: u64 = 0x4000;
pub const EXECUTABLE_TEXT_BASE: u64 = 0x1_0000_0000;

const EXEC_SEGMENTS: [&str; 5] = [
    "__PAGEZERO",
    "__TEXT",
    "__DATA_CONST",
    "__DATA",
    "__LINKEDIT",
];
const DYLIB_SEGMENTS: [&str; 4] = ["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"];

#[derive(Debug, Clone, Copy)]
pub struct LayoutInput<'a> {
    pub id: InputId,
    pub object: &'a ObjectFile,
    pub load_order: usize,
    pub archive_member_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: OutputKind,
    pub segments: Vec<OutputSegment>,
    pub sections: Vec<OutputSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct SectionKey {
    segment: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExtraSectionAnchor {
    AfterSection { segment: String, name: String },
    AfterAtom(AtomId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraOutputSection {
    pub after_section: Option<ExtraSectionAnchor>,
    pub section: OutputSection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraLayoutSections<'a> {
    pub extra_sections: &'a [ExtraOutputSection],
    pub split_after_atoms: &'a [AtomId],
}

fn output_section_key(input_section: &InputSection) -> SectionKey {
    match (
        input_section.segname.as_str(),
        input_section.sectname.as_str(),
    ) {
        ("__DATA", "__const") => SectionKey {
            segment: "__DATA_CONST".to_string(),
            name: "__const".to_string(),
        },
        _ => SectionKey {
            segment: input_section.segname.clone(),
            name: input_section.sectname.clone(),
        },
    }
}

impl Layout {
    pub fn empty(kind: OutputKind, header_size: u64) -> Self {
        Self::build(kind, &[], &AtomTable::new(), header_size)
    }

    pub fn build(
        kind: OutputKind,
        inputs: &[LayoutInput<'_>],
        atoms: &AtomTable,
        header_size: u64,
    ) -> Self {
        Self::build_with_synthetics_filtered(kind, inputs, atoms, header_size, None, None)
    }

    pub fn build_with_synthetics(
        kind: OutputKind,
        inputs: &[LayoutInput<'_>],
        atoms: &AtomTable,
        header_size: u64,
        synthetic_plan: Option<&SyntheticPlan>,
    ) -> Self {
        Self::build_with_synthetics_and_extra_filtered(
            kind,
            inputs,
            atoms,
            header_size,
            synthetic_plan,
            None,
            ExtraLayoutSections {
                extra_sections: &[],
                split_after_atoms: &[],
            },
        )
    }

    pub fn build_with_synthetics_filtered(
        kind: OutputKind,
        inputs: &[LayoutInput<'_>],
        atoms: &AtomTable,
        header_size: u64,
        synthetic_plan: Option<&SyntheticPlan>,
        live_atoms: Option<&HashSet<AtomId>>,
    ) -> Self {
        Self::build_with_synthetics_and_extra_filtered(
            kind,
            inputs,
            atoms,
            header_size,
            synthetic_plan,
            live_atoms,
            ExtraLayoutSections {
                extra_sections: &[],
                split_after_atoms: &[],
            },
        )
    }

    pub fn build_with_synthetics_and_extra_filtered(
        kind: OutputKind,
        inputs: &[LayoutInput<'_>],
        atoms: &AtomTable,
        header_size: u64,
        synthetic_plan: Option<&SyntheticPlan>,
        live_atoms: Option<&HashSet<AtomId>>,
        extra_layout: ExtraLayoutSections<'_>,
    ) -> Self {
        let input_map: HashMap<InputId, LayoutInput<'_>> =
            inputs.iter().map(|input| (input.id, *input)).collect();

        let mut sections: Vec<OutputSection> = Vec::new();
        let mut section_index: HashMap<SectionKey, usize> = HashMap::new();

        for (atom_id, atom) in atoms.iter() {
            if live_atoms.is_some_and(|live_atoms| !live_atoms.contains(&atom_id)) {
                continue;
            }
            let input = input_map
                .get(&atom.origin)
                .unwrap_or_else(|| panic!("missing object for input {:?}", atom.origin));
            let input_section = input
                .object
                .sections
                .get((atom.input_section as usize).saturating_sub(1))
                .unwrap_or_else(|| {
                    panic!(
                        "input {} section {} missing for atom {:?}",
                        input.object.path.display(),
                        atom.input_section,
                        atom_id
                    )
                });

            let key = output_section_key(input_section);
            let idx = match section_index.get(&key) {
                Some(&idx) => idx,
                None => {
                    let idx = sections.len();
                    sections.push(OutputSection {
                        segment: key.segment.clone(),
                        name: key.name.clone(),
                        kind: input_section.kind,
                        align_pow2: normalize_output_alignment(
                            input_section.kind,
                            input_section.align_pow2.min(u8::MAX as u32) as u8,
                        ),
                        flags: input_section.flags,
                        reserved1: input_section.reserved1,
                        reserved2: input_section.reserved2,
                        reserved3: input_section.reserved3,
                        atoms: Vec::new(),
                        synthetic_offset: 0,
                        synthetic_data: Vec::new(),
                        addr: 0,
                        size: 0,
                        file_off: 0,
                    });
                    section_index.insert(key, idx);
                    idx
                }
            };

            let out = &mut sections[idx];
            out.align_pow2 =
                normalize_output_alignment(out.kind, out.align_pow2.max(atom.align_pow2));
            out.atoms.push(OutputAtom {
                atom: atom_id,
                offset: 0,
                size: atom.size as u64,
                data: atom.data.clone(),
            });
        }

        if let Some(plan) = synthetic_plan {
            for synthetic in plan.output_sections() {
                if let Some(existing) = sections.iter_mut().find(|section| {
                    section.segment == synthetic.segment && section.name == synthetic.name
                }) {
                    merge_synthetic_section(existing, synthetic);
                } else {
                    sections.push(synthetic);
                }
            }
        }
        sections.sort_by(|a, b| {
            segment_rank(kind, &a.segment)
                .cmp(&segment_rank(kind, &b.segment))
                .then_with(|| {
                    section_rank(&a.segment, &a.name).cmp(&section_rank(&b.segment, &b.name))
                })
                .then_with(|| a.segment.cmp(&b.segment))
                .then_with(|| a.name.cmp(&b.name))
        });

        for section in &mut sections {
            section.atoms.sort_by(|a, b| {
                let lhs = atoms.get(a.atom);
                let rhs = atoms.get(b.atom);
                let lhs_input = input_map
                    .get(&lhs.origin)
                    .unwrap_or_else(|| panic!("missing object for input {:?}", lhs.origin));
                let rhs_input = input_map
                    .get(&rhs.origin)
                    .unwrap_or_else(|| panic!("missing object for input {:?}", rhs.origin));
                lhs_input
                    .load_order
                    .cmp(&rhs_input.load_order)
                    .then_with(|| {
                        lhs_input
                            .archive_member_offset
                            .unwrap_or(0)
                            .cmp(&rhs_input.archive_member_offset.unwrap_or(0))
                    })
                    .then_with(|| lhs.origin.cmp(&rhs.origin))
                    .then_with(|| lhs.input_offset.cmp(&rhs.input_offset))
                    .then_with(|| a.atom.cmp(&b.atom))
            });
        }

        split_sections_after_atoms(&mut sections, extra_layout.split_after_atoms);
        insert_extra_sections(&mut sections, extra_layout.extra_sections);

        for section in &mut sections {
            let synthetic_prefix = synthetic_data_precedes_atoms(section);
            let mut size = if synthetic_prefix {
                section.synthetic_data.len() as u64
            } else {
                0
            };
            for placed in &mut section.atoms {
                let atom = atoms.get(placed.atom);
                let align = 1u64 << atom.align_pow2.min(63);
                size = align_up(size, align);
                placed.offset = size;
                size += placed.size;
            }
            section.synthetic_offset = if synthetic_prefix
                || section.synthetic_data.is_empty()
                || section.atoms.is_empty()
            {
                0
            } else {
                let align = 1u64 << section.align_pow2.min(63);
                align_up(size, align)
            };
            section.size = if section.synthetic_data.is_empty() || synthetic_prefix {
                size
            } else {
                section.synthetic_offset + section.synthetic_data.len() as u64
            };
        }

        let mut layout = Layout {
            kind,
            segments: build_segments(kind, &sections),
            sections,
        };
        layout.assign_addresses(header_size);
        layout
    }

    pub fn segment(&self, name: &str) -> Option<&OutputSegment> {
        self.segments.iter().find(|seg| seg.name == name)
    }

    pub fn segment_mut(&mut self, name: &str) -> Option<&mut OutputSegment> {
        self.segments.iter_mut().find(|seg| seg.name == name)
    }

    pub fn relayout(&mut self, header_size: u64) {
        self.assign_addresses(header_size);
    }

    pub fn atom_file_offset(&self, atom_id: crate::resolve::AtomId) -> Option<u64> {
        for section in &self.sections {
            for placed in &section.atoms {
                if placed.atom == atom_id {
                    return Some(section.file_off + placed.offset);
                }
            }
        }
        None
    }

    pub fn atom_addr(&self, atom_id: crate::resolve::AtomId) -> Option<u64> {
        for section in &self.sections {
            for placed in &section.atoms {
                if placed.atom == atom_id {
                    return Some(section.addr + placed.offset);
                }
            }
        }
        None
    }

    fn assign_addresses(&mut self, header_size: u64) {
        for seg in &mut self.segments {
            seg.sections.clear();
            seg.vm_addr = 0;
            seg.vm_size = 0;
            seg.file_off = 0;
            seg.file_size = 0;
        }

        let section_membership: Vec<(usize, String)> = self
            .sections
            .iter()
            .enumerate()
            .map(|(idx, section)| (idx, section.segment.clone()))
            .collect();
        for (idx, segment_name) in section_membership {
            let segment = self
                .segment_mut(&segment_name)
                .unwrap_or_else(|| panic!("no output segment named {segment_name}"));
            segment.sections.push(OutputSectionId(idx as u32));
        }

        let text_base = match self.kind {
            OutputKind::Executable => EXECUTABLE_TEXT_BASE,
            OutputKind::Dylib => 0,
        };

        if self.kind == OutputKind::Executable {
            let pagezero = self
                .segment_mut("__PAGEZERO")
                .expect("executable layout must include __PAGEZERO");
            pagezero.vm_addr = 0;
            pagezero.vm_size = EXECUTABLE_TEXT_BASE;
            pagezero.file_off = 0;
            pagezero.file_size = 0;
        }

        let mut next_vm = text_base;
        let mut next_file = 0u64;
        let segment_names: Vec<String> = self.segments.iter().map(|seg| seg.name.clone()).collect();
        for seg_name in segment_names {
            if seg_name == "__PAGEZERO" {
                continue;
            }

            let is_text = seg_name == "__TEXT";
            let is_linkedit = seg_name == "__LINKEDIT";
            let seg_start_vm = if is_text {
                text_base
            } else {
                align_up(next_vm, PAGE_SIZE)
            };
            let seg_start_file = if is_text {
                0
            } else {
                align_up(next_file, PAGE_SIZE)
            };

            let mut vm_cursor = if is_text {
                seg_start_vm + header_size
            } else {
                seg_start_vm
            };
            let mut file_cursor = if is_text { header_size } else { seg_start_file };
            let mut seg_vm_end = if is_text {
                seg_start_vm + header_size
            } else {
                seg_start_vm
            };
            let mut seg_file_end = if is_text { header_size } else { seg_start_file };

            let section_ids = self
                .segment(&seg_name)
                .map(|seg| seg.sections.clone())
                .unwrap_or_default();
            for id in section_ids {
                let section = &mut self.sections[id.0 as usize];
                let align = 1u64 << section.align_pow2.min(63);
                vm_cursor = align_up(vm_cursor, align);
                section.addr = vm_cursor;
                seg_vm_end = seg_vm_end.max(section.addr + section.size);
                vm_cursor = section.addr + section.size;

                if is_zerofill(section.kind) {
                    section.file_off = 0;
                } else {
                    file_cursor = align_up(file_cursor, align);
                    section.file_off = file_cursor;
                    seg_file_end = seg_file_end.max(section.file_off + section.size);
                    file_cursor = section.file_off + section.size;
                }
            }

            let segment = self.segment_mut(&seg_name).expect("segment disappeared");
            segment.vm_addr = seg_start_vm;
            segment.file_off = seg_start_file;
            let raw_vm_size = seg_vm_end.saturating_sub(seg_start_vm);
            let raw_file_size = seg_file_end.saturating_sub(seg_start_file);
            segment.vm_size = if raw_vm_size == 0 || is_linkedit {
                raw_vm_size
            } else {
                align_up(raw_vm_size, PAGE_SIZE)
            };
            segment.file_size = if is_linkedit || raw_file_size == 0 {
                if is_linkedit {
                    0
                } else {
                    raw_file_size
                }
            } else {
                align_up(raw_file_size, PAGE_SIZE)
            };

            next_vm = if is_linkedit {
                seg_start_vm
            } else {
                seg_vm_end
            };
            next_file = if is_linkedit {
                seg_start_file
            } else {
                seg_file_end
            };
        }
    }
}

fn split_sections_after_atoms(sections: &mut Vec<OutputSection>, split_after_atoms: &[AtomId]) {
    if split_after_atoms.is_empty() {
        return;
    }
    let split_points: HashSet<AtomId> = split_after_atoms.iter().copied().collect();
    let mut out = Vec::with_capacity(sections.len());
    for mut section in std::mem::take(sections) {
        if section.atoms.len() < 2 || !section.synthetic_data.is_empty() {
            out.push(section);
            continue;
        }
        if !section
            .atoms
            .iter()
            .any(|placed| split_points.contains(&placed.atom))
        {
            out.push(section);
            continue;
        }
        let atoms = std::mem::take(&mut section.atoms);
        let last_idx = atoms.len().saturating_sub(1);
        let mut current = split_section_template(&section);
        for (idx, placed) in atoms.into_iter().enumerate() {
            let split_here = split_points.contains(&placed.atom) && idx != last_idx;
            current.atoms.push(placed);
            if split_here {
                out.push(current);
                current = split_section_template(&section);
            }
        }
        out.push(current);
    }
    *sections = out;
}

fn split_section_template(section: &OutputSection) -> OutputSection {
    OutputSection {
        segment: section.segment.clone(),
        name: section.name.clone(),
        kind: section.kind,
        align_pow2: section.align_pow2,
        flags: section.flags,
        reserved1: section.reserved1,
        reserved2: section.reserved2,
        reserved3: section.reserved3,
        atoms: Vec::new(),
        synthetic_offset: 0,
        synthetic_data: Vec::new(),
        addr: 0,
        size: 0,
        file_off: 0,
    }
}

fn insert_extra_sections(sections: &mut Vec<OutputSection>, extra_sections: &[ExtraOutputSection]) {
    for extra in extra_sections {
        let section = extra.section.clone();
        if let Some(anchor) = &extra.after_section {
            let insert_at = sections
                .iter()
                .rposition(|candidate| match anchor {
                    ExtraSectionAnchor::AfterSection { segment, name } => {
                        candidate.segment == *segment && candidate.name == *name
                    }
                    ExtraSectionAnchor::AfterAtom(atom_id) => candidate
                        .atoms
                        .last()
                        .map(|placed| placed.atom == *atom_id)
                        .unwrap_or(false),
                })
                .map(|idx| idx + 1)
                .unwrap_or_else(|| {
                    panic!(
                        "missing anchor {:?} for synthetic section {},{}",
                        anchor, section.segment, section.name
                    )
                });
            sections.insert(insert_at, section);
        } else {
            sections.push(section);
        }
    }
}

fn merge_synthetic_section(existing: &mut OutputSection, synthetic: OutputSection) {
    debug_assert_eq!(existing.segment, synthetic.segment);
    debug_assert_eq!(existing.name, synthetic.name);
    existing.align_pow2 =
        normalize_output_alignment(existing.kind, existing.align_pow2.max(synthetic.align_pow2));
    existing.flags = synthetic.flags;
    existing.reserved1 = synthetic.reserved1;
    existing.reserved2 = synthetic.reserved2;
    existing.reserved3 = synthetic.reserved3;
    if !synthetic.synthetic_data.is_empty() {
        existing
            .synthetic_data
            .extend_from_slice(&synthetic.synthetic_data);
    }
}

fn synthetic_data_precedes_atoms(section: &OutputSection) -> bool {
    section.segment == "__DATA" && section.name == "__data" && !section.synthetic_data.is_empty()
}

fn normalize_output_alignment(kind: crate::section::SectionKind, align_pow2: u8) -> u8 {
    match kind {
        crate::section::SectionKind::ThreadLocalRegular
        | crate::section::SectionKind::ThreadLocalZeroFill
        | crate::section::SectionKind::ThreadLocalVariables
        | crate::section::SectionKind::ThreadLocalVariablePointers
        | crate::section::SectionKind::ThreadLocalInitPointers => align_pow2.max(3),
        _ => align_pow2,
    }
}

fn build_segments(kind: OutputKind, sections: &[OutputSection]) -> Vec<OutputSegment> {
    let names: &[&str] = match kind {
        OutputKind::Executable => &EXEC_SEGMENTS,
        OutputKind::Dylib => &DYLIB_SEGMENTS,
    };
    let mut segments: Vec<OutputSegment> = names
        .iter()
        .filter(|name| standard_segment_required(kind, name, sections))
        .map(|name| OutputSegment {
            name: (*name).to_string(),
            sections: Vec::new(),
            vm_addr: 0,
            vm_size: 0,
            file_off: 0,
            file_size: 0,
            init_prot: segment_init_prot(name),
            max_prot: segment_max_prot(name),
            flags: segment_flags(name),
        })
        .collect();

    let mut custom_names: Vec<String> = sections
        .iter()
        .map(|section| section.segment.clone())
        .filter(|name| !names.contains(&name.as_str()))
        .collect();
    custom_names.sort();
    custom_names.dedup();

    let linkedit_idx = segments
        .iter()
        .position(|segment| segment.name == "__LINKEDIT")
        .unwrap_or(segments.len());
    for name in custom_names.into_iter().rev() {
        let prot = custom_segment_prot(&name, sections);
        segments.insert(
            linkedit_idx,
            OutputSegment {
                name,
                sections: Vec::new(),
                vm_addr: 0,
                vm_size: 0,
                file_off: 0,
                file_size: 0,
                init_prot: prot.0,
                max_prot: prot.1,
                flags: 0,
            },
        );
    }
    segments
}

fn standard_segment_required(kind: OutputKind, name: &&str, sections: &[OutputSection]) -> bool {
    match (kind, *name) {
        (OutputKind::Executable, "__PAGEZERO") | (_, "__TEXT") | (_, "__LINKEDIT") => true,
        _ => sections.iter().any(|section| section.segment == *name),
    }
}

fn segment_rank(kind: OutputKind, segment: &str) -> usize {
    let order: &[&str] = match kind {
        OutputKind::Executable => &EXEC_SEGMENTS,
        OutputKind::Dylib => &DYLIB_SEGMENTS,
    };
    order
        .iter()
        .position(|name| *name == segment)
        .unwrap_or(order.len())
}

fn section_rank(segment: &str, section: &str) -> usize {
    let order: &[&str] = match segment {
        "__TEXT" => &[
            "__text",
            "__thunks",
            "__stubs",
            "__stub_helper",
            "__cstring",
            "__const",
            "__literal16",
            "__unwind_info",
            "__eh_frame",
        ],
        "__DATA_CONST" => &["__got", "__const"],
        "__DATA" => &[
            "__la_symbol_ptr",
            "__data",
            "__thread_vars",
            "__thread_ptrs",
            "__thread_data",
            "__thread_bss",
            "__common",
            "__bss",
        ],
        "__LINKEDIT" => &[],
        _ => &[],
    };
    order
        .iter()
        .position(|name| *name == section)
        .unwrap_or(order.len())
}

fn segment_init_prot(name: &str) -> Prot {
    match name {
        "__PAGEZERO" => Prot::NONE,
        "__TEXT" => Prot::READ_EXECUTE,
        "__DATA_CONST" => Prot::READ_WRITE,
        "__DATA" => Prot::READ_WRITE,
        "__LINKEDIT" => Prot::READ_ONLY,
        _ => Prot::READ_WRITE,
    }
}

fn segment_max_prot(name: &str) -> Prot {
    match name {
        "__PAGEZERO" => Prot::NONE,
        "__TEXT" => Prot::READ_EXECUTE,
        "__DATA_CONST" => Prot::READ_WRITE,
        "__DATA" => Prot::READ_WRITE,
        "__LINKEDIT" => Prot::READ_ONLY,
        _ => Prot::READ_WRITE,
    }
}

fn segment_flags(name: &str) -> u32 {
    match name {
        "__DATA_CONST" => SG_READ_ONLY,
        _ => 0,
    }
}

fn custom_segment_prot(name: &str, sections: &[OutputSection]) -> (Prot, Prot) {
    let mut has_exec = false;
    let mut all_read_only = true;
    for section in sections.iter().filter(|section| section.segment == name) {
        if is_executable_kind(section.kind) {
            has_exec = true;
        }
        if !is_read_only_kind(section.kind) {
            all_read_only = false;
        }
    }

    if has_exec {
        (Prot::READ_EXECUTE, Prot::READ_EXECUTE)
    } else if all_read_only {
        (Prot::READ_ONLY, Prot::READ_ONLY)
    } else {
        (Prot::READ_WRITE, Prot::READ_WRITE)
    }
}

fn is_executable_kind(kind: crate::section::SectionKind) -> bool {
    matches!(
        kind,
        crate::section::SectionKind::Text
            | crate::section::SectionKind::SymbolStubs
            | crate::section::SectionKind::Coalesced
    )
}

fn is_read_only_kind(kind: crate::section::SectionKind) -> bool {
    matches!(
        kind,
        crate::section::SectionKind::ConstData
            | crate::section::SectionKind::CStringLiterals
            | crate::section::SectionKind::Literal4
            | crate::section::SectionKind::Literal8
            | crate::section::SectionKind::Literal16
            | crate::section::SectionKind::CompactUnwind
            | crate::section::SectionKind::EhFrame
    )
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::atom::{Atom, AtomFlags, AtomSection, AtomTable};
    use crate::input::ObjectFile;
    use crate::macho::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_MAGIC_64, MH_OBJECT, S_ATTR_PURE_INSTRUCTIONS,
        S_ATTR_SOME_INSTRUCTIONS, S_CSTRING_LITERALS, S_REGULAR, S_ZEROFILL,
    };
    use crate::macho::reader::MachHeader64;
    use crate::resolve::{DylibId, InputId, SymbolId};
    use crate::section::{InputSection, SectionKind};
    use crate::synth::{
        got::GotSection,
        stubs::{LazyPointerEntry, LazyPointerSection, StubEntry, StubsSection},
        SyntheticPlan,
    };

    use super::*;

    #[test]
    fn layout_orders_text_sections_like_ld() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout.o"),
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
                input_section(
                    "__TEXT",
                    "__cstring",
                    SectionKind::CStringLiterals,
                    0,
                    S_CSTRING_LITERALS,
                ),
                input_section(
                    "__TEXT",
                    "__text",
                    SectionKind::Text,
                    2,
                    S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                ),
                input_section("__TEXT", "__const", SectionKind::ConstData, 3, S_REGULAR),
                input_section("__DATA", "__bss", SectionKind::ZeroFill, 3, S_ZEROFILL),
            ],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(InputId(0), 2, AtomSection::Text, 0, 8, 2, vec![0; 8]));
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::CStringLiterals,
            0,
            6,
            0,
            b"hello\0".to_vec(),
        ));
        atoms.push(atom(
            InputId(0),
            3,
            AtomSection::ConstData,
            0,
            16,
            3,
            vec![1; 16],
        ));
        atoms.push(atom(
            InputId(0),
            4,
            AtomSection::ZeroFill,
            0,
            32,
            3,
            Vec::new(),
        ));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
        );

        let names: Vec<(&str, &str)> = layout
            .sections
            .iter()
            .map(|s| (s.segment.as_str(), s.name.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("__TEXT", "__text"),
                ("__TEXT", "__cstring"),
                ("__TEXT", "__const"),
                ("__DATA", "__bss"),
            ]
        );
    }

    #[test]
    fn layout_promotes_data_const_into_data_const_segment() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-const.o"),
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
            sections: vec![input_section(
                "__DATA",
                "__const",
                SectionKind::ConstData,
                3,
                S_REGULAR,
            )],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::ConstData,
            0,
            16,
            3,
            vec![1; 16],
        ));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
        );

        assert!(layout
            .sections
            .iter()
            .any(|section| section.segment == "__DATA_CONST" && section.name == "__const"));
        assert!(!layout
            .sections
            .iter()
            .any(|section| section.segment == "__DATA" && section.name == "__const"));
    }

    #[test]
    fn executable_layout_has_pagezero_and_zerofill_has_no_file_offset() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-bss.o"),
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
            sections: vec![input_section(
                "__DATA",
                "__bss",
                SectionKind::ZeroFill,
                4,
                S_ZEROFILL,
            )],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::ZeroFill,
            0,
            64,
            4,
            Vec::new(),
        ));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x300,
        );

        let pagezero = layout.segment("__PAGEZERO").unwrap();
        assert_eq!(pagezero.vm_addr, 0);
        assert_eq!(pagezero.vm_size, EXECUTABLE_TEXT_BASE);

        let bss = layout.sections.iter().find(|s| s.name == "__bss").unwrap();
        assert_eq!(bss.file_off, 0);
        assert!(bss.addr >= EXECUTABLE_TEXT_BASE + PAGE_SIZE);
    }

    #[test]
    fn layout_orders_common_before_bss() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-common-bss.o"),
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
                input_section("__DATA", "__common", SectionKind::ZeroFill, 3, S_ZEROFILL),
                input_section("__DATA", "__bss", SectionKind::ZeroFill, 3, S_ZEROFILL),
            ],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::ZeroFill,
            0,
            16,
            3,
            Vec::new(),
        ));
        atoms.push(atom(
            InputId(0),
            2,
            AtomSection::ZeroFill,
            0,
            32,
            3,
            Vec::new(),
        ));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
        );

        let names: Vec<(&str, &str)> = layout
            .sections
            .iter()
            .map(|section| (section.segment.as_str(), section.name.as_str()))
            .collect();
        assert_eq!(names, vec![("__DATA", "__common"), ("__DATA", "__bss")]);
    }

    #[test]
    fn file_backed_segments_round_to_page_boundaries() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-pages.o"),
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
                input_section(
                    "__TEXT",
                    "__text",
                    SectionKind::Text,
                    2,
                    S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                ),
                input_section("__DATA", "__data", SectionKind::Data, 3, S_REGULAR),
            ],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::Text,
            0,
            16,
            2,
            vec![0; 16],
        ));
        atoms.push(atom(InputId(0), 2, AtomSection::Data, 0, 8, 3, vec![0; 8]));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
        );

        let text = layout.segment("__TEXT").unwrap();
        let data = layout.segment("__DATA").unwrap();
        assert_eq!(text.file_size % PAGE_SIZE, 0);
        assert_eq!(text.vm_size % PAGE_SIZE, 0);
        assert_eq!(data.file_size % PAGE_SIZE, 0);
        assert_eq!(data.vm_size % PAGE_SIZE, 0);
    }

    #[test]
    fn layout_places_synthetic_import_sections_in_expected_order() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-synth.o"),
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
            sections: vec![input_section(
                "__TEXT",
                "__text",
                SectionKind::Text,
                2,
                S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            )],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(InputId(0), 1, AtomSection::Text, 0, 8, 2, vec![0; 8]));

        let plan = SyntheticPlan {
            got: GotSection {
                entries: vec![
                    crate::synth::got::GotEntry {
                        symbol: SymbolId(1),
                        weak_import: false,
                    },
                    crate::synth::got::GotEntry {
                        symbol: SymbolId(2),
                        weak_import: false,
                    },
                ],
                index: [(SymbolId(1), 0), (SymbolId(2), 1)].into_iter().collect(),
            },
            stubs: StubsSection {
                entries: vec![StubEntry {
                    symbol: SymbolId(1),
                    dylib: DylibId(0),
                    weak_import: false,
                }],
                index: [(SymbolId(1), 0)].into_iter().collect(),
            },
            lazy_pointers: LazyPointerSection {
                entries: vec![LazyPointerEntry {
                    symbol: SymbolId(1),
                    dylib: DylibId(0),
                    weak_import: false,
                }],
                index: [(SymbolId(1), 0)].into_iter().collect(),
            },
            thread_pointers: crate::synth::tlv::ThreadPointerSection {
                entries: Vec::new(),
                index: HashMap::new(),
            },
            direct_binds: Vec::new(),
            binder_symbol: Some(SymbolId(2)),
            tlv_bootstrap_symbol: None,
            needs_dyld_private: true,
        };

        let layout = Layout::build_with_synthetics(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
            Some(&plan),
        );

        let names: Vec<(&str, &str)> = layout
            .sections
            .iter()
            .map(|section| (section.segment.as_str(), section.name.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("__TEXT", "__text"),
                ("__TEXT", "__stubs"),
                ("__TEXT", "__stub_helper"),
                ("__DATA_CONST", "__got"),
                ("__DATA", "__la_symbol_ptr"),
                ("__DATA", "__data"),
            ]
        );

        let stubs = layout
            .sections
            .iter()
            .find(|section| section.name == "__stubs")
            .unwrap();
        assert_eq!(stubs.size, 12);
        assert_eq!(stubs.reserved2, 12);
        let got = layout
            .sections
            .iter()
            .find(|section| section.name == "__got")
            .unwrap();
        assert_eq!(got.size, 16);
        let helper = layout
            .sections
            .iter()
            .find(|section| section.name == "__stub_helper")
            .unwrap();
        assert_eq!(helper.size, 36);
        let lazy = layout
            .sections
            .iter()
            .find(|section| section.name == "__la_symbol_ptr")
            .unwrap();
        assert_eq!(lazy.size, 8);
        let dyld_private = layout
            .sections
            .iter()
            .find(|section| section.name == "__data")
            .unwrap();
        assert_eq!(dyld_private.size, 8);
    }

    #[test]
    fn synthetic_dyld_private_precedes_existing_data() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-data.o"),
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
            sections: vec![input_section(
                "__DATA",
                "__data",
                SectionKind::Data,
                3,
                S_REGULAR,
            )],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(
            InputId(0),
            1,
            AtomSection::Data,
            0,
            16,
            3,
            vec![0xaa; 16],
        ));

        let plan = SyntheticPlan {
            got: GotSection {
                entries: Vec::new(),
                index: HashMap::new(),
            },
            stubs: StubsSection {
                entries: Vec::new(),
                index: HashMap::new(),
            },
            lazy_pointers: LazyPointerSection {
                entries: Vec::new(),
                index: HashMap::new(),
            },
            thread_pointers: crate::synth::tlv::ThreadPointerSection {
                entries: Vec::new(),
                index: HashMap::new(),
            },
            direct_binds: Vec::new(),
            binder_symbol: None,
            tlv_bootstrap_symbol: None,
            needs_dyld_private: true,
        };

        let layout = Layout::build_with_synthetics(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
            Some(&plan),
        );

        let data = layout
            .sections
            .iter()
            .find(|section| section.segment == "__DATA" && section.name == "__data")
            .unwrap();
        assert_eq!(data.atoms.len(), 1);
        assert_eq!(data.synthetic_offset, 0);
        assert_eq!(data.synthetic_data.len(), 8);
        assert_eq!(data.atoms[0].offset, 8);
        assert_eq!(data.size, 24);
    }

    #[test]
    fn custom_segments_are_carried_opaquely_before_linkedit() {
        let object = ObjectFile {
            path: PathBuf::from("/tmp/layout-custom.o"),
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
            sections: vec![input_section(
                "__FOO",
                "__bar",
                SectionKind::Data,
                3,
                S_REGULAR,
            )],
            symbols: Vec::new(),
            strings: crate::string_table::StringTable::from_bytes(vec![0]),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        };

        let mut atoms = AtomTable::new();
        atoms.push(atom(InputId(0), 1, AtomSection::Data, 0, 8, 3, vec![0; 8]));

        let layout = Layout::build(
            OutputKind::Executable,
            &[LayoutInput {
                id: InputId(0),
                object: &object,
                load_order: 0,
                archive_member_offset: None,
            }],
            &atoms,
            0x200,
        );

        assert!(layout.segment("__FOO").is_some());
        let custom_idx = layout
            .segments
            .iter()
            .position(|segment| segment.name == "__FOO")
            .unwrap();
        let linkedit_idx = layout
            .segments
            .iter()
            .position(|segment| segment.name == "__LINKEDIT")
            .unwrap();
        assert!(custom_idx < linkedit_idx);
    }

    fn input_section(
        segname: &str,
        sectname: &str,
        kind: SectionKind,
        align_pow2: u32,
        flags: u32,
    ) -> InputSection {
        InputSection {
            segname: segname.into(),
            sectname: sectname.into(),
            kind,
            addr: 0,
            size: 0,
            align_pow2,
            flags,
            offset: 0,
            reloff: 0,
            nreloc: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: Vec::new(),
            raw_relocs: Vec::new(),
        }
    }

    fn atom(
        origin: InputId,
        input_section: u8,
        section: AtomSection,
        input_offset: u32,
        size: u32,
        align_pow2: u8,
        data: Vec<u8>,
    ) -> Atom {
        Atom {
            id: crate::resolve::AtomId(0),
            origin,
            input_section,
            section,
            input_offset,
            size,
            align_pow2,
            owner: None,
            alt_entries: Vec::new(),
            data,
            flags: AtomFlags::NONE,
            parent_of: None,
        }
    }
}
