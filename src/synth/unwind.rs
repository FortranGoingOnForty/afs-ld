use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::atom::{Atom, AtomSection, AtomTable};
use crate::layout::{Layout, LayoutInput};
use crate::macho::constants::S_REGULAR;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc};
use crate::resolve::{AtomId, InputId, Symbol, SymbolTable};
use crate::section::{OutputSection, SectionKind};

const PAGE_SIZE: usize = 4096;
const UNWIND_INFO_VERSION: u32 = 1;
const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
const FIRST_LEVEL_ENTRY_SIZE: usize = 12;
const COMPRESSED_PAGE_HEADER_SIZE: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindError {
    pub input: PathBuf,
    pub atom: AtomId,
    pub detail: String,
}

impl fmt::Display for UnwindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: unwind synthesis for atom {:?}: {}",
            self.input.display(),
            self.atom,
            self.detail
        )
    }
}

impl std::error::Error for UnwindError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnwindRecord {
    function_offset: u32,
    code_len: u32,
    encoding: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompressedPage {
    start_function_offset: u32,
    entries: Vec<u32>,
    local_encodings: Vec<u32>,
}

pub fn synthesize(
    layout: &mut Layout,
    inputs: &[LayoutInput<'_>],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
) -> Result<bool, UnwindError> {
    let mut changed = remove_compact_unwind_sections(layout);
    let records = collect_records(layout, inputs, atoms, sym_table)?;
    if records.is_empty() {
        changed |= remove_unwind_info_section(layout);
        if changed {
            prune_empty_segments(layout);
        }
        return Ok(changed);
    }

    let bytes = serialize_unwind_info(&records);
    let section_changed = upsert_unwind_info_section(layout, bytes);
    if changed || section_changed {
        prune_empty_segments(layout);
    }
    Ok(changed || section_changed)
}

fn collect_records(
    layout: &Layout,
    inputs: &[LayoutInput<'_>],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
) -> Result<Vec<UnwindRecord>, UnwindError> {
    let text_base = layout
        .segment("__TEXT")
        .map(|segment| segment.vm_addr)
        .unwrap_or(0);
    let input_map: HashMap<InputId, &crate::input::ObjectFile> = inputs
        .iter()
        .map(|input| (input.id, input.object))
        .collect();
    let mut reloc_cache: HashMap<(InputId, u8), Vec<Reloc>> = HashMap::new();
    for input in inputs {
        for (section_idx, section) in input.object.sections.iter().enumerate() {
            if section.nreloc == 0 {
                continue;
            }
            let raws = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc).map_err(|err| {
                UnwindError {
                    input: input.object.path.clone(),
                    atom: AtomId(0),
                    detail: err.to_string(),
                }
            })?;
            let relocs = parse_relocs(&raws).map_err(|err| UnwindError {
                input: input.object.path.clone(),
                atom: AtomId(0),
                detail: err.to_string(),
            })?;
            reloc_cache.insert((input.id, (section_idx + 1) as u8), relocs);
        }
    }

    let mut records = Vec::new();
    for (atom_id, atom) in atoms.iter() {
        if atom.section != AtomSection::CompactUnwind {
            continue;
        }
        let Some(obj) = input_map.get(&atom.origin) else {
            return Err(UnwindError {
                input: PathBuf::from("<missing object>"),
                atom: atom_id,
                detail: "missing parsed object".to_string(),
            });
        };
        if atom.data.len() < 32 {
            return Err(UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: format!(
                    "compact-unwind atom is {} bytes, expected 32-byte record",
                    atom.data.len()
                ),
            });
        }
        let relocs = reloc_cache
            .get(&(atom.origin, atom.input_section))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let function_addr =
            resolve_function_address(atom_id, atom, obj, relocs, atoms, sym_table, layout)?;
        if has_nonzero_u64(atom, 16) || has_reloc_at(relocs, atom.input_offset + 16) {
            return Err(UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: "personality records are not implemented yet".to_string(),
            });
        }
        if has_nonzero_u64(atom, 24) || has_reloc_at(relocs, atom.input_offset + 24) {
            return Err(UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: "LSDA records are not implemented yet".to_string(),
            });
        }

        let function_offset =
            u32::try_from(function_addr.saturating_sub(text_base)).map_err(|_| UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: "function start exceeds 32-bit unwind offset range".to_string(),
            })?;
        records.push(UnwindRecord {
            function_offset,
            code_len: u32::from_le_bytes(atom.data[8..12].try_into().unwrap()),
            encoding: u32::from_le_bytes(atom.data[12..16].try_into().unwrap()),
        });
    }

    records.sort_by_key(|record| record.function_offset);
    Ok(records)
}

fn resolve_function_address(
    atom_id: AtomId,
    atom: &Atom,
    obj: &crate::input::ObjectFile,
    relocs: &[Reloc],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
    layout: &Layout,
) -> Result<u64, UnwindError> {
    if let Some(parent) = atom.parent_of {
        return layout.atom_addr(parent).ok_or_else(|| UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: format!("function atom {:?} missing from final layout", parent),
        });
    }
    let Some(reloc) = relocs
        .iter()
        .find(|reloc| reloc.offset == atom.input_offset)
    else {
        return Err(UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: "function_start reloc is missing".to_string(),
        });
    };
    match reloc.referent {
        Referent::Section(section_idx) => {
            let target_offset = read_u64(atom, 0)? as u32;
            let Some((candidate_id, candidate)) = atoms.iter().find(|(_, candidate)| {
                candidate.origin == atom.origin
                    && candidate.input_section == section_idx
                    && candidate.input_offset <= target_offset
                    && target_offset < candidate.input_offset + candidate.size
            }) else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!(
                        "function_start points at missing input atom section {} offset 0x{:x}",
                        section_idx, target_offset
                    ),
                });
            };
            let Some(base_addr) = layout.atom_addr(candidate_id) else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("function atom {:?} missing from final layout", candidate_id),
                });
            };
            Ok(base_addr + (target_offset - candidate.input_offset) as u64)
        }
        Referent::Symbol(sym_idx) => {
            let input_symbol = obj
                .symbols
                .get(sym_idx as usize)
                .ok_or_else(|| UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("function_start symbol {} is out of range", sym_idx),
                })?;
            let name = obj.symbol_name(input_symbol).map_err(|err| UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: err.to_string(),
            })?;
            let Some((_, symbol)) = sym_table
                .iter()
                .find(|(_, symbol)| sym_table.interner.resolve(symbol.name()) == name)
            else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("function_start symbol `{name}` was not resolved"),
                });
            };
            match symbol {
                Symbol::Defined { atom, value, .. } => {
                    let Some(base_addr) = layout.atom_addr(*atom) else {
                        return Err(UnwindError {
                            input: obj.path.clone(),
                            atom: atom_id,
                            detail: format!("function atom {:?} missing from final layout", atom),
                        });
                    };
                    Ok(base_addr + *value)
                }
                other => Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!(
                        "function_start symbol `{name}` resolved to unsupported kind {:?}",
                        other.kind()
                    ),
                }),
            }
        }
    }
}

fn read_u64(atom: &Atom, offset: usize) -> Result<u64, UnwindError> {
    let end = offset + 8;
    if end > atom.data.len() {
        return Err(UnwindError {
            input: PathBuf::from("<compact unwind>"),
            atom: atom.id,
            detail: format!("record field at 0x{offset:x} overruns atom data"),
        });
    }
    Ok(u64::from_le_bytes(
        atom.data[offset..end].try_into().unwrap(),
    ))
}

fn has_nonzero_u64(atom: &Atom, offset: usize) -> bool {
    read_u64(atom, offset)
        .map(|value| value != 0)
        .unwrap_or(false)
}

fn has_reloc_at(relocs: &[Reloc], offset: u32) -> bool {
    relocs.iter().any(|reloc| reloc.offset == offset)
}

fn serialize_unwind_info(records: &[UnwindRecord]) -> Vec<u8> {
    let pages = build_pages(records);
    let indices_offset = 7 * 4;
    let indices_count = (pages.len() + 1) as u32;
    let second_level_start =
        align_up((indices_offset + indices_count as usize * FIRST_LEVEL_ENTRY_SIZE) as u32, 16)
            as usize;
    let page_blobs: Vec<Vec<u8>> = pages.iter().map(serialize_compressed_page).collect();
    let lsda_offset = second_level_start as u32;
    let sentinel = records
        .last()
        .map(|record| record.function_offset + record.code_len)
        .unwrap_or(0);

    let mut out = Vec::new();
    out.extend_from_slice(&UNWIND_INFO_VERSION.to_le_bytes());
    out.extend_from_slice(&(indices_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(indices_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(indices_offset as u32).to_le_bytes());
    out.extend_from_slice(&indices_count.to_le_bytes());

    let mut page_offset = second_level_start as u32;
    for page in &pages {
        out.extend_from_slice(&page.start_function_offset.to_le_bytes());
        out.extend_from_slice(&page_offset.to_le_bytes());
        out.extend_from_slice(&lsda_offset.to_le_bytes());
        page_offset += serialize_compressed_page(page).len() as u32;
    }
    out.extend_from_slice(&sentinel.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&lsda_offset.to_le_bytes());
    while out.len() < second_level_start {
        out.push(0);
    }

    for blob in page_blobs {
        out.extend_from_slice(&blob);
    }

    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out
}

fn build_pages(records: &[UnwindRecord]) -> Vec<CompressedPage> {
    let mut pages = Vec::new();
    let mut current: Option<CompressedPage> = None;

    for record in records {
        let page = current.get_or_insert_with(|| CompressedPage {
            start_function_offset: record.function_offset,
            entries: Vec::new(),
            local_encodings: Vec::new(),
        });

        let mut encodings = page.local_encodings.clone();
        if encodings
            .iter()
            .all(|encoding| *encoding != record.encoding)
        {
            encodings.push(record.encoding);
        }
        let delta = record
            .function_offset
            .saturating_sub(page.start_function_offset);
        let projected_size =
            COMPRESSED_PAGE_HEADER_SIZE + (page.entries.len() + 1) * 4 + encodings.len() * 4;
        if projected_size > PAGE_SIZE && !page.entries.is_empty() {
            pages.push(current.take().unwrap());
            current = Some(CompressedPage {
                start_function_offset: record.function_offset,
                entries: Vec::new(),
                local_encodings: Vec::new(),
            });
        }

        let page = current.as_mut().unwrap();
        let encoding_index = if let Some(index) = page
            .local_encodings
            .iter()
            .position(|encoding| *encoding == record.encoding)
        {
            index
        } else {
            page.local_encodings.push(record.encoding);
            page.local_encodings.len() - 1
        };
        page.entries
            .push(((encoding_index as u32) << 24) | (delta & 0x00ff_ffff));
    }

    if let Some(page) = current {
        pages.push(page);
    }
    pages
}

fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .unwrap_or(value)
}

fn serialize_compressed_page(page: &CompressedPage) -> Vec<u8> {
    let entry_offset = COMPRESSED_PAGE_HEADER_SIZE as u16;
    let encoding_offset = entry_offset + (page.entries.len() * 4) as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&UNWIND_SECOND_LEVEL_COMPRESSED.to_le_bytes());
    out.extend_from_slice(&entry_offset.to_le_bytes());
    out.extend_from_slice(&(page.entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&encoding_offset.to_le_bytes());
    out.extend_from_slice(&(page.local_encodings.len() as u16).to_le_bytes());
    for entry in &page.entries {
        out.extend_from_slice(&entry.to_le_bytes());
    }
    for encoding in &page.local_encodings {
        out.extend_from_slice(&encoding.to_le_bytes());
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn remove_compact_unwind_sections(layout: &mut Layout) -> bool {
    let before = layout.sections.len();
    layout
        .sections
        .retain(|section| section.kind != SectionKind::CompactUnwind);
    before != layout.sections.len()
}

fn remove_unwind_info_section(layout: &mut Layout) -> bool {
    let before = layout.sections.len();
    layout
        .sections
        .retain(|section| !(section.segment == "__TEXT" && section.name == "__unwind_info"));
    before != layout.sections.len()
}

fn upsert_unwind_info_section(layout: &mut Layout, bytes: Vec<u8>) -> bool {
    if let Some(section) = layout
        .sections
        .iter_mut()
        .find(|section| section.segment == "__TEXT" && section.name == "__unwind_info")
    {
        let changed = section.synthetic_data.len() != bytes.len();
        section.kind = SectionKind::Regular;
        section.align_pow2 = 2;
        section.flags = S_REGULAR;
        section.reserved1 = 0;
        section.reserved2 = 0;
        section.reserved3 = 0;
        section.atoms.clear();
        section.synthetic_offset = 0;
        section.synthetic_data = bytes;
        section.size = section.synthetic_data.len() as u64;
        return changed;
    }

    let insert_idx = layout
        .sections
        .iter()
        .position(|section| section.segment == "__TEXT" && section.name == "__eh_frame")
        .or_else(|| {
            layout
                .sections
                .iter()
                .rposition(|section| section.segment == "__TEXT")
                .map(|idx| idx + 1)
        })
        .unwrap_or(layout.sections.len());
    layout.sections.insert(
        insert_idx,
        OutputSection {
            segment: "__TEXT".into(),
            name: "__unwind_info".into(),
            kind: SectionKind::Regular,
            align_pow2: 2,
            flags: S_REGULAR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            atoms: Vec::new(),
            synthetic_offset: 0,
            synthetic_data: bytes,
            addr: 0,
            size: 0,
            file_off: 0,
        },
    );
    let section = &mut layout.sections[insert_idx];
    section.size = section.synthetic_data.len() as u64;
    true
}

fn prune_empty_segments(layout: &mut Layout) {
    let standard: &[&str] = match layout.kind {
        crate::OutputKind::Executable => &[
            "__PAGEZERO",
            "__TEXT",
            "__DATA_CONST",
            "__DATA",
            "__LINKEDIT",
        ],
        crate::OutputKind::Dylib => &["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"],
    };
    layout.segments.retain(|segment| {
        standard.iter().any(|name| *name == segment.name)
            || layout
                .sections
                .iter()
                .any(|section| section.segment == segment.name)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_single_leaf_record_matches_apple_shape() {
        let bytes = serialize_unwind_info(&[UnwindRecord {
            function_offset: 0x348,
            code_len: 0x14,
            encoding: 0x0200_1000,
        }]);
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(
            words,
            vec![
                1,
                0x1c,
                0,
                0x1c,
                0,
                0x1c,
                2,
                0x348,
                0x40,
                0x40,
                0x35c,
                0,
                0x40,
                0,
                0,
                0,
                3,
                0x0001_000c,
                0x0001_0010,
                0,
                0x0200_1000,
                0,
            ]
        );
    }

    #[test]
    fn serialize_two_records_uses_compressed_entries() {
        let bytes = serialize_unwind_info(&[
            UnwindRecord {
                function_offset: 0x348,
                code_len: 0x8,
                encoding: 0x0200_0000,
            },
            UnwindRecord {
                function_offset: 0x350,
                code_len: 0x20,
                encoding: 0x0400_0000,
            },
        ]);
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(
            words,
            vec![
                1,
                0x1c,
                0,
                0x1c,
                0,
                0x1c,
                2,
                0x348,
                0x40,
                0x40,
                0x370,
                0,
                0x40,
                0,
                0,
                0,
                3,
                0x0002_000c,
                0x0002_0014,
                0,
                0x0100_0008,
                0x0200_0000,
                0x0400_0000,
                0,
            ]
        );
    }
}
