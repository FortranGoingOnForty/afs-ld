use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::atom::{Atom, AtomSection, AtomTable};
use crate::layout::{Layout, LayoutInput};
use crate::macho::constants::S_REGULAR;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc};
use crate::resolve::{AtomId, InputId, Symbol, SymbolTable};
use crate::section::{OutputSection, SectionKind};
use crate::synth::SyntheticPlan;

const PAGE_SIZE: usize = 4096;
const UNWIND_INFO_VERSION: u32 = 1;
const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
const FIRST_LEVEL_ENTRY_SIZE: usize = 12;
const FIRST_LEVEL_INDEX_GAP_SIZE: usize = FIRST_LEVEL_ENTRY_SIZE;
const COMPRESSED_PAGE_HEADER_SIZE: usize = 12;
const UNWIND_HAS_LSDA: u32 = 0x4000_0000;
const UNWIND_PERSONALITY_MASK: u32 = 0x3000_0000;
const UNWIND_PERSONALITY_SHIFT: u32 = 28;
const UNWIND_ARM64_MODE_MASK: u32 = 0x0f00_0000;
const UNWIND_ARM64_MODE_DWARF: u32 = 0x0300_0000;
const UNWIND_ARM64_DWARF_SECTION_OFFSET_MASK: u32 = 0x00ff_ffff;
const COMPACT_UNWIND_FUNCTION_OFFSET: usize = 0;
const COMPACT_UNWIND_PERSONALITY_OFFSET: usize = 16;
const COMPACT_UNWIND_LSDA_OFFSET: usize = 24;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindReadError {
    Truncated(&'static str),
    UnsupportedVersion(u32),
    UnsupportedSecondLevelPageKind(u32),
    BadFirstLevelIndexOrder { previous: u32, next: u32 },
    BadEncodingIndex { index: u32, max: u32 },
    TooManyPersonalities(usize),
}

impl fmt::Display for UnwindReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnwindReadError::Truncated(what) => write!(f, "truncated {what}"),
            UnwindReadError::UnsupportedVersion(version) => {
                write!(f, "unsupported unwind info version {version}")
            }
            UnwindReadError::UnsupportedSecondLevelPageKind(kind) => {
                write!(f, "unsupported second-level page kind {kind}")
            }
            UnwindReadError::BadFirstLevelIndexOrder { previous, next } => write!(
                f,
                "first-level index is not strictly ascending ({previous:#x} then {next:#x})"
            ),
            UnwindReadError::BadEncodingIndex { index, max } => {
                write!(
                    f,
                    "encoding index {index} exceeds decoded encoding table size {max}"
                )
            }
            UnwindReadError::TooManyPersonalities(count) => {
                write!(
                    f,
                    "unwind info needs {count} personalities but only 3 are encodable"
                )
            }
        }
    }
}

impl std::error::Error for UnwindReadError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedUnwindRecord {
    pub function_offset: u32,
    pub encoding: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUnwindInfo {
    pub version: u32,
    pub personalities: Vec<u32>,
    pub lsdas: Vec<DecodedLsdaRecord>,
    pub records: Vec<DecodedUnwindRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnwindRecord {
    function_offset: u32,
    code_len: u32,
    encoding: u32,
    personality_offset: Option<u32>,
    lsda_offset: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedLsdaRecord {
    pub function_offset: u32,
    pub lsda_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LsdaRecord {
    function_offset: u32,
    lsda_offset: u32,
}

type FinalizedUnwindTables = (Vec<UnwindRecord>, Vec<u32>, Vec<LsdaRecord>);

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
    synthetic_plan: &SyntheticPlan,
) -> Result<bool, UnwindError> {
    let mut changed = remove_compact_unwind_sections(layout);
    let records = collect_records(layout, inputs, atoms, sym_table, synthetic_plan)?;
    if records.is_empty() {
        changed |= remove_unwind_info_section(layout);
        if changed {
            prune_empty_segments(layout);
        }
        return Ok(changed);
    }

    let bytes = serialize_unwind_info(&records).map_err(|err| UnwindError {
        input: PathBuf::from("<synthetic unwind>"),
        atom: AtomId(0),
        detail: err.to_string(),
    })?;
    validate_serialized_unwind_info(&bytes, &records).map_err(|err| UnwindError {
        input: PathBuf::from("<synthetic unwind>"),
        atom: AtomId(0),
        detail: err.to_string(),
    })?;
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
    synthetic_plan: &SyntheticPlan,
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
        let personality_offset = resolve_metadata_offset(
            atom_id,
            atom,
            obj,
            relocs,
            atoms,
            sym_table,
            layout,
            synthetic_plan,
            COMPACT_UNWIND_PERSONALITY_OFFSET,
            true,
            "personality",
        )?
        .map(|addr| {
            u32::try_from(addr.saturating_sub(text_base)).map_err(|_| UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: "personality target exceeds 32-bit unwind offset range".to_string(),
            })
        })
        .transpose()?;
        let lsda_offset = resolve_metadata_offset(
            atom_id,
            atom,
            obj,
            relocs,
            atoms,
            sym_table,
            layout,
            synthetic_plan,
            COMPACT_UNWIND_LSDA_OFFSET,
            false,
            "LSDA",
        )?
        .map(|addr| {
            u32::try_from(addr.saturating_sub(text_base)).map_err(|_| UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: "LSDA target exceeds 32-bit unwind offset range".to_string(),
            })
        })
        .transpose()?;

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
            personality_offset,
            lsda_offset,
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
    resolve_reference_address(
        atom_id,
        atom,
        obj,
        atoms,
        sym_table,
        layout,
        None,
        reloc.referent,
        read_u64(atom, COMPACT_UNWIND_FUNCTION_OFFSET)? as u32,
        "function_start",
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_metadata_offset(
    atom_id: AtomId,
    atom: &Atom,
    obj: &crate::input::ObjectFile,
    relocs: &[Reloc],
    atoms: &AtomTable,
    sym_table: &SymbolTable,
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    field_offset: usize,
    allow_import_got: bool,
    label: &str,
) -> Result<Option<u64>, UnwindError> {
    let raw_value = read_u64(atom, field_offset)?;
    let reloc = relocs
        .iter()
        .find(|reloc| reloc.offset == atom.input_offset + field_offset as u32);
    if raw_value == 0 && reloc.is_none() {
        return Ok(None);
    }
    let Some(reloc) = reloc else {
        return Err(UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: format!("{label} field has inline value but no relocation"),
        });
    };
    Ok(Some(resolve_reference_address(
        atom_id,
        atom,
        obj,
        atoms,
        sym_table,
        layout,
        Some(synthetic_plan),
        reloc.referent,
        raw_value as u32,
        label,
        allow_import_got,
    )?))
}

#[allow(clippy::too_many_arguments)]
fn resolve_reference_address(
    atom_id: AtomId,
    atom: &Atom,
    obj: &crate::input::ObjectFile,
    atoms: &AtomTable,
    sym_table: &SymbolTable,
    layout: &Layout,
    synthetic_plan: Option<&SyntheticPlan>,
    referent: Referent,
    target_offset: u32,
    label: &str,
    allow_import_got: bool,
) -> Result<u64, UnwindError> {
    match referent {
        Referent::Section(section_idx) => {
            let input_section = obj
                .sections
                .get((section_idx as usize).saturating_sub(1))
                .ok_or_else(|| UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("{label} section {} is out of range", section_idx),
                })?;
            let Some((candidate_id, candidate)) = atoms.iter().find(|(_, candidate)| {
                candidate.origin == atom.origin
                    && candidate.input_section == section_idx
                    && input_section.addr + candidate.input_offset as u64 <= target_offset as u64
                    && (target_offset as u64)
                        < input_section.addr + candidate.input_offset as u64 + candidate.size as u64
            }) else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!(
                        "{label} points at missing input atom section {} offset 0x{:x}",
                        section_idx, target_offset
                    ),
                });
            };
            let Some(base_addr) = layout.atom_addr(candidate_id) else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("{label} atom {:?} missing from final layout", candidate_id),
                });
            };
            let atom_input_addr = input_section.addr + candidate.input_offset as u64;
            Ok(base_addr + (target_offset as u64 - atom_input_addr))
        }
        Referent::Symbol(sym_idx) => {
            let input_symbol = obj
                .symbols
                .get(sym_idx as usize)
                .ok_or_else(|| UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("{label} symbol {} is out of range", sym_idx),
                })?;
            let name = obj.symbol_name(input_symbol).map_err(|err| UnwindError {
                input: obj.path.clone(),
                atom: atom_id,
                detail: err.to_string(),
            })?;
            let Some((symbol_id, symbol)) = sym_table
                .iter()
                .find(|(_, symbol)| sym_table.interner.resolve(symbol.name()) == name)
            else {
                return Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!("{label} symbol `{name}` was not resolved"),
                });
            };
            match symbol {
                Symbol::Defined {
                    atom: target_atom,
                    value,
                    ..
                } => {
                    let Some(base_addr) = layout.atom_addr(*target_atom) else {
                        return Err(UnwindError {
                            input: obj.path.clone(),
                            atom: atom_id,
                            detail: format!(
                                "{label} atom {:?} missing from final layout",
                                target_atom
                            ),
                        });
                    };
                    Ok(base_addr + *value)
                }
                Symbol::DylibImport { .. } if allow_import_got => {
                    personality_got_addr(layout, synthetic_plan, symbol_id, atom_id, obj, label)
                }
                other => Err(UnwindError {
                    input: obj.path.clone(),
                    atom: atom_id,
                    detail: format!(
                        "{label} symbol `{name}` resolved to unsupported kind {:?}",
                        other.kind()
                    ),
                }),
            }
        }
    }
}

fn personality_got_addr(
    layout: &Layout,
    synthetic_plan: Option<&SyntheticPlan>,
    symbol_id: crate::resolve::SymbolId,
    atom_id: AtomId,
    obj: &crate::input::ObjectFile,
    label: &str,
) -> Result<u64, UnwindError> {
    let Some(plan) = synthetic_plan else {
        return Err(UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: format!("{label} import needs a synthetic GOT slot"),
        });
    };
    let Some((idx, _)) = plan.got.get(symbol_id) else {
        return Err(UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: format!("{label} import is missing synthetic GOT planning"),
        });
    };
    let Some(section) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA_CONST" && section.name == "__got")
    else {
        return Err(UnwindError {
            input: obj.path.clone(),
            atom: atom_id,
            detail: format!("{label} import is missing the output __got section"),
        });
    };
    Ok(section.addr + (idx as u64) * 8)
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

fn serialize_unwind_info(records: &[UnwindRecord]) -> Result<Vec<u8>, UnwindReadError> {
    let (records, personalities, lsdas) = finalize_unwind_records(records)?;
    let common_encodings = select_common_encodings(&records);
    let pages = build_pages(&records, &common_encodings);
    let common_encodings_offset = 7 * 4;
    let common_encodings_count = common_encodings.len() as u32;
    let personalities_offset = common_encodings_offset + common_encodings_count as usize * 4;
    let indices_offset = personalities_offset + personalities.len() * 4;
    let indices_count = (pages.len() + 1) as u32;
    let lsdas_offset = indices_offset
        + indices_count as usize * FIRST_LEVEL_ENTRY_SIZE
        + FIRST_LEVEL_INDEX_GAP_SIZE;
    let second_level_start = lsdas_offset + lsdas.len() * 8;
    let page_blobs: Vec<Vec<u8>> = pages.iter().map(serialize_compressed_page).collect();
    let sentinel = records
        .last()
        .map(|record| record.function_offset + record.code_len)
        .unwrap_or(0);

    let mut out = Vec::new();
    out.extend_from_slice(&UNWIND_INFO_VERSION.to_le_bytes());
    out.extend_from_slice(&(common_encodings_offset as u32).to_le_bytes());
    out.extend_from_slice(&common_encodings_count.to_le_bytes());
    out.extend_from_slice(&(personalities_offset as u32).to_le_bytes());
    out.extend_from_slice(&(personalities.len() as u32).to_le_bytes());
    out.extend_from_slice(&(indices_offset as u32).to_le_bytes());
    out.extend_from_slice(&indices_count.to_le_bytes());

    for encoding in &common_encodings {
        out.extend_from_slice(&encoding.to_le_bytes());
    }
    for personality in &personalities {
        out.extend_from_slice(&personality.to_le_bytes());
    }

    let mut page_lsda_index = 0usize;
    let mut page_offset = second_level_start as u32;
    for (page_idx, page) in pages.iter().enumerate() {
        let next_page_start = pages
            .get(page_idx + 1)
            .map(|page| page.start_function_offset)
            .unwrap_or(sentinel);
        while page_lsda_index < lsdas.len()
            && lsdas[page_lsda_index].function_offset < page.start_function_offset
        {
            page_lsda_index += 1;
        }
        let lsda_index_offset = lsdas_offset as u32 + (page_lsda_index as u32) * 8;
        out.extend_from_slice(&page.start_function_offset.to_le_bytes());
        out.extend_from_slice(&page_offset.to_le_bytes());
        out.extend_from_slice(&lsda_index_offset.to_le_bytes());
        while page_lsda_index < lsdas.len()
            && lsdas[page_lsda_index].function_offset < next_page_start
        {
            page_lsda_index += 1;
        }
        page_offset += serialize_compressed_page(page).len() as u32;
    }
    out.extend_from_slice(&sentinel.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(lsdas_offset as u32 + (lsdas.len() as u32) * 8).to_le_bytes());

    while out.len() < lsdas_offset {
        out.push(0);
    }
    for lsda in &lsdas {
        out.extend_from_slice(&lsda.function_offset.to_le_bytes());
        out.extend_from_slice(&lsda.lsda_offset.to_le_bytes());
    }

    while out.len() < second_level_start {
        out.push(0);
    }

    for blob in page_blobs {
        out.extend_from_slice(&blob);
    }

    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    Ok(out)
}

pub fn decode_unwind_info(bytes: &[u8]) -> Result<DecodedUnwindInfo, UnwindReadError> {
    if bytes.len() < 28 {
        return Err(UnwindReadError::Truncated("unwind_info header"));
    }
    let version = read_u32(bytes, 0, "unwind_info version")?;
    if version != UNWIND_INFO_VERSION {
        return Err(UnwindReadError::UnsupportedVersion(version));
    }
    let common_encodings_offset = read_u32(bytes, 4, "common encodings offset")? as usize;
    let common_encodings_count = read_u32(bytes, 8, "common encodings count")? as usize;
    let personalities_offset = read_u32(bytes, 12, "personalities offset")? as usize;
    let personalities_count = read_u32(bytes, 16, "personalities count")? as usize;
    let indices_offset = read_u32(bytes, 20, "indices offset")? as usize;
    let indices_count = read_u32(bytes, 24, "indices count")? as usize;

    let common_encodings = read_u32_array(
        bytes,
        common_encodings_offset,
        common_encodings_count,
        "common encodings",
    )?;
    let personalities = read_u32_array(
        bytes,
        personalities_offset,
        personalities_count,
        "personality array",
    )?;
    let mut index_starts = Vec::new();
    let mut index_lsda_offsets = Vec::new();
    for idx in 0..indices_count {
        let entry_off = indices_offset + idx * FIRST_LEVEL_ENTRY_SIZE;
        if entry_off + FIRST_LEVEL_ENTRY_SIZE > bytes.len() {
            return Err(UnwindReadError::Truncated("first-level index"));
        }
        index_starts.push(read_u32(bytes, entry_off, "first-level function offset")?);
        index_lsda_offsets.push(read_u32(bytes, entry_off + 8, "first-level lsda offset")?);
    }
    for pair in index_starts.windows(2) {
        if pair[0] > pair[1] {
            return Err(UnwindReadError::BadFirstLevelIndexOrder {
                previous: pair[0],
                next: pair[1],
            });
        }
    }

    let mut lsdas = Vec::new();
    if let (Some(&lsda_start), Some(&lsda_end)) =
        (index_lsda_offsets.first(), index_lsda_offsets.last())
    {
        let start = lsda_start as usize;
        let end = lsda_end as usize;
        if end < start {
            return Err(UnwindReadError::Truncated("lsda index array"));
        }
        let mut entry_off = start;
        while entry_off < end {
            if entry_off + 8 > bytes.len() {
                return Err(UnwindReadError::Truncated("lsda index entry"));
            }
            lsdas.push(DecodedLsdaRecord {
                function_offset: read_u32(bytes, entry_off, "lsda function offset")?,
                lsda_offset: read_u32(bytes, entry_off + 4, "lsda target offset")?,
            });
            entry_off += 8;
        }
    }

    let mut records = Vec::new();
    for idx in 0..indices_count.saturating_sub(1) {
        let entry_off = indices_offset + idx * FIRST_LEVEL_ENTRY_SIZE;
        let function_offset = read_u32(bytes, entry_off, "first-level function offset")?;
        let second_level_off = read_u32(bytes, entry_off + 4, "second-level page offset")? as usize;
        let kind = read_u32(bytes, second_level_off, "second-level page kind")?;
        match kind {
            UNWIND_SECOND_LEVEL_COMPRESSED => {
                let entries_off = second_level_off
                    + read_u16(bytes, second_level_off + 4, "page entry offset")? as usize;
                let entry_count =
                    read_u16(bytes, second_level_off + 6, "page entry count")? as usize;
                let encodings_off = second_level_off
                    + read_u16(bytes, second_level_off + 8, "page encoding offset")? as usize;
                let encoding_count =
                    read_u16(bytes, second_level_off + 10, "page encoding count")? as usize;
                let local_encodings =
                    read_u32_array(bytes, encodings_off, encoding_count, "page-local encodings")?;
                for entry_idx in 0..entry_count {
                    let word =
                        read_u32(bytes, entries_off + entry_idx * 4, "compressed page entry")?;
                    let encoding_index = word >> 24;
                    let function_delta = word & 0x00ff_ffff;
                    let encoding = if (encoding_index as usize) < common_encodings.len() {
                        common_encodings[encoding_index as usize]
                    } else {
                        let local_idx = encoding_index as usize - common_encodings.len();
                        *local_encodings.get(local_idx).ok_or_else(|| {
                            UnwindReadError::BadEncodingIndex {
                                index: encoding_index,
                                max: (common_encodings.len() + local_encodings.len()) as u32,
                            }
                        })?
                    };
                    records.push(DecodedUnwindRecord {
                        function_offset: function_offset + function_delta,
                        encoding,
                    });
                }
            }
            UNWIND_SECOND_LEVEL_REGULAR => {
                return Err(UnwindReadError::UnsupportedSecondLevelPageKind(kind));
            }
            other => return Err(UnwindReadError::UnsupportedSecondLevelPageKind(other)),
        }
    }

    Ok(DecodedUnwindInfo {
        version,
        personalities,
        lsdas,
        records,
    })
}

fn validate_serialized_unwind_info(
    bytes: &[u8],
    records: &[UnwindRecord],
) -> Result<(), UnwindReadError> {
    let decoded = decode_unwind_info(bytes)?;
    let (records, personalities, lsdas) = finalize_unwind_records(records)?;
    let expected: Vec<DecodedUnwindRecord> = records
        .iter()
        .map(|record| DecodedUnwindRecord {
            function_offset: record.function_offset,
            encoding: record.encoding,
        })
        .collect();
    if decoded.records != expected {
        return Err(UnwindReadError::Truncated(
            "decoded unwind records do not round-trip",
        ));
    }
    if decoded.personalities != personalities {
        return Err(UnwindReadError::Truncated(
            "decoded personality table does not round-trip",
        ));
    }
    let expected_lsdas: Vec<DecodedLsdaRecord> = lsdas
        .iter()
        .map(|lsda| DecodedLsdaRecord {
            function_offset: lsda.function_offset,
            lsda_offset: lsda.lsda_offset,
        })
        .collect();
    if decoded.lsdas != expected_lsdas {
        return Err(UnwindReadError::Truncated(
            "decoded lsda table does not round-trip",
        ));
    }
    Ok(())
}

fn finalize_unwind_records(
    records: &[UnwindRecord],
) -> Result<FinalizedUnwindTables, UnwindReadError> {
    let mut personalities = Vec::new();
    let mut finalized = Vec::with_capacity(records.len());
    let mut lsdas = Vec::new();
    let mut personality_index = HashMap::new();

    for record in records {
        let mut encoding = record.encoding & !UNWIND_PERSONALITY_MASK;
        if let Some(personality_offset) = record.personality_offset {
            let idx = if let Some(&idx) = personality_index.get(&personality_offset) {
                idx
            } else {
                if personalities.len() == 3 {
                    return Err(UnwindReadError::TooManyPersonalities(
                        personalities.len() + 1,
                    ));
                }
                personalities.push(personality_offset);
                let idx = personalities.len() as u32;
                personality_index.insert(personality_offset, idx);
                idx
            };
            encoding |= idx << UNWIND_PERSONALITY_SHIFT;
        }
        if let Some(lsda_offset) = record.lsda_offset {
            encoding |= UNWIND_HAS_LSDA;
            lsdas.push(LsdaRecord {
                function_offset: record.function_offset,
                lsda_offset,
            });
        } else {
            encoding &= !UNWIND_HAS_LSDA;
        }
        if encoding & UNWIND_ARM64_MODE_MASK == UNWIND_ARM64_MODE_DWARF {
            encoding &= !UNWIND_ARM64_DWARF_SECTION_OFFSET_MASK;
        }
        finalized.push(UnwindRecord {
            encoding,
            ..*record
        });
    }

    Ok((finalized, personalities, lsdas))
}

fn select_common_encodings(records: &[UnwindRecord]) -> Vec<u32> {
    let mut stats: HashMap<u32, (u32, usize)> = HashMap::new();
    for (idx, record) in records.iter().enumerate() {
        stats
            .entry(record.encoding)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, idx));
    }

    let mut encodings: Vec<(u32, u32, usize)> = stats
        .into_iter()
        .filter_map(|(encoding, (count, first_seen))| {
            (count > 1).then_some((encoding, count, first_seen))
        })
        .collect();
    encodings.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
    encodings.truncate(127);
    encodings
        .into_iter()
        .map(|(encoding, _, _)| encoding)
        .collect()
}

fn build_pages(records: &[UnwindRecord], common_encodings: &[u32]) -> Vec<CompressedPage> {
    let mut pages = Vec::new();
    let mut current: Option<CompressedPage> = None;
    let common_indices: HashMap<u32, usize> = common_encodings
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, encoding)| (encoding, idx))
        .collect();

    for record in records {
        let page = current.get_or_insert_with(|| CompressedPage {
            start_function_offset: record.function_offset,
            entries: Vec::new(),
            local_encodings: Vec::new(),
        });

        let mut encodings = page.local_encodings.clone();
        if !common_indices.contains_key(&record.encoding)
            && encodings
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
        let encoding_index = if let Some(index) = common_indices.get(&record.encoding) {
            *index
        } else if let Some(index) = page
            .local_encodings
            .iter()
            .position(|encoding| *encoding == record.encoding)
        {
            common_encodings.len() + index
        } else {
            page.local_encodings.push(record.encoding);
            common_encodings.len() + page.local_encodings.len() - 1
        };
        page.entries
            .push(((encoding_index as u32) << 24) | (delta & 0x00ff_ffff));
    }

    if let Some(page) = current {
        pages.push(page);
    }
    pages
}

fn read_u16(bytes: &[u8], offset: usize, what: &'static str) -> Result<u16, UnwindReadError> {
    if offset + 2 > bytes.len() {
        return Err(UnwindReadError::Truncated(what));
    }
    Ok(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize, what: &'static str) -> Result<u32, UnwindReadError> {
    if offset + 4 > bytes.len() {
        return Err(UnwindReadError::Truncated(what));
    }
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4].try_into().unwrap(),
    ))
}

fn read_u32_array(
    bytes: &[u8],
    offset: usize,
    count: usize,
    what: &'static str,
) -> Result<Vec<u32>, UnwindReadError> {
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        out.push(read_u32(bytes, offset + idx * 4, what)?);
    }
    Ok(out)
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
            personality_offset: None,
            lsda_offset: None,
        }])
        .unwrap();
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
        let decoded = decode_unwind_info(&bytes).unwrap();
        assert!(decoded.personalities.is_empty());
        assert!(decoded.lsdas.is_empty());
        assert_eq!(
            decoded.records,
            vec![DecodedUnwindRecord {
                function_offset: 0x348,
                encoding: 0x0200_1000,
            }]
        );
    }

    #[test]
    fn serialize_two_records_uses_compressed_entries() {
        let bytes = serialize_unwind_info(&[
            UnwindRecord {
                function_offset: 0x348,
                code_len: 0x8,
                encoding: 0x0200_0000,
                personality_offset: None,
                lsda_offset: None,
            },
            UnwindRecord {
                function_offset: 0x350,
                code_len: 0x20,
                encoding: 0x0400_0000,
                personality_offset: None,
                lsda_offset: None,
            },
        ])
        .unwrap();
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
        let decoded = decode_unwind_info(&bytes).unwrap();
        assert!(decoded.personalities.is_empty());
        assert!(decoded.lsdas.is_empty());
        assert_eq!(
            decoded.records,
            vec![
                DecodedUnwindRecord {
                    function_offset: 0x348,
                    encoding: 0x0200_0000,
                },
                DecodedUnwindRecord {
                    function_offset: 0x350,
                    encoding: 0x0400_0000,
                },
            ]
        );
    }

    #[test]
    fn repeated_encodings_promote_to_common_table() {
        let bytes = serialize_unwind_info(&[
            UnwindRecord {
                function_offset: 0x348,
                code_len: 0x18,
                encoding: 0x0400_0000,
                personality_offset: None,
                lsda_offset: None,
            },
            UnwindRecord {
                function_offset: 0x360,
                code_len: 0x20,
                encoding: 0x0200_2000,
                personality_offset: None,
                lsda_offset: None,
            },
            UnwindRecord {
                function_offset: 0x390,
                code_len: 0x10,
                encoding: 0x0400_0000,
                personality_offset: None,
                lsda_offset: None,
            },
        ])
        .unwrap();
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(words[2], 1, "expected one promoted common encoding");
        assert_eq!(words[7], 0x0400_0000);

        let decoded = decode_unwind_info(&bytes).unwrap();
        assert_eq!(
            decoded.records,
            vec![
                DecodedUnwindRecord {
                    function_offset: 0x348,
                    encoding: 0x0400_0000,
                },
                DecodedUnwindRecord {
                    function_offset: 0x360,
                    encoding: 0x0200_2000,
                },
                DecodedUnwindRecord {
                    function_offset: 0x390,
                    encoding: 0x0400_0000,
                },
            ]
        );
    }

    #[test]
    fn decode_rejects_bad_encoding_index() {
        let mut bytes = serialize_unwind_info(&[UnwindRecord {
            function_offset: 0x348,
            code_len: 0x14,
            encoding: 0x0200_1000,
            personality_offset: None,
            lsda_offset: None,
        }])
        .unwrap();
        let second_level_offset =
            u32::from_le_bytes(bytes[28 + 4..28 + 8].try_into().unwrap()) as usize;
        let entries_offset = second_level_offset
            + u16::from_le_bytes(
                bytes[second_level_offset + 4..second_level_offset + 6]
                    .try_into()
                    .unwrap(),
            ) as usize;
        bytes[entries_offset..entries_offset + 4].copy_from_slice(&0xff00_0000u32.to_le_bytes());
        let err = decode_unwind_info(&bytes).unwrap_err();
        assert!(matches!(err, UnwindReadError::BadEncodingIndex { .. }));
    }
}
