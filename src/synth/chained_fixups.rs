use std::collections::BTreeMap;

pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

const FIXUPS_VERSION: u32 = 0;
const SYMBOLS_FORMAT_UNCOMPRESSED: u32 = 0;
const PAGE_SIZE: u64 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedImport {
    pub symbol: crate::resolve::SymbolId,
    pub dylib_ordinal: u16,
    pub weak_import: bool,
    pub name: String,
    pub addend: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedFixupSite {
    pub segment_index: usize,
    pub segment_offset: u64,
    pub kind: ChainedFixupKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedFixupKind {
    Rebase,
    Bind { import_ordinal: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedSegment {
    pub vm_offset: u64,
    pub vm_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedPointerWrite {
    pub segment_index: usize,
    pub segment_offset: u64,
    pub kind: ChainedPointerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedPointerKind {
    Rebase { next: u16 },
    Bind { import_ordinal: u32, next: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedFixups {
    pub bytes: Vec<u8>,
    pub pointer_writes: Vec<ChainedPointerWrite>,
}

pub fn build(
    segments: &[ChainedSegment],
    imports: &[ChainedImport],
    sites: &[ChainedFixupSite],
) -> Result<ChainedFixups, String> {
    let imports_format = imports_format(imports)?;
    let mut symbol_bytes = Vec::new();
    let mut symbol_offsets = Vec::with_capacity(imports.len());
    for import in imports {
        let offset = u32::try_from(symbol_bytes.len())
            .map_err(|_| "chained import symbol strings exceed u32".to_string())?;
        symbol_offsets.push(offset);
        symbol_bytes.extend_from_slice(import.name.as_bytes());
        symbol_bytes.push(0);
    }

    let mut starts_bytes = build_starts(segments, sites)?;
    pad_to(&mut starts_bytes, 8);

    let header_size = 28usize;
    let starts_offset = align_up(header_size, 8);
    let imports_offset = starts_offset + starts_bytes.len();
    let import_bytes = build_imports(imports, &symbol_offsets, imports_format)?;
    let symbols_offset = imports_offset + import_bytes.len();

    let mut bytes = Vec::new();
    write_u32(FIXUPS_VERSION, &mut bytes);
    write_u32(fit_u32(starts_offset, "starts offset")?, &mut bytes);
    write_u32(fit_u32(imports_offset, "imports offset")?, &mut bytes);
    write_u32(fit_u32(symbols_offset, "symbols offset")?, &mut bytes);
    write_u32(
        u32::try_from(imports.len())
            .map_err(|_| "chained imports count exceeds u32".to_string())?,
        &mut bytes,
    );
    write_u32(imports_format, &mut bytes);
    write_u32(SYMBOLS_FORMAT_UNCOMPRESSED, &mut bytes);
    pad_to(&mut bytes, 8);
    bytes.extend_from_slice(&starts_bytes);
    bytes.extend_from_slice(&import_bytes);
    bytes.extend_from_slice(&symbol_bytes);
    pad_to(&mut bytes, 8);

    Ok(ChainedFixups {
        bytes,
        pointer_writes: pointer_writes(sites)?,
    })
}

fn build_starts(
    segments: &[ChainedSegment],
    sites: &[ChainedFixupSite],
) -> Result<Vec<u8>, String> {
    let mut by_segment: BTreeMap<usize, Vec<ChainedFixupSite>> = BTreeMap::new();
    for site in sites {
        if site.segment_index >= segments.len() {
            return Err(format!(
                "chained fixup site references missing segment {}",
                site.segment_index
            ));
        }
        by_segment
            .entry(site.segment_index)
            .or_default()
            .push(*site);
    }

    let mut out = Vec::new();
    write_u32(
        u32::try_from(segments.len())
            .map_err(|_| "chained segment count exceeds u32".to_string())?,
        &mut out,
    );
    let offsets_start = out.len();
    out.resize(out.len() + segments.len() * 4, 0);

    for (segment_index, segment_sites) in by_segment.iter_mut() {
        segment_sites.sort_by_key(|site| site.segment_offset);
        segment_sites.dedup_by_key(|site| site.segment_offset);
        let info_offset = fit_u32(out.len(), "segment chain-start offset")?;
        out[offsets_start + segment_index * 4..offsets_start + segment_index * 4 + 4]
            .copy_from_slice(&info_offset.to_le_bytes());
        write_segment_starts(&segments[*segment_index], segment_sites, &mut out)?;
    }

    Ok(out)
}

fn write_segment_starts(
    segment: &ChainedSegment,
    sites: &[ChainedFixupSite],
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if sites.is_empty() {
        return Ok(());
    }
    let page_count = segment.vm_size.div_ceil(PAGE_SIZE);
    let page_count_u16 = u16::try_from(page_count)
        .map_err(|_| "chained segment page count exceeds u16".to_string())?;
    let size = 22usize + page_count as usize * 2;
    write_u32(fit_u32(size, "segment chain-start size")?, out);
    write_u16(PAGE_SIZE as u16, out);
    write_u16(DYLD_CHAINED_PTR_64_OFFSET, out);
    write_u64(segment.vm_offset, out);
    write_u32(0, out);
    write_u16(page_count_u16, out);

    let mut page_starts = vec![DYLD_CHAINED_PTR_START_NONE; page_count as usize];
    for site in sites {
        if site.segment_offset >= segment.vm_size {
            return Err(format!(
                "chained fixup at segment offset 0x{:x} exceeds segment size 0x{:x}",
                site.segment_offset, segment.vm_size
            ));
        }
        if site.segment_offset % 8 != 0 {
            return Err(format!(
                "chained fixup at segment offset 0x{:x} is not 8-byte aligned",
                site.segment_offset
            ));
        }
        let page_index = (site.segment_offset / PAGE_SIZE) as usize;
        let page_offset = u16::try_from(site.segment_offset % PAGE_SIZE)
            .map_err(|_| "chained page offset exceeds u16".to_string())?;
        if page_starts[page_index] == DYLD_CHAINED_PTR_START_NONE {
            page_starts[page_index] = page_offset;
        }
    }
    for start in page_starts {
        write_u16(start, out);
    }
    Ok(())
}

fn pointer_writes(sites: &[ChainedFixupSite]) -> Result<Vec<ChainedPointerWrite>, String> {
    let mut by_page: BTreeMap<(usize, u64), Vec<ChainedFixupSite>> = BTreeMap::new();
    for site in sites {
        by_page
            .entry((site.segment_index, site.segment_offset / PAGE_SIZE))
            .or_default()
            .push(*site);
    }

    let mut writes = Vec::with_capacity(sites.len());
    for (_, page_sites) in by_page.iter_mut() {
        page_sites.sort_by_key(|site| site.segment_offset);
        page_sites.dedup_by_key(|site| site.segment_offset);
        for idx in 0..page_sites.len() {
            let site = page_sites[idx];
            let next = if let Some(next_site) = page_sites.get(idx + 1) {
                let delta = next_site
                    .segment_offset
                    .checked_sub(site.segment_offset)
                    .ok_or_else(|| "chained fixup sites are not sorted".to_string())?;
                if delta % 4 != 0 {
                    return Err("chained fixup next delta is not 4-byte aligned".to_string());
                }
                u16::try_from(delta / 4)
                    .map_err(|_| "chained fixup next delta exceeds u16".to_string())?
            } else {
                0
            };
            let kind = match site.kind {
                ChainedFixupKind::Rebase => ChainedPointerKind::Rebase { next },
                ChainedFixupKind::Bind { import_ordinal } => ChainedPointerKind::Bind {
                    import_ordinal,
                    next,
                },
            };
            writes.push(ChainedPointerWrite {
                segment_index: site.segment_index,
                segment_offset: site.segment_offset,
                kind,
            });
        }
    }
    writes.sort_by_key(|write| (write.segment_index, write.segment_offset));
    Ok(writes)
}

fn build_imports(
    imports: &[ChainedImport],
    symbol_offsets: &[u32],
    imports_format: u32,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (import, name_offset) in imports.iter().zip(symbol_offsets) {
        match imports_format {
            DYLD_CHAINED_IMPORT => {
                if import.addend != 0 {
                    return Err("non-zero addend cannot use DYLD_CHAINED_IMPORT".to_string());
                }
                write_u32(import_word(import, *name_offset)?, &mut out);
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                write_u32(import_word(import, *name_offset)?, &mut out);
                write_u32(import.addend as i32 as u32, &mut out);
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let word = u64::from(import.dylib_ordinal)
                    | ((import.weak_import as u64) << 16)
                    | (u64::from(*name_offset) << 32);
                write_u64(word, &mut out);
                write_u64(import.addend as u64, &mut out);
            }
            _ => {
                return Err(format!(
                    "unsupported chained imports format {imports_format}"
                ))
            }
        }
    }
    Ok(out)
}

fn import_word(import: &ChainedImport, name_offset: u32) -> Result<u32, String> {
    if import.dylib_ordinal > 0xf0 {
        return Err(format!(
            "dylib ordinal {} exceeds DYLD_CHAINED_IMPORT width",
            import.dylib_ordinal
        ));
    }
    if name_offset >= (1 << 23) {
        return Err("chained import name offset exceeds 23 bits".to_string());
    }
    Ok(u32::from(import.dylib_ordinal) | ((import.weak_import as u32) << 8) | (name_offset << 9))
}

fn imports_format(imports: &[ChainedImport]) -> Result<u32, String> {
    if imports.iter().all(|import| import.addend == 0) {
        return Ok(DYLD_CHAINED_IMPORT);
    }
    if imports
        .iter()
        .all(|import| i32::try_from(import.addend).is_ok() && import.dylib_ordinal <= 0xf0)
    {
        return Ok(DYLD_CHAINED_IMPORT_ADDEND);
    }
    if imports.iter().any(|import| import.dylib_ordinal == 0) {
        return Err("special dylib ordinals are not supported in ADDEND64 chained imports".into());
    }
    Ok(DYLD_CHAINED_IMPORT_ADDEND64)
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn pad_to(bytes: &mut Vec<u8>, align: usize) {
    bytes.resize(align_up(bytes.len(), align), 0);
}

fn fit_u32(value: usize, context: &'static str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{context} exceeds u32"))
}

fn write_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(value: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use crate::resolve::SymbolId;

    use super::*;

    #[test]
    fn empty_chained_fixups_emit_header_and_empty_starts() {
        let fixups = build(
            &[ChainedSegment {
                vm_offset: 0,
                vm_size: 0x4000,
            }],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(&fixups.bytes[0..4], &0u32.to_le_bytes());
        assert_eq!(&fixups.bytes[4..8], &0x20u32.to_le_bytes());
        assert_eq!(&fixups.bytes[20..24], &DYLD_CHAINED_IMPORT.to_le_bytes());
        assert!(fixups.pointer_writes.is_empty());
    }

    #[test]
    fn rebase_sites_are_chained_with_page_local_nexts() {
        let sites = [
            ChainedFixupSite {
                segment_index: 0,
                segment_offset: 0x100,
                kind: ChainedFixupKind::Rebase,
            },
            ChainedFixupSite {
                segment_index: 0,
                segment_offset: 0x120,
                kind: ChainedFixupKind::Rebase,
            },
        ];
        let fixups = build(
            &[ChainedSegment {
                vm_offset: 0,
                vm_size: 0x4000,
            }],
            &[],
            &sites,
        )
        .unwrap();

        assert_eq!(fixups.pointer_writes.len(), 2);
        assert_eq!(
            fixups.pointer_writes[0].kind,
            ChainedPointerKind::Rebase { next: 8 }
        );
        assert_eq!(
            fixups.pointer_writes[1].kind,
            ChainedPointerKind::Rebase { next: 0 }
        );
    }

    #[test]
    fn bind_imports_encode_symbol_pool() {
        let imports = [ChainedImport {
            symbol: SymbolId(7),
            dylib_ordinal: 1,
            weak_import: false,
            name: "_puts".into(),
            addend: 0,
        }];
        let sites = [ChainedFixupSite {
            segment_index: 0,
            segment_offset: 0,
            kind: ChainedFixupKind::Bind { import_ordinal: 0 },
        }];
        let fixups = build(
            &[ChainedSegment {
                vm_offset: 0,
                vm_size: 0x4000,
            }],
            &imports,
            &sites,
        )
        .unwrap();

        assert!(fixups.bytes.windows(6).any(|window| window == b"_puts\0"));
        assert_eq!(
            fixups.pointer_writes[0].kind,
            ChainedPointerKind::Bind {
                import_ordinal: 0,
                next: 0
            }
        );
    }
}
