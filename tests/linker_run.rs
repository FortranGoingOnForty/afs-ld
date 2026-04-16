//! End-to-end `Linker::run` coverage for Sprint 10's newly wired pipeline.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

mod common;

use afs_ld::leb::read_uleb;
use afs_ld::macho::constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_MASK,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, BIND_OPCODE_SET_TYPE_IMM,
    BIND_SYMBOL_FLAGS_WEAK_IMPORT, DICE_KIND_JUMP_TABLE32, LC_DATA_IN_CODE, LC_FUNCTION_STARTS,
    REBASE_IMMEDIATE_MASK, REBASE_OPCODE_ADD_ADDR_IMM_SCALED, REBASE_OPCODE_ADD_ADDR_ULEB,
    REBASE_OPCODE_DONE, REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB, REBASE_OPCODE_DO_REBASE_IMM_TIMES,
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES, REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
    REBASE_OPCODE_MASK, REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, REBASE_OPCODE_SET_TYPE_IMM,
    REBASE_TYPE_POINTER, SG_READ_ONLY,
};
use afs_ld::macho::dylib::DylibFile;
use afs_ld::macho::exports::{ExportKind, Exports};
use afs_ld::macho::reader::{parse_commands, parse_header, u32_le, LoadCommand, Section64Header};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, SymKind};
use afs_ld::synth::unwind::decode_unwind_info;
use afs_ld::{LinkError, LinkOptions, Linker, OutputKind};
use common::harness::diff_macho;

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sdk_path() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn sdk_version() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-version"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn have_xcrun_tool(tool: &str) -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success() || !o.stderr.is_empty())
        .unwrap_or(false)
}

fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-linker-run-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn compile_c(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-linker-run-{}-{}.c",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64", "-c"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn compile_cxx(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-linker-run-{}-{}.cc",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang++", "-arch", "arm64", "-c"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang++: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang++ failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn compile_dylib_c(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-linker-run-{}-{}.c",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("lib")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let install_name = out.to_string_lossy().to_string();
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64", "-dynamiclib"])
        .arg(&tmp)
        .arg(format!("-Wl,-install_name,{install_name}"))
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang dylib: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang dylib failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-linker-run-{}-{name}", std::process::id()))
}

fn output_section(bytes: &[u8], segname: &str, sectname: &str) -> Option<(u64, Vec<u8>)> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    let data = if section.offset == 0 {
                        Vec::new()
                    } else {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
                        bytes.get(start..end)?.to_vec()
                    };
                    return Some((section.addr, data));
                }
            }
        }
    }
    None
}

fn output_section_header(bytes: &[u8], segname: &str, sectname: &str) -> Option<Section64Header> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    return Some(section);
                }
            }
        }
    }
    None
}

fn segment_flags(bytes: &[u8], segname: &str) -> Option<u32> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            if seg.segname_str() == segname {
                return Some(seg.flags);
            }
        }
    }
    None
}

fn segment_vmaddr(bytes: &[u8], segname: &str) -> Option<u64> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            if seg.segname_str() == segname {
                return Some(seg.vmaddr);
            }
        }
    }
    None
}

fn symtab_and_dysymtab(
    bytes: &[u8],
) -> (
    afs_ld::macho::reader::SymtabCmd,
    afs_ld::macho::reader::DysymtabCmd,
) {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    let mut symtab = None;
    let mut dysymtab = None;
    for cmd in commands {
        match cmd {
            LoadCommand::Symtab(cmd) => symtab = Some(cmd),
            LoadCommand::Dysymtab(cmd) => dysymtab = Some(cmd),
            _ => {}
        }
    }
    (symtab.unwrap(), dysymtab.unwrap())
}

fn symbol_partition_names(bytes: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (symtab, dysymtab) = symtab_and_dysymtab(bytes);
    let symbols = parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(bytes, symtab.stroff, symtab.strsize).unwrap();
    let names_for = |start: u32, count: u32| -> Vec<String> {
        symbols[start as usize..(start + count) as usize]
            .iter()
            .map(|symbol| strings.get(symbol.strx()).unwrap().to_string())
            .collect()
    };
    (
        names_for(dysymtab.ilocalsym, dysymtab.nlocalsym),
        names_for(dysymtab.iextdefsym, dysymtab.nextdefsym),
        names_for(dysymtab.iundefsym, dysymtab.nundefsym),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalSymbolRecord {
    name: String,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    value: u64,
}

fn section_addrs(bytes: &[u8]) -> Vec<u64> {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    let mut out = Vec::new();
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                out.push(section.addr);
            }
        }
    }
    out
}

fn canonical_symbol_records(bytes: &[u8]) -> Vec<CanonicalSymbolRecord> {
    let (symtab, _) = symtab_and_dysymtab(bytes);
    let symbols = parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(bytes, symtab.stroff, symtab.strsize).unwrap();
    let section_addrs = section_addrs(bytes);
    symbols
        .iter()
        .map(|symbol| {
            let value = if symbol.kind() == SymKind::Sect && symbol.sect_idx() != 0 {
                let section_addr = section_addrs[symbol.sect_idx() as usize - 1];
                if symbol.value() >= section_addr {
                    symbol.value() - section_addr
                } else {
                    symbol.value()
                }
            } else {
                symbol.value()
            };
            CanonicalSymbolRecord {
                name: strings.get(symbol.strx()).unwrap().to_string(),
                n_type: symbol.raw.n_type,
                n_sect: symbol.raw.n_sect,
                n_desc: symbol.raw.n_desc,
                value,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonicalExportKind {
    Regular(u64),
    ThreadLocal(u64),
    Absolute(u64),
    Reexport { ordinal: u32, imported_name: String },
    StubAndResolver { stub: u64, resolver: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalExportRecord {
    name: String,
    flags: u64,
    kind: CanonicalExportKind,
}

fn canonical_export_records(bytes: &[u8]) -> Vec<CanonicalExportRecord> {
    let dylib = DylibFile::parse("/tmp/canonical.dylib", bytes).unwrap();
    let symbol_values: HashMap<String, u64> = canonical_symbol_records(bytes)
        .into_iter()
        .map(|record| (record.name, record.value))
        .collect();
    let mut out = dylib
        .exports
        .entries()
        .unwrap()
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                ExportKind::Regular { .. } => {
                    CanonicalExportKind::Regular(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::ThreadLocal { .. } => {
                    CanonicalExportKind::ThreadLocal(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::Absolute { .. } => {
                    CanonicalExportKind::Absolute(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::Reexport {
                    ordinal,
                    imported_name,
                } => CanonicalExportKind::Reexport {
                    ordinal,
                    imported_name,
                },
                ExportKind::StubAndResolver { stub, resolver } => {
                    CanonicalExportKind::StubAndResolver { stub, resolver }
                }
            };
            CanonicalExportRecord {
                name: entry.name,
                flags: entry.flags,
                kind,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    out
}

fn dyld_info_export_names(bytes: &[u8]) -> Result<Vec<String>, String> {
    let trie = dyld_info_stream(bytes, DyldInfoStreamKind::Export)?;
    if trie.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Exports::from_trie_bytes(&trie)
        .entries()
        .map_err(|e| format!("decode export trie: {e}"))?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    out.sort();
    Ok(out)
}

fn raw_string_table(bytes: &[u8]) -> Vec<u8> {
    let (symtab, _) = symtab_and_dysymtab(bytes);
    let start = symtab.stroff as usize;
    let end = start + symtab.strsize as usize;
    bytes[start..end].to_vec()
}

fn symbol_name_offsets(bytes: &[u8]) -> HashMap<String, u32> {
    let (symtab, _) = symtab_and_dysymtab(bytes);
    let symbols = parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(bytes, symtab.stroff, symtab.strsize).unwrap();
    symbols
        .iter()
        .map(|symbol| {
            (
                strings.get(symbol.strx()).unwrap().to_string(),
                symbol.strx(),
            )
        })
        .collect()
}

fn indirect_symbol_table(bytes: &[u8]) -> Vec<u32> {
    let (_, dysymtab) = symtab_and_dysymtab(bytes);
    if dysymtab.nindirectsyms == 0 {
        return Vec::new();
    }
    let start = dysymtab.indirectsymoff as usize;
    let end = start + dysymtab.nindirectsyms as usize * 4;
    bytes[start..end]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn raw_linkedit_data_cmd(bytes: &[u8], expected_cmd: u32) -> (u32, u32) {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    for cmd in commands {
        if let LoadCommand::Raw { cmd, data, .. } = cmd {
            if cmd == expected_cmd {
                return (u32_le(&data[0..4]), u32_le(&data[4..8]));
            }
        }
    }
    panic!("missing raw linkedit command 0x{expected_cmd:x}");
}

fn linkedit_payload(bytes: &[u8], cmd: u32) -> Vec<u8> {
    let (dataoff, datasize) = raw_linkedit_data_cmd(bytes, cmd);
    if datasize == 0 {
        return Vec::new();
    }
    bytes[dataoff as usize..(dataoff + datasize) as usize].to_vec()
}

fn decode_function_starts(bytes: &[u8]) -> Vec<u64> {
    let payload = linkedit_payload(bytes, LC_FUNCTION_STARTS);
    let mut offsets = Vec::new();
    let mut cursor = 0usize;
    let mut current = 0u64;
    while cursor < payload.len() {
        let (delta, used) = read_uleb(&payload[cursor..]).unwrap();
        cursor += used;
        if delta == 0 {
            break;
        }
        current += delta;
        offsets.push(current);
    }
    offsets
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataInCodeRecord {
    offset: u32,
    length: u16,
    kind: u16,
}

fn normalized_unwind_words(bytes: &[u8]) -> Vec<u32> {
    let (_, unwind) = output_section(bytes, "__TEXT", "__unwind_info").unwrap();
    let decoded = decode_unwind_info(&unwind).unwrap();
    let mut words: Vec<u32> = unwind
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    if words.len() < 7 {
        return words;
    }
    let indices_offset_words = words[5] as usize / 4;
    let indices_count = words[6] as usize;
    if indices_count == 0 || words.len() < indices_offset_words + indices_count * 3 {
        return words;
    }
    let base = words[indices_offset_words];
    for idx in 0..indices_count {
        let word = indices_offset_words + idx * 3;
        words[word] = words[word].saturating_sub(base);
    }
    if !decoded.records.is_empty() {
        assert_eq!(decoded.records[0].function_offset, base);
    }
    words
}

fn normalized_eh_frame_dump(path: &PathBuf, text_base: u64) -> Result<String, String> {
    let output = Command::new("xcrun")
        .args(["dwarfdump", "--eh-frame"])
        .arg(path)
        .output()
        .map_err(|e| format!("spawn xcrun dwarfdump: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun dwarfdump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut normalized = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("0x") && trimmed.contains(": CFA=") {
            let (addr, rest) = trimmed.split_once(':').unwrap();
            let value = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
            normalized.push(format!("0x{:x}:{}", value - text_base, rest));
            continue;
        }
        if let Some(pc_idx) = trimmed.find("pc=") {
            let prefix = &trimmed[..pc_idx + 3];
            let range = &trimmed[pc_idx + 3..];
            if let Some((start, end)) = range.split_once("...") {
                let start = u64::from_str_radix(start, 16).unwrap();
                let end = u64::from_str_radix(end, 16).unwrap();
                normalized.push(format!(
                    "{}0x{:x}...0x{:x}",
                    prefix,
                    start - text_base,
                    end - text_base
                ));
                continue;
            }
        }
        if trimmed.is_empty()
            || trimmed.starts_with(".debug_frame")
            || trimmed.starts_with(".eh_frame")
            || trimmed.ends_with("file format Mach-O arm64")
        {
            continue;
        }
        normalized.push(rebase_hex_addresses(trimmed, text_base));
    }
    Ok(normalized.join("\n"))
}

fn canonical_unwind_info(bytes: &[u8]) -> afs_ld::synth::unwind::DecodedUnwindInfo {
    let (_, unwind) = output_section(bytes, "__TEXT", "__unwind_info").unwrap();
    let mut decoded = decode_unwind_info(&unwind).unwrap();
    let header_base = segment_vmaddr(bytes, "__TEXT").unwrap_or(0);
    let text_base = output_section(bytes, "__TEXT", "__text").unwrap().0 - header_base;
    for record in &mut decoded.records {
        record.function_offset -= text_base as u32;
    }
    if let Some((lsda_addr, _)) = output_section(bytes, "__TEXT", "__gcc_except_tab") {
        let lsda_base = lsda_addr - header_base;
        for record in &mut decoded.lsdas {
            record.function_offset -= text_base as u32;
            record.lsda_offset -= lsda_base as u32;
        }
    }
    if let Some((got_addr, got)) = output_section(bytes, "__DATA_CONST", "__got") {
        let got_base = got_addr - header_base;
        let got_end = got_base + got.len() as u64;
        for personality in &mut decoded.personalities {
            let offset = *personality as u64;
            if got_base <= offset && offset < got_end {
                *personality -= got_base as u32;
            }
        }
    }
    decoded
}

fn rebase_hex_addresses(line: &str, text_base: u64) -> String {
    let bytes = line.as_bytes();
    let mut out = String::new();
    let mut idx = 0;
    while idx < bytes.len() {
        if idx + 2 <= bytes.len() && bytes[idx] == b'0' && bytes[idx + 1] == b'x' {
            let mut end = idx + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            let token = &line[idx + 2..end];
            let value = u64::from_str_radix(token, 16).unwrap();
            if value >= text_base {
                out.push_str(&format!("0x{:x}", value - text_base));
            } else {
                out.push_str(&line[idx..end]);
            }
            idx = end;
            continue;
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

fn decode_data_in_code(bytes: &[u8]) -> Vec<DataInCodeRecord> {
    let payload = linkedit_payload(bytes, LC_DATA_IN_CODE);
    payload
        .chunks_exact(8)
        .map(|chunk| DataInCodeRecord {
            offset: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
            length: u16::from_le_bytes(chunk[4..6].try_into().unwrap()),
            kind: u16::from_le_bytes(chunk[6..8].try_into().unwrap()),
        })
        .collect()
}

fn canonical_data_in_code(bytes: &[u8]) -> Vec<DataInCodeRecord> {
    let text = output_section_header(bytes, "__TEXT", "__text").unwrap();
    decode_data_in_code(bytes)
        .into_iter()
        .map(|record| DataInCodeRecord {
            offset: record.offset - text.offset,
            length: record.length,
            kind: record.kind,
        })
        .collect()
}

fn assert_strtab_within_five_percent(ours: &[u8], apple: &[u8]) {
    let delta = ours.len().abs_diff(apple.len());
    assert!(
        delta * 20 <= apple.len(),
        "string table length drifted too far from Apple ld: ours={} apple={}",
        ours.len(),
        apple.len()
    );
}

fn apple_link(
    obj: &PathBuf,
    out: &PathBuf,
    entry: &str,
    syslibroot: &str,
    platform_version: &str,
) -> Result<(), String> {
    apple_link_with_args(obj, out, entry, syslibroot, platform_version, &[])
}

fn apple_link_with_args(
    obj: &PathBuf,
    out: &PathBuf,
    entry: &str,
    syslibroot: &str,
    platform_version: &str,
    extra_args: &[&str],
) -> Result<(), String> {
    let output = Command::new("xcrun")
        .args([
            "ld",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            platform_version,
            platform_version,
            "-syslibroot",
            syslibroot,
            "-lSystem",
            "-e",
            entry,
        ])
        .args(extra_args)
        .arg("-o")
        .arg(out)
        .arg(obj)
        .output()
        .map_err(|e| format!("spawn xcrun ld: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun ld failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn apple_link_classic_lazy(
    obj: &PathBuf,
    out: &PathBuf,
    entry: &str,
    syslibroot: &str,
    platform_version: &str,
) -> Result<(), String> {
    apple_link_with_args(
        obj,
        out,
        entry,
        syslibroot,
        platform_version,
        &["-no_fixup_chains"],
    )
}

fn apple_link_dylib_classic(
    obj: &PathBuf,
    out: &PathBuf,
    install_name: &str,
    syslibroot: &str,
    platform_version: &str,
) -> Result<(), String> {
    let output = Command::new("xcrun")
        .args([
            "ld",
            "-dylib",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            platform_version,
            platform_version,
            "-syslibroot",
            syslibroot,
            "-lSystem",
            "-install_name",
            install_name,
            "-no_fixup_chains",
        ])
        .arg("-o")
        .arg(out)
        .arg(obj)
        .output()
        .map_err(|e| format!("spawn xcrun ld -dylib: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun ld -dylib failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn apple_link_cxx_classic(obj: &PathBuf, out: &PathBuf) -> Result<(), String> {
    let output = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "clang++",
            "-arch",
            "arm64",
            "-Wl,-no_fixup_chains",
            "-o",
        ])
        .arg(out)
        .arg(obj)
        .output()
        .map_err(|e| format!("spawn xcrun clang++ link: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun clang++ link failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RebaseRecord {
    segment: String,
    section: String,
    section_offset: u64,
    rebase_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindRecord {
    segment: String,
    section: String,
    section_offset: u64,
    ordinal: u16,
    symbol: String,
    weak_import: bool,
}

#[derive(Debug, Clone)]
struct SegmentView {
    name: String,
    vm_addr: u64,
    vm_size: u64,
    sections: Vec<Section64Header>,
}

fn dyld_info_command(bytes: &[u8]) -> Result<afs_ld::macho::reader::DyldInfoCmd, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    commands
        .into_iter()
        .find_map(|cmd| match cmd {
            LoadCommand::DyldInfoOnly(cmd) => Some(cmd),
            _ => None,
        })
        .ok_or_else(|| "missing LC_DYLD_INFO_ONLY".to_string())
}

#[derive(Clone, Copy)]
enum DyldInfoStreamKind {
    Rebase,
    Bind,
    WeakBind,
    LazyBind,
    Export,
}

fn dyld_info_stream(bytes: &[u8], kind: DyldInfoStreamKind) -> Result<Vec<u8>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    let (off, size) = match kind {
        DyldInfoStreamKind::Rebase => (dyld_info.rebase_off, dyld_info.rebase_size),
        DyldInfoStreamKind::Bind => (dyld_info.bind_off, dyld_info.bind_size),
        DyldInfoStreamKind::WeakBind => (dyld_info.weak_bind_off, dyld_info.weak_bind_size),
        DyldInfoStreamKind::LazyBind => (dyld_info.lazy_bind_off, dyld_info.lazy_bind_size),
        DyldInfoStreamKind::Export => (dyld_info.export_off, dyld_info.export_size),
    };
    if size == 0 {
        return Ok(Vec::new());
    }
    let start = off as usize;
    let end = start + size as usize;
    bytes
        .get(start..end)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| "dyld-info stream out of bounds".to_string())
}

fn canonical_lazy_bind_stream(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = dyld_info_stream(bytes, DyldInfoStreamKind::LazyBind)?;
    while stream.len() >= 2
        && stream[stream.len() - 1] == BIND_OPCODE_DONE
        && stream[stream.len() - 2] == BIND_OPCODE_DONE
    {
        stream.pop();
    }
    Ok(stream)
}

fn segment_views(bytes: &[u8]) -> Result<Vec<SegmentView>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    Ok(commands
        .into_iter()
        .filter_map(|cmd| match cmd {
            LoadCommand::Segment64(seg) => Some(SegmentView {
                name: seg.segname_str().to_string(),
                vm_addr: seg.vmaddr,
                vm_size: seg.vmsize,
                sections: seg.sections,
            }),
            _ => None,
        })
        .collect())
}

fn read_cstr(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let start = *cursor;
    let end = bytes[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|len| start + len)
        .ok_or_else(|| "unterminated dyld-info string".to_string())?;
    *cursor = end + 1;
    std::str::from_utf8(&bytes[start..end])
        .map(|s| s.to_string())
        .map_err(|e| format!("dyld-info string is not UTF-8: {e}"))
}

fn locate_section(
    segments: &[SegmentView],
    segment_index: u8,
    segment_offset: u64,
) -> Result<(String, String, u64), String> {
    let segment = segments
        .get(segment_index as usize)
        .ok_or_else(|| format!("segment index {segment_index} out of range"))?;
    let addr = segment.vm_addr + segment_offset;
    for section in &segment.sections {
        if addr >= section.addr && addr < section.addr + section.size {
            return Ok((
                section.segname_str().to_string(),
                section.sectname_str().to_string(),
                addr - section.addr,
            ));
        }
    }
    if segment_offset <= segment.vm_size {
        return Ok((segment.name.clone(), String::new(), segment_offset));
    }
    Err(format!(
        "address 0x{addr:x} does not land in any section of {}",
        segment.name
    ))
}

fn decode_rebase_records(bytes: &[u8]) -> Result<Vec<RebaseRecord>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    if dyld_info.rebase_size == 0 {
        return Ok(Vec::new());
    }
    let segments = segment_views(bytes)?;
    let start = dyld_info.rebase_off as usize;
    let end = start + dyld_info.rebase_size as usize;
    let stream = bytes
        .get(start..end)
        .ok_or_else(|| "rebase stream out of bounds".to_string())?;

    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut segment_index = 0u8;
    let mut segment_offset = 0u64;
    let mut rebase_type = 0u8;
    while cursor < stream.len() {
        let byte = stream[cursor];
        cursor += 1;
        let opcode = byte & REBASE_OPCODE_MASK;
        let imm = byte & REBASE_IMMEDIATE_MASK;
        match opcode {
            REBASE_OPCODE_DONE => break,
            REBASE_OPCODE_SET_TYPE_IMM => rebase_type = imm,
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment_index = imm;
                let (offset, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += len;
                segment_offset = offset;
            }
            REBASE_OPCODE_ADD_ADDR_ULEB => {
                let (delta, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += len;
                segment_offset += delta;
            }
            REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                segment_offset += (imm as u64) * 8;
            }
            REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                for _ in 0..imm {
                    let (segment, section, section_offset) =
                        locate_section(&segments, segment_index, segment_offset)?;
                    out.push(RebaseRecord {
                        segment,
                        section,
                        section_offset,
                        rebase_type,
                    });
                    segment_offset += 8;
                }
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let (count, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += len;
                for _ in 0..count {
                    let (segment, section, section_offset) =
                        locate_section(&segments, segment_index, segment_offset)?;
                    out.push(RebaseRecord {
                        segment,
                        section,
                        section_offset,
                        rebase_type,
                    });
                    segment_offset += 8;
                }
            }
            REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                let (segment, section, section_offset) =
                    locate_section(&segments, segment_index, segment_offset)?;
                out.push(RebaseRecord {
                    segment,
                    section,
                    section_offset,
                    rebase_type,
                });
                segment_offset += 8;
                let (delta, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += len;
                segment_offset += delta;
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, count_len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += count_len;
                let (skip, skip_len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("rebase ULEB: {e}"))?;
                cursor += skip_len;
                for _ in 0..count {
                    let (segment, section, section_offset) =
                        locate_section(&segments, segment_index, segment_offset)?;
                    out.push(RebaseRecord {
                        segment,
                        section,
                        section_offset,
                        rebase_type,
                    });
                    segment_offset += 8 + skip;
                }
            }
            _ => return Err(format!("unsupported rebase opcode 0x{byte:02x}")),
        }
    }
    Ok(out)
}

fn decode_bind_records(bytes: &[u8], lazy: bool) -> Result<Vec<BindRecord>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    let (off, size) = if lazy {
        (dyld_info.lazy_bind_off, dyld_info.lazy_bind_size)
    } else {
        (dyld_info.bind_off, dyld_info.bind_size)
    };
    if size == 0 {
        return Ok(Vec::new());
    }
    let segments = segment_views(bytes)?;
    let start = off as usize;
    let end = start + size as usize;
    let stream = bytes
        .get(start..end)
        .ok_or_else(|| "bind stream out of bounds".to_string())?;

    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut segment_index = 0u8;
    let mut segment_offset = 0u64;
    let mut ordinal = 0u16;
    let mut symbol = String::new();
    let mut weak_import = false;
    while cursor < stream.len() {
        let byte = stream[cursor];
        cursor += 1;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;
        match opcode {
            BIND_OPCODE_DONE => {
                if lazy {
                    symbol.clear();
                    weak_import = false;
                } else {
                    break;
                }
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => ordinal = imm as u16,
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (value, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += len;
                ordinal = value as u16;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                let signed = ((imm as i8) << 4) >> 4;
                ordinal = signed as i16 as u16;
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                weak_import = (imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
                symbol = read_cstr(stream, &mut cursor)?;
            }
            BIND_OPCODE_SET_TYPE_IMM => {}
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment_index = imm;
                let (offset, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += len;
                segment_offset = offset;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let (delta, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += len;
                segment_offset += delta;
            }
            BIND_OPCODE_DO_BIND => {
                let (segment, section, section_offset) =
                    locate_section(&segments, segment_index, segment_offset)?;
                out.push(BindRecord {
                    segment,
                    section,
                    section_offset,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                });
                segment_offset += 8;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let (segment, section, section_offset) =
                    locate_section(&segments, segment_index, segment_offset)?;
                out.push(BindRecord {
                    segment,
                    section,
                    section_offset,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                });
                segment_offset += 8;
                let (delta, len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += len;
                segment_offset += delta;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                let (segment, section, section_offset) =
                    locate_section(&segments, segment_index, segment_offset)?;
                out.push(BindRecord {
                    segment,
                    section,
                    section_offset,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                });
                segment_offset += 8 + (imm as u64) * 8;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, count_len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += count_len;
                let (skip, skip_len) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind ULEB: {e}"))?;
                cursor += skip_len;
                for _ in 0..count {
                    let (segment, section, section_offset) =
                        locate_section(&segments, segment_index, segment_offset)?;
                    out.push(BindRecord {
                        segment,
                        section,
                        section_offset,
                        ordinal,
                        symbol: symbol.clone(),
                        weak_import,
                    });
                    segment_offset += 8 + skip;
                }
            }
            _ => return Err(format!("unsupported bind opcode 0x{byte:02x}")),
        }
    }
    Ok(out)
}

fn load_dylib_names(bytes: &[u8]) -> Result<Vec<String>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    Ok(commands
        .into_iter()
        .filter_map(|cmd| match cmd {
            LoadCommand::Dylib(cmd) if cmd.cmd == afs_ld::macho::constants::LC_LOAD_DYLIB => {
                Some(cmd.name)
            }
            _ => None,
        })
        .collect())
}

#[derive(Clone, Copy)]
struct SectionCase {
    segname: &'static str,
    sectname: &'static str,
}

#[derive(Clone, Copy)]
enum PageRefKind {
    Add,
    Load,
}

enum ParityCheck {
    ExactSections(&'static [SectionCase]),
    PageRef {
        section: SectionCase,
        site_offset: u64,
        target_offset: u64,
        kind: PageRefKind,
    },
}

struct ParityCase {
    name: &'static str,
    src: &'static str,
    check: ParityCheck,
}

struct ExportParityCase {
    name: &'static str,
    src: &'static str,
}

struct ClassicLazyParityCase {
    name: &'static str,
    src: &'static str,
}

struct DirectBindParityCase {
    name: &'static str,
    dylib_src: &'static str,
    main_src: &'static str,
}

fn assert_case_matches_apple_ld(case: &ParityCase, sdk: &str, sdk_ver: &str) -> Result<(), String> {
    let obj = scratch(&format!("parity-{}.o", case.name));
    let our_out = scratch(&format!("parity-{}-ours.out", case.name));
    let apple_out = scratch(&format!("parity-{}-apple.out", case.name));

    assemble(case.src, &obj)?;

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).map_err(|e| format!("afs-ld link failed for {}: {e}", case.name))?;
    apple_link(&obj, &apple_out, "_main", sdk, sdk_ver)?;

    let our_bytes = fs::read(&our_out).map_err(|e| format!("read our output: {e}"))?;
    let apple_bytes = fs::read(&apple_out).map_err(|e| format!("read apple output: {e}"))?;

    match case.check {
        ParityCheck::ExactSections(sections) => {
            for section in sections {
                let (_, ours) = output_section(&our_bytes, section.segname, section.sectname)
                    .ok_or_else(|| {
                        format!(
                            "missing our section {},{}",
                            section.segname, section.sectname
                        )
                    })?;
                let (_, theirs) = output_section(&apple_bytes, section.segname, section.sectname)
                    .ok_or_else(|| {
                    format!(
                        "missing apple section {},{}",
                        section.segname, section.sectname
                    )
                })?;
                let diff = diff_macho(&ours, &theirs);
                if !diff.is_clean() {
                    return Err(format!(
                        "{}: section {},{} diverged from Apple ld: {:#?}",
                        case.name, section.segname, section.sectname, diff.critical
                    ));
                }
            }
        }
        ParityCheck::PageRef {
            section,
            site_offset,
            target_offset,
            kind,
        } => {
            let (our_addr, our_bytes_sec) =
                output_section(&our_bytes, section.segname, section.sectname).ok_or_else(|| {
                    format!(
                        "missing our section {},{}",
                        section.segname, section.sectname
                    )
                })?;
            let (apple_addr, apple_bytes_sec) =
                output_section(&apple_bytes, section.segname, section.sectname).ok_or_else(
                    || {
                        format!(
                            "missing apple section {},{}",
                            section.segname, section.sectname
                        )
                    },
                )?;
            let our_target = decode_page_reference(&our_bytes_sec, our_addr, site_offset, &kind)?;
            let apple_target =
                decode_page_reference(&apple_bytes_sec, apple_addr, site_offset, &kind)?;
            let our_offset = our_target - our_addr;
            let apple_offset = apple_target - apple_addr;
            if our_offset != target_offset || apple_offset != target_offset {
                return Err(format!(
                    "{}: decoded target offset mismatch (ours={our_offset:#x}, apple={apple_offset:#x}, expected={target_offset:#x})",
                    case.name,
                ));
            }
        }
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    Ok(())
}

fn assert_dylib_export_case_matches_apple_ld(
    case: &ExportParityCase,
    sdk: &str,
    sdk_ver: &str,
) -> Result<(), String> {
    let obj = scratch(&format!("export-parity-{}.o", case.name));
    let our_out = scratch(&format!("export-parity-{}-ours.dylib", case.name));
    let apple_out = scratch(&format!("export-parity-{}-apple.dylib", case.name));

    assemble(case.src, &obj)?;

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    };
    Linker::run(&opts).map_err(|e| format!("afs-ld dylib link failed for {}: {e}", case.name))?;
    apple_link_dylib_classic(
        &obj,
        &apple_out,
        &format!("@rpath/{}.dylib", case.name),
        sdk,
        sdk_ver,
    )?;

    let our_bytes = fs::read(&our_out).map_err(|e| format!("read our output: {e}"))?;
    let apple_bytes = fs::read(&apple_out).map_err(|e| format!("read apple output: {e}"))?;
    if canonical_export_records(&our_bytes) != canonical_export_records(&apple_bytes) {
        return Err(format!(
            "{}: canonical export records diverged:\nours={:#?}\napple={:#?}",
            case.name,
            canonical_export_records(&our_bytes),
            canonical_export_records(&apple_bytes)
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::WeakBind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::WeakBind)
    {
        return Err(format!(
            "{}: weak-bind stream diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::Export)
        .map_err(|e| format!("read our export stream: {e}"))?
        .is_empty()
    {
        return Err(format!("{}: expected non-empty export trie", case.name));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    Ok(())
}

fn assert_classic_lazy_case_matches_apple_ld(
    case: &ClassicLazyParityCase,
    sdk: &str,
    sdk_ver: &str,
) -> Result<(), String> {
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        return Err(format!("no libSystem.tbd at {}", tbd.display()));
    }

    let obj = scratch(&format!("classic-lazy-{}.o", case.name));
    let our_out = scratch(&format!("classic-lazy-{}-ours.out", case.name));
    let apple_out = scratch(&format!("classic-lazy-{}-apple.out", case.name));

    assemble(case.src, &obj)?;

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts)
        .map_err(|e| format!("afs-ld classic-lazy link failed for {}: {e}", case.name))?;
    apple_link_classic_lazy(&obj, &apple_out, "_main", sdk, sdk_ver)?;

    let our_bytes = fs::read(&our_out).map_err(|e| format!("read our output: {e}"))?;
    let apple_bytes = fs::read(&apple_out).map_err(|e| format!("read apple output: {e}"))?;

    for (segname, sectname) in [("__TEXT", "__stubs"), ("__TEXT", "__stub_helper")] {
        let (_, ours) = output_section(&our_bytes, segname, sectname)
            .ok_or_else(|| format!("{}: missing our section {segname},{sectname}", case.name))?;
        let (_, theirs) = output_section(&apple_bytes, segname, sectname)
            .ok_or_else(|| format!("{}: missing apple section {segname},{sectname}", case.name))?;
        let diff = diff_macho(&ours, &theirs);
        if !diff.is_clean() {
            return Err(format!(
                "{}: section {},{} diverged from Apple ld: {:#?}",
                case.name, segname, sectname, diff.critical
            ));
        }
    }

    if load_dylib_names(&our_bytes).map_err(|e| format!("our dylibs: {e}"))?
        != load_dylib_names(&apple_bytes).map_err(|e| format!("apple dylibs: {e}"))?
    {
        return Err(format!(
            "{}: LC_LOAD_DYLIB set diverged from Apple ld",
            case.name
        ));
    }
    if segment_flags(&our_bytes, "__DATA_CONST") != segment_flags(&apple_bytes, "__DATA_CONST") {
        return Err(format!(
            "{}: __DATA_CONST flags diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::Rebase)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::Rebase)
    {
        return Err(format!(
            "{}: rebase stream diverged from Apple ld",
            case.name
        ));
    }
    if decode_rebase_records(&our_bytes).map_err(|e| format!("our rebases: {e}"))?
        != decode_rebase_records(&apple_bytes).map_err(|e| format!("apple rebases: {e}"))?
    {
        return Err(format!(
            "{}: rebase records diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::Bind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::Bind)
    {
        return Err(format!("{}: bind stream diverged from Apple ld", case.name));
    }
    if decode_bind_records(&our_bytes, false).map_err(|e| format!("our binds: {e}"))?
        != decode_bind_records(&apple_bytes, false).map_err(|e| format!("apple binds: {e}"))?
    {
        return Err(format!(
            "{}: bind records diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::WeakBind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::WeakBind)
    {
        return Err(format!(
            "{}: weak-bind stream diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_export_names(&our_bytes).map_err(|e| format!("our executable exports: {e}"))?
        != dyld_info_export_names(&apple_bytes)
            .map_err(|e| format!("apple executable exports: {e}"))?
    {
        return Err(format!(
            "{}: executable export trie diverged from Apple ld",
            case.name
        ));
    }
    if decode_bind_records(&our_bytes, true).map_err(|e| format!("our lazy binds: {e}"))?
        != decode_bind_records(&apple_bytes, true).map_err(|e| format!("apple lazy binds: {e}"))?
    {
        return Err(format!(
            "{}: lazy bind records diverged from Apple ld",
            case.name
        ));
    }
    if canonical_lazy_bind_stream(&our_bytes).map_err(|e| format!("our lazy stream: {e}"))?
        != canonical_lazy_bind_stream(&apple_bytes)
            .map_err(|e| format!("apple lazy stream: {e}"))?
    {
        return Err(format!(
            "{}: canonical lazy-bind stream diverged from Apple ld",
            case.name
        ));
    }
    if indirect_symbol_table(&our_bytes) != indirect_symbol_table(&apple_bytes) {
        return Err(format!(
            "{}: indirect symbol table diverged from Apple ld",
            case.name
        ));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    Ok(())
}

fn assert_direct_bind_case_matches_apple_ld(
    case: &DirectBindParityCase,
    sdk: &str,
    sdk_ver: &str,
) -> Result<(), String> {
    let dylib = scratch(&format!("direct-bind-{}.dylib", case.name));
    let obj = scratch(&format!("direct-bind-{}.o", case.name));
    let our_out = scratch(&format!("direct-bind-{}-ours.out", case.name));
    let apple_out = scratch(&format!("direct-bind-{}-apple.out", case.name));

    compile_dylib_c(case.dylib_src, &dylib)?;
    compile_c(case.main_src, &obj)?;

    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        return Err(format!("no libSystem.tbd at {}", tbd.display()));
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd, dylib.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts)
        .map_err(|e| format!("afs-ld direct-bind link failed for {}: {e}", case.name))?;
    let apple = Command::new("xcrun")
        .args([
            "ld",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            sdk_ver,
            sdk_ver,
            "-syslibroot",
            sdk,
            "-no_fixup_chains",
            "-lSystem",
            "-e",
            "_main",
            "-o",
        ])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&dylib)
        .output()
        .map_err(|e| format!("spawn xcrun ld: {e}"))?;
    if !apple.status.success() {
        return Err(format!(
            "xcrun ld failed for {}: {}",
            case.name,
            String::from_utf8_lossy(&apple.stderr)
        ));
    }

    let our_bytes = fs::read(&our_out).map_err(|e| format!("read our output: {e}"))?;
    let apple_bytes = fs::read(&apple_out).map_err(|e| format!("read apple output: {e}"))?;

    if load_dylib_names(&our_bytes).map_err(|e| format!("our dylibs: {e}"))?
        != load_dylib_names(&apple_bytes).map_err(|e| format!("apple dylibs: {e}"))?
    {
        return Err(format!(
            "{}: LC_LOAD_DYLIB set diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::Rebase)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::Rebase)
    {
        return Err(format!(
            "{}: rebase stream diverged from Apple ld",
            case.name
        ));
    }
    if decode_rebase_records(&our_bytes).map_err(|e| format!("our rebases: {e}"))?
        != decode_rebase_records(&apple_bytes).map_err(|e| format!("apple rebases: {e}"))?
    {
        return Err(format!(
            "{}: rebase records diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::Bind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::Bind)
    {
        return Err(format!("{}: bind stream diverged from Apple ld", case.name));
    }
    if decode_bind_records(&our_bytes, false).map_err(|e| format!("our binds: {e}"))?
        != decode_bind_records(&apple_bytes, false).map_err(|e| format!("apple binds: {e}"))?
    {
        return Err(format!(
            "{}: bind records diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::WeakBind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::WeakBind)
    {
        return Err(format!(
            "{}: weak-bind stream diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_export_names(&our_bytes).map_err(|e| format!("our executable exports: {e}"))?
        != dyld_info_export_names(&apple_bytes)
            .map_err(|e| format!("apple executable exports: {e}"))?
    {
        return Err(format!(
            "{}: executable export trie diverged from Apple ld",
            case.name
        ));
    }
    if dyld_info_stream(&our_bytes, DyldInfoStreamKind::LazyBind)
        != dyld_info_stream(&apple_bytes, DyldInfoStreamKind::LazyBind)
    {
        return Err(format!(
            "{}: lazy-bind stream diverged from Apple ld",
            case.name
        ));
    }

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    Ok(())
}

fn decode_page_reference(
    bytes: &[u8],
    section_addr: u64,
    site_offset: u64,
    kind: &PageRefKind,
) -> Result<u64, String> {
    let start = site_offset as usize;
    let adrp = read_insn(bytes, start)?;
    let second = read_insn(bytes, start + 4)?;
    let place = section_addr + site_offset;
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((place as i64) & !0xfff) + (adrp_pages << 12);
    let low = match kind {
        PageRefKind::Add => ((second >> 10) & 0xfff) as u64,
        PageRefKind::Load => {
            let shift = ((second >> 30) & 0b11) as u64;
            (((second >> 10) & 0xfff) as u64) << shift
        }
    };
    Ok((adrp_base as u64) + low)
}

fn decode_branch_target(bytes: &[u8], section_addr: u64, site_offset: u64) -> Result<u64, String> {
    let insn = read_insn(bytes, site_offset as usize)?;
    let imm26 = (insn & 0x03ff_ffff) as i64;
    let imm = sign_extend_26(imm26) << 2;
    Ok(section_addr
        .wrapping_add(site_offset)
        .wrapping_add_signed(imm))
}

fn read_insn(bytes: &[u8], start: usize) -> Result<u32, String> {
    let end = start + 4;
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| format!("instruction read OOB at 0x{start:x}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn sign_extend_26(value: i64) -> i64 {
    if value & (1 << 25) != 0 {
        value | !0x03ff_ffff
    } else {
        value
    }
}

#[test]
fn linker_run_emits_non_empty_executable_from_real_object() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun as or codesign unavailable");
        return;
    }

    let obj = scratch("main.o");
    let out = scratch("a.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov x0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut text_size = 0u64;
    let mut has_dylinker = false;
    for cmd in commands {
        match cmd {
            LoadCommand::Segment64(seg) => {
                for section in seg.sections {
                    if section.sectname_str() == "__text" {
                        text_size = section.size;
                    }
                }
            }
            LoadCommand::Raw { cmd, data, .. }
                if cmd == afs_ld::macho::constants::LC_LOAD_DYLINKER =>
            {
                has_dylinker = data
                    .windows(b"/usr/lib/dyld\0".len())
                    .any(|window| window == b"/usr/lib/dyld\0");
            }
            _ => {}
        }
    }
    assert!(text_size > 0, "expected non-empty __text output");
    assert!(
        has_dylinker,
        "expected LC_LOAD_DYLINKER in executable output"
    );
    assert!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o111 != 0,
        "expected executable output mode"
    );
    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&out).status().unwrap();
    assert_eq!(status.code(), Some(0), "expected executable to exit 0");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_minimal_dylib_from_real_object() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("lib.o");
    let out = scratch("libtiny.dylib");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _exported
        _exported:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let dyld_info = commands.iter().find_map(|cmd| match cmd {
        LoadCommand::DyldInfoOnly(cmd) => Some(*cmd),
        _ => None,
    });
    assert_eq!(header.filetype, afs_ld::macho::constants::MH_DYLIB);
    assert!(commands.iter().any(
        |cmd| matches!(cmd, LoadCommand::Dylib(d) if d.cmd == afs_ld::macho::constants::LC_ID_DYLIB)
    ));
    let dyld_info = dyld_info.expect("expected LC_DYLD_INFO_ONLY in dylib output");
    assert!(dyld_info.export_size > 0, "expected non-empty export trie");

    let dylib = DylibFile::parse(&out, &bytes).unwrap();
    let mut exports = dylib.exports.entries().unwrap();
    exports.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    assert!(
        exports.iter().any(|entry| entry.name == "_exported"),
        "expected _exported in export trie, got {:?}",
        exports
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn dylib_export_surfaces_match_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let case = ExportParityCase {
        name: "export-parity",
        src: r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _exported
            _exported:
                ret
            .subsections_via_symbols
        "#,
    };
    assert_dylib_export_case_matches_apple_ld(&case, &sdk, &sdk_ver).unwrap();
}

#[test]
fn dylib_export_surfaces_match_apple_ld_with_shared_prefixes() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let case = ExportParityCase {
        name: "export-prefix-parity",
        src: r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _alpha
            _alpha:
                ret
            .globl _alphabet
            _alphabet:
                ret
            .globl _alphanumeric
            _alphanumeric:
                ret
            .subsections_via_symbols
        "#,
    };
    assert_dylib_export_case_matches_apple_ld(&case, &sdk, &sdk_ver).unwrap();
}

#[test]
fn dylib_export_surfaces_match_apple_ld_across_fixture_matrix() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let cases = [
        ExportParityCase {
            name: "export-ordering",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _zeta
                _zeta:
                    ret
                .globl _alpha
                _alpha:
                    ret
                .globl _middle
                _middle:
                    ret
                .subsections_via_symbols
            "#,
        },
        ExportParityCase {
            name: "export-text-data",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _code_symbol
                _code_symbol:
                    ret
                .section __DATA,__data
                .p2align 3
                .globl _data_symbol
                _data_symbol:
                    .quad 0x1234
                .globl _more_data
                _more_data:
                    .long 7
                .subsections_via_symbols
            "#,
        },
        ExportParityCase {
            name: "export-text-const",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _entry
                _entry:
                    ret
                .section __TEXT,__const
                .p2align 3
                .globl _ro_value
                _ro_value:
                    .quad 0xfeedface
                .subsections_via_symbols
            "#,
        },
        ExportParityCase {
            name: "export-bss",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _touch
                _touch:
                    ret
                .zerofill __DATA,__bss,_global_bss,16,3
                .subsections_via_symbols
            "#,
        },
        ExportParityCase {
            name: "export-prefix-fanout",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _pre
                _pre:
                    ret
                .globl _prefix
                _prefix:
                    ret
                .globl _prefix_long
                _prefix_long:
                    ret
                .globl _prefix_lone
                _prefix_lone:
                    ret
                .subsections_via_symbols
            "#,
        },
        ExportParityCase {
            name: "export-shared-data-prefix",
            src: r#"
                .section __DATA,__data
                .p2align 3
                .globl _alpha_data
                _alpha_data:
                    .quad 1
                .globl _alphabet_data
                _alphabet_data:
                    .quad 2
                .globl _alphanumeric_data
                _alphanumeric_data:
                    .quad 3
                .subsections_via_symbols
            "#,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = assert_dylib_export_case_matches_apple_ld(case, &sdk, &sdk_ver) {
            failures.push(err);
        }
    }

    assert!(
        failures.is_empty(),
        "Apple ld dylib export parity failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn linker_run_reports_unresolved_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("missing.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(scratch("missing.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::UndefinedSymbols(msg) => {
            assert!(msg.contains("undefined symbol: _missing"), "{msg}");
        }
        other => panic!("expected UndefinedSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}

#[test]
fn linker_run_reports_duplicate_from_fetched_archive_member() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let main_obj = scratch("dup-main.o");
    let dup_obj = scratch("dup-member.o");
    let archive = scratch("dup.a");

    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .globl _dup
        _main:
            bl _archive_sym
            ret
        _dup:
            ret
        .subsections_via_symbols
    "#;
    let dup_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _archive_sym
        .globl _dup
        _archive_sym:
            ret
        _dup:
            ret
        .subsections_via_symbols
    "#;

    for (src, out) in [(&main_src, &main_obj), (&dup_src, &dup_obj)] {
        if let Err(e) = assemble(src, out) {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&dup_obj)
        .output()
        .unwrap();
    if !ar.status.success() {
        eprintln!(
            "skipping: ar failed: {}",
            String::from_utf8_lossy(&ar.stderr)
        );
        return;
    }

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), archive.clone()],
        output: Some(scratch("dup.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::DuplicateSymbols(msg) => {
            assert!(msg.contains("duplicate symbol _dup"), "{msg}");
        }
        other => panic!("expected DuplicateSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(dup_obj);
    let _ = fs::remove_file(archive);
}

#[test]
fn fetched_archive_member_undefined_reports_member_referrer() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let main_obj = scratch("member-main.o");
    let member_obj = scratch("member-undef.o");
    let archive = scratch("member.a");

    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _archive_sym
            ret
        .subsections_via_symbols
    "#;
    let member_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _archive_sym
        _archive_sym:
            bl _missing_from_member
            ret
        .subsections_via_symbols
    "#;

    for (src, out) in [(&main_src, &main_obj), (&member_src, &member_obj)] {
        if let Err(e) = assemble(src, out) {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member_obj)
        .output()
        .unwrap();
    if !ar.status.success() {
        eprintln!(
            "skipping: ar failed: {}",
            String::from_utf8_lossy(&ar.stderr)
        );
        return;
    }

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), archive.clone()],
        output: Some(scratch("member.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::UndefinedSymbols(msg) => {
            assert!(
                msg.contains("undefined symbol: _missing_from_member"),
                "{msg}"
            );
            assert!(
                msg.contains(&format!("referenced by {}(", archive.display())),
                "expected archive-member referrer in:\n{msg}"
            );
        }
        other => panic!("expected UndefinedSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(member_obj);
    let _ = fs::remove_file(archive);
}

#[test]
fn linker_run_carries_tbd_inputs_into_load_commands() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("tbd-main.o");
    let out = scratch("tbd-a.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov x0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(
        commands.iter().any(|cmd| matches!(
            cmd,
            LoadCommand::Dylib(d) if d.cmd == afs_ld::macho::constants::LC_LOAD_DYLIB
        )),
        "expected at least one LC_LOAD_DYLIB in output"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_handles_non_standard_segment_without_panicking() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("custom-segment.o");
    let out = scratch("custom-segment.out");
    let src = r#"
        .section __FOO,__bar
        .globl _custom
        _custom:
            .quad 1
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(commands.iter().any(|cmd| match cmd {
        LoadCommand::Segment64(seg) => seg.segname_str() == "__FOO",
        _ => false,
    }));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_uses_requested_entry_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("entry.o");
    let out = scratch("entry.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            ret
        .globl _alt
        _alt:
            mov x0, #1
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        entry: Some("_alt".into()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut text_offset = None;
    let mut main_entryoff = None;
    for cmd in commands {
        match cmd {
            LoadCommand::Segment64(seg) => {
                for section in seg.sections {
                    if section.sectname_str() == "__text" {
                        text_offset = Some(section.offset as u64);
                    }
                }
            }
            LoadCommand::Raw { cmd, data, .. } if cmd == afs_ld::macho::constants::LC_MAIN => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[0..8]);
                main_entryoff = Some(u64::from_le_bytes(buf));
            }
            _ => {}
        }
    }

    let text_offset = text_offset.expect("text section offset");
    let main_entryoff = main_entryoff.expect("LC_MAIN entryoff");
    assert!(
        main_entryoff > text_offset,
        "expected custom entry to land after start of __text: text={text_offset}, entry={main_entryoff}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_applies_core_arm64_relocations() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("relocs.o");
    let out = scratch("relocs.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .globl _helper
        _main:
            adrp x0, _target@PAGE
            add x0, x0, _target@PAGEOFF
            bl _helper
            ret
        _helper:
            ret

        .section __DATA,__data
        .p2align 3
        _target:
            .quad _helper

        .section __TEXT,__const
        .p2align 3
        _delta:
            .quad _helper - _main
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").expect("text section");
    let (data_addr, data) = output_section(&bytes, "__DATA", "__data").expect("data section");
    let (_, cdata) = output_section(&bytes, "__TEXT", "__const").expect("const section");

    let adrp = u32::from_le_bytes(text[0..4].try_into().unwrap());
    let add = u32::from_le_bytes(text[4..8].try_into().unwrap());
    let branch = u32::from_le_bytes(text[8..12].try_into().unwrap());
    let data_ptr = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let delta = u64::from_le_bytes(cdata[0..8].try_into().unwrap());

    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((text_addr as i64) & !0xfff) + (adrp_pages << 12);
    let add_imm = ((add >> 10) & 0xfff) as u64;
    let reconstructed_target = (adrp_base as u64) + add_imm;

    assert_eq!(
        reconstructed_target, data_addr,
        "ADRP+ADD should resolve _target"
    );
    assert_eq!(
        branch & 0x03ff_ffff,
        0x2,
        "BL should branch forward 8 bytes"
    );
    assert_eq!(
        data_ptr,
        text_addr + 16,
        ".quad _helper should point at helper"
    );
    assert_eq!(delta, 16, "_helper - _main should fold through SUBTRACTOR");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

fn sign_extend_21(value: i64) -> i64 {
    if value & (1 << 20) != 0 {
        value | !0x1f_ffff
    } else {
        value
    }
}

#[test]
fn linker_run_applies_scaled_pageoff12_for_ldr_x() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("scaled-ldr.o");
    let out = scratch("scaled-ldr.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldr x1, [x0, _target@PAGEOFF]
            ret

        .section __DATA,__data
        .space 0x3f8
        .p2align 3
        .globl _target
        _target:
            .quad 0x1122334455667788
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").expect("text section");
    let (data_addr, data) = output_section(&bytes, "__DATA", "__data").expect("data section");

    let adrp = u32::from_le_bytes(text[0..4].try_into().unwrap());
    let ldr = u32::from_le_bytes(text[4..8].try_into().unwrap());
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((text_addr as i64) & !0xfff) + (adrp_pages << 12);
    let ldr_shift = ((ldr >> 30) & 0b11) as u64;
    let ldr_imm = ((ldr >> 10) & 0xfff) as u64;
    let reconstructed_target = (adrp_base as u64) + (ldr_imm << ldr_shift);

    assert_eq!(ldr_shift, 3, "expected 64-bit LDR scale");
    assert_eq!(ldr_imm, 0x7f, "scaled imm12 should store 0x3f8 >> 3");
    assert_eq!(reconstructed_target, data_addr + 0x3f8);
    assert_eq!(
        u64::from_le_bytes(data[0x3f8..0x400].try_into().unwrap()),
        0x1122334455667788
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn relocated_sections_match_apple_ld_across_fixture_matrix() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    const TEXT: SectionCase = SectionCase {
        segname: "__TEXT",
        sectname: "__text",
    };
    const CONST: SectionCase = SectionCase {
        segname: "__TEXT",
        sectname: "__const",
    };

    let cases = [
        ParityCase {
            name: "branch-forward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    bl _helper
                    ret
                _helper:
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT]),
        },
        ParityCase {
            name: "branch-backward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT]),
        },
        ParityCase {
            name: "adrp-add-intra-text-forward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    ret
                .space 0x4ff4
                _target:
                    .quad 0
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x5000,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "adrp-add-intra-text-backward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                _target:
                    .quad 0x55
                .space 0x4ff8
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0x5000,
                target_offset: 0,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "adrp-ldr-x-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldr x1, [x0, _target@PAGEOFF]
                    ret
                .space 0x3f4
                _target:
                    .quad 0x1122334455667788
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x400,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldr-w-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldr w1, [x0, _target@PAGEOFF]
                    ret
                .space 0x2f4
                _target:
                    .long 0x11223344
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x300,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldrh-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldrh w1, [x0, _target@PAGEOFF]
                    ret
                .space 0x1f4
                _target:
                    .hword 0x3344
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x200,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldrb-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldrb w1, [x0, _target@PAGEOFF]
                    ret
                .space 0xf4
                _target:
                    .byte 0x44
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x100,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "mixed-branch-adrp-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                .globl _helper
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    bl _helper
                    ret
                _helper:
                    ret
                .space 0xff0
                _target:
                    .quad 0x99
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x1004,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "subtractor-positive",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _helper - _main
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[CONST]),
        },
        ParityCase {
            name: "subtractor-negative",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _main - _helper
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[CONST]),
        },
        ParityCase {
            name: "branch-and-subtractor",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _main - _helper
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT, CONST]),
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = assert_case_matches_apple_ld(case, &sdk, &sdk_ver) {
            failures.push(err);
        }
    }

    assert!(
        failures.is_empty(),
        "Apple ld parity failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn linker_run_rejects_out_of_range_branch26() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("branch26-range.o");
    let out = scratch("branch26-range.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            ret

        .zerofill __DATA,__bss,_gap,0x9000000,0

        .section __FAR,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::Reloc(err) => {
            let msg = err.to_string();
            assert!(msg.contains("Branch26"), "{msg}");
            assert!(msg.contains("out of BRANCH26 range"), "{msg}");
            assert!(msg.contains("_helper"), "{msg}");
        }
        other => panic!("expected Reloc error, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}

#[test]
fn linker_run_routes_dylib_imports_through_synthetic_sections() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("import-reloc.o");
    let out = scratch("import-reloc.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _write@GOTPAGE
            ldr x0, [x0, _write@GOTPAGEOFF]
            bl _write
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (stubs_addr, stubs) = output_section(&bytes, "__TEXT", "__stubs").unwrap();
    let (helper_addr, helper) = output_section(&bytes, "__TEXT", "__stub_helper").unwrap();
    let (got_addr, got) = output_section(&bytes, "__DATA_CONST", "__got").unwrap();
    let (lazy_addr, lazy) = output_section(&bytes, "__DATA", "__la_symbol_ptr").unwrap();
    let (dyld_private_addr, _) = output_section(&bytes, "__DATA", "__data").unwrap();
    let stubs_hdr = output_section_header(&bytes, "__TEXT", "__stubs").unwrap();
    let got_hdr = output_section_header(&bytes, "__DATA_CONST", "__got").unwrap();
    let lazy_hdr = output_section_header(&bytes, "__DATA", "__la_symbol_ptr").unwrap();

    let symtab = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Symtab(cmd) => Some(*cmd),
            _ => None,
        })
        .unwrap();
    let dysymtab = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Dysymtab(cmd) => Some(*cmd),
            _ => None,
        })
        .unwrap();
    let dyld_info = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::DyldInfoOnly(cmd) => Some(*cmd),
            _ => None,
        })
        .unwrap();
    let symbols = parse_nlist_table(&bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(&bytes, symtab.stroff, symtab.strsize).unwrap();
    let symbol_names: Vec<&str> = symbols
        .iter()
        .map(|symbol| strings.get(symbol.strx()).unwrap())
        .collect();

    assert_eq!(got.len(), 16);
    assert_eq!(stubs.len(), 12);
    assert_eq!(helper.len(), 36);
    assert_eq!(lazy.len(), 8);
    assert_eq!(symtab.nsyms, 5);
    assert_eq!(dysymtab.nlocalsym, 1);
    assert_eq!(dysymtab.nextdefsym, 2);
    assert_eq!(dysymtab.nundefsym, 2);
    assert_eq!(dysymtab.nindirectsyms, 4);
    assert_eq!(stubs_hdr.reserved1, 0);
    assert_eq!(got_hdr.reserved1, 1);
    assert_eq!(lazy_hdr.reserved1, 3);
    assert_eq!(stubs_hdr.reserved2, 12);
    assert!(dyld_info.rebase_size > 0);
    assert!(dyld_info.bind_size > 0);
    assert!(dyld_info.lazy_bind_size > 0);
    assert_eq!(
        decode_page_reference(&text, text_addr, 0, &PageRefKind::Load).unwrap(),
        got_addr
    );
    assert_eq!(
        decode_branch_target(&text, text_addr, 8).unwrap(),
        stubs_addr
    );
    assert_eq!(
        decode_page_reference(&stubs, stubs_addr, 0, &PageRefKind::Load).unwrap(),
        lazy_addr
    );
    assert_eq!(read_insn(&stubs, 8).unwrap(), 0xd61f0200);
    assert_eq!(
        u64::from_le_bytes(lazy[0..8].try_into().unwrap()),
        helper_addr + 24
    );
    assert_eq!(
        decode_page_reference(&helper, helper_addr, 0, &PageRefKind::Add).unwrap(),
        dyld_private_addr
    );
    assert_eq!(
        decode_page_reference(&helper, helper_addr, 12, &PageRefKind::Load).unwrap(),
        got_addr + 8
    );
    assert_eq!(read_insn(&helper, 20).unwrap(), 0xd61f0200);
    assert_eq!(read_insn(&helper, 24).unwrap(), 0x1800_0050);
    assert_eq!(
        decode_branch_target(&helper, helper_addr, 28).unwrap(),
        helper_addr
    );
    assert_eq!(u32::from_le_bytes(helper[32..36].try_into().unwrap()), 0);
    let (locals, extdefs, undefs) = symbol_partition_names(&bytes);
    assert_eq!(locals, vec!["__dyld_private".to_string()]);
    assert_eq!(
        extdefs,
        vec!["__mh_execute_header".to_string(), "_main".to_string()]
    );
    assert_eq!(
        undefs,
        vec!["_write".to_string(), "dyld_stub_binder".to_string()]
    );
    assert!(symbol_names.contains(&"__dyld_private"));
    assert!(symbols[dysymtab.iundefsym as usize..]
        .iter()
        .all(|symbol| symbol.kind() == SymKind::Undef));
    assert!(symbols[dysymtab.iundefsym as usize..]
        .iter()
        .all(|symbol| symbol.library_ordinal().unwrap() > 0));
    assert!(symbol_names.contains(&"_write"));
    assert!(symbol_names.contains(&"dyld_stub_binder"));

    let _ = fs::remove_file(out);
    let _ = fs::remove_file(obj);
}

#[test]
fn synthetic_import_surfaces_match_apple_ld_classic_lazy_model() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("import-parity.o");
    let our_out = scratch("import-parity-ours.out");
    let apple_out = scratch("import-parity-apple.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _write@GOTPAGE
            ldr x0, [x0, _write@GOTPAGEOFF]
            bl _write
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();

    for (segname, sectname) in [("__TEXT", "__stubs"), ("__TEXT", "__stub_helper")] {
        let (_, ours) = output_section(&our_bytes, segname, sectname).unwrap();
        let (_, apple) = output_section(&apple_bytes, segname, sectname).unwrap();
        let diff = diff_macho(&ours, &apple);
        assert!(
            diff.is_clean(),
            "{segname},{sectname} diverged from Apple ld: {:#?}",
            diff.critical
        );
    }

    let (our_helper_addr, _) = output_section(&our_bytes, "__TEXT", "__stub_helper").unwrap();
    let (apple_helper_addr, _) = output_section(&apple_bytes, "__TEXT", "__stub_helper").unwrap();
    let (_, our_lazy) = output_section(&our_bytes, "__DATA", "__la_symbol_ptr").unwrap();
    let (_, apple_lazy) = output_section(&apple_bytes, "__DATA", "__la_symbol_ptr").unwrap();
    assert_eq!(
        u64::from_le_bytes(our_lazy[0..8].try_into().unwrap()) - our_helper_addr,
        24
    );
    assert_eq!(
        u64::from_le_bytes(apple_lazy[0..8].try_into().unwrap()) - apple_helper_addr,
        24
    );

    assert_eq!(
        load_dylib_names(&our_bytes).unwrap(),
        load_dylib_names(&apple_bytes).unwrap()
    );
    assert_eq!(
        segment_flags(&our_bytes, "__DATA_CONST"),
        Some(SG_READ_ONLY)
    );
    assert_eq!(
        segment_flags(&our_bytes, "__DATA_CONST"),
        segment_flags(&apple_bytes, "__DATA_CONST")
    );

    let our_rebases = decode_rebase_records(&our_bytes).unwrap();
    let apple_rebases = decode_rebase_records(&apple_bytes).unwrap();
    assert!(our_rebases
        .iter()
        .all(|record| record.rebase_type == REBASE_TYPE_POINTER));
    assert_eq!(our_rebases, apple_rebases);
    assert_eq!(
        decode_bind_records(&our_bytes, false).unwrap(),
        decode_bind_records(&apple_bytes, false).unwrap()
    );
    assert_eq!(
        dyld_info_stream(&our_bytes, DyldInfoStreamKind::WeakBind).unwrap(),
        dyld_info_stream(&apple_bytes, DyldInfoStreamKind::WeakBind).unwrap()
    );
    assert_eq!(
        decode_bind_records(&our_bytes, true).unwrap(),
        decode_bind_records(&apple_bytes, true).unwrap()
    );
    assert_eq!(
        canonical_lazy_bind_stream(&our_bytes).unwrap(),
        canonical_lazy_bind_stream(&apple_bytes).unwrap()
    );
    assert_eq!(
        indirect_symbol_table(&our_bytes),
        indirect_symbol_table(&apple_bytes)
    );

    let _ = fs::remove_file(apple_out);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(obj);
}

#[test]
fn classic_lazy_surfaces_match_apple_ld_across_fixture_matrix() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let cases = [
        ClassicLazyParityCase {
            name: "single-got-and-call",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _write@GOTPAGE
                    ldr x0, [x0, _write@GOTPAGEOFF]
                    bl _write
                    ret
                .subsections_via_symbols
            "#,
        },
        ClassicLazyParityCase {
            name: "batched-got-and-calls",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _write@GOTPAGE
                    ldr x0, [x0, _write@GOTPAGEOFF]
                    bl _write
                    adrp x1, _close@GOTPAGE
                    ldr x1, [x1, _close@GOTPAGEOFF]
                    bl _close
                    adrp x2, _read@GOTPAGE
                    ldr x2, [x2, _read@GOTPAGEOFF]
                    bl _read
                    ret
                .subsections_via_symbols
            "#,
        },
        ClassicLazyParityCase {
            name: "branch-only-calls",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    bl _write
                    bl _close
                    bl _read
                    ret
                .subsections_via_symbols
            "#,
        },
        ClassicLazyParityCase {
            name: "deduped-import",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _write@GOTPAGE
                    ldr x0, [x0, _write@GOTPAGEOFF]
                    bl _write
                    bl _write
                    adrp x1, _write@GOTPAGE
                    ldr x1, [x1, _write@GOTPAGEOFF]
                    ret
                .subsections_via_symbols
            "#,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = assert_classic_lazy_case_matches_apple_ld(case, &sdk, &sdk_ver) {
            failures.push(err);
        }
    }

    assert!(
        failures.is_empty(),
        "Apple ld classic-lazy parity failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn linker_run_binds_direct_dylib_import_pointers() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let dylib_src = r#"
        int ext_data = 5;
    "#;
    let direct_case = DirectBindParityCase {
        name: "direct-data",
        dylib_src,
        main_src: r#"
            extern int ext_data;
            int *p = &ext_data;
            int main(void) { return *p == 5 ? 0 : 1; }
        "#,
    };
    if let Err(e) = assert_direct_bind_case_matches_apple_ld(&direct_case, &sdk, &sdk_ver) {
        panic!("{e}");
    }

    let dylib = scratch("direct-data.dylib");
    let obj = scratch("direct-data.o");
    let our_out = scratch("direct-data-ours.out");

    if let Err(e) = compile_dylib_c(dylib_src, &dylib) {
        eprintln!("skipping: dylib compile failed: {e}");
        return;
    }

    let main_src = r#"
        extern int ext_data;
        int *p = &ext_data;
        int main(void) { return *p == 5 ? 0 : 1; }
    "#;
    if let Err(e) = compile_c(main_src, &obj) {
        eprintln!("skipping: compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone(), dylib.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let binds = decode_bind_records(&our_bytes, false).unwrap();
    assert!(
        binds.iter().any(|record| {
            record.segment == "__DATA"
                && record.section == "__data"
                && record.section_offset == 0
                && record.symbol == "_ext_data"
        }),
        "missing direct bind for imported data: {binds:#?}"
    );
    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&our_out)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&our_out).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "expected direct-import pointer executable to exit 0"
    );

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
}

#[test]
fn direct_bind_surfaces_match_apple_ld_across_fixture_matrix() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let cases = [
        DirectBindParityCase {
            name: "direct-multi-data",
            dylib_src: r#"
                int ext_data = 5;
                int more_data = 9;
            "#,
            main_src: r#"
                extern int ext_data;
                extern int more_data;
                int *p = &ext_data;
                int *q = &more_data;
                int main(void) { return (*p == 5 && *q == 9) ? 0 : 1; }
            "#,
        },
        DirectBindParityCase {
            name: "direct-and-call-mixed",
            dylib_src: r#"
                int ext_data = 5;
                int ext_fn(void) { return ext_data + 1; }
            "#,
            main_src: r#"
                extern int ext_data;
                extern int ext_fn(void);
                int *p = &ext_data;
                int main(void) { return *p + ext_fn() == 11 ? 0 : 1; }
            "#,
        },
        DirectBindParityCase {
            name: "direct-deduped",
            dylib_src: r#"
                int ext_data = 5;
            "#,
            main_src: r#"
                extern int ext_data;
                int *p = &ext_data;
                int *q = &ext_data;
                int main(void) { return (*p == 5 && *q == 5) ? 0 : 1; }
            "#,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = assert_direct_bind_case_matches_apple_ld(case, &sdk, &sdk_ver) {
            failures.push(err);
        }
    }

    assert!(
        failures.is_empty(),
        "Apple ld direct-bind parity failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn linker_run_rebases_local_absolute_pointers_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("local-rebase.o");
    let our_out = scratch("local-rebase-ours.out");
    let apple_out = scratch("local-rebase-apple.out");
    let src = r#"
        int ext = 7;
        int *p = &ext;
        int main(void) { return *p == 7 ? 0 : 1; }
    "#;
    if let Err(e) = compile_c(src, &obj) {
        eprintln!("skipping: clang compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert!(!dyld_info_stream(&our_bytes, DyldInfoStreamKind::Rebase)
        .unwrap()
        .is_empty());
    assert_eq!(
        dyld_info_stream(&our_bytes, DyldInfoStreamKind::Rebase).unwrap(),
        dyld_info_stream(&apple_bytes, DyldInfoStreamKind::Rebase).unwrap()
    );
    assert_eq!(
        decode_rebase_records(&our_bytes).unwrap(),
        decode_rebase_records(&apple_bytes).unwrap()
    );

    let our_status = Command::new(&our_out).status().unwrap();
    let apple_status = Command::new(&apple_out).status().unwrap();
    assert_eq!(our_status.code(), Some(0));
    assert_eq!(apple_status.code(), Some(0));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_partitions_symtab_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }

    let dylib = scratch("symtab-partition.dylib");
    let obj = scratch("symtab-partition.o");
    let our_out = scratch("symtab-partition-ours.out");
    let apple_out = scratch("symtab-partition-apple.out");

    let dylib_src = r#"
        int ext_data = 5;
    "#;
    if let Err(e) = compile_dylib_c(dylib_src, &dylib) {
        eprintln!("skipping: dylib compile failed: {e}");
        return;
    }

    let asm = r#"
        .text
        .private_extern _hidden
        .globl _visible
        .globl _main
        .p2align 2
    _local:
        ret
    _hidden:
        ret
    _visible:
        ret
    _main:
        ret

        .data
        .quad _ext_data
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), dylib.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let apple = Command::new("xcrun")
        .args(["ld", "-arch", "arm64", "-e", "_main", "-o"])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&dylib)
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (our_symtab, our_dysymtab) = symtab_and_dysymtab(&our_bytes);
    let (apple_symtab, apple_dysymtab) = symtab_and_dysymtab(&apple_bytes);

    assert_eq!(our_symtab.nsyms, apple_symtab.nsyms);
    assert_eq!(our_dysymtab.ilocalsym, apple_dysymtab.ilocalsym);
    assert_eq!(our_dysymtab.nlocalsym, apple_dysymtab.nlocalsym);
    assert_eq!(our_dysymtab.iextdefsym, apple_dysymtab.iextdefsym);
    assert_eq!(our_dysymtab.nextdefsym, apple_dysymtab.nextdefsym);
    assert_eq!(our_dysymtab.iundefsym, apple_dysymtab.iundefsym);
    assert_eq!(our_dysymtab.nundefsym, apple_dysymtab.nundefsym);
    assert_eq!(
        canonical_symbol_records(&our_bytes),
        canonical_symbol_records(&apple_bytes)
    );
    assert_strtab_within_five_percent(
        &raw_string_table(&our_bytes),
        &raw_string_table(&apple_bytes),
    );

    assert_eq!(
        symbol_partition_names(&our_bytes),
        symbol_partition_names(&apple_bytes)
    );

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_strips_locals_with_x_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }

    let dylib = scratch("symtab-strip.dylib");
    let obj = scratch("symtab-strip.o");
    let our_out = scratch("symtab-strip-ours.out");
    let apple_out = scratch("symtab-strip-apple.out");

    let dylib_src = r#"
        int ext_data = 5;
    "#;
    if let Err(e) = compile_dylib_c(dylib_src, &dylib) {
        eprintln!("skipping: dylib compile failed: {e}");
        return;
    }

    let asm = r#"
        .text
        .private_extern _hidden
        .globl _visible
        .globl _main
        .p2align 2
    _local:
        ret
    _hidden:
        ret
    _visible:
        ret
    _main:
        ret

        .data
        .quad _ext_data
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), dylib.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        strip_locals: true,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let apple = Command::new("xcrun")
        .args(["ld", "-arch", "arm64", "-x", "-e", "_main", "-o"])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&dylib)
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (our_symtab, our_dysymtab) = symtab_and_dysymtab(&our_bytes);
    let (apple_symtab, apple_dysymtab) = symtab_and_dysymtab(&apple_bytes);

    assert_eq!(our_symtab.nsyms, apple_symtab.nsyms);
    assert_eq!(our_dysymtab.ilocalsym, apple_dysymtab.ilocalsym);
    assert_eq!(our_dysymtab.nlocalsym, apple_dysymtab.nlocalsym);
    assert_eq!(our_dysymtab.iextdefsym, apple_dysymtab.iextdefsym);
    assert_eq!(our_dysymtab.nextdefsym, apple_dysymtab.nextdefsym);
    assert_eq!(our_dysymtab.iundefsym, apple_dysymtab.iundefsym);
    assert_eq!(our_dysymtab.nundefsym, apple_dysymtab.nundefsym);
    assert_eq!(
        canonical_symbol_records(&our_bytes),
        canonical_symbol_records(&apple_bytes)
    );

    let (locals, extdefs, undefs) = symbol_partition_names(&our_bytes);
    assert!(locals.is_empty());
    assert_eq!(
        extdefs,
        vec![
            "__mh_execute_header".to_string(),
            "_main".to_string(),
            "_visible".to_string()
        ]
    );
    assert_eq!(undefs, vec!["_ext_data".to_string()]);

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_leaf_unwind_info_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("unwind-leaf.o");
    let our_out = scratch("unwind-leaf-ours.out");
    let apple_out = scratch("unwind-leaf-apple.out");
    let src = r#"
        int main(void) {
            return 0;
        }
    "#;
    if let Err(e) = compile_c(src, &obj) {
        eprintln!("skipping: clang compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        normalized_unwind_words(&our_bytes),
        normalized_unwind_words(&apple_bytes)
    );
    assert!(output_section(&our_bytes, "__LD", "__compact_unwind").is_none());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_multi_function_unwind_info_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("unwind-mixed.o");
    let our_out = scratch("unwind-mixed-ours.out");
    let apple_out = scratch("unwind-mixed-apple.out");
    let src = r#"
        int helper(void) {
            return 1;
        }

        int main(void) {
            return helper();
        }
    "#;
    if let Err(e) = compile_c(src, &obj) {
        eprintln!("skipping: clang compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        normalized_unwind_words(&our_bytes),
        normalized_unwind_words(&apple_bytes)
    );
    assert!(output_section(&our_bytes, "__LD", "__compact_unwind").is_none());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_preserves_eh_frame_like_ld() {
    if !have_xcrun() || !have_xcrun_tool("dwarfdump") {
        eprintln!("skipping: xcrun dwarfdump unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("eh-frame.o");
    let our_out = scratch("eh-frame-ours.out");
    let apple_out = scratch("eh-frame-apple.out");
    let asm = r#"
        .text
        .globl _main
        .p2align 2
    _main:
        .cfi_startproc
        sub sp, sp, #16
        .cfi_def_cfa_offset 16
        str x30, [sp, #8]
        .cfi_offset w30, -8
        bl _helper
        ldr x30, [sp, #8]
        add sp, sp, #16
        ret
        .cfi_endproc

        .globl _helper
        .p2align 2
    _helper:
        .cfi_startproc
        ret
        .cfi_endproc
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert!(output_section(&our_bytes, "__TEXT", "__eh_frame").is_some());
    assert_eq!(
        output_section(&our_bytes, "__TEXT", "__eh_frame")
            .unwrap()
            .1
            .len(),
        output_section(&apple_bytes, "__TEXT", "__eh_frame")
            .unwrap()
            .1
            .len()
    );
    let our_dump = normalized_eh_frame_dump(
        &our_out,
        output_section(&our_bytes, "__TEXT", "__text").unwrap().0,
    )
    .unwrap();
    let apple_dump = normalized_eh_frame_dump(
        &apple_out,
        output_section(&apple_bytes, "__TEXT", "__text").unwrap().0,
    )
    .unwrap();
    assert_eq!(our_dump, apple_dump);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_preserves_exception_unwind_metadata_like_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("clang++") || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang++ or codesign unavailable");
        return;
    }

    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let libsystem = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    let libcxx = PathBuf::from(format!("{sdk}/usr/lib/libc++.tbd"));
    if !libsystem.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", libsystem.display());
        return;
    }
    if !libcxx.exists() {
        eprintln!("skipping: no libc++.tbd at {}", libcxx.display());
        return;
    }

    let obj = scratch("cxx-exc.o");
    let our_out = scratch("cxx-exc-ours.out");
    let apple_out = scratch("cxx-exc-apple.out");
    let src = r#"
        int helper() { throw 7; }
        int main() {
            try { return helper(); }
            catch (...) { return 42; }
        }
    "#;
    if let Err(e) = compile_cxx(src, &obj) {
        eprintln!("skipping: clang++ compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), libcxx.clone(), libsystem.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_cxx_classic(&obj, &apple_out).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        decode_bind_records(&our_bytes, false).unwrap(),
        decode_bind_records(&apple_bytes, false).unwrap()
    );
    assert_eq!(
        decode_bind_records(&our_bytes, true).unwrap(),
        decode_bind_records(&apple_bytes, true).unwrap()
    );
    assert_eq!(
        canonical_lazy_bind_stream(&our_bytes).unwrap(),
        canonical_lazy_bind_stream(&apple_bytes).unwrap()
    );
    let our_decoded = canonical_unwind_info(&our_bytes);
    let apple_decoded = canonical_unwind_info(&apple_bytes);
    assert_eq!(our_decoded, apple_decoded);
    assert_eq!(our_decoded.personalities.len(), 1);
    assert_eq!(our_decoded.lsdas.len(), 1);
    assert!(output_section(&our_bytes, "__TEXT", "__gcc_except_tab").is_some());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_function_starts_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("function-starts.o");
    let our_out = scratch("function-starts-ours.out");
    let apple_out = scratch("function-starts-apple.out");
    let asm = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .p2align 2
    _main:
        adrp x0, _write@GOTPAGE
        ldr x0, [x0, _write@GOTPAGEOFF]
        bl _write
        ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let our_fstarts = raw_linkedit_data_cmd(&our_bytes, LC_FUNCTION_STARTS);
    let apple_fstarts = raw_linkedit_data_cmd(&apple_bytes, LC_FUNCTION_STARTS);
    assert_ne!(our_fstarts.0, 0);
    assert_eq!(our_fstarts.1, apple_fstarts.1);
    assert_eq!(our_fstarts.1, 8);
    assert!(output_section(&our_bytes, "__TEXT", "__stubs").is_some());
    assert!(output_section(&our_bytes, "__TEXT", "__stub_helper").is_some());
    assert_eq!(decode_function_starts(&our_bytes).len(), 1);
    assert_eq!(decode_function_starts(&apple_bytes).len(), 1);
    let our_text_addr = output_section(&our_bytes, "__TEXT", "__text").unwrap().0;
    let apple_text_addr = output_section(&apple_bytes, "__TEXT", "__text").unwrap().0;
    let our_text_base = segment_vmaddr(&our_bytes, "__TEXT").unwrap();
    let apple_text_base = segment_vmaddr(&apple_bytes, "__TEXT").unwrap();
    assert_eq!(
        decode_function_starts(&our_bytes),
        vec![our_text_addr - our_text_base]
    );
    assert_eq!(
        decode_function_starts(&apple_bytes),
        vec![apple_text_addr - apple_text_base]
    );

    let our_dic = raw_linkedit_data_cmd(&our_bytes, LC_DATA_IN_CODE);
    let apple_dic = raw_linkedit_data_cmd(&apple_bytes, LC_DATA_IN_CODE);
    assert_ne!(our_dic.0, 0);
    assert_eq!(our_dic.1, apple_dic.1);
    assert_eq!(our_dic.0, our_fstarts.0 + our_fstarts.1);
    assert_eq!(apple_dic.0, apple_fstarts.0 + apple_fstarts.1);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_function_starts_for_other_text_sections_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("function-starts-textcoal.o");
    let our_out = scratch("function-starts-textcoal-ours.out");
    let apple_out = scratch("function-starts-textcoal-apple.out");
    let asm = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .p2align 2
    _main:
        ret

        .section __TEXT,__textcoal_nt,regular,pure_instructions
        .globl _helper
        .p2align 2
    _helper:
        ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(decode_function_starts(&our_bytes).len(), 2);
    assert_eq!(decode_function_starts(&apple_bytes).len(), 2);

    let our_text_addr = output_section(&our_bytes, "__TEXT", "__text").unwrap().0;
    let our_textcoal_addr = output_section(&our_bytes, "__TEXT", "__textcoal_nt")
        .unwrap()
        .0;
    let our_text_base = segment_vmaddr(&our_bytes, "__TEXT").unwrap();
    assert_eq!(
        decode_function_starts(&our_bytes),
        vec![
            our_text_addr - our_text_base,
            our_textcoal_addr - our_text_base
        ]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_remaps_data_in_code_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("data-in-code.o");
    let our_out = scratch("data-in-code-ours.out");
    let apple_out = scratch("data-in-code-apple.out");
    let asm = r#"
        .text
        .globl _main
        .p2align 2
    _main:
        mov w0, #0
        b Ldispatch
        .p2align 2
    Ltable:
        .data_region jt32
        .long Lcase0-Ltable
        .long Lcase1-Ltable
        .end_data_region
    Ldispatch:
        cmp w0, #0
        b.eq Lcase0
        b Lcase1
    Lcase0:
        mov w0, #1
        ret
    Lcase1:
        mov w0, #2
        ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let our_dic = raw_linkedit_data_cmd(&our_bytes, LC_DATA_IN_CODE);
    let apple_dic = raw_linkedit_data_cmd(&apple_bytes, LC_DATA_IN_CODE);
    assert_ne!(our_dic.1, 0);
    assert_eq!(our_dic.1, apple_dic.1);
    assert_eq!(decode_data_in_code(&our_bytes).len(), 1);
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        canonical_data_in_code(&apple_bytes)
    );
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        vec![DataInCodeRecord {
            offset: 8,
            length: 8,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_remaps_data_in_code_in_later_text_section_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("data-in-code-late.o");
    let our_out = scratch("data-in-code-late-ours.out");
    let apple_out = scratch("data-in-code-late-apple.out");
    let asm = r#"
        .text
        .globl _main
        .p2align 2
    _main:
        ret

        .section __TEXT,__text2,regular,pure_instructions
        .globl _helper
        .p2align 2
    _helper:
        b Ldispatch
        .p2align 2
    Ltable:
        .data_region jt32
        .long Lcase0-Ltable
        .long Lcase1-Ltable
        .end_data_region
    Ldispatch:
        ret
    Lcase0:
        ret
    Lcase1:
        ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        canonical_data_in_code(&apple_bytes)
    );
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        vec![DataInCodeRecord {
            offset: 8,
            length: 8,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_remaps_data_in_code_after_large_first_text_section_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("data-in-code-large-first.o");
    let our_out = scratch("data-in-code-large-first-ours.out");
    let apple_out = scratch("data-in-code-large-first-apple.out");
    let asm = r#"
        .text
        .globl _main
        .p2align 2
    _main:
        nop
        nop
        nop
        nop
        nop
        ret

        .section __TEXT,__text2,regular,pure_instructions
        .globl _helper
    _helper:
        b Ldispatch
        .p2align 2
    Ltable:
        .data_region jt32
        .long Lcase0-Ltable
        .long Lcase1-Ltable
        .end_data_region
    Ldispatch:
        ret
    Lcase0:
        ret
    Lcase1:
        ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        canonical_data_in_code(&apple_bytes)
    );
    assert_eq!(
        canonical_data_in_code(&our_bytes),
        vec![DataInCodeRecord {
            offset: 28,
            length: 8,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_dedups_output_strtab_like_ld() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("strtab-dedup.o");
    let our_out = scratch("strtab-dedup-ours.out");
    let apple_out = scratch("strtab-dedup-apple.out");
    let mut asm =
        String::from("        .text\n        .globl _afs_array_sum\n        .globl _main\n");
    for idx in 0..20 {
        let symbol = format!("_pad_symbol_{idx:02}");
        asm.push_str(&format!("        .globl {symbol}\n"));
    }
    asm.push_str("        .p2align 2\n");
    asm.push_str("    _array_sum:\n        ret\n");
    asm.push_str("    _afs_array_sum:\n        ret\n");
    for idx in 0..20 {
        let symbol = format!("_pad_symbol_{idx:02}");
        asm.push_str(&format!("    {symbol}:\n        ret\n"));
    }
    asm.push_str("    _main:\n        bl _afs_array_sum\n        ret\n");
    asm.push_str("        .subsections_via_symbols\n");
    if let Err(e) = assemble(&asm, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        canonical_symbol_records(&our_bytes),
        canonical_symbol_records(&apple_bytes)
    );
    let our_strtab = raw_string_table(&our_bytes);
    let apple_strtab = raw_string_table(&apple_bytes);
    assert_strtab_within_five_percent(&our_strtab, &apple_strtab);
    assert!(
        our_strtab.len() <= apple_strtab.len(),
        "suffix dedup should not grow the output string table: ours={} apple={}",
        our_strtab.len(),
        apple_strtab.len()
    );

    let offsets = symbol_name_offsets(&our_bytes);
    assert_eq!(offsets["_array_sum"], offsets["_afs_array_sum"] + 4);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_launches_with_classic_lazy_dylib_import() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let dylib = scratch("lazy-runtime.dylib");
    let obj = scratch("lazy-runtime.o");
    let out = scratch("lazy-runtime.out");

    let dylib_src = r#"
        int ext_fn(void) { return 7; }
    "#;
    if let Err(e) = compile_dylib_c(dylib_src, &dylib) {
        eprintln!("skipping: dylib compile failed: {e}");
        return;
    }

    let main_src = r#"
        int ext_fn(void);
        int main(void) { return ext_fn() == 7 ? 0 : 1; }
    "#;
    if let Err(e) = compile_c(main_src, &obj) {
        eprintln!("skipping: compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd, dylib.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&out).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "expected dylib-import executable to exit 0"
    );

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_handles_local_tlv_descriptors() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("tlvp-local.o");
    let out = scratch("tlvp-local.out");
    let src = r#"
        __thread long tls_a = 7;
        __thread long tls_b;

        static long tls_sum(void) {
            return tls_a + tls_b;
        }

        int main(void) {
            return tls_sum() == 7 ? 0 : 1;
        }
    "#;
    if let Err(e) = compile_c(src, &obj) {
        eprintln!("skipping: compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, thread_vars) = output_section(&bytes, "__DATA", "__thread_vars").unwrap();
    let (_, thread_data) = output_section(&bytes, "__DATA", "__thread_data").unwrap();
    assert!(output_section(&bytes, "__DATA", "__thread_ptrs").is_none());
    assert_eq!(thread_vars.len(), 48);
    assert_eq!(thread_data.len(), 8);
    assert_eq!(
        u64::from_le_bytes(thread_vars[16..24].try_into().unwrap()),
        0
    );
    assert_eq!(
        u64::from_le_bytes(thread_vars[40..48].try_into().unwrap()),
        8
    );

    let binds = decode_bind_records(&bytes, false).unwrap();
    let mut tlv_binds: Vec<_> = binds
        .into_iter()
        .filter(|record| record.section == "__thread_vars" && record.symbol == "__tlv_bootstrap")
        .collect();
    tlv_binds.sort_by_key(|record| record.section_offset);
    assert_eq!(tlv_binds.len(), 2);
    assert_eq!(tlv_binds[0].section_offset, 0);
    assert_eq!(tlv_binds[1].section_offset, 24);

    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let symtab = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Symtab(cmd) => Some(*cmd),
            _ => None,
        })
        .unwrap();
    let symbols = parse_nlist_table(&bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(&bytes, symtab.stroff, symtab.strsize).unwrap();
    let symbol_names: Vec<&str> = symbols
        .iter()
        .map(|symbol| strings.get(symbol.strx()).unwrap())
        .collect();
    assert!(symbol_names.contains(&"__tlv_bootstrap"));

    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&out).status().unwrap();
    assert_eq!(status.code(), Some(0), "expected TLV executable to exit 0");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_routes_imported_tlv_through_got() {
    if !have_xcrun() || !have_tool("codesign") {
        eprintln!("skipping: xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let dylib = scratch("libtlvprobe.dylib");
    let obj = scratch("imported-tlv.o");
    let our_out = scratch("imported-tlv-ours.out");
    let apple_out = scratch("imported-tlv-apple.out");

    let dylib_src = r#"
        __thread long ext_tls = 5;
        long read_lib_tls(void) { return ext_tls; }
    "#;
    if let Err(e) = compile_dylib_c(dylib_src, &dylib) {
        eprintln!("skipping: dylib compile failed: {e}");
        return;
    }

    let main_src = r#"
        extern __thread long ext_tls;
        int main(void) { return ext_tls == 5 ? 0 : 1; }
    "#;
    if let Err(e) = compile_c(main_src, &obj) {
        eprintln!("skipping: compile failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone(), dylib.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let apple = Command::new("xcrun")
        .args([
            "ld",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            &sdk_ver,
            &sdk_ver,
            "-syslibroot",
            &sdk,
            "-no_fixup_chains",
            "-lSystem",
            "-e",
            "_main",
            "-o",
        ])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&dylib)
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (our_text_addr, our_text) = output_section(&our_bytes, "__TEXT", "__text").unwrap();
    let (apple_text_addr, apple_text) = output_section(&apple_bytes, "__TEXT", "__text").unwrap();
    let (our_got_addr, our_got) = output_section(&our_bytes, "__DATA_CONST", "__got").unwrap();
    let (apple_got_addr, apple_got) =
        output_section(&apple_bytes, "__DATA_CONST", "__got").unwrap();

    assert!(output_section(&our_bytes, "__DATA", "__thread_ptrs").is_none());
    assert!(output_section(&apple_bytes, "__DATA", "__thread_ptrs").is_none());
    assert_eq!(our_got.len(), 8);
    assert_eq!(our_got, apple_got);
    assert_eq!(
        decode_page_reference(&our_text, our_text_addr, 20, &PageRefKind::Load).unwrap(),
        our_got_addr
    );
    assert_eq!(
        decode_page_reference(&apple_text, apple_text_addr, 20, &PageRefKind::Load).unwrap(),
        apple_got_addr
    );
    assert_eq!(our_text, apple_text);
    assert_eq!(read_insn(&our_text, 24).unwrap(), 0xf9400000);
    assert_eq!(read_insn(&our_text, 28).unwrap(), 0xf9400008);
    assert_eq!(read_insn(&our_text, 32).unwrap(), 0xd63f0100);
    assert_eq!(
        decode_bind_records(&our_bytes, false).unwrap(),
        decode_bind_records(&apple_bytes, false).unwrap()
    );
    assert_eq!(
        load_dylib_names(&our_bytes).unwrap(),
        load_dylib_names(&apple_bytes).unwrap()
    );
    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&our_out)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&our_out).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "expected imported TLV executable to exit 0"
    );

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}
