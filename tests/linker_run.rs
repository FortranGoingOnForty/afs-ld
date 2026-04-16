//! End-to-end `Linker::run` coverage for Sprint 10's newly wired pipeline.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

mod common;

use afs_ld::leb::read_uleb;
use afs_ld::macho::constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_MASK,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, BIND_OPCODE_SET_TYPE_IMM,
    BIND_SYMBOL_FLAGS_WEAK_IMPORT, REBASE_IMMEDIATE_MASK, REBASE_OPCODE_ADD_ADDR_IMM_SCALED,
    REBASE_OPCODE_ADD_ADDR_ULEB, REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
    REBASE_OPCODE_DO_REBASE_IMM_TIMES, REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB, REBASE_OPCODE_DONE, REBASE_OPCODE_MASK,
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, REBASE_OPCODE_SET_TYPE_IMM, REBASE_TYPE_POINTER,
};
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand, Section64Header};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, SymKind};
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

fn dyld_info_stream(bytes: &[u8], lazy: bool) -> Result<Vec<u8>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    let (off, size) = if lazy {
        (dyld_info.lazy_bind_off, dyld_info.lazy_bind_size)
    } else {
        (dyld_info.bind_off, dyld_info.bind_size)
    };
    if size == 0 {
        return Ok(Vec::new());
    }
    let start = off as usize;
    let end = start + size as usize;
    bytes.get(start..end)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| "dyld-info stream out of bounds".to_string())
}

fn canonical_lazy_bind_stream(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = dyld_info_stream(bytes, true)?;
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

fn assert_case_matches_apple_ld(
    case: &ParityCase,
    sdk: &str,
    sdk_ver: &str,
) -> Result<(), String> {
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
                        format!("missing our section {},{}", section.segname, section.sectname)
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
            let (our_addr, our_bytes_sec) = output_section(&our_bytes, section.segname, section.sectname)
                .ok_or_else(|| format!("missing our section {},{}", section.segname, section.sectname))?;
            let (apple_addr, apple_bytes_sec) =
                output_section(&apple_bytes, section.segname, section.sectname).ok_or_else(|| {
                    format!("missing apple section {},{}", section.segname, section.sectname)
                })?;
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
    Ok(section_addr.wrapping_add(site_offset).wrapping_add_signed(imm))
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
                has_dylinker = data.windows(b"/usr/lib/dyld\0".len()).any(|window| {
                    window == b"/usr/lib/dyld\0"
                });
            }
            _ => {}
        }
    }
    assert!(text_size > 0, "expected non-empty __text output");
    assert!(has_dylinker, "expected LC_LOAD_DYLINKER in executable output");
    assert!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o111 != 0,
        "expected executable output mode"
    );
    let verify = Command::new("codesign").arg("-v").arg(&out).output().unwrap();
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
    assert_eq!(header.filetype, afs_ld::macho::constants::MH_DYLIB);
    assert!(
        commands
            .iter()
            .any(|cmd| matches!(cmd, LoadCommand::Dylib(d) if d.cmd == afs_ld::macho::constants::LC_ID_DYLIB))
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
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
        eprintln!("skipping: ar failed: {}", String::from_utf8_lossy(&ar.stderr));
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
        eprintln!("skipping: ar failed: {}", String::from_utf8_lossy(&ar.stderr));
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
            assert!(msg.contains("undefined symbol: _missing_from_member"), "{msg}");
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

    assert_eq!(reconstructed_target, data_addr, "ADRP+ADD should resolve _target");
    assert_eq!(branch & 0x03ff_ffff, 0x2, "BL should branch forward 8 bytes");
    assert_eq!(data_ptr, text_addr + 16, ".quad _helper should point at helper");
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
    assert_eq!(symtab.nsyms, 2);
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
    assert_eq!(decode_branch_target(&text, text_addr, 8).unwrap(), stubs_addr);
    assert_eq!(
        decode_page_reference(&stubs, stubs_addr, 0, &PageRefKind::Load).unwrap(),
        lazy_addr
    );
    assert_eq!(read_insn(&stubs, 8).unwrap(), 0xd61f0200);
    assert_eq!(u64::from_le_bytes(lazy[0..8].try_into().unwrap()), helper_addr + 24);
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
    assert_eq!(decode_branch_target(&helper, helper_addr, 28).unwrap(), helper_addr);
    assert_eq!(u32::from_le_bytes(helper[32..36].try_into().unwrap()), 0);
    assert!(symbols.iter().all(|symbol| symbol.kind() == SymKind::Undef));
    assert!(symbols
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

    let our_rebases = decode_rebase_records(&our_bytes).unwrap();
    let apple_rebases = decode_rebase_records(&apple_bytes).unwrap();
    assert!(our_rebases.iter().all(|record| record.rebase_type == REBASE_TYPE_POINTER));
    assert_eq!(our_rebases, apple_rebases);
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

    let _ = fs::remove_file(apple_out);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(obj);
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

    let verify = Command::new("codesign").arg("-v").arg(&out).output().unwrap();
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
    assert_eq!(u64::from_le_bytes(thread_vars[16..24].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(thread_vars[40..48].try_into().unwrap()), 8);

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

    let verify = Command::new("codesign").arg("-v").arg(&out).output().unwrap();
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
    assert_eq!(load_dylib_names(&our_bytes).unwrap(), load_dylib_names(&apple_bytes).unwrap());
    let verify = Command::new("codesign").arg("-v").arg(&our_out).output().unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let status = Command::new(&our_out).status().unwrap();
    assert_eq!(status.code(), Some(0), "expected imported TLV executable to exit 0");

    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}
