//! End-to-end `Linker::run` coverage for Sprint 10's newly wired pipeline.

#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

mod common;

use afs_ld::input::ObjectFile;
use afs_ld::leb::{read_sleb, read_uleb};
use afs_ld::macho::constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_MASK, BIND_OPCODE_SET_ADDEND_SLEB,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, BIND_OPCODE_SET_TYPE_IMM,
    BIND_SYMBOL_FLAGS_WEAK_IMPORT, CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_V8,
    CPU_SUBTYPE_LIB64, CPU_TYPE_ARM64, DICE_KIND_DATA, DICE_KIND_JUMP_TABLE32,
    EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, INDIRECT_SYMBOL_ABS,
    INDIRECT_SYMBOL_LOCAL, LC_BUILD_VERSION, LC_DATA_IN_CODE, LC_DYLD_INFO_ONLY, LC_DYSYMTAB,
    LC_FUNCTION_STARTS, LC_LINKER_OPTIMIZATION_HINT, LC_SEGMENT_64, LC_SYMTAB, MH_BINDS_TO_WEAK,
    MH_MAGIC_64, MH_OBJECT, MH_SUBSECTIONS_VIA_SYMBOLS, MH_WEAK_DEFINES, N_ABS, N_ALT_ENTRY, N_EXT,
    N_INDR, N_PEXT, N_SECT, N_UNDF, N_WEAK_DEF, N_WEAK_REF, REBASE_IMMEDIATE_MASK,
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED, REBASE_OPCODE_ADD_ADDR_ULEB, REBASE_OPCODE_DONE,
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB, REBASE_OPCODE_DO_REBASE_IMM_TIMES,
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES, REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
    REBASE_OPCODE_MASK, REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, REBASE_OPCODE_SET_TYPE_IMM,
    REBASE_TYPE_POINTER, SECTION_TYPE_MASK, SG_READ_ONLY, S_ATTR_DEBUG, S_ATTR_LIVE_SUPPORT,
    S_ATTR_NO_TOC, S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_ATTR_STRIP_STATIC_SYMS,
    S_COALESCED, S_CSTRING_LITERALS, S_REGULAR, S_ZEROFILL,
};
use afs_ld::macho::dylib::DylibFile;
use afs_ld::macho::exports::Exports;
use afs_ld::macho::reader::{
    parse_commands, parse_header, u32_le, write_header, LinkEditDataCmd, LoadCommand, MachHeader64,
    Section64Header, Segment64, SymtabCmd, HEADER_SIZE,
};
use afs_ld::reloc::{
    parse_raw_relocs, parse_relocs, write_raw_relocs, write_relocs, Referent, Reloc, RelocKind,
    RelocLength,
};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, RawNlist, SymKind, NLIST_SIZE};
use afs_ld::synth::unwind::decode_unwind_info;
use afs_ld::{FrameworkSpec, IcfMode, LinkError, LinkOptions, Linker, OutputKind};
use common::artifacts::workspace_artifact;
use common::harness::{
    canonical_export_records, compare_sections, diff_macho, CanonicalExportKind,
};

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

fn with_cpu_subtype(mut object: Vec<u8>, cpu_subtype: u32) -> Vec<u8> {
    object[8..12].copy_from_slice(&cpu_subtype.to_le_bytes());
    object
}

fn append_archive_field(archive: &mut Vec<u8>, value: &str, width: usize) {
    assert!(value.len() <= width);
    archive.extend_from_slice(value.as_bytes());
    archive.resize(archive.len() + width - value.len(), b' ');
}

fn synthetic_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = b"!<arch>\n".to_vec();
    for (name, body) in members {
        append_archive_field(&mut archive, &format!("{name}/"), 16);
        append_archive_field(&mut archive, "0", 12);
        append_archive_field(&mut archive, "0", 6);
        append_archive_field(&mut archive, "0", 6);
        append_archive_field(&mut archive, "100644", 8);
        append_archive_field(&mut archive, &body.len().to_string(), 10);
        archive.extend_from_slice(b"`\n");
        archive.extend_from_slice(body);
        if body.len() % 2 != 0 {
            archive.push(b'\n');
        }
    }
    archive
}

fn name16(name: &str) -> [u8; 16] {
    assert!(name.len() <= 16);
    let mut out = [0; 16];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

fn synthetic_single_section_object(
    segment_name: &str,
    section_name: &str,
    section_flags: u32,
    data: &[u8],
    relocs: &[Reloc],
    symbols: &[(&str, u8, u8, u16, u64)],
) -> Vec<u8> {
    let raw_relocs = write_relocs(relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let symbols: Vec<RawNlist> = symbols
        .iter()
        .map(|&(name, n_type, n_sect, n_desc, n_value)| {
            let strx = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            RawNlist {
                strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            }
        })
        .collect();

    let mut segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: data.len() as u64,
        fileoff: 0,
        filesize: data.len() as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16(section_name),
            segname: name16(segment_name),
            addr: 0,
            size: data.len() as u64,
            offset: 0,
            align: 3,
            reloff: 0,
            nreloc: raw_relocs.len() as u32,
            flags: section_flags,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + data.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_icf_const_object(symbol: &str) -> Vec<u8> {
    synthetic_single_section_object(
        "__TEXT",
        "__const",
        S_REGULAR,
        &0x1122_3344_5566_7788u64.to_le_bytes(),
        &[],
        &[(symbol, N_SECT | N_EXT | N_PEXT, 1, 0, 0)],
    )
}

fn synthetic_local_symbol_collision_reference_object() -> Vec<u8> {
    let mut data = 0u64.to_le_bytes().to_vec();
    data.extend_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
    synthetic_single_section_object(
        "__DATA",
        "__localref",
        S_REGULAR,
        &data,
        &[Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        }],
        &[
            ("_same", N_SECT, 1, 0, 8),
            ("_local_pointer", N_SECT | N_EXT, 1, 0, 0),
        ],
    )
}

fn synthetic_subtractor_difference_object(minuend: &str, subtrahend: &str) -> Vec<u8> {
    synthetic_single_section_object(
        "__DATA",
        "__data",
        S_REGULAR,
        &[0; 8],
        &[Reloc {
            offset: 0,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(2),
            addend: 0,
            subtrahend: Some(Referent::Symbol(1)),
        }],
        &[
            ("_difference", N_SECT | N_EXT, 1, 0, 0),
            (subtrahend, N_UNDF | N_EXT, 0, 0, 0),
            (minuend, N_UNDF | N_EXT, 0, 0, 0),
        ],
    )
}

fn synthetic_got_reference_object(entry: &str, target: &str, weak_ref: bool) -> Vec<u8> {
    let text = [
        0x00, 0x00, 0x00, 0x90, // adrp x0, target@GOTPAGE
        0x00, 0x00, 0x40, 0xf9, // ldr x0, [x0, target@GOTPAGEOFF]
        0x00, 0x00, 0x80, 0x52, // mov w0, #0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let relocs = [
        Reloc {
            offset: 0,
            kind: RelocKind::GotLoadPage21,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(1),
            addend: 0,
            subtrahend: None,
        },
        Reloc {
            offset: 4,
            kind: RelocKind::GotLoadPageOff12,
            length: RelocLength::Word,
            pcrel: false,
            referent: Referent::Symbol(1),
            addend: 0,
            subtrahend: None,
        },
    ];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let entry_strx = strings.len() as u32;
    strings.extend_from_slice(entry.as_bytes());
    strings.push(0);
    let target_strx = strings.len() as u32;
    strings.extend_from_slice(target.as_bytes());
    strings.push(0);
    let symbols = [
        RawNlist {
            strx: entry_strx,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: target_strx,
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc: if weak_ref { N_WEAK_REF } else { 0 },
            n_value: 0,
        },
    ];

    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: 2,
            reloff: 0,
            nreloc: raw_relocs.len() as u32,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + text.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_absolute_reference_object(entry: &str, target: &str) -> Vec<u8> {
    synthetic_data_reference_object(entry, target, RelocKind::Unsigned, RelocLength::Quad, false)
}

fn synthetic_unsigned_word_reference_object(entry: &str, target: &str) -> Vec<u8> {
    synthetic_data_reference_object(entry, target, RelocKind::Unsigned, RelocLength::Word, false)
}

fn synthetic_pointer_to_got_reference_object(
    entry: &str,
    target: &str,
    length: RelocLength,
    pcrel: bool,
) -> Vec<u8> {
    synthetic_data_reference_object(entry, target, RelocKind::PointerToGot, length, pcrel)
}

fn synthetic_data_reference_object(
    entry: &str,
    target: &str,
    kind: RelocKind,
    length: RelocLength,
    pcrel: bool,
) -> Vec<u8> {
    let field_size = length.byte_width();
    let mut text = vec![0; field_size];
    text.extend_from_slice(&[
        0x00, 0x00, 0x80, 0x52, // mov w0, #0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ]);
    let relocs = [Reloc {
        offset: 0,
        kind,
        length,
        pcrel,
        referent: Referent::Symbol(1),
        addend: 0,
        subtrahend: None,
    }];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let entry_strx = strings.len() as u32;
    strings.extend_from_slice(entry.as_bytes());
    strings.push(0);
    let target_strx = strings.len() as u32;
    strings.extend_from_slice(target.as_bytes());
    strings.push(0);
    let symbols = [
        RawNlist {
            strx: entry_strx,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: field_size as u64,
        },
        RawNlist {
            strx: target_strx,
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc: 0,
            n_value: 0,
        },
    ];

    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: field_size.trailing_zeros(),
            reloff: 0,
            nreloc: raw_relocs.len() as u32,
            flags: S_REGULAR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + text.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_segment_rebase_object(
    pointer_segment: &str,
    pointer_section: &str,
    pointer_flags: u32,
) -> Vec<u8> {
    let text = [
        0x00, 0x00, 0x80, 0x52, // mov w0, #0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let pointer = [0; 8];
    let target = 7u64.to_le_bytes();
    let relocs = [Reloc {
        offset: 0,
        kind: RelocKind::Unsigned,
        length: RelocLength::Quad,
        pcrel: false,
        referent: Referent::Section(3),
        addend: 0,
        subtrahend: None,
    }];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let symbols = [
        RawNlist {
            strx: add_string("_main"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: add_string("_p"),
            n_type: N_SECT | N_EXT,
            n_sect: 2,
            n_desc: 0,
            n_value: 8,
        },
        RawNlist {
            strx: add_string("_target"),
            n_type: N_SECT | N_EXT,
            n_sect: 3,
            n_desc: 0,
            n_value: 16,
        },
    ];

    let mut segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: 24,
        fileoff: 0,
        filesize: 24,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![
            Section64Header {
                sectname: name16("__text"),
                segname: name16("__TEXT"),
                addr: 0,
                size: text.len() as u64,
                offset: 0,
                align: 2,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16(pointer_section),
                segname: name16(pointer_segment),
                addr: 8,
                size: pointer.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: raw_relocs.len() as u32,
                flags: pointer_flags,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__data"),
                segname: name16("__DATA"),
                addr: 16,
                size: target.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
        ],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    for (index, section) in segment.sections.iter_mut().enumerate() {
        section.offset = data_offset + (index as u32) * 8;
    }
    segment.sections[1].reloff = data_offset + 24;
    let symoff = segment.sections[1].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&pointer);
    bytes.extend_from_slice(&target);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_icf_section_reference_object(symbol: &str, data_value: u64) -> Vec<u8> {
    let text = [
        0x00, 0x00, 0x00, 0x90, // adrp x0, __data@PAGE
        0x00, 0x00, 0x00, 0x91, // add x0, x0, __data@PAGEOFF
        0x00, 0x00, 0x40, 0xb9, // ldr w0, [x0]
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let data = data_value.to_le_bytes();
    let relocs = [
        Reloc {
            offset: 0,
            kind: RelocKind::Page21,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        },
        Reloc {
            offset: 4,
            kind: RelocKind::PageOff12,
            length: RelocLength::Word,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        },
    ];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let symbol_strx = strings.len() as u32;
    strings.extend_from_slice(symbol.as_bytes());
    strings.push(0);
    let symbols = [RawNlist {
        strx: symbol_strx,
        n_type: N_SECT | N_EXT | N_PEXT,
        n_sect: 1,
        n_desc: 0,
        n_value: 0,
    }];

    let mut segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: (text.len() + data.len()) as u64,
        fileoff: 0,
        filesize: (text.len() + data.len()) as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![
            Section64Header {
                sectname: name16("__text"),
                segname: name16("__TEXT"),
                addr: 0,
                size: text.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: raw_relocs.len() as u32,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__data"),
                segname: name16("__DATA"),
                addr: text.len() as u64,
                size: data.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
        ],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[1].offset = data_offset + text.len() as u32;
    segment.sections[0].reloff = data_offset + text.len() as u32 + data.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&data);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_icf_local_literal_pointer_object() -> Vec<u8> {
    let mut pointers = 0u64.to_le_bytes().to_vec();
    pointers.extend_from_slice(&4u64.to_le_bytes());
    let cstrings = b"dup\0dup\0";
    let relocs = [
        Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        },
        Reloc {
            offset: 8,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        },
    ];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let strings = b"\0_pointers\0";
    let symbols = [RawNlist {
        strx: 1,
        n_type: N_SECT | N_EXT,
        n_sect: 1,
        n_desc: 0,
        n_value: 0,
    }];
    let mut segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: (pointers.len() + cstrings.len()) as u64,
        fileoff: 0,
        filesize: (pointers.len() + cstrings.len()) as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![
            Section64Header {
                sectname: name16("__const"),
                segname: name16("__DATA"),
                addr: 0,
                size: pointers.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: raw_relocs.len() as u32,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__cstring"),
                segname: name16("__TEXT"),
                addr: pointers.len() as u64,
                size: cstrings.len() as u64,
                offset: 0,
                align: 0,
                reloff: 0,
                nreloc: 0,
                flags: S_CSTRING_LITERALS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
        ],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[1].offset = data_offset + pointers.len() as u32;
    segment.sections[0].reloff = data_offset + pointers.len() as u32 + cstrings.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&pointers);
    bytes.extend_from_slice(cstrings);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(strings);
    bytes
}

fn synthetic_icf_const_domains_object(first_segment: &str, second_segment: &str) -> Vec<u8> {
    let value = 0x1122_3344_5566_7788u64.to_le_bytes();

    let mut strings = vec![0];
    let first_strx = strings.len() as u32;
    strings.extend_from_slice(b"_first_const\0");
    let second_strx = strings.len() as u32;
    strings.extend_from_slice(b"_second_const\0");
    let symbols = [
        RawNlist {
            strx: first_strx,
            n_type: N_SECT | N_EXT | N_PEXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: second_strx,
            n_type: N_SECT | N_EXT | N_PEXT,
            n_sect: 2,
            n_desc: 0,
            n_value: value.len() as u64,
        },
    ];

    let mut segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: (value.len() * 2) as u64,
        fileoff: 0,
        filesize: (value.len() * 2) as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![
            Section64Header {
                sectname: name16("__const"),
                segname: name16(first_segment),
                addr: 0,
                size: value.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__const"),
                segname: name16(second_segment),
                addr: value.len() as u64,
                size: value.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
        ],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[1].offset = data_offset + value.len() as u32;
    let symoff = data_offset + (value.len() * 2) as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&value);
    bytes.extend_from_slice(&value);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

#[derive(Clone, Copy)]
enum SyntheticAliasEncoding {
    Indirect,
    ExplicitAlternateEntry,
    OverlappingSection,
}

const SAME_ADDRESS_ENTRY_CODE: [u8; 8] = [
    0x40, 0x05, 0x80, 0x52, // mov w0, #42
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

fn synthetic_defined_alias_object(
    private_alias: bool,
    private_main: bool,
    private_target: bool,
    reference_alias: bool,
    encoding: SyntheticAliasEncoding,
) -> Vec<u8> {
    let first_instruction = if reference_alias {
        [0x00, 0x00, 0x00, 0x94] // bl _alias
    } else {
        [0x00, 0x00, 0x80, 0x52] // mov w0, #0
    };
    let text = [
        first_instruction,
        [0xc0, 0x03, 0x5f, 0xd6], // ret
        [0x1f, 0x20, 0x03, 0xd5], // nop
        [0xc0, 0x03, 0x5f, 0xd6], // _target: ret
    ]
    .concat();
    let relocs = if reference_alias {
        vec![Reloc {
            offset: 0,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(match encoding {
                SyntheticAliasEncoding::Indirect => 1,
                SyntheticAliasEncoding::ExplicitAlternateEntry => 2,
                SyntheticAliasEncoding::OverlappingSection => 1,
            }),
            addend: 0,
            subtrahend: None,
        }]
    } else {
        Vec::new()
    };
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let main_strx = add_string("_main");
    let alias_strx = add_string("_alias");
    let target_strx = add_string("_target");
    let main = RawNlist {
        strx: main_strx,
        n_type: N_SECT | N_EXT | if private_main { N_PEXT } else { 0 },
        n_sect: 1,
        n_desc: 0,
        n_value: 0,
    };
    let target = RawNlist {
        strx: target_strx,
        n_type: N_SECT | N_EXT | if private_target { N_PEXT } else { 0 },
        n_sect: 1,
        n_desc: 0,
        n_value: 12,
    };
    let alias = match encoding {
        SyntheticAliasEncoding::Indirect => RawNlist {
            strx: alias_strx,
            n_type: N_INDR | N_EXT | if private_alias { N_PEXT } else { 0 },
            n_sect: 0,
            n_desc: 0,
            n_value: target_strx as u64,
        },
        SyntheticAliasEncoding::ExplicitAlternateEntry => RawNlist {
            strx: alias_strx,
            n_type: N_SECT | N_EXT | if private_alias { N_PEXT } else { 0 },
            n_sect: 1,
            n_desc: N_ALT_ENTRY,
            n_value: 12,
        },
        SyntheticAliasEncoding::OverlappingSection => RawNlist {
            strx: alias_strx,
            n_type: N_SECT | N_EXT | if private_alias { N_PEXT } else { 0 },
            n_sect: 1,
            n_desc: 0,
            n_value: 12,
        },
    };
    let symbols = match encoding {
        SyntheticAliasEncoding::Indirect | SyntheticAliasEncoding::OverlappingSection => {
            [main, alias, target]
        }
        SyntheticAliasEncoding::ExplicitAlternateEntry => [main, target, alias],
    };

    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: 2,
            reloff: 0,
            nreloc: raw_relocs.len() as u32,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + text.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

#[derive(Clone, Copy)]
enum SyntheticUnwindReferent {
    Direct,
    IndirectAlias,
}

fn synthetic_compact_unwind_alias_object(
    unwind_referent: Option<SyntheticUnwindReferent>,
) -> Vec<u8> {
    let text = [
        0x00, 0x00, 0x80, 0x52, // _main: mov w0, #0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let main_strx = add_string("_main");
    let alias_strx = add_string("_alias");
    let symbols = [
        RawNlist {
            strx: main_strx,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: alias_strx,
            n_type: N_INDR | N_EXT,
            n_sect: 0,
            n_desc: 0,
            n_value: main_strx as u64,
        },
    ];

    let mut compact_unwind = Vec::new();
    let mut reloc_bytes = Vec::new();
    if let Some(referent) = unwind_referent {
        compact_unwind.resize(32, 0);
        compact_unwind[8..12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        compact_unwind[12..16].copy_from_slice(&0x0200_0000u32.to_le_bytes());
        let raw_relocs = write_relocs(&[Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(match referent {
                SyntheticUnwindReferent::Direct => 0,
                SyntheticUnwindReferent::IndirectAlias => 1,
            }),
            addend: 0,
            subtrahend: None,
        }])
        .unwrap();
        write_raw_relocs(&raw_relocs, &mut reloc_bytes);
    }

    let mut sections = vec![Section64Header {
        sectname: name16("__text"),
        segname: name16("__TEXT"),
        addr: 0,
        size: text.len() as u64,
        offset: 0,
        align: 2,
        reloff: 0,
        nreloc: 0,
        flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    }];
    if unwind_referent.is_some() {
        sections.push(Section64Header {
            sectname: name16("__compact_unwind"),
            segname: name16("__LD"),
            addr: text.len() as u64,
            size: compact_unwind.len() as u64,
            offset: 0,
            align: 3,
            reloff: 0,
            nreloc: 1,
            flags: S_REGULAR | S_ATTR_DEBUG,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        });
    }

    let data_size = text.len() + compact_unwind.len();
    let mut segment = Segment64 {
        segname: name16(""),
        vmaddr: 0,
        vmsize: data_size as u64,
        fileoff: 0,
        filesize: data_size as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections,
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    if unwind_referent.is_some() {
        segment.sections[1].offset = data_offset + text.len() as u32;
        segment.sections[1].reloff = data_offset + data_size as u32;
    }
    let symoff = data_offset + data_size as u32 + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&compact_unwind);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_dwarf_unwind_object() -> Vec<u8> {
    synthetic_dwarf_unwind_object_for(8, &[("_main", 0, true)], &[(0, 8)])
}

fn synthetic_nested_local_dwarf_unwind_object() -> Vec<u8> {
    synthetic_dwarf_unwind_object_for(
        24,
        &[
            ("L_local_one", 8, false),
            ("L_local_two", 16, false),
            ("_main", 0, true),
        ],
        &[(0, 8), (1, 8)],
    )
}

fn synthetic_dwarf_unwind_fde_addend_object() -> Vec<u8> {
    synthetic_dwarf_unwind_object_for_with_fde_referents(
        16,
        &[("_dead_base", 0, true), ("_main", 8, true)],
        &[(1, 8)],
        &[(0, 8)],
    )
}

/// Build LLVM-shaped compact-unwind and CFI records. `unwind_functions`
/// indexes `text_symbols`, allowing local function entries to live inside a
/// larger atom owned by an external symbol at a different offset.
fn synthetic_dwarf_unwind_object_for(
    text_len: usize,
    text_symbols: &[(&str, u64, bool)],
    unwind_functions: &[(usize, u32)],
) -> Vec<u8> {
    let fde_referents = unwind_functions
        .iter()
        .map(|(symbol_index, _)| (*symbol_index, 0))
        .collect::<Vec<_>>();
    synthetic_dwarf_unwind_object_for_with_fde_referents(
        text_len,
        text_symbols,
        unwind_functions,
        &fde_referents,
    )
}

fn synthetic_dwarf_unwind_object_for_with_fde_referents(
    text_len: usize,
    text_symbols: &[(&str, u64, bool)],
    unwind_functions: &[(usize, u32)],
    fde_referents: &[(usize, i64)],
) -> Vec<u8> {
    assert!(text_len >= 4 && text_len.is_multiple_of(4));
    assert_eq!(unwind_functions.len(), fde_referents.len());
    let mut text = [0x1f, 0x20, 0x03, 0xd5].repeat(text_len / 4);
    text[text_len - 4..].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);

    let mut compact_unwind = vec![0u8; 32 * unwind_functions.len()];
    for (record_index, (_, code_len)) in unwind_functions.iter().enumerate() {
        let record = &mut compact_unwind[record_index * 32..(record_index + 1) * 32];
        record[8..12].copy_from_slice(&code_len.to_le_bytes());
        record[12..16].copy_from_slice(&0x0300_0000u32.to_le_bytes());
    }

    // Canonical CIE/FDE shape emitted by LLVM's Mach-O assembler for arm64
    // functions whose CFI cannot be represented compactly.
    let mut eh_frame = vec![
        0x10, 0x00, 0x00, 0x00, // CIE payload length
        0x00, 0x00, 0x00, 0x00, // CIE id
        0x01, 0x7a, 0x52, 0x00, // version 1, augmentation "zR"
        0x01, 0x78, 0x1e, 0x01, // code/data alignment, return register, aug len
        0x10, 0x0c, 0x1f, 0x00, // pcrel pointer encoding, CFA=WSP
    ];
    let mut fde_field_offsets = Vec::with_capacity(unwind_functions.len());
    for ((_, code_len), (_, target_addend)) in unwind_functions.iter().zip(fde_referents) {
        let fde_offset = eh_frame.len() as u32;
        eh_frame.extend_from_slice(&0x18u32.to_le_bytes());
        eh_frame.extend_from_slice(&(fde_offset + 4).to_le_bytes());
        let field_offset = fde_offset + 8;
        eh_frame.extend_from_slice(&(target_addend - i64::from(field_offset)).to_le_bytes());
        eh_frame.extend_from_slice(&u64::from(*code_len).to_le_bytes());
        eh_frame.extend_from_slice(&[0x00, 0x0f, 0x01, 0x9c]);
        fde_field_offsets.push(field_offset);
    }

    let compact_relocs = write_relocs(
        &unwind_functions
            .iter()
            .enumerate()
            .map(|(record_index, (symbol_index, _))| {
                assert!(*symbol_index < text_symbols.len());
                Reloc {
                    offset: (record_index * 32) as u32,
                    kind: RelocKind::Unsigned,
                    length: RelocLength::Quad,
                    pcrel: false,
                    referent: Referent::Symbol((*symbol_index + 1) as u32),
                    addend: 0,
                    subtrahend: None,
                }
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut compact_reloc_bytes = Vec::new();
    write_raw_relocs(&compact_relocs, &mut compact_reloc_bytes);

    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let eh_base_strx = add_string("L_eh_base");
    let text_symbol_strx: Vec<u32> = text_symbols
        .iter()
        .map(|(name, _, _)| add_string(name))
        .collect();
    let eh_frame_addr = (text.len() + compact_unwind.len()) as u64;
    let mut symbols = vec![RawNlist {
        strx: eh_base_strx,
        n_type: N_SECT,
        n_sect: 3,
        n_desc: 0,
        n_value: eh_frame_addr,
    }];
    symbols.extend(text_symbols.iter().zip(text_symbol_strx).map(
        |((_, value, external), strx)| RawNlist {
            strx,
            n_type: N_SECT | if *external { N_EXT } else { 0 },
            n_sect: 1,
            n_desc: 0,
            n_value: *value,
        },
    ));
    let eh_frame_relocs = write_relocs(
        &fde_referents
            .iter()
            .zip(fde_field_offsets)
            .map(|((symbol_index, _), field_offset)| Reloc {
                offset: field_offset,
                kind: RelocKind::Subtractor,
                length: RelocLength::Quad,
                pcrel: false,
                referent: Referent::Symbol((*symbol_index + 1) as u32),
                addend: 0,
                subtrahend: Some(Referent::Symbol(0)),
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut eh_frame_reloc_bytes = Vec::new();
    write_raw_relocs(&eh_frame_relocs, &mut eh_frame_reloc_bytes);

    let data_size = text.len() + compact_unwind.len() + eh_frame.len();
    let mut segment = Segment64 {
        segname: name16(""),
        vmaddr: 0,
        vmsize: data_size as u64,
        fileoff: 0,
        filesize: data_size as u64,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: vec![
            Section64Header {
                sectname: name16("__text"),
                segname: name16("__TEXT"),
                addr: 0,
                size: text.len() as u64,
                offset: 0,
                align: 2,
                reloff: 0,
                nreloc: 0,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__compact_unwind"),
                segname: name16("__LD"),
                addr: text.len() as u64,
                size: compact_unwind.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: compact_relocs.len() as u32,
                flags: S_REGULAR | S_ATTR_DEBUG,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
            Section64Header {
                sectname: name16("__eh_frame"),
                segname: name16("__TEXT"),
                addr: eh_frame_addr,
                size: eh_frame.len() as u64,
                offset: 0,
                align: 3,
                reloff: 0,
                nreloc: eh_frame_relocs.len() as u32,
                flags: S_COALESCED | S_ATTR_LIVE_SUPPORT | S_ATTR_NO_TOC | S_ATTR_STRIP_STATIC_SYMS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            },
        ],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[1].offset = data_offset + text.len() as u32;
    segment.sections[2].offset = data_offset + eh_frame_addr as u32;
    segment.sections[1].reloff = data_offset + data_size as u32;
    segment.sections[2].reloff = segment.sections[1].reloff + compact_reloc_bytes.len() as u32;
    let symoff = segment.sections[2].reloff + eh_frame_reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&compact_unwind);
    bytes.extend_from_slice(&eh_frame);
    bytes.extend_from_slice(&compact_reloc_bytes);
    bytes.extend_from_slice(&eh_frame_reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_same_address_entry_alias_object() -> Vec<u8> {
    let text = [
        SAME_ADDRESS_ENTRY_CODE.as_slice(),
        &[
            0xe0, 0x00, 0x80, 0x52, // _unused: mov w0, #7
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ],
    ]
    .concat();
    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let symbols = [
        RawNlist {
            strx: add_string("_main"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: add_string("_zalias"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: add_string("_unused"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: SAME_ADDRESS_ENTRY_CODE.len() as u64,
        },
    ];
    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: 2,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = u64::from(data_offset);
    segment.sections[0].offset = data_offset;
    let symoff = data_offset + text.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_alias_object(alias: &str, target: &str, private_alias: bool) -> Vec<u8> {
    let mut strings = vec![0];
    let alias_strx = strings.len() as u32;
    strings.extend_from_slice(alias.as_bytes());
    strings.push(0);
    let target_strx = strings.len() as u32;
    strings.extend_from_slice(target.as_bytes());
    strings.push(0);
    let symbol = RawNlist {
        strx: alias_strx,
        n_type: N_INDR | N_EXT | if private_alias { N_PEXT } else { 0 },
        n_sect: 0,
        n_desc: 0,
        n_value: target_strx as u64,
    };
    synthetic_atomless_object(strings, &[symbol])
}

fn synthetic_absolute_object(name: &str, value: u64) -> Vec<u8> {
    synthetic_absolute_object_with_desc(name, value, 0)
}

fn synthetic_absolute_object_with_desc(name: &str, value: u64, n_desc: u16) -> Vec<u8> {
    let mut strings = vec![0];
    let strx = strings.len() as u32;
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    let symbol = RawNlist {
        strx,
        n_type: N_ABS | N_EXT,
        n_sect: 0,
        n_desc,
        n_value: value,
    };
    synthetic_atomless_object(strings, &[symbol])
}

fn synthetic_atomless_object(strings: Vec<u8>, symbols: &[RawNlist]) -> Vec<u8> {
    let segment = Segment64 {
        segname: [0; 16],
        vmaddr: 0,
        vmsize: 0,
        fileoff: 0,
        filesize: 0,
        maxprot: 7,
        initprot: 7,
        flags: 0,
        sections: Vec::new(),
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let symoff = HEADER_SIZE as u32 + sizeofcmds;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_aligned_subsections_object() -> Vec<u8> {
    const RET: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    const ASSEMBLER_RESOLVED_DELTA: u64 = 4;

    let mut text = Vec::with_capacity(16);
    text.extend_from_slice(&RET);
    text.extend_from_slice(&RET);
    text.extend_from_slice(&ASSEMBLER_RESOLVED_DELTA.to_le_bytes());

    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let symbols = [
        RawNlist {
            strx: add_string("_a"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: add_string("_b"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: RET.len() as u64,
        },
    ];

    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: 4,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = u64::from(data_offset);
    segment.sections[0].offset = data_offset;
    let symoff = data_offset + text.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_data_in_code_object(
    symbol_name: &str,
    section_name: &str,
    section_addr: u32,
    kind: u16,
    private_extern: bool,
) -> Vec<u8> {
    const RET: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    const TABLE: [u8; 4] = [0, 0, 0, 0];

    let text = [RET.as_slice(), TABLE.as_slice(), RET.as_slice()].concat();
    let mut strings = vec![0];
    strings.extend_from_slice(symbol_name.as_bytes());
    strings.push(0);
    let symbol = RawNlist {
        strx: 1,
        n_type: N_SECT | N_EXT | if private_extern { N_PEXT } else { 0 },
        n_sect: 1,
        n_desc: 0,
        n_value: u64::from(section_addr),
    };
    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: u64::from(section_addr),
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16(section_name),
            segname: name16("__TEXT"),
            addr: u64::from(section_addr),
            size: text.len() as u64,
            offset: 0,
            align: 2,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + LinkEditDataCmd::WIRE_SIZE + SymtabCmd::WIRE_SIZE;
    let text_offset = HEADER_SIZE as u32 + sizeofcmds;
    let data_in_code_offset = text_offset + text.len() as u32;
    let symoff = data_in_code_offset + 8;
    let stroff = symoff + NLIST_SIZE as u32;
    segment.fileoff = u64::from(text_offset);
    segment.sections[0].offset = text_offset;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 3,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    LinkEditDataCmd {
        dataoff: data_in_code_offset,
        datasize: 8,
    }
    .write(LC_DATA_IN_CODE, &mut bytes);
    SymtabCmd {
        symoff,
        nsyms: 1,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&(section_addr + RET.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(TABLE.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    symbol.write(&mut bytes);
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_branch_addend_object() -> Vec<u8> {
    const BL: [u8; 4] = 0x9400_0000u32.to_le_bytes();
    const RET: [u8; 4] = 0xd65f_03c0u32.to_le_bytes();

    let mut text = Vec::with_capacity(28);
    text.extend_from_slice(&BL);
    text.extend_from_slice(&BL);
    text.extend_from_slice(&BL);
    text.extend_from_slice(&RET);
    text.extend_from_slice(&RET);
    let target_offset = text.len() as u64;
    text.extend_from_slice(&RET);
    text.extend_from_slice(&RET);

    let relocs = [
        Reloc {
            offset: 0,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(1),
            addend: 4,
            subtrahend: None,
        },
        Reloc {
            offset: 4,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(1),
            addend: -4,
            subtrahend: None,
        },
        Reloc {
            offset: 8,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(1),
            addend: 4,
            subtrahend: None,
        },
    ];
    let raw_relocs = write_relocs(&relocs).unwrap();
    let mut reloc_bytes = Vec::new();
    write_raw_relocs(&raw_relocs, &mut reloc_bytes);

    let mut strings = vec![0];
    let mut add_string = |name: &str| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strx
    };
    let symbols = [
        RawNlist {
            strx: add_string("_main"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        },
        RawNlist {
            strx: add_string("_target"),
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: target_offset,
        },
    ];

    let mut segment = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: 0,
        vmsize: text.len() as u64,
        fileoff: 0,
        filesize: text.len() as u64,
        maxprot: 5,
        initprot: 5,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: text.len() as u64,
            offset: 0,
            align: 2,
            reloff: 0,
            nreloc: raw_relocs.len() as u32,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = u64::from(data_offset);
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + text.len() as u32;
    let symoff = segment.sections[0].reloff + reloc_bytes.len() as u32;
    let stroff = symoff + (symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    segment.write(&mut bytes);
    SymtabCmd {
        symoff,
        nsyms: symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&reloc_bytes);
    for symbol in symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
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

fn eh_frame_fde_offsets(bytes: &[u8]) -> Vec<u32> {
    let mut offsets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let length_bytes: [u8; 4] = bytes
            .get(offset..offset + 4)
            .expect("truncated DWARF record length")
            .try_into()
            .unwrap();
        let length = u32::from_le_bytes(length_bytes);
        assert_ne!(length, u32::MAX, "DWARF64 records are outside this fixture");
        if length == 0 {
            break;
        }
        let end = offset + 4 + length as usize;
        assert!(end <= bytes.len(), "DWARF record overruns __eh_frame");
        let cie_pointer = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        if cie_pointer != 0 {
            offsets.push(offset as u32);
        }
        offset = end;
    }
    offsets
}

fn output_sections(bytes: &[u8], segname: &str, sectname: &str) -> Vec<(u64, Vec<u8>)> {
    let Ok(header) = parse_header(bytes) else {
        return Vec::new();
    };
    let Ok(commands) = parse_commands(&header, bytes) else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    let data = if section.offset == 0 {
                        Vec::new()
                    } else {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
                        let Some(bytes) = bytes.get(start..end) else {
                            continue;
                        };
                        bytes.to_vec()
                    };
                    matches.push((section.addr, data));
                }
            }
        }
    }
    matches
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

fn segment_protections(bytes: &[u8], segname: &str) -> Option<(u32, u32)> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    commands.into_iter().find_map(|cmd| match cmd {
        LoadCommand::Segment64(seg) if seg.segname_str() == segname => {
            Some((seg.maxprot, seg.initprot))
        }
        _ => None,
    })
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

fn symbol_values(bytes: &[u8]) -> HashMap<String, u64> {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    let symtab = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Symtab(cmd) => Some(*cmd),
            _ => None,
        })
        .unwrap();
    let symbols = parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(bytes, symtab.stroff, symtab.strsize).unwrap();
    let mut out = HashMap::new();
    for symbol in symbols {
        let Ok(name) = strings.get(symbol.strx()) else {
            continue;
        };
        out.insert(name.to_string(), symbol.value());
    }
    out
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

fn canonical_symbol_record_map(bytes: &[u8]) -> HashMap<String, CanonicalSymbolRecord> {
    canonical_symbol_records(bytes)
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect()
}

fn assert_same_address_entry_alias_output(bytes: &[u8]) {
    let records = canonical_symbol_record_map(bytes);
    let main = records.get("_main").unwrap();
    let alias = records.get("_zalias").unwrap();
    assert_eq!(main.n_sect, alias.n_sect);
    assert_eq!(main.value, 0);
    assert_eq!(alias.value, 0);
    assert_eq!(main.n_desc & N_ALT_ENTRY, N_ALT_ENTRY);
    assert_eq!(alias.n_desc & N_ALT_ENTRY, 0);
    assert!(!records.contains_key("_unused"));

    let text = output_section_header(bytes, "__TEXT", "__text").unwrap();
    assert_eq!(
        output_section(bytes, "__TEXT", "__text").unwrap().1,
        SAME_ADDRESS_ENTRY_CODE
    );
    let header = parse_header(bytes).unwrap();
    let entryoff = parse_commands(&header, bytes)
        .unwrap()
        .into_iter()
        .find_map(|command| match command {
            LoadCommand::Raw { cmd, data, .. } if cmd == afs_ld::macho::constants::LC_MAIN => {
                Some(u64::from_le_bytes(data[0..8].try_into().unwrap()))
            }
            _ => None,
        })
        .expect("LC_MAIN");
    assert_eq!(entryoff, u64::from(text.offset));
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
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect()
}

fn indirect_symbol_identities(bytes: &[u8]) -> Vec<String> {
    let (symtab, _) = symtab_and_dysymtab(bytes);
    let symbols = parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(bytes, symtab.stroff, symtab.strsize).unwrap();
    indirect_symbol_table(bytes)
        .into_iter()
        .map(|index| {
            if index & INDIRECT_SYMBOL_LOCAL != 0 {
                if index & INDIRECT_SYMBOL_ABS != 0 {
                    "<LOCAL|ABS>".to_string()
                } else {
                    "<LOCAL>".to_string()
                }
            } else if index & INDIRECT_SYMBOL_ABS != 0 {
                "<ABS>".to_string()
            } else {
                let symbol = &symbols[index as usize];
                strings.get(symbol.strx()).unwrap().to_string()
            }
        })
        .collect()
}

fn raw_linkedit_data_cmd(bytes: &[u8], expected_cmd: u32) -> (u32, u32) {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    for cmd in commands {
        match cmd {
            LoadCommand::Raw { cmd, data, .. } if cmd == expected_cmd => {
                return (u32_le(&data[0..4]), u32_le(&data[4..8]));
            }
            LoadCommand::LinkerOptimizationHint(linkedit)
                if expected_cmd == LC_LINKER_OPTIMIZATION_HINT =>
            {
                return (linkedit.dataoff, linkedit.datasize);
            }
            _ => {}
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

fn command_ids(bytes: &[u8]) -> Vec<u32> {
    let header = parse_header(bytes).unwrap();
    let commands = parse_commands(&header, bytes).unwrap();
    commands
        .into_iter()
        .map(|cmd| match cmd {
            LoadCommand::Segment64(_) => LC_SEGMENT_64,
            LoadCommand::Symtab(_) => LC_SYMTAB,
            LoadCommand::Dysymtab(_) => LC_DYSYMTAB,
            LoadCommand::BuildVersion(_) => LC_BUILD_VERSION,
            LoadCommand::Dylib(d) => d.cmd,
            LoadCommand::DyldInfoOnly(_) => LC_DYLD_INFO_ONLY,
            LoadCommand::Raw { cmd, .. } => cmd,
            other => panic!("unexpected load command in command_ids helper: {other:?}"),
        })
        .collect()
}

fn normalize_function_start_offsets(starts: &[u64]) -> Vec<u64> {
    let Some(&base) = starts.first() else {
        return Vec::new();
    };
    starts.iter().map(|offset| offset - base).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataInCodeRecord {
    offset: u32,
    length: u16,
    kind: u16,
}

fn rebased_unwind_bytes(bytes: &[u8]) -> Vec<u8> {
    let header_base = segment_vmaddr(bytes, "__TEXT").unwrap_or(0);
    let text_base = output_section(bytes, "__TEXT", "__text").unwrap().0 - header_base;
    let got_range = output_section(bytes, "__DATA_CONST", "__got")
        .map(|(addr, data)| (addr - header_base, addr - header_base + data.len() as u64));
    let lsda_base =
        output_section(bytes, "__TEXT", "__gcc_except_tab").map(|(addr, _)| addr - header_base);
    let (_, unwind) = output_section(bytes, "__TEXT", "__unwind_info").unwrap();
    let mut out = unwind;
    if out.len() < 28 {
        return out;
    }

    let personalities_offset = u32_le(&out[12..16]) as usize;
    let personalities_count = u32_le(&out[16..20]) as usize;
    let indices_offset = u32_le(&out[20..24]) as usize;
    let indices_count = u32_le(&out[24..28]) as usize;

    for idx in 0..personalities_count {
        let off = personalities_offset + idx * 4;
        let value = u32_le(&out[off..off + 4]) as u64;
        let rebased = if let Some((got_start, got_end)) = got_range {
            if got_start <= value && value < got_end {
                value - got_start
            } else if value >= text_base {
                value - text_base
            } else {
                value
            }
        } else if value >= text_base {
            value - text_base
        } else {
            value
        };
        out[off..off + 4].copy_from_slice(&(rebased as u32).to_le_bytes());
    }

    let mut lsda_offsets = Vec::with_capacity(indices_count);
    for idx in 0..indices_count {
        let entry_off = indices_offset + idx * 12;
        let function_offset = u32_le(&out[entry_off..entry_off + 4]) as u64;
        let rebased = function_offset.saturating_sub(text_base);
        out[entry_off..entry_off + 4].copy_from_slice(&(rebased as u32).to_le_bytes());
        lsda_offsets.push(u32_le(&out[entry_off + 8..entry_off + 12]) as usize);
    }

    if let (Some(lsda_base), Some(&start), Some(&end)) =
        (lsda_base, lsda_offsets.first(), lsda_offsets.last())
    {
        let mut entry_off = start;
        while entry_off < end {
            let function_offset = u32_le(&out[entry_off..entry_off + 4]) as u64;
            let lsda_offset = u32_le(&out[entry_off + 4..entry_off + 8]) as u64;
            out[entry_off..entry_off + 4]
                .copy_from_slice(&(function_offset.saturating_sub(text_base) as u32).to_le_bytes());
            out[entry_off + 4..entry_off + 8]
                .copy_from_slice(&(lsda_offset.saturating_sub(lsda_base) as u32).to_le_bytes());
            entry_off += 8;
        }
    }

    out
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
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| DataInCodeRecord {
            offset: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
            length: u16::from_le_bytes(chunk[4..6].try_into().unwrap()),
            kind: u16::from_le_bytes(chunk[6..8].try_into().unwrap()),
        })
        .collect()
}

fn has_loh_command(bytes: &[u8]) -> bool {
    let header = parse_header(bytes).unwrap();
    parse_commands(&header, bytes)
        .unwrap()
        .into_iter()
        .any(|cmd| match cmd {
            LoadCommand::LinkerOptimizationHint(_) => true,
            LoadCommand::Raw { cmd, .. } => cmd == LC_LINKER_OPTIMIZATION_HINT,
            _ => false,
        })
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BindRecord {
    segment: String,
    section: String,
    section_offset: u64,
    ordinal: u16,
    symbol: String,
    weak_import: bool,
    addend: i64,
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
    WeakBind,
    LazyBind,
    Export,
}

fn dyld_info_stream(bytes: &[u8], kind: DyldInfoStreamKind) -> Result<Vec<u8>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    let (off, size) = match kind {
        DyldInfoStreamKind::Rebase => (dyld_info.rebase_off, dyld_info.rebase_size),
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

/// Apple linker releases disagree about where the private dyld scratch word
/// lives inside `__DATA,__data`. It is linker-owned bookkeeping, not an input
/// atom, so its rebase offset is not a stable user-visible parity surface.
/// Remove exactly that record while leaving every input/runtime rebase intact.
fn decode_input_rebase_records(bytes: &[u8]) -> Result<Vec<RebaseRecord>, String> {
    let mut records = decode_rebase_records(bytes)?;
    let Some(private_addr) = symbol_values(bytes).get("__dyld_private").copied() else {
        return Ok(records);
    };
    let Some((data_addr, data)) = output_section(bytes, "__DATA", "__data") else {
        return Ok(records);
    };
    if private_addr < data_addr || private_addr >= data_addr + data.len() as u64 {
        return Ok(records);
    }
    let private_offset = private_addr - data_addr;
    records.retain(|record| {
        !(record.segment == "__DATA"
            && record.section == "__data"
            && record.section_offset == private_offset)
    });
    Ok(records)
}

/// The same private scratch placement can shift every input pointer in
/// `__DATA,__data` by one word. Compare direct binds relative to the first
/// input bind in that section; all other sections keep absolute offsets.
fn normalize_direct_data_bind_offsets(records: &mut [BindRecord]) {
    let base = records
        .iter()
        .filter(|record| record.segment == "__DATA" && record.section == "__data")
        .map(|record| record.section_offset)
        .min();
    let Some(base) = base else {
        return;
    };
    for record in records {
        if record.segment == "__DATA" && record.section == "__data" {
            record.section_offset -= base;
        }
    }
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
    let mut addend = 0i64;
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
                    addend = 0;
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
            BIND_OPCODE_SET_ADDEND_SLEB => {
                let (value, len) =
                    read_sleb(&stream[cursor..]).map_err(|e| format!("bind SLEB: {e}"))?;
                cursor += len;
                addend = value;
            }
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
                    addend,
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
                    addend,
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
                    addend,
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
                        addend,
                    });
                    segment_offset += 8 + skip;
                }
            }
            _ => return Err(format!("unsupported bind opcode 0x{byte:02x}")),
        }
    }
    Ok(out)
}

fn canonical_bind_records(bytes: &[u8], lazy: bool) -> Result<Vec<BindRecord>, String> {
    let mut records = decode_bind_records(bytes, lazy)?;
    records.sort();
    Ok(records)
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
    let our_exports = canonical_export_records(&our_bytes)
        .map_err(|error| format!("{}: invalid afs-ld exports: {error}", case.name))?;
    let apple_exports = canonical_export_records(&apple_bytes)
        .map_err(|error| format!("{}: invalid Apple ld exports: {error}", case.name))?;
    if our_exports != apple_exports {
        return Err(format!(
            "{}: canonical export records diverged:\nours={:#?}\napple={:#?}",
            case.name, our_exports, apple_exports
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

    compare_sections(
        &our_bytes,
        &apple_bytes,
        &[
            ("__TEXT".to_string(), "__stubs".to_string()),
            ("__TEXT".to_string(), "__stub_helper".to_string()),
        ],
        &[],
    )
    .map_err(|err| format!("{}: {err}", case.name))?;

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
    let our_binds =
        canonical_bind_records(&our_bytes, false).map_err(|e| format!("our binds: {e}"))?;
    let apple_binds =
        canonical_bind_records(&apple_bytes, false).map_err(|e| format!("apple binds: {e}"))?;
    if our_binds != apple_binds {
        return Err(format!(
            "{}: bind records diverged from Apple ld:\nours={our_binds:#?}\napple={apple_binds:#?}",
            case.name,
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
    if decode_input_rebase_records(&our_bytes).map_err(|e| format!("our rebases: {e}"))?
        != decode_input_rebase_records(&apple_bytes).map_err(|e| format!("apple rebases: {e}"))?
    {
        return Err(format!(
            "{}: input rebase records diverged from Apple ld",
            case.name
        ));
    }
    let mut our_binds =
        canonical_bind_records(&our_bytes, false).map_err(|e| format!("our binds: {e}"))?;
    let mut apple_binds =
        canonical_bind_records(&apple_bytes, false).map_err(|e| format!("apple binds: {e}"))?;
    normalize_direct_data_bind_offsets(&mut our_binds);
    normalize_direct_data_bind_offsets(&mut apple_binds);
    if our_binds != apple_binds {
        return Err(format!(
            "{}: bind records diverged from Apple ld:\nours={our_binds:#?}\napple={apple_binds:#?}",
            case.name,
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

    for (label, output) in [("afs-ld", &our_out), ("Apple ld", &apple_out)] {
        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .map_err(|e| format!("spawn codesign for {label}: {e}"))?;
        if !verify.status.success() {
            return Err(format!(
                "{}: {label} codesign verification failed: {}",
                case.name,
                String::from_utf8_lossy(&verify.stderr)
            ));
        }
        let status = Command::new(output)
            .status()
            .map_err(|e| format!("run {label} output for {}: {e}", case.name))?;
        if status.code() != Some(0) {
            return Err(format!(
                "{}: {label} output exited with {:?}",
                case.name,
                status.code()
            ));
        }
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

fn is_adrp(insn: u32) -> bool {
    (insn & 0x9f00_0000) == 0x9000_0000
}

fn is_add_imm_64(insn: u32) -> bool {
    (insn & 0xffc0_0000) == 0x9100_0000
}

fn is_ldr_literal(insn: u32) -> bool {
    matches!(
        insn & 0xff00_0000,
        0x1800_0000 | 0x5800_0000 | 0x1c00_0000 | 0x5c00_0000 | 0x9c00_0000
    )
}

fn sign_extend_26(value: i64) -> i64 {
    if value & (1 << 25) != 0 {
        value | !0x03ff_ffff
    } else {
        value
    }
}

#[test]
fn linker_run_preserves_arm64e_cpu_subtype_and_capabilities_deterministically() {
    const ARM64E_PTRAUTH_ABI_V0: u32 = 0x8000_0002;
    const ABSOLUTE_VALUE: u64 = 0x1234_5678_9abc_def0;

    let reference = scratch("arm64e-subtype-reference.o");
    let definition = scratch("arm64e-subtype-definition.o");
    let out = scratch("arm64e-subtype.out");
    fs::write(
        &reference,
        with_cpu_subtype(
            synthetic_got_reference_object("_main", "_absolute", false),
            ARM64E_PTRAUTH_ABI_V0,
        ),
    )
    .unwrap();
    fs::write(
        &definition,
        with_cpu_subtype(
            synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
            ARM64E_PTRAUTH_ABI_V0,
        ),
    )
    .unwrap();

    let _ = fs::remove_file(&out);
    let mut outputs = Vec::new();
    for _ in 0..2 {
        Linker::run(&LinkOptions {
            inputs: vec![reference.clone(), definition.clone()],
            output: Some(out.clone()),
            arch: Some("arm64".into()),
            ..LinkOptions::default()
        })
        .unwrap();
        outputs.push(fs::read(&out).unwrap());
    }

    assert_eq!(
        parse_header(&outputs[0]).unwrap().cpusubtype,
        ARM64E_PTRAUTH_ABI_V0
    );
    assert_eq!(
        outputs[0], outputs[1],
        "repeated ARM64e links must be byte-identical"
    );

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_preserves_other_defined_arm64_subtypes() {
    for cpu_subtype in [
        CPU_SUBTYPE_ARM64_V8,
        CPU_SUBTYPE_LIB64,
        CPU_SUBTYPE_ARM64_V8 | CPU_SUBTYPE_LIB64,
    ] {
        let reference = scratch(&format!("arm64-subtype-{cpu_subtype:08x}-reference.o"));
        let definition = scratch(&format!("arm64-subtype-{cpu_subtype:08x}-definition.o"));
        let out = scratch(&format!("arm64-subtype-{cpu_subtype:08x}.out"));
        fs::write(
            &reference,
            with_cpu_subtype(
                synthetic_got_reference_object("_main", "_absolute", false),
                cpu_subtype,
            ),
        )
        .unwrap();
        fs::write(
            &definition,
            with_cpu_subtype(synthetic_absolute_object("_absolute", 42), cpu_subtype),
        )
        .unwrap();

        let _ = fs::remove_file(&out);
        Linker::run(&LinkOptions {
            inputs: vec![reference.clone(), definition.clone()],
            output: Some(out.clone()),
            ..LinkOptions::default()
        })
        .unwrap();
        assert_eq!(
            parse_header(&fs::read(&out).unwrap()).unwrap().cpusubtype,
            cpu_subtype
        );

        let _ = fs::remove_file(reference);
        let _ = fs::remove_file(definition);
        let _ = fs::remove_file(out);
    }
}

#[test]
fn linker_run_rejects_conflicting_arm64e_capabilities_without_replacing_output() {
    const ARM64E_PTRAUTH_ABI_V0: u32 = 0x8000_0002;
    const ARM64E_PTRAUTH_ABI_V1: u32 = 0x8100_0002;
    const SENTINEL: &[u8] = b"pre-existing output\n";

    let reference = scratch("arm64e-conflict-reference.o");
    let definition = scratch("arm64e-conflict-definition.o");
    let out = scratch("arm64e-conflict.out");
    fs::write(
        &reference,
        with_cpu_subtype(
            synthetic_got_reference_object("_main", "_absolute", false),
            ARM64E_PTRAUTH_ABI_V0,
        ),
    )
    .unwrap();
    fs::write(
        &definition,
        with_cpu_subtype(
            synthetic_absolute_object("_absolute", 42),
            ARM64E_PTRAUTH_ABI_V1,
        ),
    )
    .unwrap();
    fs::write(&out, SENTINEL).unwrap();

    let error = Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        ..LinkOptions::default()
    })
    .unwrap_err();

    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains("incompatible ARM64 CPU subtypes"),
        "unexpected diagnostic: {diagnostic}"
    );
    assert!(diagnostic.contains(&reference.display().to_string()));
    assert!(diagnostic.contains(&definition.display().to_string()));
    assert_eq!(fs::read(&out).unwrap(), SENTINEL);

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_rejects_unknown_arm64_cpu_subtype_without_publishing_output() {
    let object = scratch("unknown-arm64-subtype.o");
    let out = scratch("unknown-arm64-subtype.out");
    let _ = fs::remove_file(&out);
    fs::write(
        &object,
        with_cpu_subtype(
            synthetic_got_reference_object("_main", "_unused", false),
            0x0000_0003,
        ),
    )
    .unwrap();

    let error = Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(out.clone()),
        ..LinkOptions::default()
    })
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unsupported ARM64 CPU subtype 0x00000003"),
        "unexpected diagnostic: {error}"
    );
    assert!(!out.exists());

    let _ = fs::remove_file(object);
}

#[test]
fn linker_run_preserves_arm64e_subtype_from_force_loaded_archive_members() {
    const ARM64E_PTRAUTH_ABI_V0: u32 = 0x8000_0002;

    let archive_path = scratch("arm64e-subtype.a");
    let out = scratch("arm64e-subtype-archive.out");
    let _ = fs::remove_file(&out);
    let reference = with_cpu_subtype(
        synthetic_got_reference_object("_main", "_absolute", false),
        ARM64E_PTRAUTH_ABI_V0,
    );
    let definition = with_cpu_subtype(
        synthetic_absolute_object("_absolute", 42),
        ARM64E_PTRAUTH_ABI_V0,
    );
    fs::write(
        &archive_path,
        synthetic_archive(&[("main.o", &reference), ("absolute.o", &definition)]),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![archive_path.clone()],
        output: Some(out.clone()),
        all_load: true,
        ..LinkOptions::default()
    })
    .unwrap();

    assert_eq!(
        parse_header(&fs::read(&out).unwrap()).unwrap().cpusubtype,
        ARM64E_PTRAUTH_ABI_V0
    );

    let _ = fs::remove_file(archive_path);
    let _ = fs::remove_file(out);
}

#[test]
fn clang_arm64e_object_subtype_round_trips_when_available() {
    let source = scratch("arm64e-subtype.s");
    let object = scratch("arm64e-clang.o");
    let out = scratch("arm64e-clang.out");
    fs::write(
        &source,
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                mov w0, #42
                ret
            .subsections_via_symbols
        "#,
    )
    .unwrap();

    let (mut compiler, compiler_name) = if have_xcrun_tool("clang") {
        let mut compiler = Command::new("xcrun");
        compiler.args([
            "--sdk",
            "macosx",
            "clang",
            "-arch",
            "arm64e",
            "-x",
            "assembler",
            "-c",
        ]);
        (compiler, "xcrun clang")
    } else if have_tool("clang") {
        let targets = Command::new("clang")
            .arg("--print-targets")
            .output()
            .unwrap();
        if !targets.status.success()
            || !String::from_utf8_lossy(&targets.stdout).contains("aarch64")
        {
            harness_skip!("installed clang has no AArch64 backend");
            let _ = fs::remove_file(source);
            return;
        }
        let mut compiler = Command::new("clang");
        compiler.args(["--target=arm64e-apple-macos11", "-x", "assembler", "-c"]);
        (compiler, "clang ARM64e cross-target")
    } else {
        harness_skip!("clang unavailable");
        let _ = fs::remove_file(source);
        return;
    };
    let compile = compiler
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{compiler_name} fixture compilation failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let input_subtype = parse_header(&fs::read(&object).unwrap())
        .unwrap()
        .cpusubtype;
    assert_eq!(input_subtype & 0x00ff_ffff, CPU_SUBTYPE_ARM64E);
    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(out.clone()),
        arch: Some("arm64".into()),
        ..LinkOptions::default()
    })
    .unwrap();
    assert_eq!(
        parse_header(&fs::read(&out).unwrap()).unwrap().cpusubtype,
        input_subtype
    );

    let _ = fs::remove_file(source);
    let _ = fs::remove_file(object);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_non_empty_executable_from_real_object() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun as or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("main.o");
    let out = scratch("a.out");
    let apple_out = scratch("a-apple.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov x0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let bytes = fs::read(&out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut text_size = 0u64;
    let mut has_dylinker = false;
    let mut has_uuid = false;
    let mut has_source_version = false;
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
            LoadCommand::Raw { cmd, data, .. } if cmd == afs_ld::macho::constants::LC_UUID => {
                has_uuid = data.len() == 16 && data.iter().any(|byte| *byte != 0);
            }
            LoadCommand::Raw { cmd, .. } if cmd == afs_ld::macho::constants::LC_SOURCE_VERSION => {
                has_source_version = true;
            }
            _ => {}
        }
    }
    assert!(text_size > 0, "expected non-empty __text output");
    assert!(
        has_dylinker,
        "expected LC_LOAD_DYLINKER in executable output"
    );
    assert!(has_uuid, "expected LC_UUID in executable output");
    assert!(
        has_source_version,
        "expected LC_SOURCE_VERSION in executable output"
    );
    let our_cmds: Vec<u32> = command_ids(&bytes)
        .into_iter()
        .filter(|cmd| *cmd != afs_ld::macho::constants::LC_LOAD_DYLIB)
        .collect();
    let apple_cmds: Vec<u32> = command_ids(&apple_bytes)
        .into_iter()
        .filter(|cmd| *cmd != afs_ld::macho::constants::LC_LOAD_DYLIB)
        .collect();
    assert_eq!(our_cmds, apple_cmds);
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
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_loh_executable_surfaces_match_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };

    let cases = [
        (
            "loh-apple-adrp-add-exec",
            r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                .globl _target
                _main:
                Lloh0:
                    adrp x0, _target@PAGE
                Lloh1:
                    add x0, x0, _target@PAGEOFF
                    mov w0, #0
                    ret
                _target:
                    ret
                .loh AdrpAdd Lloh0, Lloh1
                .subsections_via_symbols
            "#,
        ),
        (
            "loh-apple-adrp-ldr-exec",
            r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                .globl _target
                _main:
                Lloh0:
                    adrp x0, _target@PAGE
                Lloh1:
                    ldr x1, [x0, _target@PAGEOFF]
                    mov w0, #0
                    ret
                    .p2align 3
                _target:
                    .quad 0x1122334455667788
                .loh AdrpLdr Lloh0, Lloh1
                .subsections_via_symbols
            "#,
        ),
        (
            "loh-apple-adrp-ldr-got-ldr-exec",
            r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                .globl _value
                _main:
                Lloh0:
                    adrp x8, _value@GOTPAGE
                Lloh1:
                    ldr x8, [x8, _value@GOTPAGEOFF]
                Lloh2:
                    ldr w0, [x8]
                    ret

                .section __DATA,__data
                .p2align 2
                _value:
                    .long 7
                .loh AdrpLdrGotLdr Lloh0, Lloh1, Lloh2
                .subsections_via_symbols
            "#,
        ),
    ];

    for (name, src) in cases {
        let obj = scratch(&format!("{name}.o"));
        let our_out = scratch(&format!("{name}-ours.out"));
        let apple_out = scratch(&format!("{name}-apple.out"));
        require_fixture!("assembly fixture", assemble(src, &obj));

        let opts = LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(our_out.clone()),
            kind: OutputKind::Executable,
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();
        apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

        let our_bytes = fs::read(&our_out).unwrap();
        let apple_bytes = fs::read(&apple_out).unwrap();
        let (our_text_addr, our_text) = output_section(&our_bytes, "__TEXT", "__text").unwrap();
        let (apple_text_addr, apple_text) =
            output_section(&apple_bytes, "__TEXT", "__text").unwrap();
        assert_eq!(
            our_text.len(),
            apple_text.len(),
            "{name} text length drifted from Apple ld"
        );
        assert!(
            !has_loh_command(&our_bytes),
            "{name} should omit LC_LINKER_OPTIMIZATION_HINT"
        );
        assert!(
            !has_loh_command(&apple_bytes),
            "{name} Apple peer unexpectedly emitted LC_LINKER_OPTIMIZATION_HINT"
        );
        match name {
            "loh-apple-adrp-add-exec" => {
                let our_target = symbol_values(&our_bytes)["_target"];
                let apple_target = symbol_values(&apple_bytes)["_target"];
                let our_first = read_insn(&our_text, 0).unwrap();
                let our_second = read_insn(&our_text, 4).unwrap();
                let apple_first = read_insn(&apple_text, 0).unwrap();
                let apple_second = read_insn(&apple_text, 4).unwrap();
                assert!(is_adrp(our_first), "{name} should keep ADRP");
                assert!(is_add_imm_64(our_second), "{name} should keep ADD");
                assert!(is_adrp(apple_first), "{name} Apple peer should keep ADRP");
                assert!(
                    is_add_imm_64(apple_second),
                    "{name} Apple peer should keep ADD"
                );
                assert_eq!(
                    decode_page_reference(&our_text, our_text_addr, 0, &PageRefKind::Add).unwrap(),
                    our_target
                );
                assert_eq!(
                    decode_page_reference(&apple_text, apple_text_addr, 0, &PageRefKind::Add)
                        .unwrap(),
                    apple_target
                );
            }
            "loh-apple-adrp-ldr-exec" => {
                let our_target = symbol_values(&our_bytes)["_target"];
                let apple_target = symbol_values(&apple_bytes)["_target"];
                let our_first = read_insn(&our_text, 0).unwrap();
                let our_second = read_insn(&our_text, 4).unwrap();
                let apple_first = read_insn(&apple_text, 0).unwrap();
                let apple_second = read_insn(&apple_text, 4).unwrap();
                assert!(is_adrp(our_first), "{name} should keep ADRP");
                assert!(
                    !is_ldr_literal(our_second),
                    "{name} should keep pageoff LDR"
                );
                assert!(is_adrp(apple_first), "{name} Apple peer should keep ADRP");
                assert!(
                    !is_ldr_literal(apple_second),
                    "{name} Apple peer should keep pageoff LDR"
                );
                assert_eq!(
                    decode_page_reference(&our_text, our_text_addr, 0, &PageRefKind::Load).unwrap(),
                    our_target
                );
                assert_eq!(
                    decode_page_reference(&apple_text, apple_text_addr, 0, &PageRefKind::Load)
                        .unwrap(),
                    apple_target
                );
            }
            "loh-apple-adrp-ldr-got-ldr-exec" => {
                let our_target = symbol_values(&our_bytes)["_value"];
                let apple_target = symbol_values(&apple_bytes)["_value"];
                let our_first = read_insn(&our_text, 0).unwrap();
                let our_second = read_insn(&our_text, 4).unwrap();
                let our_third = read_insn(&our_text, 8).unwrap();
                let apple_first = read_insn(&apple_text, 0).unwrap();
                let apple_second = read_insn(&apple_text, 4).unwrap();
                let apple_third = read_insn(&apple_text, 8).unwrap();
                assert!(is_adrp(our_first), "{name} should keep ADRP");
                assert!(
                    is_add_imm_64(our_second),
                    "{name} should keep GOT-resolved ADD"
                );
                assert!(is_adrp(apple_first), "{name} Apple peer should keep ADRP");
                assert!(
                    is_add_imm_64(apple_second),
                    "{name} Apple peer should keep GOT-resolved ADD"
                );
                assert_eq!(our_third, apple_third, "{name} final load drifted");
                assert_eq!(
                    decode_page_reference(&our_text, our_text_addr, 0, &PageRefKind::Add).unwrap(),
                    our_target
                );
                assert_eq!(
                    decode_page_reference(&apple_text, apple_text_addr, 0, &PageRefKind::Add)
                        .unwrap(),
                    apple_target
                );
            }
            _ => unreachable!("unexpected LOH parity case"),
        }

        let _ = fs::remove_file(obj);
        let _ = fs::remove_file(our_out);
        let _ = fs::remove_file(apple_out);
    }
}

#[test]
fn linker_run_loh_dylib_surfaces_match_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("loh-apple-dylib.o");
    let our_out = scratch("loh-apple-ours.dylib");
    let apple_out = scratch("loh-apple-apple.dylib");
    let install_name = "@rpath/liblohprobe.dylib";
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _loh_probe
        .globl _target
        _loh_probe:
        Lloh0:
            adrp x0, _target@PAGE
        Lloh1:
            add x0, x0, _target@PAGEOFF
            ret
        _target:
            ret
        .loh AdrpAdd Lloh0, Lloh1
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Dylib,
        install_name: Some(install_name.into()),
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_dylib_classic(&obj, &apple_out, install_name, &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (our_text_addr, our_text) = output_section(&our_bytes, "__TEXT", "__text").unwrap();
    let (apple_text_addr, apple_text) = output_section(&apple_bytes, "__TEXT", "__text").unwrap();
    let our_target = symbol_values(&our_bytes)["_target"];
    let apple_target = symbol_values(&apple_bytes)["_target"];
    let our_first = read_insn(&our_text, 0).unwrap();
    let our_second = read_insn(&our_text, 4).unwrap();
    let apple_first = read_insn(&apple_text, 0).unwrap();
    let apple_second = read_insn(&apple_text, 4).unwrap();
    assert!(is_adrp(our_first), "dylib LOH should keep ADRP");
    assert!(is_add_imm_64(our_second), "dylib LOH should keep ADD");
    assert!(is_adrp(apple_first), "Apple dylib LOH should keep ADRP");
    assert!(
        is_add_imm_64(apple_second),
        "Apple dylib LOH should keep ADD"
    );
    assert_eq!(
        decode_page_reference(&our_text, our_text_addr, 0, &PageRefKind::Add).unwrap(),
        our_target
    );
    assert_eq!(
        decode_page_reference(&apple_text, apple_text_addr, 0, &PageRefKind::Add).unwrap(),
        apple_target
    );
    assert!(
        !has_loh_command(&our_bytes),
        "dylib output should omit LC_LINKER_OPTIMIZATION_HINT"
    );
    assert!(
        !has_loh_command(&apple_bytes),
        "Apple dylib peer unexpectedly emitted LC_LINKER_OPTIMIZATION_HINT"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_minimal_dylib_from_real_object() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
fn linker_run_marks_surviving_external_weak_definitions_in_the_image_header() {
    const WEAK_VALUE: u64 = 0x1234_5678;

    let obj = scratch("weak-definition.o");
    let out = scratch("weak-definition.dylib");
    fs::write(
        &obj,
        synthetic_absolute_object_with_desc("_weak_definition", WEAK_VALUE, N_WEAK_DEF),
    )
    .unwrap();

    let mut outputs = Vec::new();
    for jobs in [1, 4] {
        Linker::run(&LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Dylib,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        outputs.push(fs::read(&out).unwrap());
    }
    assert_eq!(outputs[0], outputs[1], "-j1 and -j4 output differs");

    let bytes = &outputs[0];
    let header = parse_header(bytes).unwrap();
    assert_eq!(
        header.flags & (MH_WEAK_DEFINES | MH_BINDS_TO_WEAK),
        MH_WEAK_DEFINES | MH_BINDS_TO_WEAK
    );
    let symbol = canonical_symbol_record_map(bytes)
        .remove("_weak_definition")
        .unwrap();
    assert_eq!(symbol.n_type, N_ABS | N_EXT);
    assert_ne!(symbol.n_desc & N_WEAK_DEF, 0);
    let export = canonical_export_records(bytes)
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == "_weak_definition")
        .unwrap();
    assert_ne!(export.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, 0);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_uses_dylib_identity_flags() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("libmeta.o");
    let out = scratch("libmeta.dylib");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _exported
        _exported:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        install_name: Some("@rpath/libmeta_custom.dylib".into()),
        current_version: Some((2 << 16) | (3 << 8) | 4),
        compatibility_version: Some((1 << 16) | (5 << 8)),
        rpaths: vec!["@loader_path/../lib".into()],
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let id_dylib = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Dylib(cmd) if cmd.cmd == afs_ld::macho::constants::LC_ID_DYLIB => {
                Some(cmd.clone())
            }
            _ => None,
        })
        .expect("missing LC_ID_DYLIB");
    assert_eq!(id_dylib.name, "@rpath/libmeta_custom.dylib");
    assert_eq!(id_dylib.current_version, (2 << 16) | (3 << 8) | 4);
    assert_eq!(id_dylib.compatibility_version, (1 << 16) | (5 << 8));
    assert!(commands
        .iter()
        .any(|cmd| matches!(cmd, LoadCommand::Rpath(r) if r.path == "@loader_path/../lib")));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_honors_exported_symbol_filters_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("export-filter.o");
    let our_out = scratch("export-filter-ours.dylib");
    let apple_out = scratch("export-filter-apple.dylib");
    let list_path = scratch("export-filter-exports.txt");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _alpha
        .globl _beta
        .globl _gamma
        _alpha:
            ret
        _beta:
            ret
        _gamma:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));
    fs::write(&list_path, "_bet?\n").unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Dylib,
        exported_symbols: vec!["_alpha".into()],
        exported_symbols_lists: vec![list_path.clone()],
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let apple = Command::new("xcrun")
        .args(["clang", "-arch", "arm64", "-dynamiclib"])
        .arg(&obj)
        .arg("-o")
        .arg(&apple_out)
        .arg("-Wl,-exported_symbol,_alpha")
        .arg(format!(
            "-Wl,-exported_symbols_list,{}",
            list_path.display()
        ))
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        canonical_export_records(&our_bytes).unwrap(),
        canonical_export_records(&apple_bytes).unwrap()
    );
    assert_eq!(
        dyld_info_export_names(&our_bytes).unwrap(),
        vec!["_alpha".to_string(), "_beta".to_string()]
    );
    assert_eq!(
        canonical_symbol_record_map(&our_bytes),
        canonical_symbol_record_map(&apple_bytes)
    );

    let our_symbols = canonical_symbol_record_map(&our_bytes);
    let gamma = our_symbols.get("_gamma").expect("missing _gamma");
    assert_ne!(
        gamma.n_type & N_PEXT,
        0,
        "expected _gamma to be private extern"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    let _ = fs::remove_file(list_path);
}

#[test]
fn linker_run_honors_unexported_symbol_filters_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("unexport-filter.o");
    let our_out = scratch("unexport-filter-ours.dylib");
    let apple_out = scratch("unexport-filter-apple.dylib");
    let list_path = scratch("unexport-filter-hidden.txt");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _alpha
        .globl _beta
        .globl _gamma
        _alpha:
            ret
        _beta:
            ret
        _gamma:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));
    fs::write(&list_path, "_bet?\n").unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Dylib,
        unexported_symbols: vec!["_gamma".into()],
        unexported_symbols_lists: vec![list_path.clone()],
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let apple = Command::new("xcrun")
        .args(["clang", "-arch", "arm64", "-dynamiclib"])
        .arg(&obj)
        .arg("-o")
        .arg(&apple_out)
        .arg("-Wl,-unexported_symbol,_gamma")
        .arg(format!(
            "-Wl,-unexported_symbols_list,{}",
            list_path.display()
        ))
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert_eq!(
        canonical_export_records(&our_bytes).unwrap(),
        canonical_export_records(&apple_bytes).unwrap()
    );
    assert_eq!(
        dyld_info_export_names(&our_bytes).unwrap(),
        vec!["_alpha".to_string()]
    );
    assert_eq!(
        canonical_symbol_record_map(&our_bytes),
        canonical_symbol_record_map(&apple_bytes)
    );

    let our_symbols = canonical_symbol_record_map(&our_bytes);
    for name in ["_beta", "_gamma"] {
        let record = our_symbols
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert_ne!(
            record.n_type & N_PEXT,
            0,
            "expected {name} to be private extern"
        );
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    let _ = fs::remove_file(list_path);
}

#[test]
fn linker_run_dead_strip_applies_dylib_export_policy_to_roots() {
    let obj = scratch("AFSLD-069-export-policy.o");
    let out = scratch("AFSLD-069-export-policy.dylib");
    let exported_list = scratch("AFSLD-069-exported.txt");
    let unexported_list = scratch("AFSLD-069-unexported.txt");
    let inline_keep = 0x1111_2222_3333_4444u64;
    let listed_keep = 0x5555_6666_7777_8888u64;
    let blocked = 0x9999_aaaa_bbbb_ccccu64;
    let mut data = inline_keep.to_le_bytes().to_vec();
    data.extend_from_slice(&listed_keep.to_le_bytes());
    data.extend_from_slice(&blocked.to_le_bytes());
    fs::write(
        &obj,
        synthetic_single_section_object(
            "__DATA",
            "__policy",
            S_REGULAR,
            &data,
            &[],
            &[
                ("_inline_keep", N_SECT | N_EXT, 1, 0, 0),
                ("_listed_keep", N_SECT | N_EXT, 1, 0, 8),
                ("_blocked", N_SECT | N_EXT, 1, 0, 16),
            ],
        ),
    )
    .unwrap();
    fs::write(&exported_list, "_listed_*\n").unwrap();
    fs::write(&unexported_list, "_blocked\n").unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        dead_strip: true,
        exported_symbols: vec!["_inline_keep".into(), "_blocked".into()],
        exported_symbols_lists: vec![exported_list.clone()],
        unexported_symbols_lists: vec![unexported_list.clone()],
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    assert_eq!(
        output_section(&bytes, "__DATA", "__policy")
            .expect("policy fixture section must survive")
            .1,
        [inline_keep.to_le_bytes(), listed_keep.to_le_bytes()].concat()
    );
    assert_eq!(
        dyld_info_export_names(&bytes).unwrap(),
        vec!["_inline_keep".to_string(), "_listed_keep".to_string()]
    );
    let symbols = canonical_symbol_record_map(&bytes);
    assert!(symbols.contains_key("_inline_keep"));
    assert!(symbols.contains_key("_listed_keep"));
    assert!(!symbols.contains_key("_blocked"));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(exported_list);
    let _ = fs::remove_file(unexported_list);
}

#[test]
fn linker_run_loads_minimal_dylib_via_dlopen() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun clang/as or codesign unavailable");
        return;
    }

    let obj = scratch("libfoo_add.o");
    let out = scratch("libfoo_add.dylib");
    let caller_src = scratch("libfoo_add-caller.c");
    let caller = scratch("libfoo_add-caller.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _foo_add
        _foo_add:
            add w0, w0, w1
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
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

    fs::write(
        &caller_src,
        r#"
            #include <dlfcn.h>
            typedef int (*foo_add_fn)(int, int);
            int main(int argc, char **argv) {
                if (argc != 2) return 10;
                void *handle = dlopen(argv[1], RTLD_NOW);
                if (!handle) return 11;
                foo_add_fn fn = (foo_add_fn)dlsym(handle, "foo_add");
                if (!fn) return 12;
                int value = fn(2, 3);
                dlclose(handle);
                return value == 5 ? 0 : 1;
            }
        "#,
    )
    .unwrap();

    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64"])
        .arg(&caller_src)
        .arg("-o")
        .arg(&caller)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "xcrun clang caller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = Command::new(&caller).arg(&out).status().unwrap();
    assert_eq!(status.code(), Some(0), "expected dlopen caller to exit 0");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(caller_src);
    let _ = fs::remove_file(caller);
}

#[test]
fn dylib_export_surfaces_match_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
        harness_skip!("xcrun as unavailable");
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
fn linker_run_promotes_unresolved_symbol_to_dynamic_lookup() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("missing-dynamic.o");
    let out = scratch("missing-dynamic.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .section __DATA,__data
        .p2align 3
        .globl _missing_slot
        _missing_slot:
            .quad _missing
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        undefined_treatment: afs_ld::resolve::UndefinedTreatment::DynamicLookup,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let bind_records = decode_bind_records(&bytes, false).unwrap();
    assert!(
        bind_records
            .iter()
            .any(|record| record.symbol == "_missing" && record.ordinal == 0xFFFE),
        "expected flat-lookup bind for _missing, got {bind_records:?}"
    );
    let (_, _, undefs) = symbol_partition_names(&bytes);
    assert_eq!(undefs, vec!["_missing".to_string()]);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

fn assert_got_import(bytes: &[u8], symbol: &str, ordinal: u16, weak_import: bool) {
    let bind_records = decode_bind_records(bytes, false).unwrap();
    assert!(
        bind_records.iter().any(|record| {
            record.symbol == symbol
                && record.ordinal == ordinal
                && record.weak_import == weak_import
                && record.segment == "__DATA_CONST"
                && record.section == "__got"
        }),
        "expected GOT bind for {symbol} at ordinal {ordinal} with weak_import={weak_import}, got {bind_records:?}"
    );
    let got = output_section_header(bytes, "__DATA_CONST", "__got").unwrap();
    let got_start = got.offset as usize;
    let got_bytes = &bytes[got_start..got_start + got.size as usize];
    assert_eq!(got_bytes, &[0; 8]);

    let symbols = canonical_symbol_record_map(bytes);
    let imported = symbols.get(symbol).unwrap();
    assert_eq!(imported.n_type, N_UNDF | N_EXT);
    assert_eq!(imported.n_sect, 0);
    assert_eq!(imported.value, 0);
    assert_eq!(imported.n_desc >> 8, ordinal & 0xff);
    assert_eq!(imported.n_desc & N_WEAK_REF != 0, weak_import);
}

#[test]
fn linker_run_reports_unresolved_weak_symbol_under_error_policy() {
    let obj = scratch("missing-weak.o");
    let out = scratch("missing-weak.out");
    fs::write(
        &obj,
        synthetic_got_reference_object("_main", "_optional", true),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::UndefinedSymbols(msg) => {
            assert!(msg.contains("undefined symbol: _optional"), "{msg}");
        }
        other => panic!("expected UndefinedSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_flat_weak_bind_for_permitted_unresolved_reference() {
    let obj = scratch("missing-weak-dynamic.o");
    let out = scratch("missing-weak-dynamic.out");
    fs::write(
        &obj,
        synthetic_got_reference_object("_main", "_optional", true),
    )
    .unwrap();

    let mut outputs = Vec::new();
    for jobs in [1, 4] {
        let opts = LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            undefined_treatment: afs_ld::resolve::UndefinedTreatment::DynamicLookup,
            jobs: Some(jobs),
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();
        outputs.push(fs::read(&out).unwrap());
    }
    assert_eq!(outputs[0], outputs[1], "-j1 and -j4 output differs");

    let bytes = &outputs[0];
    assert_got_import(bytes, "_optional", 0xFFFE, true);
    assert_ne!(
        parse_header(bytes).unwrap().flags & MH_BINDS_TO_WEAK,
        0,
        "weak import bindings must mark the image as binding to weak symbols"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_required_flat_bind_for_strong_unresolved_reference() {
    let obj = scratch("missing-strong-dynamic.o");
    let out = scratch("missing-strong-dynamic.out");
    let target = "_afs_ld_required_missing_symbol";
    fs::write(&obj, synthetic_got_reference_object("_main", target, false)).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        undefined_treatment: afs_ld::resolve::UndefinedTreatment::DynamicLookup,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    assert_eq!(parse_header(&bytes).unwrap().flags & MH_BINDS_TO_WEAK, 0);
    assert_got_import(&bytes, target, 0xFFFE, false);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_mixed_undefined_references_are_required_in_both_orders() {
    let target = "_afs_ld_mixed_missing_symbol";
    for weak_first in [false, true] {
        let order = if weak_first {
            "weak-first"
        } else {
            "strong-first"
        };
        let first = scratch(&format!("mixed-{order}-first.o"));
        let second = scratch(&format!("mixed-{order}-second.o"));
        let out = scratch(&format!("mixed-{order}.out"));
        fs::write(
            &first,
            synthetic_got_reference_object("_main", target, weak_first),
        )
        .unwrap();
        fs::write(
            &second,
            synthetic_got_reference_object("_helper", target, !weak_first),
        )
        .unwrap();

        let opts = LinkOptions {
            inputs: vec![first.clone(), second.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            undefined_treatment: afs_ld::resolve::UndefinedTreatment::DynamicLookup,
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();

        let bytes = fs::read(&out).unwrap();
        assert_got_import(&bytes, target, 0xFFFE, false);

        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
        let _ = fs::remove_file(out);
    }
}

#[test]
fn linker_run_preserves_consumer_weak_reference_after_dylib_resolution() {
    let weak_object = scratch("dylib-weak-consumer.o");
    let strong_object = scratch("dylib-strong-consumer.o");
    let tbd = scratch("dylib-consumer-weakness.tbd");
    let weak_output = scratch("dylib-weak-consumer.out");
    let strong_output = scratch("dylib-strong-consumer.out");
    let symbol = "_optional_from_strong_provider";

    fs::write(
        &weak_object,
        synthetic_got_reference_object("_main", symbol, true),
    )
    .unwrap();
    fs::write(
        &strong_object,
        synthetic_got_reference_object("_main", symbol, false),
    )
    .unwrap();
    fs::write(
        &tbd,
        format!(
            r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libconsumerweakness.dylib'
exports:
  - targets: [ arm64-macos ]
    symbols: [ {symbol} ]
...
"#
        ),
    )
    .unwrap();

    let mut weak_outputs = Vec::new();
    let mut strong_outputs = Vec::new();
    for jobs in [1, 4] {
        for (object, output, captures) in [
            (&weak_object, &weak_output, &mut weak_outputs),
            (&strong_object, &strong_output, &mut strong_outputs),
        ] {
            Linker::run(&LinkOptions {
                inputs: vec![object.clone(), tbd.clone()],
                output: Some(output.clone()),
                kind: OutputKind::Executable,
                jobs: Some(jobs),
                ..LinkOptions::default()
            })
            .unwrap();
            captures.push(fs::read(output).unwrap());
        }
    }

    assert_eq!(
        weak_outputs[0], weak_outputs[1],
        "weak -j1/-j4 output differs"
    );
    assert_eq!(
        strong_outputs[0], strong_outputs[1],
        "strong -j1/-j4 output differs"
    );
    assert_got_import(&weak_outputs[0], symbol, 1, true);
    assert_ne!(
        parse_header(&weak_outputs[0]).unwrap().flags & MH_BINDS_TO_WEAK,
        0,
        "consumer weak reference must mark the output as binding weakly"
    );
    assert_got_import(&strong_outputs[0], symbol, 1, false);
    assert_eq!(
        parse_header(&strong_outputs[0]).unwrap().flags & MH_BINDS_TO_WEAK,
        0,
        "strong consumer of a regular export must remain a strong import"
    );

    let _ = fs::remove_file(weak_object);
    let _ = fs::remove_file(strong_object);
    let _ = fs::remove_file(tbd);
    let _ = fs::remove_file(weak_output);
    let _ = fs::remove_file(strong_output);
}

#[test]
fn linker_run_weak_framework_marks_all_imports_weak() {
    let syslibroot = scratch("weak-framework-import-root");
    let framework_dir = syslibroot.join("System/Library/Frameworks/Demo.framework");
    let tbd = framework_dir.join("Demo.tbd");
    let object = scratch("weak-framework-import.o");
    let weak_output = scratch("weak-framework-import-weak.out");
    let strong_output = scratch("weak-framework-import-strong.out");
    let install_name = "@rpath/Demo.framework/Demo";
    let symbol = "_optional_from_weak_framework";

    fs::create_dir_all(&framework_dir).unwrap();
    fs::write(
        &tbd,
        format!(
            r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '{install_name}'
exports:
  - targets: [ arm64-macos ]
    symbols: [ {symbol} ]
...
"#
        ),
    )
    .unwrap();
    fs::write(
        &object,
        synthetic_got_reference_object("_main", symbol, false),
    )
    .unwrap();

    let mut weak_outputs = Vec::new();
    let mut strong_outputs = Vec::new();
    for jobs in [1, 4] {
        for (weak, output, captures) in [
            (true, &weak_output, &mut weak_outputs),
            (false, &strong_output, &mut strong_outputs),
        ] {
            Linker::run(&LinkOptions {
                inputs: vec![object.clone()],
                frameworks: vec![FrameworkSpec {
                    name: "Demo".into(),
                    weak,
                }],
                syslibroot: Some(syslibroot.clone()),
                output: Some(output.clone()),
                kind: OutputKind::Executable,
                jobs: Some(jobs),
                ..LinkOptions::default()
            })
            .unwrap();
            captures.push(fs::read(output).unwrap());
        }
    }

    assert_eq!(
        weak_outputs[0], weak_outputs[1],
        "weak-framework -j1/-j4 output differs"
    );
    assert_eq!(
        strong_outputs[0], strong_outputs[1],
        "normal-framework -j1/-j4 output differs"
    );
    for (bytes, weak, expected_cmd) in [
        (
            &weak_outputs[0],
            true,
            afs_ld::macho::constants::LC_LOAD_WEAK_DYLIB,
        ),
        (
            &strong_outputs[0],
            false,
            afs_ld::macho::constants::LC_LOAD_DYLIB,
        ),
    ] {
        let header = parse_header(bytes).unwrap();
        let commands = parse_commands(&header, bytes).unwrap();
        assert!(commands.iter().any(|command| {
            matches!(
                command,
                LoadCommand::Dylib(dylib)
                    if dylib.cmd == expected_cmd && dylib.name == install_name
            )
        }));
        assert_got_import(bytes, symbol, 1, weak);
        assert_eq!(
            header.flags & MH_BINDS_TO_WEAK != 0,
            weak,
            "image weak-bind flag must follow the framework load kind"
        );
    }

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(weak_output);
    let _ = fs::remove_file(strong_output);
    let _ = fs::remove_dir_all(syslibroot);
}

#[test]
fn linker_run_preserves_assembler_resolved_deltas_between_subsections() {
    let object = scratch("aligned-subsections.o");
    let output = scratch("aligned-subsections.dylib");
    fs::write(&object, synthetic_aligned_subsections_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let symbols = symbol_values(&bytes);
    let linked_delta = symbols["_b"] - symbols["_a"];
    let embedded_delta = u64::from_le_bytes(text[text.len() - 8..].try_into().unwrap());

    assert_eq!(text_addr % 16, 0, "section-level alignment was lost");
    assert_eq!(
        linked_delta, embedded_delta,
        "atom layout disagrees with the assembler-resolved _b-_a value"
    );
    assert_eq!(
        text,
        [0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 4, 0, 0, 0, 0, 0, 0, 0,]
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_resolves_indirect_aliases_and_preserves_visibility() {
    for private_alias in [false, true] {
        let visibility = if private_alias { "private" } else { "public" };
        let obj = scratch(&format!("indirect-alias-{visibility}.o"));
        let out = scratch(&format!("indirect-alias-{visibility}.out"));
        let map = scratch(&format!("indirect-alias-{visibility}.map"));
        fs::write(
            &obj,
            synthetic_defined_alias_object(
                private_alias,
                false,
                false,
                true,
                SyntheticAliasEncoding::Indirect,
            ),
        )
        .unwrap();

        let opts = LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            map: Some(map.clone()),
            kind: OutputKind::Executable,
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();

        let bytes = fs::read(&out).unwrap();
        let records = canonical_symbol_record_map(&bytes);
        let main = records.get("_main").unwrap();
        let alias = records.get("_alias").unwrap();
        let target = records.get("_target").unwrap();
        assert_eq!(
            alias.n_type,
            N_SECT | if private_alias { N_PEXT } else { N_EXT }
        );
        assert_eq!(alias.n_sect, target.n_sect);
        assert_eq!(alias.n_desc, N_ALT_ENTRY);
        assert_eq!(alias.value, target.value);

        let (_, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
        let start = main.value as usize;
        let instruction = u32::from_le_bytes(text[start..start + 4].try_into().unwrap());
        let immediate = ((instruction & 0x03ff_ffff) as i32) << 6 >> 6;
        assert_eq!(
            main.value as i64 + (i64::from(immediate) << 2),
            target.value as i64
        );

        let (locals, external_defineds, _) = symbol_partition_names(&bytes);
        assert_eq!(locals.contains(&"_alias".to_string()), private_alias);
        assert_eq!(
            external_defineds.contains(&"_alias".to_string()),
            !private_alias
        );
        let map_text = fs::read_to_string(&map).unwrap();
        let alias_line = map_text
            .lines()
            .find(|line| line.ends_with(" _alias"))
            .unwrap();
        assert_eq!(alias_line.split_whitespace().nth(1), Some("0x00000000"));

        let _ = fs::remove_file(obj);
        let _ = fs::remove_file(out);
        let _ = fs::remove_file(map);
    }
}

#[test]
fn linker_run_marks_section_alias_descriptors() {
    for (encoding_name, encoding) in [
        ("explicit", SyntheticAliasEncoding::ExplicitAlternateEntry),
        ("overlapping", SyntheticAliasEncoding::OverlappingSection),
    ] {
        for private_alias in [false, true] {
            let visibility = if private_alias { "private" } else { "public" };
            let obj = scratch(&format!("section-alias-{encoding_name}-{visibility}.o"));
            let out = scratch(&format!("section-alias-{encoding_name}-{visibility}.out"));
            fs::write(
                &obj,
                synthetic_defined_alias_object(private_alias, false, false, true, encoding),
            )
            .unwrap();

            let opts = LinkOptions {
                inputs: vec![obj.clone()],
                output: Some(out.clone()),
                kind: OutputKind::Executable,
                ..LinkOptions::default()
            };
            Linker::run(&opts).unwrap();

            let bytes = fs::read(&out).unwrap();
            let records = canonical_symbol_record_map(&bytes);
            let alias = records.get("_alias").unwrap();
            let target = records.get("_target").unwrap();
            assert_eq!(
                alias.n_type,
                N_SECT | if private_alias { N_PEXT } else { N_EXT }
            );
            assert_eq!(alias.n_sect, target.n_sect);
            assert_eq!(alias.n_desc, N_ALT_ENTRY);
            assert_eq!(alias.value, target.value);
            assert_eq!(target.n_desc & N_ALT_ENTRY, 0);

            let _ = fs::remove_file(obj);
            let _ = fs::remove_file(out);
        }
    }
}

#[test]
fn linker_run_omits_relaxed_defined_got_slots() {
    let reference = scratch("defined-got-reference.o");
    let definition = scratch("defined-got-definition.o");
    let out = scratch("defined-got-reference.out");
    fs::write(
        &reference,
        synthetic_got_reference_object("_main", "_value", false),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_single_section_object(
            "__DATA",
            "__data",
            S_REGULAR,
            &7u64.to_le_bytes(),
            &[],
            &[("_value", N_SECT | N_EXT, 1, 0, 0)],
        ),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    assert!(output_section(&bytes, "__DATA_CONST", "__got").is_none());
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    assert!(is_add_imm_64(read_insn(&text, 4).unwrap()));
    assert_eq!(
        decode_page_reference(&text, text_addr, 0, &PageRefKind::Add).unwrap(),
        symbol_values(&bytes)["_value"]
    );

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_routes_far_absolute_got_loads_through_unrebased_slot() {
    const ABSOLUTE_VALUE: u64 = 0x1234_5678_9abc_def0;

    let reference = scratch("absolute-got-reference.o");
    let definition = scratch("absolute-got-definition.o");
    let out = scratch("absolute-got-reference.out");
    fs::write(
        &reference,
        synthetic_got_reference_object("_main", "_absolute", false),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, got) = output_section(&bytes, "__DATA_CONST", "__got").unwrap();
    assert_eq!(got, ABSOLUTE_VALUE.to_le_bytes());
    assert!(decode_rebase_records(&bytes).unwrap().is_empty());

    let absolute = canonical_symbol_record_map(&bytes)
        .remove("_absolute")
        .unwrap();
    assert_eq!(absolute.n_type, N_ABS | N_EXT);
    assert_eq!(absolute.n_sect, 0);
    assert_eq!(absolute.value, ABSOLUTE_VALUE);

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_writes_pcrel_pointer_to_got_as_delta_from_place() {
    const ABSOLUTE_VALUE: u64 = 0x1234_5678_9abc_def0;

    let reference = scratch("pcrel-pointer-to-got-reference.o");
    let definition = scratch("pcrel-pointer-to-got-definition.o");
    let out = scratch("pcrel-pointer-to-got.out");
    fs::write(
        &reference,
        synthetic_pointer_to_got_reference_object("_main", "_absolute", RelocLength::Word, true),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (got_addr, got) = output_section(&bytes, "__DATA_CONST", "__got").unwrap();
    let actual = i32::from_le_bytes(text[0..4].try_into().unwrap());
    let expected = i32::try_from(i128::from(got_addr) - i128::from(text_addr)).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(got, ABSOLUTE_VALUE.to_le_bytes());

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_preserves_absolute_pointer_to_got() {
    const ABSOLUTE_VALUE: u64 = 0x1234_5678_9abc_def0;

    let reference = scratch("absolute-pointer-to-got-reference.o");
    let definition = scratch("absolute-pointer-to-got-definition.o");
    let out = scratch("absolute-pointer-to-got.out");
    fs::write(
        &reference,
        synthetic_pointer_to_got_reference_object("_main", "_absolute", RelocLength::Quad, false),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (got_addr, got) = output_section(&bytes, "__DATA_CONST", "__got").unwrap();
    assert_eq!(u64::from_le_bytes(text[0..8].try_into().unwrap()), got_addr);
    assert_eq!(got, ABSOLUTE_VALUE.to_le_bytes());

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_resolves_external_absolute_symbols_without_atoms() {
    const ABSOLUTE_VALUE: u64 = 0x1234_5678_9abc_def0;

    let reference = scratch("absolute-reference.o");
    let definition = scratch("absolute-definition.o");
    let out = scratch("absolute-reference.out");
    let map = scratch("absolute-reference.map");
    fs::write(
        &reference,
        synthetic_absolute_reference_object("_main", "_absolute"),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        map: Some(map.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    assert_eq!(
        u64::from_le_bytes(text[..8].try_into().unwrap()),
        ABSOLUTE_VALUE
    );
    let absolute = canonical_symbol_record_map(&bytes)
        .remove("_absolute")
        .unwrap();
    assert_eq!(absolute.n_type, N_ABS | N_EXT);
    assert_eq!(absolute.n_sect, 0);
    assert_eq!(absolute.value, ABSOLUTE_VALUE);

    let map_text = fs::read_to_string(&map).unwrap();
    let absolute_line = map_text
        .lines()
        .find(|line| line.ends_with(" _absolute"))
        .unwrap();
    assert!(absolute_line.starts_with("0x123456789abcdef0 "));
    assert_eq!(absolute_line.split_whitespace().nth(1), Some("0x00000000"));

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_preserves_maximum_unsigned_word_relocation() {
    const ABSOLUTE_VALUE: u64 = u32::MAX as u64;

    let reference = scratch("unsigned-word-max-reference.o");
    let definition = scratch("unsigned-word-max-definition.o");
    let out = scratch("unsigned-word-max.out");
    fs::write(
        &reference,
        synthetic_unsigned_word_reference_object("_main", "_absolute"),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    assert_eq!(u32::from_le_bytes(text[..4].try_into().unwrap()), u32::MAX);

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_rejects_overflowing_unsigned_word_without_publishing_output() {
    const OVERFLOWING_VALUE: u64 = u32::MAX as u64 + 1;
    const SENTINEL: &[u8] = b"AFSLD-050 existing output";

    let reference = scratch("unsigned-word-overflow-reference.o");
    let definition = scratch("unsigned-word-overflow-definition.o");
    let out = scratch("unsigned-word-overflow.out");
    fs::write(
        &reference,
        synthetic_unsigned_word_reference_object("_main", "_absolute"),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", OVERFLOWING_VALUE),
    )
    .unwrap();
    fs::write(&out, SENTINEL).unwrap();

    let error = Linker::run(&LinkOptions {
        inputs: vec![reference.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap_err();

    match error {
        LinkError::Reloc(error) => {
            assert_eq!(error.kind, RelocKind::Unsigned);
            assert_eq!(error.referent, "_absolute");
            assert!(error.detail.contains("32-bit"), "{error}");
            assert!(error.detail.contains("0x100000000"), "{error}");
            assert!(error.detail.contains("out of range"), "{error}");
        }
        other => panic!("expected Reloc error, got {other:?}"),
    }
    assert_eq!(fs::read(&out).unwrap(), SENTINEL);

    let _ = fs::remove_file(reference);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_aliases_to_absolute_symbols() {
    const ABSOLUTE_VALUE: u64 = 0x1234_5678;

    let alias = scratch("absolute-alias.o");
    let definition = scratch("absolute-alias-definition.o");
    let out = scratch("absolute-alias.dylib");
    fs::write(
        &alias,
        synthetic_alias_object("_absolute_alias", "_absolute", false),
    )
    .unwrap();
    fs::write(
        &definition,
        synthetic_absolute_object("_absolute", ABSOLUTE_VALUE),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![alias.clone(), definition.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        dead_strip: true,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let records = canonical_symbol_record_map(&bytes);
    for name in ["_absolute", "_absolute_alias"] {
        let record = records.get(name).unwrap();
        assert_eq!(record.n_type, N_ABS | N_EXT);
        assert_eq!(record.n_sect, 0);
        assert_eq!(record.n_desc, 0);
        assert_eq!(record.value, ABSOLUTE_VALUE);
    }
    let exports = canonical_export_records(&bytes).unwrap();
    for name in ["_absolute", "_absolute_alias"] {
        let export = exports.iter().find(|entry| entry.name == name).unwrap();
        assert!(matches!(
            export.kind,
            CanonicalExportKind::Absolute(ABSOLUTE_VALUE)
        ));
    }

    let _ = fs::remove_file(alias);
    let _ = fs::remove_file(definition);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_keeps_public_alias_targets_live_in_dead_stripped_dylibs() {
    let obj = scratch("indirect-alias-dead-strip.o");
    let out = scratch("indirect-alias-dead-strip.dylib");
    fs::write(
        &obj,
        synthetic_defined_alias_object(false, false, true, false, SyntheticAliasEncoding::Indirect),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        dead_strip: true,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let records = canonical_symbol_record_map(&bytes);
    let alias = records.get("_alias").unwrap();
    assert_eq!(alias.n_type, N_SECT | N_EXT);
    assert!(
        output_section(&bytes, "__TEXT", "__text").is_some_and(|(_, text)| !text.is_empty()),
        "public alias target was dead stripped"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_binds_import_aliases_through_their_reexported_target() {
    for private_alias in [false, true] {
        let visibility = if private_alias { "private" } else { "public" };
        let use_obj = scratch(&format!("indirect-import-{visibility}-use.o"));
        let alias_obj = scratch(&format!("indirect-import-{visibility}-alias.o"));
        let tbd = scratch(&format!("indirect-import-{visibility}.tbd"));
        let out = scratch(&format!("indirect-import-{visibility}.dylib"));
        fs::write(
            &use_obj,
            synthetic_got_reference_object("_probe", "_alias", false),
        )
        .unwrap();
        fs::write(
            &alias_obj,
            synthetic_alias_object("_alias", "_target", private_alias),
        )
        .unwrap();
        fs::write(
            &tbd,
            r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libtarget.dylib'
exports:
  - targets: [ arm64-macos ]
    weak-symbols: [ _target ]
...
"#,
        )
        .unwrap();

        let opts = LinkOptions {
            inputs: vec![use_obj.clone(), alias_obj.clone(), tbd.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Dylib,
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();

        let bytes = fs::read(&out).unwrap();
        Linker::run(&opts).unwrap();
        assert_eq!(bytes, fs::read(&out).unwrap());
        let binds = decode_bind_records(&bytes, false).unwrap();
        assert!(
            binds.iter().any(|record| {
                record.symbol == "_target" && record.ordinal == 1 && record.weak_import
            }),
            "expected target bind, got {binds:?}"
        );
        assert!(!binds.iter().any(|record| record.symbol == "_alias"));

        let records = canonical_symbol_record_map(&bytes);
        let (locals, external_defineds, _) = symbol_partition_names(&bytes);
        let exports = canonical_export_records(&bytes).unwrap();
        let alias_export = exports.iter().find(|entry| entry.name == "_alias");
        if private_alias {
            assert!(!records.contains_key("_alias"));
            assert!(!locals.contains(&"_alias".to_string()));
            assert!(!external_defineds.contains(&"_alias".to_string()));
            assert!(alias_export.is_none());
        } else {
            let alias = records.get("_alias").unwrap();
            assert_eq!(alias.n_type, N_INDR | N_EXT);
            assert_eq!(alias.n_desc, 0);
            let (symtab, _) = symtab_and_dysymtab(&bytes);
            let strings = StringTable::from_file(&bytes, symtab.stroff, symtab.strsize).unwrap();
            assert_eq!(strings.get(alias.value as u32).unwrap(), "_target");
            assert!(external_defineds.contains(&"_alias".to_string()));
            let alias_export = alias_export.unwrap();
            assert_eq!(
                alias_export.kind,
                CanonicalExportKind::Reexport {
                    ordinal: 1,
                    imported_name: "_target".to_string(),
                }
            );
            assert_eq!(
                alias_export.flags,
                EXPORT_SYMBOL_FLAGS_REEXPORT | EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION
            );
        }

        let _ = fs::remove_file(use_obj);
        let _ = fs::remove_file(alias_obj);
        let _ = fs::remove_file(tbd);
        let _ = fs::remove_file(out);
    }
}

#[test]
fn linker_run_reports_alias_cycles_from_object_inputs() {
    let first = scratch("indirect-cycle-a.o");
    let second = scratch("indirect-cycle-b.o");
    let out = scratch("indirect-cycle.out");
    let _ = fs::remove_file(&out);
    fs::write(&first, synthetic_alias_object("_a", "_b", false)).unwrap();
    fs::write(&second, synthetic_alias_object("_b", "_a", false)).unwrap();

    let error = Linker::run(&LinkOptions {
        inputs: vec![first.clone(), second.clone()],
        output: Some(out.clone()),
        ..LinkOptions::default()
    })
    .unwrap_err();

    match error {
        LinkError::DuplicateSymbols(message) => {
            assert_eq!(message, "afs-ld: error: alias cycle involving _b\n");
        }
        other => panic!("expected DuplicateSymbols, got {other:?}"),
    }
    assert!(!out.exists());

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
}

#[test]
fn linker_run_reports_alias_definition_provenance_in_input_order() {
    let alias = scratch("indirect-duplicate-alias.o");
    let definition = scratch("indirect-duplicate-definition.o");
    fs::write(&alias, synthetic_alias_object("_dup", "_target", false)).unwrap();
    fs::write(
        &definition,
        synthetic_got_reference_object("_dup", "_unused", false),
    )
    .unwrap();

    for alias_first in [false, true] {
        let out = scratch(&format!("indirect-duplicate-{alias_first}.out"));
        let _ = fs::remove_file(&out);
        let (first, second) = if alias_first {
            (&alias, &definition)
        } else {
            (&definition, &alias)
        };
        let error = Linker::run(&LinkOptions {
            inputs: vec![first.clone(), second.clone()],
            output: Some(out.clone()),
            ..LinkOptions::default()
        })
        .unwrap_err();

        match error {
            LinkError::DuplicateSymbols(message) => assert_eq!(
                message,
                format!(
                    "afs-ld: error: duplicate symbol _dup\n  defined in {}\n  also in {}\n",
                    first.display(),
                    second.display()
                )
            ),
            other => panic!("expected DuplicateSymbols, got {other:?}"),
        }
        assert!(!out.exists());
    }

    let _ = fs::remove_file(alias);
    let _ = fs::remove_file(definition);
}

#[test]
fn linker_run_reports_duplicate_from_fetched_archive_member() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
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
        require_fixture!("assembly fixture", assemble(src, out));
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&dup_obj)
        .output()
        .unwrap();
    assert!(
        ar.status.success(),
        "archive fixture failed: {}",
        String::from_utf8_lossy(&ar.stderr)
    );

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
        harness_skip!("xcrun as unavailable");
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
        require_fixture!("assembly fixture", assemble(src, out));
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member_obj)
        .output()
        .unwrap();
    assert!(
        ar.status.success(),
        "archive fixture failed: {}",
        String::from_utf8_lossy(&ar.stderr)
    );

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
fn linker_run_all_load_pulls_entry_from_archive() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun as or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("no macOS SDK path");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let member_obj = scratch("all-load-main.o");
    let archive = scratch("all-load-main.a");
    let out = scratch("all-load-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #7
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &member_obj));
    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member_obj)
        .output()
        .unwrap();
    assert!(
        ar.status.success(),
        "archive fixture failed: {}",
        String::from_utf8_lossy(&ar.stderr)
    );

    let opts = LinkOptions {
        inputs: vec![archive.clone(), tbd],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        all_load: true,
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
        Some(7),
        "expected all-load executable to exit 7"
    );

    let _ = fs::remove_file(member_obj);
    let _ = fs::remove_file(archive);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_force_load_pulls_entry_from_archive() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun as or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("no macOS SDK path");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let member_obj = scratch("force-load-main.o");
    let archive = scratch("force-load-main.a");
    let out = scratch("force-load-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #9
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &member_obj));
    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member_obj)
        .output()
        .unwrap();
    assert!(
        ar.status.success(),
        "archive fixture failed: {}",
        String::from_utf8_lossy(&ar.stderr)
    );

    let opts = LinkOptions {
        inputs: vec![archive.clone(), tbd],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        force_load_archives: vec![archive.clone()],
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
        Some(9),
        "expected force-load executable to exit 9"
    );

    let _ = fs::remove_file(member_obj);
    let _ = fs::remove_file(archive);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_resolves_lsystem_via_syslibroot() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun as or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("no macOS SDK path");
        return;
    };

    let obj = scratch("lsystem-main.o");
    let out = scratch("lsystem-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        library_names: vec!["System".into()],
        syslibroot: Some(PathBuf::from(&sdk)),
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let dylibs = load_dylib_names(&bytes).unwrap();
    assert!(
        dylibs
            .iter()
            .any(|name| name == "/usr/lib/libSystem.B.dylib"),
        "expected libSystem load command, got {dylibs:?}"
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
    assert_eq!(
        status.code(),
        Some(0),
        "expected executable linked via -lSystem to exit 0"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_resolves_framework_via_syslibroot() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let metal = PathBuf::from(format!(
        "{sdk}/System/Library/Frameworks/Metal.framework/Metal.tbd"
    ));
    if !metal.exists() {
        harness_skip!("no Metal.tbd at {}", metal.display());
        return;
    }

    let obj = scratch("framework-main.o");
    let out = scratch("framework-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        frameworks: vec![FrameworkSpec {
            name: "Metal".into(),
            weak: false,
        }],
        syslibroot: Some(PathBuf::from(&sdk)),
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(commands.iter().any(|cmd| matches!(
        cmd,
        LoadCommand::Dylib(d)
            if d.cmd == afs_ld::macho::constants::LC_LOAD_DYLIB
                && d.name.contains("Metal.framework")
    )));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_resolves_weak_framework_via_syslibroot() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let metal = PathBuf::from(format!(
        "{sdk}/System/Library/Frameworks/Metal.framework/Metal.tbd"
    ));
    if !metal.exists() {
        harness_skip!("no Metal.tbd at {}", metal.display());
        return;
    }

    let obj = scratch("weak-framework-main.o");
    let out = scratch("weak-framework-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        frameworks: vec![FrameworkSpec {
            name: "Metal".into(),
            weak: true,
        }],
        syslibroot: Some(PathBuf::from(&sdk)),
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(commands.iter().any(|cmd| matches!(
        cmd,
        LoadCommand::Dylib(d)
            if d.cmd == afs_ld::macho::constants::LC_LOAD_WEAK_DYLIB
                && d.name.contains("Metal.framework")
    )));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_uses_platform_version_for_build_command() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("platform-version.o");
    let out = scratch("platform-version.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        platform_version: Some(afs_ld::PlatformVersion {
            minos: (13 << 16) | (2 << 8) | 1,
            sdk: (14 << 16) | (5 << 8),
        }),
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let build = commands
        .into_iter()
        .find_map(|cmd| match cmd {
            LoadCommand::BuildVersion(cmd) => Some(cmd),
            _ => None,
        })
        .expect("missing LC_BUILD_VERSION");
    assert_eq!(build.minos, (13 << 16) | (2 << 8) | 1);
    assert_eq!(build.sdk, (14 << 16) | (5 << 8));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_rpath_command() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("rpath-main.o");
    let out = scratch("rpath-main.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        rpaths: vec!["@loader_path/../Frameworks".into()],
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let rpaths: Vec<String> = commands
        .into_iter()
        .filter_map(|cmd| match cmd {
            LoadCommand::Rpath(cmd) => Some(cmd.path),
            _ => None,
        })
        .collect();
    assert_eq!(rpaths, vec!["@loader_path/../Frameworks".to_string()]);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_map_file() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("map-main.o");
    let out = scratch("map-main.out");
    let map = scratch("map-main.map");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        map: Some(map.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let map_text = fs::read_to_string(&map).unwrap();
    assert!(map_text.contains("# Path:"));
    assert!(map_text.contains("# Object files:"));
    assert!(map_text.contains("linker synthesized"));
    assert!(map_text.contains(&obj.display().to_string()));
    assert!(map_text.contains("# Sections:"));
    assert!(map_text.contains("__TEXT"));
    assert!(map_text.contains("__text"));
    assert!(map_text.contains("# Symbols:"));
    assert!(map_text.contains("_main"));
    assert!(map_text.contains("# Dead stripped:"));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_map_lists_dead_stripped_symbols() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let main_obj = scratch("map-dead-main.o");
    let helper_obj = scratch("map-dead-helper.o");
    let unused_obj = scratch("map-dead-unused.o");
    let out = scratch("map-dead.out");
    let map = scratch("map-dead.map");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    let unused_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _unused
        _unused:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(main_src, &main_obj));
    require_fixture!("assembly fixture", assemble(helper_src, &helper_obj));
    require_fixture!("assembly fixture", assemble(unused_src, &unused_obj));

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), helper_obj.clone(), unused_obj.clone()],
        output: Some(out.clone()),
        map: Some(map.clone()),
        dead_strip: true,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let map_text = fs::read_to_string(&map).unwrap();
    let dead_stripped_idx = map_text.find("# Dead stripped:").unwrap();
    let dead_stripped = &map_text[dead_stripped_idx..];
    assert!(dead_stripped.contains("_unused"));
    assert!(!dead_stripped.contains("_helper"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(unused_obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_map_lists_folded_symbols_under_icf_safe() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("map-icf-folded.o");
    let out = scratch("map-icf-folded.out");
    let map = scratch("map-icf-folded.map");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper1
            bl _helper2
            mov w0, #0
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #7
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #7
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        map: Some(map.clone()),
        icf_mode: afs_ld::IcfMode::Safe,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let map_text = fs::read_to_string(&map).unwrap();
    let folded_idx = map_text.find("# Folded symbols:").unwrap();
    let folded = &map_text[folded_idx..];
    assert!(folded.contains("_helper2 folded to _helper1"));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_carries_tbd_inputs_into_load_commands() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
fn linker_run_resolves_reexported_inline_tbd_documents_through_the_umbrella() {
    let object = scratch("inline-tbd-reexport.o");
    let tbd = scratch("inline-tbd-reexport.tbd");
    let output = scratch("inline-tbd-reexport.out");
    let child_symbol = "_inline_child_export";
    fs::write(
        &object,
        synthetic_got_reference_object("_main", child_symbol, false),
    )
    .unwrap();
    fs::write(
        &tbd,
        format!(
            r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libinline_umbrella.dylib'
reexported-libraries:
  - targets: [ arm64-macos ]
    libraries: [ '/usr/lib/libinline_middle.dylib' ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libinline_middle.dylib'
parent-umbrella:
  - targets: [ arm64-macos ]
    umbrella: inline_umbrella
reexported-libraries:
  - targets: [ arm64-macos ]
    libraries: [ '/usr/lib/libinline_child.dylib' ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libinline_child.dylib'
parent-umbrella:
  - targets: [ arm64-macos ]
    umbrella: inline_umbrella
exports:
  - targets: [ arm64-macos ]
    symbols: [ {child_symbol} ]
...
"#
        ),
    )
    .unwrap();

    let mut outputs = Vec::new();
    for jobs in [1, 4] {
        Linker::run(&LinkOptions {
            inputs: vec![object.clone(), tbd.clone()],
            output: Some(output.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        outputs.push(fs::read(&output).unwrap());
    }
    assert_eq!(outputs[0], outputs[1], "-j1 and -j4 output differs");
    assert_eq!(
        load_dylib_names(&outputs[0]).unwrap(),
        ["/usr/lib/libinline_umbrella.dylib"]
    );
    assert_got_import(&outputs[0], child_symbol, 1, false);

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(tbd);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_rejects_exports_from_unrelated_inline_tbd_documents() {
    const SENTINEL: &[u8] = b"AFSLD-057 existing output";

    let object = scratch("inline-tbd-unrelated.o");
    let tbd = scratch("inline-tbd-unrelated.tbd");
    let output = scratch("inline-tbd-unrelated.out");
    let unrelated_symbol = "_unrelated_inline_export";
    fs::write(
        &object,
        synthetic_got_reference_object("_main", unrelated_symbol, false),
    )
    .unwrap();
    fs::write(
        &tbd,
        format!(
            r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libinline_primary.dylib'
exports:
  - targets: [ arm64-macos ]
    symbols: [ _primary_export ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libinline_unrelated.dylib'
exports:
  - targets: [ arm64-macos ]
    symbols: [ {unrelated_symbol} ]
...
"#
        ),
    )
    .unwrap();

    let mut diagnostics = Vec::new();
    for jobs in [1, 4] {
        fs::write(&output, SENTINEL).unwrap();
        let error = Linker::run(&LinkOptions {
            inputs: vec![object.clone(), tbd.clone()],
            output: Some(output.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .expect_err("an unrelated inline TBD document must not satisfy imports");
        diagnostics.push(error.to_string());
        assert_eq!(fs::read(&output).unwrap(), SENTINEL);
    }
    assert_eq!(diagnostics[0], diagnostics[1]);
    assert!(
        diagnostics[0].contains(&format!("undefined symbol: {unrelated_symbol}")),
        "unexpected diagnostic: {}",
        diagnostics[0]
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(tbd);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_enforces_the_macho_library_ordinal_boundary() {
    const MAX_ORDINARY_LIBRARY_ORDINAL: usize = 0xfd;
    const SENTINEL: &[u8] = b"previous complete Mach-O output";

    let dir = scratch("library-ordinal-boundary");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let max_object = dir.join("max-ordinal.o");
    let reserved_object = dir.join("reserved-ordinal.o");
    fs::write(
        &max_object,
        synthetic_got_reference_object("_max_probe", "_max_target", false),
    )
    .unwrap();
    fs::write(
        &reserved_object,
        synthetic_got_reference_object("_reserved_probe", "_reserved_target", false),
    )
    .unwrap();

    let mut dependencies = Vec::new();
    for ordinal in 1..=MAX_ORDINARY_LIBRARY_ORDINAL + 1 {
        let path = dir.join(format!("libordinal{ordinal:03}.tbd"));
        let exported_symbol = match ordinal {
            MAX_ORDINARY_LIBRARY_ORDINAL => "_max_target",
            ordinal if ordinal == MAX_ORDINARY_LIBRARY_ORDINAL + 1 => "_reserved_target",
            _ => "",
        };
        let exports = if exported_symbol.is_empty() {
            String::new()
        } else {
            format!("exports:\n  - targets: [ arm64-macos ]\n    symbols: [ {exported_symbol} ]\n")
        };
        fs::write(
            &path,
            format!(
                "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: '/usr/lib/libordinal{ordinal:03}.dylib'\n{exports}...\n"
            ),
        )
        .unwrap();
        dependencies.push(path);
    }

    let mut max_outputs = Vec::new();
    let max_output = dir.join("max-ordinal.dylib");
    for jobs in [1, 4] {
        let mut inputs = vec![max_object.clone()];
        inputs.extend_from_slice(&dependencies[..MAX_ORDINARY_LIBRARY_ORDINAL]);
        Linker::run(&LinkOptions {
            inputs,
            output: Some(max_output.clone()),
            install_name: Some("@rpath/max-ordinal.dylib".into()),
            kind: OutputKind::Dylib,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        max_outputs.push(fs::read(&max_output).unwrap());
    }

    assert_eq!(max_outputs[0], max_outputs[1]);
    let max_bytes = &max_outputs[0];
    let load_names = load_dylib_names(max_bytes).unwrap();
    assert_eq!(load_names.len(), MAX_ORDINARY_LIBRARY_ORDINAL);
    assert_eq!(load_names.last().unwrap(), "/usr/lib/libordinal253.dylib");
    assert_eq!(
        canonical_symbol_record_map(max_bytes)["_max_target"].n_desc >> 8,
        MAX_ORDINARY_LIBRARY_ORDINAL as u16
    );
    assert!(decode_bind_records(max_bytes, false)
        .unwrap()
        .iter()
        .any(|record| {
            record.symbol == "_max_target" && record.ordinal == MAX_ORDINARY_LIBRARY_ORDINAL as u16
        }));

    let mut diagnostics = Vec::new();
    for jobs in [1, 4] {
        let output = dir.join(format!("reserved-ordinal-j{jobs}.dylib"));
        fs::write(&output, SENTINEL).unwrap();
        let mut inputs = vec![reserved_object.clone()];
        inputs.extend_from_slice(&dependencies);
        let error = Linker::run(&LinkOptions {
            inputs,
            output: Some(output.clone()),
            kind: OutputKind::Dylib,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .expect_err("ordinary dylib ordinal 254 must be rejected");
        diagnostics.push(error.to_string());
        assert_eq!(fs::read(output).unwrap(), SENTINEL);
    }
    assert_eq!(diagnostics[0], diagnostics[1]);
    assert_eq!(
        diagnostics[0],
        "too many dylib dependencies: Mach-O supports at most 253 ordinary library ordinals"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn linker_run_handles_non_standard_segment_without_panicking() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("custom-segment.o");
    let out = scratch("custom-segment.out");
    let src = r#"
        .section __FOO,__bar
        .globl _custom
        _custom:
            .quad 1

        .text
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

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
fn linker_run_rebases_local_pointers_in_custom_segments() {
    for pointer_section in ["__ptrs", "__thread_vars"] {
        let obj = scratch(&format!("custom-segment-{pointer_section}-synthetic.o"));
        let out = scratch(&format!("custom-segment-{pointer_section}-synthetic.out"));
        fs::write(
            &obj,
            synthetic_segment_rebase_object("__CUSTOM", pointer_section, S_REGULAR),
        )
        .unwrap();

        let opts = LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            entry: Some("_main".into()),
            kind: OutputKind::Executable,
            ..LinkOptions::default()
        };
        Linker::run(&opts).unwrap();

        let bytes = fs::read(&out).unwrap();
        assert_eq!(segment_protections(&bytes, "__CUSTOM"), Some((3, 3)));
        let (target_addr, _) = output_section(&bytes, "__DATA", "__data").unwrap();
        let (_, pointer) = output_section(&bytes, "__CUSTOM", pointer_section).unwrap();
        assert_eq!(
            u64::from_le_bytes(pointer.try_into().unwrap()),
            target_addr,
            "custom-segment pointer should contain the target preferred address"
        );
        assert_eq!(
            decode_rebase_records(&bytes).unwrap(),
            vec![RebaseRecord {
                segment: "__CUSTOM".into(),
                section: pointer_section.into(),
                section_offset: 0,
                rebase_type: REBASE_TYPE_POINTER,
            }]
        );

        let _ = fs::remove_file(obj);
        let _ = fs::remove_file(out);
    }
}

#[test]
fn linker_run_omits_debug_section_rebases() {
    let obj = scratch("debug-section-rebase-synthetic.o");
    let out = scratch("debug-section-rebase-synthetic.out");
    fs::write(
        &obj,
        synthetic_segment_rebase_object("__DWARF", "__debug_info", S_REGULAR | S_ATTR_DEBUG),
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        entry: Some("_main".into()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (target_addr, _) = output_section(&bytes, "__DATA", "__data").unwrap();
    let (_, debug_info) = output_section(&bytes, "__DWARF", "__debug_info").unwrap();
    assert_eq!(
        u64::from_le_bytes(debug_info.try_into().unwrap()),
        target_addr
    );
    assert!(
        decode_rebase_records(&bytes).unwrap().is_empty(),
        "debug relocation sites must not become runtime rebase records"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_rebases_custom_segment_pointers_like_apple_ld() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("custom-segment-rebase.o");
    let our_out = scratch("custom-segment-rebase-ours.out");
    let apple_out = scratch("custom-segment-rebase-apple.out");
    let src = r#"
        .section __CUSTOM,__ptrs,regular
        .p2align 3
        .globl _p
        _p: .quad _target

        .data
        .p2align 3
        .globl _target
        _target: .quad 7

        .text
        .globl _main
        _main:
            adrp x8, _p@PAGE
            add x8, x8, _p@PAGEOFF
            ldr x9, [x8]
            adrp x10, _target@PAGE
            add x10, x10, _target@PAGEOFF
            cmp x9, x10
            cset w0, ne
            ret
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        entry: Some("_main".into()),
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
            "-e",
            "_main",
            "-o",
        ])
        .arg(&apple_out)
        .arg(&obj)
        .arg("-lSystem")
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let our_rebases = decode_rebase_records(&our_bytes).unwrap();
    assert!(
        our_rebases.iter().any(|record| {
            record.segment == "__CUSTOM"
                && record.section == "__ptrs"
                && record.section_offset == 0
                && record.rebase_type == REBASE_TYPE_POINTER
        }),
        "missing custom-segment rebase: {our_rebases:#?}"
    );
    assert_eq!(our_rebases, decode_rebase_records(&apple_bytes).unwrap());

    for output in [&our_out, &apple_out] {
        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "codesign verify failed for {}: {}",
            output.display(),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(Command::new(output).status().unwrap().code(), Some(0));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_uses_requested_entry_symbol() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
fn linker_run_dead_strip_keeps_same_address_entry_alias_bytes() {
    let obj = scratch("same-address-entry-alias-synthetic.o");
    let out = scratch("same-address-entry-alias-synthetic.out");
    fs::write(&obj, synthetic_same_address_entry_alias_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        dead_strip: true,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    assert_same_address_entry_alias_output(&fs::read(&out).unwrap());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_dead_strip_keeps_same_address_entry_alias() {
    if !have_xcrun_tool("ld") || !have_tool("codesign") {
        harness_skip!("xcrun ld or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("same-address-entry-alias.o");
    let our_out = scratch("same-address-entry-alias-ours.out");
    let apple_out = scratch("same-address-entry-alias-apple.out");
    fs::write(&obj, synthetic_same_address_entry_alias_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        dead_strip: true,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();
    apple_link_with_args(
        &obj,
        &apple_out,
        "_main",
        &sdk,
        &sdk_ver,
        &["-dead_strip", "-no_fixup_chains"],
    )
    .unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    for bytes in [&our_bytes, &apple_bytes] {
        assert_same_address_entry_alias_output(bytes);
    }
    let our_records = canonical_symbol_record_map(&our_bytes);
    let apple_records = canonical_symbol_record_map(&apple_bytes);
    for name in ["_main", "_zalias"] {
        assert_eq!(our_records.get(name), apple_records.get(name));
    }

    for output in [&our_out, &apple_out] {
        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "codesign verify failed for {}: {}",
            output.display(),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(Command::new(output).status().unwrap().code(), Some(42));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_defaults_entry_to_main_symbol() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("default-entry.o");
    let out = scratch("default-entry.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            mov w0, #7
            ret
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let status = Command::new(&out).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "default executable entry should prefer _main over the first text atom"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_applies_core_arm64_relocations() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
        harness_skip!("xcrun as unavailable");
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
fn linker_run_thunks_none_rejects_out_of_range_branch26() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("branch26-range.o");
    let out = scratch("branch26-range.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper
            ldp x29, x30, [sp], #16
            ret

        .zerofill __DATA,__bss,_gap,0x9000000,0

        .section __FAR,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out),
        kind: OutputKind::Executable,
        thunks: afs_ld::ThunkMode::None,
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
fn linker_run_inserts_thunk_for_out_of_range_branch26() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }

    let obj = scratch("branch26-thunk.o");
    let out = scratch("branch26-thunk.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper
            ldp x29, x30, [sp], #16
            ret

        .zerofill __DATA,__bss,_gap,0x9000000,0

        .section __FAR,__text,regular,pure_instructions
        .globl _helper
        _helper:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (thunks_addr, thunks) = output_section(&bytes, "__TEXT", "__thunks").unwrap();
    assert_eq!(thunks.len(), 12, "expected one synthetic thunk");
    assert_eq!(
        decode_branch_target(&text, text_addr, 8).unwrap(),
        thunks_addr,
        "expected _main BL to target __thunks"
    );
    assert!(is_adrp(read_insn(&thunks, 0).unwrap()));
    assert!(is_add_imm_64(read_insn(&thunks, 4).unwrap()));
    assert_eq!(read_insn(&thunks, 8).unwrap(), 0xd61f_0200);

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
        "expected thunked executable to exit 0"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_safe_thunks_do_not_grow_small_programs() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("branch26-small.o");
    let out = scratch("branch26-small.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            ret

        _helper:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    assert!(
        output_section(&fs::read(&out).unwrap(), "__TEXT", "__thunks").is_none(),
        "small in-range program should not gain __thunks"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_thunks_all_forces_shared_thunk_for_in_range_calls() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }

    let obj = scratch("branch26-thunks-all.o");
    let out = scratch("branch26-thunks-all.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper
            bl _helper
            ldp x29, x30, [sp], #16
            ret

        _helper:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        thunks: afs_ld::ThunkMode::All,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (thunks_addr, thunks) = output_section(&bytes, "__TEXT", "__thunks").unwrap();
    assert_eq!(
        thunks.len(),
        12,
        "expected both in-range calls to share one forced thunk"
    );
    assert_eq!(
        decode_branch_target(&text, text_addr, 8).unwrap(),
        thunks_addr,
        "expected first BL to route through __thunks under -thunks=all"
    );
    assert_eq!(
        decode_branch_target(&text, text_addr, 12).unwrap(),
        thunks_addr,
        "expected second BL to share the same thunk target"
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
    assert_eq!(
        status.code(),
        Some(0),
        "expected -thunks=all executable to exit 0"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_thunks_preserve_branch_addends_and_identity() {
    let obj = scratch("branch26-thunk-addends.o");
    let direct_out = scratch("branch26-direct-addends.dylib");
    let out = scratch("branch26-thunk-addends.dylib");
    fs::write(&obj, synthetic_branch_addend_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(direct_out.clone()),
        kind: OutputKind::Dylib,
        thunks: afs_ld::ThunkMode::None,
        ..LinkOptions::default()
    })
    .unwrap();
    let direct_bytes = fs::read(&direct_out).unwrap();
    let direct_symbols = symbol_values(&direct_bytes);
    let (direct_text_addr, direct_text) =
        output_section(&direct_bytes, "__TEXT", "__text").unwrap();
    assert_eq!(
        [
            decode_branch_target(&direct_text, direct_text_addr, 0).unwrap(),
            decode_branch_target(&direct_text, direct_text_addr, 4).unwrap(),
            decode_branch_target(&direct_text, direct_text_addr, 8).unwrap(),
        ],
        [
            direct_symbols["_target"] + 4,
            direct_symbols["_target"] - 4,
            direct_symbols["_target"] + 4,
        ],
        "direct branches must retain their relocation addends"
    );

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        thunks: afs_ld::ThunkMode::All,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    let symbols = symbol_values(&bytes);
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (thunks_addr, thunks) = output_section(&bytes, "__TEXT", "__thunks").unwrap();
    assert_eq!(
        thunks.len(),
        24,
        "distinct relocation addends require distinct thunks"
    );

    let positive = decode_branch_target(&text, text_addr, 0).unwrap();
    let negative = decode_branch_target(&text, text_addr, 4).unwrap();
    let repeated_positive = decode_branch_target(&text, text_addr, 8).unwrap();
    assert_eq!(
        positive, repeated_positive,
        "equal addends should share a thunk"
    );
    assert_ne!(
        positive, negative,
        "distinct addends must not share a thunk"
    );

    let thunk_starts = [thunks_addr, thunks_addr + 12];
    for (caller_target, effective_target) in [
        (positive, symbols["_target"] + 4),
        (negative, symbols["_target"] - 4),
    ] {
        assert!(
            thunk_starts.contains(&caller_target),
            "caller landed inside a thunk instead of at its first instruction"
        );
        let thunk_offset = caller_target - thunks_addr;
        assert_eq!(
            decode_page_reference(&thunks, thunks_addr, thunk_offset, &PageRefKind::Add).unwrap(),
            effective_target,
            "thunk materialized the bare symbol instead of the addend-adjusted target"
        );
        assert_eq!(
            read_insn(&thunks, thunk_offset as usize + 8).unwrap(),
            0xd61f_0200
        );
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(direct_out);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_places_thunks_in_caller_segment() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }

    let obj = scratch("branch26-custom-segment-thunk.o");
    let out = scratch("branch26-custom-segment-thunk.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            mov w0, #0
            ret

        .zerofill __DATA,__bss,_gap,0x9000000,0

        .section __FARCALL,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper
            ldp x29, x30, [sp], #16
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    assert!(
        output_section(&bytes, "__TEXT", "__thunks").is_none(),
        "expected no __TEXT thunk section for custom-segment caller"
    );
    let (text_addr, text) = output_section(&bytes, "__FARCALL", "__text").unwrap();
    let (thunks_addr, thunks) = output_section(&bytes, "__FARCALL", "__thunks").unwrap();
    assert_eq!(thunks.len(), 12, "expected one custom-segment thunk");
    assert_eq!(
        decode_branch_target(&text, text_addr, 8).unwrap(),
        thunks_addr,
        "expected custom-segment BL to target custom-segment thunk"
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

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_replans_thunks_until_layout_converges() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let obj = scratch("branch26-thunk-fixed-point.o");
    let out = scratch("branch26-thunk-fixed-point.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _overflow
            bl _borderline
            mov w0, #0
            ret
            .space 0x3fe8

        .zerofill __DATA,__bss,_gap,0x7ff8000,2

        .section __FAR,__text,regular,pure_instructions
            .space 0x3ffc
        .globl _borderline
        _borderline:
            ret

        .globl _overflow
        _overflow:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (thunks_addr, thunks) = output_section(&bytes, "__TEXT", "__thunks").unwrap();
    assert_eq!(
        thunks.len(),
        24,
        "expected two thunks after fixed-point replanning"
    );
    let mut actual_targets = [
        decode_branch_target(&text, text_addr, 0).unwrap(),
        decode_branch_target(&text, text_addr, 4).unwrap(),
    ];
    actual_targets.sort_unstable();
    assert_eq!(
        actual_targets,
        [thunks_addr, thunks_addr + 12],
        "expected both branches to redirect through the two thunk slots"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_multiple_thunk_islands_within_text_segment() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }

    let obj = scratch("branch26-multi-island.o");
    let out = scratch("branch26-multi-island.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _midcaller
            mov w0, #0
            ret

        .section __TEXT,__bmid,regular,pure_instructions
        .globl _midcaller
        _midcaller:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper
            ldp x29, x30, [sp], #16
            ret

        .section __TEXT,__dlate,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        thunks: afs_ld::ThunkMode::All,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let thunk_sections = output_sections(&bytes, "__TEXT", "__thunks");
    assert_eq!(
        thunk_sections.len(),
        2,
        "expected one thunk island after each caller"
    );
    assert!(
        thunk_sections.iter().all(|(_, bytes)| bytes.len() == 12),
        "expected one thunk per island"
    );

    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").unwrap();
    let (mid_addr, mid) = output_section(&bytes, "__TEXT", "__bmid").unwrap();
    let mut actual_targets = [
        decode_branch_target(&text, text_addr, 0).unwrap(),
        decode_branch_target(&mid, mid_addr, 8).unwrap(),
    ];
    actual_targets.sort_unstable();
    let mut expected_targets = [thunk_sections[0].0, thunk_sections[1].0];
    expected_targets.sort_unstable();
    assert_eq!(
        actual_targets, expected_targets,
        "expected the two call sites to route through the two thunk islands"
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

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_routes_dylib_imports_through_synthetic_sections() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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
    let libsystem_load = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Dylib(cmd)
                if cmd.cmd == afs_ld::macho::constants::LC_LOAD_DYLIB
                    && cmd.name == "/usr/lib/libSystem.B.dylib" =>
            {
                Some(cmd.clone())
            }
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
    assert!(libsystem_load.current_version >= (1 << 16));
    assert_eq!(libsystem_load.compatibility_version, 1 << 16);
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
fn linker_run_applies_pcrel_pointer_to_got_like_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("ld") || !have_tool("codesign") {
        harness_skip!("xcrun as/ld or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("pcrel-pointer-to-got.o");
    let our_out = scratch("pcrel-pointer-to-got-ours.out");
    let apple_out = scratch("pcrel-pointer-to-got-apple.out");
    let src = r#"
        .data
        .globl _delta
        _delta:
            .long _puts@GOT - .

        .text
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    assemble(src, &obj).unwrap();

    let object_bytes = fs::read(&obj).unwrap();
    let object = ObjectFile::parse(&obj, &object_bytes).unwrap();
    let relocs: Vec<_> = object
        .sections
        .iter()
        .flat_map(|section| {
            let raw = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc).unwrap();
            parse_relocs(&raw).unwrap()
        })
        .collect();
    assert!(relocs.iter().any(|reloc| {
        reloc.kind == RelocKind::PointerToGot && reloc.length == RelocLength::Word && reloc.pcrel
    }));

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();
    apple_link_with_args(
        &obj,
        &apple_out,
        "_main",
        &sdk,
        &sdk_ver,
        &["-no_fixup_chains"],
    )
    .unwrap();

    for output in [&our_out, &apple_out] {
        let bytes = fs::read(output).unwrap();
        let (data_addr, data) = output_section(&bytes, "__DATA", "__data").unwrap();
        let (got_addr, _) = output_section(&bytes, "__DATA_CONST", "__got").unwrap();
        let delta_addr = symbol_values(&bytes)["_delta"];
        let delta_offset = usize::try_from(delta_addr - data_addr).unwrap();
        let actual = i32::from_le_bytes(data[delta_offset..delta_offset + 4].try_into().unwrap());
        let expected = i32::try_from(i128::from(got_addr) - i128::from(delta_addr)).unwrap();
        assert_eq!(actual, expected);

        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "codesign verify failed for {}: {}",
            output.display(),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(Command::new(output).status().unwrap().code(), Some(0));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn synthetic_import_surfaces_match_apple_ld_classic_lazy_model() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("assembly fixture", assemble(src, &obj));

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

    compare_sections(
        &our_bytes,
        &apple_bytes,
        &[
            ("__TEXT".to_string(), "__stubs".to_string()),
            ("__TEXT".to_string(), "__stub_helper".to_string()),
        ],
        &[],
    )
    .unwrap();

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
        harness_skip!("xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
        harness_skip!("xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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

    require_fixture!(
        "dylib fixture compilation",
        compile_dylib_c(dylib_src, &dylib)
    );

    let main_src = r#"
        extern int ext_data;
        int *p = &ext_data;
        int main(void) { return *p == 5 ? 0 : 1; }
    "#;
    require_fixture!("C fixture compilation", compile_c(main_src, &obj));

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
        harness_skip!("xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
        DirectBindParityCase {
            name: "direct-addend",
            dylib_src: r#"
                char ext_data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            "#,
            main_src: r#"
                extern char ext_data[];
                char *p = ext_data + 4;
                int main(void) { return p == &ext_data[4] ? 0 : 1; }
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
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("C fixture compilation", compile_c(src, &obj));

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
fn linker_run_relaxes_local_got_loads_like_apple_ld() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("local-got.o");
    let our_out = scratch("local-got-ours.out");
    let apple_out = scratch("local-got-apple.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x8, _value@GOTPAGE
            ldr x8, [x8, _value@GOTPAGEOFF]
            ldr w0, [x8]
            ret

        .section __DATA,__data
        .globl _value
        .p2align 2
        _value:
            .long 7
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let our_binds = decode_bind_records(&our_bytes, false).unwrap();
    let apple_binds = decode_bind_records(&apple_bytes, false).unwrap();
    assert_eq!(our_binds, apple_binds);
    assert!(
        our_binds.iter().all(|record| record.symbol != "_value"),
        "local GOT target should not be emitted as a dylib bind: {our_binds:#?}"
    );
    assert!(output_section(&our_bytes, "__DATA_CONST", "__got").is_none());
    assert!(output_section(&apple_bytes, "__DATA_CONST", "__got").is_none());
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
        Some(7),
        "expected local GOT executable to exit 7"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_dead_strip_prunes_synthetic_import_sections() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("dead-strip-import.o");
    let our_out = scratch("dead-strip-import-ours.out");
    let apple_out = scratch("dead-strip-import-apple.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .globl _unused
        _unused:
            bl _puts
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(our_out.clone()),
        dead_strip: true,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_with_args(
        &obj,
        &apple_out,
        "_main",
        &sdk,
        &sdk_ver,
        &["-dead_strip", "-no_fixup_chains"],
    )
    .unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    for (segname, sectname) in [
        ("__TEXT", "__stubs"),
        ("__TEXT", "__stub_helper"),
        ("__DATA", "__la_symbol_ptr"),
        ("__DATA_CONST", "__got"),
    ] {
        assert!(
            output_section(&our_bytes, segname, sectname).is_none(),
            "unexpected synthetic section {segname},{sectname} in our output"
        );
        assert!(
            output_section(&apple_bytes, segname, sectname).is_none(),
            "unexpected synthetic section {segname},{sectname} in apple output"
        );
    }
    assert!(decode_bind_records(&our_bytes, false).unwrap().is_empty());
    assert_eq!(
        decode_bind_records(&our_bytes, false).unwrap(),
        decode_bind_records(&apple_bytes, false).unwrap()
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
    assert_eq!(status.code(), Some(0));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_dead_strip_keeps_and_runs_initializers() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("dead-strip-initializers.o");
    let our_out = scratch("dead-strip-initializers-ours.out");
    let apple_out = scratch("dead-strip-initializers-apple.out");
    let src = r#"
        .data
        .p2align 2
        Lstate:
            .long 0

        .text
        .private_extern _ctor
        _ctor:
            adrp x8, Lstate@PAGE
            add x8, x8, Lstate@PAGEOFF
            mov w9, #1
            str w9, [x8]
            ret

        .globl _main
        _main:
            adrp x8, Lstate@PAGE
            add x8, x8, Lstate@PAGEOFF
            ldr w0, [x8]
            ret

        .section __DATA,__mod_init_func,mod_init_funcs
        .p2align 3
            .quad _ctor
        .subsections_via_symbols
    "#;
    assemble(src, &obj).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        dead_strip: true,
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_with_args(
        &obj,
        &apple_out,
        "_main",
        &sdk,
        &sdk_ver,
        &["-dead_strip", "-no_fixup_chains"],
    )
    .unwrap();

    for output in [&our_out, &apple_out] {
        let bytes = fs::read(output).unwrap();
        assert!([
            ("__DATA", "__mod_init_func"),
            ("__DATA_CONST", "__mod_init_func"),
        ]
        .into_iter()
        .any(|(segment, section)| output_section(&bytes, segment, section).is_some()));
        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "codesign verify failed for {}: {}",
            output.display(),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(Command::new(output).status().unwrap().code(), Some(1));
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_preserves_initialized_same_name_section_data() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let zerofill_obj = scratch("same-name-zerofill.o");
    let regular_obj = scratch("same-name-regular.o");
    let main_obj = scratch("same-name-main.o");
    let output = scratch("same-name-sections.out");
    assemble(
        r#"
        .globl _z
        .zerofill __DATA,__foo,_z,8,3
        "#,
        &zerofill_obj,
    )
    .unwrap();
    assemble(
        r#"
        .section __DATA,__foo,regular
        .p2align 3
        .globl _x
        _x:
            .quad 42
        "#,
        &regular_obj,
    )
    .unwrap();
    assemble(
        r#"
        .text
        .globl _main
        _main:
            adrp x8, _x@PAGE
            ldr x0, [x8, _x@PAGEOFF]
            ret
        .subsections_via_symbols
        "#,
        &main_obj,
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![
            zerofill_obj.clone(),
            regular_obj.clone(),
            main_obj.clone(),
            tbd,
        ],
        output: Some(output.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut matching = Vec::new();
    for command in &commands {
        let LoadCommand::Segment64(segment) = command else {
            continue;
        };
        matching.extend(segment.sections.iter().filter(|section| {
            section.segname_str() == "__DATA" && section.sectname_str() == "__foo"
        }));
    }
    assert_eq!(matching.len(), 2);
    assert!(matching
        .iter()
        .any(|section| section.flags & SECTION_TYPE_MASK == S_ZEROFILL));
    let regular = matching
        .iter()
        .find(|section| section.flags & SECTION_TYPE_MASK == S_REGULAR)
        .unwrap();
    let regular_start = usize::try_from(regular.offset).unwrap();
    let regular_end = regular_start + usize::try_from(regular.size).unwrap();
    assert_eq!(&bytes[regular_start..regular_end], &42u64.to_le_bytes());

    let verify = Command::new("codesign")
        .arg("-v")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(Command::new(&output).status().unwrap().code(), Some(42));

    let _ = fs::remove_file(zerofill_obj);
    let _ = fs::remove_file(regular_obj);
    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_relaxes_hidden_got_loads_like_apple_ld() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("hidden-got.o");
    let our_out = scratch("hidden-got-ours.out");
    let apple_out = scratch("hidden-got-apple.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x8, _value@GOTPAGE
            ldr x8, [x8, _value@GOTPAGEOFF]
            ldr w0, [x8]
            ret

        .private_extern _value
        .section __DATA,__data
        .p2align 2
        _value:
            .long 7
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (our_text_addr, our_text) = output_section(&our_bytes, "__TEXT", "__text").unwrap();
    let (apple_text_addr, apple_text) = output_section(&apple_bytes, "__TEXT", "__text").unwrap();
    assert_eq!(
        decode_page_reference(&our_text, our_text_addr, 0, &PageRefKind::Add).unwrap(),
        decode_page_reference(&apple_text, apple_text_addr, 0, &PageRefKind::Add).unwrap()
    );
    assert_eq!(our_text.len(), apple_text.len());
    assert_eq!(
        read_insn(&our_text, 0).unwrap() & 0x9f00_001f,
        read_insn(&apple_text, 0).unwrap() & 0x9f00_001f
    );
    assert_eq!(&our_text[4..], &apple_text[4..]);
    assert!(output_section(&our_bytes, "__DATA_CONST", "__got").is_none());
    assert!(output_section(&apple_bytes, "__DATA_CONST", "__got").is_none());

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
        Some(7),
        "expected hidden GOT executable to exit 7"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_partitions_symtab_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }

    let dylib = scratch("symtab-partition.dylib");
    let obj = scratch("symtab-partition.o");
    let our_out = scratch("symtab-partition-ours.out");
    let apple_out = scratch("symtab-partition-apple.out");

    let dylib_src = r#"
        int ext_data = 5;
    "#;
    require_fixture!(
        "dylib fixture compilation",
        compile_dylib_c(dylib_src, &dylib)
    );

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
    require_fixture!("assembly fixture", assemble(asm, &obj));

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
        harness_skip!("xcrun unavailable");
        return;
    }

    let dylib = scratch("symtab-strip.dylib");
    let obj = scratch("symtab-strip.o");
    let our_out = scratch("symtab-strip-ours.out");
    let apple_out = scratch("symtab-strip-apple.out");

    let dylib_src = r#"
        int ext_data = 5;
    "#;
    require_fixture!(
        "dylib fixture compilation",
        compile_dylib_c(dylib_src, &dylib)
    );

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
    require_fixture!("assembly fixture", assemble(asm, &obj));

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
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
    require_fixture!("C fixture compilation", compile_c(src, &obj));

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
        rebased_unwind_bytes(&our_bytes),
        rebased_unwind_bytes(&apple_bytes)
    );
    assert!(output_section(&our_bytes, "__LD", "__compact_unwind").is_none());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_resolves_compact_unwind_function_aliases() {
    let obj = scratch("compact-unwind-alias.o");
    let out = scratch("compact-unwind-alias.out");
    let direct_fixture =
        synthetic_compact_unwind_alias_object(Some(SyntheticUnwindReferent::Direct));
    let alias_fixture =
        synthetic_compact_unwind_alias_object(Some(SyntheticUnwindReferent::IndirectAlias));

    let parsed = ObjectFile::parse(&obj, &alias_fixture).unwrap();
    let compact = parsed
        .sections
        .iter()
        .find(|section| section.sectname == "__compact_unwind")
        .expect("alias fixture must contain compact unwind data");
    let relocs =
        parse_relocs(&parse_raw_relocs(&compact.raw_relocs, 0, compact.nreloc).unwrap()).unwrap();
    assert_eq!(relocs.len(), 1);
    assert_eq!(relocs[0].referent, Referent::Symbol(1));
    assert_eq!(parsed.symbol_name(&parsed.symbols[1]).unwrap(), "_alias");
    assert_eq!(parsed.symbols[1].kind(), SymKind::Indirect);

    let link = |fixture: &[u8], jobs| {
        fs::write(&obj, fixture).unwrap();
        Linker::run(&LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        fs::read(&out).unwrap()
    };

    let direct_outputs = [link(&direct_fixture, 1), link(&direct_fixture, 4)];
    assert_eq!(direct_outputs[0], direct_outputs[1]);
    let direct_unwind = canonical_unwind_info(&direct_outputs[0]);
    assert_eq!(direct_unwind.records.len(), 1);
    assert_eq!(direct_unwind.records[0].function_offset, 0);
    assert_eq!(direct_unwind.records[0].encoding, 0x0200_0000);

    let alias_outputs = [link(&alias_fixture, 1), link(&alias_fixture, 4)];
    assert_eq!(alias_outputs[0], alias_outputs[1]);
    assert_eq!(alias_outputs[0], direct_outputs[0]);
    assert_eq!(canonical_unwind_info(&alias_outputs[0]), direct_unwind);

    let no_unwind = link(&synthetic_compact_unwind_alias_object(None), 4);
    assert!(output_section(&no_unwind, "__TEXT", "__unwind_info").is_none());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_dwarf_unwind_encoding_points_to_final_fde() {
    const DWARF_MODE: u32 = 0x0300_0000;
    const DWARF_OFFSET_MASK: u32 = 0x00ff_ffff;

    let obj = scratch("dwarf-unwind-offset.o");
    let out = scratch("dwarf-unwind-offset.out");
    let fixture = synthetic_dwarf_unwind_object();
    let parsed = ObjectFile::parse(&obj, &fixture).unwrap();
    let compact = parsed
        .sections
        .iter()
        .find(|section| section.sectname == "__compact_unwind")
        .expect("fixture must contain compact unwind input");
    assert_eq!(u32_le(&compact.data[12..16]), DWARF_MODE);
    let input_eh_frame = parsed
        .sections
        .iter()
        .find(|section| section.sectname == "__eh_frame")
        .expect("fixture must contain an FDE");
    assert_eq!(eh_frame_fde_offsets(&input_eh_frame.data), vec![0x14]);

    let link = |jobs| {
        fs::write(&obj, &fixture).unwrap();
        Linker::run(&LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        fs::read(&out).unwrap()
    };
    let outputs = [link(1), link(4)];
    assert_eq!(outputs[0], outputs[1]);
    assert!(output_section(&outputs[0], "__LD", "__compact_unwind").is_none());

    let decoded = canonical_unwind_info(&outputs[0]);
    assert_eq!(decoded.records.len(), 1);
    assert_eq!(decoded.records[0].function_offset, 0);
    let (_, eh_frame) = output_section(&outputs[0], "__TEXT", "__eh_frame").unwrap();
    let fde_offsets = eh_frame_fde_offsets(&eh_frame);
    assert_eq!(fde_offsets, vec![0x14]);
    assert_eq!(decoded.records[0].encoding & 0x0f00_0000, DWARF_MODE);
    assert_eq!(
        decoded.records[0].encoding & DWARF_OFFSET_MASK,
        fde_offsets[0]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_dwarf_unwind_distinguishes_local_functions_inside_one_atom() {
    const DWARF_MODE: u32 = 0x0300_0000;
    const DWARF_OFFSET_MASK: u32 = 0x00ff_ffff;

    let obj = scratch("nested-local-dwarf-unwind.o");
    let out = scratch("nested-local-dwarf-unwind.out");
    let fixture = synthetic_nested_local_dwarf_unwind_object();
    let link = |jobs| {
        fs::write(&obj, &fixture).unwrap();
        Linker::run(&LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        fs::read(&out).unwrap()
    };

    let outputs = [link(1), link(4)];
    assert_eq!(outputs[0], outputs[1]);
    let decoded = canonical_unwind_info(&outputs[0]);
    assert_eq!(
        decoded
            .records
            .iter()
            .map(|record| record.function_offset)
            .collect::<Vec<_>>(),
        vec![8, 16]
    );
    let (_, eh_frame) = output_section(&outputs[0], "__TEXT", "__eh_frame").unwrap();
    let fde_offsets = eh_frame_fde_offsets(&eh_frame);
    assert_eq!(fde_offsets, vec![0x14, 0x30]);
    for (record, fde_offset) in decoded.records.iter().zip(fde_offsets) {
        assert_eq!(record.encoding & 0x0f00_0000, DWARF_MODE);
        assert_eq!(record.encoding & DWARF_OFFSET_MASK, fde_offset);
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_dead_strip_preserves_fde_for_symbol_plus_addend() {
    let obj = scratch("dwarf-unwind-symbol-addend.o");
    let out = scratch("dwarf-unwind-symbol-addend.out");
    fs::write(&obj, synthetic_dwarf_unwind_fde_addend_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        dead_strip: true,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&out).unwrap();
    let symbols = canonical_symbol_record_map(&bytes);
    assert!(!symbols.contains_key("_dead_base"));
    assert!(symbols.contains_key("_main"));
    assert_eq!(
        eh_frame_fde_offsets(&output_section(&bytes, "__TEXT", "__eh_frame").unwrap().1),
        vec![0x14]
    );
    assert_eq!(canonical_unwind_info(&bytes).records.len(), 1);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_rejects_dwarf_unwind_without_fde_and_preserves_output() {
    const DWARF_MODE: u32 = 0x0300_0000;
    const SENTINEL: &[u8] = b"AFSLD-056 existing output";

    let obj = scratch("dwarf-unwind-missing-fde.o");
    let out = scratch("dwarf-unwind-missing-fde.out");
    let mut fixture = synthetic_compact_unwind_alias_object(Some(SyntheticUnwindReferent::Direct));
    let compact = output_section_header(&fixture, "__LD", "__compact_unwind")
        .expect("fixture must contain compact unwind input");
    let encoding_offset = compact.offset as usize + 12;
    fixture[encoding_offset..encoding_offset + 4].copy_from_slice(&DWARF_MODE.to_le_bytes());
    fs::write(&obj, fixture).unwrap();

    let mut diagnostics = Vec::new();
    for jobs in [1, 4] {
        fs::write(&out, SENTINEL).unwrap();
        let error = Linker::run(&LinkOptions {
            inputs: vec![obj.clone()],
            output: Some(out.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .expect_err("DWARF-mode compact unwind without an FDE must be rejected");
        diagnostics.push(error.to_string());
        assert_eq!(fs::read(&out).unwrap(), SENTINEL);
    }
    assert_eq!(diagnostics[0], diagnostics[1]);
    assert!(
        diagnostics[0].contains("has no retained __eh_frame FDE"),
        "unexpected diagnostic: {}",
        diagnostics[0]
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_multi_function_unwind_info_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
    require_fixture!("C fixture compilation", compile_c(src, &obj));

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
        rebased_unwind_bytes(&our_bytes),
        rebased_unwind_bytes(&apple_bytes)
    );
    assert!(output_section(&our_bytes, "__LD", "__compact_unwind").is_none());

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_dead_strip_prunes_unused_unwind_records_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("unwind-dead-strip.o");
    let our_out = scratch("unwind-dead-strip-ours.out");
    let apple_out = scratch("unwind-dead-strip-apple.out");
    let src = r#"
        int helper(void) {
            return 1;
        }

        int unused(void) {
            return 2;
        }

        int main(void) {
            return helper();
        }
    "#;
    require_fixture!("C fixture compilation", compile_c(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        dead_strip: true,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_with_args(&obj, &apple_out, "_main", &sdk, &sdk_ver, &["-dead_strip"]).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let (_, our_unwind) = output_section(&our_bytes, "__TEXT", "__unwind_info").unwrap();
    let (_, apple_unwind) = output_section(&apple_bytes, "__TEXT", "__unwind_info").unwrap();
    let our_decoded = decode_unwind_info(&our_unwind).unwrap();
    let apple_decoded = decode_unwind_info(&apple_unwind).unwrap();
    let normalize = |records: &[afs_ld::synth::unwind::DecodedUnwindRecord]| {
        let base = records
            .first()
            .map(|record| record.function_offset)
            .unwrap_or(0);
        records
            .iter()
            .map(|record| (record.function_offset - base, record.encoding))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        normalize(&our_decoded.records),
        normalize(&apple_decoded.records)
    );
    assert_eq!(our_decoded.records.len(), 2);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_handles_large_unwind_function_gaps() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }

    let obj = scratch("unwind-gap.o");
    let out = scratch("unwind-gap-ours.out");
    let asm = r#"
        .text
        .globl _main
        .p2align 2
    _main:
        .cfi_startproc
        bl _helper
        ret
        .cfi_endproc
        .space 0x1000010
        .globl _helper
        .p2align 2
    _helper:
        .cfi_startproc
        ret
        .cfi_endproc
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(asm, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (_, unwind) = output_section(&bytes, "__TEXT", "__unwind_info").unwrap();
    let decoded = decode_unwind_info(&unwind).unwrap();
    assert!(
        decoded
            .records
            .windows(2)
            .all(|pair| pair[0].function_offset < pair[1].function_offset),
        "expected strictly ascending unwind records after large-gap pagination"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_preserves_eh_frame_like_ld() {
    if !have_xcrun() || !have_xcrun_tool("dwarfdump") {
        harness_skip!("xcrun dwarfdump unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
    require_fixture!("assembly fixture", assemble(asm, &obj));

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
fn linker_run_dead_strip_preserves_pruned_eh_frame_like_ld() {
    if !have_xcrun() || !have_xcrun_tool("dwarfdump") {
        harness_skip!("xcrun dwarfdump unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };

    let obj = scratch("eh-frame-dead-strip.o");
    let our_out = scratch("eh-frame-dead-strip-ours.out");
    let apple_out = scratch("eh-frame-dead-strip-apple.out");
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
        sub sp, sp, #16
        .cfi_def_cfa_offset 16
        str x30, [sp, #8]
        .cfi_offset w30, -8
        ldr x30, [sp, #8]
        add sp, sp, #16
        ret
        .cfi_endproc

        .globl _unused
        .p2align 2
    _unused:
        .cfi_startproc
        sub sp, sp, #16
        .cfi_def_cfa_offset 16
        str x30, [sp, #8]
        .cfi_offset w30, -8
        ldr x30, [sp, #8]
        add sp, sp, #16
        ret
        .cfi_endproc
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(asm, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        dead_strip: true,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_with_args(&obj, &apple_out, "_main", &sdk, &sdk_ver, &["-dead_strip"]).unwrap();

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
fn linker_run_emits_backtrace_metadata_like_apple_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("unwind-backtrace.o");
    let our_out = scratch("unwind-backtrace-ours.out");
    let apple_out = scratch("unwind-backtrace-apple.out");
    let src = r#"
        #include <unwind.h>

        static _Unwind_Reason_Code cb(struct _Unwind_Context* ctx, void* arg) {
            (void)ctx;
            int* count = (int*)arg;
            (*count)++;
            return *count >= 8 ? _URC_END_OF_STACK : _URC_NO_REASON;
        }

        __attribute__((noinline)) int helper(void) {
            int count = 0;
            _Unwind_Backtrace(cb, &count);
            return count;
        }

        int main(void) {
            return helper() > 1 ? 0 : 1;
        }
    "#;
    require_fixture!("C fixture compilation", compile_c(src, &obj));

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
    assert_eq!(
        rebased_unwind_bytes(&our_bytes),
        rebased_unwind_bytes(&apple_bytes)
    );
    assert_eq!(
        normalize_function_start_offsets(&decode_function_starts(&our_bytes)),
        normalize_function_start_offsets(&decode_function_starts(&apple_bytes))
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_preserves_exception_unwind_metadata_like_apple_ld() {
    if !have_xcrun() || !have_xcrun_tool("clang++") || !have_tool("codesign") {
        harness_skip!("xcrun clang++ or codesign unavailable");
        return;
    }

    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let libsystem = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    let libcxx = PathBuf::from(format!("{sdk}/usr/lib/libc++.tbd"));
    if !libsystem.exists() {
        harness_skip!("no libSystem.tbd at {}", libsystem.display());
        return;
    }
    if !libcxx.exists() {
        harness_skip!("no libc++.tbd at {}", libcxx.display());
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
    require_fixture!("C++ fixture compilation", compile_cxx(src, &obj));

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
    let our_status = Command::new(&our_out).status().unwrap();
    let apple_status = Command::new(&apple_out).status().unwrap();
    assert_eq!(our_status.code(), Some(42));
    assert_eq!(apple_status.code(), Some(42));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_resolves_backtrace_symbols_at_runtime() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("execinfo-backtrace.o");
    let our_out = scratch("execinfo-backtrace-ours.out");
    let apple_out = scratch("execinfo-backtrace-apple.out");
    let src = r#"
        #include <execinfo.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        __attribute__((noinline)) int helper(void) {
            void *frames[8];
            int n = backtrace(frames, 8);
            char **syms = backtrace_symbols(frames, n);
            int saw_helper = 0;
            int saw_main = 0;
            if (!syms) return 2;
            for (int i = 0; i < n; i++) {
                puts(syms[i]);
                saw_helper |= strstr(syms[i], "helper") != NULL;
                saw_main |= strstr(syms[i], "main") != NULL;
            }
            free(syms);
            return (saw_helper && saw_main) ? 0 : 1;
        }

        int main(void) {
            return helper();
        }
    "#;
    require_fixture!("C fixture compilation", compile_c(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();
    apple_link_classic_lazy(&obj, &apple_out, "_main", &sdk, &sdk_ver).unwrap();

    let our_output = Command::new(&our_out).output().unwrap();
    let apple_output = Command::new(&apple_out).output().unwrap();
    let our_stdout = String::from_utf8_lossy(&our_output.stdout);
    let apple_stdout = String::from_utf8_lossy(&apple_output.stdout);

    assert_eq!(our_output.status.code(), Some(0));
    assert_eq!(apple_output.status.code(), Some(0));
    assert!(
        our_stdout.contains("helper"),
        "expected helper in output: {our_stdout}"
    );
    assert!(
        our_stdout.contains("main"),
        "expected main in output: {our_stdout}"
    );
    assert!(
        apple_stdout.contains("helper"),
        "expected helper in apple output: {apple_stdout}"
    );
    assert!(
        apple_stdout.contains("main"),
        "expected main in apple output: {apple_stdout}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_emits_function_starts_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("assembly fixture", assemble(asm, &obj));

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
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
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
    require_fixture!("assembly fixture", assemble(asm, &obj));

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
fn linker_run_preserves_and_rebases_data_in_code_records_deterministically() {
    let prefix = scratch("AFSLD-058-data-in-code-prefix.o");
    let marked = scratch("AFSLD-058-data-in-code-marked.o");
    let output = scratch("AFSLD-058-data-in-code.out");
    fs::write(&prefix, synthetic_aligned_subsections_object()).unwrap();
    fs::write(
        &marked,
        synthetic_data_in_code_object("_main", "__text", 0, DICE_KIND_JUMP_TABLE32, false),
    )
    .unwrap();

    let mut outputs = Vec::new();
    for jobs in [1, 4] {
        Linker::run(&LinkOptions {
            inputs: vec![prefix.clone(), marked.clone()],
            output: Some(output.clone()),
            kind: OutputKind::Executable,
            jobs: Some(jobs),
            ..LinkOptions::default()
        })
        .unwrap();
        outputs.push(fs::read(&output).unwrap());
    }

    let [serial, parallel] = outputs.as_slice() else {
        unreachable!()
    };
    assert_eq!(serial, parallel, "-j1 and -j4 output differs");
    let image_base = segment_vmaddr(serial, "__TEXT").unwrap();
    let main_offset = u32::try_from(symbol_values(serial)["_main"] - image_base).unwrap();
    assert_eq!(
        decode_data_in_code(serial),
        vec![DataInCodeRecord {
            offset: main_offset + 4,
            length: 4,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(prefix);
    let _ = fs::remove_file(marked);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_sorts_rebased_data_in_code_across_output_sections() {
    let later = scratch("AFSLD-058-data-in-code-later.o");
    let main = scratch("AFSLD-058-data-in-code-main.o");
    let output = scratch("AFSLD-058-data-in-code-sections.out");
    fs::write(
        &later,
        synthetic_data_in_code_object("_helper", "__text2", 0x80, DICE_KIND_DATA, false),
    )
    .unwrap();
    fs::write(
        &main,
        synthetic_data_in_code_object("_main", "__text", 0, DICE_KIND_JUMP_TABLE32, false),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        // Input order intentionally disagrees with final section order.
        inputs: vec![later.clone(), main.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let image_base = segment_vmaddr(&bytes, "__TEXT").unwrap();
    let symbols = symbol_values(&bytes);
    let main_offset = u32::try_from(symbols["_main"] - image_base).unwrap() + 4;
    let helper_offset = u32::try_from(symbols["_helper"] - image_base).unwrap() + 4;
    assert!(main_offset < helper_offset);
    assert_eq!(
        decode_data_in_code(&bytes),
        vec![
            DataInCodeRecord {
                offset: main_offset,
                length: 4,
                kind: DICE_KIND_JUMP_TABLE32,
            },
            DataInCodeRecord {
                offset: helper_offset,
                length: 4,
                kind: DICE_KIND_DATA,
            },
        ]
    );

    let _ = fs::remove_file(later);
    let _ = fs::remove_file(main);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_omits_data_in_code_for_dead_stripped_atoms() {
    let main = scratch("AFSLD-058-data-in-code-live.o");
    let unused = scratch("AFSLD-058-data-in-code-dead.o");
    let output = scratch("AFSLD-058-data-in-code-dead-strip.out");
    fs::write(
        &main,
        synthetic_data_in_code_object("_main", "__text", 0, DICE_KIND_JUMP_TABLE32, false),
    )
    .unwrap();
    fs::write(
        &unused,
        synthetic_data_in_code_object("_unused", "__text", 0, DICE_KIND_DATA, false),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![main.clone(), unused.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Executable,
        dead_strip: true,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let image_base = segment_vmaddr(&bytes, "__TEXT").unwrap();
    let symbols = symbol_values(&bytes);
    assert!(!symbols.contains_key("_unused"));
    assert_eq!(
        decode_data_in_code(&bytes),
        vec![DataInCodeRecord {
            offset: u32::try_from(symbols["_main"] - image_base).unwrap() + 4,
            length: 4,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(main);
    let _ = fs::remove_file(unused);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_emits_data_in_code_for_one_surviving_icf_atom() {
    let first = scratch("AFSLD-058-data-in-code-icf-first.o");
    let second = scratch("AFSLD-058-data-in-code-icf-second.o");
    let output = scratch("AFSLD-058-data-in-code-icf.dylib");
    fs::write(
        &first,
        synthetic_data_in_code_object("_first", "__text", 0, DICE_KIND_JUMP_TABLE32, true),
    )
    .unwrap();
    fs::write(
        &second,
        synthetic_data_in_code_object("_second", "__text", 0, DICE_KIND_JUMP_TABLE32, true),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![first.clone(), second.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        icf_mode: IcfMode::Safe,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let image_base = segment_vmaddr(&bytes, "__TEXT").unwrap();
    let symbols = symbol_values(&bytes);
    assert_eq!(symbols["_first"], symbols["_second"]);
    assert_eq!(
        decode_data_in_code(&bytes),
        vec![DataInCodeRecord {
            offset: u32::try_from(symbols["_first"] - image_base).unwrap() + 4,
            length: 4,
            kind: DICE_KIND_JUMP_TABLE32,
        }]
    );

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_dedups_output_strtab_like_ld() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("assembly fixture", assemble(&asm, &obj));

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
        harness_skip!("xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let dylib = scratch("lazy-runtime.dylib");
    let obj = scratch("lazy-runtime.o");
    let out = scratch("lazy-runtime.out");

    let dylib_src = r#"
        int ext_fn(void) { return 7; }
    "#;
    require_fixture!(
        "dylib fixture compilation",
        compile_dylib_c(dylib_src, &dylib)
    );

    let main_src = r#"
        int ext_fn(void);
        int main(void) { return ext_fn() == 7 ? 0 : 1; }
    "#;
    require_fixture!("C fixture compilation", compile_c(main_src, &obj));

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
        harness_skip!("xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!("C fixture compilation", compile_c(src, &obj));

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
fn linker_run_routes_imported_tlv_through_thread_pointers() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun clang or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
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
    require_fixture!(
        "dylib fixture compilation",
        compile_dylib_c(dylib_src, &dylib)
    );

    let main_src = r#"
        extern __thread long ext_tls;
        int main(void) { return ext_tls == 5 ? 0 : 1; }
    "#;
    require_fixture!("C fixture compilation", compile_c(main_src, &obj));

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
    let (our_thread_ptrs_addr, our_thread_ptrs) =
        output_section(&our_bytes, "__DATA", "__thread_ptrs").unwrap();
    let (apple_thread_ptrs_addr, apple_thread_ptrs) =
        output_section(&apple_bytes, "__DATA", "__thread_ptrs").unwrap();

    assert!(output_section(&our_bytes, "__DATA_CONST", "__got").is_none());
    assert!(output_section(&apple_bytes, "__DATA_CONST", "__got").is_none());
    assert_eq!(our_thread_ptrs.len(), 8);
    assert_eq!(our_thread_ptrs, apple_thread_ptrs);
    assert_eq!(
        decode_page_reference(&our_text, our_text_addr, 20, &PageRefKind::Load).unwrap(),
        our_thread_ptrs_addr
    );
    assert_eq!(
        decode_page_reference(&apple_text, apple_text_addr, 20, &PageRefKind::Load).unwrap(),
        apple_thread_ptrs_addr
    );
    assert_eq!(our_text.len(), apple_text.len());
    assert_eq!(
        read_insn(&our_text, 20).unwrap() & 0x9f00_001f,
        read_insn(&apple_text, 20).unwrap() & 0x9f00_001f
    );
    assert_eq!(&our_text[..20], &apple_text[..20]);
    assert_eq!(&our_text[24..], &apple_text[24..]);
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

#[test]
fn linker_run_preserves_runtime_tlv_descriptor_offsets() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(runtime) = workspace_artifact("libarmfortas_rt.a") else {
        harness_skip!("libarmfortas_rt.a not built");
        return;
    };
    let Some(sdk) = sdk_path() else {
        harness_skip!("no macOS SDK path");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("no macOS SDK version");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("runtime-hello.o");
    let out = scratch("runtime-hello.out");
    let apple_out = scratch("runtime-hello-apple.out");
    let src = r#"
        extern void afs_program_init(void);
        extern void afs_program_finalize(void);
        extern void afs_write_string(int, const char *, long);
        extern void afs_write_newline(int);

        int main(void) {
            afs_program_init();
            afs_write_string(6, "Hello, World!", 13);
            afs_write_newline(6);
            afs_program_finalize();
            return 0;
        }
    "#;
    require_fixture!("C fixture compilation", compile_c(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), runtime.clone(), tbd],
        output: Some(out.clone()),
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
            "-e",
            "_main",
            "-no_fixup_chains",
            "-o",
        ])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&runtime)
        .arg("-lSystem")
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
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

    let bytes = fs::read(&out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    assert!(
        output_section(&bytes, "__DATA_CONST", "__const").is_some(),
        "runtime hello should promote file-backed __const data into __DATA_CONST"
    );
    assert!(
        output_section(&bytes, "__DATA", "__const").is_none(),
        "runtime hello should not leave file-backed __const data in __DATA"
    );
    let (thread_vars_addr, thread_vars) =
        output_section(&bytes, "__DATA", "__thread_vars").unwrap();
    let (thread_data_addr, _) = output_section(&bytes, "__DATA", "__thread_data").unwrap();
    let symbols = symbol_values(&bytes);
    let tlv_binds: Vec<_> = decode_bind_records(&bytes, false)
        .unwrap()
        .into_iter()
        .filter(|record| record.section == "__thread_vars")
        .collect();
    assert_eq!(
        tlv_binds.len(),
        thread_vars.len() / 24,
        "every TLV descriptor should carry exactly one bootstrap bind"
    );
    assert!(tlv_binds
        .iter()
        .all(|record| record.symbol == "__tlv_bootstrap"));

    assert_eq!(
        decode_bind_records(&bytes, false).unwrap(),
        decode_bind_records(&apple_bytes, false).unwrap(),
        "runtime hello bind records diverged from Apple ld"
    );
    assert_eq!(
        decode_bind_records(&bytes, true).unwrap(),
        decode_bind_records(&apple_bytes, true).unwrap(),
        "runtime hello lazy-bind records diverged from Apple ld"
    );
    assert_eq!(
        decode_input_rebase_records(&bytes).unwrap(),
        decode_input_rebase_records(&apple_bytes).unwrap(),
        "runtime hello input rebase records diverged from Apple ld"
    );
    assert_eq!(
        indirect_symbol_identities(&bytes),
        indirect_symbol_identities(&apple_bytes),
        "runtime hello indirect symbol identities diverged from Apple ld"
    );

    for (name, descriptor_addr) in symbols.iter().filter(|(name, value)| {
        !name.ends_with("$tlv$init")
            && **value >= thread_vars_addr
            && **value < thread_vars_addr + thread_vars.len() as u64
    }) {
        let init_name = format!("{name}$tlv$init");
        let Some(init_addr) = symbols.get(&init_name) else {
            continue;
        };
        let offset = (*descriptor_addr - thread_vars_addr) as usize;
        let actual = u64::from_le_bytes(thread_vars[offset + 16..offset + 24].try_into().unwrap());
        let expected = init_addr - thread_data_addr;
        assert_eq!(
            actual, expected,
            "TLV descriptor {} should point at {} via template offset",
            name, init_name
        );
    }

    let output = Command::new(&out).output().unwrap();
    let apple_output = Command::new(&apple_out).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected runtime hello executable to exit 0, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        apple_output.status.code(),
        Some(0),
        "expected Apple-linked runtime hello executable to exit 0, stderr={}",
        String::from_utf8_lossy(&apple_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&apple_output.stdout)
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(apple_out);
}

#[test]
fn linker_run_rebases_runtime_init_metadata_like_apple_ld() {
    if !have_xcrun() || !have_tool("codesign") {
        harness_skip!("xcrun or codesign unavailable");
        return;
    }
    let Some(runtime) = workspace_artifact("libarmfortas_rt.a") else {
        harness_skip!("libarmfortas_rt.a not built");
        return;
    };
    let Some(sdk) = sdk_path() else {
        harness_skip!("no macOS SDK path");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("no macOS SDK version");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("runtime-init-only.o");
    let our_out = scratch("runtime-init-only-ours.out");
    let apple_out = scratch("runtime-init-only-apple.out");
    let src = r#"
        extern void afs_program_init(void);

        int main(void) {
            afs_program_init();
            return 0;
        }
    "#;
    require_fixture!("C fixture compilation", compile_c(src, &obj));

    let opts = LinkOptions {
        inputs: vec![obj.clone(), runtime.clone(), tbd],
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
            "-e",
            "_main",
            "-no_fixup_chains",
            "-o",
        ])
        .arg(&apple_out)
        .arg(&obj)
        .arg(&runtime)
        .arg("-lSystem")
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_bytes = fs::read(&our_out).unwrap();
    let apple_bytes = fs::read(&apple_out).unwrap();
    let our_rebases = decode_rebase_records(&our_bytes).unwrap();
    let apple_rebases = decode_rebase_records(&apple_bytes).unwrap();
    assert_eq!(
        our_rebases
            .iter()
            .filter(|record| record.section == "__const")
            .count(),
        apple_rebases
            .iter()
            .filter(|record| record.section == "__const")
            .count(),
        "runtime init const rebases diverged from Apple ld"
    );
    assert_eq!(
        our_rebases
            .iter()
            .filter(|record| record.section == "__la_symbol_ptr")
            .count(),
        apple_rebases
            .iter()
            .filter(|record| record.section == "__la_symbol_ptr")
            .count(),
        "runtime init lazy-pointer rebases diverged from Apple ld"
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
fn synthetic_icf_fixture_uses_section_relocation() {
    let bytes = synthetic_icf_section_reference_object("_f", 1);
    let object = ObjectFile::parse("icf-section.o", &bytes).unwrap();
    let text = &object.sections[0];
    let raw = parse_raw_relocs(&text.raw_relocs, 0, text.nreloc).unwrap();
    let relocs = parse_relocs(&raw).unwrap();

    assert_eq!(relocs.len(), 2);
    assert!(relocs.iter().any(|reloc| {
        reloc.offset == 0
            && reloc.kind == RelocKind::Page21
            && reloc.referent == Referent::Section(2)
    }));
    assert!(relocs.iter().any(|reloc| {
        reloc.offset == 4
            && reloc.kind == RelocKind::PageOff12
            && reloc.referent == Referent::Section(2)
    }));
}

#[test]
fn linker_run_icf_safe_preserves_const_output_protection_domains() {
    let object = scratch("icf-protection-domains.o");
    let output = scratch("icf-protection-domains.dylib");
    fs::write(
        &object,
        synthetic_icf_const_domains_object("__TEXT", "__DATA"),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        output_section(&bytes, "__TEXT", "__const")
            .expect("safe ICF erased __TEXT,__const")
            .1
            .len(),
        8
    );
    assert_eq!(
        output_section(&bytes, "__DATA_CONST", "__const")
            .expect("safe ICF erased __DATA_CONST,__const")
            .1
            .len(),
        8
    );
    assert_ne!(
        segment_protections(&bytes, "__TEXT"),
        segment_protections(&bytes, "__DATA_CONST"),
        "fixture must exercise distinct output protection domains"
    );
    let symbols = canonical_symbol_record_map(&bytes);
    assert_ne!(
        symbols["_first_const"].n_sect, symbols["_second_const"].n_sect,
        "safe ICF rebound symbols across output sections"
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_icf_safe_folds_const_sections_mapped_to_same_output_domain() {
    let object = scratch("icf-mapped-domain.o");
    let output = scratch("icf-mapped-domain.dylib");
    fs::write(
        &object,
        synthetic_icf_const_domains_object("__DATA", "__DATA_CONST"),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        output_section(&bytes, "__DATA_CONST", "__const")
            .expect("mapped const output section")
            .1
            .len(),
        8,
        "same-domain constants should still fold"
    );
    let symbols = canonical_symbol_record_map(&bytes);
    assert_eq!(
        symbols["_first_const"].n_sect, symbols["_second_const"].n_sect,
        "same-domain folded symbols should share one output section"
    );
    assert_eq!(
        symbols["_first_const"].value, symbols["_second_const"].value,
        "same-domain folded symbols should share one output address"
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_icf_safe_preserves_cross_object_subtractor_difference() {
    let first = scratch("AFSLD-065-subtractor-first.o");
    let second = scratch("AFSLD-065-subtractor-second.o");
    let difference = scratch("AFSLD-065-subtractor-difference.o");
    let baseline_output = scratch("AFSLD-065-subtractor-baseline.dylib");
    let icf_output = scratch("AFSLD-065-subtractor-icf.dylib");
    fs::write(&first, synthetic_icf_const_object("_first")).unwrap();
    fs::write(&second, synthetic_icf_const_object("_second")).unwrap();
    fs::write(
        &difference,
        synthetic_subtractor_difference_object("_second", "_first"),
    )
    .unwrap();

    let inputs = vec![first.clone(), second.clone(), difference.clone()];
    Linker::run(&LinkOptions {
        inputs: inputs.clone(),
        output: Some(baseline_output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    })
    .unwrap();
    Linker::run(&LinkOptions {
        inputs,
        output: Some(icf_output.clone()),
        kind: OutputKind::Dylib,
        icf_mode: IcfMode::Safe,
        ..LinkOptions::default()
    })
    .unwrap();

    let difference_value = |path: &PathBuf| {
        let bytes = fs::read(path).unwrap();
        let data = output_section(&bytes, "__DATA", "__data")
            .expect("SUBTRACTOR fixture must retain __DATA,__data")
            .1;
        u64::from_le_bytes(data[..8].try_into().unwrap())
    };
    assert_eq!(
        difference_value(&baseline_output),
        8,
        "fixture must materialize the cross-object address difference"
    );
    assert_eq!(
        difference_value(&icf_output),
        8,
        "safe ICF must not collapse either operand of a SUBTRACTOR relocation"
    );
    let icf_symbols = symbol_values(&fs::read(&icf_output).unwrap());
    assert_ne!(
        icf_symbols.get("_first"),
        icf_symbols.get("_second"),
        "safe ICF must preserve distinct addresses observed by SUBTRACTOR"
    );

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
    let _ = fs::remove_file(difference);
    let _ = fs::remove_file(baseline_output);
    let _ = fs::remove_file(icf_output);
}

#[test]
fn linker_run_dead_strip_omits_private_symbols_from_removed_atoms() {
    let object = scratch("AFSLD-066-dead-private.o");
    let output = scratch("AFSLD-066-dead-private.dylib");
    fs::write(
        &object,
        synthetic_single_section_object(
            "__TEXT",
            "__const",
            S_REGULAR,
            &[0x11; 16],
            &[],
            &[
                ("_live", N_SECT | N_EXT, 1, 0, 0),
                ("_dead_private", N_SECT | N_EXT | N_PEXT, 1, 0, 8),
            ],
        ),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        dead_strip: true,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        output_section(&bytes, "__TEXT", "__const")
            .expect("live public atom must retain __TEXT,__const")
            .1
            .len(),
        8,
        "dead stripping must remove the unreferenced private atom"
    );
    let symbols = canonical_symbol_record_map(&bytes);
    assert!(symbols.contains_key("_live"));
    assert!(
        !symbols.contains_key("_dead_private"),
        "a symbol whose atom was dead stripped must not be emitted"
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_icf_safe_preserves_section_relative_literal_pointers() {
    let object = scratch("AFSLD-067-local-literal-pointers.o");
    let baseline_output = scratch("AFSLD-067-local-literal-pointers-baseline.dylib");
    let icf_output = scratch("AFSLD-067-local-literal-pointers-icf.dylib");
    fs::write(&object, synthetic_icf_local_literal_pointer_object()).unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(baseline_output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    })
    .unwrap();
    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(icf_output.clone()),
        kind: OutputKind::Dylib,
        icf_mode: IcfMode::Safe,
        ..LinkOptions::default()
    })
    .unwrap();

    let assert_valid_literal_pointers = |path: &PathBuf| {
        let bytes = fs::read(path).unwrap();
        let (cstring_addr, cstrings) = output_section(&bytes, "__TEXT", "__cstring")
            .expect("literal pointer fixture must retain __TEXT,__cstring");
        let (_, pointers) = output_section(&bytes, "__DATA_CONST", "__const")
            .expect("literal pointer fixture must retain __DATA_CONST,__const");
        assert_eq!(cstrings, b"dup\0dup\0");
        assert_eq!(pointers.len(), 16);
        let first = u64::from_le_bytes(pointers[..8].try_into().unwrap());
        let second = u64::from_le_bytes(pointers[8..16].try_into().unwrap());
        assert_eq!(first, cstring_addr);
        assert_eq!(second, cstring_addr + 4);
        assert!(first < cstring_addr + cstrings.len() as u64);
        assert!(second < cstring_addr + cstrings.len() as u64);
    };
    assert_valid_literal_pointers(&baseline_output);
    assert_valid_literal_pointers(&icf_output);

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(baseline_output);
    let _ = fs::remove_file(icf_output);
}

#[test]
fn linker_run_preserves_local_symbol_identity_on_global_name_collision() {
    let local_object = scratch("AFSLD-068-local-reference.o");
    let global_object = scratch("AFSLD-068-global-target.o");
    let output = scratch("AFSLD-068-local-symbol-collision.dylib");
    fs::write(
        &local_object,
        synthetic_local_symbol_collision_reference_object(),
    )
    .unwrap();
    fs::write(
        &global_object,
        synthetic_single_section_object(
            "__DATA",
            "__global",
            S_REGULAR,
            &0xaaaa_bbbb_cccc_ddddu64.to_le_bytes(),
            &[],
            &[("_same", N_SECT | N_EXT, 1, 0, 0)],
        ),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![local_object.clone(), global_object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let (local_addr, local_data) = output_section(&bytes, "__DATA", "__localref")
        .expect("local collision fixture must retain __DATA,__localref");
    let (global_addr, global_data) = output_section(&bytes, "__DATA", "__global")
        .expect("local collision fixture must retain __DATA,__global");
    assert_eq!(&local_data[8..], &0x1111_2222_3333_4444u64.to_le_bytes());
    assert_eq!(global_data, 0xaaaa_bbbb_cccc_ddddu64.to_le_bytes());
    assert_ne!(local_addr + 8, global_addr);
    let emitted_pointer = u64::from_le_bytes(local_data[..8].try_into().unwrap());
    assert_eq!(emitted_pointer, local_addr + 8);
    assert_ne!(emitted_pointer, global_addr);
    assert_eq!(
        decode_rebase_records(&bytes).unwrap(),
        vec![RebaseRecord {
            segment: "__DATA".into(),
            section: "__localref".into(),
            section_offset: 0,
            rebase_type: REBASE_TYPE_POINTER,
        }]
    );

    let _ = fs::remove_file(local_object);
    let _ = fs::remove_file(global_object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_preserves_local_symbol_at_input_section_end() {
    let object = scratch("local-symbol-at-section-end.o");
    let output = scratch("local-symbol-at-section-end.dylib");
    fs::write(
        &object,
        synthetic_single_section_object(
            "__DATA",
            "__const",
            S_REGULAR,
            &[0x5a; 8],
            &[],
            &[
                ("_anchor", N_SECT | N_EXT, 1, 0, 0),
                ("_section_end", N_SECT, 1, 0, 8),
            ],
        ),
    )
    .unwrap();

    Linker::run(&LinkOptions {
        inputs: vec![object.clone()],
        output: Some(output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    })
    .unwrap();

    let bytes = fs::read(&output).unwrap();
    let (_, data) = output_section(&bytes, "__DATA_CONST", "__const")
        .expect("const fixture must be retained in __DATA_CONST,__const");
    assert_eq!(data, vec![0x5a; 8]);
    let symbols = canonical_symbol_record_map(&bytes);
    let anchor = symbols.get("_anchor").expect("external anchor symbol");
    let section_end = symbols
        .get("_section_end")
        .expect("local section-end symbol");
    assert_eq!(section_end.n_type, N_SECT);
    assert_eq!(section_end.n_sect, anchor.n_sect);
    assert_eq!(section_end.value, 8);

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn linker_run_icf_safe_keeps_cross_object_section_targets_distinct() {
    if !have_xcrun() || !have_xcrun_tool("ld") || !have_tool("codesign") {
        harness_skip!("xcrun as/ld or codesign unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        harness_skip!("xcrun --show-sdk-version unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        harness_skip!("no libSystem.tbd at {}", tbd.display());
        return;
    }

    let first = scratch("icf-section-first.o");
    let second = scratch("icf-section-second.o");
    let apple_first = scratch("icf-section-first-apple.o");
    let apple_second = scratch("icf-section-second-apple.o");
    let main = scratch("icf-section-main.o");
    let our_out = scratch("icf-section-ours.out");
    let apple_out = scratch("icf-section-apple.out");
    let map = scratch("icf-section.map");
    fs::write(&first, synthetic_icf_section_reference_object("_fa", 1)).unwrap();
    fs::write(&second, synthetic_icf_section_reference_object("_fb", 2)).unwrap();
    assemble(
        r#"
            .data
            .p2align 3
        Lvalue:
            .quad 1

            .text
            .private_extern _fa
        _fa:
            adrp x0, Lvalue@PAGE
            add x0, x0, Lvalue@PAGEOFF
            ldr w0, [x0]
            ret
            .subsections_via_symbols
        "#,
        &apple_first,
    )
    .unwrap();
    assemble(
        r#"
            .data
            .p2align 3
        Lvalue:
            .quad 2

            .text
            .private_extern _fb
        _fb:
            adrp x0, Lvalue@PAGE
            add x0, x0, Lvalue@PAGEOFF
            ldr w0, [x0]
            ret
            .subsections_via_symbols
        "#,
        &apple_second,
    )
    .unwrap();
    assemble(
        r#"
            .text
            .globl _main
            _main:
              sub sp, sp, #32
              stp x29, x30, [sp, #16]
              bl _fa
              str w0, [sp, #12]
              bl _fb
              ldr w1, [sp, #12]
              add w0, w0, w1
              ldp x29, x30, [sp, #16]
              add sp, sp, #32
              ret
            .subsections_via_symbols
        "#,
        &main,
    )
    .unwrap();

    let opts = LinkOptions {
        inputs: vec![first.clone(), second.clone(), main.clone(), tbd],
        output: Some(our_out.clone()),
        map: Some(map.clone()),
        icf_mode: afs_ld::IcfMode::Safe,
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
        ])
        .arg(&apple_first)
        .arg(&apple_second)
        .arg(&main)
        .args(["-lSystem", "-e", "_main", "-o"])
        .arg(&apple_out)
        .output()
        .unwrap();
    assert!(
        apple.status.success(),
        "xcrun ld failed: {}",
        String::from_utf8_lossy(&apple.stderr)
    );

    let our_symbols = symbol_values(&fs::read(&our_out).unwrap());
    assert_ne!(our_symbols.get("_fa"), our_symbols.get("_fb"));
    let map_text = fs::read_to_string(&map).unwrap();
    assert!(!map_text.contains("_fa folded to _fb"));
    assert!(!map_text.contains("_fb folded to _fa"));

    for output in [&our_out, &apple_out] {
        let verify = Command::new("codesign")
            .arg("-v")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "codesign verify failed for {}: {}",
            output.display(),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(Command::new(output).status().unwrap().code(), Some(3));
    }

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
    let _ = fs::remove_file(apple_first);
    let _ = fs::remove_file(apple_second);
    let _ = fs::remove_file(main);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_icf_safe_folds_identical_private_text() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-fold.o");
    let baseline_out = scratch("icf-fold-baseline.out");
    let our_out = scratch("icf-fold-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper1
            bl _helper2
            ldp x29, x30, [sp], #16
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #7
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #7
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_eq!(
        our_symbols.get("_helper1"),
        our_symbols.get("_helper2"),
        "expected afs-ld -icf=safe to coalesce identical private text atoms"
    );
    assert_ne!(
        baseline_symbols.get("_helper1"),
        baseline_symbols.get("_helper2"),
        "expected baseline link to keep identical helpers separate"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(7),
        "folded executable should preserve runtime behavior"
    );
    assert!(
        our_text.len() < baseline_text.len(),
        "expected -icf=safe to reduce text size on identical helpers"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_keeps_address_taken_functions_distinct() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-address-taken.o");
    let baseline_out = scratch("icf-address-taken-baseline.out");
    let our_out = scratch("icf-address-taken-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper1
            bl _helper2
            ldp x29, x30, [sp], #16
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #7
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #7
            ret

        .section __DATA,__const
        .p2align 3
        _ptrs:
            .quad _helper1
            .quad _helper2
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_ne!(
        our_symbols.get("_helper1"),
        our_symbols.get("_helper2"),
        "address-taken helpers should not be folded by afs-ld -icf=safe"
    );
    assert_ne!(
        baseline_symbols.get("_helper1"),
        baseline_symbols.get("_helper2"),
        "baseline link should keep address-taken helpers separate"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(7),
        "address-taken executable should preserve runtime behavior"
    );
    assert_eq!(
        our_text.len(),
        baseline_text.len(),
        "address-taken helpers should not shrink under -icf=safe"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_keeps_adrp_add_address_taken_functions_distinct() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-adrp-address-taken.o");
    let baseline_out = scratch("icf-adrp-address-taken-baseline.out");
    let our_out = scratch("icf-adrp-address-taken-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            adrp x10, _helper1@PAGE
            add x10, x10, _helper1@PAGEOFF
            adrp x11, _helper2@PAGE
            add x11, x11, _helper2@PAGEOFF
            cmp x10, x11
            b.ne 1f
            mov w0, #1
            ldp x29, x30, [sp], #16
            ret
        1:
            mov w0, #0
            ldp x29, x30, [sp], #16
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #7
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #7
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_ne!(
        our_symbols.get("_helper1"),
        our_symbols.get("_helper2"),
        "adrp/add address-taken helpers should not be folded by afs-ld -icf=safe"
    );
    assert_ne!(
        baseline_symbols.get("_helper1"),
        baseline_symbols.get("_helper2"),
        "baseline link should keep adrp/add address-taken helpers separate"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(0),
        "adrp/add address-taken executable should preserve pointer inequality"
    );
    assert_eq!(
        our_text.len(),
        baseline_text.len(),
        "adrp/add address-taken helpers should not shrink under -icf=safe"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_folds_matching_branch_relocs() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-branch-match.o");
    let baseline_out = scratch("icf-branch-match-baseline.out");
    let our_out = scratch("icf-branch-match-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-32]!
            mov x29, sp
            bl _wrapper1
            str w0, [sp, #16]
            bl _wrapper2
            ldr w8, [sp, #16]
            add w0, w8, w0
            ldp x29, x30, [sp], #32
            ret

        .private_extern _wrapper1
        _wrapper1:
            b _leaf

        .private_extern _wrapper2
        _wrapper2:
            b _leaf

        .private_extern _leaf
        _leaf:
            mov w0, #5
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_ne!(
        baseline_symbols.get("_wrapper1"),
        baseline_symbols.get("_wrapper2"),
        "baseline link should keep identical wrappers separate"
    );
    assert_eq!(
        our_symbols.get("_wrapper1"),
        our_symbols.get("_wrapper2"),
        "matching branch relocations should fold under -icf=safe"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(10),
        "folded branch-reloc executable should preserve runtime behavior"
    );
    assert!(
        our_text.len() < baseline_text.len(),
        "expected matching branch-reloc wrappers to shrink under -icf=safe"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_keeps_distinct_branch_targets_unfolded() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-branch-distinct.o");
    let baseline_out = scratch("icf-branch-distinct-baseline.out");
    let our_out = scratch("icf-branch-distinct-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-32]!
            mov x29, sp
            bl _wrapper1
            str w0, [sp, #16]
            bl _wrapper2
            ldr w8, [sp, #16]
            add w0, w8, w0
            ldp x29, x30, [sp], #32
            ret

        .private_extern _wrapper1
        _wrapper1:
            b _leaf1

        .private_extern _wrapper2
        _wrapper2:
            b _leaf2

        .private_extern _leaf1
        _leaf1:
            mov w0, #3
            ret

        .private_extern _leaf2
        _leaf2:
            mov w0, #5
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_ne!(
        baseline_symbols.get("_wrapper1"),
        baseline_symbols.get("_wrapper2"),
        "baseline link should keep distinct wrappers separate"
    );
    assert_ne!(
        our_symbols.get("_wrapper1"),
        our_symbols.get("_wrapper2"),
        "wrappers targeting different leaves must not fold under -icf=safe"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(8),
        "distinct branch-target executable should preserve runtime behavior"
    );
    assert_eq!(
        our_text.len(),
        baseline_text.len(),
        "distinct branch-target wrappers should not shrink under -icf=safe"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_folds_identical_private_const_data() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-const-fold.o");
    let baseline_out = scratch("icf-const-fold-baseline.out");
    let our_out = scratch("icf-const-fold-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .section __TEXT,__const
        .p2align 3
        .private_extern _const1
        _const1:
            .quad 0x1122334455667788
        .p2align 3
        .private_extern _const2
        _const2:
            .quad 0x1122334455667788
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_const = output_section(&baseline_bytes, "__TEXT", "__const")
        .unwrap()
        .1;
    let our_const = output_section(&our_bytes, "__TEXT", "__const").unwrap().1;

    assert_ne!(
        baseline_symbols.get("_const1"),
        baseline_symbols.get("_const2"),
        "baseline link should keep identical private const atoms separate"
    );
    assert_eq!(
        our_symbols.get("_const1"),
        our_symbols.get("_const2"),
        "expected afs-ld -icf=safe to coalesce identical private const atoms"
    );
    assert!(
        our_const.len() < baseline_const.len(),
        "expected -icf=safe to reduce const section size on identical atoms"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_folds_identical_private_cstrings() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-cstring-fold.o");
    let baseline_out = scratch("icf-cstring-fold-baseline.out");
    let our_out = scratch("icf-cstring-fold-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .section __TEXT,__cstring,cstring_literals
        .private_extern _str1
        _str1:
            .asciz "fold me"
        .private_extern _str2
        _str2:
            .asciz "fold me"
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_cstrings = output_section(&baseline_bytes, "__TEXT", "__cstring")
        .unwrap()
        .1;
    let our_cstrings = output_section(&our_bytes, "__TEXT", "__cstring").unwrap().1;

    assert_ne!(
        baseline_symbols.get("_str1"),
        baseline_symbols.get("_str2"),
        "baseline link should keep identical private cstrings separate"
    );
    assert_eq!(
        our_symbols.get("_str1"),
        our_symbols.get("_str2"),
        "expected afs-ld -icf=safe to coalesce identical private cstrings"
    );
    assert!(
        our_cstrings.len() < baseline_cstrings.len(),
        "expected -icf=safe to reduce cstring section size on identical literals"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_folds_identical_private_literal16() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-literal16-fold.o");
    let baseline_out = scratch("icf-literal16-fold-baseline.out");
    let our_out = scratch("icf-literal16-fold-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .section __TEXT,__literal16,16byte_literals
        .private_extern _lit1
        _lit1:
            .quad 0x1122334455667788
            .quad 0x99aabbccddeeff00
        .private_extern _lit2
        _lit2:
            .quad 0x1122334455667788
            .quad 0x99aabbccddeeff00
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_literals = output_section(&baseline_bytes, "__TEXT", "__literal16")
        .unwrap()
        .1;
    let our_literals = output_section(&our_bytes, "__TEXT", "__literal16")
        .unwrap()
        .1;

    assert_ne!(
        baseline_symbols.get("_lit1"),
        baseline_symbols.get("_lit2"),
        "baseline link should keep identical private literal16 atoms separate"
    );
    assert_eq!(
        our_symbols.get("_lit1"),
        our_symbols.get("_lit2"),
        "expected afs-ld -icf=safe to coalesce identical private literal16 atoms"
    );
    assert!(
        our_literals.len() < baseline_literals.len(),
        "expected -icf=safe to reduce literal16 section size on identical atoms"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_folds_identical_private_data_const_atoms() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-data-const-fold.o");
    let baseline_out = scratch("icf-data-const-fold-baseline.out");
    let our_out = scratch("icf-data-const-fold-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .section __DATA_CONST,__const
        .p2align 3
        .private_extern _const1
        _const1:
            .quad 0x0123456789abcdef
        .p2align 3
        .private_extern _const2
        _const2:
            .quad 0x0123456789abcdef
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_const = output_section(&baseline_bytes, "__DATA_CONST", "__const")
        .unwrap()
        .1;
    let our_const = output_section(&our_bytes, "__DATA_CONST", "__const")
        .unwrap()
        .1;

    assert_ne!(
        baseline_symbols.get("_const1"),
        baseline_symbols.get("_const2"),
        "baseline link should keep identical private __DATA_CONST atoms separate"
    );
    assert_eq!(
        our_symbols.get("_const1"),
        our_symbols.get("_const2"),
        "expected afs-ld -icf=safe to coalesce identical private __DATA_CONST atoms"
    );
    assert!(
        our_const.len() < baseline_const.len(),
        "expected -icf=safe to reduce __DATA_CONST,__const size on identical atoms"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_reaches_fixed_point_through_folded_targets() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let obj = scratch("icf-fixed-point.o");
    let baseline_out = scratch("icf-fixed-point-baseline.out");
    let our_out = scratch("icf-fixed-point-ours.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-32]!
            mov x29, sp
            bl _wrapper1
            str w0, [sp, #16]
            bl _wrapper2
            ldr w8, [sp, #16]
            add w0, w8, w0
            ldp x29, x30, [sp], #32
            ret

        .private_extern _wrapper1
        _wrapper1:
            b _leaf1

        .private_extern _wrapper2
        _wrapper2:
            b _leaf2

        .private_extern _leaf1
        _leaf1:
            mov w0, #6
            ret

        .private_extern _leaf2
        _leaf2:
            mov w0, #6
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let baseline_opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(baseline_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&baseline_opts).unwrap();

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let baseline_bytes = fs::read(&baseline_out).unwrap();
    let our_bytes = fs::read(&our_out).unwrap();
    let baseline_symbols = symbol_values(&baseline_bytes);
    let our_symbols = symbol_values(&our_bytes);
    let baseline_text = output_section(&baseline_bytes, "__TEXT", "__text")
        .unwrap()
        .1;
    let our_text = output_section(&our_bytes, "__TEXT", "__text").unwrap().1;

    assert_ne!(
        baseline_symbols.get("_leaf1"),
        baseline_symbols.get("_leaf2"),
        "baseline link should keep equivalent leaves separate"
    );
    assert_ne!(
        baseline_symbols.get("_wrapper1"),
        baseline_symbols.get("_wrapper2"),
        "baseline link should keep wrappers separate"
    );
    assert_eq!(
        our_symbols.get("_leaf1"),
        our_symbols.get("_leaf2"),
        "equivalent leaves should fold under -icf=safe"
    );
    assert_eq!(
        our_symbols.get("_wrapper1"),
        our_symbols.get("_wrapper2"),
        "wrappers should fold once their targets converge to the same winner"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(12),
        "fixed-point folded executable should preserve runtime behavior"
    );
    assert!(
        our_text.len() < baseline_text.len(),
        "expected fixed-point folding to reduce text size"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(baseline_out);
    let _ = fs::remove_file(our_out);
}

#[test]
fn linker_run_icf_safe_prefers_earlier_input_order_winner() {
    if !have_xcrun() {
        harness_skip!("xcrun unavailable");
        return;
    };

    let main_obj = scratch("icf-order-main.o");
    let first_obj = scratch("icf-order-first.o");
    let second_obj = scratch("icf-order-second.o");
    let our_out = scratch("icf-order-ours.out");
    let map = scratch("icf-order.map");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-32]!
            mov x29, sp
            bl _helper_a
            str w0, [sp, #16]
            bl _helper_b
            ldr w8, [sp, #16]
            add w0, w8, w0
            ldp x29, x30, [sp], #32
            ret
        .subsections_via_symbols
    "#;
    let helper_a_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .private_extern _helper_a
        .globl _helper_a
        _helper_a:
            mov w0, #4
            ret
        .subsections_via_symbols
    "#;
    let helper_b_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .private_extern _helper_b
        .globl _helper_b
        _helper_b:
            mov w0, #4
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(main_src, &main_obj));
    require_fixture!("assembly fixture", assemble(helper_a_src, &first_obj));
    require_fixture!("assembly fixture", assemble(helper_b_src, &second_obj));

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), first_obj.clone(), second_obj.clone()],
        output: Some(our_out.clone()),
        map: Some(map.clone()),
        kind: OutputKind::Executable,
        icf_mode: afs_ld::IcfMode::Safe,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let our_bytes = fs::read(&our_out).unwrap();
    let our_symbols = symbol_values(&our_bytes);
    let map_text = fs::read_to_string(&map).unwrap();

    assert_eq!(
        our_symbols.get("_helper_a"),
        our_symbols.get("_helper_b"),
        "equivalent helpers should fold to the same winner"
    );
    assert!(
        map_text.contains("_helper_b folded to _helper_a"),
        "earlier input should win safe-ICF ties:\n{map_text}"
    );
    assert_eq!(
        Command::new(&our_out).status().unwrap().code(),
        Some(8),
        "input-order folded executable should preserve runtime behavior"
    );

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(first_obj);
    let _ = fs::remove_file(second_obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(map);
}

#[test]
fn linker_run_rejects_link_map_alias_of_unpublished_output() {
    let directory = scratch("AFSLD-071-map-output-alias");
    let nested = directory.join("nested");
    let object = directory.join("input.o");
    let output = directory.join("linked.dylib");
    let map_alias = nested.join("..").join("linked.dylib");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        &object,
        synthetic_single_section_object(
            "__TEXT",
            "__const",
            S_REGULAR,
            &[0x71; 8],
            &[],
            &[("_value", N_SECT | N_EXT, 1, 0, 0)],
        ),
    )
    .unwrap();

    let result = Linker::run(&LinkOptions {
        inputs: vec![object],
        output: Some(output.clone()),
        map: Some(map_alias.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    });
    let output_exists = output.exists();
    let _ = fs::remove_dir_all(&directory);

    assert!(
        matches!(
            result,
            Err(LinkError::LinkMapAliasesOutput {
                map,
                output: rejected_output,
            }) if map == map_alias && rejected_output == output
        ),
        "a link map must report its conflict with the primary output"
    );
    assert!(
        !output_exists,
        "path-alias rejection must happen before publishing the primary output"
    );
}

#[test]
fn linker_run_preserves_existing_output_when_link_map_aliases_it() {
    const SENTINEL: &[u8] = b"previous complete executable";
    let directory = scratch("AFSLD-071-existing-output-alias");
    let object = directory.join("input.o");
    let output = directory.join("linked.dylib");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        &object,
        synthetic_single_section_object(
            "__TEXT",
            "__const",
            S_REGULAR,
            &[0x71; 8],
            &[],
            &[("_value", N_SECT | N_EXT, 1, 0, 0)],
        ),
    )
    .unwrap();
    fs::write(&output, SENTINEL).unwrap();

    let result = Linker::run(&LinkOptions {
        inputs: vec![object],
        output: Some(output.clone()),
        map: Some(output.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    });
    let output_after = fs::read(&output).unwrap();
    let _ = fs::remove_dir_all(&directory);

    assert!(matches!(
        result,
        Err(LinkError::LinkMapAliasesOutput { .. })
    ));
    assert_eq!(
        output_after, SENTINEL,
        "alias rejection must preserve the previously published output"
    );
}

#[test]
fn linker_run_rejects_link_map_filesystem_aliases_of_inputs() {
    for alias_kind in ["symlink", "hardlink"] {
        let directory = scratch(&format!("AFSLD-071-map-input-{alias_kind}"));
        let object = directory.join("input.o");
        let output = directory.join("linked.dylib");
        let map_alias = directory.join("linked.map");
        fs::create_dir_all(&directory).unwrap();
        let object_bytes = synthetic_single_section_object(
            "__TEXT",
            "__const",
            S_REGULAR,
            &[0x71; 8],
            &[],
            &[("_value", N_SECT | N_EXT, 1, 0, 0)],
        );
        fs::write(&object, &object_bytes).unwrap();
        match alias_kind {
            "symlink" => std::os::unix::fs::symlink(&object, &map_alias).unwrap(),
            "hardlink" => fs::hard_link(&object, &map_alias).unwrap(),
            _ => unreachable!(),
        }

        let result = Linker::run(&LinkOptions {
            inputs: vec![object.clone()],
            output: Some(output.clone()),
            map: Some(map_alias.clone()),
            kind: OutputKind::Dylib,
            ..LinkOptions::default()
        });
        let object_after = fs::read(&object).unwrap();
        let output_exists = output.exists();
        let _ = fs::remove_dir_all(&directory);

        assert!(
            matches!(
                result,
                Err(LinkError::LinkMapAliasesInput { map, input })
                    if map == map_alias && input == object
            ),
            "a {alias_kind} link map alias must identify the protected input"
        );
        assert_eq!(
            object_after, object_bytes,
            "a rejected {alias_kind} map alias must leave the input byte-exact"
        );
        assert!(
            !output_exists,
            "input-alias rejection must happen before publishing the primary output"
        );
    }
}
