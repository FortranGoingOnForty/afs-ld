use std::fs;
#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

#[cfg(unix)]
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

use afs_ld::macho::constants::{
    ARM64_RELOC_ADDEND, CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_ID_DYLIB, LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_UUID, MH_BUNDLE, MH_DYLDLINK, MH_DYLIB, MH_DYLINKER,
    MH_EXECUTE, MH_MAGIC_64, MH_OBJECT, MH_TWOLEVEL, N_ABS, N_EXT, N_NO_DEAD_STRIP, N_PEXT, N_SECT,
    N_UNDF, SECTION_TYPE_MASK, S_REGULAR, S_ZEROFILL,
};
use afs_ld::macho::dylib::DylibFile;
use afs_ld::macho::reader::{
    parse_commands, parse_header, write_commands, write_header, DyldInfoCmd, DylibCmd, DysymtabCmd,
    LoadCommand, MachHeader64, Section64Header, Segment64, SymtabCmd, HEADER_SIZE,
};
use afs_ld::reloc::{write_raw_relocs, RawRelocation};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, RawNlist, SymKind, NLIST_SIZE};
use afs_ld::{InputSpec, LinkError, LinkOptions, Linker, OutputKind};

const EXPECTED_HELP: &str = include_str!("snapshots/help.txt");

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

fn minimal_main_src() -> &'static str {
    r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#
}

fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-cli-diag-{}-{}.s",
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

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-cli-diag-{}-{name}", std::process::id()))
}

#[cfg(unix)]
fn link_with_small_file_limit(args: &[&OsStr]) -> std::process::Output {
    Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' 25; ulimit -f 1; exec \"$@\"",
            "afs-ld-file-limit",
        ])
        .arg(env!("CARGO_BIN_EXE_afs-ld"))
        .args(args)
        .output()
        .expect("run afs-ld with a small file-size limit")
}

fn synthetic_undefined_object(name: &str) -> Vec<u8> {
    synthetic_symbol_object(&[(name, N_UNDF | N_EXT, 0)])
}

fn synthetic_legacy_dylib(name: &str, install_name: &str) -> Vec<u8> {
    let mut strings = vec![0];
    let strx = strings.len() as u32;
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    let identity = LoadCommand::Dylib(DylibCmd {
        cmd: LC_ID_DYLIB,
        name: install_name.into(),
        timestamp: 2,
        current_version: 1 << 16,
        compatibility_version: 1 << 16,
    });
    let sizeofcmds = identity.cmdsize() + SymtabCmd::WIRE_SIZE + DysymtabCmd::WIRE_SIZE;
    let symoff = HEADER_SIZE as u32 + sizeofcmds;
    let stroff = symoff + NLIST_SIZE as u32;
    let commands = vec![
        identity,
        LoadCommand::Symtab(SymtabCmd {
            symoff,
            nsyms: 1,
            stroff,
            strsize: strings.len() as u32,
        }),
        LoadCommand::Dysymtab(DysymtabCmd {
            iextdefsym: 0,
            nextdefsym: 1,
            iundefsym: 1,
            ..DysymtabCmd::default()
        }),
    ];
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_DYLIB,
            ncmds: commands.len() as u32,
            sizeofcmds,
            flags: MH_DYLDLINK | MH_TWOLEVEL,
            reserved: 0,
        },
        &mut bytes,
    );
    write_commands(&commands, &mut bytes);
    RawNlist {
        strx,
        n_type: N_SECT | N_EXT,
        n_sect: 1,
        n_desc: 0,
        n_value: 0x1000,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_export_trie_dylib(install_name: &str, trie: &[u8]) -> Vec<u8> {
    let identity = LoadCommand::Dylib(DylibCmd {
        cmd: LC_ID_DYLIB,
        name: install_name.into(),
        timestamp: 2,
        current_version: 1 << 16,
        compatibility_version: 1 << 16,
    });
    let sizeofcmds = identity.cmdsize() + DyldInfoCmd::WIRE_SIZE;
    let commands = vec![
        identity,
        LoadCommand::DyldInfoOnly(DyldInfoCmd {
            export_off: HEADER_SIZE as u32 + sizeofcmds,
            export_size: trie.len() as u32,
            ..DyldInfoCmd::default()
        }),
    ];
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_DYLIB,
            ncmds: commands.len() as u32,
            sizeofcmds,
            flags: MH_DYLDLINK | MH_TWOLEVEL,
            reserved: 0,
        },
        &mut bytes,
    );
    write_commands(&commands, &mut bytes);
    bytes.extend_from_slice(trie);
    bytes
}

fn synthetic_symbol_object(symbols: &[(&str, u8, u64)]) -> Vec<u8> {
    let symbols = symbols
        .iter()
        .map(|&(name, n_type, value)| (name, n_type, 0, value))
        .collect::<Vec<_>>();
    synthetic_symbol_object_with_desc(&symbols)
}

fn synthetic_symbol_object_with_desc(symbols: &[(&str, u8, u16, u64)]) -> Vec<u8> {
    let mut strings = vec![0];
    let mut raw_symbols = Vec::with_capacity(symbols.len());
    for &(name, n_type, n_desc, value) in symbols {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        raw_symbols.push(RawNlist {
            strx,
            n_type,
            n_sect: 0,
            n_desc,
            n_value: value,
        });
    }
    let symoff = afs_ld::macho::reader::HEADER_SIZE as u32 + SymtabCmd::WIRE_SIZE;
    let stroff = symoff + (raw_symbols.len() * NLIST_SIZE) as u32;

    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_OBJECT,
            ncmds: 1,
            sizeofcmds: SymtabCmd::WIRE_SIZE,
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    SymtabCmd {
        symoff,
        nsyms: raw_symbols.len() as u32,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    for symbol in raw_symbols {
        symbol.write(&mut bytes);
    }
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_text_object(symbol_name: &str) -> Vec<u8> {
    synthetic_text_object_with_relocations(symbol_name, &[])
}

fn synthetic_text_object_with_relocations(
    symbol_name: &str,
    relocations: &[RawRelocation],
) -> Vec<u8> {
    let text = [0xc0, 0x03, 0x5f, 0xd6]; // ret
    let mut relocation_bytes = Vec::new();
    write_raw_relocs(relocations, &mut relocation_bytes);
    let mut strings = vec![0];
    let strx = strings.len() as u32;
    strings.extend_from_slice(symbol_name.as_bytes());
    strings.push(0);
    let symbol = RawNlist {
        strx,
        n_type: N_SECT | N_EXT,
        n_sect: 1,
        n_desc: 0,
        n_value: 0,
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
            nreloc: 0,
            flags: S_REGULAR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = afs_ld::macho::reader::HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    segment.sections[0].reloff = data_offset + text.len() as u32;
    segment.sections[0].nreloc = relocations.len() as u32;
    let symoff = segment.sections[0].reloff + relocation_bytes.len() as u32;
    let stroff = symoff + NLIST_SIZE as u32;

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
        nsyms: 1,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&relocation_bytes);
    symbol.write(&mut bytes);
    bytes.extend_from_slice(&strings);
    bytes
}

fn synthetic_text_object_with_invalid_symbol_name() -> Vec<u8> {
    let mut bytes = synthetic_text_object("_main");
    let header = parse_header(&bytes).unwrap();
    let symtab = parse_commands(&header, &bytes)
        .unwrap()
        .into_iter()
        .find_map(|command| match command {
            LoadCommand::Symtab(symtab) => Some(symtab),
            _ => None,
        })
        .unwrap();
    bytes[symtab.symoff as usize..symtab.symoff as usize + 4]
        .copy_from_slice(&symtab.strsize.to_le_bytes());
    bytes
}

fn name16(name: &str) -> [u8; 16] {
    assert!(name.len() <= 16);
    let mut out = [0; 16];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

fn synthetic_common_with_regular_common_section() -> Vec<u8> {
    let strings = b"\0_collision\0";
    let mut segment = Segment64 {
        segname: name16("__DATA"),
        vmaddr: 0,
        vmsize: 1,
        fileoff: 0,
        filesize: 1,
        maxprot: 3,
        initprot: 3,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__common"),
            segname: name16("__DATA"),
            addr: 0,
            size: 1,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    let sizeofcmds = segment.wire_size() + SymtabCmd::WIRE_SIZE;
    let data_offset = afs_ld::macho::reader::HEADER_SIZE as u32 + sizeofcmds;
    segment.fileoff = data_offset as u64;
    segment.sections[0].offset = data_offset;
    let symoff = data_offset + 1;
    let stroff = symoff + NLIST_SIZE as u32;
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
        nsyms: 1,
        stroff,
        strsize: strings.len() as u32,
    }
    .write(&mut bytes);
    bytes.push(0xaa);
    RawNlist {
        strx: 1,
        n_type: N_UNDF | N_EXT,
        n_sect: 0,
        n_desc: 3 << 8,
        n_value: 8,
    }
    .write(&mut bytes);
    bytes.extend_from_slice(strings);
    bytes
}

fn synthetic_dylib_with_ids(install_names: &[&str]) -> Vec<u8> {
    let commands = install_names
        .iter()
        .map(|install_name| DylibCmd {
            cmd: LC_ID_DYLIB,
            name: (*install_name).to_string(),
            timestamp: 2,
            current_version: 1 << 16,
            compatibility_version: 1 << 16,
        })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_DYLIB,
            ncmds: commands.len() as u32,
            sizeofcmds: commands.iter().map(DylibCmd::wire_size).sum(),
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    for command in commands {
        command.write(&mut bytes);
    }
    bytes
}

fn synthetic_dylib(install_name: &str) -> Vec<u8> {
    synthetic_dylib_with_ids(&[install_name])
}

fn synthetic_macho_with_truncated_commands(filetype: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype,
            ncmds: 1,
            sizeofcmds: 8,
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    bytes
}

fn synthetic_text_macho_with_filetype(symbol: &str, filetype: u32) -> Vec<u8> {
    let mut bytes = synthetic_text_object(symbol);
    bytes[12..16].copy_from_slice(&filetype.to_le_bytes());
    bytes
}

fn synthetic_ar_header(raw_name: &str, size: usize) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, value: &str, width: usize) {
        assert!(value.len() <= width);
        out.extend_from_slice(value.as_bytes());
        out.resize(out.len() + width - value.len(), b' ');
    }

    let mut encoded = Vec::new();
    field(&mut encoded, raw_name, 16);
    field(&mut encoded, "0", 12);
    field(&mut encoded, "0", 6);
    field(&mut encoded, "0", 6);
    field(&mut encoded, "100644", 8);
    field(&mut encoded, &size.to_string(), 10);
    encoded.extend_from_slice(b"`\n");
    encoded
}

fn synthetic_ar_member(raw_name: &str, body: &[u8]) -> Vec<u8> {
    let mut encoded = synthetic_ar_header(raw_name, body.len());
    encoded.extend_from_slice(body);
    if body.len() & 1 != 0 {
        encoded.push(b'\n');
    }
    encoded
}

fn synthetic_indexed_archive(symbol: &str, member_name: &str, member_body: &[u8]) -> Vec<u8> {
    fn index_body(symbol: &str, member_offset: u32) -> Vec<u8> {
        let mut body = b"__.SYMDEF".to_vec();
        body.extend_from_slice(&8_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&member_offset.to_le_bytes());
        body.extend_from_slice(&((symbol.len() + 1) as u32).to_le_bytes());
        body.extend_from_slice(symbol.as_bytes());
        body.push(0);
        body
    }

    let encoded_member = synthetic_ar_member(member_name, member_body);
    let placeholder_index = synthetic_ar_member("#1/9", &index_body(symbol, 0));
    let member_offset = 8 + placeholder_index.len() as u32;
    let index = synthetic_ar_member("#1/9", &index_body(symbol, member_offset));
    assert_eq!(index.len(), placeholder_index.len());

    let mut archive = b"!<arch>\n".to_vec();
    archive.extend_from_slice(&index);
    archive.extend_from_slice(&encoded_member);
    archive
}

fn synthetic_malformed_archive(symbol: &str) -> Vec<u8> {
    synthetic_indexed_archive(symbol, "bad.o/", &[0; 32])
}

fn synthetic_thin_archive(symbol: &str, member_name: &str, member_size: usize) -> Vec<u8> {
    synthetic_thin_archive_reference(symbol, member_name, member_size, None)
}

fn synthetic_thin_archive_reference(
    symbol: &str,
    member_name: &str,
    member_size: usize,
    nested_member_offset: Option<u64>,
) -> Vec<u8> {
    fn index_body(symbol: &str, member_offset: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u32.to_be_bytes());
        body.extend_from_slice(&member_offset.to_be_bytes());
        body.extend_from_slice(symbol.as_bytes());
        body.push(0);
        body
    }

    let long_names = format!("{member_name}/\n");
    let placeholder_index = synthetic_ar_member("/", &index_body(symbol, 0));
    let long_name_member = synthetic_ar_member("//", long_names.as_bytes());
    let member_offset = 8 + placeholder_index.len() as u32 + long_name_member.len() as u32;
    let index = synthetic_ar_member("/", &index_body(symbol, member_offset));
    assert_eq!(index.len(), placeholder_index.len());

    let mut archive = b"!<thin>\n".to_vec();
    archive.extend_from_slice(&index);
    archive.extend_from_slice(&long_name_member);
    let member_reference = nested_member_offset
        .map(|offset| format!("/0:{offset}"))
        .unwrap_or_else(|| "/0".to_string());
    archive.extend_from_slice(&synthetic_ar_header(&member_reference, member_size));
    archive
}

fn assemble_minimal_main(name: &str) -> Result<PathBuf, String> {
    let obj = scratch(name);
    assemble(minimal_main_src(), &obj)?;
    Ok(obj)
}

fn assert_flag_errors(flag: &str, expected: &str, name: &str) {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!(
        "assembly fixture",
        assemble_minimal_main(&format!("{name}.o"))
    );
    let out_path = scratch(&format!("{name}.out"));
    let out = Command::new(exe)
        .arg(flag)
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(!out.status.success(), "{flag} should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected),
        "missing expected `{expected}` in stderr:\n{stderr}"
    );
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

fn archive(objects: &[&PathBuf], out: &PathBuf) -> Result<(), String> {
    let output = Command::new("libtool")
        .arg("-static")
        .arg("-o")
        .arg(out)
        .args(objects)
        .output()
        .map_err(|e| format!("spawn libtool: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "libtool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn nm_defined_names(path: &PathBuf) -> Result<Vec<String>, String> {
    let output = Command::new("xcrun")
        .args(["nm", "-gj"])
        .arg(path)
        .output()
        .map_err(|e| format!("spawn xcrun nm: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun nm failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[test]
fn help_flag_prints_usage_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--help")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "help should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.as_ref(), EXPECTED_HELP);
    assert!(
        out.stderr.is_empty(),
        "help should not write to stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_flag_prints_version_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "version should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        format!("afs-ld {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn no_uuid_flag_omits_uuid_load_command() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!("assembly fixture", assemble_minimal_main("no-uuid-main.o"));
    let out_path = scratch("no-uuid.out");
    let out = Command::new(exe)
        .arg("-no_uuid")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-no_uuid link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = fs::read(&out_path).expect("read linked output");
    let header = parse_header(&bytes).expect("parse header");
    let commands = parse_commands(&header, &bytes).expect("parse commands");
    assert!(
        commands.iter().all(|cmd| match cmd {
            LoadCommand::Raw { cmd, .. } => *cmd != LC_UUID,
            _ => true,
        }),
        "expected -no_uuid output to omit LC_UUID"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn no_loh_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!("assembly fixture", assemble_minimal_main("no-loh-main.o"));
    let out_path = scratch("no-loh.out");
    let out = Command::new(exe)
        .arg("-no_loh")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-no_loh link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-no_loh` requested"),
        "expected -no_loh warning:\n{stderr}"
    );
    assert!(
        out_path.is_file(),
        "expected -no_loh link to produce {}",
        out_path.display()
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn strip_debug_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!(
        "assembly fixture",
        assemble_minimal_main("strip-debug-main.o")
    );
    let out_path = scratch("strip-debug.out");
    let out = Command::new(exe)
        .arg("-S")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-S link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-S` requested"),
        "expected -S warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn objc_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!("assembly fixture", assemble_minimal_main("objc-main.o"));
    let out_path = scratch("objc.out");
    let out = Command::new(exe)
        .arg("-ObjC")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-ObjC link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-ObjC` requested"),
        "expected -ObjC warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn explicit_absolute_entry_symbol_is_rejected() {
    let object = scratch("absolute-entry.o");
    let output = scratch("absolute-entry.out");
    let _ = fs::remove_file(&output);
    fs::write(
        &object,
        synthetic_symbol_object(&[("_absolute_entry", N_ABS | N_EXT, 0x1234)]),
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-e")
        .arg("_absolute_entry")
        .arg("-o")
        .arg(&output)
        .arg(&object)
        .output()
        .expect("afs-ld should run");

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(
            "entry symbol `_absolute_entry` is absolute and cannot be used as an executable entry point"
        ),
        "unexpected diagnostic:\n{stderr}"
    );
    assert!(
        !stderr.contains("AtomId"),
        "leaked internal sentinel:\n{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_file(object);
}

#[test]
fn executable_without_default_entry_is_rejected() {
    let object = scratch("missing-default-entry.o");
    let output = scratch("missing-default-entry.out");
    let _ = fs::remove_file(&output);
    fs::write(&object, synthetic_text_object("_foo")).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-dead_strip")
        .arg("-o")
        .arg(&output)
        .arg(&object)
        .output()
        .expect("afs-ld should run");

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(
            "executable has no entry symbol; define `_main` or `_start`, or use `-e <symbol>`"
        ),
        "unexpected diagnostic:\n{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_file(object);
}

#[test]
fn executable_accepts_default_and_explicit_entries() {
    for (symbol, entry) in [("_main", None), ("_start", None), ("_foo", Some("_foo"))] {
        let stem = symbol.trim_start_matches('_');
        let object = scratch(&format!("valid-{stem}-entry.o"));
        let output = scratch(&format!("valid-{stem}-entry.out"));
        let _ = fs::remove_file(&output);
        fs::write(&object, synthetic_text_object(symbol)).unwrap();

        let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
        if let Some(entry) = entry {
            command.arg("-e").arg(entry);
        }
        let result = command
            .arg("-o")
            .arg(&output)
            .arg(&object)
            .output()
            .expect("afs-ld should run");
        assert!(
            result.status.success(),
            "valid entry {symbol} failed:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );

        let bytes = fs::read(&output).unwrap();
        let header = parse_header(&bytes).unwrap();
        assert_eq!(header.filetype, MH_EXECUTE);
        assert!(parse_commands(&header, &bytes)
            .unwrap()
            .iter()
            .any(|command| matches!(command, LoadCommand::Raw { cmd, .. } if *cmd == LC_MAIN)));

        let _ = fs::remove_file(object);
        let _ = fs::remove_file(output);
    }
}

#[cfg(unix)]
#[test]
fn primary_macho_output_preserves_previous_file_after_write_failure() {
    const SENTINEL: &[u8] = b"previous complete Mach-O output";

    let dir = scratch("atomic-primary-output");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let object = dir.join("main.o");
    let output = dir.join("linked");
    fs::write(&object, synthetic_text_object("_main")).unwrap();
    fs::write(&output, SENTINEL).unwrap();

    let result =
        link_with_small_file_limit(&[OsStr::new("-o"), output.as_os_str(), object.as_os_str()]);

    assert!(!result.status.success(), "file-limited link must fail");
    assert_eq!(
        fs::read(&output).unwrap(),
        SENTINEL,
        "failed Mach-O publication replaced the previous complete output"
    );
    assert!(
        fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("afs-ld-tmp")),
        "failed Mach-O publication leaked a temporary output"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dylib_does_not_require_an_executable_entry() {
    let object = scratch("dylib-without-entry.o");
    let output = scratch("dylib-without-entry.dylib");
    let _ = fs::remove_file(&output);
    fs::write(&object, synthetic_text_object("_foo")).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-dylib")
        .arg("-o")
        .arg(&output)
        .arg(&object)
        .output()
        .expect("afs-ld should run");
    assert!(
        result.status.success(),
        "dylib link failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let bytes = fs::read(&output).unwrap();
    let header = parse_header(&bytes).unwrap();
    assert_eq!(header.filetype, MH_DYLIB);
    assert!(!parse_commands(&header, &bytes)
        .unwrap()
        .iter()
        .any(|command| matches!(command, LoadCommand::Raw { cmd, .. } if *cmd == LC_MAIN)));

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn why_live_reports_absolute_symbols_outside_dead_stripping() {
    let object = scratch("absolute-why-live.o");
    let output = scratch("absolute-why-live.dylib");
    fs::write(
        &object,
        synthetic_symbol_object(&[("_absolute", N_ABS | N_EXT, 0x1234)]),
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-dylib")
        .arg("-dead_strip")
        .arg("-why_live")
        .arg("_absolute")
        .arg("-o")
        .arg(&output)
        .arg(&object)
        .output()
        .expect("afs-ld should run");

    assert!(
        result.status.success(),
        "absolute why-live link failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "_absolute is absolute and is not subject to dead stripping\n"
    );

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn relocatable_flag_errors_loudly() {
    assert_flag_errors(
        "-r",
        "`-r` relocatable output is not yet supported",
        "relocatable",
    );
}

#[test]
fn bundle_flag_errors_loudly() {
    assert_flag_errors("-bundle", "`-bundle` output is not yet supported", "bundle");
}

#[test]
fn dead_strip_removes_unreferenced_symbols_and_reports_why_live() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("dead-strip-main.o");
    let helper_obj = scratch("dead-strip-helper.o");
    let unused_obj = scratch("dead-strip-unused.o");
    let out_path = scratch("dead-strip.out");
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

    let out = Command::new(exe)
        .arg("-dead_strip")
        .arg("-why_live")
        .arg("_helper")
        .arg("-why_live")
        .arg("_unused")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&helper_obj)
        .arg(&unused_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-dead_strip link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_helper is live because:"));
    assert!(stdout.contains("_helper is reachable from _main"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));
    assert!(stdout.contains("_unused is not live (dead-stripped)"));

    let symbols = match nm_defined_names(&out_path) {
        Ok(symbols) => symbols,
        Err(e) => {
            panic!("nm failed: {e}");
        }
    };
    assert!(symbols.contains(&"_main".to_string()));
    assert!(symbols.contains(&"_helper".to_string()));
    assert!(
        !symbols.contains(&"_unused".to_string()),
        "dead-stripped symbol still present:\n{}",
        symbols.join("\n")
    );

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(unused_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn dead_strip_keeps_no_dead_strip_roots() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("dead-strip-no-dead-strip.o");
    let out_path = scratch("dead-strip-no-dead-strip.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .globl _keep
        _keep:
            ret
        .desc _keep, 0x20

        .globl _drop
        _drop:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let out = Command::new(exe)
        .arg("-dead_strip")
        .arg("-why_live")
        .arg("_keep")
        .arg("-why_live")
        .arg("_drop")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-dead_strip link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_keep is live because:"));
    assert!(stdout.contains("_keep is marked N_NO_DEAD_STRIP (GC root)"));
    assert!(stdout.contains("_drop is not live (dead-stripped)"));

    let symbols = match nm_defined_names(&out_path) {
        Ok(symbols) => symbols,
        Err(e) => {
            panic!("nm failed: {e}");
        }
    };
    assert!(symbols.contains(&"_main".to_string()));
    assert!(symbols.contains(&"_keep".to_string()));
    assert!(
        !symbols.contains(&"_drop".to_string()),
        "dead-stripped symbol still present:\n{}",
        symbols.join("\n")
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn icf_safe_flag_links_successfully() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = require_fixture!("assembly fixture", assemble_minimal_main("icf-safe-main.o"));
    let out_path = scratch("icf-safe.out");
    let out = Command::new(exe)
        .arg("-icf=safe")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-icf=safe link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out_path.is_file(),
        "expected -icf=safe link to produce {}",
        out_path.display()
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn icf_all_flag_errors_loudly() {
    assert_flag_errors(
        "-icf=all",
        "`-icf=all` is not yet supported; use `-icf=safe` or `-icf=none`",
        "icf-all",
    );
}

#[test]
fn fixup_chains_flag_errors_loudly() {
    assert_flag_errors(
        "-fixup_chains",
        "`-fixup_chains` is not yet supported",
        "fixup-chains",
    );
}

#[test]
fn undefined_symbol_diagnostic_is_not_double_prefixed() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
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

    let out = Command::new(exe)
        .arg("-o")
        .arg(scratch("missing.out"))
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: error: undefined symbol: _missing"),
        "missing expected undefined-symbol diagnostic:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: error: afs-ld: error:"),
        "diagnostic was double-prefixed:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
}

#[test]
fn undefined_warning_mode_links_and_warns_once() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-warning.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let out_path = scratch("missing-warning.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("warning")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined warning should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: undefined symbol: _missing"),
        "missing expected undefined-symbol warning:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: warning: afs-ld: warning:"),
        "warning diagnostic was double-prefixed:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn undefined_suppress_mode_links_silently() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-suppress.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let out_path = scratch("missing-suppress.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("suppress")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined suppress should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("undefined symbol: _missing"),
        "expected -undefined suppress to omit undefined diagnostic:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn trace_flag_prints_loaded_inputs_and_archive_members() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("trace-main.o");
    let helper_obj = scratch("trace-helper.o");
    let tail_obj = scratch("trace-tail.o");
    let archive_path = scratch("libtracehelpers.a");
    let out_path = scratch("trace.out");
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
    let tail_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _tail
        _tail:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(main_src, &main_obj));
    require_fixture!("assembly fixture", assemble(helper_src, &helper_obj));
    require_fixture!("assembly fixture", assemble(tail_src, &tail_obj));
    require_fixture!("archive fixture", archive(&[&helper_obj], &archive_path));

    let out = Command::new(exe)
        .arg("-t")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&archive_path)
        .arg(&tail_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "trace link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let main_pos = stderr
        .find(&format!("afs-ld: loading {}", main_obj.display()))
        .unwrap_or_else(|| panic!("missing main object trace:\n{stderr}"));
    let archive_pos = stderr
        .find(&format!("afs-ld: loading {}", archive_path.display()))
        .unwrap_or_else(|| panic!("missing archive trace:\n{stderr}"));
    let member_pos = stderr
        .find("libtracehelpers.a(")
        .unwrap_or_else(|| panic!("missing fetched archive member trace:\n{stderr}"));
    let tail_pos = stderr
        .find(&format!("afs-ld: loading {}", tail_obj.display()))
        .unwrap_or_else(|| panic!("missing tail object trace:\n{stderr}"));
    assert!(main_pos < archive_pos && archive_pos < member_pos && member_pos < tail_pos);

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(tail_obj);
    let _ = fs::remove_file(archive_path);
    let _ = fs::remove_file(out_path);
}

#[test]
fn mixed_library_and_positional_inputs_follow_command_line_order() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        harness_skip!("xcrun --show-sdk-path unavailable");
        return;
    };

    let root = scratch("mixed-input-order");
    fs::create_dir_all(&root).unwrap();
    let main_obj = root.join("main.o");
    let a_obj = root.join("a.o");
    let b_obj = root.join("b.o");
    let lib_a = root.join("libA.a");
    let lib_b = root.join("libB.a");
    let out_path = root.join("linked.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _choice
            ldp x29, x30, [sp], #16
            ret
        .subsections_via_symbols
    "#;
    let a_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _choice
        _choice:
            mov w0, #11
            ret
        .subsections_via_symbols
    "#;
    let b_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _choice
        _choice:
            mov w0, #22
            ret
        .subsections_via_symbols
    "#;

    for (src, object) in [(main_src, &main_obj), (a_src, &a_obj), (b_src, &b_obj)] {
        require_fixture!("assembly fixture", assemble(src, object));
    }
    require_fixture!("archive fixture", archive(&[&a_obj], &lib_a));
    require_fixture!("archive fixture", archive(&[&b_obj], &lib_b));

    let link = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-arch")
        .arg("arm64")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-L")
        .arg(&root)
        .arg(&main_obj)
        .arg("-lA")
        .arg(&lib_b)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("afs-ld should run");
    assert!(
        link.status.success(),
        "mixed-order link failed:\n{}",
        String::from_utf8_lossy(&link.stderr)
    );
    assert_eq!(
        Command::new(&out_path).status().unwrap().code(),
        Some(11),
        "the first archive on the command line must provide _choice"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn extensionless_dylib_is_dispatched_in_input_order() {
    let named_dylib = scratch("named-dylib.dylib");
    let extensionless_dylib = scratch("extensionless-dylib");
    let named_install_name = "@rpath/libnamed.dylib";
    let extensionless_install_name = "@rpath/libextensionless.dylib";
    fs::write(&named_dylib, synthetic_dylib(named_install_name)).unwrap();
    fs::write(
        &extensionless_dylib,
        synthetic_dylib(extensionless_install_name),
    )
    .unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("extensionless-dylib-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&named_dylib)
            .arg(&extensionless_dylib)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            result.status.success(),
            "extensionless dylib link failed with -j{jobs}:\n{stderr}"
        );
        let named_trace = stderr
            .find(&format!("afs-ld: loading {}", named_dylib.display()))
            .unwrap_or_else(|| panic!("missing named dylib trace with -j{jobs}:\n{stderr}"));
        let extensionless_trace = stderr
            .find(&format!(
                "afs-ld: loading {}",
                extensionless_dylib.display()
            ))
            .unwrap_or_else(|| panic!("missing extensionless trace with -j{jobs}:\n{stderr}"));
        assert!(named_trace < extensionless_trace);

        let bytes = fs::read(&output).unwrap();
        let header = parse_header(&bytes).unwrap();
        let commands = parse_commands(&header, &bytes).unwrap();
        let load_names: Vec<&str> = commands
            .iter()
            .filter_map(|command| match command {
                LoadCommand::Dylib(dylib) if dylib.cmd == LC_LOAD_DYLIB => {
                    Some(dylib.name.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            load_names,
            vec![named_install_name, extensionless_install_name]
        );
        let _ = fs::remove_file(output);
    }

    let _ = fs::remove_file(named_dylib);
    let _ = fs::remove_file(extensionless_dylib);
}

#[test]
fn extensionless_framework_preserves_weak_load_kind() {
    let root = scratch("extensionless-framework-root");
    let framework_dir = root.join("System/Library/Frameworks/Demo.framework");
    let framework = framework_dir.join("Demo");
    let install_name = "@rpath/Demo.framework/Demo";
    fs::create_dir_all(&framework_dir).unwrap();
    fs::write(&framework, synthetic_dylib(install_name)).unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("extensionless-framework-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-syslibroot")
            .arg(&root)
            .arg("-weak_framework")
            .arg("Demo")
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(
            result.status.success(),
            "extensionless framework link failed with -j{jobs}:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );

        let bytes = fs::read(&output).unwrap();
        let header = parse_header(&bytes).unwrap();
        let commands = parse_commands(&header, &bytes).unwrap();
        assert!(commands.iter().any(|command| {
            matches!(
                command,
                LoadCommand::Dylib(dylib)
                    if dylib.cmd == LC_LOAD_WEAK_DYLIB && dylib.name == install_name
            )
        }));
        let _ = fs::remove_file(output);
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn macho_parse_diagnostics_include_input_paths() {
    let valid = scratch("path-diagnostic-valid.o");
    fs::write(
        &valid,
        synthetic_symbol_object(&[("_main", N_ABS | N_EXT, 0)]),
    )
    .unwrap();

    for (name, bytes, context) in [
        (
            "path-diagnostic-header.o",
            vec![0xcf, 0xfa],
            "mach_header_64",
        ),
        (
            "path-diagnostic-object.o",
            synthetic_macho_with_truncated_commands(MH_OBJECT),
            "load-command region",
        ),
        (
            "path-diagnostic-dylib",
            synthetic_macho_with_truncated_commands(MH_DYLIB),
            "load-command region",
        ),
    ] {
        let malformed = scratch(name);
        fs::write(&malformed, bytes).unwrap();
        for jobs in [1, 4] {
            let output = scratch(&format!("{name}-{jobs}.out"));
            let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
                .arg("-j")
                .arg(jobs.to_string())
                .arg(&valid)
                .arg(&malformed)
                .arg("-o")
                .arg(&output)
                .output()
                .expect("afs-ld should run");
            assert!(!result.status.success());
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(
                stderr.contains(&malformed.display().to_string()),
                "missing malformed input path with -j{jobs}:\n{stderr}"
            );
            assert!(
                stderr.contains(&format!("truncated input while reading {context}")),
                "missing parse context with -j{jobs}:\n{stderr}"
            );
            let _ = fs::remove_file(output);
        }
        let _ = fs::remove_file(malformed);
    }

    let _ = fs::remove_file(valid);
}

#[test]
fn malformed_dylib_identities_are_rejected_without_output() {
    let cases = [
        ("missing", Vec::new(), "missing LC_ID_DYLIB load command"),
        ("empty", vec![""], "LC_ID_DYLIB install name is empty"),
        (
            "duplicate",
            vec!["@rpath/libfirst.dylib", "@rpath/libsecond.dylib"],
            "multiple LC_ID_DYLIB load commands",
        ),
    ];

    for (case, install_names, expected) in cases {
        let input = scratch(&format!("invalid-dylib-id-{case}.dylib"));
        fs::write(&input, synthetic_dylib_with_ids(&install_names)).unwrap();

        for jobs in [1, 4] {
            let output = scratch(&format!("invalid-dylib-id-{case}-{jobs}.dylib"));
            let _ = fs::remove_file(&output);
            let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
                .arg("-dylib")
                .arg("-j")
                .arg(jobs.to_string())
                .arg(&input)
                .arg("-o")
                .arg(&output)
                .output()
                .expect("afs-ld should run");
            let stderr = String::from_utf8_lossy(&result.stderr);

            assert!(
                !result.status.success(),
                "malformed {case} identity was accepted with -j{jobs}"
            );
            assert!(
                stderr.contains(&input.display().to_string()),
                "missing malformed dylib path with -j{jobs}:\n{stderr}"
            );
            assert!(
                stderr.contains(expected),
                "unexpected malformed {case} diagnostic with -j{jobs}:\n{stderr}"
            );
            assert!(
                !output.exists(),
                "rejected {case} identity left an output with -j{jobs}"
            );
        }

        let _ = fs::remove_file(input);
    }
}

#[test]
fn malformed_tbd_versions_are_rejected_without_output() {
    let cases = [
        ("nondigit", "current-version", "1.x.3"),
        ("empty", "compatibility-version", ""),
        ("extra-component", "current-version", "1.2.3.4"),
        ("major-overflow", "compatibility-version", "65536"),
        ("minor-overflow", "current-version", "1.256"),
        ("patch-overflow", "compatibility-version", "1.2.256"),
        ("integer-overflow", "current-version", "4294967296"),
    ];

    for (case, field, value) in cases {
        let input = scratch(&format!("invalid-tbd-version-{case}.tbd"));
        fs::write(
            &input,
            format!(
                "--- !tapi-tbd\n\
                 tbd-version: 4\n\
                 targets: [ arm64-macos ]\n\
                 install-name: '/usr/lib/libbad.dylib'\n\
                 {field}: '{value}'\n\
                 ...\n"
            ),
        )
        .unwrap();

        for jobs in [1, 4] {
            let output = scratch(&format!("invalid-tbd-version-{case}-{jobs}.dylib"));
            let _ = fs::remove_file(&output);
            let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
                .arg("-dylib")
                .arg("-j")
                .arg(jobs.to_string())
                .arg(&input)
                .arg("-o")
                .arg(&output)
                .output()
                .expect("afs-ld should run");
            let stderr = String::from_utf8_lossy(&result.stderr);

            assert!(
                !result.status.success(),
                "{case} {field} {value:?} was accepted with -j{jobs}"
            );
            assert!(
                stderr.contains(&input.display().to_string()),
                "missing malformed TBD path with -j{jobs}:\n{stderr}"
            );
            assert!(
                stderr.contains(field) && stderr.contains(&format!("{value:?}")),
                "unexpected {case} {field} diagnostic with -j{jobs}:\n{stderr}"
            );
            assert!(
                !output.exists(),
                "rejected {case} {field} left an output with -j{jobs}"
            );
        }

        let _ = fs::remove_file(input);
    }
}

#[test]
fn maximum_tbd_versions_are_preserved_deterministically() {
    let input = scratch("maximum-tbd-version.tbd");
    let install_name = "/usr/lib/libmaximum-version.dylib";
    fs::write(
        &input,
        format!(
            "--- !tapi-tbd\n\
             tbd-version: 4\n\
             targets: [ arm64-macos ]\n\
             install-name: '{install_name}'\n\
             current-version: 65535.255.255\n\
             compatibility-version: 65535.255\n\
             ...\n"
        ),
    )
    .unwrap();

    let mut images = Vec::new();
    let output = scratch("maximum-tbd-version-output.dylib");
    for jobs in [1, 4] {
        let _ = fs::remove_file(&output);
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(
            result.status.success(),
            "maximum legal TBD version failed with -j{jobs}:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );

        let image = fs::read(&output).unwrap();
        let header = parse_header(&image).unwrap();
        let commands = parse_commands(&header, &image).unwrap();
        let load = commands
            .iter()
            .find_map(|command| match command {
                LoadCommand::Dylib(dylib)
                    if dylib.cmd == LC_LOAD_DYLIB && dylib.name == install_name =>
                {
                    Some(dylib)
                }
                _ => None,
            })
            .expect("linked image must load the TBD install name");
        assert_eq!(load.current_version, u32::MAX);
        assert_eq!(load.compatibility_version, 0xffff_ff00);
        images.push(image);
        let _ = fs::remove_file(&output);
    }
    assert!(images[0] == images[1], "-j1 and -j4 outputs differ");

    let _ = fs::remove_file(input);
}

#[test]
fn double_quoted_utf8_tbd_symbol_resolves_deterministically() {
    let object = scratch("utf8-tbd-symbol.o");
    let tbd = scratch("utf8-tbd-symbol.tbd");
    let output = scratch("utf8-tbd-symbol.dylib");
    let symbol = "_café";
    fs::write(&object, synthetic_undefined_object(symbol)).unwrap();
    fs::write(
        &tbd,
        format!(
            "--- !tapi-tbd\n\
             tbd-version: 4\n\
             targets: [ arm64-macos ]\n\
             install-name: '/usr/lib/libutf8-symbol.dylib'\n\
             exports:\n\
             \x20 - targets: [ arm64-macos ]\n\
             \x20   symbols: [ \"{symbol}\" ]\n\
             ...\n"
        ),
    )
    .unwrap();

    let mut images = Vec::new();
    for jobs in [1, 4] {
        let _ = fs::remove_file(&output);
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&object)
            .arg(&tbd)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(
            result.status.success(),
            "double-quoted UTF-8 TBD symbol failed with -j{jobs}:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let image = fs::read(&output).unwrap();
        let header = parse_header(&image).unwrap();
        let commands = parse_commands(&header, &image).unwrap();
        assert!(commands.iter().any(|command| matches!(
            command,
            LoadCommand::Dylib(dylib)
                if dylib.cmd == LC_LOAD_DYLIB
                    && dylib.name == "/usr/lib/libutf8-symbol.dylib"
        )));
        images.push(image);
    }
    assert_eq!(images[0], images[1], "-j1 and -j4 outputs differ");

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(tbd);
    let _ = fs::remove_file(output);
}

#[test]
fn legacy_dysymtab_dylib_symbol_resolves_deterministically() {
    let object = scratch("legacy-dysymtab-symbol.o");
    let dylib = scratch("legacy-dysymtab-symbol.dylib");
    let output = scratch("legacy-dysymtab-consumer.dylib");
    let symbol = "_legacy_export";
    let install_name = "/usr/lib/liblegacy-dysymtab.dylib";
    fs::write(&object, synthetic_undefined_object(symbol)).unwrap();
    fs::write(&dylib, synthetic_legacy_dylib(symbol, install_name)).unwrap();

    let mut images = Vec::new();
    for jobs in [1, 4] {
        let _ = fs::remove_file(&output);
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&object)
            .arg(&dylib)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(
            result.status.success(),
            "legacy LC_DYSYMTAB export failed with -j{jobs}:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let image = fs::read(&output).unwrap();
        let header = parse_header(&image).unwrap();
        let commands = parse_commands(&header, &image).unwrap();
        assert!(commands.iter().any(|command| matches!(
            command,
            LoadCommand::Dylib(dylib)
                if dylib.cmd == LC_LOAD_DYLIB && dylib.name == install_name
        )));
        images.push(image);
    }
    assert_eq!(images[0], images[1], "-j1 and -j4 outputs differ");

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(dylib);
    let _ = fs::remove_file(output);
}

#[test]
fn short_export_terminal_is_rejected_without_replacing_output() {
    const SENTINEL: &[u8] = b"previous complete Mach-O output";

    let dir = scratch("short-export-terminal");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let object = dir.join("consumer.o");
    let dylib = dir.join("malformed.dylib");
    let output = dir.join("consumer.dylib");
    let symbol = "_forged";

    // Root edge `_forged` points to a leaf whose one-byte payload contains
    // only flags. The final zero belongs to child_count, not the address.
    let mut trie = vec![0, 1];
    trie.extend_from_slice(symbol.as_bytes());
    trie.push(0);
    let leaf_offset = trie.len() + 1;
    assert!(leaf_offset < 0x80);
    trie.push(leaf_offset as u8);
    trie.extend_from_slice(&[1, 0, 0]);

    fs::write(&object, synthetic_undefined_object(symbol)).unwrap();
    fs::write(
        &dylib,
        synthetic_export_trie_dylib("/usr/lib/libmalformed-export.dylib", &trie),
    )
    .unwrap();

    for jobs in [1, 4] {
        fs::write(&output, SENTINEL).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&object)
            .arg(&dylib)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        let stderr = String::from_utf8_lossy(&result.stderr);

        assert!(
            !result.status.success(),
            "short export terminal was accepted with -j{jobs}"
        );
        assert!(
            stderr.contains("truncated input while reading ULEB128 (unterminated)"),
            "missing terminal-payload diagnostic with -j{jobs}:\n{stderr}"
        );
        assert_eq!(
            fs::read(&output).unwrap(),
            SENTINEL,
            "rejected export terminal replaced prior output with -j{jobs}"
        );
        assert!(
            fs::read_dir(&dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("afs-ld-tmp")),
            "rejected export terminal leaked a temporary output with -j{jobs}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn linker_rejects_non_linkable_macho_filetypes() {
    for (stem, filetype, filetype_name) in [
        ("execute", MH_EXECUTE, "MH_EXECUTE"),
        ("dylinker", MH_DYLINKER, "MH_DYLINKER"),
        ("bundle", MH_BUNDLE, "MH_BUNDLE"),
    ] {
        let input = scratch(&format!("non-linkable-{stem}"));
        fs::write(
            &input,
            synthetic_text_macho_with_filetype("_not_an_object", filetype),
        )
        .unwrap();

        for jobs in [1, 4] {
            let output = scratch(&format!("non-linkable-{stem}-{jobs}.dylib"));
            let _ = fs::remove_file(&output);
            let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
                .arg("-dylib")
                .arg("-j")
                .arg(jobs.to_string())
                .arg("-o")
                .arg(&output)
                .arg(&input)
                .output()
                .expect("afs-ld should run");
            let stderr = String::from_utf8_lossy(&result.stderr);

            assert!(
                !result.status.success(),
                "{filetype_name} input was accepted with -j{jobs}"
            );
            assert!(
                stderr.contains(&input.display().to_string()),
                "missing input path with -j{jobs}:\n{stderr}"
            );
            assert!(
                stderr.contains(filetype_name) && stderr.contains("expected MH_OBJECT or MH_DYLIB"),
                "unexpected {filetype_name} diagnostic with -j{jobs}:\n{stderr}"
            );
            assert!(
                !output.exists(),
                "rejected {filetype_name} input left an output with -j{jobs}"
            );
        }

        let _ = fs::remove_file(input);
    }
}

#[test]
fn archive_members_must_be_relocatable_macho_objects() {
    let archive = scratch("non-object-member.a");
    let member_name = "final-image.o/";
    fs::write(
        &archive,
        synthetic_indexed_archive(
            "_final_image",
            member_name,
            &synthetic_text_macho_with_filetype("_final_image", MH_EXECUTE),
        ),
    )
    .unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("non-object-member-{jobs}.dylib"));
        let _ = fs::remove_file(&output);
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-all_load")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-o")
            .arg(&output)
            .arg(&archive)
            .output()
            .expect("afs-ld should run");
        let stderr = String::from_utf8_lossy(&result.stderr);

        assert!(
            !result.status.success(),
            "MH_EXECUTE archive member was accepted with -j{jobs}"
        );
        assert!(
            stderr.contains(&archive.display().to_string()) && stderr.contains("final-image.o"),
            "missing archive-member path with -j{jobs}:\n{stderr}"
        );
        assert!(
            stderr.contains("MH_EXECUTE") && stderr.contains("expected MH_OBJECT"),
            "unexpected archive-member diagnostic with -j{jobs}:\n{stderr}"
        );
        assert!(
            !output.exists(),
            "rejected archive member left an output with -j{jobs}"
        );
    }

    let _ = fs::remove_file(archive);
}

#[test]
fn dump_still_inspects_final_macho_images() {
    let input = scratch("dump-final-image");
    fs::write(
        &input,
        synthetic_text_macho_with_filetype("_main", MH_EXECUTE),
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("--dump")
        .arg(&input)
        .output()
        .expect("afs-ld should run");
    assert!(
        result.status.success(),
        "dump rejected a final Mach-O image:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("MH_EXECUTE"));

    let _ = fs::remove_file(input);
}

fn assert_dump_rejects(
    name: &str,
    bytes: Vec<u8>,
    expected_error: &str,
    forbidden_placeholder: &str,
) {
    let input = scratch(name);
    fs::write(&input, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("--dump")
        .arg(&input)
        .output()
        .expect("afs-ld should run");
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "dump accepted malformed input {name}:\n{stdout}"
    );
    assert!(
        stderr.contains(expected_error),
        "dump diagnostic for {name} omitted {expected_error:?}:\n{stderr}"
    );
    assert!(
        !stdout.contains(forbidden_placeholder),
        "dump reduced malformed input {name} to placeholder output:\n{stdout}"
    );

    let _ = fs::remove_file(input);
}

#[test]
fn dump_rejects_malformed_relocations() {
    assert_dump_rejects(
        "dump-malformed-relocation.o",
        synthetic_text_object_with_relocations(
            "_main",
            &[RawRelocation {
                r_address: 0,
                r_symbolnum: 1,
                r_pcrel: false,
                r_length: 2,
                r_extern: false,
                r_type: ARM64_RELOC_ADDEND,
            }],
        ),
        "trailing ARM64_RELOC_ADDEND with no following primary",
        "<parse error:",
    );
}

#[test]
fn dump_rejects_invalid_symbol_names() {
    assert_dump_rejects(
        "dump-malformed-symbol.o",
        synthetic_text_object_with_invalid_symbol_name(),
        "strx out of bounds",
        "<unresolved>",
    );
}

#[test]
fn input_errors_follow_command_line_order() {
    let malformed = scratch("ordered-error-input.o");
    fs::write(&malformed, [0_u8; 32]).unwrap();
    let missing_library = "afs_ld_ordering_fixture_that_does_not_exist";

    let malformed_first = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg(&malformed)
        .arg(format!("-l{missing_library}"))
        .output()
        .expect("afs-ld should run");
    assert!(!malformed_first.status.success());
    let stderr = String::from_utf8_lossy(&malformed_first.stderr);
    assert!(
        stderr.contains("not a Mach-O 64 file"),
        "earlier malformed input should win:\n{stderr}"
    );
    assert!(!stderr.contains("unable to find library"));

    let missing_first = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg(format!("-l{missing_library}"))
        .arg(&malformed)
        .output()
        .expect("afs-ld should run");
    assert!(!missing_first.status.success());
    let stderr = String::from_utf8_lossy(&missing_first.stderr);
    assert!(
        stderr.contains(&format!("unable to find library `{missing_library}`")),
        "earlier missing library should win:\n{stderr}"
    );
    assert!(!stderr.contains("not a Mach-O 64 file"));

    let _ = fs::remove_file(malformed);
}

#[test]
fn trace_precedes_archive_member_parse_error() {
    let main = scratch("trace-error-main.o");
    let archive = scratch("trace-error-lib.a");
    fs::write(&main, synthetic_undefined_object("_bad")).unwrap();
    fs::write(&archive, synthetic_malformed_archive("_bad")).unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("trace-error-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&main)
            .arg(&archive)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        let main_trace = stderr
            .find(&format!("afs-ld: loading {}", main.display()))
            .unwrap_or_else(|| panic!("missing main trace with -j{jobs}:\n{stderr}"));
        let archive_trace = stderr
            .find(&format!("afs-ld: loading {}", archive.display()))
            .unwrap_or_else(|| panic!("missing archive trace with -j{jobs}:\n{stderr}"));
        let diagnostic = stderr
            .find("not a Mach-O 64 file")
            .unwrap_or_else(|| panic!("missing member parse error with -j{jobs}:\n{stderr}"));
        assert!(main_trace < archive_trace && archive_trace < diagnostic);
        let _ = fs::remove_file(output);
    }

    let _ = fs::remove_file(main);
    let _ = fs::remove_file(archive);
}

#[test]
fn force_load_trace_precedes_member_parse_error() {
    let archive = scratch("force-trace-error-lib");
    fs::write(&archive, synthetic_malformed_archive("_bad")).unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("force-trace-error-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-force_load")
            .arg(&archive)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        let archive_trace = stderr
            .find(&format!("afs-ld: loading {}", archive.display()))
            .unwrap_or_else(|| panic!("missing forced archive trace with -j{jobs}:\n{stderr}"));
        let diagnostic = stderr
            .find("not a Mach-O 64 file")
            .unwrap_or_else(|| panic!("missing forced member error with -j{jobs}:\n{stderr}"));
        assert!(archive_trace < diagnostic);
        let _ = fs::remove_file(output);
    }

    let _ = fs::remove_file(archive);
}

#[test]
fn force_load_resolves_references_from_later_archive() {
    let forced_archive = scratch("force-order-first");
    let later_archive = scratch("force-order-later.a");
    let forced_member = synthetic_symbol_object(&[
        ("_forced", N_ABS | N_EXT, 11),
        ("_later", N_UNDF | N_EXT, 0),
    ]);
    let later_member = synthetic_symbol_object(&[("_later", N_ABS | N_EXT, 22)]);
    fs::write(
        &forced_archive,
        synthetic_indexed_archive("_forced", "forced.o/", &forced_member),
    )
    .unwrap();
    fs::write(
        &later_archive,
        synthetic_indexed_archive("_later", "later.o/", &later_member),
    )
    .unwrap();

    for jobs in [1, 4] {
        let output = scratch(&format!("force-order-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-force_load")
            .arg(&forced_archive)
            .arg(&later_archive)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            result.status.success(),
            "later archive did not resolve the forced member with -j{jobs}:\n{stderr}"
        );
        assert!(!stderr.contains("undefined symbol: _later"));

        let forced = stderr
            .find(&format!("afs-ld: loading {}", forced_archive.display()))
            .unwrap_or_else(|| panic!("missing forced archive trace with -j{jobs}:\n{stderr}"));
        let forced_member = stderr
            .find(&format!("{}(forced.o)", forced_archive.display()))
            .unwrap_or_else(|| panic!("missing forced member trace with -j{jobs}:\n{stderr}"));
        let later = stderr
            .find(&format!("afs-ld: loading {}", later_archive.display()))
            .unwrap_or_else(|| panic!("missing later archive trace with -j{jobs}:\n{stderr}"));
        let later_member = stderr
            .find(&format!("{}(later.o)", later_archive.display()))
            .unwrap_or_else(|| panic!("missing later member trace with -j{jobs}:\n{stderr}"));
        assert!(forced < forced_member && forced_member < later && later < later_member);
        let _ = fs::remove_file(output);
    }

    let _ = fs::remove_file(forced_archive);
    let _ = fs::remove_file(later_archive);
}

#[test]
fn thin_archive_loads_external_macho_members() {
    let root = scratch("thin-macho-root");
    let member_relative = PathBuf::from("members/thin_member_with_a_long_name.o");
    let member = root.join(&member_relative);
    let main = root.join("main.o");
    let archive = root.join("libthin.a");
    fs::create_dir_all(member.parent().unwrap()).unwrap();
    fs::write(&main, synthetic_undefined_object("_thin_symbol")).unwrap();
    let member_bytes = synthetic_symbol_object(&[("_thin_symbol", N_ABS | N_EXT, 37)]);
    fs::write(&member, &member_bytes).unwrap();
    fs::write(
        &archive,
        synthetic_thin_archive(
            "_thin_symbol",
            member_relative.to_str().unwrap(),
            member_bytes.len(),
        ),
    )
    .unwrap();

    let nested_member_name = "nested.o";
    let nested_source = root.join("nested-source.a");
    let nested_source_bytes = synthetic_indexed_archive("_thin_symbol", "nested.o/", &member_bytes);
    let nested_member_offset = afs_ld::archive::Archive::open(&nested_source, &nested_source_bytes)
        .unwrap()
        .object_members()
        .next()
        .unwrap()
        .header_offset as u64;
    fs::write(&nested_source, &nested_source_bytes).unwrap();
    let nested_archive = root.join("libthin-nested.a");
    fs::write(
        &nested_archive,
        synthetic_thin_archive_reference(
            "_thin_symbol",
            nested_source.file_name().unwrap().to_str().unwrap(),
            member_bytes.len(),
            Some(nested_member_offset),
        ),
    )
    .unwrap();

    let inner_thin = root.join("libthin-inner.a");
    let inner_thin_bytes = synthetic_thin_archive(
        "_thin_symbol",
        member_relative.to_str().unwrap(),
        member_bytes.len(),
    );
    let inner_member_offset = afs_ld::archive::Archive::open(&inner_thin, &inner_thin_bytes)
        .unwrap()
        .object_members()
        .next()
        .unwrap()
        .header_offset as u64;
    fs::write(&inner_thin, inner_thin_bytes).unwrap();
    let recursive_archive = root.join("libthin-recursive.a");
    fs::write(
        &recursive_archive,
        synthetic_thin_archive_reference(
            "_thin_symbol",
            inner_thin.file_name().unwrap().to_str().unwrap(),
            member_bytes.len(),
            Some(inner_member_offset),
        ),
    )
    .unwrap();

    for jobs in [1, 4] {
        let output = root.join(format!("thin-lazy-{jobs}.out"));
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&main)
            .arg(&archive)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("afs-ld should run");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            result.status.success(),
            "thin archive lazy link failed with -j{jobs}:\n{stderr}"
        );
        let main_trace = stderr
            .find(&format!("afs-ld: loading {}", main.display()))
            .unwrap_or_else(|| panic!("missing main trace with -j{jobs}:\n{stderr}"));
        let archive_trace = stderr
            .find(&format!("afs-ld: loading {}", archive.display()))
            .unwrap_or_else(|| panic!("missing thin archive trace with -j{jobs}:\n{stderr}"));
        let member_trace = stderr
            .find(&format!("afs-ld: loading {}", member.display()))
            .unwrap_or_else(|| panic!("missing external member trace with -j{jobs}:\n{stderr}"));
        assert!(main_trace < archive_trace && archive_trace < member_trace);

        let force_output = root.join(format!("thin-force-{jobs}.out"));
        let forced = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-force_load")
            .arg(&archive)
            .arg("-o")
            .arg(&force_output)
            .output()
            .expect("afs-ld should run");
        let force_stderr = String::from_utf8_lossy(&forced.stderr);
        assert!(
            forced.status.success(),
            "thin archive force-load failed with -j{jobs}:\n{force_stderr}"
        );
        let archive_trace = force_stderr
            .find(&format!("afs-ld: loading {}", archive.display()))
            .unwrap_or_else(|| {
                panic!("missing forced archive trace with -j{jobs}:\n{force_stderr}")
            });
        let member_trace = force_stderr
            .find(&format!("afs-ld: loading {}", member.display()))
            .unwrap_or_else(|| {
                panic!("missing forced member trace with -j{jobs}:\n{force_stderr}")
            });
        assert!(archive_trace < member_trace);

        let nested_output = root.join(format!("thin-nested-lazy-{jobs}.out"));
        let nested = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&main)
            .arg(&nested_archive)
            .arg("-o")
            .arg(&nested_output)
            .output()
            .expect("afs-ld should run");
        let nested_stderr = String::from_utf8_lossy(&nested.stderr);
        assert!(
            nested.status.success(),
            "nested thin archive lazy link failed with -j{jobs}:\n{nested_stderr}"
        );
        assert!(
            nested_stderr.contains(&format!(
                "{}({nested_member_name})",
                nested_source.display()
            )),
            "{nested_stderr}"
        );

        let nested_force_output = root.join(format!("thin-nested-force-{jobs}.out"));
        let nested_forced = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-force_load")
            .arg(&nested_archive)
            .arg("-o")
            .arg(&nested_force_output)
            .output()
            .expect("afs-ld should run");
        let nested_force_stderr = String::from_utf8_lossy(&nested_forced.stderr);
        assert!(
            nested_forced.status.success(),
            "nested thin archive force-load failed with -j{jobs}:\n{nested_force_stderr}"
        );
        assert!(
            nested_force_stderr.contains(&format!(
                "{}({nested_member_name})",
                nested_source.display()
            )),
            "{nested_force_stderr}"
        );

        let recursive_output = root.join(format!("thin-recursive-lazy-{jobs}.out"));
        let recursive = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&main)
            .arg(&recursive_archive)
            .arg("-o")
            .arg(&recursive_output)
            .output()
            .expect("afs-ld should run");
        let recursive_stderr = String::from_utf8_lossy(&recursive.stderr);
        assert!(
            recursive.status.success(),
            "recursive thin archive lazy link failed with -j{jobs}:\n{recursive_stderr}"
        );
        assert!(
            recursive_stderr.contains(&format!("afs-ld: loading {}", member.display())),
            "{recursive_stderr}"
        );

        let recursive_force_output = root.join(format!("thin-recursive-force-{jobs}.out"));
        let recursive_forced = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-t")
            .arg("-j")
            .arg(jobs.to_string())
            .arg("-force_load")
            .arg(&recursive_archive)
            .arg("-o")
            .arg(&recursive_force_output)
            .output()
            .expect("afs-ld should run");
        let recursive_force_stderr = String::from_utf8_lossy(&recursive_forced.stderr);
        assert!(
            recursive_forced.status.success(),
            "recursive thin archive force-load failed with -j{jobs}:\n{recursive_force_stderr}"
        );
        assert!(
            recursive_force_stderr.contains(&format!("afs-ld: loading {}", member.display())),
            "{recursive_force_stderr}"
        );
    }

    fs::remove_file(&member).unwrap();
    for jobs in [1, 4] {
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-dylib")
            .arg("-j")
            .arg(jobs.to_string())
            .arg(&main)
            .arg(&archive)
            .output()
            .expect("afs-ld should run");
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(&member.display().to_string()), "{stderr}");
        assert!(stderr.contains("thin archive member I/O"), "{stderr}");
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn common_symbols_allocate_coalesced_zerofill_storage() {
    let first = scratch("common-first.o");
    let second = scratch("common-second.o");
    let output = scratch("common-output.dylib");
    fs::write(
        &first,
        synthetic_symbol_object_with_desc(&[
            ("_shared", N_UNDF | N_EXT, 5 << 8, 8),
            ("_unused", N_UNDF | N_EXT, 4 << 8, 24),
        ]),
    )
    .unwrap();
    fs::write(
        &second,
        synthetic_symbol_object_with_desc(&[("_shared", N_UNDF | N_EXT, 3 << 8, 32)]),
    )
    .unwrap();

    let inputs = [
        InputSpec::Path(first.clone()),
        InputSpec::Path(second.clone()),
    ];
    let mut baseline = None;
    for jobs in [1, 4] {
        let opts = LinkOptions {
            kind: OutputKind::Dylib,
            install_name: Some("@rpath/libcommon.dylib".to_string()),
            emit_uuid: false,
            jobs: Some(jobs),
            output: Some(output.clone()),
            ..LinkOptions::default()
        };
        Linker::run_ordered(&opts, &inputs).unwrap();
        let bytes = fs::read(&output).unwrap();
        if let Some(expected) = &baseline {
            assert_eq!(&bytes, expected, "COMMON layout changed with -j{jobs}");
        } else {
            baseline = Some(bytes.clone());
        }

        let header = parse_header(&bytes).unwrap();
        let commands = parse_commands(&header, &bytes).unwrap();
        let mut section_ordinal = 0_u8;
        let mut common = None;
        let mut symtab = None;
        for command in &commands {
            match command {
                LoadCommand::Segment64(segment) => {
                    for section in &segment.sections {
                        section_ordinal += 1;
                        if section.segname_str() == "__DATA" && section.sectname_str() == "__common"
                        {
                            common = Some((section_ordinal, section.clone()));
                        }
                    }
                }
                LoadCommand::Symtab(command) => symtab = Some(*command),
                _ => {}
            }
        }
        let (common_ordinal, common) = common.expect("missing __DATA,__common");
        assert_eq!(common.flags & SECTION_TYPE_MASK, S_ZEROFILL);
        assert_eq!(common.offset, 0);
        assert_eq!(common.align, 4);
        assert_eq!(common.size, 56);

        let symtab = symtab.unwrap();
        let symbols = parse_nlist_table(&bytes, symtab.symoff, symtab.nsyms).unwrap();
        let strings = StringTable::from_file(&bytes, symtab.stroff, symtab.strsize).unwrap();
        let symbol = |name: &str| {
            symbols
                .iter()
                .find(|symbol| strings.get(symbol.strx()).is_ok_and(|found| found == name))
                .unwrap_or_else(|| panic!("missing output symbol {name}"))
        };
        let shared = symbol("_shared");
        let unused = symbol("_unused");
        for symbol in [shared, unused] {
            assert_eq!(symbol.kind(), SymKind::Sect);
            assert!(symbol.is_ext());
            assert_eq!(symbol.raw.n_type, N_SECT | N_EXT);
            assert_eq!(symbol.sect_idx(), common_ordinal);
            assert!(
                (common.addr..common.addr + common.size).contains(&symbol.value()),
                "symbol is outside __DATA,__common"
            );
        }
        assert_eq!(unused.value(), common.addr);
        assert_eq!(shared.value(), common.addr + 24);
    }

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
    let _ = fs::remove_file(output);
}

#[test]
fn oversized_common_symbol_is_rejected_before_output() {
    let object = scratch("oversized-common.o");
    let output = scratch("oversized-common.dylib");
    let _ = fs::remove_file(&output);
    fs::write(
        &object,
        synthetic_symbol_object(&[("_huge", N_UNDF | N_EXT, u32::MAX as u64 + 1)]),
    )
    .unwrap();
    let opts = LinkOptions {
        kind: OutputKind::Dylib,
        install_name: Some("@rpath/liboversized-common.dylib".to_string()),
        output: Some(output.clone()),
        ..LinkOptions::default()
    };

    let error = Linker::run_ordered(&opts, &[InputSpec::Path(object.clone())]).unwrap_err();

    assert!(matches!(
        error,
        LinkError::CommonMaterialization(ref error)
            if error.symbol == "_huge" && error.size == u32::MAX as u64 + 1
    ));
    assert!(!output.exists());
    let _ = fs::remove_file(object);
}

#[test]
fn private_retained_common_survives_dead_strip_without_exporting() {
    let object = scratch("private-retained-common.o");
    let output = scratch("private-retained-common.dylib");
    fs::write(
        &object,
        synthetic_symbol_object_with_desc(&[(
            "_private_common",
            N_UNDF | N_EXT | N_PEXT,
            (3 << 8) | N_NO_DEAD_STRIP,
            8,
        )]),
    )
    .unwrap();
    let opts = LinkOptions {
        kind: OutputKind::Dylib,
        install_name: Some("@rpath/libprivate-common.dylib".to_string()),
        dead_strip: true,
        emit_uuid: false,
        output: Some(output.clone()),
        ..LinkOptions::default()
    };

    Linker::run_ordered(&opts, &[InputSpec::Path(object.clone())]).unwrap();

    let bytes = fs::read(&output).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut common_ordinal = None;
    let mut section_ordinal = 0_u8;
    let mut symtab = None;
    for command in &commands {
        match command {
            LoadCommand::Segment64(segment) => {
                for section in &segment.sections {
                    section_ordinal += 1;
                    if section.segname_str() == "__DATA" && section.sectname_str() == "__common" {
                        common_ordinal = Some(section_ordinal);
                    }
                }
            }
            LoadCommand::Symtab(command) => symtab = Some(*command),
            _ => {}
        }
    }
    let symtab = symtab.unwrap();
    let symbols = parse_nlist_table(&bytes, symtab.symoff, symtab.nsyms).unwrap();
    let strings = StringTable::from_file(&bytes, symtab.stroff, symtab.strsize).unwrap();
    let symbol = symbols
        .iter()
        .find(|symbol| {
            strings
                .get(symbol.strx())
                .is_ok_and(|name| name == "_private_common")
        })
        .expect("missing retained private COMMON symbol");
    assert_eq!(symbol.raw.n_type, N_SECT | N_PEXT);
    assert_eq!(symbol.sect_idx(), common_ordinal.unwrap());
    assert_ne!(symbol.raw.n_desc & N_NO_DEAD_STRIP, 0);
    let exports = DylibFile::parse(output.clone(), &bytes)
        .unwrap()
        .exports
        .entries()
        .unwrap();
    assert!(!exports.iter().any(|entry| entry.name == "_private_common"));

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(output);
}

#[test]
fn common_symbols_reject_file_backed_common_section_collision() {
    let object = scratch("regular-common-section.o");
    let output = scratch("regular-common-section.dylib");
    let _ = fs::remove_file(&output);
    fs::write(&object, synthetic_common_with_regular_common_section()).unwrap();
    let opts = LinkOptions {
        kind: OutputKind::Dylib,
        install_name: Some("@rpath/libregular-common-section.dylib".to_string()),
        output: Some(output.clone()),
        ..LinkOptions::default()
    };

    let error = Linker::run_ordered(&opts, &[InputSpec::Path(object.clone())]).unwrap_err();

    assert!(matches!(
        error,
        LinkError::IncompatibleCommonSection(ref path) if path == &object
    ));
    assert!(!output.exists());
    let _ = fs::remove_file(object);
}

#[test]
fn force_load_rejects_non_archive_input() {
    let object = scratch("force-load-not-archive.o");
    fs::write(&object, synthetic_undefined_object("_missing")).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-force_load")
        .arg(&object)
        .output()
        .expect("afs-ld should run");
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("-force_load requires a static archive"),
        "unexpected diagnostic:\n{stderr}"
    );
    assert!(!stderr.contains("no input files"));

    let _ = fs::remove_file(object);
}

#[test]
fn ordered_api_applies_configured_force_load_archives() {
    let object = scratch("ordered-api-force-main.o");
    let archive = scratch("ordered-api-force.a");
    fs::write(
        &object,
        synthetic_symbol_object(&[("_duplicate", N_ABS | N_EXT, 1)]),
    )
    .unwrap();
    fs::write(
        &archive,
        synthetic_indexed_archive(
            "_duplicate",
            "duplicate.o/",
            &synthetic_symbol_object(&[("_duplicate", N_ABS | N_EXT, 2)]),
        ),
    )
    .unwrap();

    let opts = LinkOptions {
        force_load_archives: vec![archive.clone()],
        ..LinkOptions::default()
    };
    let specs = [
        InputSpec::Path(object.clone()),
        InputSpec::Path(archive.clone()),
    ];
    let error = Linker::run_ordered(&opts, &specs).unwrap_err();
    assert!(matches!(error, LinkError::DuplicateSymbols(_)));

    let _ = fs::remove_file(object);
    let _ = fs::remove_file(archive);
}

#[test]
fn why_live_reports_root_entry_symbol() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-root-main.o");
    let out_path = scratch("why-live-root.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &main_obj));

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_main")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_main is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_transitive_symbol_chain() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-main.o");
    let helper_obj = scratch("why-live-helper.o");
    let leaf_obj = scratch("why-live-leaf.o");
    let out_path = scratch("why-live.out");
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
            bl _leaf
            ret
        .subsections_via_symbols
    "#;
    let leaf_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _leaf
        _leaf:
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(main_src, &main_obj));
    require_fixture!("assembly fixture", assemble(helper_src, &helper_obj));
    require_fixture!("assembly fixture", assemble(leaf_src, &leaf_obj));

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_leaf")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&helper_obj)
        .arg(&leaf_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_leaf is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_leaf is reachable from _helper"));
    assert!(stdout.contains("_helper is reachable from _main"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(leaf_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_folded_symbol_winner_chain() {
    if !have_xcrun() {
        harness_skip!("xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("why-live-folded.o");
    let out_path = scratch("why-live-folded.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper1
            bl _helper2
            mov w0, #0
            ldp x29, x30, [sp], #16
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #0
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    require_fixture!("assembly fixture", assemble(src, &obj));

    let out = Command::new(exe)
        .arg("-icf=safe")
        .arg("-why_live")
        .arg("_helper2")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live folded-symbol link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_helper2 was folded to _helper1 by -icf=safe"));
    assert!(stdout.contains("_helper1 is live because:"));
    assert!(stdout.contains("_helper1 is reachable from _main"));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}
