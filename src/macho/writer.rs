//! Sprint 10 writer surface.
//!
//! This first slice writes valid empty `MH_EXECUTE` and `MH_DYLIB` files from
//! the layout model. It intentionally stops before symbol-table population,
//! reloc application, and real `__LINKEDIT` payload emission.

use crate::atom::AtomTable;
use crate::macho::constants::*;
use crate::macho::reader::{
    write_commands, write_header, BuildVersionCmd, DyldInfoCmd, DylibCmd, DysymtabCmd,
    LinkEditDataCmd, LoadCommand, MachHeader64, Section64Header, Segment64, SymtabCmd,
};
use crate::section::{assign_layout, is_zerofill, Layout};
use crate::{LinkOptions, OutputKind};

#[derive(Debug)]
pub enum WriteError {
    NumericOverflow(&'static str),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::NumericOverflow(what) => write!(f, "{what} does not fit in u32"),
        }
    }
}

impl std::error::Error for WriteError {}

pub fn write(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    write_with_atoms(layout, &AtomTable::new(), kind, opts, out)
}

pub fn write_with_atoms(
    layout: &Layout,
    atoms: &AtomTable,
    kind: OutputKind,
    opts: &LinkOptions,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let mut layout = layout.clone();
    let sizeofcmds = provisional_sizeofcmds(&layout, kind, opts)?;
    assign_layout(
        &mut layout,
        std::mem::size_of::<MachHeader64>() as u64 + sizeofcmds as u64,
        0,
    );

    let cmds = build_commands(&layout, kind, opts)?;
    let sizeofcmds = cmds.iter().map(LoadCommand::cmdsize).sum::<u32>();
    let header = MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64_ALL,
        filetype: match kind {
            OutputKind::Executable => MH_EXECUTE,
            OutputKind::Dylib => MH_DYLIB,
        },
        ncmds: cmds.len() as u32,
        sizeofcmds,
        flags: mach_header_flags(kind),
        reserved: 0,
    };

    let file_len = total_file_size(&layout)
        .max(std::mem::size_of::<MachHeader64>() as u64 + sizeofcmds as u64) as usize;
    out.clear();
    out.resize(file_len, 0);

    let mut header_and_cmds = Vec::new();
    write_header(&header, &mut header_and_cmds);
    write_commands(&cmds, &mut header_and_cmds);
    out[..header_and_cmds.len()].copy_from_slice(&header_and_cmds);

    for section in &layout.sections {
        if is_zerofill(section.kind) {
            continue;
        }
        let mut cursor = 0u64;
        for atom_id in &section.atoms {
            let atom = atoms.get(*atom_id);
            cursor = align_to(cursor, 1u64 << atom.align_pow2);
            let start = (section.file_off + cursor) as usize;
            let end = start + atom.data.len();
            if end > out.len() {
                return Err(WriteError::NumericOverflow("section body write"));
            }
            out[start..end].copy_from_slice(&atom.data);
            cursor += atom.size as u64;
        }
    }
    Ok(())
}

fn build_commands(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
) -> Result<Vec<LoadCommand>, WriteError> {
    let mut out = Vec::new();
    for segment in &layout.segments {
        out.push(LoadCommand::Segment64(build_segment_command(layout, segment)?));
    }

    out.push(LoadCommand::BuildVersion(BuildVersionCmd {
        platform: PLATFORM_MACOS,
        minos: packed_version(14, 0, 0),
        sdk: packed_version(14, 0, 0),
        tools: Vec::new(),
    }));
    out.push(LoadCommand::Symtab(SymtabCmd {
        symoff: 0,
        nsyms: 0,
        stroff: 0,
        strsize: 0,
    }));
    out.push(LoadCommand::Dysymtab(DysymtabCmd::default()));
    out.push(LoadCommand::DyldInfoOnly(DyldInfoCmd::default()));
    out.push(linkedit_raw(LC_FUNCTION_STARTS));
    out.push(linkedit_raw(LC_DATA_IN_CODE));
    out.push(linkedit_raw(LC_CODE_SIGNATURE));

    match kind {
        OutputKind::Executable => out.push(lc_main_raw(0)),
        OutputKind::Dylib => out.push(LoadCommand::Dylib(DylibCmd {
            cmd: LC_ID_DYLIB,
            name: install_name(opts),
            timestamp: 2,
            current_version: packed_version(1, 0, 0),
            compatibility_version: packed_version(1, 0, 0),
        })),
    }

    Ok(out)
}

fn provisional_sizeofcmds(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
) -> Result<u32, WriteError> {
    Ok(build_commands(layout, kind, opts)?
        .iter()
        .map(LoadCommand::cmdsize)
        .sum())
}

fn build_segment_command(
    layout: &Layout,
    segment: &crate::section::OutputSegment,
) -> Result<Segment64, WriteError> {
    let mut sections = Vec::new();
    for sec_id in &segment.sections {
        let sec = &layout.sections[sec_id.0 as usize];
        sections.push(Section64Header {
            sectname: name16(&sec.name),
            segname: name16(&sec.segment),
            addr: sec.addr,
            size: sec.size,
            offset: as_u32(sec.file_off, "section file offset")?,
            align: sec.align_pow2 as u32,
            reloff: 0,
            nreloc: 0,
            flags: sec.flags,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        });
    }

    Ok(Segment64 {
        segname: name16(&segment.name),
        vmaddr: segment.vm_addr,
        vmsize: segment.vm_size,
        fileoff: segment.file_off,
        filesize: segment.file_size,
        maxprot: segment.max_prot.bits(),
        initprot: segment.init_prot.bits(),
        flags: 0,
        sections,
    })
}

fn linkedit_raw(cmd: u32) -> LoadCommand {
    let mut payload = Vec::new();
    LinkEditDataCmd {
        dataoff: 0,
        datasize: 0,
    }
    .write(cmd, &mut payload);
    LoadCommand::Raw {
        cmd,
        cmdsize: LinkEditDataCmd::WIRE_SIZE,
        data: payload[8..].to_vec(),
    }
}

fn lc_main_raw(entryoff: u64) -> LoadCommand {
    let mut data = Vec::new();
    data.extend_from_slice(&entryoff.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    LoadCommand::Raw {
        cmd: LC_MAIN,
        cmdsize: 24,
        data,
    }
}

fn mach_header_flags(kind: OutputKind) -> u32 {
    match kind {
        OutputKind::Executable => MH_DYLDLINK | MH_NOUNDEFS | MH_TWOLEVEL | MH_PIE,
        OutputKind::Dylib => MH_DYLDLINK | MH_NOUNDEFS | MH_TWOLEVEL,
    }
}

fn install_name(opts: &LinkOptions) -> String {
    let file_name = opts
        .output
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("libempty.dylib");
    format!("@rpath/{file_name}")
}

fn packed_version(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

fn name16(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(16);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn as_u32(value: u64, what: &'static str) -> Result<u32, WriteError> {
    u32::try_from(value).map_err(|_| WriteError::NumericOverflow(what))
}

fn total_file_size(layout: &Layout) -> u64 {
    layout
        .segments
        .iter()
        .map(|segment| segment.file_off + segment.file_size)
        .max()
        .unwrap_or(0)
}

fn align_to(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}
