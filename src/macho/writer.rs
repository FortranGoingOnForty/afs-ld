//! Sprint 10 Mach-O writer.
//!
//! Emits a parseable `MH_EXECUTE` or `MH_DYLIB` image from the output layout.

use std::fmt;

use crate::layout::Layout;
use crate::macho::constants::*;
use crate::macho::dylib::DylibDependency;
use crate::macho::reader::{
    write_commands, write_header, BuildVersionCmd, BuildTool, DysymtabCmd, DylibCmd, LoadCommand,
    MachHeader64, Section64Header, Segment64, SymtabCmd, HEADER_SIZE,
};
use crate::{LinkOptions, OutputKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    pub atom: crate::resolve::AtomId,
    pub atom_value: u64,
}

#[derive(Debug)]
pub enum WriteError {
    MissingSegment(&'static str),
    OffsetTooLarge(&'static str),
    EntryAtomMissing(crate::resolve::AtomId),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::MissingSegment(name) => write!(f, "missing output segment `{name}`"),
            WriteError::OffsetTooLarge(what) => write!(f, "{what} exceeds 32-bit Mach-O field width"),
            WriteError::EntryAtomMissing(atom) => write!(f, "entry atom {:?} missing from layout", atom),
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
    write_with_dylibs(layout, kind, opts, None, &[], out)
}

pub fn write_with_dylibs(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let layout = finalize_layout(layout, kind, opts, dylibs)?;
    write_finalized_with_dylibs(&layout, kind, opts, entry_point, dylibs, out)
}

pub fn finalize_layout(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
) -> Result<Layout, WriteError> {
    let mut layout = layout.clone();
    let header_size = estimate_header_size(&layout, kind, opts, dylibs);
    layout.relayout(header_size);

    let linkedit = layout
        .segment("__LINKEDIT")
        .cloned()
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    let strtab_off = u32_fit(linkedit.file_off, "string table offset")?;
    let symtab = SymtabCmd {
        symoff: strtab_off,
        nsyms: 0,
        stroff: strtab_off,
        strsize: 1,
    };
    let dysymtab = DysymtabCmd::default();
    let sizeofcmds: u32 = build_commands(&layout, kind, opts, None, dylibs, symtab, dysymtab)?
        .iter()
        .map(LoadCommand::cmdsize)
        .sum();
    let header_size = HEADER_SIZE as u64 + sizeofcmds as u64;
    layout.relayout(header_size);

    let linkedit = layout
        .segment_mut("__LINKEDIT")
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    linkedit.file_size = 1;
    linkedit.vm_size = 1;
    Ok(layout)
}

pub fn write_finalized_with_dylibs(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let linkedit = layout
        .segment("__LINKEDIT")
        .cloned()
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    let strtab_off = u32_fit(linkedit.file_off, "string table offset")?;
    let symtab = SymtabCmd {
        symoff: strtab_off,
        nsyms: 0,
        stroff: strtab_off,
        strsize: 1,
    };
    let dysymtab = DysymtabCmd::default();
    let commands = build_commands(
        layout,
        kind,
        opts,
        entry_point,
        dylibs,
        symtab,
        dysymtab,
    )?;

    let sizeofcmds: u32 = commands.iter().map(LoadCommand::cmdsize).sum();
    let header = MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64_ALL,
        filetype: match kind {
            OutputKind::Executable => MH_EXECUTE,
            OutputKind::Dylib => MH_DYLIB,
        },
        ncmds: commands.len() as u32,
        sizeofcmds,
        flags: header_flags(kind),
        reserved: 0,
    };

    let final_size = final_file_size(layout);
    out.clear();
    out.reserve(final_size as usize);
    write_header(&header, out);
    write_commands(&commands, out);
    out.resize(final_size as usize, 0);

    for section in &layout.sections {
        if section.is_zerofill() {
            continue;
        }
        for placed in &section.atoms {
            let start = (section.file_off + placed.offset) as usize;
            let end = start + placed.data.len();
            out[start..end].copy_from_slice(&placed.data);
        }
    }

    out[strtab_off as usize] = 0;
    Ok(())
}

fn build_commands(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    symtab: SymtabCmd,
    dysymtab: DysymtabCmd,
) -> Result<Vec<LoadCommand>, WriteError> {
    let mut commands = Vec::new();
    for segment in &layout.segments {
        commands.push(LoadCommand::Segment64(segment_command(layout, segment.name.as_str())?));
    }

    commands.push(LoadCommand::BuildVersion(BuildVersionCmd {
        platform: PLATFORM_MACOS,
        minos: pack_version(11, 0, 0),
        sdk: pack_version(11, 0, 0),
        tools: vec![BuildTool {
            tool: 3,
            version: pack_version(0, 1, 0),
        }],
    }));

    match kind {
        OutputKind::Executable => commands.push(raw_entry_point(
            resolve_entryoff(layout, entry_point)?,
            0,
        )),
        OutputKind::Dylib => commands.push(LoadCommand::Dylib(DylibCmd {
            cmd: LC_ID_DYLIB,
            name: dylib_install_name(opts),
            timestamp: 2,
            current_version: pack_version(1, 0, 0),
            compatibility_version: pack_version(1, 0, 0),
        })),
    }

    for dylib in dylibs {
        commands.push(LoadCommand::Dylib(DylibCmd {
            cmd: LC_LOAD_DYLIB,
            name: dylib.install_name.clone(),
            timestamp: 2,
            current_version: dylib.current_version,
            compatibility_version: dylib.compatibility_version,
        }));
    }

    commands.push(LoadCommand::Symtab(symtab));
    commands.push(LoadCommand::Dysymtab(dysymtab));
    commands.push(raw_linkedit_command(LC_FUNCTION_STARTS, 0, 0));
    commands.push(raw_linkedit_command(LC_DATA_IN_CODE, 0, 0));
    commands.push(raw_linkedit_command(LC_CODE_SIGNATURE, 0, 0));
    commands.push(raw_dyld_info_only());

    Ok(commands)
}

fn estimate_header_size(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
) -> u64 {
    let mut size = HEADER_SIZE as u64;
    for segment in &layout.segments {
        size += (8 + 64 + 80 * segment.sections.len()) as u64;
    }
    size += BuildVersionCmd {
        platform: PLATFORM_MACOS,
        minos: pack_version(11, 0, 0),
        sdk: pack_version(11, 0, 0),
        tools: vec![BuildTool {
            tool: 3,
            version: pack_version(0, 1, 0),
        }],
    }
    .wire_size() as u64;
    size += match kind {
        OutputKind::Executable => 24,
        OutputKind::Dylib => DylibCmd {
            cmd: LC_ID_DYLIB,
            name: dylib_install_name(opts),
            timestamp: 2,
            current_version: pack_version(1, 0, 0),
            compatibility_version: pack_version(1, 0, 0),
        }
        .wire_size() as u64,
    };
    for dylib in dylibs {
        size += DylibCmd {
            cmd: LC_LOAD_DYLIB,
            name: dylib.install_name.clone(),
            timestamp: 2,
            current_version: dylib.current_version,
            compatibility_version: dylib.compatibility_version,
        }
        .wire_size() as u64;
    }
    size += SymtabCmd::WIRE_SIZE as u64;
    size += DysymtabCmd::WIRE_SIZE as u64;
    size += 16 * 3;
    size += 48;
    size
}

fn segment_command(layout: &Layout, segment_name: &str) -> Result<Segment64, WriteError> {
    let segment = layout
        .segment(segment_name)
        .ok_or(WriteError::MissingSegment(match segment_name {
            "__PAGEZERO" => "__PAGEZERO",
            "__TEXT" => "__TEXT",
            "__DATA_CONST" => "__DATA_CONST",
            "__DATA" => "__DATA",
            "__LINKEDIT" => "__LINKEDIT",
            _ => "__UNKNOWN",
        }))?;
    let mut sections = Vec::with_capacity(segment.sections.len());
    for id in &segment.sections {
        let section = &layout.sections[id.0 as usize];
        sections.push(Section64Header {
            sectname: name16(&section.name),
            segname: name16(&section.segment),
            addr: section.addr,
            size: section.size,
            offset: if section.is_zerofill() {
                0
            } else {
                u32_fit(section.file_off, "section file offset")?
            },
            align: section.align_pow2 as u32,
            reloff: 0,
            nreloc: 0,
            flags: section.flags,
            reserved1: section.reserved1,
            reserved2: section.reserved2,
            reserved3: section.reserved3,
        });
    }

    Ok(Segment64 {
        segname: name16(segment_name),
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

fn raw_entry_point(entryoff: u64, stacksize: u64) -> LoadCommand {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&entryoff.to_le_bytes());
    data.extend_from_slice(&stacksize.to_le_bytes());
    LoadCommand::Raw {
        cmd: LC_MAIN,
        cmdsize: 24,
        data,
    }
}

fn raw_linkedit_command(cmd: u32, dataoff: u32, datasize: u32) -> LoadCommand {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&dataoff.to_le_bytes());
    data.extend_from_slice(&datasize.to_le_bytes());
    LoadCommand::Raw {
        cmd,
        cmdsize: 16,
        data,
    }
}

fn raw_dyld_info_only() -> LoadCommand {
    LoadCommand::Raw {
        cmd: LC_DYLD_INFO_ONLY,
        cmdsize: 48,
        data: vec![0; 40],
    }
}

fn header_flags(kind: OutputKind) -> u32 {
    match kind {
        OutputKind::Executable => MH_DYLDLINK | MH_NOUNDEFS | MH_TWOLEVEL | MH_PIE,
        OutputKind::Dylib => MH_DYLDLINK | MH_TWOLEVEL | MH_NOUNDEFS,
    }
}

fn dylib_install_name(opts: &LinkOptions) -> String {
    if let Some(path) = &opts.output {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            return format!("@rpath/{name}");
        }
        return path.display().to_string();
    }
    "@rpath/a.out.dylib".to_string()
}

fn entryoff(layout: &Layout) -> Result<u64, WriteError> {
    if let Some(text) = layout
        .sections
        .iter()
        .find(|section| section.segment == "__TEXT" && section.name == "__text")
    {
        return Ok(text.file_off);
    }
    let text = layout
        .segment("__TEXT")
        .ok_or(WriteError::MissingSegment("__TEXT"))?;
    Ok(text.file_off)
}

fn resolve_entryoff(layout: &Layout, entry_point: Option<EntryPoint>) -> Result<u64, WriteError> {
    if let Some(entry_point) = entry_point {
        let atom_file_off = layout
            .atom_file_offset(entry_point.atom)
            .ok_or(WriteError::EntryAtomMissing(entry_point.atom))?;
        return Ok(atom_file_off + entry_point.atom_value);
    }
    entryoff(layout)
}

fn final_file_size(layout: &Layout) -> u64 {
    let mut max_size = 0u64;
    for segment in &layout.segments {
        max_size = max_size.max(segment.file_off + segment.file_size);
    }
    align_up(max_size.max(1), 1)
}

fn pack_version(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

fn name16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = s.as_bytes();
    let n = bytes.len().min(16);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

fn u32_fit(value: u64, what: &'static str) -> Result<u32, WriteError> {
    u32::try_from(value).map_err(|_| WriteError::OffsetTooLarge(what))
}

#[cfg(test)]
mod tests {
    use crate::layout::{Layout, PAGE_SIZE};

    use super::*;

    #[test]
    fn minimal_executable_writes_parseable_header() {
        let layout = Layout::empty(OutputKind::Executable, 0);
        let mut bytes = Vec::new();
        write(&layout, OutputKind::Executable, &LinkOptions::default(), &mut bytes).unwrap();

        let header = crate::macho::reader::parse_header(&bytes).unwrap();
        let commands = crate::macho::reader::parse_commands(&header, &bytes).unwrap();
        assert_eq!(header.filetype, MH_EXECUTE);
        assert!(
            commands.iter().any(|cmd| matches!(cmd, LoadCommand::Raw { cmd, .. } if *cmd == LC_MAIN)),
            "expected LC_MAIN in {commands:?}"
        );
        assert!(bytes.len() >= HEADER_SIZE);
    }

    #[test]
    fn minimal_dylib_writes_parseable_header() {
        let layout = Layout::empty(OutputKind::Dylib, 0);
        let mut bytes = Vec::new();
        let opts = LinkOptions {
            output: Some("libtiny.dylib".into()),
            ..LinkOptions::default()
        };
        write(&layout, OutputKind::Dylib, &opts, &mut bytes).unwrap();

        let header = crate::macho::reader::parse_header(&bytes).unwrap();
        let commands = crate::macho::reader::parse_commands(&header, &bytes).unwrap();
        assert_eq!(header.filetype, MH_DYLIB);
        assert!(
            commands
                .iter()
                .any(|cmd| matches!(cmd, LoadCommand::Dylib(d) if d.cmd == LC_ID_DYLIB)),
            "expected LC_ID_DYLIB in {commands:?}"
        );
    }

    #[test]
    fn linkedit_starts_on_page_boundary_after_text() {
        let layout = Layout::empty(OutputKind::Executable, 0);
        let mut bytes = Vec::new();
        write(&layout, OutputKind::Executable, &LinkOptions::default(), &mut bytes).unwrap();

        let header = crate::macho::reader::parse_header(&bytes).unwrap();
        let commands = crate::macho::reader::parse_commands(&header, &bytes).unwrap();
        let mut text = None;
        let mut linkedit = None;
        for cmd in commands {
            if let LoadCommand::Segment64(seg) = cmd {
                let name = seg.segname_str();
                if name == "__TEXT" {
                    text = Some(seg);
                } else if name == "__LINKEDIT" {
                    linkedit = Some(seg);
                }
            }
        }

        let text = text.unwrap();
        let linkedit = linkedit.unwrap();
        assert_eq!(linkedit.fileoff % PAGE_SIZE, 0);
        assert!(linkedit.fileoff >= text.filesize);
    }

    #[test]
    fn text_only_executable_omits_empty_data_segments() {
        let layout = Layout::empty(OutputKind::Executable, 0);
        let mut bytes = Vec::new();
        write(&layout, OutputKind::Executable, &LinkOptions::default(), &mut bytes).unwrap();

        let header = crate::macho::reader::parse_header(&bytes).unwrap();
        let commands = crate::macho::reader::parse_commands(&header, &bytes).unwrap();
        let segment_names: Vec<String> = commands
            .into_iter()
            .filter_map(|cmd| match cmd {
                LoadCommand::Segment64(seg) => Some(seg.segname_str()),
                _ => None,
            })
            .collect();

        assert!(segment_names.iter().any(|name| name == "__TEXT"));
        assert!(segment_names.iter().any(|name| name == "__LINKEDIT"));
        assert!(!segment_names.iter().any(|name| name == "__DATA_CONST"));
        assert!(!segment_names.iter().any(|name| name == "__DATA"));
    }
}
