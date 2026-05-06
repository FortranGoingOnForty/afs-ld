//! Sprint 10 Mach-O writer.
//!
//! Emits a parseable `MH_EXECUTE` or `MH_DYLIB` image from the output layout.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::atom::AtomTable;
use crate::input::{DataInCodeEntry, ObjectFile};
use crate::layout::{Layout, LayoutInput, PAGE_SIZE};
use crate::leb::write_uleb;
use crate::macho::constants::*;
use crate::macho::dylib::DylibDependency;
use crate::macho::exports::{ExportEntry, ExportKind};
use crate::macho::reader::{
    write_commands, write_header, BuildTool, BuildVersionCmd, DyldInfoCmd, DylibCmd, DysymtabCmd,
    LinkEditDataCmd, LoadCommand, MachHeader64, RpathCmd, Section64Header, Segment64, SymtabCmd,
    HEADER_SIZE,
};
use crate::reloc::{
    parse_raw_relocs, parse_relocs, ParsedRelocCache, Referent, Reloc, RelocKind, RelocLength,
};
use crate::resolve::{AtomId, InputId};
use crate::resolve::{Symbol, SymbolId, SymbolTable};
use crate::section::is_executable;
use crate::string_table::StringTableBuilder;
use crate::symbol::{write_nlist_table, InputSymbol, RawNlist, SymKind};
use crate::synth::tlv::THREAD_VARIABLE_DESCRIPTOR_SIZE;
use crate::synth::{
    code_sig::CodeSignaturePlan,
    dyld_info::{
        build_export_trie, emit_bind_records, emit_lazy_bind_record, emit_rebase_run,
        BindRecordSpec, OpcodeStream,
    },
    SyntheticPlan,
};
use crate::{LinkOptions, OutputKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    pub atom: crate::resolve::AtomId,
    pub atom_value: u64,
}

#[derive(Clone, Copy)]
pub struct LinkEditContext<'a> {
    pub layout_inputs: &'a [LayoutInput<'a>],
    pub atom_table: &'a AtomTable,
    pub sym_table: &'a SymbolTable,
    pub synthetic_plan: &'a SyntheticPlan,
    pub icf_redirects: Option<&'a HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
    pub parsed_relocs: &'a ParsedRelocCache,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkEditBuildTimings {
    pub symbol_plan: Duration,
    pub symbol_plan_locals: Duration,
    pub symbol_plan_globals: Duration,
    pub symbol_plan_strtab: Duration,
    pub dyld_info: Duration,
    pub dyld_bind: Duration,
    pub dyld_rebase: Duration,
    pub dyld_export: Duration,
    pub metadata_tables: Duration,
    pub code_signature: Duration,
}

impl std::ops::AddAssign for LinkEditBuildTimings {
    fn add_assign(&mut self, rhs: Self) {
        self.symbol_plan += rhs.symbol_plan;
        self.symbol_plan_locals += rhs.symbol_plan_locals;
        self.symbol_plan_globals += rhs.symbol_plan_globals;
        self.symbol_plan_strtab += rhs.symbol_plan_strtab;
        self.dyld_info += rhs.dyld_info;
        self.dyld_bind += rhs.dyld_bind;
        self.dyld_rebase += rhs.dyld_rebase;
        self.dyld_export += rhs.dyld_export;
        self.metadata_tables += rhs.metadata_tables;
        self.code_signature += rhs.code_signature;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMapSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub file_index: usize,
}

#[derive(Debug)]
pub enum WriteError {
    MissingSegment(&'static str),
    OffsetTooLarge(&'static str),
    EntryAtomMissing(crate::resolve::AtomId),
    DefinedSymbolAtomMissing(SymbolId, crate::resolve::AtomId),
    DefinedSymbolSectionMissing(SymbolId, crate::resolve::AtomId),
    DirectBindAtomMissing(crate::resolve::AtomId),
    DirectBindSectionMissing(crate::resolve::AtomId),
    ImportSymbolMissing(SymbolId),
    ImportSymbolWrongKind(SymbolId),
    MalformedRelocations(PathBuf, u8, String),
    MalformedLoh(PathBuf, String),
    MalformedDataInCode(PathBuf, String),
    SymbolListRead(PathBuf, String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::MissingSegment(name) => write!(f, "missing output segment `{name}`"),
            WriteError::OffsetTooLarge(what) => {
                write!(f, "{what} exceeds 32-bit Mach-O field width")
            }
            WriteError::EntryAtomMissing(atom) => {
                write!(f, "entry atom {:?} missing from layout", atom)
            }
            WriteError::DefinedSymbolAtomMissing(symbol, atom) => write!(
                f,
                "defined symbol {:?} points at missing atom {:?} in final layout",
                symbol, atom
            ),
            WriteError::DefinedSymbolSectionMissing(symbol, atom) => write!(
                f,
                "defined symbol {:?} points at atom {:?} outside any output section",
                symbol, atom
            ),
            WriteError::DirectBindAtomMissing(atom) => {
                write!(f, "direct bind atom {:?} missing from layout", atom)
            }
            WriteError::DirectBindSectionMissing(atom) => {
                write!(
                    f,
                    "direct bind atom {:?} is not inside an output section",
                    atom
                )
            }
            WriteError::ImportSymbolMissing(symbol) => {
                write!(
                    f,
                    "synthetic import symbol {:?} missing from symbol table",
                    symbol
                )
            }
            WriteError::ImportSymbolWrongKind(symbol) => {
                write!(
                    f,
                    "synthetic import symbol {:?} is not a dylib import",
                    symbol
                )
            }
            WriteError::MalformedRelocations(path, section, detail) => write!(
                f,
                "failed to parse relocations in {} section {}: {detail}",
                path.display(),
                section
            ),
            WriteError::MalformedLoh(path, detail) => {
                write!(
                    f,
                    "failed to remap LC_LINKER_OPTIMIZATION_HINT in {}: {detail}",
                    path.display()
                )
            }
            WriteError::MalformedDataInCode(path, detail) => {
                write!(
                    f,
                    "failed to remap LC_DATA_IN_CODE in {}: {detail}",
                    path.display()
                )
            }
            WriteError::SymbolListRead(path, detail) => {
                write!(
                    f,
                    "{}: unable to read symbol list: {detail}",
                    path.display()
                )
            }
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
    Ok(finalize_with_linkedit(layout, kind, opts, dylibs, None)?.0)
}

pub fn finalize_layout_with_linkedit(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    context: LinkEditContext<'_>,
) -> Result<(Layout, LinkEditPlan, LinkEditBuildTimings), WriteError> {
    finalize_with_linkedit(layout, kind, opts, dylibs, Some(LinkEditInputs(context)))
}

pub fn build_parsed_reloc_cache(
    inputs: &[LayoutInput<'_>],
) -> Result<ParsedRelocCache, WriteError> {
    let mut cache = HashMap::new();
    for input in inputs {
        for (sect_idx, section) in input.object.sections.iter().enumerate() {
            if section.raw_relocs.is_empty() {
                continue;
            }
            let section_idx = (sect_idx + 1) as u8;
            let raws = parse_raw_relocs(&section.raw_relocs, 0, section.nreloc).map_err(|err| {
                WriteError::MalformedRelocations(
                    input.object.path.clone(),
                    section_idx,
                    err.to_string(),
                )
            })?;
            let relocs = parse_relocs(&raws).map_err(|err| {
                WriteError::MalformedRelocations(
                    input.object.path.clone(),
                    section_idx,
                    err.to_string(),
                )
            })?;
            cache.insert((input.id, section_idx), relocs);
        }
    }
    Ok(cache)
}

fn finalize_with_linkedit(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    inputs: Option<LinkEditInputs<'_>>,
) -> Result<(Layout, LinkEditPlan, LinkEditBuildTimings), WriteError> {
    let mut layout = layout.clone();
    let (mut linkedit, mut timings) = build_linkedit_plan_profiled(&layout, kind, opts, inputs)?;
    apply_indirect_starts(&mut layout, &linkedit);
    let header_size = estimate_header_size(&layout, kind, opts, dylibs, &linkedit);
    layout.relayout(header_size);

    let (next_linkedit, next_timings) = build_linkedit_plan_profiled(&layout, kind, opts, inputs)?;
    linkedit = next_linkedit;
    timings += next_timings;
    apply_indirect_starts(&mut layout, &linkedit);
    let exact_header_size =
        HEADER_SIZE as u64 + exact_sizeofcmds(&layout, kind, opts, dylibs, &linkedit)? as u64;
    if exact_header_size != header_size {
        layout.relayout(exact_header_size);
        let (next_linkedit, next_timings) =
            build_linkedit_plan_profiled(&layout, kind, opts, inputs)?;
        linkedit = next_linkedit;
        timings += next_timings;
        apply_indirect_starts(&mut layout, &linkedit);
    }

    let linkedit_seg = layout
        .segment_mut("__LINKEDIT")
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    linkedit_seg.file_size = linkedit.total_size().max(1);
    linkedit_seg.vm_size = align_up(linkedit.total_size().max(1), PAGE_SIZE);
    Ok((layout, linkedit, timings))
}

fn exact_sizeofcmds(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    linkedit: &LinkEditPlan,
) -> Result<u32, WriteError> {
    Ok(build_commands(layout, kind, opts, None, dylibs, linkedit)?
        .iter()
        .map(LoadCommand::cmdsize)
        .sum())
}

pub fn write_finalized_with_dylibs(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let linkedit = LinkEditPlan::minimal(layout, kind, opts)?;
    write_finalized_with_linkedit(layout, kind, opts, entry_point, dylibs, &linkedit, out)
}

pub fn write_finalized_with_linkedit(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    linkedit_plan: &LinkEditPlan,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let _linkedit_segment = layout
        .segment("__LINKEDIT")
        .cloned()
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    let commands = build_commands(layout, kind, opts, entry_point, dylibs, linkedit_plan)?;

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
        flags: header_flags(layout, kind),
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
        if !section.synthetic_data.is_empty() {
            let start = (section.file_off + section.synthetic_offset) as usize;
            let end = start + section.synthetic_data.len();
            out[start..end].copy_from_slice(&section.synthetic_data);
        }
        for placed in &section.atoms {
            let start = (section.file_off + placed.offset) as usize;
            let end = start + placed.data.len();
            out[start..end].copy_from_slice(&placed.data);
        }
    }

    let symoff = linkedit_plan.symtab.symoff as usize;
    let indirectoff = linkedit_plan.dysymtab.indirectsymoff as usize;
    let rebaseoff = linkedit_plan.dyld_info.rebase_off as usize;
    let bindoff = linkedit_plan.dyld_info.bind_off as usize;
    let weak_bind_off = linkedit_plan.dyld_info.weak_bind_off as usize;
    let lazy_bind_off = linkedit_plan.dyld_info.lazy_bind_off as usize;
    let export_off = linkedit_plan.dyld_info.export_off as usize;
    let loh_off = linkedit_plan.loh.map(|loh| loh.dataoff as usize);
    let function_starts_off = linkedit_plan.function_starts.dataoff as usize;
    let data_in_code_off = linkedit_plan.data_in_code.dataoff as usize;
    let stroff = linkedit_plan.symtab.stroff as usize;
    if !linkedit_plan.symtab_bytes.is_empty() {
        let end = symoff + linkedit_plan.symtab_bytes.len();
        out[symoff..end].copy_from_slice(&linkedit_plan.symtab_bytes);
    }
    if !linkedit_plan.indirect_bytes.is_empty() {
        let end = indirectoff + linkedit_plan.indirect_bytes.len();
        out[indirectoff..end].copy_from_slice(&linkedit_plan.indirect_bytes);
    }
    if !linkedit_plan.rebase_bytes.is_empty() {
        let end = rebaseoff + linkedit_plan.rebase_bytes.len();
        out[rebaseoff..end].copy_from_slice(&linkedit_plan.rebase_bytes);
    }
    if !linkedit_plan.bind_bytes.is_empty() {
        let end = bindoff + linkedit_plan.bind_bytes.len();
        out[bindoff..end].copy_from_slice(&linkedit_plan.bind_bytes);
    }
    if !linkedit_plan.weak_bind_bytes.is_empty() {
        let end = weak_bind_off + linkedit_plan.weak_bind_bytes.len();
        out[weak_bind_off..end].copy_from_slice(&linkedit_plan.weak_bind_bytes);
    }
    if !linkedit_plan.lazy_bind_bytes.is_empty() {
        let end = lazy_bind_off + linkedit_plan.lazy_bind_bytes.len();
        out[lazy_bind_off..end].copy_from_slice(&linkedit_plan.lazy_bind_bytes);
    }
    if !linkedit_plan.export_bytes.is_empty() {
        let end = export_off + linkedit_plan.export_bytes.len();
        out[export_off..end].copy_from_slice(&linkedit_plan.export_bytes);
    }
    if let Some(loh_off) = loh_off {
        if !linkedit_plan.loh_bytes.is_empty() {
            let end = loh_off + linkedit_plan.loh_bytes.len();
            out[loh_off..end].copy_from_slice(&linkedit_plan.loh_bytes);
        }
    }
    if !linkedit_plan.function_starts_bytes.is_empty() {
        let end = function_starts_off + linkedit_plan.function_starts_bytes.len();
        out[function_starts_off..end].copy_from_slice(&linkedit_plan.function_starts_bytes);
    }
    if !linkedit_plan.data_in_code_bytes.is_empty() {
        let end = data_in_code_off + linkedit_plan.data_in_code_bytes.len();
        out[data_in_code_off..end].copy_from_slice(&linkedit_plan.data_in_code_bytes);
    }
    let end = stroff + linkedit_plan.strtab_bytes.len();
    out[stroff..end].copy_from_slice(&linkedit_plan.strtab_bytes);
    if let Some(code_signature) = &linkedit_plan.code_signature {
        let start = code_signature.dataoff as usize;
        let bytes = code_signature.build_with_jobs(&out[..start], opts.parallel_jobs());
        let end = start + bytes.len();
        out[start..end].copy_from_slice(&bytes);
    }

    Ok(())
}

fn build_commands(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    entry_point: Option<EntryPoint>,
    dylibs: &[DylibDependency],
    linkedit: &LinkEditPlan,
) -> Result<Vec<LoadCommand>, WriteError> {
    let mut commands = Vec::new();
    for segment in &layout.segments {
        commands.push(LoadCommand::Segment64(segment_command(
            layout,
            segment.name.as_str(),
        )?));
    }

    match kind {
        OutputKind::Executable => {
            commands.push(LoadCommand::DyldInfoOnly(linkedit.dyld_info));
            commands.push(LoadCommand::Symtab(linkedit.symtab));
            commands.push(LoadCommand::Dysymtab(linkedit.dysymtab));
            commands.push(raw_dylinker_command("/usr/lib/dyld"));
            if opts.emit_uuid {
                commands.push(raw_uuid_command(stable_uuid(layout, kind)));
            }
            commands.push(LoadCommand::BuildVersion(build_version_command(opts)));
            commands.push(raw_source_version_command(0));
            commands.push(raw_entry_point(resolve_entryoff(layout, entry_point)?, 0));
        }
        OutputKind::Dylib => {
            commands.push(LoadCommand::Dylib(DylibCmd {
                cmd: LC_ID_DYLIB,
                name: dylib_install_name(opts),
                timestamp: 2,
                current_version: dylib_current_version(opts),
                compatibility_version: dylib_compatibility_version(opts),
            }));
            commands.push(LoadCommand::DyldInfoOnly(linkedit.dyld_info));
            commands.push(LoadCommand::Symtab(linkedit.symtab));
            commands.push(LoadCommand::Dysymtab(linkedit.dysymtab));
            if opts.emit_uuid {
                commands.push(raw_uuid_command(stable_uuid(layout, kind)));
            }
            commands.push(LoadCommand::BuildVersion(build_version_command(opts)));
            commands.push(raw_source_version_command(0));
        }
    }

    for dylib in dylibs {
        commands.push(LoadCommand::Dylib(DylibCmd {
            cmd: dylib.kind.load_cmd(),
            name: dylib.install_name.clone(),
            timestamp: 2,
            current_version: dylib.current_version,
            compatibility_version: dylib.compatibility_version,
        }));
    }

    for rpath in &opts.rpaths {
        commands.push(LoadCommand::Rpath(RpathCmd {
            path: rpath.clone(),
        }));
    }

    if let Some(loh) = linkedit.loh {
        commands.push(raw_linkedit_command(
            LC_LINKER_OPTIMIZATION_HINT,
            loh.dataoff,
            loh.datasize,
        ));
    }
    commands.push(raw_linkedit_command(
        LC_FUNCTION_STARTS,
        linkedit.function_starts.dataoff,
        linkedit.function_starts.datasize,
    ));
    commands.push(raw_linkedit_command(
        LC_DATA_IN_CODE,
        linkedit.data_in_code.dataoff,
        linkedit.data_in_code.datasize,
    ));
    if let Some(code_signature) = &linkedit.code_signature {
        commands.push(raw_linkedit_command(
            LC_CODE_SIGNATURE,
            code_signature.dataoff,
            code_signature.datasize,
        ));
    } else {
        commands.push(raw_linkedit_command(LC_CODE_SIGNATURE, 0, 0));
    }
    Ok(commands)
}

fn estimate_header_size(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    linkedit: &LinkEditPlan,
) -> u64 {
    let mut size = HEADER_SIZE as u64;
    for segment in &layout.segments {
        size += (8 + 64 + 80 * segment.sections.len()) as u64;
    }
    size += build_version_command(opts).wire_size() as u64;
    if opts.emit_uuid {
        size += 24;
    }
    size += match kind {
        OutputKind::Executable => {
            raw_dylinker_command("/usr/lib/dyld").cmdsize() as u64
                + 24
                + raw_source_version_command(0).cmdsize() as u64
        }
        OutputKind::Dylib => {
            DylibCmd {
                cmd: LC_ID_DYLIB,
                name: dylib_install_name(opts),
                timestamp: 2,
                current_version: dylib_current_version(opts),
                compatibility_version: dylib_compatibility_version(opts),
            }
            .wire_size() as u64
                + raw_source_version_command(0).cmdsize() as u64
        }
    };
    for rpath in &opts.rpaths {
        size += RpathCmd {
            path: rpath.clone(),
        }
        .wire_size() as u64;
    }
    for dylib in dylibs {
        size += DylibCmd {
            cmd: dylib.kind.load_cmd(),
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
    if linkedit.loh.is_some() {
        size += 16;
    }
    size += DyldInfoCmd::WIRE_SIZE as u64;
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
        flags: segment.flags,
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

fn raw_dylinker_command(path: &str) -> LoadCommand {
    let mut data = Vec::with_capacity(4 + path.len() + 1);
    let path_offset: u32 = 12;
    data.extend_from_slice(&path_offset.to_le_bytes());
    data.extend_from_slice(path.as_bytes());
    data.push(0);
    while !(8 + data.len()).is_multiple_of(8) {
        data.push(0);
    }
    LoadCommand::Raw {
        cmd: LC_LOAD_DYLINKER,
        cmdsize: (8 + data.len()) as u32,
        data,
    }
}

fn raw_uuid_command(uuid: [u8; 16]) -> LoadCommand {
    LoadCommand::Raw {
        cmd: LC_UUID,
        cmdsize: 24,
        data: uuid.to_vec(),
    }
}

fn raw_source_version_command(version: u64) -> LoadCommand {
    LoadCommand::Raw {
        cmd: LC_SOURCE_VERSION,
        cmdsize: 16,
        data: version.to_le_bytes().to_vec(),
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

fn build_version_command(opts: &LinkOptions) -> BuildVersionCmd {
    let platform = opts.platform_version.unwrap_or(crate::PlatformVersion {
        minos: pack_version(11, 0, 0),
        sdk: pack_version(11, 0, 0),
    });
    BuildVersionCmd {
        platform: PLATFORM_MACOS,
        minos: platform.minos,
        sdk: platform.sdk,
        tools: vec![BuildTool {
            tool: 3,
            version: pack_version(0, 1, 0),
        }],
    }
}

fn stable_uuid(layout: &Layout, kind: OutputKind) -> [u8; 16] {
    fn mix(state: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *state ^= u64::from(*byte);
            *state = state.wrapping_mul(0x100000001b3);
        }
    }

    let mut lo = 0xcbf29ce484222325u64;
    let mut hi = 0x84222325cbf29ce4u64;
    mix(
        &mut lo,
        &[match kind {
            OutputKind::Executable => 1,
            OutputKind::Dylib => 2,
        }],
    );
    for segment in &layout.segments {
        mix(&mut lo, segment.name.as_bytes());
        mix(&mut lo, &segment.vm_addr.to_le_bytes());
        mix(&mut lo, &segment.vm_size.to_le_bytes());
        mix(&mut hi, &segment.file_off.to_le_bytes());
        mix(&mut hi, &segment.file_size.to_le_bytes());
        mix(&mut hi, &segment.flags.to_le_bytes());
    }
    for section in &layout.sections {
        mix(&mut lo, section.segment.as_bytes());
        mix(&mut lo, section.name.as_bytes());
        mix(&mut lo, &section.addr.to_le_bytes());
        mix(&mut hi, &section.size.to_le_bytes());
        mix(&mut hi, &section.file_off.to_le_bytes());
        mix(&mut hi, &section.flags.to_le_bytes());
    }
    let mut uuid = [0u8; 16];
    uuid[..8].copy_from_slice(&lo.to_be_bytes());
    uuid[8..].copy_from_slice(&hi.to_be_bytes());
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

fn header_flags(layout: &Layout, kind: OutputKind) -> u32 {
    let mut flags = match kind {
        OutputKind::Executable => MH_DYLDLINK | MH_NOUNDEFS | MH_TWOLEVEL | MH_PIE,
        OutputKind::Dylib => MH_DYLDLINK | MH_TWOLEVEL | MH_NOUNDEFS,
    };
    if layout
        .sections
        .iter()
        .any(|section| section.segment == "__DATA" && section.name == "__thread_vars")
    {
        flags |= MH_HAS_TLV_DESCRIPTORS;
    }
    flags
}

fn dylib_install_name(opts: &LinkOptions) -> String {
    if let Some(name) = &opts.install_name {
        return name.clone();
    }
    if let Some(path) = &opts.output {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            return format!("@rpath/{name}");
        }
        return path.display().to_string();
    }
    "@rpath/a.out.dylib".to_string()
}

fn dylib_current_version(opts: &LinkOptions) -> u32 {
    opts.current_version
        .unwrap_or_else(|| pack_version(1, 0, 0))
}

fn dylib_compatibility_version(opts: &LinkOptions) -> u32 {
    opts.compatibility_version
        .unwrap_or_else(|| pack_version(1, 0, 0))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEditPlan {
    base_off: u32,
    pub symtab: SymtabCmd,
    pub dysymtab: DysymtabCmd,
    pub dyld_info: DyldInfoCmd,
    pub loh: Option<LinkEditDataCmd>,
    pub function_starts: LinkEditDataCmd,
    pub data_in_code: LinkEditDataCmd,
    pub symtab_bytes: Vec<u8>,
    pub indirect_bytes: Vec<u8>,
    rebase_bytes: Vec<u8>,
    bind_bytes: Vec<u8>,
    weak_bind_bytes: Vec<u8>,
    lazy_bind_bytes: Vec<u8>,
    export_bytes: Vec<u8>,
    loh_bytes: Vec<u8>,
    function_starts_bytes: Vec<u8>,
    data_in_code_bytes: Vec<u8>,
    pub strtab_bytes: Vec<u8>,
    code_signature: Option<CodeSignaturePlan>,
    indirect_starts: HashMap<(String, String), u32>,
    lazy_bind_offsets: HashMap<SymbolId, u32>,
    pub map_symbols: Vec<LinkMapSymbol>,
}

impl LinkEditPlan {
    fn minimal(layout: &Layout, kind: OutputKind, opts: &LinkOptions) -> Result<Self, WriteError> {
        build_linkedit_plan(layout, kind, opts, None)
    }

    fn total_size(&self) -> u64 {
        let base_off = self.base_off as u64;
        let regular_end = self.symtab.stroff as u64 + self.strtab_bytes.len() as u64;
        let regular_size = regular_end.saturating_sub(base_off);
        if let Some(code_signature) = &self.code_signature {
            (code_signature.dataoff as u64 - base_off) + code_signature.datasize as u64
        } else {
            regular_size
        }
    }

    pub fn lazy_bind_offset(&self, symbol: SymbolId) -> Option<u32> {
        self.lazy_bind_offsets.get(&symbol).copied()
    }

    pub fn loh_bytes(&self) -> &[u8] {
        &self.loh_bytes
    }
}

fn build_linkedit_plan(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    inputs: Option<LinkEditInputs<'_>>,
) -> Result<LinkEditPlan, WriteError> {
    build_linkedit_plan_profiled(layout, kind, opts, inputs).map(|(plan, _)| plan)
}

fn build_linkedit_plan_profiled(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    inputs: Option<LinkEditInputs<'_>>,
) -> Result<(LinkEditPlan, LinkEditBuildTimings), WriteError> {
    let mut timings = LinkEditBuildTimings::default();
    let linkedit = layout
        .segment("__LINKEDIT")
        .cloned()
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    let base_off = u32_fit(linkedit.file_off, "linkedit file offset")?;

    let Some(inputs) = inputs else {
        let phase_started = std::time::Instant::now();
        let code_signature = Some(build_code_signature(
            layout,
            kind,
            opts,
            base_off as u64 + 8,
        )?);
        timings.code_signature += phase_started.elapsed();
        return Ok((
            LinkEditPlan {
                base_off,
                symtab: SymtabCmd {
                    symoff: base_off,
                    nsyms: 0,
                    stroff: base_off,
                    strsize: 8,
                },
                dysymtab: DysymtabCmd::default(),
                dyld_info: DyldInfoCmd::default(),
                loh: None,
                function_starts: LinkEditDataCmd {
                    dataoff: base_off,
                    datasize: 0,
                },
                data_in_code: LinkEditDataCmd {
                    dataoff: base_off,
                    datasize: 0,
                },
                symtab_bytes: Vec::new(),
                indirect_bytes: Vec::new(),
                rebase_bytes: Vec::new(),
                bind_bytes: Vec::new(),
                weak_bind_bytes: Vec::new(),
                lazy_bind_bytes: Vec::new(),
                export_bytes: Vec::new(),
                loh_bytes: Vec::new(),
                function_starts_bytes: Vec::new(),
                data_in_code_bytes: Vec::new(),
                strtab_bytes: vec![0; 8],
                code_signature,
                indirect_starts: HashMap::new(),
                lazy_bind_offsets: HashMap::new(),
                map_symbols: Vec::new(),
            },
            timings,
        ));
    };
    let sym_table = inputs.0.sym_table;
    let synthetic_plan = inputs.0.synthetic_plan;

    let phase_started = std::time::Instant::now();
    let imports = collect_imports(sym_table, synthetic_plan)?;
    let import_lookup: HashMap<SymbolId, &ImportSymbolRecord> = imports
        .iter()
        .map(|record| (record.symbol, record))
        .collect();
    let visibility = SymbolVisibilityPolicy::from_opts(opts)?;
    let (symbol_plan, symbol_plan_timings) = build_output_symbols_profiled(
        layout,
        kind,
        opts.dead_strip,
        opts.strip_locals,
        &visibility,
        inputs,
        &imports,
    )?;
    timings.symbol_plan += phase_started.elapsed();
    timings.symbol_plan_locals += symbol_plan_timings.locals;
    timings.symbol_plan_globals += symbol_plan_timings.globals;
    timings.symbol_plan_strtab += symbol_plan_timings.strtab;
    let mut symtab_bytes = Vec::new();
    write_nlist_table(&symbol_plan.symbols, &mut symtab_bytes);

    let mut indirect_symbols = Vec::new();
    let mut indirect_starts = HashMap::new();
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__TEXT", "__stubs"),
        synthetic_plan.stubs.entries.iter().map(|entry| {
            indirect_symbol_index(entry.symbol, &import_lookup, &symbol_plan.symbol_indices)
        }),
    );
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__DATA_CONST", "__got"),
        synthetic_plan.got.entries.iter().map(|entry| {
            indirect_symbol_index(entry.symbol, &import_lookup, &symbol_plan.symbol_indices)
        }),
    );
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__DATA", "__la_symbol_ptr"),
        synthetic_plan.lazy_pointers.entries.iter().map(|entry| {
            indirect_symbol_index(entry.symbol, &import_lookup, &symbol_plan.symbol_indices)
        }),
    );

    let mut indirect_bytes = Vec::with_capacity(indirect_symbols.len() * 4);
    for index in &indirect_symbols {
        indirect_bytes.extend_from_slice(&index.to_le_bytes());
    }

    let dyld_started = std::time::Instant::now();
    let phase_started = std::time::Instant::now();
    let bind_streams = build_bind_streams(layout, synthetic_plan, &import_lookup)?;
    let bind_bytes = pad_dyld_info_stream(bind_streams.bind);
    let weak_bind_bytes = pad_dyld_info_stream(bind_streams.weak_bind);
    let lazy_bind_bytes = pad_dyld_info_stream(bind_streams.lazy_bind);
    timings.dyld_bind += phase_started.elapsed();
    let phase_started = std::time::Instant::now();
    let rebase_bytes = pad_dyld_info_stream(build_rebase_stream(layout, synthetic_plan, inputs)?);
    timings.dyld_rebase += phase_started.elapsed();
    let phase_started = std::time::Instant::now();
    let export_bytes = pad_dyld_info_stream(build_export_trie(&symbol_plan.exports));
    timings.dyld_export += phase_started.elapsed();
    timings.dyld_info += dyld_started.elapsed();

    let phase_started = std::time::Instant::now();
    let loh_bytes = build_loh(
        layout,
        inputs.0.layout_inputs,
        inputs.0.atom_table,
        inputs.0.icf_redirects,
    )?;
    let function_starts_bytes =
        build_function_starts(layout, inputs.0.layout_inputs, inputs.0.atom_table)?;
    let data_in_code_bytes = build_data_in_code(
        layout,
        inputs.0.layout_inputs,
        inputs.0.atom_table,
        inputs.0.icf_redirects,
    )?;
    timings.metadata_tables += phase_started.elapsed();

    let mut cursor = base_off as u64;
    let rebase_off = place_optional_block(&mut cursor, rebase_bytes.len(), "rebase stream offset")?;
    let bindoff = place_optional_block(&mut cursor, bind_bytes.len(), "bind stream offset")?;
    let weak_bind_off = place_optional_block(
        &mut cursor,
        weak_bind_bytes.len(),
        "weak bind stream offset",
    )?;
    let lazy_bind_off = place_optional_block(
        &mut cursor,
        lazy_bind_bytes.len(),
        "lazy bind stream offset",
    )?;
    let export_off = place_optional_block(&mut cursor, export_bytes.len(), "export trie offset")?;
    let loh = place_optional_linkedit_data_block(&mut cursor, loh_bytes.len(), "LOH offset")?;
    let function_starts = place_linkedit_data_block(
        &mut cursor,
        function_starts_bytes.len(),
        "function starts offset",
    )?;
    let data_in_code =
        place_linkedit_data_block(&mut cursor, data_in_code_bytes.len(), "data-in-code offset")?;
    let symoff = place_required_block(&mut cursor, symtab_bytes.len(), "symbol table offset")?;
    let indirectsymoff = place_optional_block(
        &mut cursor,
        indirect_bytes.len(),
        "indirect symbol table offset",
    )?;
    let stroff = place_required_block(
        &mut cursor,
        symbol_plan.strtab_bytes.len(),
        "string table offset",
    )?;
    let regular_end = stroff as u64 + symbol_plan.strtab_bytes.len() as u64;
    let phase_started = std::time::Instant::now();
    let code_signature = Some(build_code_signature(layout, kind, opts, regular_end)?);
    timings.code_signature += phase_started.elapsed();
    Ok((
        LinkEditPlan {
            base_off,
            symtab: SymtabCmd {
                symoff,
                nsyms: symbol_plan.symbols.len() as u32,
                stroff,
                strsize: symbol_plan.strtab_bytes.len() as u32,
            },
            dysymtab: DysymtabCmd {
                indirectsymoff,
                nindirectsyms: indirect_symbols.len() as u32,
                ..symbol_plan.dysymtab
            },
            dyld_info: DyldInfoCmd {
                rebase_off,
                rebase_size: rebase_bytes.len() as u32,
                bind_off: bindoff,
                bind_size: bind_bytes.len() as u32,
                weak_bind_off,
                weak_bind_size: weak_bind_bytes.len() as u32,
                lazy_bind_off,
                lazy_bind_size: lazy_bind_bytes.len() as u32,
                export_off,
                export_size: export_bytes.len() as u32,
            },
            loh,
            function_starts,
            data_in_code,
            symtab_bytes,
            indirect_bytes,
            rebase_bytes,
            bind_bytes,
            weak_bind_bytes,
            lazy_bind_bytes,
            export_bytes,
            loh_bytes,
            function_starts_bytes,
            data_in_code_bytes,
            strtab_bytes: symbol_plan.strtab_bytes,
            code_signature,
            indirect_starts,
            lazy_bind_offsets: bind_streams.lazy_offsets,
            map_symbols: symbol_plan.map_symbols,
        },
        timings,
    ))
}

fn build_code_signature(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    regular_end: u64,
) -> Result<CodeSignaturePlan, WriteError> {
    let code_limit = align_up(regular_end, 16);
    CodeSignaturePlan::new(layout, opts, code_limit, kind == OutputKind::Executable)
        .map_err(WriteError::OffsetTooLarge)
}

fn pad_dyld_info_stream(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let padded_len = align_up(bytes.len() as u64, 8) as usize;
    bytes.resize(padded_len, 0);
    bytes
}

#[derive(Debug, Clone)]
struct ImportSymbolRecord {
    symbol: SymbolId,
    name: String,
    ordinal: u16,
    weak_import: bool,
}

#[derive(Clone, Copy)]
struct LinkEditInputs<'a>(LinkEditContext<'a>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputSymbolPartition {
    Local,
    ExternalDefined,
    Undefined,
}

#[derive(Debug, Clone)]
struct OutputSymbolSpec {
    symbol: Option<SymbolId>,
    name: String,
    partition: OutputSymbolPartition,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
    size: u64,
    file_index: usize,
}

#[derive(Debug, Clone)]
struct SymbolVisibilityPolicy {
    exported: Vec<String>,
    unexported: Vec<String>,
}

impl SymbolVisibilityPolicy {
    fn from_opts(opts: &LinkOptions) -> Result<Self, WriteError> {
        let mut exported = opts.exported_symbols.clone();
        let mut unexported = opts.unexported_symbols.clone();
        for path in &opts.exported_symbols_lists {
            exported.extend(read_symbol_patterns(path)?);
        }
        for path in &opts.unexported_symbols_lists {
            unexported.extend(read_symbol_patterns(path)?);
        }
        Ok(Self {
            exported,
            unexported,
        })
    }

    fn hides(&self, name: &str) -> bool {
        if !self.exported.is_empty()
            && !self
                .exported
                .iter()
                .any(|pattern| wildcard_matches(pattern, name))
        {
            return true;
        }
        self.unexported
            .iter()
            .any(|pattern| wildcard_matches(pattern, name))
    }
}

#[derive(Debug, Clone)]
struct SymbolTablePlan {
    symbols: Vec<InputSymbol>,
    map_symbols: Vec<LinkMapSymbol>,
    strtab_bytes: Vec<u8>,
    symbol_indices: HashMap<SymbolId, u32>,
    exports: Vec<ExportEntry>,
    dysymtab: DysymtabCmd,
}

struct BindStreams {
    bind: Vec<u8>,
    weak_bind: Vec<u8>,
    lazy_bind: Vec<u8>,
    lazy_offsets: HashMap<SymbolId, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RebaseSite {
    segment_index: u8,
    segment_offset: u64,
}

fn build_rebase_stream(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    inputs: LinkEditInputs<'_>,
) -> Result<Vec<u8>, WriteError> {
    let mut sites = collect_rebase_sites(layout, synthetic_plan, inputs)?;
    if sites.is_empty() {
        return Ok(Vec::new());
    }
    sites.sort_unstable();
    sites.dedup();

    let mut out = OpcodeStream::new();
    out.byte(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    let mut idx = 0usize;
    while idx < sites.len() {
        let segment_index = sites[idx].segment_index;
        out.byte(
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (segment_index & REBASE_IMMEDIATE_MASK),
        );
        out.uleb(sites[idx].segment_offset);
        let mut cursor = sites[idx].segment_offset;
        while idx < sites.len() && sites[idx].segment_index == segment_index {
            if sites[idx].segment_offset > cursor {
                out.byte(REBASE_OPCODE_ADD_ADDR_ULEB);
                out.uleb(sites[idx].segment_offset - cursor);
            }
            let run_start = sites[idx].segment_offset;
            let mut run_len = 1usize;
            while idx + run_len < sites.len()
                && sites[idx + run_len].segment_index == segment_index
                && sites[idx + run_len].segment_offset == run_start + (run_len as u64) * 8
            {
                run_len += 1;
            }
            emit_rebase_run(&mut out, run_len);
            cursor = run_start + (run_len as u64) * 8;
            idx += run_len;
        }
    }
    out.done();
    Ok(out.into_vec())
}

fn collect_rebase_sites(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    inputs: LinkEditInputs<'_>,
) -> Result<Vec<RebaseSite>, WriteError> {
    let mut sites = collect_lazy_pointer_rebase_sites(layout, synthetic_plan)?;
    sites.extend(collect_local_got_rebase_sites(
        layout,
        synthetic_plan,
        inputs.0.sym_table,
    )?);
    let input_map: HashMap<InputId, &ObjectFile> = inputs
        .0
        .layout_inputs
        .iter()
        .map(|input| (input.id, input.object))
        .collect();
    let symbol_name_index = build_symbol_name_index(inputs.0.sym_table);

    for section in &layout.sections {
        if !matches!(section.segment.as_str(), "__DATA" | "__DATA_CONST") {
            continue;
        }
        if section.name == "__thread_vars" {
            continue;
        }
        let segment = layout
            .segment(&section.segment)
            .ok_or(WriteError::MissingSegment("__UNKNOWN"))?;
        let segment_index = segment_index(layout, &section.segment)?;
        for placed in &section.atoms {
            let atom = inputs.0.atom_table.get(placed.atom);
            let Some(obj) = input_map.get(&atom.origin).copied() else {
                continue;
            };
            let relocs = inputs
                .0
                .parsed_relocs
                .get(&(atom.origin, atom.input_section))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for reloc in relocs_for_rebase(relocs, atom) {
                if !reloc_needs_rebase(obj, reloc, inputs.0.sym_table, &symbol_name_index) {
                    continue;
                }
                let local_offset = reloc.offset.saturating_sub(atom.input_offset) as u64;
                sites.push(RebaseSite {
                    segment_index,
                    segment_offset: section.addr + placed.offset + local_offset - segment.vm_addr,
                });
            }
        }
    }

    Ok(sites)
}

fn collect_lazy_pointer_rebase_sites(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
) -> Result<Vec<RebaseSite>, WriteError> {
    if synthetic_plan.lazy_pointers.entries.is_empty() {
        return Ok(Vec::new());
    }

    let segment_index = segment_index(layout, "__DATA")?;
    let segment = layout
        .segment("__DATA")
        .ok_or(WriteError::MissingSegment("__DATA"))?;
    let section = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA" && section.name == "__la_symbol_ptr")
        .ok_or(WriteError::MissingSegment("__DATA"))?;

    Ok((0..synthetic_plan.lazy_pointers.entries.len())
        .map(|idx| RebaseSite {
            segment_index,
            segment_offset: section.addr + (idx as u64) * 8 - segment.vm_addr,
        })
        .collect())
}

fn collect_local_got_rebase_sites(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    sym_table: &SymbolTable,
) -> Result<Vec<RebaseSite>, WriteError> {
    if synthetic_plan.got.entries.is_empty() {
        return Ok(Vec::new());
    }

    let segment_index = segment_index(layout, "__DATA_CONST")?;
    let segment = layout
        .segment("__DATA_CONST")
        .ok_or(WriteError::MissingSegment("__DATA_CONST"))?;
    let section = layout
        .sections
        .iter()
        .find(|section| section.segment == "__DATA_CONST" && section.name == "__got")
        .ok_or(WriteError::MissingSegment("__DATA_CONST"))?;

    Ok(synthetic_plan
        .got
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| !matches!(sym_table.get(entry.symbol), Symbol::DylibImport { .. }))
        .map(|(idx, _)| RebaseSite {
            segment_index,
            segment_offset: section.addr + (idx as u64) * 8 - segment.vm_addr,
        })
        .collect())
}

fn relocs_for_rebase<'a>(
    relocs: &'a [Reloc],
    atom: &crate::atom::Atom,
) -> impl Iterator<Item = Reloc> + 'a {
    let start = atom.input_offset;
    let end = atom.input_offset + atom.size;
    relocs.iter().copied().filter(move |reloc| {
        let reloc_end = reloc.offset + reloc.length.byte_width() as u32;
        reloc.offset >= start && reloc_end <= end
    })
}

fn reloc_needs_rebase(
    obj: &ObjectFile,
    reloc: Reloc,
    sym_table: &SymbolTable,
    symbol_name_index: &HashMap<String, SymbolId>,
) -> bool {
    if reloc.kind != RelocKind::Unsigned
        || reloc.length != RelocLength::Quad
        || reloc.pcrel
        || reloc.subtrahend.is_some()
    {
        return false;
    }

    match reloc.referent {
        Referent::Section(_) => true,
        Referent::Symbol(sym_idx) => {
            let Some(input_sym) = obj.symbols.get(sym_idx as usize) else {
                return false;
            };
            match symbol_referent_id(obj, reloc.referent, symbol_name_index) {
                Some(symbol_id) => match sym_table.get(symbol_id) {
                    Symbol::DylibImport { .. } => false,
                    Symbol::Defined { atom, .. } => atom.0 != 0,
                    Symbol::Common { .. } => true,
                    _ => false,
                },
                None => matches!(input_sym.kind(), SymKind::Sect),
            }
        }
    }
}

fn build_symbol_name_index(sym_table: &SymbolTable) -> HashMap<String, SymbolId> {
    sym_table
        .iter()
        .map(|(symbol_id, symbol)| {
            (
                sym_table.interner.resolve(symbol.name()).to_string(),
                symbol_id,
            )
        })
        .collect()
}

fn symbol_referent_id(
    obj: &ObjectFile,
    referent: Referent,
    symbol_name_index: &HashMap<String, SymbolId>,
) -> Option<SymbolId> {
    let Referent::Symbol(sym_idx) = referent else {
        return None;
    };
    let input_sym = obj.symbols.get(sym_idx as usize)?;
    let name = obj.symbol_name(input_sym).ok()?;
    symbol_name_index.get(name).copied()
}

fn build_function_starts(
    layout: &Layout,
    inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
) -> Result<Vec<u8>, WriteError> {
    let image_base = layout
        .segment("__TEXT")
        .ok_or(WriteError::MissingSegment("__TEXT"))?
        .vm_addr;
    let symbol_offsets = build_function_start_symbol_index(inputs);
    let mut starts = Vec::new();

    for section in &layout.sections {
        if section.segment != "__TEXT" || !is_executable(section.kind) {
            continue;
        }
        for placed in &section.atoms {
            starts.push(section.addr + placed.offset - image_base);
            let atom = atom_table.get(placed.atom);
            for alt in &atom.alt_entries {
                starts.push(
                    section.addr + placed.offset + alt.offset_within_atom as u64 - image_base,
                );
            }
            let Some(section_symbols) = symbol_offsets.get(&(atom.origin, atom.input_section))
            else {
                continue;
            };
            let atom_start = atom.input_offset as u64;
            let atom_end = atom_start + atom.size as u64;
            let start_idx = section_symbols.partition_point(|&offset| offset <= atom_start);
            let end_idx = section_symbols.partition_point(|&offset| offset < atom_end);
            if start_idx >= end_idx {
                continue;
            }
            for &offset in &section_symbols[start_idx..end_idx] {
                starts.push(section.addr + placed.offset + (offset - atom_start) - image_base);
            }
        }
    }

    starts.sort_unstable();
    starts.dedup();
    if starts.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut previous = 0u64;
    for start in starts {
        write_uleb(start - previous, &mut out);
        previous = start;
    }
    out.push(0);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    Ok(out)
}

type FunctionStartSymbolIndex = HashMap<(InputId, u8), Vec<u64>>;

fn build_function_start_symbol_index(inputs: &[LayoutInput<'_>]) -> FunctionStartSymbolIndex {
    let mut out: FunctionStartSymbolIndex = HashMap::new();
    for input in inputs {
        for input_sym in &input.object.symbols {
            if input_sym.stab_kind().is_some()
                || input_sym.kind() != SymKind::Sect
                || input_sym.alt_entry()
            {
                continue;
            }
            let Ok(name) = input.object.symbol_name(input_sym) else {
                continue;
            };
            if is_assembler_temporary_symbol(name) {
                continue;
            }
            let Some(section) = input.object.section_for_symbol(input_sym) else {
                continue;
            };
            out.entry((input.id, input_sym.sect_idx()))
                .or_default()
                .push(input_sym.value().saturating_sub(section.addr));
        }
    }
    for offsets in out.values_mut() {
        offsets.sort_unstable();
        offsets.dedup();
    }
    out
}

fn build_data_in_code(
    layout: &Layout,
    inputs: &[LayoutInput<'_>],
    atom_table: &AtomTable,
    icf_redirects: Option<&HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
) -> Result<Vec<u8>, WriteError> {
    #[derive(Clone, Copy)]
    struct RemappedEntry {
        input_order: usize,
        input_entry_index: usize,
        offset: u32,
        length: u16,
        kind: u16,
    }

    let atoms_by_input_section = atom_table.by_input_section();
    let atom_ranges = build_atom_range_index(atom_table, &atoms_by_input_section, icf_redirects);
    let mut remapped = Vec::new();
    for (input_order, input) in inputs.iter().enumerate() {
        for (input_entry_index, entry) in input.object.data_in_code.iter().copied().enumerate() {
            let (section_index, section_relative) =
                remap_data_in_code_to_section(input.object, entry)?;
            let (atom_id, atom_delta) = find_containing_atom_range(
                &atom_ranges,
                input.id,
                section_index,
                section_relative,
                entry.length as u32,
            )
            .ok_or_else(|| {
                WriteError::MalformedDataInCode(
                    input.object.path.clone(),
                    format!(
                        "entry at file offset {} (len {}) did not land inside any atom",
                        entry.offset, entry.length
                    ),
                )
            })?;
            let output_offset = layout.atom_file_offset(atom_id).ok_or_else(|| {
                WriteError::MalformedDataInCode(
                    input.object.path.clone(),
                    format!(
                        "atom {:?} for entry at file offset {} is missing from final layout",
                        atom_id, entry.offset
                    ),
                )
            })? + atom_delta as u64;
            remapped.push(RemappedEntry {
                input_order,
                input_entry_index,
                offset: u32_fit(output_offset, "data-in-code output offset")?,
                length: entry.length,
                kind: entry.kind,
            });
        }
    }

    remapped.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.input_order.cmp(&b.input_order))
            .then_with(|| a.input_entry_index.cmp(&b.input_entry_index))
    });

    let mut out = Vec::with_capacity(remapped.len() * 8);
    for entry in remapped {
        out.extend_from_slice(&entry.offset.to_le_bytes());
        out.extend_from_slice(&entry.length.to_le_bytes());
        out.extend_from_slice(&entry.kind.to_le_bytes());
    }
    Ok(out)
}

fn build_loh(
    _layout: &Layout,
    _inputs: &[LayoutInput<'_>],
    _atom_table: &AtomTable,
    _icf_redirects: Option<&HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
) -> Result<Vec<u8>, WriteError> {
    // Current Apple ld omits LC_LINKER_OPTIMIZATION_HINT from final linked
    // executables and dylibs on our parity corpus, so we do the same.
    Ok(Vec::new())
}

fn remap_data_in_code_to_section(
    object: &ObjectFile,
    entry: DataInCodeEntry,
) -> Result<(u8, u32), WriteError> {
    let entry_start = entry.offset as u64;
    let entry_end = entry_start
        .checked_add(entry.length as u64)
        .ok_or_else(|| {
            WriteError::MalformedDataInCode(
                object.path.clone(),
                format!(
                    "entry at input offset {} with len {} overflows u64",
                    entry.offset, entry.length
                ),
            )
        })?;
    let mut matches = object
        .sections
        .iter()
        .enumerate()
        .filter(|(_, section)| !section.data.is_empty() && is_executable(section.kind))
        .filter_map(|(idx, section)| {
            let section_start = section.addr;
            let section_end = section.addr.checked_add(section.size)?;
            (section_start <= entry_start && entry_end <= section_end)
                .then_some(((idx + 1) as u8, (entry_start - section_start) as u32))
        });
    if let Some(mapped) = matches.next() {
        if matches.next().is_none() {
            return Ok(mapped);
        }
        return Err(WriteError::MalformedDataInCode(
            object.path.clone(),
            format!(
                "entry at input offset {} (len {}) ambiguously matches multiple executable input sections",
                entry.offset, entry.length
            ),
        ));
    }
    Err(WriteError::MalformedDataInCode(
        object.path.clone(),
        format!(
            "entry at input offset {} (len {}) does not map to any executable input section range",
            entry.offset, entry.length
        ),
    ))
}

fn collect_imports(
    sym_table: &SymbolTable,
    synthetic_plan: &SyntheticPlan,
) -> Result<Vec<ImportSymbolRecord>, WriteError> {
    let mut ids: Vec<SymbolId> = synthetic_plan
        .stubs
        .entries
        .iter()
        .map(|entry| entry.symbol)
        .chain(synthetic_plan.got.entries.iter().map(|entry| entry.symbol))
        .chain(
            synthetic_plan
                .thread_pointers
                .entries
                .iter()
                .map(|entry| entry.symbol),
        )
        .chain(
            synthetic_plan
                .lazy_pointers
                .entries
                .iter()
                .map(|entry| entry.symbol),
        )
        .chain(synthetic_plan.direct_binds.iter().map(|entry| entry.symbol))
        .collect();
    if let Some(symbol) = synthetic_plan.tlv_bootstrap_symbol {
        ids.push(symbol);
    }
    ids.sort();
    ids.dedup();

    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let symbol = sym_table.get(id);
        let Symbol::DylibImport {
            name,
            ordinal,
            weak_import,
            ..
        } = symbol
        else {
            continue;
        };
        out.push(ImportSymbolRecord {
            symbol: id,
            name: sym_table.interner.resolve(*name).to_string(),
            ordinal: *ordinal,
            weak_import: *weak_import,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SymbolPlanBuildTimings {
    locals: Duration,
    globals: Duration,
    strtab: Duration,
}

fn build_output_symbols_profiled(
    layout: &Layout,
    kind: OutputKind,
    dead_strip: bool,
    strip_locals: bool,
    visibility: &SymbolVisibilityPolicy,
    inputs: LinkEditInputs<'_>,
    imports: &[ImportSymbolRecord],
) -> Result<(SymbolTablePlan, SymbolPlanBuildTimings), WriteError> {
    let sym_table = inputs.0.sym_table;
    let atom_sections = atom_section_ordinals(layout);
    let atom_addrs = atom_addresses(layout);
    let atoms_by_input_section = inputs.0.atom_table.by_input_section();
    let atom_ranges = build_atom_range_index(
        inputs.0.atom_table,
        &atoms_by_input_section,
        inputs.0.icf_redirects,
    );
    let file_index_by_input: HashMap<InputId, usize> = inputs
        .0
        .layout_inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| (input.id, idx + 1))
        .collect();
    let image_base = layout.segment("__TEXT").map(|seg| seg.vm_addr).unwrap_or(0);
    let mut timings = SymbolPlanBuildTimings::default();
    let mut locals = Vec::new();
    let mut external_defineds = Vec::new();
    let mut undefineds = Vec::with_capacity(imports.len());

    if kind == OutputKind::Executable && !layout.sections.is_empty() {
        let text_vmaddr = layout
            .segment("__TEXT")
            .ok_or(WriteError::MissingSegment("__TEXT"))?
            .vm_addr;
        let hide_header = visibility.hides("__mh_execute_header");
        let header_partition = if hide_header {
            OutputSymbolPartition::Local
        } else {
            OutputSymbolPartition::ExternalDefined
        };
        let header_type = defined_symbol_type(hide_header);
        let target = if hide_header {
            &mut locals
        } else {
            &mut external_defineds
        };
        target.push(OutputSymbolSpec {
            symbol: None,
            name: "__mh_execute_header".to_string(),
            partition: header_partition,
            n_type: header_type,
            n_sect: 1,
            n_desc: REFERENCED_DYNAMICALLY,
            n_value: text_vmaddr,
            size: 0,
            file_index: 0,
        });
    }

    let phase_started = std::time::Instant::now();
    for input in inputs.0.layout_inputs {
        let ctx = LocalSymbolContext {
            atom_table: inputs.0.atom_table,
            atom_ranges: &atom_ranges,
            atom_sections: &atom_sections,
            atom_addrs: &atom_addrs,
            input_id: input.id,
            file_index: file_index_by_input[&input.id],
        };
        collect_local_symbols(&ctx, input.object, &mut locals)?;
    }
    collect_synthetic_local_symbols(layout, inputs.0.synthetic_plan, &mut locals)?;
    timings.locals += phase_started.elapsed();

    let phase_started = std::time::Instant::now();
    for (symbol_id, symbol) in sym_table.iter() {
        let Symbol::Defined {
            name,
            origin,
            atom,
            value,
            weak,
            private_extern,
            no_dead_strip,
            ..
        } = symbol
        else {
            continue;
        };
        if *private_extern {
            continue;
        }
        let name = sym_table.interner.resolve(*name).to_string();
        let hidden = visibility.hides(&name);
        let (n_type, n_sect, n_value) = if atom.0 == 0 {
            (absolute_symbol_type(hidden), NO_SECT, *value)
        } else {
            let Some(addr) = atom_addrs.get(atom).copied() else {
                if dead_strip {
                    continue;
                }
                return Err(WriteError::DefinedSymbolAtomMissing(symbol_id, *atom));
            };
            let sect = *atom_sections
                .get(atom)
                .ok_or(WriteError::DefinedSymbolSectionMissing(symbol_id, *atom))?;
            (defined_symbol_type(hidden), sect, addr + *value)
        };
        let size = if atom.0 == 0 {
            0
        } else {
            inputs
                .0
                .atom_table
                .get(*atom)
                .size
                .saturating_sub(*value as u32) as u64
        };
        let mut n_desc = 0;
        if *weak {
            n_desc |= N_WEAK_DEF;
        }
        if *no_dead_strip {
            n_desc |= N_NO_DEAD_STRIP;
        }
        let partition = if hidden {
            OutputSymbolPartition::Local
        } else {
            OutputSymbolPartition::ExternalDefined
        };
        let target = if hidden {
            &mut locals
        } else {
            &mut external_defineds
        };
        target.push(OutputSymbolSpec {
            symbol: Some(symbol_id),
            name,
            partition,
            n_type,
            n_sect,
            n_desc,
            n_value,
            size,
            file_index: file_index_by_input.get(origin).copied().unwrap_or(0),
        });
    }

    sort_local_symbols(&mut locals);
    external_defineds.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    for import in imports {
        let mut n_desc = import.ordinal << 8;
        if import.weak_import {
            n_desc |= N_WEAK_REF;
        }
        undefineds.push(OutputSymbolSpec {
            symbol: Some(import.symbol),
            name: import.name.clone(),
            partition: OutputSymbolPartition::Undefined,
            n_type: N_UNDF | N_EXT,
            n_sect: NO_SECT,
            n_desc,
            n_value: 0,
            size: 0,
            file_index: 0,
        });
    }
    undefineds.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    timings.globals += phase_started.elapsed();

    let exports = if matches!(kind, OutputKind::Dylib | OutputKind::Executable) {
        external_defineds
            .iter()
            .map(|spec| ExportEntry {
                name: spec.name.clone(),
                flags: export_symbol_flags(layout, spec.n_desc, spec.n_type, spec.n_sect),
                kind: export_symbol_kind(
                    layout,
                    image_base,
                    spec.n_type,
                    spec.n_sect,
                    spec.n_value,
                ),
            })
            .collect()
    } else {
        Vec::new()
    };

    let phase_started = std::time::Instant::now();
    let local_count = if strip_locals { 0 } else { locals.len() };
    let mut specs = Vec::with_capacity(local_count + external_defineds.len() + undefineds.len());
    if !strip_locals {
        specs.extend(locals);
    }
    specs.extend(external_defineds);
    specs.extend(undefineds);

    let mut strtab = StringTableBuilder::new();
    for spec in &specs {
        strtab.insert(&spec.name);
    }
    let (strtab_bytes, strx_by_name) = strtab.finish();

    let nlocalsym = specs
        .iter()
        .filter(|spec| spec.partition == OutputSymbolPartition::Local)
        .count() as u32;
    let nextdefsym = specs
        .iter()
        .filter(|spec| spec.partition == OutputSymbolPartition::ExternalDefined)
        .count() as u32;
    let nundefsym = specs
        .iter()
        .filter(|spec| spec.partition == OutputSymbolPartition::Undefined)
        .count() as u32;

    let mut symbols = Vec::with_capacity(specs.len());
    let mut symbol_indices = HashMap::new();
    let map_symbols = specs
        .iter()
        .filter(|spec| spec.partition != OutputSymbolPartition::Undefined)
        .map(|spec| LinkMapSymbol {
            name: spec.name.clone(),
            addr: spec.n_value,
            size: spec.size,
            file_index: spec.file_index,
        })
        .collect();
    for (idx, spec) in specs.into_iter().enumerate() {
        let strx = *strx_by_name
            .get(&spec.name)
            .expect("string table offset missing for output symbol");
        symbols.push(InputSymbol::from_raw(RawNlist {
            strx,
            n_type: spec.n_type,
            n_sect: spec.n_sect,
            n_desc: spec.n_desc,
            n_value: spec.n_value,
        }));
        if let Some(symbol) = spec.symbol {
            symbol_indices.insert(symbol, idx as u32);
        }
    }
    timings.strtab += phase_started.elapsed();

    Ok((
        SymbolTablePlan {
            symbols,
            map_symbols,
            strtab_bytes,
            symbol_indices,
            exports,
            dysymtab: DysymtabCmd {
                ilocalsym: 0,
                nlocalsym,
                iextdefsym: nlocalsym,
                nextdefsym,
                iundefsym: nlocalsym + nextdefsym,
                nundefsym,
                ..DysymtabCmd::default()
            },
        },
        timings,
    ))
}

fn sort_local_symbols(locals: &mut [OutputSymbolSpec]) {
    locals.sort_by(|lhs, rhs| {
        lhs.n_sect
            .cmp(&rhs.n_sect)
            .then_with(|| lhs.n_value.cmp(&rhs.n_value))
            .then_with(|| lhs.n_type.cmp(&rhs.n_type))
            .then_with(|| lhs.name.cmp(&rhs.name))
    });
}

fn collect_synthetic_local_symbols(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    out: &mut Vec<OutputSymbolSpec>,
) -> Result<(), WriteError> {
    if !synthetic_plan.needs_dyld_private {
        return Ok(());
    }

    let Some((section_index, section)) = layout
        .sections
        .iter()
        .enumerate()
        .find(|(_, section)| section.segment == "__DATA" && section.name == "__data")
    else {
        return Err(WriteError::MissingSegment("__DATA"));
    };

    out.push(OutputSymbolSpec {
        symbol: None,
        name: "__dyld_private".to_string(),
        partition: OutputSymbolPartition::Local,
        n_type: N_SECT,
        n_sect: u8::try_from(section_index + 1).expect("section index should fit in n_sect"),
        n_desc: 0,
        n_value: section.addr + section.synthetic_offset,
        size: 8,
        file_index: 0,
    });
    Ok(())
}

fn collect_local_symbols(
    ctx: &LocalSymbolContext<'_>,
    object: &ObjectFile,
    out: &mut Vec<OutputSymbolSpec>,
) -> Result<(), WriteError> {
    for input_sym in &object.symbols {
        if input_sym.stab_kind().is_some() {
            continue;
        }
        if input_sym.is_ext() && !input_sym.is_private_ext() {
            continue;
        }
        let name = object.symbol_name(input_sym).unwrap_or("").to_string();
        if is_assembler_temporary_symbol(&name) {
            continue;
        }
        match input_sym.kind() {
            SymKind::Sect => {
                let section = object
                    .section_for_symbol(input_sym)
                    .expect("section symbol without section");
                let offset = input_sym.value().saturating_sub(section.addr) as u32;
                let (atom_id, delta) = find_containing_atom(
                    ctx.atom_ranges,
                    ctx.input_id,
                    input_sym.sect_idx(),
                    offset,
                )
                .ok_or(WriteError::MissingSegment("__UNKNOWN"))?;
                let addr = ctx.atom_addrs.get(&atom_id).copied().ok_or(
                    WriteError::DefinedSymbolAtomMissing(SymbolId(u32::MAX), atom_id),
                )? + delta as u64;
                let n_sect = *ctx.atom_sections.get(&atom_id).ok_or(
                    WriteError::DefinedSymbolSectionMissing(SymbolId(u32::MAX), atom_id),
                )?;
                out.push(OutputSymbolSpec {
                    symbol: None,
                    name,
                    partition: OutputSymbolPartition::Local,
                    n_type: input_symbol_type(input_sym),
                    n_sect,
                    n_desc: input_sym.raw.n_desc,
                    n_value: addr,
                    size: ctx.atom_table.get(atom_id).size.saturating_sub(delta) as u64,
                    file_index: ctx.file_index,
                });
            }
            SymKind::Abs => {
                out.push(OutputSymbolSpec {
                    symbol: None,
                    name,
                    partition: OutputSymbolPartition::Local,
                    n_type: input_symbol_type(input_sym),
                    n_sect: NO_SECT,
                    n_desc: input_sym.raw.n_desc,
                    n_value: input_sym.value(),
                    size: 0,
                    file_index: ctx.file_index,
                });
            }
            SymKind::Undef | SymKind::Indirect => {}
        }
    }
    Ok(())
}

struct LocalSymbolContext<'a> {
    atom_table: &'a AtomTable,
    atom_ranges: &'a AtomRangeIndex,
    atom_sections: &'a HashMap<crate::resolve::AtomId, u8>,
    atom_addrs: &'a HashMap<crate::resolve::AtomId, u64>,
    input_id: InputId,
    file_index: usize,
}

#[derive(Debug, Clone, Copy)]
struct AtomRange {
    atom: crate::resolve::AtomId,
    start: u32,
    end: u32,
}

type AtomRangeIndex = HashMap<(InputId, u8), Vec<AtomRange>>;

fn is_assembler_temporary_symbol(name: &str) -> bool {
    name.starts_with('L') || name.starts_with("ltmp")
}

fn build_atom_range_index(
    atom_table: &AtomTable,
    atoms_by_input_section: &HashMap<(InputId, u8), Vec<crate::resolve::AtomId>>,
    icf_redirects: Option<&HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
) -> AtomRangeIndex {
    let mut out = HashMap::with_capacity(atoms_by_input_section.len());
    for (&key, ids) in atoms_by_input_section {
        let mut ranges = Vec::with_capacity(ids.len());
        for atom_id in ids {
            let atom = atom_table.get(*atom_id);
            ranges.push(AtomRange {
                atom: canonical_atom(*atom_id, icf_redirects),
                start: atom.input_offset,
                end: atom.input_offset.saturating_add(atom.size),
            });
        }
        ranges.sort_by(|lhs, rhs| {
            lhs.start
                .cmp(&rhs.start)
                .then_with(|| lhs.end.cmp(&rhs.end))
        });
        out.insert(key, ranges);
    }
    out
}

fn find_containing_atom(
    atom_ranges: &AtomRangeIndex,
    input_id: InputId,
    input_section: u8,
    offset: u32,
) -> Option<(crate::resolve::AtomId, u32)> {
    find_containing_atom_range(atom_ranges, input_id, input_section, offset, 1)
}

fn find_containing_atom_range(
    atom_ranges: &AtomRangeIndex,
    input_id: InputId,
    input_section: u8,
    offset: u32,
    len: u32,
) -> Option<(crate::resolve::AtomId, u32)> {
    let ranges = atom_ranges.get(&(input_id, input_section))?;
    let range_end = offset.checked_add(len)?;
    let idx = ranges.partition_point(|range| range.start <= offset);
    let range = idx.checked_sub(1).and_then(|idx| ranges.get(idx))?;
    (range.start <= offset && range_end <= range.end).then_some((range.atom, offset - range.start))
}

fn canonical_atom(
    atom_id: crate::resolve::AtomId,
    redirects: Option<&HashMap<crate::resolve::AtomId, crate::resolve::AtomId>>,
) -> crate::resolve::AtomId {
    let Some(redirects) = redirects else {
        return atom_id;
    };
    let mut current = atom_id;
    while let Some(&next) = redirects.get(&current) {
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn input_symbol_type(input_sym: &InputSymbol) -> u8 {
    let mut n_type = match input_sym.kind() {
        SymKind::Sect => N_SECT,
        SymKind::Abs => N_ABS,
        SymKind::Undef => N_UNDF,
        SymKind::Indirect => N_INDR,
    };
    if input_sym.is_private_ext() {
        n_type |= N_PEXT;
    } else if input_sym.is_ext() {
        n_type |= N_EXT;
    }
    n_type
}

fn atom_section_ordinals(layout: &Layout) -> HashMap<crate::resolve::AtomId, u8> {
    let mut out = HashMap::new();
    for (idx, section) in layout.sections.iter().enumerate() {
        let ordinal = (idx + 1) as u8;
        for placed in &section.atoms {
            out.insert(placed.atom, ordinal);
        }
    }
    out
}

fn atom_addresses(layout: &Layout) -> HashMap<AtomId, u64> {
    let mut out = HashMap::new();
    for section in &layout.sections {
        for placed in &section.atoms {
            out.insert(placed.atom, section.addr + placed.offset);
        }
    }
    out
}

fn export_symbol_flags(layout: &Layout, n_desc: u16, n_type: u8, n_sect: u8) -> u64 {
    let mut flags = 0u64;
    if n_desc & N_WEAK_DEF != 0 {
        flags |= EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
    }
    match n_type & N_TYPE {
        N_ABS => flags | EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
        _ if section_is_thread_local(layout, n_sect) => {
            flags | EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
        }
        _ => flags,
    }
}

fn export_symbol_kind(
    layout: &Layout,
    image_base: u64,
    n_type: u8,
    n_sect: u8,
    n_value: u64,
) -> ExportKind {
    match n_type & N_TYPE {
        N_ABS => ExportKind::Absolute { address: n_value },
        _ if section_is_thread_local(layout, n_sect) => ExportKind::ThreadLocal {
            address: n_value.saturating_sub(image_base),
        },
        _ => ExportKind::Regular {
            address: n_value.saturating_sub(image_base),
        },
    }
}

fn section_is_thread_local(layout: &Layout, n_sect: u8) -> bool {
    if n_sect == 0 {
        return false;
    }
    layout
        .sections
        .get(n_sect as usize - 1)
        .map(|section| {
            matches!(
                section.kind,
                crate::section::SectionKind::ThreadLocalRegular
                    | crate::section::SectionKind::ThreadLocalZeroFill
            )
        })
        .unwrap_or(false)
}

fn defined_symbol_type(private_extern: bool) -> u8 {
    if private_extern {
        N_SECT | N_PEXT
    } else {
        N_SECT | N_EXT
    }
}

fn absolute_symbol_type(private_extern: bool) -> u8 {
    if private_extern {
        N_ABS | N_PEXT
    } else {
        N_ABS | N_EXT
    }
}

fn read_symbol_patterns(path: &PathBuf) -> Result<Vec<String>, WriteError> {
    let contents = fs::read_to_string(path)
        .map_err(|err| WriteError::SymbolListRead(path.clone(), err.to_string()))?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut p = 0usize;
    let mut v = 0usize;
    let mut star = None;
    let mut backtrack = 0usize;

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            backtrack = v;
        } else if let Some(star_idx) = star {
            p = star_idx + 1;
            backtrack += 1;
            v = backtrack;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn place_optional_block(
    cursor: &mut u64,
    size: usize,
    context: &'static str,
) -> Result<u32, WriteError> {
    if size == 0 {
        return Ok(0);
    }
    place_required_block(cursor, size, context)
}

fn place_required_block(
    cursor: &mut u64,
    size: usize,
    context: &'static str,
) -> Result<u32, WriteError> {
    *cursor = align_up(*cursor, 8);
    let offset = u32_fit(*cursor, context)?;
    *cursor += size as u64;
    Ok(offset)
}

fn place_linkedit_data_block(
    cursor: &mut u64,
    size: usize,
    context: &'static str,
) -> Result<LinkEditDataCmd, WriteError> {
    *cursor = align_up(*cursor, 8);
    let dataoff = u32_fit(*cursor, context)?;
    *cursor += size as u64;
    Ok(LinkEditDataCmd {
        dataoff,
        datasize: size as u32,
    })
}

fn place_optional_linkedit_data_block(
    cursor: &mut u64,
    size: usize,
    context: &'static str,
) -> Result<Option<LinkEditDataCmd>, WriteError> {
    if size == 0 {
        return Ok(None);
    }
    Ok(Some(place_linkedit_data_block(cursor, size, context)?))
}

fn push_indirect_section(
    indirect_symbols: &mut Vec<u32>,
    indirect_starts: &mut HashMap<(String, String), u32>,
    key: (&str, &str),
    symbols: impl Iterator<Item = u32>,
) {
    let start = indirect_symbols.len() as u32;
    let mut saw_any = false;
    for symbol in symbols {
        saw_any = true;
        indirect_symbols.push(symbol);
    }
    if saw_any {
        indirect_starts.insert((key.0.to_string(), key.1.to_string()), start);
    }
}

fn indirect_symbol_index(
    symbol: SymbolId,
    import_lookup: &HashMap<SymbolId, &ImportSymbolRecord>,
    symbol_indices: &HashMap<SymbolId, u32>,
) -> u32 {
    if import_lookup.contains_key(&symbol) {
        symbol_indices
            .get(&symbol)
            .copied()
            .unwrap_or(INDIRECT_SYMBOL_LOCAL)
    } else {
        INDIRECT_SYMBOL_LOCAL
    }
}

fn build_bind_streams(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    imports: &HashMap<SymbolId, &ImportSymbolRecord>,
) -> Result<BindStreams, WriteError> {
    let mut bind_specs = Vec::new();
    let weak_bind = Vec::new();
    let mut lazy_bind = OpcodeStream::new();
    let mut lazy_offsets = HashMap::new();
    let layout_index = BindLayoutIndex::build(layout)?;

    if let Some(tlv_bootstrap) = synthetic_plan.tlv_bootstrap_symbol {
        let segment_index = segment_index(layout, "__DATA")?;
        let segment = layout
            .segment("__DATA")
            .ok_or(WriteError::MissingSegment("__DATA"))?;
        if let Some(section) = layout
            .sections
            .iter()
            .find(|section| section.segment == "__DATA" && section.name == "__thread_vars")
        {
            let import = imports
                .get(&tlv_bootstrap)
                .copied()
                .ok_or(WriteError::ImportSymbolMissing(tlv_bootstrap))?;
            for placed in &section.atoms {
                for descriptor_offset in
                    (0..placed.size).step_by(THREAD_VARIABLE_DESCRIPTOR_SIZE as usize)
                {
                    let slot_addr = section.addr + placed.offset + descriptor_offset;
                    bind_specs.push(BindRecordSpec {
                        segment_index,
                        segment_offset: slot_addr - segment.vm_addr,
                        ordinal: import.ordinal,
                        name: &import.name,
                        weak_import: import.weak_import,
                        addend: 0,
                        terminate: false,
                    });
                }
            }
        }
    }

    if !synthetic_plan.got.entries.is_empty() {
        let segment_index = segment_index(layout, "__DATA_CONST")?;
        let segment = layout
            .segment("__DATA_CONST")
            .ok_or(WriteError::MissingSegment("__DATA_CONST"))?;
        let section = layout
            .sections
            .iter()
            .find(|section| section.segment == "__DATA_CONST" && section.name == "__got")
            .ok_or(WriteError::MissingSegment("__DATA_CONST"))?;
        for (idx, entry) in synthetic_plan.got.entries.iter().enumerate() {
            let Some(import) = imports.get(&entry.symbol).copied() else {
                continue;
            };
            let slot_addr = section.addr + (idx as u64) * 8;
            bind_specs.push(BindRecordSpec {
                segment_index,
                segment_offset: slot_addr - segment.vm_addr,
                ordinal: import.ordinal,
                name: &import.name,
                weak_import: import.weak_import,
                addend: 0,
                terminate: false,
            });
        }
    }

    for entry in &synthetic_plan.direct_binds {
        let import = imports
            .get(&entry.symbol)
            .copied()
            .ok_or(WriteError::ImportSymbolMissing(entry.symbol))?;
        let placement = layout_index
            .atoms
            .get(&entry.atom)
            .ok_or(WriteError::DirectBindAtomMissing(entry.atom))?;
        if placement.is_thread_vars {
            // `__thread_vars` starts are emitted through the dedicated
            // `__tlv_bootstrap` pass above. Descriptor tails are rewritten to
            // template offsets before write, so any generic direct bind landing
            // back in this section is stale and would override the TLV bind.
            continue;
        }
        let slot_addr = placement.addr + entry.atom_offset as u64;
        bind_specs.push(BindRecordSpec {
            segment_index: placement.segment_index,
            segment_offset: slot_addr - placement.segment_vm_addr,
            ordinal: import.ordinal,
            name: &import.name,
            weak_import: import.weak_import,
            addend: entry.addend,
            terminate: false,
        });
    }

    if let Some(last) = bind_specs.last_mut() {
        last.terminate = true;
    }

    if !synthetic_plan.lazy_pointers.entries.is_empty() {
        let segment_index = segment_index(layout, "__DATA")?;
        let segment = layout
            .segment("__DATA")
            .ok_or(WriteError::MissingSegment("__DATA"))?;
        let section = layout
            .sections
            .iter()
            .find(|section| section.segment == "__DATA" && section.name == "__la_symbol_ptr")
            .ok_or(WriteError::MissingSegment("__DATA"))?;
        for (idx, entry) in synthetic_plan.lazy_pointers.entries.iter().enumerate() {
            let import = imports
                .get(&entry.symbol)
                .copied()
                .ok_or(WriteError::ImportSymbolMissing(entry.symbol))?;
            let slot_addr = section.addr + (idx as u64) * 8;
            lazy_offsets.insert(entry.symbol, lazy_bind.len() as u32);
            emit_lazy_bind_record(
                &mut lazy_bind,
                segment_index,
                slot_addr - segment.vm_addr,
                import.ordinal,
                &import.name,
                import.weak_import,
            );
        }
    }

    Ok(BindStreams {
        bind: emit_bind_records(&bind_specs),
        weak_bind,
        lazy_bind: lazy_bind.into_vec(),
        lazy_offsets,
    })
}

struct BindLayoutIndex {
    atoms: HashMap<AtomId, BindAtomPlacement>,
}

#[derive(Clone, Copy)]
struct BindAtomPlacement {
    addr: u64,
    segment_index: u8,
    segment_vm_addr: u64,
    is_thread_vars: bool,
}

impl BindLayoutIndex {
    fn build(layout: &Layout) -> Result<Self, WriteError> {
        let mut segment_meta = HashMap::with_capacity(layout.segments.len());
        for (idx, segment) in layout.segments.iter().enumerate() {
            segment_meta.insert(
                segment.name.as_str(),
                (
                    u8::try_from(idx).map_err(|_| WriteError::OffsetTooLarge("segment index"))?,
                    segment.vm_addr,
                ),
            );
        }
        let atom_count: usize = layout
            .sections
            .iter()
            .map(|section| section.atoms.len())
            .sum();
        let mut atoms = HashMap::with_capacity(atom_count);
        for section in &layout.sections {
            let Some((segment_index, segment_vm_addr)) =
                segment_meta.get(section.segment.as_str()).copied()
            else {
                continue;
            };
            let is_thread_vars = section.segment == "__DATA" && section.name == "__thread_vars";
            for placed in &section.atoms {
                atoms.insert(
                    placed.atom,
                    BindAtomPlacement {
                        addr: section.addr + placed.offset,
                        segment_index,
                        segment_vm_addr,
                        is_thread_vars,
                    },
                );
            }
        }
        Ok(Self { atoms })
    }
}

fn segment_index(layout: &Layout, name: &str) -> Result<u8, WriteError> {
    let idx = layout
        .segments
        .iter()
        .position(|segment| segment.name == name)
        .ok_or(WriteError::MissingSegment(match name {
            "__DATA_CONST" => "__DATA_CONST",
            "__DATA" => "__DATA",
            "__TEXT" => "__TEXT",
            "__LINKEDIT" => "__LINKEDIT",
            _ => "__UNKNOWN",
        }))?;
    u8::try_from(idx).map_err(|_| WriteError::OffsetTooLarge("segment index"))
}

fn apply_indirect_starts(layout: &mut Layout, linkedit: &LinkEditPlan) {
    for section in &mut layout.sections {
        if let Some(&start) = linkedit
            .indirect_starts
            .get(&(section.segment.clone(), section.name.clone()))
        {
            section.reserved1 = start;
        }
    }
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
    use crate::atom::{AltEntry, Atom, AtomFlags, AtomSection, AtomTable};
    use crate::input::ObjectFile;
    use crate::layout::{Layout, PAGE_SIZE};
    use crate::leb::read_uleb;
    use crate::macho::reader::MachHeader64;
    use crate::resolve::{AtomId, InputId, SymbolId};
    use crate::section::{
        InputSection, OutputAtom, OutputSection, OutputSectionId, OutputSegment, Prot, SectionKind,
    };
    use crate::string_table::StringTable;

    use super::*;

    fn decode_function_starts_blob(blob: &[u8]) -> Vec<u64> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut current = 0u64;
        while cursor < blob.len() {
            let (delta, used) = read_uleb(&blob[cursor..]).unwrap();
            cursor += used;
            if delta == 0 {
                break;
            }
            current += delta;
            out.push(current);
        }
        out
    }

    #[test]
    fn minimal_executable_writes_parseable_header() {
        let layout = Layout::empty(OutputKind::Executable, 0);
        let mut bytes = Vec::new();
        write(
            &layout,
            OutputKind::Executable,
            &LinkOptions::default(),
            &mut bytes,
        )
        .unwrap();

        let header = crate::macho::reader::parse_header(&bytes).unwrap();
        let commands = crate::macho::reader::parse_commands(&header, &bytes).unwrap();
        assert_eq!(header.filetype, MH_EXECUTE);
        assert!(
            commands
                .iter()
                .any(|cmd| matches!(cmd, LoadCommand::Raw { cmd, .. } if *cmd == LC_MAIN)),
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
        write(
            &layout,
            OutputKind::Executable,
            &LinkOptions::default(),
            &mut bytes,
        )
        .unwrap();

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
        write(
            &layout,
            OutputKind::Executable,
            &LinkOptions::default(),
            &mut bytes,
        )
        .unwrap();

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

    #[test]
    fn function_starts_use_all_executable_text_atoms_and_alt_entries_only() {
        let mut atoms = AtomTable::new();
        let atom_id = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(1),
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 16,
            align_pow2: 2,
            owner: None,
            alt_entries: vec![AltEntry {
                symbol: SymbolId(1),
                offset_within_atom: 8,
            }],
            data: vec![0; 16],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let coalesced_atom_id = atoms.push(Atom {
            id: AtomId(1),
            origin: InputId(1),
            input_section: 2,
            section: AtomSection::Text,
            input_offset: 0,
            size: 4,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 4],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let layout = Layout {
            kind: OutputKind::Executable,
            segments: vec![OutputSegment {
                name: "__TEXT".into(),
                sections: vec![
                    OutputSectionId(0),
                    OutputSectionId(1),
                    OutputSectionId(2),
                    OutputSectionId(3),
                ],
                vm_addr: 0x1_0000_0000,
                vm_size: 0x4000,
                file_off: 0,
                file_size: 0x4000,
                init_prot: Prot::READ_EXECUTE,
                max_prot: Prot::READ_EXECUTE,
                flags: 0,
            }],
            sections: vec![
                OutputSection {
                    segment: "__TEXT".into(),
                    name: "__text".into(),
                    kind: SectionKind::Text,
                    align_pow2: 2,
                    flags: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    atoms: vec![OutputAtom {
                        atom: atom_id,
                        offset: 0,
                        size: 16,
                        data: vec![0; 16],
                    }],
                    synthetic_offset: 0,
                    synthetic_data: Vec::new(),
                    addr: 0x1_0000_1000,
                    size: 16,
                    file_off: 0x1000,
                },
                OutputSection {
                    segment: "__TEXT".into(),
                    name: "__stubs".into(),
                    kind: SectionKind::SymbolStubs,
                    align_pow2: 2,
                    flags: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    atoms: Vec::new(),
                    synthetic_offset: 0,
                    synthetic_data: vec![0; 12],
                    addr: 0x1_0000_1010,
                    size: 12,
                    file_off: 0x1010,
                },
                OutputSection {
                    segment: "__TEXT".into(),
                    name: "__stub_helper".into(),
                    kind: SectionKind::Text,
                    align_pow2: 2,
                    flags: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    atoms: Vec::new(),
                    synthetic_offset: 0,
                    synthetic_data: vec![0; 36],
                    addr: 0x1_0000_101c,
                    size: 36,
                    file_off: 0x101c,
                },
                OutputSection {
                    segment: "__TEXT".into(),
                    name: "__textcoal_nt".into(),
                    kind: SectionKind::Coalesced,
                    align_pow2: 2,
                    flags: 0,
                    reserved1: 0,
                    reserved2: 0,
                    reserved3: 0,
                    atoms: vec![OutputAtom {
                        atom: coalesced_atom_id,
                        offset: 0,
                        size: 4,
                        data: vec![0; 4],
                    }],
                    synthetic_offset: 0,
                    synthetic_data: Vec::new(),
                    addr: 0x1_0000_1040,
                    size: 4,
                    file_off: 0x1040,
                },
            ],
        };

        let blob = build_function_starts(&layout, &[], &atoms).unwrap();
        assert_eq!(
            decode_function_starts_blob(&blob),
            vec![0x1000, 0x1008, 0x1040]
        );
    }

    #[test]
    fn function_starts_index_uses_only_interior_named_entries() {
        let mut atoms = AtomTable::new();
        let atom_id = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(1),
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 0,
            size: 16,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 16],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let zero_atom_id = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(1),
            input_section: 1,
            section: AtomSection::Text,
            input_offset: 16,
            size: 0,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: Vec::new(),
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let object = object_with_text_symbols(&[
            ("_start", 0x1000, 0),
            ("Ltmp0", 0x1004, 0),
            ("_middle", 0x1008, 0),
            ("_alt", 0x100c, N_ALT_ENTRY),
            ("_end", 0x1010, 0),
        ]);
        let inputs = [LayoutInput {
            id: InputId(1),
            object: &object,
            load_order: 0,
            archive_member_offset: None,
        }];
        let layout = Layout {
            kind: OutputKind::Executable,
            segments: vec![OutputSegment {
                name: "__TEXT".into(),
                sections: vec![OutputSectionId(0)],
                vm_addr: 0x1_0000_0000,
                vm_size: 0x4000,
                file_off: 0,
                file_size: 0x4000,
                init_prot: Prot::READ_EXECUTE,
                max_prot: Prot::READ_EXECUTE,
                flags: 0,
            }],
            sections: vec![OutputSection {
                segment: "__TEXT".into(),
                name: "__text".into(),
                kind: SectionKind::Text,
                align_pow2: 2,
                flags: 0,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                atoms: vec![
                    OutputAtom {
                        atom: atom_id,
                        offset: 0,
                        size: 16,
                        data: vec![0; 16],
                    },
                    OutputAtom {
                        atom: zero_atom_id,
                        offset: 16,
                        size: 0,
                        data: Vec::new(),
                    },
                ],
                synthetic_offset: 0,
                synthetic_data: Vec::new(),
                addr: 0x1_0000_1000,
                size: 16,
                file_off: 0x1000,
            }],
        };

        let blob = build_function_starts(&layout, &inputs, &atoms).unwrap();
        assert_eq!(
            decode_function_starts_blob(&blob),
            vec![0x1000, 0x1008, 0x1010]
        );
    }

    fn object_with_text_symbols(symbols: &[(&str, u64, u16)]) -> ObjectFile {
        let mut strings = vec![0];
        let mut strx = Vec::new();
        for (name, _, _) in symbols {
            strx.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        ObjectFile {
            path: "function-starts-index.o".into(),
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
            sections: vec![InputSection {
                segname: "__TEXT".into(),
                sectname: "__text".into(),
                kind: SectionKind::Text,
                addr: 0x1000,
                size: 16,
                align_pow2: 2,
                flags: 0,
                offset: 0,
                reloff: 0,
                nreloc: 0,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
                data: vec![0; 16],
                raw_relocs: Vec::new(),
            }],
            symbols: symbols
                .iter()
                .zip(strx)
                .map(|((_, value, desc), strx)| {
                    InputSymbol::from_raw(RawNlist {
                        strx,
                        n_type: N_SECT,
                        n_sect: 1,
                        n_desc: *desc,
                        n_value: *value,
                    })
                })
                .collect(),
            strings: StringTable::from_bytes(strings),
            symtab: None,
            dysymtab: None,
            loh: Vec::new(),
            data_in_code: Vec::new(),
        }
    }

    #[test]
    fn containing_atom_lookup_reuses_precomputed_section_index() {
        let mut atoms = AtomTable::new();
        let first = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(7),
            input_section: 3,
            section: AtomSection::Text,
            input_offset: 0,
            size: 8,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 8],
            flags: AtomFlags::NONE,
            parent_of: None,
        });
        let second = atoms.push(Atom {
            id: AtomId(0),
            origin: InputId(7),
            input_section: 3,
            section: AtomSection::Text,
            input_offset: 8,
            size: 12,
            align_pow2: 2,
            owner: None,
            alt_entries: Vec::new(),
            data: vec![0; 12],
            flags: AtomFlags::NONE,
            parent_of: None,
        });

        let by_input_section = atoms.by_input_section();
        let atom_ranges = build_atom_range_index(&atoms, &by_input_section, None);
        assert_eq!(
            find_containing_atom(&atom_ranges, InputId(7), 3, 4),
            Some((first, 4))
        );
        assert_eq!(
            find_containing_atom_range(&atom_ranges, InputId(7), 3, 10, 2),
            Some((second, 2))
        );
    }
}
