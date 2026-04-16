//! Sprint 10 Mach-O writer.
//!
//! Emits a parseable `MH_EXECUTE` or `MH_DYLIB` image from the output layout.

use std::collections::HashMap;
use std::fmt;

use crate::leb::write_uleb;
use crate::layout::Layout;
use crate::macho::constants::*;
use crate::macho::dylib::DylibDependency;
use crate::macho::reader::{
    write_commands, write_header, BuildVersionCmd, BuildTool, DyldInfoCmd, DysymtabCmd,
    DylibCmd, LoadCommand, MachHeader64, Section64Header, Segment64, SymtabCmd, HEADER_SIZE,
};
use crate::resolve::{Symbol, SymbolId, SymbolTable};
use crate::symbol::{write_nlist_table, InputSymbol, RawNlist};
use crate::synth::{code_sig::CodeSignaturePlan, SyntheticPlan};
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
    ImportSymbolMissing(SymbolId),
    ImportSymbolWrongKind(SymbolId),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::MissingSegment(name) => write!(f, "missing output segment `{name}`"),
            WriteError::OffsetTooLarge(what) => write!(f, "{what} exceeds 32-bit Mach-O field width"),
            WriteError::EntryAtomMissing(atom) => write!(f, "entry atom {:?} missing from layout", atom),
            WriteError::ImportSymbolMissing(symbol) => {
                write!(f, "synthetic import symbol {:?} missing from symbol table", symbol)
            }
            WriteError::ImportSymbolWrongKind(symbol) => {
                write!(f, "synthetic import symbol {:?} is not a dylib import", symbol)
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
    sym_table: &SymbolTable,
    synthetic_plan: &SyntheticPlan,
) -> Result<(Layout, LinkEditPlan), WriteError> {
    finalize_with_linkedit(layout, kind, opts, dylibs, Some((sym_table, synthetic_plan)))
}

fn finalize_with_linkedit(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    imports: Option<(&SymbolTable, &SyntheticPlan)>,
) -> Result<(Layout, LinkEditPlan), WriteError> {
    let mut layout = layout.clone();
    let mut linkedit = build_linkedit_plan(&layout, kind, opts, imports)?;
    apply_indirect_starts(&mut layout, &linkedit);
    let header_size = estimate_header_size(&layout, kind, opts, dylibs, &linkedit);
    layout.relayout(header_size);

    linkedit = build_linkedit_plan(&layout, kind, opts, imports)?;
    apply_indirect_starts(&mut layout, &linkedit);
    let sizeofcmds: u32 = build_commands(&layout, kind, opts, None, dylibs, &linkedit)?
        .iter()
        .map(LoadCommand::cmdsize)
        .sum();
    let header_size = HEADER_SIZE as u64 + sizeofcmds as u64;
    layout.relayout(header_size);
    linkedit = build_linkedit_plan(&layout, kind, opts, imports)?;
    apply_indirect_starts(&mut layout, &linkedit);

    let linkedit_seg = layout
        .segment_mut("__LINKEDIT")
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    linkedit_seg.file_size = linkedit.total_size().max(1);
    linkedit_seg.vm_size = linkedit.total_size().max(1);
    Ok((layout, linkedit))
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
    let commands = build_commands(
        layout,
        kind,
        opts,
        entry_point,
        dylibs,
        linkedit_plan,
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
    let lazy_bind_off = linkedit_plan.dyld_info.lazy_bind_off as usize;
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
    if !linkedit_plan.lazy_bind_bytes.is_empty() {
        let end = lazy_bind_off + linkedit_plan.lazy_bind_bytes.len();
        out[lazy_bind_off..end].copy_from_slice(&linkedit_plan.lazy_bind_bytes);
    }
    let end = stroff + linkedit_plan.strtab_bytes.len();
    out[stroff..end].copy_from_slice(&linkedit_plan.strtab_bytes);
    if let Some(code_signature) = &linkedit_plan.code_signature {
        let start = code_signature.dataoff as usize;
        let bytes = code_signature.build(&out[..start]);
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
        OutputKind::Executable => {
            commands.push(raw_dylinker_command("/usr/lib/dyld"));
            commands.push(raw_entry_point(resolve_entryoff(layout, entry_point)?, 0));
        }
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

    commands.push(LoadCommand::Symtab(linkedit.symtab));
    commands.push(LoadCommand::Dysymtab(linkedit.dysymtab));
    commands.push(raw_linkedit_command(LC_FUNCTION_STARTS, 0, 0));
    commands.push(raw_linkedit_command(LC_DATA_IN_CODE, 0, 0));
    if let Some(code_signature) = &linkedit.code_signature {
        commands.push(raw_linkedit_command(
            LC_CODE_SIGNATURE,
            code_signature.dataoff,
            code_signature.datasize,
        ));
    } else {
        commands.push(raw_linkedit_command(LC_CODE_SIGNATURE, 0, 0));
    }
    commands.push(LoadCommand::DyldInfoOnly(linkedit.dyld_info));

    Ok(commands)
}

fn estimate_header_size(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    dylibs: &[DylibDependency],
    _linkedit: &LinkEditPlan,
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
        OutputKind::Executable => raw_dylinker_command("/usr/lib/dyld").cmdsize() as u64 + 24,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEditPlan {
    pub symtab: SymtabCmd,
    pub dysymtab: DysymtabCmd,
    pub dyld_info: DyldInfoCmd,
    pub symtab_bytes: Vec<u8>,
    pub indirect_bytes: Vec<u8>,
    rebase_bytes: Vec<u8>,
    bind_bytes: Vec<u8>,
    lazy_bind_bytes: Vec<u8>,
    pub strtab_bytes: Vec<u8>,
    code_signature: Option<CodeSignaturePlan>,
    indirect_starts: HashMap<(String, String), u32>,
    lazy_bind_offsets: HashMap<SymbolId, u32>,
}

impl LinkEditPlan {
    fn minimal(layout: &Layout, kind: OutputKind, opts: &LinkOptions) -> Result<Self, WriteError> {
        build_linkedit_plan(layout, kind, opts, None)
    }

    fn total_size(&self) -> u64 {
        let base_off = self.symtab.symoff as u64;
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
}

fn build_linkedit_plan(
    layout: &Layout,
    kind: OutputKind,
    opts: &LinkOptions,
    imports: Option<(&SymbolTable, &SyntheticPlan)>,
) -> Result<LinkEditPlan, WriteError> {
    let linkedit = layout
        .segment("__LINKEDIT")
        .cloned()
        .ok_or(WriteError::MissingSegment("__LINKEDIT"))?;
    let base_off = u32_fit(linkedit.file_off, "linkedit file offset")?;

    let Some((sym_table, synthetic_plan)) = imports else {
        return Ok(LinkEditPlan {
            symtab: SymtabCmd {
                symoff: base_off,
                nsyms: 0,
                stroff: base_off,
                strsize: 1,
            },
            dysymtab: DysymtabCmd::default(),
            dyld_info: DyldInfoCmd::default(),
            symtab_bytes: Vec::new(),
            indirect_bytes: Vec::new(),
            rebase_bytes: Vec::new(),
            bind_bytes: Vec::new(),
            lazy_bind_bytes: Vec::new(),
            strtab_bytes: vec![0],
            code_signature: Some(build_code_signature(layout, kind, opts, base_off as u64 + 1)?),
            indirect_starts: HashMap::new(),
            lazy_bind_offsets: HashMap::new(),
        });
    };

    let imports = collect_imports(sym_table, synthetic_plan)?;
    let import_lookup: HashMap<SymbolId, &ImportSymbolRecord> =
        imports.iter().map(|record| (record.symbol, record)).collect();
    let mut strtab_bytes = vec![0];
    let mut symbols = Vec::with_capacity(imports.len());
    let mut symbol_indices = HashMap::new();
    for (idx, import) in imports.iter().enumerate() {
        let strx = strtab_bytes.len() as u32;
        strtab_bytes.extend_from_slice(import.name.as_bytes());
        strtab_bytes.push(0);
        let mut n_desc = import.ordinal << 8;
        if import.weak_import {
            n_desc |= N_WEAK_REF;
        }
        symbols.push(InputSymbol::from_raw(RawNlist {
            strx,
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc,
            n_value: 0,
        }));
        symbol_indices.insert(import.symbol, idx as u32);
    }

    let mut symtab_bytes = Vec::new();
    write_nlist_table(&symbols, &mut symtab_bytes);

    let mut indirect_symbols = Vec::new();
    let mut indirect_starts = HashMap::new();
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__TEXT", "__stubs"),
        synthetic_plan
            .stubs
            .entries
            .iter()
            .map(|entry| entry.symbol),
        &symbol_indices,
    );
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__DATA_CONST", "__got"),
        synthetic_plan.got.entries.iter().map(|entry| entry.symbol),
        &symbol_indices,
    );
    push_indirect_section(
        &mut indirect_symbols,
        &mut indirect_starts,
        ("__DATA", "__la_symbol_ptr"),
        synthetic_plan
            .lazy_pointers
            .entries
            .iter()
            .map(|entry| entry.symbol),
        &symbol_indices,
    );

    let mut indirect_bytes = Vec::with_capacity(indirect_symbols.len() * 4);
    for index in &indirect_symbols {
        indirect_bytes.extend_from_slice(&index.to_le_bytes());
    }

    let bind_streams = build_bind_streams(layout, synthetic_plan, &import_lookup)?;
    let rebase_bytes = build_rebase_stream(layout, synthetic_plan)?;

    let symoff = base_off;
    let indirectsymoff = u32_fit(
        symoff as u64 + symtab_bytes.len() as u64,
        "indirect symbol table offset",
    )?;
    let rebase_off = if rebase_bytes.is_empty() {
        0
    } else {
        u32_fit(
            indirectsymoff as u64 + indirect_bytes.len() as u64,
            "rebase stream offset",
        )?
    };
    let bindoff = if bind_streams.bind.is_empty() {
        0
    } else {
        u32_fit(
            indirectsymoff as u64 + indirect_bytes.len() as u64 + rebase_bytes.len() as u64,
            "bind stream offset",
        )?
    };
    let lazy_bind_off = if bind_streams.lazy_bind.is_empty() {
        0
    } else {
        u32_fit(
            indirectsymoff as u64
                + indirect_bytes.len() as u64
                + rebase_bytes.len() as u64
                + bind_streams.bind.len() as u64,
            "lazy bind stream offset",
        )?
    };
    let stroff = u32_fit(
        indirectsymoff as u64
            + indirect_bytes.len() as u64
            + rebase_bytes.len() as u64
            + bind_streams.bind.len() as u64
            + bind_streams.lazy_bind.len() as u64,
        "string table offset",
    )?;
    let regular_end = stroff as u64 + strtab_bytes.len() as u64;
    Ok(LinkEditPlan {
        symtab: SymtabCmd {
            symoff,
            nsyms: symbols.len() as u32,
            stroff,
            strsize: strtab_bytes.len() as u32,
        },
        dysymtab: DysymtabCmd {
            iundefsym: 0,
            nundefsym: symbols.len() as u32,
            indirectsymoff,
            nindirectsyms: indirect_symbols.len() as u32,
            ..DysymtabCmd::default()
        },
        dyld_info: DyldInfoCmd {
            rebase_off,
            rebase_size: rebase_bytes.len() as u32,
            bind_off: bindoff,
            bind_size: bind_streams.bind.len() as u32,
            lazy_bind_off,
            lazy_bind_size: bind_streams.lazy_bind.len() as u32,
            ..DyldInfoCmd::default()
        },
        symtab_bytes,
        indirect_bytes,
        rebase_bytes,
        bind_bytes: bind_streams.bind,
        lazy_bind_bytes: bind_streams.lazy_bind,
        strtab_bytes,
        code_signature: Some(build_code_signature(layout, kind, opts, regular_end)?),
        indirect_starts,
        lazy_bind_offsets: bind_streams.lazy_offsets,
    })
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

#[derive(Debug, Clone)]
struct ImportSymbolRecord {
    symbol: SymbolId,
    name: String,
    ordinal: u16,
    weak_import: bool,
}

struct BindStreams {
    bind: Vec<u8>,
    lazy_bind: Vec<u8>,
    lazy_offsets: HashMap<SymbolId, u32>,
}

fn build_rebase_stream(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
) -> Result<Vec<u8>, WriteError> {
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

    let mut out = Vec::new();
    out.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    out.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (segment_index & REBASE_IMMEDIATE_MASK));
    write_uleb(section.addr - segment.vm_addr, &mut out);
    emit_rebase_run(&mut out, synthetic_plan.lazy_pointers.entries.len());
    out.push(REBASE_OPCODE_DONE);
    Ok(out)
}

fn emit_rebase_run(out: &mut Vec<u8>, count: usize) {
    if count <= REBASE_IMMEDIATE_MASK as usize {
        out.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | count as u8);
    } else {
        out.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
        write_uleb(count as u64, out);
    }
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
                .lazy_pointers
                .entries
                .iter()
                .map(|entry| entry.symbol),
        )
        .collect();
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
            return Err(WriteError::ImportSymbolWrongKind(id));
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

fn push_indirect_section(
    indirect_symbols: &mut Vec<u32>,
    indirect_starts: &mut HashMap<(String, String), u32>,
    key: (&str, &str),
    symbols: impl Iterator<Item = SymbolId>,
    symbol_indices: &HashMap<SymbolId, u32>,
) {
    let start = indirect_symbols.len() as u32;
    let mut saw_any = false;
    for symbol in symbols {
        saw_any = true;
        indirect_symbols.push(*symbol_indices.get(&symbol).expect("symbol index missing"));
    }
    if saw_any {
        indirect_starts.insert((key.0.to_string(), key.1.to_string()), start);
    }
}

fn build_bind_streams(
    layout: &Layout,
    synthetic_plan: &SyntheticPlan,
    imports: &HashMap<SymbolId, &ImportSymbolRecord>,
) -> Result<BindStreams, WriteError> {
    let mut bind = Vec::new();
    let mut lazy_bind = Vec::new();
    let mut lazy_offsets = HashMap::new();

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
            let import = imports
                .get(&entry.symbol)
                .copied()
                .ok_or(WriteError::ImportSymbolMissing(entry.symbol))?;
            let slot_addr = section.addr + (idx as u64) * 8;
            emit_bind_record(
                &mut bind,
                segment_index,
                slot_addr - segment.vm_addr,
                import.ordinal,
                &import.name,
                import.weak_import,
                false,
            );
        }
        if !bind.is_empty() {
            bind.push(BIND_OPCODE_DONE);
        }
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
            emit_bind_record(
                &mut lazy_bind,
                segment_index,
                slot_addr - segment.vm_addr,
                import.ordinal,
                &import.name,
                import.weak_import,
                true,
            );
        }
    }

    Ok(BindStreams {
        bind,
        lazy_bind,
        lazy_offsets,
    })
}

fn emit_bind_record(
    out: &mut Vec<u8>,
    segment_index: u8,
    segment_offset: u64,
    ordinal: u16,
    name: &str,
    weak_import: bool,
    terminate: bool,
) {
    emit_bind_ordinal(out, ordinal);
    out.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | bind_symbol_flags(weak_import));
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
    out.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (segment_index & BIND_IMMEDIATE_MASK));
    write_uleb(segment_offset, out);
    out.push(BIND_OPCODE_DO_BIND);
    if terminate {
        out.push(BIND_OPCODE_DONE);
    }
}

fn emit_bind_ordinal(out: &mut Vec<u8>, ordinal: u16) {
    let signed = ordinal as i16;
    if (-8..=-1).contains(&signed) {
        out.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | ((signed as u8) & BIND_IMMEDIATE_MASK));
    } else if ordinal <= BIND_IMMEDIATE_MASK as u16 {
        out.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal as u8);
    } else {
        out.push(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
        write_uleb(ordinal as u64, out);
    }
}

fn bind_symbol_flags(weak_import: bool) -> u8 {
    if weak_import {
        BIND_SYMBOL_FLAGS_WEAK_IMPORT
    } else {
        0
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
