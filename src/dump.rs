//! `afs-ld --dump <path>` — otool-style summary of a Mach-O object.
//!
//! Sprint 1 prints the `mach_header_64` + every load command in `header.ncmds`.
//! Section bodies, symbols, strings, and relocations become visible as Sprint 2
//! and later sprints bring them into the reader's model.

use std::io::{self, Write};
use std::path::Path;

use crate::archive::Archive;
use crate::input::ObjectFile;
use crate::macho::constants::*;
use crate::macho::dylib::{DylibFile, DylibLoadKind};
use crate::macho::exports::ExportKind;
use crate::macho::reader::{
    BuildVersionCmd, DyldInfoCmd, DylibCmd, DysymtabCmd, LinkEditDataCmd, LoadCommand,
    MachHeader64, RpathCmd, Section64Header, Segment64, SymtabCmd,
};
use crate::macho::tbd::parse_tbd;
use crate::reloc::{parse_raw_relocs, parse_relocs, Referent, Reloc, RelocKind};
use crate::section::InputSection;
use crate::symbol::{InputSymbol, SymKind};

pub fn dump_archive_file(path: &Path) -> io::Result<()> {
    let bytes = std::fs::read(path)?;
    let ar = Archive::open(path, &bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let out = io::stdout();
    let mut h = out.lock();
    for member in ar.members() {
        writeln!(h, "{}", member.name)?;
    }
    Ok(())
}

pub fn dump_tbd_file(path: &Path) -> io::Result<()> {
    let src = std::fs::read_to_string(path)?;
    let docs =
        parse_tbd(&src).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let out = io::stdout();
    let mut h = out.lock();
    writeln!(h, "{}:", path.display())?;
    writeln!(h, "tbd: documents={}", docs.len())?;
    for (i, tbd) in docs.iter().enumerate() {
        let targets: Vec<String> = tbd.targets.iter().map(|t| t.as_string()).collect();
        writeln!(
            h,
            "  [{i}] install_name={:?} targets=[{}] current={} compat={}",
            tbd.install_name,
            targets.join(", "),
            tbd.current_version.as_deref().unwrap_or("-"),
            tbd.compatibility_version.as_deref().unwrap_or("-")
        )?;
        if !tbd.reexported_libraries.is_empty() {
            let total: usize = tbd.reexported_libraries.iter().map(|s| s.value.len()).sum();
            writeln!(h, "      reexported-libraries: {total}")?;
        }
        let export_syms: usize = tbd.exports.iter().map(|s| s.value.total()).sum();
        if export_syms > 0 {
            writeln!(h, "      exports: {export_syms} symbols total")?;
        }
    }
    Ok(())
}

pub fn dump_dylib_file(path: &Path) -> io::Result<()> {
    let bytes = std::fs::read(path)?;
    let dy = DylibFile::parse(path, &bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let out = io::stdout();
    let mut h = out.lock();
    writeln!(h, "{}:", path.display())?;
    writeln!(
        h,
        "dylib: install_name={:?} current={} compat={}",
        dy.install_name,
        version_str(dy.current_version),
        version_str(dy.compatibility_version)
    )?;
    writeln!(h, "Dependencies ({}):", dy.dependencies.len())?;
    for d in &dy.dependencies {
        let kind = match d.kind {
            DylibLoadKind::Normal => "normal",
            DylibLoadKind::Weak => "weak",
            DylibLoadKind::Reexport => "reexport",
            DylibLoadKind::Upward => "upward",
        };
        writeln!(
            h,
            "  [{}] {kind:<8} {} current={} compat={}",
            d.ordinal,
            d.install_name,
            version_str(d.current_version),
            version_str(d.compatibility_version)
        )?;
    }
    if !dy.rpaths.is_empty() {
        writeln!(h, "Rpaths ({}):", dy.rpaths.len())?;
        for (i, p) in dy.rpaths.iter().enumerate() {
            writeln!(h, "  [{i}] {p}")?;
        }
    }
    let entries = dy
        .exports
        .entries()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    writeln!(h, "Exports ({}):", entries.len())?;
    for (i, e) in entries.iter().enumerate().take(32) {
        let rhs = match &e.kind {
            ExportKind::Regular { address } => format!("addr=0x{address:x}"),
            ExportKind::ThreadLocal { address } => format!("tlv addr=0x{address:x}"),
            ExportKind::Absolute { address } => format!("abs=0x{address:x}"),
            ExportKind::Reexport {
                ordinal,
                imported_name,
            } => {
                if imported_name.is_empty() {
                    format!("reexport from dylib#{ordinal}")
                } else {
                    format!("reexport from dylib#{ordinal} as {imported_name}")
                }
            }
            ExportKind::StubAndResolver { stub, resolver } => {
                format!("stub=0x{stub:x} resolver=0x{resolver:x}")
            }
        };
        writeln!(h, "  [{i}] {:<40} {rhs}", e.name)?;
    }
    if entries.len() > 32 {
        writeln!(h, "  ... ({} more)", entries.len() - 32)?;
    }
    Ok(())
}

pub fn dump_file(path: &Path) -> io::Result<()> {
    let bytes = std::fs::read(path)?;
    let obj = ObjectFile::parse(path, &bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let out = io::stdout();
    let mut h = out.lock();
    writeln!(h, "{}:", path.display())?;
    write_header(&mut h, &obj.header)?;
    for (i, cmd) in obj.commands.iter().enumerate() {
        write_command(&mut h, i, cmd)?;
    }
    write_sections(&mut h, &obj.sections)?;
    write_symbols(&mut h, &obj)?;
    Ok(())
}

fn write_header(w: &mut impl Write, hdr: &MachHeader64) -> io::Result<()> {
    writeln!(
        w,
        "mach_header_64: {} {} ncmds={} sizeofcmds={} flags=0x{:08x}",
        cpu_name(hdr.cputype),
        filetype_name(hdr.filetype),
        hdr.ncmds,
        hdr.sizeofcmds,
        hdr.flags
    )
}

fn write_command(w: &mut impl Write, idx: usize, cmd: &LoadCommand) -> io::Result<()> {
    writeln!(w, "Load command {idx}")?;
    writeln!(w, "      cmd {}", cmd_name(cmd.cmd()))?;
    writeln!(w, "  cmdsize {}", cmd.cmdsize())?;
    match cmd {
        LoadCommand::Segment64(s) => write_segment64(w, s),
        LoadCommand::Symtab(s) => write_symtab(w, s),
        LoadCommand::Dysymtab(d) => write_dysymtab(w, d),
        LoadCommand::BuildVersion(b) => write_build_version(w, b),
        LoadCommand::LinkerOptimizationHint(l) => write_linkedit_data(w, l, "LOH"),
        LoadCommand::Dylib(d) => write_dylib(w, d),
        LoadCommand::Rpath(r) => write_rpath(w, r),
        LoadCommand::DyldInfoOnly(d) => write_dyld_info(w, d),
        LoadCommand::DyldExportsTrie(l) => write_linkedit_data(w, l, "EXPORTS_TRIE"),
        LoadCommand::DyldChainedFixups(l) => write_linkedit_data(w, l, "CHAINED_FIXUPS"),
        LoadCommand::Raw { cmd, data, .. } => {
            writeln!(w, "  rawcmd 0x{cmd:x}")?;
            writeln!(w, " payload {} bytes", data.len())
        }
    }
}

fn write_dylib(w: &mut impl Write, d: &DylibCmd) -> io::Result<()> {
    writeln!(
        w,
        "  name={:?} timestamp={} current={} compat={}",
        d.name,
        d.timestamp,
        version_str(d.current_version),
        version_str(d.compatibility_version)
    )
}

fn write_rpath(w: &mut impl Write, r: &RpathCmd) -> io::Result<()> {
    writeln!(w, "  path={:?}", r.path)
}

fn write_dyld_info(w: &mut impl Write, d: &DyldInfoCmd) -> io::Result<()> {
    writeln!(
        w,
        " rebase_off {} rebase_size {} bind_off {} bind_size {} weak_bind_off {} weak_bind_size {} lazy_bind_off {} lazy_bind_size {} export_off {} export_size {}",
        d.rebase_off,
        d.rebase_size,
        d.bind_off,
        d.bind_size,
        d.weak_bind_off,
        d.weak_bind_size,
        d.lazy_bind_off,
        d.lazy_bind_size,
        d.export_off,
        d.export_size
    )
}

fn write_segment64(w: &mut impl Write, s: &Segment64) -> io::Result<()> {
    writeln!(w, "  segname {}", s.segname_str())?;
    writeln!(w, "   vmaddr 0x{:016x}", s.vmaddr)?;
    writeln!(w, "   vmsize 0x{:016x}", s.vmsize)?;
    writeln!(w, "  fileoff {}", s.fileoff)?;
    writeln!(w, " filesize {}", s.filesize)?;
    writeln!(w, "  maxprot {}", prot_str(s.maxprot))?;
    writeln!(w, " initprot {}", prot_str(s.initprot))?;
    writeln!(w, "   nsects {}", s.sections.len())?;
    writeln!(w, "    flags {}", segment_flags_str(s.flags))?;
    for sec in &s.sections {
        write_section(w, sec)?;
    }
    Ok(())
}

fn write_section(w: &mut impl Write, s: &Section64Header) -> io::Result<()> {
    writeln!(w, "Section")?;
    writeln!(w, "  sectname {}", s.sectname_str())?;
    writeln!(w, "   segname {}", s.segname_str())?;
    writeln!(w, "      addr 0x{:016x}", s.addr)?;
    writeln!(w, "      size 0x{:016x}", s.size)?;
    writeln!(w, "    offset {}", s.offset)?;
    writeln!(w, "     align 2^{} ({})", s.align, 1u64 << s.align)?;
    writeln!(w, "    reloff {}", s.reloff)?;
    writeln!(w, "    nreloc {}", s.nreloc)?;
    writeln!(w, "      type {}", section_type_name(s.flags))?;
    writeln!(w, "attributes {}", section_attributes(s.flags))?;
    writeln!(w, " reserved1 {}", s.reserved1)?;
    writeln!(w, " reserved2 {}", s.reserved2)
}

fn write_symtab(w: &mut impl Write, s: &SymtabCmd) -> io::Result<()> {
    writeln!(w, "  symoff {}", s.symoff)?;
    writeln!(w, "   nsyms {}", s.nsyms)?;
    writeln!(w, "  stroff {}", s.stroff)?;
    writeln!(w, " strsize {}", s.strsize)
}

fn write_dysymtab(w: &mut impl Write, d: &DysymtabCmd) -> io::Result<()> {
    writeln!(w, "      ilocalsym {}", d.ilocalsym)?;
    writeln!(w, "      nlocalsym {}", d.nlocalsym)?;
    writeln!(w, "     iextdefsym {}", d.iextdefsym)?;
    writeln!(w, "     nextdefsym {}", d.nextdefsym)?;
    writeln!(w, "      iundefsym {}", d.iundefsym)?;
    writeln!(w, "      nundefsym {}", d.nundefsym)?;
    writeln!(w, "         tocoff {}", d.tocoff)?;
    writeln!(w, "           ntoc {}", d.ntoc)?;
    writeln!(w, "      modtaboff {}", d.modtaboff)?;
    writeln!(w, "        nmodtab {}", d.nmodtab)?;
    writeln!(w, "   extrefsymoff {}", d.extrefsymoff)?;
    writeln!(w, "    nextrefsyms {}", d.nextrefsyms)?;
    writeln!(w, " indirectsymoff {}", d.indirectsymoff)?;
    writeln!(w, "  nindirectsyms {}", d.nindirectsyms)?;
    writeln!(w, "      extreloff {}", d.extreloff)?;
    writeln!(w, "        nextrel {}", d.nextrel)?;
    writeln!(w, "      locreloff {}", d.locreloff)?;
    writeln!(w, "        nlocrel {}", d.nlocrel)
}

fn write_build_version(w: &mut impl Write, b: &BuildVersionCmd) -> io::Result<()> {
    writeln!(w, " platform {}", platform_name(b.platform))?;
    writeln!(w, "    minos {}", otool_version_str(b.minos))?;
    writeln!(w, "      sdk {}", otool_sdk_str(b.sdk))?;
    writeln!(w, "   ntools {}", b.tools.len())?;
    for t in &b.tools {
        writeln!(
            w,
            "    tool {} version {}",
            t.tool,
            otool_version_str(t.version)
        )?;
    }
    Ok(())
}

fn write_linkedit_data(w: &mut impl Write, l: &LinkEditDataCmd, kind: &str) -> io::Result<()> {
    let _ = kind;
    writeln!(w, " dataoff {}", l.dataoff)?;
    writeln!(w, "datasize {}", l.datasize)
}

fn write_sections(w: &mut impl Write, secs: &[InputSection]) -> io::Result<()> {
    if secs.is_empty() {
        return Ok(());
    }
    writeln!(w, "Sections ({}):", secs.len())?;
    for (i, s) in secs.iter().enumerate() {
        writeln!(
            w,
            "  [{i}] {},{:<16} {:?} addr=0x{:x} size=0x{:x} align=2^{} offset={} flags=0x{:08x}",
            s.segname, s.sectname, s.kind, s.addr, s.size, s.align_pow2, s.offset, s.flags
        )?;
        if !s.data.is_empty() {
            writeln!(w, "      data: {}", hex_preview(&s.data, 16))?;
        }
        if s.nreloc > 0 {
            writeln!(w, "      relocs ({}):", s.nreloc)?;
            match parse_raw_relocs(&s.raw_relocs, 0, s.nreloc).and_then(|raws| parse_relocs(&raws))
            {
                Ok(fused) => {
                    for (ri, r) in fused.iter().enumerate() {
                        writeln!(w, "        [{ri}] {}", describe_reloc(r))?;
                    }
                }
                Err(e) => writeln!(w, "        <parse error: {e}>")?,
            }
        }
    }
    Ok(())
}

fn write_symbols(w: &mut impl Write, obj: &ObjectFile) -> io::Result<()> {
    if obj.symbols.is_empty() {
        return Ok(());
    }
    writeln!(w, "Symbols ({}):", obj.symbols.len())?;
    for (i, sym) in obj.symbols.iter().enumerate() {
        let name = obj.symbol_name(sym).unwrap_or("<unresolved>");
        writeln!(w, "  [{i}] {:<32} {}", name, describe_symbol(sym))?;
    }
    Ok(())
}

fn describe_symbol(sym: &InputSymbol) -> String {
    if let Some(stab) = sym.stab_kind() {
        return format!(
            "STAB kind=0x{stab:02x} sect={} value=0x{:x}",
            sym.sect_idx(),
            sym.value()
        );
    }
    let mut parts: Vec<String> = Vec::new();
    parts.push(
        match sym.kind() {
            SymKind::Undef => "UNDF",
            SymKind::Abs => "ABS",
            SymKind::Sect => "SECT",
            SymKind::Indirect => "INDR",
        }
        .to_string(),
    );
    if sym.is_ext() {
        parts.push("ext".into());
    }
    if sym.is_private_ext() {
        parts.push("pext".into());
    }
    if sym.weak_def() {
        parts.push("weak_def".into());
    }
    if sym.weak_ref() {
        parts.push("weak_ref".into());
    }
    if sym.no_dead_strip() {
        parts.push("no_dead_strip".into());
    }
    match sym.kind() {
        SymKind::Sect => parts.push(format!("sect={} value=0x{:x}", sym.sect_idx(), sym.value())),
        SymKind::Abs => parts.push(format!("value=0x{:x}", sym.value())),
        SymKind::Undef => {
            if let Some(sz) = sym.common_size() {
                let a = sym.common_align_pow2().unwrap_or(0);
                parts.push(format!("common size={sz} align=2^{a}"));
            } else if let Some(ord) = sym.library_ordinal() {
                parts.push(format!("ord={ord}"));
            }
        }
        SymKind::Indirect => {
            parts.push(format!("-> strx={}", sym.value() as u32));
        }
    }
    parts.join(" ")
}

fn describe_reloc(r: &Reloc) -> String {
    let kind = match r.kind {
        RelocKind::Unsigned => "Unsigned",
        RelocKind::Branch26 => "Branch26",
        RelocKind::Page21 => "Page21",
        RelocKind::PageOff12 => "PageOff12",
        RelocKind::GotLoadPage21 => "GotLoadPage21",
        RelocKind::GotLoadPageOff12 => "GotLoadPageOff12",
        RelocKind::PointerToGot => "PointerToGot",
        RelocKind::TlvpLoadPage21 => "TlvpLoadPage21",
        RelocKind::TlvpLoadPageOff12 => "TlvpLoadPageOff12",
        RelocKind::Subtractor => "Subtractor",
    };
    let width = r.length.byte_width();
    let mut parts = vec![
        format!("offset=0x{:x}", r.offset),
        kind.to_string(),
        format!("len={width}"),
    ];
    if r.pcrel {
        parts.push("pcrel".into());
    }
    parts.push(match r.referent {
        Referent::Symbol(i) => format!("sym={i}"),
        Referent::Section(i) => format!("sect={i}"),
    });
    if let Some(sub) = r.subtrahend {
        parts.push(match sub {
            Referent::Symbol(i) => format!("- sym={i}"),
            Referent::Section(i) => format!("- sect={i}"),
        });
    }
    if r.addend != 0 {
        parts.push(format!("+ 0x{:x}", r.addend));
    }
    parts.join(" ")
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let shown = bytes.iter().take(max);
    let hex: Vec<String> = shown.map(|b| format!("{b:02x}")).collect();
    if bytes.len() > max {
        format!("{} ... ({} more)", hex.join(" "), bytes.len() - max)
    } else {
        hex.join(" ")
    }
}

// ---- pretty-printers ------------------------------------------------------

fn cpu_name(ct: u32) -> &'static str {
    match ct {
        CPU_TYPE_ARM64 => "arm64",
        _ => "??",
    }
}

fn filetype_name(ft: u32) -> &'static str {
    match ft {
        MH_OBJECT => "MH_OBJECT",
        MH_EXECUTE => "MH_EXECUTE",
        MH_DYLIB => "MH_DYLIB",
        _ => "??",
    }
}

fn cmd_name(cmd: u32) -> String {
    match cmd {
        LC_SEGMENT_64 => "LC_SEGMENT_64".into(),
        LC_SYMTAB => "LC_SYMTAB".into(),
        LC_DYSYMTAB => "LC_DYSYMTAB".into(),
        LC_BUILD_VERSION => "LC_BUILD_VERSION".into(),
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT".into(),
        LC_UUID => "LC_UUID".into(),
        LC_MAIN => "LC_MAIN".into(),
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB".into(),
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER".into(),
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB".into(),
        LC_ID_DYLIB => "LC_ID_DYLIB".into(),
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB".into(),
        LC_RPATH => "LC_RPATH".into(),
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE".into(),
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS".into(),
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE".into(),
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION".into(),
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY".into(),
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS".into(),
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE".into(),
        _ => format!("LC_0x{cmd:x}"),
    }
}

fn platform_name(p: u32) -> &'static str {
    match p {
        PLATFORM_MACOS => "MACOS",
        PLATFORM_IOS => "IOS",
        _ => "UNKNOWN",
    }
}

/// X.Y.Z packed 0xXXXXYYZZ → "X.Y.Z".
fn version_str(v: u32) -> String {
    let x = (v >> 16) & 0xffff;
    let y = (v >> 8) & 0xff;
    let z = v & 0xff;
    format!("{x}.{y}.{z}")
}

fn prot_str(p: u32) -> String {
    let r = if p & 1 != 0 { 'r' } else { '-' };
    let w = if p & 2 != 0 { 'w' } else { '-' };
    let x = if p & 4 != 0 { 'x' } else { '-' };
    format!("{r}{w}{x}")
}

fn segment_flags_str(flags: u32) -> String {
    if flags == 0 {
        "(none)".into()
    } else {
        format!("0x{flags:x}")
    }
}

fn section_type_name(flags: u32) -> &'static str {
    match flags & SECTION_TYPE_MASK {
        S_REGULAR => "S_REGULAR",
        S_ZEROFILL => "S_ZEROFILL",
        S_CSTRING_LITERALS => "S_CSTRING_LITERALS",
        S_4BYTE_LITERALS => "S_4BYTE_LITERALS",
        S_8BYTE_LITERALS => "S_8BYTE_LITERALS",
        S_LITERAL_POINTERS => "S_LITERAL_POINTERS",
        S_NON_LAZY_SYMBOL_POINTERS => "S_NON_LAZY_SYMBOL_POINTERS",
        S_LAZY_SYMBOL_POINTERS => "S_LAZY_SYMBOL_POINTERS",
        S_SYMBOL_STUBS => "S_SYMBOL_STUBS",
        S_MOD_INIT_FUNC_POINTERS => "S_MOD_INIT_FUNC_POINTERS",
        S_MOD_TERM_FUNC_POINTERS => "S_MOD_TERM_FUNC_POINTERS",
        S_COALESCED => "S_COALESCED",
        S_GB_ZEROFILL => "S_GB_ZEROFILL",
        S_INTERPOSING => "S_INTERPOSING",
        S_16BYTE_LITERALS => "S_16BYTE_LITERALS",
        S_THREAD_LOCAL_REGULAR => "S_THREAD_LOCAL_REGULAR",
        S_THREAD_LOCAL_ZEROFILL => "S_THREAD_LOCAL_ZEROFILL",
        S_THREAD_LOCAL_VARIABLES => "S_THREAD_LOCAL_VARIABLES",
        S_THREAD_LOCAL_VARIABLE_POINTERS => "S_THREAD_LOCAL_VARIABLE_POINTERS",
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
        _ => "UNKNOWN",
    }
}

fn section_attributes(flags: u32) -> String {
    let attrs = [
        (S_ATTR_PURE_INSTRUCTIONS, "PURE_INSTRUCTIONS"),
        (S_ATTR_NO_TOC, "NO_TOC"),
        (S_ATTR_STRIP_STATIC_SYMS, "STRIP_STATIC_SYMS"),
        (S_ATTR_NO_DEAD_STRIP, "NO_DEAD_STRIP"),
        (S_ATTR_LIVE_SUPPORT, "LIVE_SUPPORT"),
        (S_ATTR_SELF_MODIFYING_CODE, "SELF_MODIFYING_CODE"),
        (S_ATTR_DEBUG, "DEBUG"),
        (S_ATTR_SOME_INSTRUCTIONS, "SOME_INSTRUCTIONS"),
        (S_ATTR_EXT_RELOC, "EXT_RELOC"),
        (S_ATTR_LOC_RELOC, "LOC_RELOC"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
    .collect::<Vec<_>>();
    if attrs.is_empty() {
        "(none)".into()
    } else {
        attrs.join(" ")
    }
}

fn otool_version_str(v: u32) -> String {
    let x = (v >> 16) & 0xffff;
    let y = (v >> 8) & 0xff;
    let z = v & 0xff;
    if z == 0 {
        format!("{x}.{y}")
    } else {
        format!("{x}.{y}.{z}")
    }
}

fn otool_sdk_str(v: u32) -> String {
    if v == 0 {
        "n/a".into()
    } else {
        otool_version_str(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_str_examples() {
        assert_eq!(version_str(0x000B_0000), "11.0.0");
        assert_eq!(version_str(0x000E_0200), "14.2.0");
        assert_eq!(version_str(0x000E_0203), "14.2.3");
    }

    #[test]
    fn prot_str_examples() {
        assert_eq!(prot_str(0), "---");
        assert_eq!(prot_str(7), "rwx");
        assert_eq!(prot_str(5), "r-x");
    }
}
