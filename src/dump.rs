//! `afs-ld --dump <path>` — otool-style summary of a Mach-O object.
//!
//! Sprint 1 prints the `mach_header_64` + every load command in `header.ncmds`.
//! Section bodies, symbols, strings, and relocations become visible as Sprint 2
//! and later sprints bring them into the reader's model.

use std::io::{self, Write};
use std::path::Path;

use crate::macho::constants::*;
use crate::macho::reader::{
    parse_commands, parse_header, BuildVersionCmd, DysymtabCmd, LinkEditDataCmd, LoadCommand,
    MachHeader64, Section64Header, Segment64, SymtabCmd,
};

pub fn dump_file(path: &Path) -> io::Result<()> {
    let bytes = std::fs::read(path)?;
    let out = io::stdout();
    let mut h = out.lock();
    writeln!(h, "{}:", path.display())?;
    let hdr = match parse_header(&bytes) {
        Ok(h) => h,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    write_header(&mut h, &hdr)?;
    let cmds = match parse_commands(&hdr, &bytes) {
        Ok(c) => c,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    for (i, cmd) in cmds.iter().enumerate() {
        write_command(&mut h, i, cmd)?;
    }
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
    writeln!(
        w,
        "Load command {}: {} cmdsize={}",
        idx,
        cmd_name(cmd.cmd()),
        cmd.cmdsize()
    )?;
    match cmd {
        LoadCommand::Segment64(s) => write_segment64(w, s),
        LoadCommand::Symtab(s) => write_symtab(w, s),
        LoadCommand::Dysymtab(d) => write_dysymtab(w, d),
        LoadCommand::BuildVersion(b) => write_build_version(w, b),
        LoadCommand::LinkerOptimizationHint(l) => write_linkedit_data(w, l, "LOH"),
        LoadCommand::Raw { cmd, data, .. } => {
            writeln!(
                w,
                "  (raw — cmd=0x{:x}, payload {} bytes)",
                cmd,
                data.len()
            )
        }
    }
}

fn write_segment64(w: &mut impl Write, s: &Segment64) -> io::Result<()> {
    writeln!(
        w,
        "  segname={:<16} vmaddr=0x{:x} vmsize=0x{:x} fileoff={} filesize={} maxprot={} initprot={} nsects={} flags=0x{:x}",
        format!("\"{}\"", s.segname_str()),
        s.vmaddr,
        s.vmsize,
        s.fileoff,
        s.filesize,
        prot_str(s.maxprot),
        prot_str(s.initprot),
        s.sections.len(),
        s.flags
    )?;
    for (i, sec) in s.sections.iter().enumerate() {
        write_section(w, i, sec)?;
    }
    Ok(())
}

fn write_section(w: &mut impl Write, idx: usize, s: &Section64Header) -> io::Result<()> {
    writeln!(
        w,
        "  Section {}: {},{} addr=0x{:x} size=0x{:x} offset={} align=2^{} reloff={} nreloc={} flags=0x{:08x}",
        idx,
        s.segname_str(),
        s.sectname_str(),
        s.addr,
        s.size,
        s.offset,
        s.align,
        s.reloff,
        s.nreloc,
        s.flags
    )
}

fn write_symtab(w: &mut impl Write, s: &SymtabCmd) -> io::Result<()> {
    writeln!(
        w,
        "  symoff={} nsyms={} stroff={} strsize={}",
        s.symoff, s.nsyms, s.stroff, s.strsize
    )
}

fn write_dysymtab(w: &mut impl Write, d: &DysymtabCmd) -> io::Result<()> {
    writeln!(
        w,
        "  ilocalsym={} nlocalsym={} iextdefsym={} nextdefsym={} iundefsym={} nundefsym={} indirectsymoff={} nindirectsyms={}",
        d.ilocalsym,
        d.nlocalsym,
        d.iextdefsym,
        d.nextdefsym,
        d.iundefsym,
        d.nundefsym,
        d.indirectsymoff,
        d.nindirectsyms
    )
}

fn write_build_version(w: &mut impl Write, b: &BuildVersionCmd) -> io::Result<()> {
    writeln!(
        w,
        "  platform={} minos={} sdk={} ntools={}",
        platform_name(b.platform),
        version_str(b.minos),
        version_str(b.sdk),
        b.tools.len()
    )?;
    for t in &b.tools {
        writeln!(w, "    tool={} version={}", t.tool, version_str(t.version))?;
    }
    Ok(())
}

fn write_linkedit_data(w: &mut impl Write, l: &LinkEditDataCmd, kind: &str) -> io::Result<()> {
    writeln!(
        w,
        "  {kind} dataoff={} datasize={}",
        l.dataoff, l.datasize
    )
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
