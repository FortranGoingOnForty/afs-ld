//! Input-file aggregate: one `ObjectFile` per parsed `.o` on disk.
//!
//! Sprint 2 ties `MachHeader64`, the load-command list, `InputSection`s,
//! `InputSymbol`s, the `StringTable`, and the decoded `DysymtabCmd` together.
//! Sprint 4 will wrap this in an `InputFile` enum alongside `ArchiveFile`;
//! for now `ObjectFile` stands alone.

use std::path::PathBuf;

use crate::macho::reader::{
    parse_commands, parse_header, DysymtabCmd, LoadCommand, MachHeader64, ReadError, SymtabCmd,
    HEADER_SIZE,
};
use crate::section::InputSection;
use crate::string_table::StringTable;
use crate::symbol::{parse_nlist_table, InputSymbol, SymKind};

/// Whole parsed `.o` on disk. Section bodies and relocation bytes are owned
/// copies so the buffer this was parsed from can drop.
#[derive(Debug, Clone)]
pub struct ObjectFile {
    pub path: PathBuf,
    pub header: MachHeader64,
    pub commands: Vec<LoadCommand>,
    pub sections: Vec<InputSection>,
    pub symbols: Vec<InputSymbol>,
    pub strings: StringTable,
    pub symtab: Option<SymtabCmd>,
    pub dysymtab: Option<DysymtabCmd>,
}

impl ObjectFile {
    pub fn parse(path: impl Into<PathBuf>, file_bytes: &[u8]) -> Result<Self, ReadError> {
        let path = path.into();
        let header = parse_header(file_bytes)?;
        let commands = parse_commands(&header, file_bytes)?;

        // Collect sections from every LC_SEGMENT_64 (MH_OBJECT usually has
        // exactly one segment, but the layout is not required to).
        let mut sections = Vec::new();
        for cmd in &commands {
            if let LoadCommand::Segment64(seg) = cmd {
                for hdr in &seg.sections {
                    sections.push(InputSection::from_header(hdr, file_bytes)?);
                }
            }
        }

        // Lift the symbol table + string table if present. A bare segment-only
        // .o without LC_SYMTAB is technically legal and stays symbol-empty.
        let symtab = commands.iter().find_map(|c| match c {
            LoadCommand::Symtab(s) => Some(*s),
            _ => None,
        });
        let dysymtab = commands.iter().find_map(|c| match c {
            LoadCommand::Dysymtab(d) => Some(*d),
            _ => None,
        });

        let (symbols, strings) = match symtab {
            Some(s) => (
                parse_nlist_table(file_bytes, s.symoff, s.nsyms)?,
                StringTable::from_file(file_bytes, s.stroff, s.strsize)?,
            ),
            None => (Vec::new(), StringTable::from_bytes(Vec::new())),
        };

        Ok(ObjectFile {
            path,
            header,
            commands,
            sections,
            symbols,
            strings,
            symtab,
            dysymtab,
        })
    }

    /// Resolve the name of a symbol via this object's string table.
    pub fn symbol_name(&self, sym: &InputSymbol) -> Result<&str, ReadError> {
        self.strings.get(sym.strx())
    }

    /// For `N_INDR` aliases, resolve the aliased name via this object's
    /// string table. Returns `None` when the symbol is not an indirect entry.
    pub fn indirect_target_name(&self, sym: &InputSymbol) -> Option<Result<&str, ReadError>> {
        if sym.kind() == SymKind::Indirect {
            Some(self.strings.get(sym.value() as u32))
        } else {
            None
        }
    }

    /// Iterate over sections in 1-based-nlist order — i.e., the order
    /// `nlist.n_sect` refers to. afs-ld preserves the parsed order, which
    /// matches the order they appear in the segments.
    pub fn section_for_symbol(&self, sym: &InputSymbol) -> Option<&InputSection> {
        if sym.sect_idx() == 0 {
            return None;
        }
        self.sections.get((sym.sect_idx() as usize).saturating_sub(1))
    }
}

/// Total `sizeofcmds` region, exposed for callers doing byte-level round-trip
/// checks against the original file image.
pub fn header_and_cmds_end(header: &MachHeader64) -> usize {
    HEADER_SIZE + header.sizeofcmds as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::constants::*;
    use crate::macho::reader::{write_commands, write_header, Segment64, Section64Header};
    use crate::symbol::{RawNlist, NLIST_SIZE};

    fn name16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let bytes = s.as_bytes();
        let n = bytes.len().min(16);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    /// Build a tiny in-memory MH_OBJECT image with one __TEXT,__text section
    /// holding 8 bytes, one external symbol `_main`, and the minimum symtab.
    fn synth_image() -> Vec<u8> {
        // 1) Section header for __text.
        let text_sect = Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: 0,
            size: 8,
            offset: 0, // fill in after layout
            align: 2,
            reloff: 0,
            nreloc: 0,
            flags: S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        // 2) Segment with one section.
        let seg = Segment64 {
            segname: name16(""),
            vmaddr: 0,
            vmsize: 8,
            fileoff: 0,
            filesize: 8,
            maxprot: 7,
            initprot: 7,
            flags: 0,
            sections: vec![text_sect],
        };
        // 3) Symtab+string table.
        let strtab = b"\0_main\0";
        let nsyms = 1u32;
        let sym = RawNlist {
            strx: 1, // "_main"
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0,
        };

        // Layout: header → seg load cmd → symtab cmd → section content → nlist → strtab.
        let hdr_size = HEADER_SIZE;
        let seg_size = seg.wire_size() as usize;
        let symtab_size = SymtabCmd::WIRE_SIZE as usize;
        let sizeofcmds = (seg_size + symtab_size) as u32;

        let section_offset = (hdr_size + sizeofcmds as usize) as u32;
        let symoff = section_offset + 8; // after section content
        let stroff = symoff + NLIST_SIZE as u32 * nsyms;

        // Rebuild segment with the correct offset now that we know it.
        let seg = Segment64 {
            sections: vec![Section64Header {
                offset: section_offset,
                ..seg.sections[0]
            }],
            fileoff: section_offset as u64,
            ..seg
        };
        let seg_size = seg.wire_size() as usize;
        let sizeofcmds = (seg_size + symtab_size) as u32;

        let header = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        };
        let symtab_cmd = SymtabCmd {
            symoff,
            nsyms,
            stroff,
            strsize: strtab.len() as u32,
        };

        let mut image = Vec::new();
        write_header(&header, &mut image);
        let cmds = vec![LoadCommand::Segment64(seg), LoadCommand::Symtab(symtab_cmd)];
        write_commands(&cmds, &mut image);
        // Section content: 8 bytes (fake instructions).
        image.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
        // Nlist.
        sym.write(&mut image);
        // String table.
        image.extend_from_slice(strtab);
        image
    }

    #[test]
    fn parse_synth_object_end_to_end() {
        let image = synth_image();
        let obj = ObjectFile::parse("/tmp/synth.o", &image).unwrap();
        assert_eq!(obj.sections.len(), 1);
        let sec = &obj.sections[0];
        assert_eq!(sec.segname, "__TEXT");
        assert_eq!(sec.sectname, "__text");
        assert_eq!(sec.data.len(), 8);
        assert_eq!(
            sec.data,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        );

        assert_eq!(obj.symbols.len(), 1);
        let sym = &obj.symbols[0];
        assert_eq!(obj.symbol_name(sym).unwrap(), "_main");
        assert!(sym.is_ext());
        let sect = obj.section_for_symbol(sym).expect("n_sect=1 resolves");
        assert_eq!(sect.sectname, "__text");
    }

    #[test]
    fn indirect_target_name_resolves() {
        // Build a minimal strtab with "\0_alias\0_target\0" and a RawNlist
        // whose n_value points at "_target".
        let strtab = StringTable::from_bytes(b"\0_alias\0_target\0".to_vec());
        let obj = ObjectFile {
            path: PathBuf::from("/tmp/t"),
            header: MachHeader64 {
                magic: MH_MAGIC_64,
                cputype: CPU_TYPE_ARM64,
                cpusubtype: 0,
                filetype: MH_OBJECT,
                ncmds: 0,
                sizeofcmds: 0,
                flags: 0,
                reserved: 0,
            },
            commands: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            strings: strtab,
            symtab: None,
            dysymtab: None,
        };
        let alias = InputSymbol::from_raw(RawNlist {
            strx: 1,
            n_type: N_INDR | N_EXT,
            n_sect: 0,
            n_desc: 0,
            n_value: 8, // strx of "_target"
        });
        let resolved = obj.indirect_target_name(&alias).unwrap().unwrap();
        assert_eq!(resolved, "_target");
    }
}
