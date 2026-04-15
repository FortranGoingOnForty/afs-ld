//! Mach-O 64 reader.
//!
//! Sprint 1: parse `mach_header_64` and the load-command list, round-tripping
//! every command afs-as emits. Section contents, symbol bodies, and relocation
//! entries arrive in Sprint 2 and Sprint 3.
//!
//! All input is assumed little-endian (arm64 mach-o is always little-endian in
//! practice; we error out on any other cpu type).

use std::fmt;

use super::constants::*;

/// Every error surface this module can produce. Diagnostics include byte
/// offsets and a static context string so downstream layers can produce the
/// caret-under-source style that `afs-as/src/diag*.rs` uses.
#[derive(Debug)]
pub enum ReadError {
    /// Not enough bytes to decode the next field.
    Truncated { need: usize, have: usize, context: &'static str },
    /// Magic number is not `MH_MAGIC_64`.
    BadMagic { got: u32 },
    /// CPU type is not `CPU_TYPE_ARM64`.
    UnsupportedCpu { got: u32 },
    /// A load command's `cmdsize` field is malformed.
    BadCmdsize { cmd: u32, cmdsize: u32, at_offset: usize, reason: &'static str },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Truncated { need, have, context } => write!(
                f,
                "truncated input while reading {context}: need {need} bytes, have {have}"
            ),
            ReadError::BadMagic { got } => write!(
                f,
                "not a Mach-O 64 file: magic 0x{got:08x} (expected 0x{MH_MAGIC_64:08x})"
            ),
            ReadError::UnsupportedCpu { got } => write!(
                f,
                "unsupported cpu type 0x{got:08x} (afs-ld requires arm64 / 0x{CPU_TYPE_ARM64:08x})"
            ),
            ReadError::BadCmdsize { cmd, cmdsize, at_offset, reason } => write!(
                f,
                "load command 0x{cmd:x} at offset 0x{at_offset:x}: cmdsize {cmdsize} invalid ({reason})"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

/// `mach_header_64` — 32 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

/// Size of a `mach_header_64` on the wire.
pub const HEADER_SIZE: usize = 32;

pub fn parse_header(bytes: &[u8]) -> Result<MachHeader64, ReadError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ReadError::Truncated {
            need: HEADER_SIZE,
            have: bytes.len(),
            context: "mach_header_64",
        });
    }
    let magic = u32_le(&bytes[0..4]);
    if magic != MH_MAGIC_64 {
        return Err(ReadError::BadMagic { got: magic });
    }
    let cputype = u32_le(&bytes[4..8]);
    if cputype != CPU_TYPE_ARM64 {
        return Err(ReadError::UnsupportedCpu { got: cputype });
    }
    Ok(MachHeader64 {
        magic,
        cputype,
        cpusubtype: u32_le(&bytes[8..12]),
        filetype: u32_le(&bytes[12..16]),
        ncmds: u32_le(&bytes[16..20]),
        sizeofcmds: u32_le(&bytes[20..24]),
        flags: u32_le(&bytes[24..28]),
        reserved: u32_le(&bytes[28..32]),
    })
}

pub fn write_header(hdr: &MachHeader64, out: &mut Vec<u8>) {
    out.extend_from_slice(&hdr.magic.to_le_bytes());
    out.extend_from_slice(&hdr.cputype.to_le_bytes());
    out.extend_from_slice(&hdr.cpusubtype.to_le_bytes());
    out.extend_from_slice(&hdr.filetype.to_le_bytes());
    out.extend_from_slice(&hdr.ncmds.to_le_bytes());
    out.extend_from_slice(&hdr.sizeofcmds.to_le_bytes());
    out.extend_from_slice(&hdr.flags.to_le_bytes());
    out.extend_from_slice(&hdr.reserved.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Load commands.
//
// Every command starts with `cmd: u32` + `cmdsize: u32` (the "load_command"
// header). `cmdsize` is 8-byte aligned and counts both those 8 header bytes
// plus the payload. Specific command kinds get their own variants as each
// commit in this sprint decodes them; unknown-to-us kinds live in
// `LoadCommand::Raw` forever so round-trips survive.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadCommand {
    Segment64(Segment64),
    /// A load command whose payload we haven't decoded yet. Preserves bytes
    /// verbatim for byte-level round-trip.
    Raw { cmd: u32, cmdsize: u32, data: Vec<u8> },
}

impl LoadCommand {
    pub fn cmd(&self) -> u32 {
        match self {
            LoadCommand::Segment64(_) => LC_SEGMENT_64,
            LoadCommand::Raw { cmd, .. } => *cmd,
        }
    }

    pub fn cmdsize(&self) -> u32 {
        match self {
            LoadCommand::Segment64(s) => s.wire_size(),
            LoadCommand::Raw { cmdsize, .. } => *cmdsize,
        }
    }
}

// ---------------------------------------------------------------------------
// LC_SEGMENT_64 + section_64
// ---------------------------------------------------------------------------

/// Raw 16-byte name field. Null-padded; may be non-UTF-8 in pathological cases
/// (the spec doesn't guarantee anything beyond "null-padded bytes"). Kept raw
/// so byte-level round-trip is preserved; helpers below produce a lossy &str
/// for display.
pub type Name16 = [u8; 16];

pub fn name16_str(name: &Name16) -> String {
    let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..n]).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment64 {
    pub segname: Name16,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub flags: u32,
    pub sections: Vec<Section64Header>,
}

impl Segment64 {
    /// Fixed portion (before sections array): 16 + 4×u64 + 4×u32 = 64 bytes.
    const BASE: usize = 64;
    /// Per-section size: 2×name16 + 2×u64 + 8×u32 = 80 bytes.
    const SECT: usize = 80;

    pub fn wire_size(&self) -> u32 {
        (8 + Self::BASE + Self::SECT * self.sections.len()) as u32
    }

    pub fn segname_str(&self) -> String {
        name16_str(&self.segname)
    }

    pub fn parse(cmdsize: u32, payload: &[u8]) -> Result<Self, ReadError> {
        if payload.len() < Self::BASE {
            return Err(ReadError::Truncated {
                need: Self::BASE,
                have: payload.len(),
                context: "segment_command_64 base",
            });
        }
        let segname: Name16 = payload[0..16].try_into().unwrap();
        let vmaddr = u64_le(&payload[16..24]);
        let vmsize = u64_le(&payload[24..32]);
        let fileoff = u64_le(&payload[32..40]);
        let filesize = u64_le(&payload[40..48]);
        let maxprot = u32_le(&payload[48..52]);
        let initprot = u32_le(&payload[52..56]);
        let nsects = u32_le(&payload[56..60]);
        let flags = u32_le(&payload[60..64]);

        let body_needed = Self::BASE + Self::SECT * nsects as usize;
        if payload.len() < body_needed {
            return Err(ReadError::BadCmdsize {
                cmd: LC_SEGMENT_64,
                cmdsize,
                at_offset: 0,
                reason: "nsects implies more bytes than cmdsize accommodates",
            });
        }
        let mut sections = Vec::with_capacity(nsects as usize);
        for i in 0..nsects as usize {
            let off = Self::BASE + i * Self::SECT;
            sections.push(Section64Header::parse(&payload[off..off + Self::SECT])?);
        }

        Ok(Segment64 {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            flags,
            sections,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        out.extend_from_slice(&self.wire_size().to_le_bytes());
        out.extend_from_slice(&self.segname);
        out.extend_from_slice(&self.vmaddr.to_le_bytes());
        out.extend_from_slice(&self.vmsize.to_le_bytes());
        out.extend_from_slice(&self.fileoff.to_le_bytes());
        out.extend_from_slice(&self.filesize.to_le_bytes());
        out.extend_from_slice(&self.maxprot.to_le_bytes());
        out.extend_from_slice(&self.initprot.to_le_bytes());
        out.extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        for s in &self.sections {
            s.write(out);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section64Header {
    pub sectname: Name16,
    pub segname: Name16,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32, // log2
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section64Header {
    fn parse(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.len() < Segment64::SECT {
            return Err(ReadError::Truncated {
                need: Segment64::SECT,
                have: bytes.len(),
                context: "section_64",
            });
        }
        let sectname: Name16 = bytes[0..16].try_into().unwrap();
        let segname: Name16 = bytes[16..32].try_into().unwrap();
        Ok(Section64Header {
            sectname,
            segname,
            addr: u64_le(&bytes[32..40]),
            size: u64_le(&bytes[40..48]),
            offset: u32_le(&bytes[48..52]),
            align: u32_le(&bytes[52..56]),
            reloff: u32_le(&bytes[56..60]),
            nreloc: u32_le(&bytes[60..64]),
            flags: u32_le(&bytes[64..68]),
            reserved1: u32_le(&bytes[68..72]),
            reserved2: u32_le(&bytes[72..76]),
            reserved3: u32_le(&bytes[76..80]),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sectname);
        out.extend_from_slice(&self.segname);
        out.extend_from_slice(&self.addr.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.align.to_le_bytes());
        out.extend_from_slice(&self.reloff.to_le_bytes());
        out.extend_from_slice(&self.nreloc.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.reserved1.to_le_bytes());
        out.extend_from_slice(&self.reserved2.to_le_bytes());
        out.extend_from_slice(&self.reserved3.to_le_bytes());
    }

    pub fn sectname_str(&self) -> String {
        name16_str(&self.sectname)
    }

    pub fn segname_str(&self) -> String {
        name16_str(&self.segname)
    }
}

/// Parse the `header.ncmds` load commands that follow a `mach_header_64`.
/// The slice must cover the full file (or at least through `sizeofcmds`);
/// offsets are always relative to the start of the mach-o image.
pub fn parse_commands(
    header: &MachHeader64,
    bytes: &[u8],
) -> Result<Vec<LoadCommand>, ReadError> {
    let cmds_end = HEADER_SIZE
        .checked_add(header.sizeofcmds as usize)
        .ok_or(ReadError::Truncated {
            need: usize::MAX,
            have: bytes.len(),
            context: "load-command region (sizeofcmds overflows)",
        })?;
    if bytes.len() < cmds_end {
        return Err(ReadError::Truncated {
            need: cmds_end,
            have: bytes.len(),
            context: "load-command region",
        });
    }

    let mut out = Vec::with_capacity(header.ncmds as usize);
    let mut cursor = HEADER_SIZE;
    for _ in 0..header.ncmds {
        if cursor + 8 > cmds_end {
            return Err(ReadError::Truncated {
                need: 8,
                have: cmds_end.saturating_sub(cursor),
                context: "load_command header (cmd + cmdsize)",
            });
        }
        let cmd = u32_le(&bytes[cursor..cursor + 4]);
        let cmdsize = u32_le(&bytes[cursor + 4..cursor + 8]);
        if cmdsize < 8 {
            return Err(ReadError::BadCmdsize {
                cmd,
                cmdsize,
                at_offset: cursor,
                reason: "smaller than 8-byte header",
            });
        }
        if !cmdsize.is_multiple_of(8) {
            return Err(ReadError::BadCmdsize {
                cmd,
                cmdsize,
                at_offset: cursor,
                reason: "not 8-byte aligned",
            });
        }
        let end = cursor
            .checked_add(cmdsize as usize)
            .ok_or(ReadError::BadCmdsize {
                cmd,
                cmdsize,
                at_offset: cursor,
                reason: "cmdsize overflow",
            })?;
        if end > cmds_end {
            return Err(ReadError::BadCmdsize {
                cmd,
                cmdsize,
                at_offset: cursor,
                reason: "overruns sizeofcmds",
            });
        }
        let payload = &bytes[cursor + 8..end];
        out.push(decode_command(cmd, cmdsize, payload)?);
        cursor = end;
    }

    Ok(out)
}

fn decode_command(cmd: u32, cmdsize: u32, payload: &[u8]) -> Result<LoadCommand, ReadError> {
    match cmd {
        LC_SEGMENT_64 => Ok(LoadCommand::Segment64(Segment64::parse(cmdsize, payload)?)),
        _ => Ok(LoadCommand::Raw {
            cmd,
            cmdsize,
            data: payload.to_vec(),
        }),
    }
}

/// Write a sequence of load commands back to wire form. Paired with
/// `parse_commands` so `write_commands(parse_commands(hdr, bytes)?, &mut out)`
/// produces byte-identical output to the original region.
pub fn write_commands(cmds: &[LoadCommand], out: &mut Vec<u8>) {
    for c in cmds {
        match c {
            LoadCommand::Segment64(s) => s.write(out),
            LoadCommand::Raw { cmd, cmdsize, data } => {
                out.extend_from_slice(&cmd.to_le_bytes());
                out.extend_from_slice(&cmdsize.to_le_bytes());
                out.extend_from_slice(data);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Little-endian primitive readers. `u*_le(slice)` panics on short slices; every
// caller in this module pre-checks length via `Truncated` diagnostics.
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
#[allow(dead_code)] // consumed by the LC_SEGMENT_64 decoder added in the next commit
pub(crate) fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-crafted minimal MH_OBJECT header: arm64, 0 load commands, 0 flags.
    fn minimal_object_header_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        b.extend_from_slice(&MH_OBJECT.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
        b.extend_from_slice(&MH_SUBSECTIONS_VIA_SYMBOLS.to_le_bytes()); // flags
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved
        b
    }

    #[test]
    fn parse_minimal_object_header() {
        let bytes = minimal_object_header_bytes();
        let hdr = parse_header(&bytes).expect("valid header");
        assert_eq!(hdr.magic, MH_MAGIC_64);
        assert_eq!(hdr.cputype, CPU_TYPE_ARM64);
        assert_eq!(hdr.filetype, MH_OBJECT);
        assert_eq!(hdr.flags, MH_SUBSECTIONS_VIA_SYMBOLS);
    }

    #[test]
    fn round_trip_header_byte_equal() {
        let bytes = minimal_object_header_bytes();
        let hdr = parse_header(&bytes).unwrap();
        let mut out = Vec::new();
        write_header(&hdr, &mut out);
        assert_eq!(out, bytes);
    }

    #[test]
    fn truncated_header_errors_cleanly() {
        let err = parse_header(&[0u8; 10]).unwrap_err();
        assert!(
            matches!(err, ReadError::Truncated { need: HEADER_SIZE, have: 10, .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn bad_magic_errors() {
        let mut bytes = minimal_object_header_bytes();
        bytes[0] ^= 0xff;
        let err = parse_header(&bytes).unwrap_err();
        assert!(matches!(err, ReadError::BadMagic { .. }));
    }

    #[test]
    fn wrong_cpu_errors() {
        let mut bytes = minimal_object_header_bytes();
        // Overwrite cputype with x86_64 (0x01000007).
        bytes[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        let err = parse_header(&bytes).unwrap_err();
        assert!(matches!(err, ReadError::UnsupportedCpu { got: 0x0100_0007 }));
    }

    /// Synthesize a mach-o image with `n` load commands, each of size
    /// `cmdsize` (must include the 8-byte header).
    fn synth_image(ncmds: u32, cmds: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let sizeofcmds: u32 = cmds.iter().map(|(_, sz, _)| *sz).sum();
        let mut image = Vec::new();
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds,
            sizeofcmds,
            flags: 0,
            reserved: 0,
        };
        write_header(&hdr, &mut image);
        for (cmd, sz, payload) in cmds {
            image.extend_from_slice(&cmd.to_le_bytes());
            image.extend_from_slice(&sz.to_le_bytes());
            image.extend_from_slice(payload);
        }
        image
    }

    #[test]
    fn round_trip_two_raw_commands() {
        // Two fake commands of size 16 each (8 header + 8 payload).
        let payload_a = [0xAAu8; 8];
        let payload_b = [0xBBu8; 8];
        let image = synth_image(
            2,
            &[(0xDEAD_BEEF, 16, &payload_a), (0xCAFE_F00D, 16, &payload_b)],
        );
        let hdr = parse_header(&image).unwrap();
        let cmds = parse_commands(&hdr, &image).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].cmd(), 0xDEAD_BEEF);
        assert_eq!(cmds[0].cmdsize(), 16);
        assert_eq!(cmds[1].cmd(), 0xCAFE_F00D);

        let mut out = Vec::new();
        write_header(&hdr, &mut out);
        write_commands(&cmds, &mut out);
        assert_eq!(out, image);
    }

    #[test]
    fn cmdsize_below_header_errors() {
        let image = synth_image(1, &[(0x1234, 4, &[])]);
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds: 1,
            sizeofcmds: 4, // too small for even the header
            flags: 0,
            reserved: 0,
        };
        let err = parse_commands(&hdr, &image).unwrap_err();
        assert!(matches!(err, ReadError::Truncated { .. }));
    }

    #[test]
    fn cmdsize_unaligned_errors() {
        // cmdsize = 10 — not 8-aligned.
        let image = synth_image(1, &[(0x1234, 10, &[0u8; 2])]);
        let hdr = parse_header(&image).unwrap();
        let err = parse_commands(&hdr, &image).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadCmdsize { cmd: 0x1234, cmdsize: 10, reason, .. } if reason.contains("aligned")
        ));
    }

    fn name16(s: &str) -> Name16 {
        let mut out = [0u8; 16];
        let bytes = s.as_bytes();
        let n = bytes.len().min(16);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    fn sample_segment64() -> Segment64 {
        Segment64 {
            segname: name16("__TEXT"),
            vmaddr: 0,
            vmsize: 0x1000,
            fileoff: 0x200,
            filesize: 0x40,
            maxprot: 7,
            initprot: 5,
            flags: 0,
            sections: vec![Section64Header {
                sectname: name16("__text"),
                segname: name16("__TEXT"),
                addr: 0,
                size: 0x10,
                offset: 0x200,
                align: 2,
                reloff: 0,
                nreloc: 0,
                flags: S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            }],
        }
    }

    #[test]
    fn segment64_round_trip_byte_equal() {
        let seg = sample_segment64();
        let mut wire = Vec::new();
        seg.write(&mut wire);
        // Strip LC header so Segment64::parse gets just the payload.
        let payload = &wire[8..];
        let decoded = Segment64::parse(seg.wire_size(), payload).unwrap();
        assert_eq!(decoded, seg);

        // And byte-equal on re-emit.
        let mut reemit = Vec::new();
        decoded.write(&mut reemit);
        assert_eq!(reemit, wire);
    }

    #[test]
    fn segment64_helpers_decode_names() {
        let seg = sample_segment64();
        assert_eq!(seg.segname_str(), "__TEXT");
        assert_eq!(seg.sections[0].sectname_str(), "__text");
        assert_eq!(seg.sections[0].segname_str(), "__TEXT");
    }

    #[test]
    fn segment64_with_zero_sections_round_trips() {
        let seg = Segment64 {
            segname: name16("__DATA"),
            vmaddr: 0,
            vmsize: 0,
            fileoff: 0,
            filesize: 0,
            maxprot: 3,
            initprot: 3,
            flags: 0,
            sections: vec![],
        };
        let mut wire = Vec::new();
        seg.write(&mut wire);
        let decoded = Segment64::parse(seg.wire_size(), &wire[8..]).unwrap();
        assert_eq!(decoded, seg);
        assert_eq!(seg.wire_size(), 8 + 64);
    }

    #[test]
    fn segment64_through_dispatcher_preserves_bytes() {
        // Build a synthetic image with a single LC_SEGMENT_64 + a following
        // opaque LC_BUILD_VERSION-shaped Raw command. Both must survive the
        // parse/write round-trip.
        let seg = sample_segment64();
        let mut seg_wire = Vec::new();
        seg.write(&mut seg_wire);

        let raw_cmd = 0xCAFE_F00Du32; // any unknown cmd
        let raw_cmdsize: u32 = 16;
        let mut raw_wire = Vec::new();
        raw_wire.extend_from_slice(&raw_cmd.to_le_bytes());
        raw_wire.extend_from_slice(&raw_cmdsize.to_le_bytes());
        raw_wire.extend_from_slice(&[0x55u8; 8]);

        let sizeofcmds = (seg_wire.len() + raw_wire.len()) as u32;
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds: 2,
            sizeofcmds,
            flags: MH_SUBSECTIONS_VIA_SYMBOLS,
            reserved: 0,
        };
        let mut image = Vec::new();
        write_header(&hdr, &mut image);
        image.extend_from_slice(&seg_wire);
        image.extend_from_slice(&raw_wire);

        let parsed_hdr = parse_header(&image).unwrap();
        let cmds = parse_commands(&parsed_hdr, &image).unwrap();
        assert!(matches!(cmds[0], LoadCommand::Segment64(_)));
        assert!(matches!(cmds[1], LoadCommand::Raw { cmd: 0xCAFE_F00D, .. }));

        let mut out = Vec::new();
        write_header(&parsed_hdr, &mut out);
        write_commands(&cmds, &mut out);
        assert_eq!(out, image);
    }

    #[test]
    fn cmdsize_overrun_errors() {
        // sizeofcmds says 8, but the command claims 16 bytes.
        let mut image = Vec::new();
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds: 1,
            sizeofcmds: 8,
            flags: 0,
            reserved: 0,
        };
        write_header(&hdr, &mut image);
        image.extend_from_slice(&0x1234u32.to_le_bytes());
        image.extend_from_slice(&16u32.to_le_bytes());
        let err = parse_commands(&hdr, &image).unwrap_err();
        assert!(matches!(err, ReadError::BadCmdsize { reason, .. } if reason.contains("overruns")));
    }
}
