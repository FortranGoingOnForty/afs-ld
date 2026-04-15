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
    /// A load command whose payload we haven't decoded yet. Preserves bytes
    /// verbatim for byte-level round-trip.
    Raw { cmd: u32, cmdsize: u32, data: Vec<u8> },
}

impl LoadCommand {
    pub fn cmd(&self) -> u32 {
        match self {
            LoadCommand::Raw { cmd, .. } => *cmd,
        }
    }

    pub fn cmdsize(&self) -> u32 {
        match self {
            LoadCommand::Raw { cmdsize, .. } => *cmdsize,
        }
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
        let data = bytes[cursor + 8..end].to_vec();
        out.push(LoadCommand::Raw { cmd, cmdsize, data });
        cursor = end;
    }

    Ok(out)
}

/// Write a sequence of load commands back to wire form. Paired with
/// `parse_commands` so `write_commands(parse_commands(hdr, bytes)?, &mut out)`
/// produces byte-identical output to the original region.
pub fn write_commands(cmds: &[LoadCommand], out: &mut Vec<u8>) {
    for c in cmds {
        match c {
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
