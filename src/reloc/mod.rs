//! ARM64 Mach-O relocations — reader side.
//!
//! Sprint 3 decodes every `ARM64_RELOC_*` kind afs-as emits, normalizes
//! paired relocations (ADDEND + primary, SUBTRACTOR + UNSIGNED) into a
//! linker-friendly form, and round-trips the lot. Sprint 11 consumes this
//! model when it applies relocations against final output addresses.
//!
//! Wire format (Mach-O `relocation_info`, 8 bytes, little-endian):
//! ```text
//!   int32  r_address;       byte offset into the containing section
//!   uint32 r_info  = [r_symbolnum:24 | r_pcrel:1 | r_length:2 | r_extern:1 | r_type:4]
//! ```
//!
//! `afs-ld` parses the raw form below, then `parse_relocs` lifts it into the
//! fused `Reloc` form. Later passes (Sprint 11, Sprint 23's dead-strip) reason
//! about `Reloc` and never touch `RawRelocation` again.

use crate::macho::reader::{u32_le, ReadError};

/// Size of one `relocation_info` on the wire.
pub const RAW_RELOC_SIZE: usize = 8;

/// Exact wire representation — pre-fusion, post-decoding of the bit fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRelocation {
    pub r_address: i32,
    pub r_symbolnum: u32,
    pub r_pcrel: bool,
    pub r_length: u8,
    pub r_extern: bool,
    pub r_type: u8,
}

impl RawRelocation {
    pub fn parse(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.len() < RAW_RELOC_SIZE {
            return Err(ReadError::Truncated {
                need: RAW_RELOC_SIZE,
                have: bytes.len(),
                context: "relocation_info",
            });
        }
        let r_address = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let info = u32_le(&bytes[4..8]);
        Ok(RawRelocation {
            r_address,
            r_symbolnum: info & 0x00FF_FFFF,
            r_pcrel: (info >> 24) & 1 != 0,
            r_length: ((info >> 25) & 0b11) as u8,
            r_extern: (info >> 27) & 1 != 0,
            r_type: ((info >> 28) & 0x0f) as u8,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.r_address.to_le_bytes());
        let info = (self.r_symbolnum & 0x00FF_FFFF)
            | ((self.r_pcrel as u32) << 24)
            | (((self.r_length as u32) & 0b11) << 25)
            | ((self.r_extern as u32) << 27)
            | (((self.r_type as u32) & 0x0f) << 28);
        out.extend_from_slice(&info.to_le_bytes());
    }
}

/// Parse `nreloc` raw relocation_info entries starting at `reloff` bytes into
/// the file image. Each entry is 8 bytes.
pub fn parse_raw_relocs(
    file_bytes: &[u8],
    reloff: u32,
    nreloc: u32,
) -> Result<Vec<RawRelocation>, ReadError> {
    let start = reloff as usize;
    let total = (nreloc as usize).checked_mul(RAW_RELOC_SIZE).ok_or(ReadError::Truncated {
        need: usize::MAX,
        have: file_bytes.len(),
        context: "reloc table (nreloc × 8 overflows)",
    })?;
    let end = start.checked_add(total).ok_or(ReadError::Truncated {
        need: usize::MAX,
        have: file_bytes.len(),
        context: "reloc table (reloff + size overflows)",
    })?;
    if end > file_bytes.len() {
        return Err(ReadError::Truncated {
            need: end,
            have: file_bytes.len(),
            context: "reloc table",
        });
    }
    let mut out = Vec::with_capacity(nreloc as usize);
    for i in 0..nreloc as usize {
        let off = start + i * RAW_RELOC_SIZE;
        out.push(RawRelocation::parse(&file_bytes[off..off + RAW_RELOC_SIZE])?);
    }
    Ok(out)
}

/// Serialize raw relocs back to wire form.
pub fn write_raw_relocs(relocs: &[RawRelocation], out: &mut Vec<u8>) {
    for r in relocs {
        r.write(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::constants::*;

    #[test]
    fn raw_reloc_round_trip_byte_equal() {
        let raw = RawRelocation {
            r_address: 0x24,
            r_symbolnum: 5,
            r_pcrel: true,
            r_length: 2,
            r_extern: true,
            r_type: ARM64_RELOC_BRANCH26,
        };
        let mut buf = Vec::new();
        raw.write(&mut buf);
        assert_eq!(buf.len(), RAW_RELOC_SIZE);
        let back = RawRelocation::parse(&buf).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn raw_reloc_preserves_all_bit_fields() {
        // Cover every extreme value to catch shift/mask bugs.
        let raw = RawRelocation {
            r_address: -1, // signed negative round-trips
            r_symbolnum: 0x00FF_FFFF, // max 24-bit value
            r_pcrel: true,
            r_length: 0b11,
            r_extern: true,
            r_type: 0x0f,
        };
        let mut buf = Vec::new();
        raw.write(&mut buf);
        let back = RawRelocation::parse(&buf).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn raw_reloc_parses_known_branch26_pattern() {
        // BRANCH26, external, length=2, pcrel, symnum=3.
        // r_info = 3 | (1<<24) | (2<<25) | (1<<27) | (2<<28)
        //       = 0x0000_0003 | 0x0100_0000 | 0x0400_0000 | 0x0800_0000 | 0x2000_0000
        //       = 0x2D00_0003 → little-endian bytes [03, 00, 00, 2D]
        let bytes = [
            0x10, 0x00, 0x00, 0x00, // r_address = 0x10
            0x03, 0x00, 0x00, 0x2D, // r_info
        ];
        let raw = RawRelocation::parse(&bytes).unwrap();
        assert_eq!(raw.r_address, 0x10);
        assert_eq!(raw.r_symbolnum, 3);
        assert!(raw.r_pcrel);
        assert_eq!(raw.r_length, 2);
        assert!(raw.r_extern);
        assert_eq!(raw.r_type, ARM64_RELOC_BRANCH26);
    }

    #[test]
    fn raw_reloc_truncated_errors() {
        let err = RawRelocation::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, ReadError::Truncated { need: RAW_RELOC_SIZE, have: 4, .. }));
    }

    #[test]
    fn parse_raw_relocs_reads_consecutive_entries() {
        let r1 = RawRelocation {
            r_address: 0x4,
            r_symbolnum: 1,
            r_pcrel: true,
            r_length: 2,
            r_extern: true,
            r_type: ARM64_RELOC_BRANCH26,
        };
        let r2 = RawRelocation {
            r_address: 0x10,
            r_symbolnum: 2,
            r_pcrel: false,
            r_length: 3,
            r_extern: true,
            r_type: ARM64_RELOC_UNSIGNED,
        };
        let mut file = vec![0u8; 32]; // plant at offset 16
        let mut plant = Vec::new();
        r1.write(&mut plant);
        r2.write(&mut plant);
        file[16..16 + plant.len()].copy_from_slice(&plant);

        let parsed = parse_raw_relocs(&file, 16, 2).unwrap();
        assert_eq!(parsed, vec![r1, r2]);

        let mut reemit = Vec::new();
        write_raw_relocs(&parsed, &mut reemit);
        assert_eq!(reemit, plant);
    }

    #[test]
    fn parse_raw_relocs_oob_errors() {
        let file = vec![0u8; 8];
        // Ask for 2 × 8 = 16 bytes starting at 0; we only have 8.
        let err = parse_raw_relocs(&file, 0, 2).unwrap_err();
        assert!(matches!(err, ReadError::Truncated { .. }));
    }
}
