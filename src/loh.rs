//! ARM64 Linker Optimization Hints (LOH).
//!
//! `LC_LINKER_OPTIMIZATION_HINT` stores a ULEB128 stream of `(kind, argc,
//! args...)` records. The args are file offsets of the participating
//! instructions.

use crate::leb::{read_uleb, write_uleb};
use crate::macho::reader::ReadError;

pub const LOH_ARM64_ADRP_LDR: u32 = 2;
pub const LOH_ARM64_ADRP_LDR_GOT_LDR: u32 = 4;
pub const LOH_ARM64_ADRP_ADD: u32 = 7;
pub const LOH_ARM64_ADRP_LDR_GOT: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LohEntry {
    pub kind: u32,
    pub args: Vec<u32>,
}

pub fn parse_loh_blob(bytes: &[u8]) -> Result<Vec<LohEntry>, ReadError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor..].iter().all(|&byte| byte == 0) {
            break;
        }
        let at_offset = cursor as u32;
        let (kind, used) = read_uleb(&bytes[cursor..])?;
        cursor += used;
        let (argc, used) = read_uleb(&bytes[cursor..])?;
        cursor += used;
        let kind = u32::try_from(kind).map_err(|_| ReadError::BadRelocation {
            at_offset,
            reason: "LOH kind overflows u32",
        })?;
        let argc = usize::try_from(argc).map_err(|_| ReadError::BadRelocation {
            at_offset,
            reason: "LOH argcount overflows usize",
        })?;
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            let (arg, used) = read_uleb(&bytes[cursor..])?;
            cursor += used;
            args.push(u32::try_from(arg).map_err(|_| ReadError::BadRelocation {
                at_offset,
                reason: "LOH arg overflows u32",
            })?);
        }
        out.push(LohEntry { kind, args });
    }
    Ok(out)
}

pub fn write_loh_blob(entries: &[LohEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        write_uleb(entry.kind as u64, &mut out);
        write_uleb(entry.args.len() as u64, &mut out);
        for &arg in &entry.args {
            write_uleb(arg as u64, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loh_blob_round_trips() {
        let entries = vec![
            LohEntry {
                kind: LOH_ARM64_ADRP_ADD,
                args: vec![0, 4],
            },
            LohEntry {
                kind: LOH_ARM64_ADRP_LDR_GOT_LDR,
                args: vec![8, 12, 16],
            },
        ];
        let blob = write_loh_blob(&entries);
        assert_eq!(parse_loh_blob(&blob).unwrap(), entries);
    }

    #[test]
    fn loh_blob_ignores_trailing_zero_padding() {
        let mut blob = write_loh_blob(&[LohEntry {
            kind: LOH_ARM64_ADRP_ADD,
            args: vec![0, 4],
        }]);
        while !blob.len().is_multiple_of(8) {
            blob.push(0);
        }
        assert_eq!(
            parse_loh_blob(&blob).unwrap(),
            vec![LohEntry {
                kind: LOH_ARM64_ADRP_ADD,
                args: vec![0, 4],
            }]
        );
    }
}
