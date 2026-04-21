//! ARM64 Linker Optimization Hints (LOH).
//!
//! `LC_LINKER_OPTIMIZATION_HINT` stores a ULEB128 stream of `(kind, argc,
//! args...)` records. The args are file offsets of the participating
//! instructions.

use std::collections::HashSet;
use std::fmt;

use crate::layout::Layout;
use crate::leb::{read_uleb, write_uleb};
use crate::macho::reader::ReadError;
use crate::macho::writer::LinkEditPlan;

pub const LOH_ARM64_ADRP_LDR: u32 = 2;
pub const LOH_ARM64_ADRP_LDR_GOT_LDR: u32 = 4;
pub const LOH_ARM64_ADRP_ADD: u32 = 7;
pub const LOH_ARM64_ADRP_LDR_GOT: u32 = 8;
const NOP: u32 = 0xd503_201f;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LohEntry {
    pub kind: u32,
    pub args: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LohError(String);

impl fmt::Display for LohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LOH relaxation error: {}", self.0)
    }
}

impl std::error::Error for LohError {}

impl From<ReadError> for LohError {
    fn from(value: ReadError) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocatedWord {
    section_idx: usize,
    atom_idx: usize,
    word_off: usize,
    addr: u64,
    insn: u32,
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

pub fn relax_layout(
    layout: &mut Layout,
    linkedit: &LinkEditPlan,
    enabled: bool,
) -> Result<(), LohError> {
    if !enabled || linkedit.loh.is_none() || linkedit.loh_bytes().is_empty() {
        return Ok(());
    }

    let entries = parse_loh_blob(linkedit.loh_bytes())?;
    let mut rewritten = HashSet::new();
    for entry in entries {
        if entry.kind != LOH_ARM64_ADRP_ADD || entry.args.len() != 2 {
            continue;
        }

        let adrp_off = entry.args[0] as u64;
        let add_off = entry.args[1] as u64;
        if !rewritten.insert(adrp_off) || !rewritten.insert(add_off) {
            continue;
        }

        let adrp = locate_word(layout, adrp_off)?;
        let add = locate_word(layout, add_off)?;
        let Some(target) = decode_adrp_add_target(adrp.insn, add.insn, adrp.addr) else {
            continue;
        };
        let Some(adr) = encode_adr(target, adrp.addr, (adrp.insn & 0x1f) as u8) else {
            continue;
        };

        write_word(layout, adrp, adr)?;
        write_word(layout, add, NOP)?;
    }
    Ok(())
}

fn locate_word(layout: &Layout, file_offset: u64) -> Result<LocatedWord, LohError> {
    for (section_idx, section) in layout.sections.iter().enumerate() {
        for (atom_idx, atom) in section.atoms.iter().enumerate() {
            let start = section.file_off + atom.offset;
            let end = start + atom.data.len() as u64;
            if !(start <= file_offset && file_offset + 4 <= end) {
                continue;
            }
            let word_off = (file_offset - start) as usize;
            let bytes = atom.data.get(word_off..word_off + 4).ok_or_else(|| {
                LohError(format!(
                    "instruction read OOB at file offset 0x{file_offset:x}"
                ))
            })?;
            return Ok(LocatedWord {
                section_idx,
                atom_idx,
                word_off,
                addr: section.addr + atom.offset + word_off as u64,
                insn: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            });
        }
    }
    Err(LohError(format!(
        "LOH instruction offset 0x{file_offset:x} did not resolve to an output atom"
    )))
}

fn write_word(layout: &mut Layout, word: LocatedWord, insn: u32) -> Result<(), LohError> {
    let atom = &mut layout.sections[word.section_idx].atoms[word.atom_idx];
    let bytes = atom
        .data
        .get_mut(word.word_off..word.word_off + 4)
        .ok_or_else(|| {
            LohError(format!(
                "instruction write OOB at section {} atom {} word {}",
                word.section_idx, word.atom_idx, word.word_off
            ))
        })?;
    bytes.copy_from_slice(&insn.to_le_bytes());
    Ok(())
}

fn decode_adrp_add_target(adrp: u32, add: u32, place: u64) -> Option<u64> {
    if !is_adrp(adrp) || !is_add_imm_64(add) {
        return None;
    }
    let rd = (adrp & 0x1f) as u8;
    let add_rd = (add & 0x1f) as u8;
    let add_rn = ((add >> 5) & 0x1f) as u8;
    if rd == 31 || add_rd != rd || add_rn != rd {
        return None;
    }
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((place as i64) & !0xfff) + (adrp_pages << 12);
    let low = ((add >> 10) & 0xfff) as u64;
    Some((adrp_base as u64) + low)
}

fn encode_adr(target: u64, place: u64, reg: u8) -> Option<u32> {
    if reg == 31 {
        return None;
    }
    let delta = (target as i64).wrapping_sub(place as i64);
    if !fits_signed(delta, 21) {
        return None;
    }
    let encoded = (delta as u32) & 0x1f_ffff;
    let immlo = encoded & 0x3;
    let immhi = (encoded >> 2) & 0x7ffff;
    Some(0x1000_0000 | (immlo << 29) | (immhi << 5) | reg as u32)
}

fn is_adrp(insn: u32) -> bool {
    (insn & 0x9f00_0000) == 0x9000_0000
}

fn is_add_imm_64(insn: u32) -> bool {
    (insn & 0xffc0_0000) == 0x9100_0000
}

fn fits_signed(value: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    (min..=max).contains(&value)
}

fn sign_extend_21(value: i64) -> i64 {
    if value & (1 << 20) != 0 {
        value | !0x1f_ffff
    } else {
        value
    }
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

    #[test]
    fn encode_adr_round_trips_small_delta() {
        let place = 0x1_0000_1000;
        let target = place + 0x48;
        let adr = encode_adr(target, place, 9).unwrap();
        assert_eq!(adr & 0x1f, 9);
        let immlo = ((adr >> 29) & 0x3) as i64;
        let immhi = ((adr >> 5) & 0x7ffff) as i64;
        let delta = sign_extend_21((immhi << 2) | immlo);
        assert_eq!(place.wrapping_add_signed(delta), target);
    }
}
