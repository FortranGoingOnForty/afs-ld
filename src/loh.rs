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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralLoadKind {
    W,
    X,
    S,
    D,
    Q,
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

    let mut entries = parse_loh_blob(linkedit.loh_bytes())?;
    entries.sort_by(|lhs, rhs| {
        rhs.args
            .len()
            .cmp(&lhs.args.len())
            .then_with(|| lhs.args.first().cmp(&rhs.args.first()))
            .then_with(|| lhs.kind.cmp(&rhs.kind))
    });
    let mut rewritten = HashSet::new();
    for entry in entries {
        match entry.kind {
            LOH_ARM64_ADRP_LDR => relax_adrp_ldr(layout, &entry, &mut rewritten)?,
            LOH_ARM64_ADRP_LDR_GOT_LDR => relax_adrp_ldr_got_ldr(layout, &entry, &mut rewritten)?,
            LOH_ARM64_ADRP_ADD => relax_adrp_add(layout, &entry, &mut rewritten)?,
            LOH_ARM64_ADRP_LDR_GOT => relax_adrp_ldr_got(layout, &entry, &mut rewritten)?,
            _ => {}
        }
    }
    Ok(())
}

fn relax_adrp_add(
    layout: &mut Layout,
    entry: &LohEntry,
    rewritten: &mut HashSet<u64>,
) -> Result<(), LohError> {
    if entry.args.len() != 2 {
        return Ok(());
    }
    let adrp_off = entry.args[0] as u64;
    let add_off = entry.args[1] as u64;
    if !claim_offsets(rewritten, &[adrp_off, add_off]) {
        return Ok(());
    }
    let adrp = locate_word(layout, adrp_off)?;
    let add = locate_word(layout, add_off)?;
    let Some(target) = decode_adrp_add_target(adrp.insn, add.insn, adrp.addr) else {
        return Ok(());
    };
    let dest = (add.insn & 0x1f) as u8;
    let Some(adr) = encode_adr(target, adrp.addr, dest) else {
        return Ok(());
    };
    write_word(layout, adrp, adr)?;
    write_word(layout, add, NOP)?;
    Ok(())
}

fn relax_adrp_ldr(
    layout: &mut Layout,
    entry: &LohEntry,
    rewritten: &mut HashSet<u64>,
) -> Result<(), LohError> {
    if entry.args.len() != 2 {
        return Ok(());
    }
    let adrp_off = entry.args[0] as u64;
    let ldr_off = entry.args[1] as u64;
    if !claim_offsets(rewritten, &[adrp_off, ldr_off]) {
        return Ok(());
    }
    let adrp = locate_word(layout, adrp_off)?;
    let ldr = locate_word(layout, ldr_off)?;
    let Some(target) = decode_adrp_ldr_target(adrp.insn, ldr.insn, adrp.addr) else {
        return Ok(());
    };
    let Some(literal) = encode_ldr_literal(ldr.insn, target, ldr.addr) else {
        return Ok(());
    };
    write_word(layout, adrp, NOP)?;
    write_word(layout, ldr, literal)?;
    Ok(())
}

fn relax_adrp_ldr_got(
    layout: &mut Layout,
    entry: &LohEntry,
    rewritten: &mut HashSet<u64>,
) -> Result<(), LohError> {
    if entry.args.len() != 2 {
        return Ok(());
    }
    let adrp_off = entry.args[0] as u64;
    let ldr_off = entry.args[1] as u64;
    if !claim_offsets(rewritten, &[adrp_off, ldr_off]) {
        return Ok(());
    }
    let adrp = locate_word(layout, adrp_off)?;
    let ldr = locate_word(layout, ldr_off)?;
    let Some(got_slot_addr) = decode_adrp_ldr_target(adrp.insn, ldr.insn, adrp.addr) else {
        return Ok(());
    };
    if pageoff_load_kind(ldr.insn) != Some(LiteralLoadKind::X) {
        return Ok(());
    }
    let Some(local_target) = read_u64_at_addr(layout, got_slot_addr) else {
        return Ok(());
    };
    if !points_into_output(layout, local_target) {
        return Ok(());
    }
    let dest = (ldr.insn & 0x1f) as u8;
    let Some(adr) = encode_adr(local_target, adrp.addr, dest) else {
        return Ok(());
    };
    write_word(layout, adrp, adr)?;
    write_word(layout, ldr, NOP)?;
    Ok(())
}

fn relax_adrp_ldr_got_ldr(
    layout: &mut Layout,
    entry: &LohEntry,
    rewritten: &mut HashSet<u64>,
) -> Result<(), LohError> {
    if entry.args.len() != 3 {
        return Ok(());
    }
    let adrp_off = entry.args[0] as u64;
    let got_ldr_off = entry.args[1] as u64;
    let final_ldr_off = entry.args[2] as u64;
    if !claim_offsets(rewritten, &[adrp_off, got_ldr_off, final_ldr_off]) {
        return Ok(());
    }
    let adrp = locate_word(layout, adrp_off)?;
    let got_ldr = locate_word(layout, got_ldr_off)?;
    let final_ldr = locate_word(layout, final_ldr_off)?;
    let Some(got_slot_addr) = decode_adrp_ldr_target(adrp.insn, got_ldr.insn, adrp.addr) else {
        return Ok(());
    };
    if pageoff_load_kind(got_ldr.insn) != Some(LiteralLoadKind::X) {
        return Ok(());
    }
    let got_dest = (got_ldr.insn & 0x1f) as u8;
    if load_base_reg(final_ldr.insn) != Some(got_dest) {
        return Ok(());
    }
    let Some(local_target) = read_u64_at_addr(layout, got_slot_addr) else {
        return Ok(());
    };
    if !points_into_output(layout, local_target) {
        return Ok(());
    }
    let Some(adr) = encode_adr(local_target, adrp.addr, got_dest) else {
        return Ok(());
    };
    write_word(layout, adrp, adr)?;
    write_word(layout, got_ldr, NOP)?;
    Ok(())
}

fn claim_offsets(rewritten: &mut HashSet<u64>, offsets: &[u64]) -> bool {
    if offsets.iter().any(|offset| rewritten.contains(offset)) {
        return false;
    }
    rewritten.extend(offsets.iter().copied());
    true
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

fn decode_adrp_ldr_target(adrp: u32, ldr: u32, place: u64) -> Option<u64> {
    let _kind = pageoff_load_kind(ldr)?;
    let base = ((ldr >> 5) & 0x1f) as u8;
    let adrp_reg = (adrp & 0x1f) as u8;
    if adrp_reg == 31 || base != adrp_reg {
        return None;
    }
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((place as i64) & !0xfff) + (adrp_pages << 12);
    let shift = pageoff_shift(ldr);
    let low = (((ldr >> 10) & 0xfff) as u64) << shift;
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

fn encode_ldr_literal(insn: u32, target: u64, place: u64) -> Option<u32> {
    let kind = pageoff_load_kind(insn)?;
    let delta = (target as i64).wrapping_sub(place as i64);
    if delta & 0b11 != 0 {
        return None;
    }
    let imm = delta >> 2;
    if !fits_signed(imm, 19) {
        return None;
    }
    let encoded = (imm as u32) & 0x7ffff;
    let rt = insn & 0x1f;
    let base = match kind {
        LiteralLoadKind::W => 0x1800_0000,
        LiteralLoadKind::X => 0x5800_0000,
        LiteralLoadKind::S => 0x1c00_0000,
        LiteralLoadKind::D => 0x5c00_0000,
        LiteralLoadKind::Q => 0x9c00_0000,
    };
    Some(base | (encoded << 5) | rt)
}

fn is_adrp(insn: u32) -> bool {
    (insn & 0x9f00_0000) == 0x9000_0000
}

fn is_add_imm_64(insn: u32) -> bool {
    (insn & 0xffc0_0000) == 0x9100_0000
}

fn pageoff_load_kind(insn: u32) -> Option<LiteralLoadKind> {
    match insn & 0xffc0_0000 {
        0xb940_0000 => Some(LiteralLoadKind::W),
        0xf940_0000 => Some(LiteralLoadKind::X),
        0xbd40_0000 => Some(LiteralLoadKind::S),
        0xfd40_0000 => Some(LiteralLoadKind::D),
        0x3dc0_0000 => Some(LiteralLoadKind::Q),
        _ => None,
    }
}

fn load_base_reg(insn: u32) -> Option<u8> {
    match insn & 0xffc0_0000 {
        0xb940_0000 | 0xf940_0000 | 0xbd40_0000 | 0xfd40_0000 | 0x3dc0_0000 | 0x7940_0000
        | 0x3940_0000 => Some(((insn >> 5) & 0x1f) as u8),
        _ => None,
    }
}

fn pageoff_shift(insn: u32) -> u64 {
    if is_simd_fp_pageoff(insn) {
        let size = ((insn >> 30) & 0b11) as u64;
        let opc = ((insn >> 22) & 0b11) as u64;
        if size == 0 && (opc & 0b10) != 0 {
            4
        } else {
            size
        }
    } else {
        ((insn >> 30) & 0b11) as u64
    }
}

fn is_simd_fp_pageoff(insn: u32) -> bool {
    ((insn >> 24) & 0b111) == 0b101
}

fn points_into_output(layout: &Layout, addr: u64) -> bool {
    layout
        .sections
        .iter()
        .any(|section| section.addr <= addr && addr < section.addr + section.size)
}

fn read_u64_at_addr(layout: &Layout, addr: u64) -> Option<u64> {
    let bytes = read_bytes_at_addr(layout, addr, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_bytes_at_addr(layout: &Layout, addr: u64, len: usize) -> Option<Vec<u8>> {
    for section in &layout.sections {
        for atom in &section.atoms {
            let start = section.addr + atom.offset;
            let end = start + atom.data.len() as u64;
            if start <= addr && addr + len as u64 <= end {
                let word_off = (addr - start) as usize;
                return Some(atom.data.get(word_off..word_off + len)?.to_vec());
            }
        }
        if !section.synthetic_data.is_empty() {
            let start = section.addr + section.synthetic_offset;
            let end = start + section.synthetic_data.len() as u64;
            if start <= addr && addr + len as u64 <= end {
                let word_off = (addr - start) as usize;
                return Some(
                    section
                        .synthetic_data
                        .get(word_off..word_off + len)?
                        .to_vec(),
                );
            }
        }
    }
    None
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

    #[test]
    fn encode_ldr_literal_round_trips_x_load() {
        let place = 0x1_0000_2004;
        let target = place + 0x1fc;
        let insn = 0xf940_0005u32;
        let literal = encode_ldr_literal(insn, target, place).unwrap();
        assert_eq!(literal & 0x1f, 5);
        let imm = ((literal >> 5) & 0x7ffff) as i64;
        let delta = if imm & (1 << 18) != 0 {
            (imm | !0x7ffff) << 2
        } else {
            imm << 2
        };
        assert_eq!(place.wrapping_add_signed(delta), target);
    }
}
