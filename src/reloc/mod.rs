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

use crate::macho::constants::*;
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

// ---------------------------------------------------------------------------
// Fused Reloc form. Sprint 11's reloc-application pass consumes this.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    Unsigned,
    Branch26,
    Page21,
    PageOff12,
    GotLoadPage21,
    GotLoadPageOff12,
    PointerToGot,
    TlvpLoadPage21,
    TlvpLoadPageOff12,
    /// Fused `ARM64_RELOC_SUBTRACTOR` + `ARM64_RELOC_UNSIGNED` pair — the
    /// value stored is `minuend - subtrahend + addend`. `referent` carries
    /// the minuend; `subtrahend` (set on the fused form only) carries the
    /// other half.
    Subtractor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelocLength {
    Byte = 0,
    Half = 1,
    Word = 2,
    Quad = 3,
}

impl RelocLength {
    pub fn from_bits(v: u8) -> Option<Self> {
        match v {
            0 => Some(RelocLength::Byte),
            1 => Some(RelocLength::Half),
            2 => Some(RelocLength::Word),
            3 => Some(RelocLength::Quad),
            _ => None,
        }
    }

    pub fn as_bits(self) -> u8 {
        self as u8
    }

    pub fn byte_width(self) -> usize {
        1 << (self as u8)
    }
}

/// What a relocation references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Referent {
    /// Set when the raw `r_extern` flag is `1`. Index into the nlist table.
    Symbol(u32),
    /// Set when `r_extern = 0`. 1-based section index.
    Section(u8),
}

/// Fused linker-facing relocation. One `Reloc` may correspond to 1-3 raw
/// `relocation_info` entries on the wire (ADDEND prefix, SUBTRACTOR + UNSIGNED
/// pair, or the combination of both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    pub offset: u32,
    pub kind: RelocKind,
    pub length: RelocLength,
    pub pcrel: bool,
    pub referent: Referent,
    pub addend: i64,
    /// Only set when `kind == Subtractor`.
    pub subtrahend: Option<Referent>,
}

fn referent_from(raw: &RawRelocation) -> Result<Referent, ReadError> {
    if raw.r_extern {
        Ok(Referent::Symbol(raw.r_symbolnum))
    } else {
        if raw.r_symbolnum == 0 || raw.r_symbolnum > u8::MAX as u32 {
            return Err(ReadError::BadRelocation {
                at_offset: raw.r_address as u32,
                reason: "non-extern reloc with out-of-range section index",
            });
        }
        Ok(Referent::Section(raw.r_symbolnum as u8))
    }
}

/// Sign-extend a 24-bit value (the ADDEND reloc's `r_symbolnum` field) into
/// a full `i32`.
fn sign_extend_24(v: u32) -> i32 {
    if v & 0x0080_0000 != 0 {
        (v | 0xFF00_0000) as i32
    } else {
        v as i32
    }
}

fn primary_kind_from_type(t: u8) -> Option<RelocKind> {
    match t {
        ARM64_RELOC_UNSIGNED => Some(RelocKind::Unsigned),
        ARM64_RELOC_BRANCH26 => Some(RelocKind::Branch26),
        ARM64_RELOC_PAGE21 => Some(RelocKind::Page21),
        ARM64_RELOC_PAGEOFF12 => Some(RelocKind::PageOff12),
        ARM64_RELOC_GOT_LOAD_PAGE21 => Some(RelocKind::GotLoadPage21),
        ARM64_RELOC_GOT_LOAD_PAGEOFF12 => Some(RelocKind::GotLoadPageOff12),
        ARM64_RELOC_POINTER_TO_GOT => Some(RelocKind::PointerToGot),
        ARM64_RELOC_TLVP_LOAD_PAGE21 => Some(RelocKind::TlvpLoadPage21),
        ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => Some(RelocKind::TlvpLoadPageOff12),
        _ => None,
    }
}

/// Lift a vector of raw relocation entries into the fused `Reloc` form.
/// ADDEND prefixes fold into their following primary; SUBTRACTOR + UNSIGNED
/// pairs fold into a single `RelocKind::Subtractor`.
pub fn parse_relocs(raws: &[RawRelocation]) -> Result<Vec<Reloc>, ReadError> {
    let mut out: Vec<Reloc> = Vec::with_capacity(raws.len());
    let mut pending_addend: Option<i32> = None;
    let mut pending_subtractor: Option<RawRelocation> = None;

    for raw in raws {
        match raw.r_type {
            ARM64_RELOC_ADDEND => {
                if pending_addend.is_some() {
                    return Err(ReadError::BadRelocation {
                        at_offset: raw.r_address as u32,
                        reason: "two ARM64_RELOC_ADDEND in a row",
                    });
                }
                if raw.r_extern {
                    return Err(ReadError::BadRelocation {
                        at_offset: raw.r_address as u32,
                        reason: "ARM64_RELOC_ADDEND must not have r_extern set",
                    });
                }
                pending_addend = Some(sign_extend_24(raw.r_symbolnum));
            }
            ARM64_RELOC_SUBTRACTOR => {
                if pending_subtractor.is_some() {
                    return Err(ReadError::BadRelocation {
                        at_offset: raw.r_address as u32,
                        reason: "two ARM64_RELOC_SUBTRACTOR in a row",
                    });
                }
                pending_subtractor = Some(*raw);
            }
            t => {
                let kind = primary_kind_from_type(t).ok_or(ReadError::BadRelocation {
                    at_offset: raw.r_address as u32,
                    reason: "unknown ARM64_RELOC_* type",
                })?;
                let length = RelocLength::from_bits(raw.r_length).ok_or(ReadError::BadRelocation {
                    at_offset: raw.r_address as u32,
                    reason: "invalid r_length (must be 0..=3)",
                })?;
                let addend = pending_addend.take().map(|v| v as i64).unwrap_or(0);
                let referent = referent_from(raw)?;

                let (kind, subtrahend) = match pending_subtractor.take() {
                    Some(sub) => {
                        if t != ARM64_RELOC_UNSIGNED {
                            return Err(ReadError::BadRelocation {
                                at_offset: raw.r_address as u32,
                                reason: "SUBTRACTOR must be followed by UNSIGNED",
                            });
                        }
                        if sub.r_address != raw.r_address {
                            return Err(ReadError::BadRelocation {
                                at_offset: raw.r_address as u32,
                                reason: "SUBTRACTOR/UNSIGNED pair must share r_address",
                            });
                        }
                        if sub.r_length != raw.r_length {
                            return Err(ReadError::BadRelocation {
                                at_offset: raw.r_address as u32,
                                reason: "SUBTRACTOR/UNSIGNED pair must share r_length",
                            });
                        }
                        (RelocKind::Subtractor, Some(referent_from(&sub)?))
                    }
                    None => (kind, None),
                };

                out.push(Reloc {
                    offset: raw.r_address as u32,
                    kind,
                    length,
                    pcrel: raw.r_pcrel,
                    referent,
                    addend,
                    subtrahend,
                });
            }
        }
    }

    if pending_addend.is_some() {
        return Err(ReadError::BadRelocation {
            at_offset: 0,
            reason: "trailing ARM64_RELOC_ADDEND with no following primary",
        });
    }
    if pending_subtractor.is_some() {
        return Err(ReadError::BadRelocation {
            at_offset: 0,
            reason: "trailing ARM64_RELOC_SUBTRACTOR with no following UNSIGNED",
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Round-trip encoder: fused Reloc -> raw wire entries.
// ---------------------------------------------------------------------------

fn ref_to_raw_parts(r: Referent) -> (u32, bool) {
    match r {
        Referent::Symbol(idx) => (idx & 0x00FF_FFFF, true),
        Referent::Section(idx) => (idx as u32, false),
    }
}

fn reloc_type_byte(k: RelocKind) -> u8 {
    match k {
        RelocKind::Unsigned => ARM64_RELOC_UNSIGNED,
        RelocKind::Branch26 => ARM64_RELOC_BRANCH26,
        RelocKind::Page21 => ARM64_RELOC_PAGE21,
        RelocKind::PageOff12 => ARM64_RELOC_PAGEOFF12,
        RelocKind::GotLoadPage21 => ARM64_RELOC_GOT_LOAD_PAGE21,
        RelocKind::GotLoadPageOff12 => ARM64_RELOC_GOT_LOAD_PAGEOFF12,
        RelocKind::PointerToGot => ARM64_RELOC_POINTER_TO_GOT,
        RelocKind::TlvpLoadPage21 => ARM64_RELOC_TLVP_LOAD_PAGE21,
        RelocKind::TlvpLoadPageOff12 => ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
        RelocKind::Subtractor => ARM64_RELOC_UNSIGNED, // the minuend half of the pair
    }
}

fn encode_addend_prefix(offset: i32, addend: i64, length: u8) -> Result<RawRelocation, ReadError> {
    const ADDEND_MIN: i64 = -0x0080_0000;
    const ADDEND_MAX: i64 = 0x007F_FFFF;
    if !(ADDEND_MIN..=ADDEND_MAX).contains(&addend) {
        return Err(ReadError::BadRelocation {
            at_offset: offset as u32,
            reason: "addend outside 24-bit signed range (use ARM64_RELOC_ADDEND)",
        });
    }
    let sym = (addend as i32) as u32 & 0x00FF_FFFF;
    Ok(RawRelocation {
        r_address: offset,
        r_symbolnum: sym,
        r_pcrel: false,
        r_length: length,
        r_extern: false,
        r_type: ARM64_RELOC_ADDEND,
    })
}

/// Per-kind expected `r_length` (in bit-width form). `Unsigned` / `Subtractor`
/// are the only kinds that validly carry both `Word` and `Quad`; every other
/// kind is always `Word` (one 4-byte instruction).
fn kind_expects_word_only(k: RelocKind) -> bool {
    !matches!(k, RelocKind::Unsigned | RelocKind::Subtractor)
}

/// Per-kind expected `r_pcrel`. `None` means the flag is unconstrained
/// (currently: `Unsigned` and `Subtractor`).
fn kind_expects_pcrel(k: RelocKind) -> Option<bool> {
    match k {
        RelocKind::Branch26
        | RelocKind::Page21
        | RelocKind::GotLoadPage21
        | RelocKind::TlvpLoadPage21
        | RelocKind::PointerToGot => Some(true),
        RelocKind::PageOff12 | RelocKind::GotLoadPageOff12 | RelocKind::TlvpLoadPageOff12 => {
            Some(false)
        }
        RelocKind::Unsigned | RelocKind::Subtractor => None,
    }
}

/// Validate one fused relocation against the sizes of its containing section,
/// the symbol table, and the section table. Sprint 11 will additionally check
/// semantic constraints (range of BRANCH26 targets, etc.) when it has final
/// addresses.
pub fn validate_reloc(
    r: &Reloc,
    section_size: u64,
    nsyms: u32,
    nsects: u8,
) -> Result<(), ReadError> {
    // Offset + width must fit inside the section.
    let width = r.length.byte_width() as u64;
    let end = (r.offset as u64)
        .checked_add(width)
        .ok_or(ReadError::BadRelocation {
            at_offset: r.offset,
            reason: "reloc offset + width overflows u64",
        })?;
    if end > section_size {
        return Err(ReadError::BadRelocation {
            at_offset: r.offset,
            reason: "reloc offset + width exceeds section size",
        });
    }

    // Referent must be in range.
    validate_referent(r.offset, r.referent, nsyms, nsects)?;
    if let Some(sub) = r.subtrahend {
        validate_referent(r.offset, sub, nsyms, nsects)?;
    }

    // Kind-specific length constraint.
    if kind_expects_word_only(r.kind) && r.length != RelocLength::Word {
        return Err(ReadError::BadRelocation {
            at_offset: r.offset,
            reason: "reloc kind must use Word length (4 bytes)",
        });
    }

    // Kind-specific pcrel constraint.
    if let Some(expected) = kind_expects_pcrel(r.kind) {
        if r.pcrel != expected {
            return Err(ReadError::BadRelocation {
                at_offset: r.offset,
                reason: "reloc kind has fixed r_pcrel value that this entry violates",
            });
        }
    }

    // Subtractor invariants: must have a subtrahend.
    if r.kind == RelocKind::Subtractor && r.subtrahend.is_none() {
        return Err(ReadError::BadRelocation {
            at_offset: r.offset,
            reason: "Subtractor kind requires a subtrahend",
        });
    }

    Ok(())
}

fn validate_referent(
    offset: u32,
    referent: Referent,
    nsyms: u32,
    nsects: u8,
) -> Result<(), ReadError> {
    match referent {
        Referent::Symbol(idx) => {
            if idx >= nsyms {
                return Err(ReadError::BadRelocation {
                    at_offset: offset,
                    reason: "r_symbolnum past end of symbol table",
                });
            }
        }
        Referent::Section(idx) => {
            if idx == 0 || idx > nsects {
                return Err(ReadError::BadRelocation {
                    at_offset: offset,
                    reason: "section-relative reloc with out-of-range section index",
                });
            }
        }
    }
    Ok(())
}

/// Validate every entry in a section's reloc list. Short-circuits on the first
/// error so the diagnostic stream stays stable across re-runs.
pub fn validate_relocs(
    relocs: &[Reloc],
    section_size: u64,
    nsyms: u32,
    nsects: u8,
) -> Result<(), ReadError> {
    for r in relocs {
        validate_reloc(r, section_size, nsyms, nsects)?;
    }
    Ok(())
}

/// Lower the fused `Reloc` stream back to raw wire entries.
/// `parse_relocs(write_relocs(r))` must produce `r` for any `r` that came out
/// of `parse_relocs`; `write_raw_relocs(write_relocs(r))` produces bytes that
/// re-read through `parse_raw_relocs` into the same raw stream.
pub fn write_relocs(relocs: &[Reloc]) -> Result<Vec<RawRelocation>, ReadError> {
    let mut out = Vec::with_capacity(relocs.len() * 2);
    for r in relocs {
        match r.kind {
            RelocKind::Subtractor => {
                let sub = r.subtrahend.ok_or(ReadError::BadRelocation {
                    at_offset: r.offset,
                    reason: "Subtractor kind requires a subtrahend",
                })?;
                let (sub_sym, sub_ext) = ref_to_raw_parts(sub);
                out.push(RawRelocation {
                    r_address: r.offset as i32,
                    r_symbolnum: sub_sym,
                    r_pcrel: false,
                    r_length: r.length.as_bits(),
                    r_extern: sub_ext,
                    r_type: ARM64_RELOC_SUBTRACTOR,
                });
                if r.addend != 0 {
                    out.push(encode_addend_prefix(
                        r.offset as i32,
                        r.addend,
                        r.length.as_bits(),
                    )?);
                }
                let (min_sym, min_ext) = ref_to_raw_parts(r.referent);
                out.push(RawRelocation {
                    r_address: r.offset as i32,
                    r_symbolnum: min_sym,
                    r_pcrel: false,
                    r_length: r.length.as_bits(),
                    r_extern: min_ext,
                    r_type: ARM64_RELOC_UNSIGNED,
                });
            }
            kind => {
                if r.addend != 0 {
                    out.push(encode_addend_prefix(
                        r.offset as i32,
                        r.addend,
                        r.length.as_bits(),
                    )?);
                }
                let (sym, ext) = ref_to_raw_parts(r.referent);
                out.push(RawRelocation {
                    r_address: r.offset as i32,
                    r_symbolnum: sym,
                    r_pcrel: r.pcrel,
                    r_length: r.length.as_bits(),
                    r_extern: ext,
                    r_type: reloc_type_byte(kind),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---------- fused Reloc tests ----------

    fn rel(ty: u8, addr: i32, symnum: u32, ext: bool, pcrel: bool, len: u8) -> RawRelocation {
        RawRelocation {
            r_address: addr,
            r_symbolnum: symnum,
            r_pcrel: pcrel,
            r_length: len,
            r_extern: ext,
            r_type: ty,
        }
    }

    #[test]
    fn parse_branch26_simple() {
        let raws = vec![rel(ARM64_RELOC_BRANCH26, 0x10, 3, true, true, 2)];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 1);
        let r = parsed[0];
        assert_eq!(r.kind, RelocKind::Branch26);
        assert_eq!(r.length, RelocLength::Word);
        assert!(r.pcrel);
        assert_eq!(r.referent, Referent::Symbol(3));
        assert_eq!(r.addend, 0);
        assert_eq!(r.subtrahend, None);
    }

    #[test]
    fn parse_page_pageoff_pair() {
        let raws = vec![
            rel(ARM64_RELOC_PAGE21, 0x10, 5, true, true, 2),
            rel(ARM64_RELOC_PAGEOFF12, 0x14, 5, true, false, 2),
        ];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, RelocKind::Page21);
        assert_eq!(parsed[1].kind, RelocKind::PageOff12);
        assert!(parsed[0].pcrel);
        assert!(!parsed[1].pcrel);
    }

    #[test]
    fn parse_addend_prefix_folds_positive() {
        let raws = vec![
            rel(ARM64_RELOC_ADDEND, 0x10, 0x1000, false, false, 2),
            rel(ARM64_RELOC_PAGEOFF12, 0x10, 7, true, false, 2),
        ];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, RelocKind::PageOff12);
        assert_eq!(parsed[0].addend, 0x1000);
        assert_eq!(parsed[0].referent, Referent::Symbol(7));
    }

    #[test]
    fn parse_addend_prefix_folds_negative() {
        // r_symbolnum = 0xFFFFFF → 24-bit signed = -1.
        let raws = vec![
            rel(ARM64_RELOC_ADDEND, 0x20, 0x00FF_FFFF, false, false, 2),
            rel(ARM64_RELOC_UNSIGNED, 0x20, 9, true, false, 3),
        ];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].addend, -1);
        assert_eq!(parsed[0].kind, RelocKind::Unsigned);
        assert_eq!(parsed[0].length, RelocLength::Quad);
    }

    #[test]
    fn parse_subtractor_unsigned_pair() {
        let raws = vec![
            rel(ARM64_RELOC_SUBTRACTOR, 0x30, 11, true, false, 3),
            rel(ARM64_RELOC_UNSIGNED, 0x30, 12, true, false, 3),
        ];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 1);
        let r = parsed[0];
        assert_eq!(r.kind, RelocKind::Subtractor);
        assert_eq!(r.referent, Referent::Symbol(12)); // minuend
        assert_eq!(r.subtrahend, Some(Referent::Symbol(11))); // subtrahend
        assert_eq!(r.length, RelocLength::Quad);
    }

    #[test]
    fn parse_subtractor_with_addend() {
        // SUBTRACTOR, ADDEND, UNSIGNED — addend applies to the final value.
        let raws = vec![
            rel(ARM64_RELOC_SUBTRACTOR, 0x40, 20, true, false, 3),
            rel(ARM64_RELOC_ADDEND, 0x40, 0x100, false, false, 3),
            rel(ARM64_RELOC_UNSIGNED, 0x40, 21, true, false, 3),
        ];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, RelocKind::Subtractor);
        assert_eq!(parsed[0].referent, Referent::Symbol(21));
        assert_eq!(parsed[0].subtrahend, Some(Referent::Symbol(20)));
        assert_eq!(parsed[0].addend, 0x100);
    }

    #[test]
    fn parse_section_relative_referent() {
        // r_extern = false → section referent (1-based).
        let raws = vec![rel(ARM64_RELOC_UNSIGNED, 0x0, 2, false, false, 3)];
        let parsed = parse_relocs(&raws).unwrap();
        assert_eq!(parsed[0].referent, Referent::Section(2));
    }

    #[test]
    fn parse_trailing_addend_errors() {
        let raws = vec![rel(ARM64_RELOC_ADDEND, 0x0, 1, false, false, 2)];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("trailing")
        ));
    }

    #[test]
    fn parse_trailing_subtractor_errors() {
        let raws = vec![rel(ARM64_RELOC_SUBTRACTOR, 0x0, 1, true, false, 3)];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("trailing")
        ));
    }

    #[test]
    fn parse_subtractor_not_followed_by_unsigned_errors() {
        let raws = vec![
            rel(ARM64_RELOC_SUBTRACTOR, 0x0, 1, true, false, 3),
            rel(ARM64_RELOC_BRANCH26, 0x0, 2, true, true, 2),
        ];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("followed by UNSIGNED")
        ));
    }

    #[test]
    fn parse_subtractor_address_mismatch_errors() {
        let raws = vec![
            rel(ARM64_RELOC_SUBTRACTOR, 0x0, 1, true, false, 3),
            rel(ARM64_RELOC_UNSIGNED, 0x8, 2, true, false, 3),
        ];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("share r_address")
        ));
    }

    #[test]
    fn parse_subtractor_length_mismatch_errors() {
        let raws = vec![
            rel(ARM64_RELOC_SUBTRACTOR, 0x0, 1, true, false, 2),
            rel(ARM64_RELOC_UNSIGNED, 0x0, 2, true, false, 3),
        ];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("share r_length")
        ));
    }

    #[test]
    fn parse_unknown_reloc_type_errors() {
        let raws = vec![rel(0x0F, 0x0, 1, true, false, 2)];
        let err = parse_relocs(&raws).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("unknown")
        ));
    }

    // ---------- round-trip write_relocs tests ----------

    #[test]
    fn write_then_parse_round_trip_simple() {
        let input = vec![Reloc {
            offset: 0x10,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(5),
            addend: 0,
            subtrahend: None,
        }];
        let raws = write_relocs(&input).unwrap();
        assert_eq!(raws.len(), 1); // no ADDEND prefix when addend=0
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn write_then_parse_round_trip_with_addend() {
        let input = vec![Reloc {
            offset: 0x20,
            kind: RelocKind::PageOff12,
            length: RelocLength::Word,
            pcrel: false,
            referent: Referent::Symbol(7),
            addend: 0x1000,
            subtrahend: None,
        }];
        let raws = write_relocs(&input).unwrap();
        assert_eq!(raws.len(), 2);
        assert_eq!(raws[0].r_type, ARM64_RELOC_ADDEND);
        assert_eq!(raws[1].r_type, ARM64_RELOC_PAGEOFF12);
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn write_then_parse_round_trip_subtractor_pair() {
        let input = vec![Reloc {
            offset: 0x30,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(12),
            addend: 0,
            subtrahend: Some(Referent::Symbol(11)),
        }];
        let raws = write_relocs(&input).unwrap();
        assert_eq!(raws.len(), 2);
        assert_eq!(raws[0].r_type, ARM64_RELOC_SUBTRACTOR);
        assert_eq!(raws[0].r_symbolnum, 11);
        assert_eq!(raws[1].r_type, ARM64_RELOC_UNSIGNED);
        assert_eq!(raws[1].r_symbolnum, 12);
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn write_then_parse_round_trip_subtractor_with_addend() {
        let input = vec![Reloc {
            offset: 0x40,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(21),
            addend: 0x100,
            subtrahend: Some(Referent::Symbol(20)),
        }];
        let raws = write_relocs(&input).unwrap();
        assert_eq!(raws.len(), 3);
        assert_eq!(raws[0].r_type, ARM64_RELOC_SUBTRACTOR);
        assert_eq!(raws[1].r_type, ARM64_RELOC_ADDEND);
        assert_eq!(raws[2].r_type, ARM64_RELOC_UNSIGNED);
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn write_then_parse_round_trip_negative_addend() {
        let input = vec![Reloc {
            offset: 0x50,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(3),
            addend: -1,
            subtrahend: None,
        }];
        let raws = write_relocs(&input).unwrap();
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn write_subtractor_without_subtrahend_errors() {
        let bad = vec![Reloc {
            offset: 0,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(1),
            addend: 0,
            subtrahend: None,
        }];
        let err = write_relocs(&bad).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("subtrahend")
        ));
    }

    #[test]
    fn write_addend_overflow_errors() {
        let bad = vec![Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(1),
            addend: 0x0100_0000, // outside 24-bit signed range
            subtrahend: None,
        }];
        let err = write_relocs(&bad).unwrap_err();
        assert!(matches!(
            err,
            ReadError::BadRelocation { reason, .. } if reason.contains("24-bit")
        ));
    }

    // ---------- validate_reloc tests ----------

    fn good() -> Reloc {
        Reloc {
            offset: 0x10,
            kind: RelocKind::Branch26,
            length: RelocLength::Word,
            pcrel: true,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        }
    }

    #[test]
    fn validate_accepts_good_reloc() {
        assert!(validate_reloc(&good(), 0x100, 1, 1).is_ok());
    }

    #[test]
    fn validate_rejects_out_of_bounds_offset() {
        let mut r = good();
        r.offset = 0xFC; // offset+4 = 0x100, at boundary → ok
        assert!(validate_reloc(&r, 0x100, 1, 1).is_ok());
        r.offset = 0xFD; // offset+4 = 0x101, past end
        assert!(matches!(
            validate_reloc(&r, 0x100, 1, 1).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("exceeds section")
        ));
    }

    #[test]
    fn validate_rejects_symbol_oob() {
        let mut r = good();
        r.referent = Referent::Symbol(5);
        assert!(matches!(
            validate_reloc(&r, 0x100, 3, 1).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("past end of symbol")
        ));
    }

    #[test]
    fn validate_rejects_section_oob() {
        let mut r = good();
        r.referent = Referent::Section(4);
        assert!(matches!(
            validate_reloc(&r, 0x100, 0, 2).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("out-of-range section")
        ));
    }

    #[test]
    fn validate_rejects_branch26_with_wrong_length() {
        let mut r = good();
        r.length = RelocLength::Quad; // BRANCH26 must be Word
        assert!(matches!(
            validate_reloc(&r, 0x100, 1, 1).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("Word length")
        ));
    }

    #[test]
    fn validate_rejects_page21_without_pcrel() {
        let r = Reloc {
            offset: 0x10,
            kind: RelocKind::Page21,
            length: RelocLength::Word,
            pcrel: false, // Page21 requires pcrel=true
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        };
        assert!(matches!(
            validate_reloc(&r, 0x100, 1, 1).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("pcrel")
        ));
    }

    #[test]
    fn validate_accepts_unsigned_quad() {
        let r = Reloc {
            offset: 0,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        };
        assert!(validate_reloc(&r, 0x100, 1, 1).is_ok());
    }

    #[test]
    fn validate_rejects_subtractor_missing_subtrahend() {
        let r = Reloc {
            offset: 0,
            kind: RelocKind::Subtractor,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Symbol(0),
            addend: 0,
            subtrahend: None,
        };
        assert!(matches!(
            validate_reloc(&r, 0x100, 1, 1).unwrap_err(),
            ReadError::BadRelocation { reason, .. } if reason.contains("subtrahend")
        ));
    }

    #[test]
    fn write_then_parse_round_trip_section_referent() {
        let input = vec![Reloc {
            offset: 0x60,
            kind: RelocKind::Unsigned,
            length: RelocLength::Quad,
            pcrel: false,
            referent: Referent::Section(2),
            addend: 0,
            subtrahend: None,
        }];
        let raws = write_relocs(&input).unwrap();
        assert!(!raws[0].r_extern);
        assert_eq!(raws[0].r_symbolnum, 2);
        let back = parse_relocs(&raws).unwrap();
        assert_eq!(back, input);
    }
}
