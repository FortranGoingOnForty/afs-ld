//! ULEB128 / SLEB128 codec.
//!
//! dyld uses LEB128 pervasively: the export trie (Sprint 5), function-starts
//! deltas (Sprint 16), rebase/bind/lazy-bind opcode streams (Sprint 15), and
//! chained-fixups imports (Sprint 15.5) all encode variable-width integers
//! this way. One codec, reused across all of them.

use crate::macho::reader::ReadError;

/// Read a ULEB128 from `bytes`. On success returns `(value, consumed)`.
/// Errors on overrun beyond the buffer or on encodings that exceed 10 bytes
/// (maximum for a `u64`).
pub fn read_uleb(bytes: &[u8]) -> Result<(u64, usize), ReadError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        // The top bit of each byte is the continuation flag; low 7 bits are
        // value bits, concatenated little-end first.
        if shift >= 64 {
            return Err(ReadError::BadRelocation {
                at_offset: 0,
                reason: "ULEB128 overflows u64",
            });
        }
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(ReadError::Truncated {
        need: bytes.len() + 1,
        have: bytes.len(),
        context: "ULEB128 (unterminated)",
    })
}

/// Read an SLEB128 from `bytes`. On success returns `(value, consumed)`.
pub fn read_sleb(bytes: &[u8]) -> Result<(i64, usize), ReadError> {
    let mut value: i64 = 0;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return Err(ReadError::BadRelocation {
                at_offset: 0,
                reason: "SLEB128 overflows i64",
            });
        }
        value |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            // Sign-extend: if the value's sign bit (bit 6 of the last byte)
            // is set and we have spare high bits, fill them with 1s.
            if shift < 64 && (b & 0x40) != 0 {
                value |= !0i64 << shift;
            }
            return Ok((value, i + 1));
        }
    }
    Err(ReadError::Truncated {
        need: bytes.len() + 1,
        have: bytes.len(),
        context: "SLEB128 (unterminated)",
    })
}

/// Append a ULEB128 encoding of `value` to `out`.
pub fn write_uleb(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append an SLEB128 encoding of `value` to `out`.
pub fn write_sleb(mut value: i64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        // Arithmetic shift preserves the sign.
        let next = value >> 7;
        let sign_bit = byte & 0x40 != 0;
        let done = (next == 0 && !sign_bit) || (next == -1 && sign_bit);
        value = next;
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb_small_one_byte() {
        let mut buf = Vec::new();
        write_uleb(0, &mut buf);
        assert_eq!(buf, vec![0x00]);
        write_uleb(0x7f, &mut buf);
        assert_eq!(buf[1], 0x7f);
    }

    #[test]
    fn uleb_round_trips_many_values() {
        for v in [
            0u64,
            1,
            127,
            128,
            129,
            16383,
            16384,
            0xdead_beef,
            0xffff_ffff,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write_uleb(v, &mut buf);
            let (back, consumed) = read_uleb(&buf).unwrap();
            assert_eq!(back, v, "round-trip failed for {v:#x}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn sleb_round_trips_many_values() {
        for v in [
            0i64,
            1,
            -1,
            63,
            -63,
            64,
            -64,
            65,
            -65,
            127,
            -128,
            8192,
            -8192,
            0x0001_0000,
            -0x0001_0000,
            i64::MIN,
            i64::MAX,
        ] {
            let mut buf = Vec::new();
            write_sleb(v, &mut buf);
            let (back, consumed) = read_sleb(&buf).unwrap();
            assert_eq!(back, v, "sleb round-trip failed for {v}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn uleb_known_multibyte_encoding() {
        // 624485 = 0b100110000111011100101 — canonical LEB example.
        let mut buf = Vec::new();
        write_uleb(624485, &mut buf);
        assert_eq!(buf, vec![0xe5, 0x8e, 0x26]);
        let (v, n) = read_uleb(&buf).unwrap();
        assert_eq!(v, 624485);
        assert_eq!(n, 3);
    }

    #[test]
    fn sleb_known_multibyte_encoding() {
        // -12345 in SLEB: widely quoted example.
        let mut buf = Vec::new();
        write_sleb(-12345, &mut buf);
        let (v, n) = read_sleb(&buf).unwrap();
        assert_eq!(v, -12345);
        assert_eq!(n, buf.len());
    }

    #[test]
    fn uleb_unterminated_errors() {
        // Continuation bit set on every byte but no terminator.
        let buf = vec![0x80, 0x80, 0x80];
        assert!(matches!(
            read_uleb(&buf).unwrap_err(),
            ReadError::Truncated { .. }
        ));
    }

    #[test]
    fn sleb_unterminated_errors() {
        let buf = vec![0x80, 0x80];
        assert!(matches!(
            read_sleb(&buf).unwrap_err(),
            ReadError::Truncated { .. }
        ));
    }

    #[test]
    fn uleb_consumes_exactly_first_encoding() {
        let mut buf = Vec::new();
        write_uleb(100, &mut buf);
        buf.extend_from_slice(&[0xff, 0xee]); // trailing unrelated bytes
        let (v, n) = read_uleb(&buf).unwrap();
        assert_eq!(v, 100);
        assert_eq!(n, 1);
    }
}
