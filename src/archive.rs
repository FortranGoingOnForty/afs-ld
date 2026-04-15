//! Static archive (`ar`) reader.
//!
//! `.a` files come in three flavors afs-ld cares about:
//!
//! | Flavor    | Magic        | Names                                          |
//! |-----------|--------------|------------------------------------------------|
//! | `Bsd`     | `!<arch>\n`  | `#1/<N>` — next N bytes of the body are the name |
//! | `Sysv`    | `!<arch>\n`  | `foo.o/` (short) or `/NNN` into `//` (long)    |
//! | `GnuThin` | `!<thin>\n`  | name field holds an external path (body empty) |
//!
//! Both BSD and SysV archives use the same magic; distinguishing them
//! requires peeking at the first member. Apple's `ar` emits BSD; GNU's `ar`
//! on Linux emits SysV; GNU-thin archives use the `!<thin>\n` magic.
//!
//! Sprint 4 parses headers and member names, builds a symbol index, and
//! exposes `fetch_by_name` for lazy member retrieval driven by the Sprint 8
//! resolution pass. Member body bytes are returned as borrowed slices into
//! the archive buffer (or a secondary mmap for GNU-thin).

use std::fmt;
use std::path::PathBuf;
use std::str;

/// 8-byte magic bytes common to both regular `ar` variants.
pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
/// 8-byte magic bytes for a GNU "thin" archive.
pub const AR_MAGIC_THIN: &[u8; 8] = b"!<thin>\n";
/// Per-entry footer bytes following the 60-byte header.
pub const AR_FMAG: &[u8; 2] = b"`\n";
/// Size of `ar_hdr` on the wire.
pub const AR_HDR_SIZE: usize = 60;

/// Every parser error the archive reader can produce.
#[derive(Debug)]
pub enum ArchiveError {
    /// The input buffer is shorter than the next structure we need to read.
    Truncated { need: usize, have: usize, context: &'static str },
    /// The 8-byte magic is neither `!<arch>\n` nor `!<thin>\n`.
    BadMagic { got: [u8; 8] },
    /// A header footer (`fmag`) wasn't `` `\n ``.
    BadEntryFooter { at_offset: usize },
    /// An ASCII decimal field (size/date/uid/gid/mode) didn't parse.
    BadAsciiField { at_offset: usize, field: &'static str },
    /// A member's claimed size would overrun the archive.
    MemberOverrun { at_offset: usize, size: u64 },
    /// A `/NNN` long-name offset didn't land inside the `//` table.
    LongNameOob { at_offset: usize, strx: u32 },
    /// Required special member (e.g. `__.SYMDEF`) malformed.
    BadSymbolIndex { reason: &'static str },
    /// Name field could not be interpreted as UTF-8.
    BadName { at_offset: usize },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::Truncated { need, have, context } => write!(
                f,
                "archive truncated while reading {context}: need {need} bytes, have {have}"
            ),
            ArchiveError::BadMagic { got } => write!(
                f,
                "archive magic {:?} is not `!<arch>\\n` or `!<thin>\\n`",
                String::from_utf8_lossy(got)
            ),
            ArchiveError::BadEntryFooter { at_offset } => write!(
                f,
                "archive member at offset 0x{at_offset:x}: missing or malformed entry footer"
            ),
            ArchiveError::BadAsciiField { at_offset, field } => write!(
                f,
                "archive member at offset 0x{at_offset:x}: {field} field is not ASCII decimal"
            ),
            ArchiveError::MemberOverrun { at_offset, size } => write!(
                f,
                "archive member at offset 0x{at_offset:x}: claimed size {size} overruns archive"
            ),
            ArchiveError::LongNameOob { at_offset, strx } => write!(
                f,
                "archive member at offset 0x{at_offset:x}: /{strx} out of bounds of // long-name table"
            ),
            ArchiveError::BadSymbolIndex { reason } => {
                write!(f, "archive symbol index malformed: {reason}")
            }
            ArchiveError::BadName { at_offset } => write!(
                f,
                "archive member at offset 0x{at_offset:x}: name is not valid UTF-8"
            ),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Which wire flavor this archive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// `!<arch>\n` with BSD "extended" member names (`#1/<N>`).
    Bsd,
    /// `!<arch>\n` with SysV short names (`foo.o/`) and a `//` long-name
    /// string table for anything that doesn't fit in 16 bytes.
    Sysv,
    /// `!<thin>\n` — member bodies are zero bytes; the name field carries an
    /// external path, resolved lazily against the archive's parent directory.
    GnuThin,
}

/// The 60-byte `ar_hdr` decoded into fixed fields. Name bytes are held raw
/// (null-padded, slash-terminated) — `Member` does the flavor-specific
/// interpretation that turns them into a real filename.
#[derive(Debug, Clone, Copy)]
pub struct ArHeader {
    pub name: [u8; 16],
    pub date: [u8; 12],
    pub uid: [u8; 6],
    pub gid: [u8; 6],
    pub mode: [u8; 8],
    /// Raw ASCII-decimal `size` field, decoded.
    pub size: u64,
}

impl ArHeader {
    pub fn parse(bytes: &[u8], at_offset: usize) -> Result<Self, ArchiveError> {
        if bytes.len() < AR_HDR_SIZE {
            return Err(ArchiveError::Truncated {
                need: AR_HDR_SIZE,
                have: bytes.len(),
                context: "ar_hdr",
            });
        }
        let fmag: [u8; 2] = [bytes[58], bytes[59]];
        if &fmag != AR_FMAG {
            return Err(ArchiveError::BadEntryFooter { at_offset });
        }
        let size = ascii_decimal(&bytes[48..58]).map_err(|_| ArchiveError::BadAsciiField {
            at_offset,
            field: "size",
        })?;
        Ok(ArHeader {
            name: bytes[0..16].try_into().unwrap(),
            date: bytes[16..28].try_into().unwrap(),
            uid: bytes[28..34].try_into().unwrap(),
            gid: bytes[34..40].try_into().unwrap(),
            mode: bytes[40..48].try_into().unwrap(),
            size,
        })
    }

    pub fn raw_name_str(&self) -> &str {
        trim_ascii(&self.name)
    }
}

/// Leading slice skeleton — reader identifies magic + flavor and exposes a
/// cursor-based interface. Later commits build `Member` + symbol index +
/// name resolution on top of this.
#[derive(Debug)]
pub struct Archive<'a> {
    pub path: PathBuf,
    pub flavor: Flavor,
    data: &'a [u8],
}

impl<'a> Archive<'a> {
    /// Open an archive given its raw bytes and the source path (for
    /// diagnostics and GNU-thin external-file resolution).
    pub fn open(path: impl Into<PathBuf>, data: &'a [u8]) -> Result<Self, ArchiveError> {
        let flavor = detect_flavor(data)?;
        Ok(Archive {
            path: path.into(),
            flavor,
            data,
        })
    }

    /// Raw bytes following the 8-byte magic — where member entries begin.
    pub fn body_bytes(&self) -> &'a [u8] {
        &self.data[AR_MAGIC.len()..]
    }

    /// Starting offset (inside the full archive buffer) of the first member.
    pub const fn body_start(&self) -> usize {
        AR_MAGIC.len()
    }
}

pub fn detect_flavor(data: &[u8]) -> Result<Flavor, ArchiveError> {
    if data.len() < AR_MAGIC.len() {
        return Err(ArchiveError::Truncated {
            need: AR_MAGIC.len(),
            have: data.len(),
            context: "archive magic",
        });
    }
    let head: [u8; 8] = data[..8].try_into().unwrap();
    match &head {
        m if m == AR_MAGIC => Ok(Flavor::Bsd), // refined vs Sysv by peeking at first member
        m if m == AR_MAGIC_THIN => Ok(Flavor::GnuThin),
        _ => Err(ArchiveError::BadMagic { got: head }),
    }
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// Trim trailing spaces and null bytes from a fixed-width ASCII field.
pub(crate) fn trim_ascii(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    // Safe: `ar_hdr` fields are ASCII in practice; non-ASCII surfaces via
    // the caller-level `BadName` diagnostic.
    str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// Parse a right-trimmed ASCII-decimal field into `u64`. Empty (all-space)
/// fields return 0 — this matches what Apple's `ar` writes for `date/uid/gid/mode`
/// on anonymized archives.
pub(crate) fn ascii_decimal(bytes: &[u8]) -> Result<u64, ()> {
    let s = trim_ascii(bytes);
    if s.is_empty() {
        return Ok(0);
    }
    s.parse::<u64>().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_bsd_flavor() {
        let buf = b"!<arch>\nextra bytes";
        let flavor = detect_flavor(buf).unwrap();
        assert_eq!(flavor, Flavor::Bsd);
    }

    #[test]
    fn detect_thin_flavor() {
        let buf = b"!<thin>\n";
        assert_eq!(detect_flavor(buf).unwrap(), Flavor::GnuThin);
    }

    #[test]
    fn detect_rejects_bad_magic() {
        let buf = b"NOTARCH!";
        assert!(matches!(
            detect_flavor(buf).unwrap_err(),
            ArchiveError::BadMagic { .. }
        ));
    }

    #[test]
    fn detect_rejects_truncated_magic() {
        let buf = b"!<ar";
        assert!(matches!(
            detect_flavor(buf).unwrap_err(),
            ArchiveError::Truncated { .. }
        ));
    }

    /// Synthesize a 60-byte ar_hdr with the given fixed fields.
    fn make_ar_hdr(name: &str, size: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(AR_HDR_SIZE);
        let name_bytes = name.as_bytes();
        let mut name_field = [b' '; 16];
        name_field[..name_bytes.len().min(16)].copy_from_slice(&name_bytes[..name_bytes.len().min(16)]);
        buf.extend_from_slice(&name_field);
        buf.extend_from_slice(&[b' '; 12]); // date
        buf.extend_from_slice(&[b' '; 6]);  // uid
        buf.extend_from_slice(&[b' '; 6]);  // gid
        buf.extend_from_slice(&[b' '; 8]);  // mode
        let mut size_field = [b' '; 10];
        let size_str = size.to_string();
        let bytes = size_str.as_bytes();
        size_field[..bytes.len()].copy_from_slice(bytes);
        buf.extend_from_slice(&size_field);
        buf.extend_from_slice(AR_FMAG);
        buf
    }

    #[test]
    fn ar_header_decodes_fields() {
        let hdr = make_ar_hdr("foo.o/", 128);
        let parsed = ArHeader::parse(&hdr, 0).unwrap();
        assert_eq!(parsed.size, 128);
        assert_eq!(parsed.raw_name_str(), "foo.o/");
    }

    #[test]
    fn ar_header_rejects_bad_fmag() {
        let mut hdr = make_ar_hdr("foo.o/", 0);
        hdr[58] = b'X';
        assert!(matches!(
            ArHeader::parse(&hdr, 0x40).unwrap_err(),
            ArchiveError::BadEntryFooter { at_offset: 0x40 }
        ));
    }

    #[test]
    fn ar_header_rejects_non_decimal_size() {
        let mut hdr = make_ar_hdr("foo.o/", 0);
        hdr[48..58].copy_from_slice(b"abc       ");
        assert!(matches!(
            ArHeader::parse(&hdr, 0).unwrap_err(),
            ArchiveError::BadAsciiField { field: "size", .. }
        ));
    }

    #[test]
    fn ar_header_truncated_errors() {
        let short = vec![0u8; 30];
        assert!(matches!(
            ArHeader::parse(&short, 0).unwrap_err(),
            ArchiveError::Truncated { need: AR_HDR_SIZE, .. }
        ));
    }

    #[test]
    fn ascii_decimal_accepts_empty_as_zero() {
        assert_eq!(ascii_decimal(b"          ").unwrap(), 0);
        assert_eq!(ascii_decimal(b"42        ").unwrap(), 42);
        assert!(ascii_decimal(b"abc       ").is_err());
    }

    #[test]
    fn archive_open_exposes_body_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(b"BODY");
        let ar = Archive::open("/tmp/fake.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::Bsd);
        assert_eq!(ar.body_bytes(), b"BODY");
        assert_eq!(ar.body_start(), AR_MAGIC.len());
    }
}
