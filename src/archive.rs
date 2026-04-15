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
use std::path::{Path, PathBuf};
use std::str;

use crate::input::ObjectFile;
use crate::macho::reader::ReadError;

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

/// Flag marking which, if any, special role a member plays in the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialMember {
    None,
    /// BSD `__.SYMDEF` or `__.SYMDEF SORTED` — the symbol index.
    BsdSymIndex,
    /// SysV `/` — the symbol index.
    SysvSymIndex,
    /// SysV `//` — long-name string table.
    SysvLongNames,
}

/// A single parsed archive member.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    /// Real filename, post-flavor-specific decoding.
    pub name: String,
    /// Byte offset of the member's `ar_hdr` within the archive.
    pub header_offset: usize,
    /// Byte offset of the member's visible body (after any BSD extended-name
    /// prefix is stripped). For `GnuThin`, `body.len() == 0` and the real
    /// contents live in an external file named by `name`.
    pub body_offset: usize,
    /// Raw accessible body bytes.
    pub body: &'a [u8],
    /// Present for members that serve a special structural role.
    pub special: SpecialMember,
}

#[derive(Debug)]
pub struct Archive<'a> {
    pub path: PathBuf,
    pub flavor: Flavor,
    data: &'a [u8],
    members: Vec<Member<'a>>,
    symbol_index: Option<SymbolIndex>,
}

impl<'a> Archive<'a> {
    /// Open an archive given its raw bytes and the source path (for
    /// diagnostics and GNU-thin external-file resolution).
    pub fn open(path: impl Into<PathBuf>, data: &'a [u8]) -> Result<Self, ArchiveError> {
        let flavor = detect_flavor(data)?;
        let (members, flavor) = parse_members(data, flavor)?;
        let symbol_index = build_symbol_index(&members)?;
        Ok(Archive {
            path: path.into(),
            flavor,
            data,
            members,
            symbol_index,
        })
    }

    pub fn symbol_index(&self) -> Option<&SymbolIndex> {
        self.symbol_index.as_ref()
    }

    /// Raw bytes following the 8-byte magic — where member entries begin.
    pub fn body_bytes(&self) -> &'a [u8] {
        &self.data[AR_MAGIC.len()..]
    }

    /// Starting offset (inside the full archive buffer) of the first member.
    pub const fn body_start(&self) -> usize {
        AR_MAGIC.len()
    }

    pub fn members(&self) -> &[Member<'a>] {
        &self.members
    }

    /// Return every non-special member (skips symbol indexes and long-name
    /// tables).
    pub fn object_members(&self) -> impl Iterator<Item = &Member<'a>> {
        self.members.iter().filter(|m| m.special == SpecialMember::None)
    }

    /// Find the first member whose `ar_hdr` begins at `header_offset`. The
    /// symbol-index's `member_header_offset` fields feed into this lookup.
    pub fn member_at_offset(&self, header_offset: u32) -> Option<&Member<'a>> {
        self.members
            .iter()
            .find(|m| m.header_offset == header_offset as usize)
    }

    /// First member that defines `name` according to the archive's symbol
    /// index. Returns `None` when either no index is present or `name` is
    /// absent.
    pub fn first_member_defining(&self, name: &str) -> Option<&Member<'a>> {
        let off = self.symbol_index.as_ref()?.first_defining_offset(name)?;
        self.member_at_offset(off)
    }

    /// Parse a member's body as a Mach-O `ObjectFile`. Non-thin members use
    /// the in-buffer slice; GNU-thin members read their external file on
    /// demand.
    pub fn parse_member_object(&self, member: &Member<'a>) -> Result<ObjectFile, FetchError> {
        let logical_path = self.member_logical_path(member);
        match self.flavor {
            Flavor::GnuThin => {
                let file_path = self.member_external_path(member);
                let bytes = std::fs::read(&file_path).map_err(FetchError::Io)?;
                ObjectFile::parse(logical_path, &bytes).map_err(FetchError::Read)
            }
            _ => ObjectFile::parse(logical_path, member.body).map_err(FetchError::Read),
        }
    }

    /// Resolve `name` to its defining member, then parse that member as an
    /// `ObjectFile`. Returns `None` when the symbol is absent; `Some(Err(_))`
    /// when the member exists but fails to parse.
    pub fn fetch_object_defining(
        &self,
        name: &str,
    ) -> Option<Result<ObjectFile, FetchError>> {
        let member = self.first_member_defining(name)?;
        Some(self.parse_member_object(member))
    }

    /// Produce the display path a member should surface as when parsed:
    /// `/abs/path/libfoo.a(foo.o)`. For thin archives the path is the
    /// external source file — that path is useful on its own.
    fn member_logical_path(&self, member: &Member<'a>) -> PathBuf {
        if self.flavor == Flavor::GnuThin {
            return self.member_external_path(member);
        }
        let mut s = self.path.as_os_str().to_owned();
        s.push("(");
        s.push(member.name.as_str());
        s.push(")");
        PathBuf::from(s)
    }

    fn member_external_path(&self, member: &Member<'a>) -> PathBuf {
        let base = self.path.parent().unwrap_or_else(|| Path::new("."));
        base.join(&member.name)
    }
}

/// Unified error for member fetching — I/O (GNU-thin only) or Mach-O parse.
#[derive(Debug)]
pub enum FetchError {
    Io(std::io::Error),
    Read(ReadError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Io(e) => write!(f, "thin-member I/O: {e}"),
            FetchError::Read(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FetchError {}

// ---------------------------------------------------------------------------
// Member walking & name decoding.
// ---------------------------------------------------------------------------

fn parse_members<'a>(
    data: &'a [u8],
    initial_flavor: Flavor,
) -> Result<(Vec<Member<'a>>, Flavor), ArchiveError> {
    let mut cursor = AR_MAGIC.len();
    let mut flavor = initial_flavor;
    let mut long_names: Option<&'a [u8]> = None;
    let mut out: Vec<Member<'a>> = Vec::new();

    while cursor < data.len() {
        if cursor + AR_HDR_SIZE > data.len() {
            return Err(ArchiveError::Truncated {
                need: AR_HDR_SIZE,
                have: data.len() - cursor,
                context: "ar_hdr",
            });
        }
        let hdr = ArHeader::parse(&data[cursor..cursor + AR_HDR_SIZE], cursor)?;
        let size = hdr.size as usize;
        let body_start = cursor + AR_HDR_SIZE;
        let body_end = body_start
            .checked_add(size)
            .ok_or(ArchiveError::MemberOverrun {
                at_offset: cursor,
                size: hdr.size,
            })?;
        if flavor != Flavor::GnuThin && body_end > data.len() {
            return Err(ArchiveError::MemberOverrun {
                at_offset: cursor,
                size: hdr.size,
            });
        }
        let raw_name = hdr.raw_name_str();
        let (real_name, body_offset, body, special) = decode_member(
            raw_name,
            data,
            body_start,
            size,
            flavor,
            long_names,
            cursor,
        )?;

        // Opportunistic flavor refinement. The sole unambiguous signal for
        // Sysv is the presence of `/` or `//` members — BSD never emits
        // either.
        match special {
            SpecialMember::SysvSymIndex | SpecialMember::SysvLongNames => {
                flavor = Flavor::Sysv;
            }
            _ => {}
        }
        if matches!(special, SpecialMember::SysvLongNames) {
            long_names = Some(body);
        }

        out.push(Member {
            name: real_name,
            header_offset: cursor,
            body_offset,
            body,
            special,
        });

        // Advance past body + 1-byte alignment pad for odd sizes (GNU-thin
        // members have zero-byte bodies so this collapses to a no-op).
        let advance = AR_HDR_SIZE + size + (size & 1);
        cursor = cursor.checked_add(advance).ok_or(ArchiveError::MemberOverrun {
            at_offset: cursor,
            size: hdr.size,
        })?;
    }

    Ok((out, flavor))
}

#[allow(clippy::too_many_arguments)]
fn decode_member<'a>(
    raw_name: &str,
    data: &'a [u8],
    body_start: usize,
    size: usize,
    flavor: Flavor,
    long_names: Option<&'a [u8]>,
    header_offset: usize,
) -> Result<(String, usize, &'a [u8], SpecialMember), ArchiveError> {
    // GNU-thin: body is zero bytes; name field is the external path.
    if flavor == Flavor::GnuThin {
        let name = raw_name.trim_end_matches('/').to_string();
        return Ok((name, body_start, &data[body_start..body_start], SpecialMember::None));
    }

    // BSD extended: "#1/<N>" — first N bytes of the body are the real name.
    if let Some(rest) = raw_name.strip_prefix("#1/") {
        let nlen: usize = rest.parse().map_err(|_| ArchiveError::BadAsciiField {
            at_offset: header_offset,
            field: "#1/<N>",
        })?;
        if body_start + nlen > data.len() || nlen > size {
            return Err(ArchiveError::MemberOverrun {
                at_offset: header_offset,
                size: size as u64,
            });
        }
        let name_bytes = &data[body_start..body_start + nlen];
        let name = str::from_utf8(name_bytes).map_err(|_| ArchiveError::BadName {
            at_offset: header_offset,
        })?;
        // Trim trailing nulls (some writers pad the name to 4/8 bytes).
        let name = name.trim_end_matches('\0').to_string();
        let body = &data[body_start + nlen..body_start + size];
        let special = if name == "__.SYMDEF" || name == "__.SYMDEF SORTED" {
            SpecialMember::BsdSymIndex
        } else {
            SpecialMember::None
        };
        return Ok((name, body_start + nlen, body, special));
    }

    // SysV structural members.
    if raw_name == "/" {
        return Ok((
            "/".to_string(),
            body_start,
            &data[body_start..body_start + size],
            SpecialMember::SysvSymIndex,
        ));
    }
    if raw_name == "//" {
        return Ok((
            "//".to_string(),
            body_start,
            &data[body_start..body_start + size],
            SpecialMember::SysvLongNames,
        ));
    }

    // SysV long-name reference: "/NNN".
    if let Some(rest) = raw_name.strip_prefix('/') {
        if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
            let strx: u32 = rest.parse().map_err(|_| ArchiveError::BadAsciiField {
                at_offset: header_offset,
                field: "/NNN",
            })?;
            let table = long_names.ok_or(ArchiveError::LongNameOob {
                at_offset: header_offset,
                strx,
            })?;
            let name = decode_long_name(table, strx, header_offset)?;
            return Ok((
                name,
                body_start,
                &data[body_start..body_start + size],
                SpecialMember::None,
            ));
        }
    }

    // SysV short name — slash-terminated.
    if let Some(stripped) = raw_name.strip_suffix('/') {
        return Ok((
            stripped.to_string(),
            body_start,
            &data[body_start..body_start + size],
            SpecialMember::None,
        ));
    }

    // BSD short name (no trailing slash, no #1/ prefix).
    Ok((
        raw_name.to_string(),
        body_start,
        &data[body_start..body_start + size],
        SpecialMember::None,
    ))
}

// ---------------------------------------------------------------------------
// Symbol index parsing (BSD __.SYMDEF / SysV `/`).
// ---------------------------------------------------------------------------

/// One defined-symbol row in the archive symbol index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolIndexEntry {
    pub name: String,
    /// Byte offset of the defining member's `ar_hdr` within the archive.
    pub member_header_offset: u32,
}

/// The table of `(symbol → defining member offset)` the archive writer
/// embeds up front. A given name can appear multiple times — ld's policy is
/// to take the first defining member. Iteration preserves the source order.
#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    pub entries: Vec<SymbolIndexEntry>,
}

impl SymbolIndex {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the `ar_hdr` offset of the first member that defines `name`,
    /// or `None` if the index has no such entry. The "first" rule matches
    /// ld's classic ordering — a later duplicate doesn't shadow an earlier.
    pub fn first_defining_offset(&self, name: &str) -> Option<u32> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.member_header_offset)
    }

    /// All `ar_hdr` offsets where `name` appears. Exists for `-all_load` /
    /// `-force_load` semantics and for tests that want to verify duplicates.
    pub fn offsets_for<'n>(&'n self, name: &'n str) -> impl Iterator<Item = u32> + 'n {
        self.entries
            .iter()
            .filter(move |e| e.name == name)
            .map(|e| e.member_header_offset)
    }
}

fn build_symbol_index(members: &[Member<'_>]) -> Result<Option<SymbolIndex>, ArchiveError> {
    for m in members {
        match m.special {
            SpecialMember::BsdSymIndex => {
                return Ok(Some(parse_bsd_symbol_index(m.body)?));
            }
            SpecialMember::SysvSymIndex => {
                return Ok(Some(parse_sysv_symbol_index(m.body)?));
            }
            _ => {}
        }
    }
    Ok(None)
}

/// BSD `__.SYMDEF` / `__.SYMDEF SORTED`, little-endian:
/// ```text
///   u32 ranlib_byte_count
///   ranlib[] { u32 strx; u32 member_header_offset; }
///   u32 string_size
///   char strings[string_size]
/// ```
fn parse_bsd_symbol_index(body: &[u8]) -> Result<SymbolIndex, ArchiveError> {
    if body.len() < 8 {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "__.SYMDEF shorter than 8-byte header",
        });
    }
    let ranlib_bytes = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    if !ranlib_bytes.is_multiple_of(8) {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "__.SYMDEF ranlib byte count not a multiple of 8",
        });
    }
    let ranlib_end = 4usize.checked_add(ranlib_bytes).ok_or(ArchiveError::BadSymbolIndex {
        reason: "__.SYMDEF ranlib region overflows",
    })?;
    if ranlib_end + 4 > body.len() {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "__.SYMDEF ranlib + stringsize region overruns member",
        });
    }
    let stringsize =
        u32::from_le_bytes(body[ranlib_end..ranlib_end + 4].try_into().unwrap()) as usize;
    let strings_start = ranlib_end + 4;
    let strings_end = strings_start
        .checked_add(stringsize)
        .ok_or(ArchiveError::BadSymbolIndex {
            reason: "__.SYMDEF strings region overflows",
        })?;
    if strings_end > body.len() {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "__.SYMDEF strings region overruns member",
        });
    }
    let strings = &body[strings_start..strings_end];

    let mut entries = Vec::with_capacity(ranlib_bytes / 8);
    let mut off = 4;
    while off < ranlib_end {
        let strx = u32::from_le_bytes(body[off..off + 4].try_into().unwrap()) as usize;
        let mh_off = u32::from_le_bytes(body[off + 4..off + 8].try_into().unwrap());
        if strx >= strings.len() {
            return Err(ArchiveError::BadSymbolIndex {
                reason: "ranlib strx out of bounds",
            });
        }
        let end = strings[strx..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| strx + i)
            .ok_or(ArchiveError::BadSymbolIndex {
                reason: "ranlib name not null-terminated",
            })?;
        let name = str::from_utf8(&strings[strx..end])
            .map_err(|_| ArchiveError::BadSymbolIndex {
                reason: "ranlib name not UTF-8",
            })?
            .to_string();
        entries.push(SymbolIndexEntry {
            name,
            member_header_offset: mh_off,
        });
        off += 8;
    }
    Ok(SymbolIndex { entries })
}

/// SysV `/` symbol index, big-endian:
/// ```text
///   u32  nsyms
///   u32  offsets[nsyms]   — each a member ar_hdr offset
///   char strings[]        — nsyms null-terminated names, concatenated
/// ```
fn parse_sysv_symbol_index(body: &[u8]) -> Result<SymbolIndex, ArchiveError> {
    if body.len() < 4 {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "SysV symbol index shorter than 4-byte header",
        });
    }
    let nsyms = u32::from_be_bytes(body[0..4].try_into().unwrap()) as usize;
    let offsets_end = 4usize
        .checked_add(nsyms * 4)
        .ok_or(ArchiveError::BadSymbolIndex {
            reason: "SysV symbol-index offsets region overflows",
        })?;
    if offsets_end > body.len() {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "SysV symbol-index offsets region overruns member",
        });
    }
    let strings = &body[offsets_end..];

    let mut entries = Vec::with_capacity(nsyms);
    let mut cursor = 0usize;
    for i in 0..nsyms {
        let off = 4 + i * 4;
        let mh_off = u32::from_be_bytes(body[off..off + 4].try_into().unwrap());
        if cursor >= strings.len() {
            return Err(ArchiveError::BadSymbolIndex {
                reason: "SysV symbol-index names exhausted before nsyms satisfied",
            });
        }
        let end = strings[cursor..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| cursor + i)
            .ok_or(ArchiveError::BadSymbolIndex {
                reason: "SysV symbol-index name not null-terminated",
            })?;
        let name = str::from_utf8(&strings[cursor..end])
            .map_err(|_| ArchiveError::BadSymbolIndex {
                reason: "SysV symbol-index name not UTF-8",
            })?
            .to_string();
        entries.push(SymbolIndexEntry {
            name,
            member_header_offset: mh_off,
        });
        cursor = end + 1;
    }
    Ok(SymbolIndex { entries })
}

fn decode_long_name(
    table: &[u8],
    strx: u32,
    at_offset: usize,
) -> Result<String, ArchiveError> {
    let start = strx as usize;
    if start >= table.len() {
        return Err(ArchiveError::LongNameOob { at_offset, strx });
    }
    // GNU-style long names end at either a null or a "/\n" sequence; we
    // accept the more permissive union and stop at the first of either.
    let end = table[start..]
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .map(|i| start + i)
        .unwrap_or(table.len());
    // Strip a trailing slash that GNU appends before the newline.
    let trimmed_end = if end > 0 && table[end - 1] == b'/' { end - 1 } else { end };
    str::from_utf8(&table[start..trimmed_end])
        .map(|s| s.to_string())
        .map_err(|_| ArchiveError::BadName { at_offset })
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
        let ar = Archive::open("/tmp/empty.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::Bsd);
        assert_eq!(ar.body_bytes(), b"");
        assert_eq!(ar.body_start(), AR_MAGIC.len());
        assert!(ar.members().is_empty());
    }

    // ----- helpers for member fixtures -----

    /// Build a member: 60-byte header with name field `raw_name`, size
    /// equal to `body.len()`, followed by the body bytes and a 1-byte pad
    /// if the body is odd-length.
    fn encode_member(raw_name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = make_ar_hdr(raw_name, body.len() as u64);
        out.extend_from_slice(body);
        if body.len() & 1 != 0 {
            out.push(b'\n');
        }
        out
    }

    /// Build a BSD extended-name member: raw name "#1/<N>", body = name + content.
    fn encode_bsd_extended(name: &str, content: &[u8]) -> Vec<u8> {
        let raw = format!("#1/{}", name.len());
        let mut body = Vec::with_capacity(name.len() + content.len());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(content);
        encode_member(&raw, &body)
    }

    #[test]
    fn bsd_short_name_roundtrips() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("foo.o", b"XXXX"));
        let ar = Archive::open("/tmp/bsd.a", &buf).unwrap();
        assert_eq!(ar.members().len(), 1);
        assert_eq!(ar.members()[0].name, "foo.o");
        assert_eq!(ar.members()[0].body, b"XXXX");
        assert_eq!(ar.members()[0].special, SpecialMember::None);
    }

    #[test]
    fn bsd_extended_name_splits_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("long_filename_with_many_chars.o", b"CONT"));
        let ar = Archive::open("/tmp/bsd_ext.a", &buf).unwrap();
        assert_eq!(ar.members()[0].name, "long_filename_with_many_chars.o");
        assert_eq!(ar.members()[0].body, b"CONT");
    }

    #[test]
    fn bsd_extended_symdef_marked_special() {
        let empty_idx = encode_bsd_symbol_index(&[]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("__.SYMDEF SORTED", &empty_idx));
        let ar = Archive::open("/tmp/bsd_symdef.a", &buf).unwrap();
        assert_eq!(ar.members()[0].special, SpecialMember::BsdSymIndex);
    }

    #[test]
    fn sysv_short_name_strips_slash() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        // Sysv short names are right-padded with spaces and terminated by '/'.
        buf.extend_from_slice(&encode_member("foo.o/", b"aa"));
        let ar = Archive::open("/tmp/sysv.a", &buf).unwrap();
        assert_eq!(ar.members()[0].name, "foo.o");
    }

    #[test]
    fn sysv_long_names_resolve_via_slash_slash_table() {
        // Long-name table content: "really_long_name.o/\nfoo/\n"
        // Offsets: 0 → "really_long_name.o", 20 → "foo".
        let lns_body: &[u8] = b"really_long_name.o/\nfoo/\n";
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("//", lns_body));
        buf.extend_from_slice(&encode_member("/0", b"BODY1"));
        buf.extend_from_slice(&encode_member("/20", b"BODY2"));
        let ar = Archive::open("/tmp/sysv_long.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::Sysv);
        assert_eq!(ar.members().len(), 3);
        assert_eq!(ar.members()[0].special, SpecialMember::SysvLongNames);
        assert_eq!(ar.members()[1].name, "really_long_name.o");
        assert_eq!(ar.members()[1].body, b"BODY1");
        assert_eq!(ar.members()[2].name, "foo");
    }

    #[test]
    fn sysv_symbol_index_member_is_special() {
        let empty_idx = encode_sysv_symbol_index(&[]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("/", &empty_idx));
        let ar = Archive::open("/tmp/sysv_sym.a", &buf).unwrap();
        assert_eq!(ar.members()[0].special, SpecialMember::SysvSymIndex);
        assert_eq!(ar.flavor, Flavor::Sysv);
    }

    #[test]
    fn odd_sized_member_pad_byte_consumed() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("a.o", b"ODD")); // 3 bytes → 1 pad
        buf.extend_from_slice(&encode_member("b.o", b"AA")); // 2 bytes → no pad
        let ar = Archive::open("/tmp/pad.a", &buf).unwrap();
        assert_eq!(ar.members().len(), 2);
        assert_eq!(ar.members()[0].name, "a.o");
        assert_eq!(ar.members()[1].name, "b.o");
    }

    #[test]
    fn object_members_skip_specials() {
        let empty_idx = encode_bsd_symbol_index(&[]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("__.SYMDEF", &empty_idx));
        buf.extend_from_slice(&encode_member("real.o", b"CONTENT"));
        let ar = Archive::open("/tmp/mixed.a", &buf).unwrap();
        assert_eq!(ar.members().len(), 2);
        let reals: Vec<_> = ar.object_members().map(|m| m.name.clone()).collect();
        assert_eq!(reals, vec!["real.o"]);
    }

    #[test]
    fn gnu_thin_decodes_paths_without_bodies() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC_THIN);
        // Thin members have zero-byte bodies.
        buf.extend_from_slice(&make_ar_hdr("../foo.o/", 0));
        buf.extend_from_slice(&make_ar_hdr("bar.o/", 0));
        let ar = Archive::open("/tmp/thin.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::GnuThin);
        assert_eq!(ar.members().len(), 2);
        assert_eq!(ar.members()[0].name, "../foo.o");
        assert_eq!(ar.members()[1].name, "bar.o");
    }

    // ----- symbol-index tests -----

    /// Build a BSD __.SYMDEF body: ranlib array + stringtab.
    fn encode_bsd_symbol_index(entries: &[(&str, u32)]) -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut strx_map = Vec::new();
        for (name, _) in entries {
            let strx = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            strx_map.push(strx);
        }
        let ranlib_bytes = (entries.len() * 8) as u32;

        let mut body = Vec::new();
        body.extend_from_slice(&ranlib_bytes.to_le_bytes());
        for ((_, mh_off), strx) in entries.iter().zip(strx_map.iter()) {
            body.extend_from_slice(&strx.to_le_bytes());
            body.extend_from_slice(&mh_off.to_le_bytes());
        }
        let stringsize = strings.len() as u32;
        body.extend_from_slice(&stringsize.to_le_bytes());
        body.extend_from_slice(&strings);
        body
    }

    fn encode_sysv_symbol_index(entries: &[(&str, u32)]) -> Vec<u8> {
        let nsyms = entries.len() as u32;
        let mut body = Vec::new();
        body.extend_from_slice(&nsyms.to_be_bytes());
        for (_, mh_off) in entries {
            body.extend_from_slice(&mh_off.to_be_bytes());
        }
        for (name, _) in entries {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
        }
        body
    }

    #[test]
    fn bsd_symbol_index_parses_entries() {
        let idx_body = encode_bsd_symbol_index(&[("_alpha", 0x100), ("_beta", 0x200)]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("__.SYMDEF SORTED", &idx_body));
        let ar = Archive::open("/tmp/bsd_idx.a", &buf).unwrap();
        let idx = ar.symbol_index().expect("index present");
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.first_defining_offset("_alpha"), Some(0x100));
        assert_eq!(idx.first_defining_offset("_beta"), Some(0x200));
        assert_eq!(idx.first_defining_offset("_missing"), None);
    }

    #[test]
    fn sysv_symbol_index_parses_entries() {
        let idx_body = encode_sysv_symbol_index(&[("_alpha", 0x60), ("_beta", 0xC0)]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("/", &idx_body));
        let ar = Archive::open("/tmp/sysv_idx.a", &buf).unwrap();
        let idx = ar.symbol_index().expect("index present");
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.first_defining_offset("_alpha"), Some(0x60));
        assert_eq!(idx.first_defining_offset("_beta"), Some(0xC0));
    }

    #[test]
    fn symbol_index_absent_when_no_special_member() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("foo.o/", b"CONTENT"));
        let ar = Archive::open("/tmp/noidx.a", &buf).unwrap();
        assert!(ar.symbol_index().is_none());
    }

    #[test]
    fn symbol_index_duplicate_returns_first() {
        let idx_body = encode_bsd_symbol_index(&[("_sym", 0x100), ("_sym", 0x200)]);
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("__.SYMDEF", &idx_body));
        let ar = Archive::open("/tmp/dup.a", &buf).unwrap();
        let idx = ar.symbol_index().unwrap();
        assert_eq!(idx.first_defining_offset("_sym"), Some(0x100));
        let all: Vec<u32> = idx.offsets_for("_sym").collect();
        assert_eq!(all, vec![0x100, 0x200]);
    }

    #[test]
    fn bsd_symbol_index_rejects_oob_strx() {
        // ranlib entry with strx = 999 but strings is tiny.
        let mut body = Vec::new();
        body.extend_from_slice(&8u32.to_le_bytes()); // 8 bytes → 1 ranlib
        body.extend_from_slice(&999u32.to_le_bytes()); // strx
        body.extend_from_slice(&0u32.to_le_bytes()); // mh_off
        body.extend_from_slice(&4u32.to_le_bytes()); // stringsize
        body.extend_from_slice(b"abc\0");
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended("__.SYMDEF", &body));
        assert!(matches!(
            Archive::open("/tmp/bad_idx.a", &buf).unwrap_err(),
            ArchiveError::BadSymbolIndex { .. }
        ));
    }

    // ----- fetch API tests -----

    fn encode_member_at(raw_name: &str, body: &[u8], out: &mut Vec<u8>) -> usize {
        let off = out.len();
        out.extend_from_slice(&encode_member(raw_name, body));
        off
    }

    #[test]
    fn first_member_defining_uses_symbol_index_offset() {
        // Layout: magic, __.SYMDEF placeholder, real.o body. Patch the index
        // after we know real.o's header offset.
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(AR_MAGIC);
        let idx_placeholder = encode_bsd_symbol_index(&[("_foo", 0)]);
        let idx_member_bytes = encode_bsd_extended("__.SYMDEF", &idx_placeholder);
        let idx_member_off = buf.len();
        buf.extend_from_slice(&idx_member_bytes);

        let real_off = encode_member_at("real.o", b"CONTENT", &mut buf) as u32;
        let updated_idx = encode_bsd_symbol_index(&[("_foo", real_off)]);
        let updated_member = encode_bsd_extended("__.SYMDEF", &updated_idx);
        buf.splice(
            idx_member_off..idx_member_off + idx_member_bytes.len(),
            updated_member,
        );

        let ar = Archive::open("/tmp/sym_fetch.a", &buf).unwrap();
        let m = ar.first_member_defining("_foo").expect("symbol found");
        assert_eq!(m.name, "real.o");
        assert_eq!(m.body, b"CONTENT");
    }

    #[test]
    fn fetch_object_defining_reports_parse_error_for_non_macho_body() {
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(AR_MAGIC);
        let idx_placeholder = encode_bsd_symbol_index(&[("_bogus", 0)]);
        let idx_bytes = encode_bsd_extended("__.SYMDEF", &idx_placeholder);
        let idx_off = buf.len();
        buf.extend_from_slice(&idx_bytes);
        let real_off = encode_member_at("bogus.o", b"notmacho", &mut buf) as u32;
        let updated_idx = encode_bsd_symbol_index(&[("_bogus", real_off)]);
        let updated_member = encode_bsd_extended("__.SYMDEF", &updated_idx);
        buf.splice(idx_off..idx_off + idx_bytes.len(), updated_member);

        let ar = Archive::open("/tmp/bad_body.a", &buf).unwrap();
        let result = ar.fetch_object_defining("_bogus").expect("found");
        assert!(matches!(result, Err(FetchError::Read(_))));
    }

    #[test]
    fn fetch_object_defining_returns_none_for_unknown_symbol() {
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_member("foo.o", b"BODY"));
        let ar = Archive::open("/tmp/no_idx.a", &buf).unwrap();
        assert!(ar.fetch_object_defining("_missing").is_none());
    }

    #[test]
    fn member_overrun_errors() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&make_ar_hdr("foo.o/", 999)); // claims 999 bytes but body absent
        assert!(matches!(
            Archive::open("/tmp/bad.a", &buf).unwrap_err(),
            ArchiveError::MemberOverrun { .. }
        ));
    }
}
