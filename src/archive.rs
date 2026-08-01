//! Static archive (`ar`) reader.
//!
//! `.a` files come in three flavors afs-ld cares about:
//!
//! | Flavor    | Magic        | Names                                          |
//! |-----------|--------------|------------------------------------------------|
//! | `Bsd`     | `!<arch>\n`  | `#1/<N>` — next N bytes of the body are the name |
//! | `Sysv`    | `!<arch>\n`  | `foo.o/` (short) or `/NNN` into `//` (long)    |
//! | `GnuThin` | `!<thin>\n`  | SysV names; ordinary bodies live in external files |
//!
//! Both BSD and SysV archives use the same magic; distinguishing them
//! requires peeking at the first member. Apple's `ar` emits BSD; GNU's `ar`
//! on Linux emits SysV; GNU-thin archives use the `!<thin>\n` magic.
//!
//! Sprint 4 parses headers and member names, builds a symbol index, and
//! exposes `fetch_by_name` for lazy member retrieval driven by the Sprint 8
//! resolution pass. Regular bodies borrow from the archive buffer; GNU-thin
//! object files are read from their external paths on demand.

use std::borrow::Cow;
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::OsString;
use std::fmt;
use std::io;
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

#[cfg(test)]
thread_local! {
    static ARCHIVE_PARSE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_archive_parse_count() {
    ARCHIVE_PARSE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn archive_parse_count() -> usize {
    ARCHIVE_PARSE_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_archive_parse() {
    ARCHIVE_PARSE_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

/// Every parser error the archive reader can produce.
#[derive(Debug)]
pub enum ArchiveError {
    /// The input buffer is shorter than the next structure we need to read.
    Truncated {
        need: usize,
        have: usize,
        context: &'static str,
    },
    /// The 8-byte magic is neither `!<arch>\n` nor `!<thin>\n`.
    BadMagic { got: [u8; 8] },
    /// A header footer (`fmag`) wasn't `` `\n ``.
    BadEntryFooter { at_offset: usize },
    /// An ASCII decimal field (size/date/uid/gid/mode) didn't parse.
    BadAsciiField {
        at_offset: usize,
        field: &'static str,
    },
    /// A member's claimed size would overrun the archive.
    MemberOverrun { at_offset: usize, size: u64 },
    /// A `/NNN` long-name offset didn't land inside the `//` table.
    LongNameOob { at_offset: usize, strx: u64 },
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
    /// `!<thin>\n` — symbol and name tables stay inline, while ordinary
    /// member bodies live at paths resolved against the archive's parent.
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

    pub fn raw_name_bytes(&self) -> &[u8] {
        let trimmed = trim_ascii_bytes(&self.name);
        let Some(without_terminal_slash) = trimmed.strip_suffix(b"/") else {
            return trimmed;
        };
        let candidate = trim_ascii_bytes(without_terminal_slash);
        if is_sysv_name_reference(candidate) {
            candidate
        } else {
            trimmed
        }
    }

    pub fn raw_name_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.raw_name_bytes())
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
    /// GNU `/SYM64/` — the symbol index with 64-bit counts and offsets.
    SysvSymIndex64,
    /// SysV `//` — long-name string table.
    SysvLongNames,
}

/// A single parsed archive member.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    /// Decoded member path. For flattened thin members this names the
    /// external archive; `nested_member_offset` selects the object inside it.
    pub name: PathBuf,
    /// For a member flattened from another archive, the `ar_hdr` offset in
    /// that external archive. Direct external object files use `None`.
    pub nested_member_offset: Option<u64>,
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
    member_by_offset: HashMap<u64, usize>,
    symbol_index: Option<SymbolIndex>,
}

#[derive(Debug)]
pub(crate) struct ArchiveMemberMetadata {
    name: PathBuf,
    nested_member_offset: Option<u64>,
    header_offset: u64,
    body_offset: usize,
    body_len: usize,
    special: SpecialMember,
}

#[derive(Debug)]
pub(crate) struct ArchiveMetadata {
    flavor: Flavor,
    members: Vec<ArchiveMemberMetadata>,
    member_by_offset: HashMap<u64, usize>,
    symbol_index: Option<SymbolIndex>,
}

pub(crate) struct LoadedMember<'a> {
    pub logical_path: PathBuf,
    pub bytes: Cow<'a, [u8]>,
}

#[derive(Debug)]
pub enum MemberLoadError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    NestedArchive {
        path: PathBuf,
        source: ArchiveError,
    },
    MissingNestedMember {
        path: PathBuf,
        member_header_offset: u64,
    },
    NestingTooDeep {
        path: PathBuf,
    },
    CachedMemberOutOfBounds {
        path: PathBuf,
        member_header_offset: u64,
    },
}

impl fmt::Display for MemberLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemberLoadError::Io { path, source } => {
                write!(f, "{}: thin archive member I/O: {source}", path.display())
            }
            MemberLoadError::NestedArchive { path, source } => {
                write!(f, "{}: nested archive is malformed: {source}", path.display())
            }
            MemberLoadError::MissingNestedMember {
                path,
                member_header_offset,
            } => write!(
                f,
                "{}: nested archive has no object member at ar_hdr offset {member_header_offset:#x}",
                path.display()
            ),
            MemberLoadError::NestingTooDeep { path } => write!(
                f,
                "{}: nested thin archive depth exceeds the supported limit",
                path.display()
            ),
            MemberLoadError::CachedMemberOutOfBounds {
                path,
                member_header_offset,
            } => write!(
                f,
                "{}: cached archive member at ar_hdr offset {member_header_offset:#x} is out of bounds",
                path.display()
            ),
        }
    }
}

impl std::error::Error for MemberLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemberLoadError::Io { source, .. } => Some(source),
            MemberLoadError::NestedArchive { source, .. } => Some(source),
            MemberLoadError::MissingNestedMember { .. }
            | MemberLoadError::NestingTooDeep { .. }
            | MemberLoadError::CachedMemberOutOfBounds { .. } => None,
        }
    }
}

const MAX_THIN_ARCHIVE_NESTING: usize = 32;

impl ArchiveMetadata {
    pub(crate) fn parse(path: &Path, data: &[u8]) -> Result<Self, ArchiveError> {
        Ok(Archive::open(path, data)?.into_metadata())
    }

    pub(crate) fn symbol_index(&self) -> Option<&SymbolIndex> {
        self.symbol_index.as_ref()
    }

    pub(crate) fn member_at_offset(&self, header_offset: u64) -> Option<&ArchiveMemberMetadata> {
        let index = *self.member_by_offset.get(&header_offset)?;
        self.members.get(index)
    }

    pub(crate) fn object_member_offsets(&self) -> impl Iterator<Item = u64> + '_ {
        self.members
            .iter()
            .filter(|member| member.special == SpecialMember::None)
            .map(|member| member.header_offset)
    }

    pub(crate) fn load_member<'a>(
        &self,
        archive_path: &Path,
        archive_data: &'a [u8],
        member: &ArchiveMemberMetadata,
    ) -> Result<LoadedMember<'a>, MemberLoadError> {
        if self.flavor == Flavor::GnuThin {
            return load_thin_member(archive_path, &member.name, member.nested_member_offset, 0);
        }

        let end = member
            .body_offset
            .checked_add(member.body_len)
            .ok_or_else(|| MemberLoadError::CachedMemberOutOfBounds {
                path: archive_path.to_path_buf(),
                member_header_offset: member.header_offset,
            })?;
        let body = archive_data.get(member.body_offset..end).ok_or_else(|| {
            MemberLoadError::CachedMemberOutOfBounds {
                path: archive_path.to_path_buf(),
                member_header_offset: member.header_offset,
            }
        })?;
        Ok(LoadedMember {
            logical_path: inline_member_logical_path(archive_path, &member.name),
            bytes: Cow::Borrowed(body),
        })
    }
}

impl<'a> Archive<'a> {
    /// Open an archive given its raw bytes and the source path (for
    /// diagnostics and GNU-thin external-file resolution).
    pub fn open(path: impl Into<PathBuf>, data: &'a [u8]) -> Result<Self, ArchiveError> {
        #[cfg(test)]
        record_archive_parse();

        let flavor = detect_flavor(data)?;
        let (members, flavor) = parse_members(data, flavor)?;
        let symbol_index = build_symbol_index(&members)?;
        let member_by_offset = members
            .iter()
            .enumerate()
            .map(|(index, member)| (member.header_offset as u64, index))
            .collect();
        Ok(Archive {
            path: path.into(),
            flavor,
            data,
            members,
            member_by_offset,
            symbol_index,
        })
    }

    pub(crate) fn into_metadata(self) -> ArchiveMetadata {
        let members = self
            .members
            .into_iter()
            .map(|member| ArchiveMemberMetadata {
                name: member.name,
                nested_member_offset: member.nested_member_offset,
                header_offset: member.header_offset as u64,
                body_offset: member.body_offset,
                body_len: member.body.len(),
                special: member.special,
            })
            .collect();
        ArchiveMetadata {
            flavor: self.flavor,
            members,
            member_by_offset: self.member_by_offset,
            symbol_index: self.symbol_index,
        }
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
        self.members
            .iter()
            .filter(|m| m.special == SpecialMember::None)
    }

    /// Load one ordinary member's bytes without imposing an object format.
    /// Regular archives borrow from the archive image; thin archives read
    /// the external member on demand.
    pub fn member_bytes<'m>(
        &'m self,
        member: &'m Member<'a>,
    ) -> Result<Cow<'m, [u8]>, MemberLoadError> {
        self.load_member(member).map(|loaded| loaded.bytes)
    }

    /// Find the first member whose `ar_hdr` begins at `header_offset`. The
    /// symbol-index's `member_header_offset` fields feed into this lookup.
    pub fn member_at_offset(&self, header_offset: u64) -> Option<&Member<'a>> {
        let index = *self.member_by_offset.get(&header_offset)?;
        self.members.get(index)
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
        let loaded = self.load_member(member).map_err(FetchError::Load)?;
        let path = loaded.logical_path;
        ObjectFile::parse(&path, loaded.bytes.as_ref())
            .map_err(|source| FetchError::MachOParse { path, source })
    }

    /// Resolve `name` to its defining member, then parse that member as an
    /// `ObjectFile`. Returns `None` when the symbol is absent; `Some(Err(_))`
    /// when the member exists but fails to parse.
    pub fn fetch_object_defining(&self, name: &str) -> Option<Result<ObjectFile, FetchError>> {
        let member = self.first_member_defining(name)?;
        Some(self.parse_member_object(member))
    }

    pub(crate) fn load_member<'m>(
        &'m self,
        member: &'m Member<'a>,
    ) -> Result<LoadedMember<'m>, MemberLoadError> {
        self.load_member_at_depth(member, 0)
    }

    fn load_member_at_depth<'m>(
        &'m self,
        member: &'m Member<'a>,
        depth: usize,
    ) -> Result<LoadedMember<'m>, MemberLoadError> {
        if self.flavor != Flavor::GnuThin {
            return Ok(LoadedMember {
                logical_path: inline_member_logical_path(&self.path, &member.name),
                bytes: Cow::Borrowed(member.body),
            });
        }
        load_thin_member(&self.path, &member.name, member.nested_member_offset, depth)
    }
}

fn inline_member_logical_path(archive_path: &Path, member_name: &Path) -> PathBuf {
    let mut path = archive_path.as_os_str().to_owned();
    path.push("(");
    path.push(member_name.as_os_str());
    path.push(")");
    PathBuf::from(path)
}

fn load_thin_member<'a>(
    archive_path: &Path,
    member_name: &Path,
    nested_member_offset: Option<u64>,
    depth: usize,
) -> Result<LoadedMember<'a>, MemberLoadError> {
    let base = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let external_path = base.join(member_name);
    let bytes = std::fs::read(&external_path).map_err(|source| MemberLoadError::Io {
        path: external_path.clone(),
        source,
    })?;
    let Some(member_header_offset) = nested_member_offset else {
        return Ok(LoadedMember {
            logical_path: external_path,
            bytes: Cow::Owned(bytes),
        });
    };

    if depth >= MAX_THIN_ARCHIVE_NESTING {
        return Err(MemberLoadError::NestingTooDeep {
            path: external_path,
        });
    }
    let nested =
        Archive::open(&external_path, &bytes).map_err(|source| MemberLoadError::NestedArchive {
            path: external_path.clone(),
            source,
        })?;
    let nested_member = nested
        .member_at_offset(member_header_offset)
        .filter(|member| member.special == SpecialMember::None)
        .ok_or_else(|| MemberLoadError::MissingNestedMember {
            path: external_path.clone(),
            member_header_offset,
        })?;
    let loaded = nested.load_member_at_depth(nested_member, depth + 1)?;
    Ok(LoadedMember {
        logical_path: loaded.logical_path,
        bytes: Cow::Owned(loaded.bytes.into_owned()),
    })
}

/// Unified error for member fetching — I/O (GNU-thin only) or Mach-O parse.
#[derive(Debug)]
pub enum FetchError {
    Load(MemberLoadError),
    MachOParse { path: PathBuf, source: ReadError },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Load(e) => write!(f, "{e}"),
            FetchError::MachOParse { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FetchError::Load(error) => Some(error),
            FetchError::MachOParse { source, .. } => Some(source),
        }
    }
}

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
        let raw_name = hdr.raw_name_bytes();
        let size = hdr.size as usize;
        let stored_size = if flavor == Flavor::GnuThin && !thin_member_has_body(raw_name) {
            0
        } else {
            size
        };
        let body_start = cursor + AR_HDR_SIZE;
        let body_end = body_start
            .checked_add(stored_size)
            .ok_or(ArchiveError::MemberOverrun {
                at_offset: cursor,
                size: hdr.size,
            })?;
        if body_end > data.len() {
            return Err(ArchiveError::MemberOverrun {
                at_offset: cursor,
                size: hdr.size,
            });
        }
        let DecodedMember {
            name,
            nested_member_offset,
            body_offset,
            body,
            special,
        } = decode_member(
            raw_name,
            data,
            body_start,
            stored_size,
            flavor,
            long_names,
            cursor,
        )?;

        // Opportunistic flavor refinement. The sole unambiguous signal for
        // Sysv is the presence of `/` or `//` members — BSD never emits
        // either.
        if flavor == Flavor::Bsd
            && matches!(
                special,
                SpecialMember::SysvSymIndex
                    | SpecialMember::SysvSymIndex64
                    | SpecialMember::SysvLongNames
            )
        {
            flavor = Flavor::Sysv;
        }
        if matches!(special, SpecialMember::SysvLongNames) {
            long_names = Some(body);
        }

        out.push(Member {
            name,
            nested_member_offset,
            header_offset: cursor,
            body_offset,
            body,
            special,
        });

        // Thin structural members keep inline bodies; ordinary thin members
        // advertise the external file size but store no bytes here.
        let advance = AR_HDR_SIZE + stored_size + (stored_size & 1);
        cursor = cursor
            .checked_add(advance)
            .ok_or(ArchiveError::MemberOverrun {
                at_offset: cursor,
                size: hdr.size,
            })?;
    }

    Ok((out, flavor))
}

fn thin_member_has_body(raw_name: &[u8]) -> bool {
    matches!(raw_name, b"/" | b"/SYM64/" | b"//")
}

struct DecodedMember<'a> {
    name: PathBuf,
    nested_member_offset: Option<u64>,
    body_offset: usize,
    body: &'a [u8],
    special: SpecialMember,
}

#[allow(clippy::too_many_arguments)]
fn decode_member<'a>(
    raw_name: &[u8],
    data: &'a [u8],
    body_start: usize,
    size: usize,
    flavor: Flavor,
    long_names: Option<&'a [u8]>,
    header_offset: usize,
) -> Result<DecodedMember<'a>, ArchiveError> {
    // BSD extended: "#1/<N>" — first N bytes of the body are the real name.
    if let Some(rest) = raw_name.strip_prefix(b"#1/") {
        let nlen = parse_ascii_usize(rest).map_err(|_| ArchiveError::BadAsciiField {
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
        // Trim trailing nulls (some writers pad the name to 4/8 bytes).
        let name_end = name_bytes
            .iter()
            .rposition(|&byte| byte != 0)
            .map(|index| index + 1)
            .unwrap_or(0);
        let name_bytes = &name_bytes[..name_end];
        let name = archive_name_path(name_bytes, header_offset)?;
        let body = &data[body_start + nlen..body_start + size];
        let special = if name_bytes == b"__.SYMDEF" || name_bytes == b"__.SYMDEF SORTED" {
            SpecialMember::BsdSymIndex
        } else {
            SpecialMember::None
        };
        return Ok(DecodedMember {
            name,
            nested_member_offset: None,
            body_offset: body_start + nlen,
            body,
            special,
        });
    }

    // SysV structural members.
    if raw_name == b"/" {
        return Ok(DecodedMember {
            name: PathBuf::from("/"),
            nested_member_offset: None,
            body_offset: body_start,
            body: &data[body_start..body_start + size],
            special: SpecialMember::SysvSymIndex,
        });
    }
    if raw_name == b"/SYM64/" {
        return Ok(DecodedMember {
            name: PathBuf::from("/SYM64/"),
            nested_member_offset: None,
            body_offset: body_start,
            body: &data[body_start..body_start + size],
            special: SpecialMember::SysvSymIndex64,
        });
    }
    if raw_name == b"//" {
        return Ok(DecodedMember {
            name: PathBuf::from("//"),
            nested_member_offset: None,
            body_offset: body_start,
            body: &data[body_start..body_start + size],
            special: SpecialMember::SysvLongNames,
        });
    }

    // SysV long-name reference: "/NNN".
    if let Some(rest) = raw_name.strip_prefix(b"/") {
        let (strx_bytes, nested_offset_bytes) = match rest.iter().position(|&byte| byte == b':') {
            Some(colon) if flavor == Flavor::GnuThin => (&rest[..colon], Some(&rest[colon + 1..])),
            _ => (rest, None),
        };
        if !strx_bytes.is_empty() && strx_bytes.iter().all(u8::is_ascii_digit) {
            let strx = parse_ascii_u64(strx_bytes).map_err(|_| ArchiveError::BadAsciiField {
                at_offset: header_offset,
                field: "/NNN",
            })?;
            let table = long_names.ok_or(ArchiveError::LongNameOob {
                at_offset: header_offset,
                strx,
            })?;
            let name = decode_long_name(table, strx, header_offset)?;
            let nested_member_offset = nested_offset_bytes
                .map(|bytes| {
                    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                        return Err(ArchiveError::BadAsciiField {
                            at_offset: header_offset,
                            field: "/NNN:MMM",
                        });
                    }
                    parse_ascii_u64(bytes).map_err(|_| ArchiveError::BadAsciiField {
                        at_offset: header_offset,
                        field: "/NNN:MMM",
                    })
                })
                .transpose()?;
            return Ok(DecodedMember {
                name,
                nested_member_offset,
                body_offset: body_start,
                body: &data[body_start..body_start + size],
                special: SpecialMember::None,
            });
        }
    }

    // GNU-thin ordinary members have no inline body. Their names use the
    // same short-name or /NNN encoding as regular GNU archives.
    if flavor == Flavor::GnuThin {
        let name_bytes = raw_name.strip_suffix(b"/").unwrap_or(raw_name);
        let name = archive_name_path(name_bytes, header_offset)?;
        return Ok(DecodedMember {
            name,
            nested_member_offset: None,
            body_offset: body_start,
            body: &data[body_start..body_start],
            special: SpecialMember::None,
        });
    }

    // SysV short name — slash-terminated.
    if let Some(stripped) = raw_name.strip_suffix(b"/") {
        return Ok(DecodedMember {
            name: archive_name_path(stripped, header_offset)?,
            nested_member_offset: None,
            body_offset: body_start,
            body: &data[body_start..body_start + size],
            special: SpecialMember::None,
        });
    }

    // BSD short name (no trailing slash, no #1/ prefix).
    Ok(DecodedMember {
        name: archive_name_path(raw_name, header_offset)?,
        nested_member_offset: None,
        body_offset: body_start,
        body: &data[body_start..body_start + size],
        special: SpecialMember::None,
    })
}

// ---------------------------------------------------------------------------
// Symbol index parsing (BSD __.SYMDEF / SysV `/`).
// ---------------------------------------------------------------------------

/// One defined-symbol row in the archive symbol index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolIndexEntry {
    pub name: String,
    /// Byte offset of the defining member's `ar_hdr` within the archive.
    pub member_header_offset: u64,
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
    pub fn first_defining_offset(&self, name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.member_header_offset)
    }

    /// All `ar_hdr` offsets where `name` appears. Exists for `-all_load` /
    /// `-force_load` semantics and for tests that want to verify duplicates.
    pub fn offsets_for<'n>(&'n self, name: &'n str) -> impl Iterator<Item = u64> + 'n {
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
            SpecialMember::SysvSymIndex64 => {
                return Ok(Some(parse_sysv_symbol_index64(m.body)?));
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
    let ranlib_end = 4usize
        .checked_add(ranlib_bytes)
        .ok_or(ArchiveError::BadSymbolIndex {
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
    let strings_end =
        strings_start
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
            member_header_offset: mh_off as u64,
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
            member_header_offset: mh_off as u64,
        });
        cursor = end + 1;
    }
    Ok(SymbolIndex { entries })
}

/// GNU `/SYM64/` symbol index, big-endian. It matches the SysV `/` layout
/// but widens the symbol count and every member-header offset to 64 bits.
fn parse_sysv_symbol_index64(body: &[u8]) -> Result<SymbolIndex, ArchiveError> {
    if body.len() < 8 {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "GNU 64-bit symbol index shorter than 8-byte header",
        });
    }
    let nsyms =
        usize::try_from(u64::from_be_bytes(body[0..8].try_into().unwrap())).map_err(|_| {
            ArchiveError::BadSymbolIndex {
                reason: "GNU 64-bit symbol count does not fit in memory",
            }
        })?;
    let offsets_end = nsyms
        .checked_mul(8)
        .and_then(|size| 8usize.checked_add(size))
        .ok_or(ArchiveError::BadSymbolIndex {
            reason: "GNU 64-bit symbol-index offsets region overflows",
        })?;
    if offsets_end > body.len() {
        return Err(ArchiveError::BadSymbolIndex {
            reason: "GNU 64-bit symbol-index offsets region overruns member",
        });
    }
    let strings = &body[offsets_end..];

    let mut entries = Vec::with_capacity(nsyms);
    let mut cursor = 0usize;
    for i in 0..nsyms {
        let off = 8 + i * 8;
        let member_header_offset = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        if cursor >= strings.len() {
            return Err(ArchiveError::BadSymbolIndex {
                reason: "GNU 64-bit symbol-index names exhausted before nsyms satisfied",
            });
        }
        let end = strings[cursor..]
            .iter()
            .position(|&byte| byte == 0)
            .map(|length| cursor + length)
            .ok_or(ArchiveError::BadSymbolIndex {
                reason: "GNU 64-bit symbol-index name not null-terminated",
            })?;
        let name = str::from_utf8(&strings[cursor..end])
            .map_err(|_| ArchiveError::BadSymbolIndex {
                reason: "GNU 64-bit symbol-index name not UTF-8",
            })?
            .to_string();
        entries.push(SymbolIndexEntry {
            name,
            member_header_offset,
        });
        cursor = end + 1;
    }
    Ok(SymbolIndex { entries })
}

fn decode_long_name(table: &[u8], strx: u64, at_offset: usize) -> Result<PathBuf, ArchiveError> {
    let start = usize::try_from(strx).map_err(|_| ArchiveError::LongNameOob { at_offset, strx })?;
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
    let trimmed_end = if end > 0 && table[end - 1] == b'/' {
        end - 1
    } else {
        end
    };
    archive_name_path(&table[start..trimmed_end], at_offset)
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

/// Trim trailing spaces and null bytes from a fixed-width archive field.
pub(crate) fn trim_ascii_bytes(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &bytes[..end]
}

/// Parse a right-trimmed ASCII-decimal field into `u64`. Empty (all-space)
/// fields return 0 — this matches what Apple's `ar` writes for `date/uid/gid/mode`
/// on anonymized archives.
pub(crate) fn ascii_decimal(bytes: &[u8]) -> Result<u64, ()> {
    let s = str::from_utf8(trim_ascii_bytes(bytes)).map_err(|_| ())?;
    if s.is_empty() {
        return Ok(0);
    }
    s.parse::<u64>().map_err(|_| ())
}

fn parse_ascii_u64(bytes: &[u8]) -> Result<u64, ()> {
    str::from_utf8(bytes)
        .map_err(|_| ())?
        .parse::<u64>()
        .map_err(|_| ())
}

fn parse_ascii_usize(bytes: &[u8]) -> Result<usize, ()> {
    usize::try_from(parse_ascii_u64(bytes)?).map_err(|_| ())
}

fn is_sysv_name_reference(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return false;
    };
    let mut parts = rest.split(|&byte| byte == b':');
    let Some(strx) = parts.next() else {
        return false;
    };
    if strx.is_empty() || !strx.iter().all(u8::is_ascii_digit) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, _) => true,
        (Some(offset), None) => !offset.is_empty() && offset.iter().all(u8::is_ascii_digit),
        (Some(_), Some(_)) => false,
    }
}

#[cfg(unix)]
fn archive_name_path(bytes: &[u8], _at_offset: usize) -> Result<PathBuf, ArchiveError> {
    use std::os::unix::ffi::OsStringExt;

    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn archive_name_path(bytes: &[u8], at_offset: usize) -> Result<PathBuf, ArchiveError> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|_| ArchiveError::BadName { at_offset })
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
        name_field[..name_bytes.len().min(16)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(16)]);
        buf.extend_from_slice(&name_field);
        buf.extend_from_slice(&[b' '; 12]); // date
        buf.extend_from_slice(&[b' '; 6]); // uid
        buf.extend_from_slice(&[b' '; 6]); // gid
        buf.extend_from_slice(&[b' '; 8]); // mode
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
        assert_eq!(parsed.raw_name_str().unwrap(), "foo.o/");
    }

    #[test]
    fn ar_header_normalizes_padded_sysv_name_reference() {
        let mut hdr = make_ar_hdr("/0", 128);
        hdr[15] = b'/';
        let parsed = ArHeader::parse(&hdr, 0).unwrap();
        assert_eq!(parsed.raw_name_bytes(), b"/0");
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
            ArchiveError::Truncated {
                need: AR_HDR_SIZE,
                ..
            }
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
        assert_eq!(ar.members()[0].name, Path::new("foo.o"));
        assert_eq!(ar.members()[0].body, b"XXXX");
        assert_eq!(ar.members()[0].special, SpecialMember::None);
    }

    #[test]
    fn bsd_extended_name_splits_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC);
        buf.extend_from_slice(&encode_bsd_extended(
            "long_filename_with_many_chars.o",
            b"CONT",
        ));
        let ar = Archive::open("/tmp/bsd_ext.a", &buf).unwrap();
        assert_eq!(
            ar.members()[0].name,
            Path::new("long_filename_with_many_chars.o")
        );
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
        assert_eq!(ar.members()[0].name, Path::new("foo.o"));
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
        assert_eq!(ar.members()[1].name, Path::new("really_long_name.o"));
        assert_eq!(ar.members()[1].body, b"BODY1");
        assert_eq!(ar.members()[2].name, Path::new("foo"));
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
        assert_eq!(ar.members()[0].name, Path::new("a.o"));
        assert_eq!(ar.members()[1].name, Path::new("b.o"));
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
        assert_eq!(reals, vec![PathBuf::from("real.o")]);
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
        assert_eq!(ar.members()[0].name, Path::new("../foo.o"));
        assert_eq!(ar.members()[1].name, Path::new("bar.o"));
    }

    #[test]
    fn gnu_thin_decodes_structural_members_and_long_paths() {
        let first_name = "objects/very_long_thin_member_name.o";
        let second_name = "objects/second_thin_member_name.o";
        let long_names = format!("{first_name}/\n{second_name}/\n");
        let placeholder_index =
            encode_member("/", &encode_sysv_symbol_index(&[("_thin_symbol", 0)]));
        let long_name_member = encode_member("//", long_names.as_bytes());
        let object_offset =
            (AR_MAGIC_THIN.len() + placeholder_index.len() + long_name_member.len()) as u32;
        let second_object_offset = object_offset + AR_HDR_SIZE as u32;
        let symbol_index = encode_member(
            "/",
            &encode_sysv_symbol_index(&[("_thin_symbol", object_offset)]),
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC_THIN);
        buf.extend_from_slice(&symbol_index);
        buf.extend_from_slice(&long_name_member);
        buf.extend_from_slice(&make_ar_hdr("/0", 4097));
        buf.extend_from_slice(&make_ar_hdr(
            &format!("/{}:8192", first_name.len() + 2),
            2048,
        ));

        let ar = Archive::open("/tmp/libthin.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::GnuThin);
        assert_eq!(ar.members().len(), 4);
        assert_eq!(ar.members()[0].special, SpecialMember::SysvSymIndex);
        assert_eq!(ar.members()[1].special, SpecialMember::SysvLongNames);
        assert_eq!(ar.members()[2].name, Path::new(first_name));
        assert!(ar.members()[2].body.is_empty());
        assert_eq!(ar.members()[2].nested_member_offset, None);
        assert_eq!(ar.members()[2].header_offset as u32, object_offset);
        assert_eq!(ar.members()[3].name, Path::new(second_name));
        assert_eq!(ar.members()[3].nested_member_offset, Some(8192));
        assert_eq!(ar.members()[3].header_offset as u32, second_object_offset);
        assert_eq!(
            ar.first_member_defining("_thin_symbol")
                .map(|member| member.header_offset as u32),
            Some(object_offset)
        );
    }

    #[cfg(unix)]
    #[test]
    fn gnu_thin_preserves_non_utf8_long_name_bytes() {
        use std::os::unix::ffi::OsStrExt;

        let long_name = b"member-\xff.o/\n";
        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC_THIN);
        buf.extend_from_slice(&encode_member("//", long_name));
        buf.extend_from_slice(&make_ar_hdr("/0", 1));

        let archive = Archive::open("/tmp/non-utf8-thin.a", &buf).unwrap();
        let member = archive.object_members().next().unwrap();
        assert_eq!(member.name.as_os_str().as_bytes(), b"member-\xff.o");
    }

    #[test]
    fn gnu_thin_decodes_sym64_index() {
        const WIDE_OFFSET: u64 = u32::MAX as u64 + 0x100;
        let placeholder = encode_member(
            "/SYM64/",
            &encode_sysv_symbol_index64(&[("_wide_symbol", 0), ("_beyond_u32", WIDE_OFFSET)]),
        );
        let object_offset = (AR_MAGIC_THIN.len() + placeholder.len()) as u32;
        let index = encode_member(
            "/SYM64/",
            &encode_sysv_symbol_index64(&[
                ("_wide_symbol", object_offset as u64),
                ("_beyond_u32", WIDE_OFFSET),
            ]),
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(AR_MAGIC_THIN);
        buf.extend_from_slice(&index);
        buf.extend_from_slice(&make_ar_hdr("member.o/", 4097));

        let ar = Archive::open("/tmp/libthin64.a", &buf).unwrap();
        assert_eq!(ar.flavor, Flavor::GnuThin);
        assert_eq!(ar.members().len(), 2);
        assert_eq!(ar.members()[0].special, SpecialMember::SysvSymIndex64);
        assert_eq!(ar.members()[1].name, Path::new("member.o"));
        assert_eq!(
            ar.first_member_defining("_wide_symbol")
                .map(|member| member.header_offset as u32),
            Some(object_offset)
        );
        assert_eq!(
            ar.symbol_index()
                .unwrap()
                .first_defining_offset("_beyond_u32"),
            Some(WIDE_OFFSET)
        );
        assert!(ar.member_at_offset(WIDE_OFFSET).is_none());
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

    fn encode_sysv_symbol_index64(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (_, member_offset) in entries {
            body.extend_from_slice(&member_offset.to_be_bytes());
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
        let all: Vec<u64> = idx.offsets_for("_sym").collect();
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
        assert_eq!(m.name, Path::new("real.o"));
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
        assert!(matches!(result, Err(FetchError::MachOParse { .. })));
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
