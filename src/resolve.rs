//! Linker-side symbol table and name resolution.
//!
//! Sprint 7 lays the substrate:
//!
//! * `StringInterner` — the source of all symbol-name identity.
//! * Opaque ID newtypes (`InputId`, `AtomId`, `DylibId`, `ArchiveId`,
//!   `MemberId`, `SymbolId`) that later sprints populate with real
//!   registries.
//! * `Symbol` sum type with seven variants — every state a name can be in
//!   during resolution.
//! * `SymbolTable` with the full insertion matrix and a transition log.
//!
//! Sprint 8 builds the fixed-point `resolve()` pass on top. This module's
//! API is deliberately thin: callers hand it symbols, it tells them what
//! happened (inserted / replaced / kept / pending archive fetch), and they
//! drive the outer loop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use crate::archive::{Archive, ArchiveError};
use crate::input::ObjectFile;
use crate::macho::dylib::DylibFile;
use crate::macho::reader::ReadError;

// ---------------------------------------------------------------------------
// Interned strings.
// ---------------------------------------------------------------------------

/// Opaque handle into a `StringInterner`. Cheap to copy; all comparisons
/// between names go through handle equality, not string compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Istr(u32);

impl Istr {
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct StringInterner {
    strings: Vec<Rc<str>>,
    index: HashMap<Rc<str>, u32>,
}

impl StringInterner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `s`, returning the existing handle when the string was already
    /// seen. Allocates at most one `Rc<str>` per unique name.
    pub fn intern(&mut self, s: &str) -> Istr {
        if let Some(&i) = self.index.get(s) {
            return Istr(i);
        }
        let rc: Rc<str> = Rc::from(s);
        let id = self.strings.len() as u32;
        self.strings.push(rc.clone());
        self.index.insert(rc, id);
        Istr(id)
    }

    pub fn get(&self, s: &str) -> Option<Istr> {
        self.index.get(s).copied().map(Istr)
    }

    pub fn resolve(&self, i: Istr) -> &str {
        &self.strings[i.0 as usize]
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Opaque IDs — populated by later sprints. Sprint 7 only defines the
// newtypes so `Symbol` can reference them without cyclic-module pain.
// ---------------------------------------------------------------------------

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
        impl $name {
            pub fn as_u32(self) -> u32 {
                self.0
            }
        }
    };
}

opaque_id!(
    /// Handle into the driver's input registry (Sprint 8): one slot per
    /// `.o`, archive member fetched on demand, `.a`, `.dylib`, or `.tbd`.
    InputId
);
opaque_id!(
    /// Handle into the atomization table populated in Sprint 9. Each
    /// `Symbol::Defined` owns exactly one atom.
    AtomId
);
opaque_id!(
    /// Handle into the dylib registry: one slot per loaded `DylibFile`.
    DylibId
);
opaque_id!(
    /// Handle into the archive registry (Sprint 4's `Archive` wrapped
    /// in a per-linker instance): one slot per `.a` on the link line.
    ArchiveId
);
opaque_id!(
    /// Per-archive handle identifying a member by its `ar_hdr` offset.
    MemberId
);
opaque_id!(
    /// Index into `SymbolTable::symbols`. Stable across the whole link.
    SymbolId
);

// ---------------------------------------------------------------------------
// Inputs registry.
//
// Sprint 8 drives resolution against a triple of per-kind Vecs. Handles
// `InputId` / `ArchiveId` / `DylibId` are 1:1 with slot indices here, and
// the opaque newtypes (above) keep them from being confused across
// categories.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ObjectInput {
    pub path: PathBuf,
    pub load_order: usize,
    pub archive_member_offset: Option<u32>,
    /// Raw bytes retained for diagnostics and future low-level readers.
    pub bytes: Vec<u8>,
    /// Parsed object view. It owns section/relocation/string-table buffers,
    /// so it is safe to build off-thread and then borrow during the link.
    pub parsed: ObjectFile,
}

#[derive(Debug)]
pub struct ArchiveInput {
    pub path: PathBuf,
    pub load_order: usize,
    pub bytes: Vec<u8>,
    /// Members we've already fetched (keyed by `ar_hdr` offset). Prevents
    /// the fixed-point loop from re-ingesting the same object twice —
    /// important both for correctness (no duplicate-strong errors from
    /// our own symbols) and for keeping transitions deterministic.
    pub fetched: HashSet<u32>,
}

#[derive(Debug)]
pub struct DylibInput {
    pub path: PathBuf,
    /// Parsed `DylibFile`. `DylibFile` owns its data (no borrow into
    /// `bytes`), so we keep it pre-parsed for O(1) export-trie walks.
    pub file: DylibFile,
    /// Install name surfaced in the output's `LC_LOAD_DYLIB` list.
    ///
    /// Multi-document TBD inputs may seed exports from several sibling
    /// documents while still canonicalizing them back to one umbrella load
    /// command (e.g. `libSystem.tbd`).
    pub load_install_name: String,
    /// Current-version field surfaced in the output `LC_LOAD_DYLIB`.
    pub load_current_version: u32,
    /// Compatibility-version field surfaced in the output `LC_LOAD_DYLIB`.
    pub load_compatibility_version: u32,
    /// 1-based two-level-namespace ordinal encoded into undefined symbols and
    /// bind opcodes. Matches the output's `LC_LOAD_DYLIB` ordering, so several
    /// parsed TBD documents from one umbrella input may legitimately share it.
    pub ordinal: u16,
}

#[derive(Debug, Clone)]
pub struct DylibLoadMeta {
    pub install_name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub ordinal: u16,
}

#[derive(Debug, Default)]
pub struct Inputs {
    pub objects: Vec<ObjectInput>,
    pub archives: Vec<ArchiveInput>,
    pub dylibs: Vec<DylibInput>,
}

#[derive(Debug)]
pub enum InputAddError {
    Read(ReadError),
    Archive(ArchiveError),
}

impl std::fmt::Display for InputAddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputAddError::Read(e) => write!(f, "{e}"),
            InputAddError::Archive(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InputAddError {}

impl From<ReadError> for InputAddError {
    fn from(e: ReadError) -> Self {
        InputAddError::Read(e)
    }
}

impl From<ArchiveError> for InputAddError {
    fn from(e: ArchiveError) -> Self {
        InputAddError::Archive(e)
    }
}

impl Inputs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an `.o` file. Validates the Mach-O header by parsing once,
    /// then keeps only the raw bytes (re-parsing on demand is cheap and
    /// sidesteps borrow-lifetime headaches).
    pub fn add_object(
        &mut self,
        path: PathBuf,
        bytes: Vec<u8>,
        load_order: usize,
    ) -> Result<InputId, InputAddError> {
        // Validate now — we'd rather catch a bad object at the add site.
        let parsed = ObjectFile::parse(&path, &bytes)?;
        Ok(self.add_parsed_object(path, bytes, parsed, load_order))
    }

    pub fn add_parsed_object(
        &mut self,
        path: PathBuf,
        bytes: Vec<u8>,
        parsed: ObjectFile,
        load_order: usize,
    ) -> InputId {
        let id = InputId(self.objects.len() as u32);
        self.objects.push(ObjectInput {
            path,
            load_order,
            archive_member_offset: None,
            bytes,
            parsed,
        });
        id
    }

    /// Register an `.a` file.
    pub fn add_archive(
        &mut self,
        path: PathBuf,
        bytes: Vec<u8>,
        load_order: usize,
    ) -> Result<ArchiveId, InputAddError> {
        Archive::open(&path, &bytes)?; // validate
        Ok(self.add_validated_archive(path, bytes, load_order))
    }

    pub fn add_validated_archive(
        &mut self,
        path: PathBuf,
        bytes: Vec<u8>,
        load_order: usize,
    ) -> ArchiveId {
        let id = ArchiveId(self.archives.len() as u32);
        self.archives.push(ArchiveInput {
            path,
            load_order,
            bytes,
            fetched: std::collections::HashSet::new(),
        });
        id
    }

    /// Register a `.dylib`. TBD-backed dylibs go through
    /// [`Inputs::add_dylib_from_tbd`].
    pub fn add_dylib(&mut self, path: PathBuf, bytes: Vec<u8>) -> Result<DylibId, InputAddError> {
        let file = DylibFile::parse(&path, &bytes)?;
        let ordinal = self.next_dylib_ordinal();
        let id = DylibId(self.dylibs.len() as u32);
        self.dylibs.push(DylibInput {
            path,
            load_install_name: file.install_name.clone(),
            load_current_version: file.current_version,
            load_compatibility_version: file.compatibility_version,
            file,
            ordinal,
        });
        Ok(id)
    }

    /// Register a TBD-backed dylib. The caller materializes the `DylibFile`
    /// via `DylibFile::from_tbd(path, tbd, target)` so the target filter
    /// is explicit.
    pub fn add_dylib_from_file(&mut self, path: PathBuf, file: DylibFile) -> DylibId {
        let ordinal = self.next_dylib_ordinal();
        let load = DylibLoadMeta {
            install_name: file.install_name.clone(),
            current_version: file.current_version,
            compatibility_version: file.compatibility_version,
            ordinal,
        };
        self.add_dylib_from_file_with_meta(path, file, load)
    }

    pub fn add_dylib_from_file_with_meta(
        &mut self,
        path: PathBuf,
        file: DylibFile,
        load: DylibLoadMeta,
    ) -> DylibId {
        let id = DylibId(self.dylibs.len() as u32);
        self.dylibs.push(DylibInput {
            path,
            load_install_name: load.install_name,
            load_current_version: load.current_version,
            load_compatibility_version: load.compatibility_version,
            file,
            ordinal: load.ordinal,
        });
        id
    }

    pub fn next_dylib_ordinal(&self) -> u16 {
        self.dylibs
            .iter()
            .map(|dylib| dylib.ordinal)
            .max()
            .unwrap_or(0)
            + 1
    }

    // ---- accessors ----

    pub fn object(&self, id: InputId) -> &ObjectInput {
        &self.objects[id.0 as usize]
    }

    pub fn archive(&self, id: ArchiveId) -> &ArchiveInput {
        &self.archives[id.0 as usize]
    }

    pub fn archive_mut(&mut self, id: ArchiveId) -> &mut ArchiveInput {
        &mut self.archives[id.0 as usize]
    }

    pub fn dylib(&self, id: DylibId) -> &DylibInput {
        &self.dylibs[id.0 as usize]
    }

    /// Borrow a parsed `ObjectFile` view of a registered object.
    pub fn object_file(&self, id: InputId) -> Result<&ObjectFile, ReadError> {
        let o = &self.objects[id.0 as usize];
        Ok(&o.parsed)
    }

    /// Open an `Archive` view, borrowing from the registry's bytes for the
    /// returned lifetime.
    pub fn archive_view(&self, id: ArchiveId) -> Result<Archive<'_>, ArchiveError> {
        let a = &self.archives[id.0 as usize];
        Archive::open(&a.path, &a.bytes)
    }
}

// ---------------------------------------------------------------------------
// Symbol sum type.
//
// Every state a name can be in during resolution:
//   * Undefined — referenced but not yet satisfied
//   * Defined — an object file provides a concrete body at `atom + value`
//   * Common — tentative definition (`N_UNDF + N_EXT + n_value>0`); picks
//     a winner by size/alignment, then morphs into Defined during atomization
//   * DylibImport — resolved from a dylib's export trie / TBD
//   * LazyArchive — name covered by a not-yet-fetched archive member
//   * LazyObject — name covered by a not-yet-loaded `--start-lib` object
//   * Alias — `N_INDR` pointing at another name; Sprint 8's resolver
//     flattens the chain when the target becomes available
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbol {
    Undefined {
        name: Istr,
        origin: InputId,
        weak_ref: bool,
    },
    Defined {
        name: Istr,
        origin: InputId,
        atom: AtomId,
        value: u64,
        weak: bool,
        private_extern: bool,
        no_dead_strip: bool,
    },
    Common {
        name: Istr,
        origin: InputId,
        size: u64,
        align_pow2: u8,
    },
    DylibImport {
        name: Istr,
        dylib: DylibId,
        ordinal: u16,
        weak_import: bool,
    },
    LazyArchive {
        name: Istr,
        archive: ArchiveId,
        member: MemberId,
    },
    LazyObject {
        name: Istr,
        origin: InputId,
    },
    Alias {
        name: Istr,
        aliased: Istr,
    },
}

impl Symbol {
    pub fn name(&self) -> Istr {
        match self {
            Symbol::Undefined { name, .. }
            | Symbol::Defined { name, .. }
            | Symbol::Common { name, .. }
            | Symbol::DylibImport { name, .. }
            | Symbol::LazyArchive { name, .. }
            | Symbol::LazyObject { name, .. }
            | Symbol::Alias { name, .. } => *name,
        }
    }

    pub fn kind(&self) -> SymbolKindTag {
        match self {
            Symbol::Undefined { .. } => SymbolKindTag::Undefined,
            Symbol::Defined { .. } => SymbolKindTag::Defined,
            Symbol::Common { .. } => SymbolKindTag::Common,
            Symbol::DylibImport { .. } => SymbolKindTag::DylibImport,
            Symbol::LazyArchive { .. } => SymbolKindTag::LazyArchive,
            Symbol::LazyObject { .. } => SymbolKindTag::LazyObject,
            Symbol::Alias { .. } => SymbolKindTag::Alias,
        }
    }

    /// True for `Defined` without the weak flag — ld's "strong" category,
    /// the only one where duplicates are an error.
    pub fn is_strong_defined(&self) -> bool {
        matches!(self, Symbol::Defined { weak: false, .. })
    }

    pub fn is_weak_defined(&self) -> bool {
        matches!(self, Symbol::Defined { weak: true, .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKindTag {
    Undefined,
    Defined,
    Common,
    DylibImport,
    LazyArchive,
    LazyObject,
    Alias,
}

// ---------------------------------------------------------------------------
// SymbolTable.
// ---------------------------------------------------------------------------

/// What `SymbolTable::insert` did with the incoming symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// First time this name appeared; the new symbol is now at `id`.
    Inserted(SymbolId),
    /// A stronger / more-concrete symbol replaced the existing entry.
    Replaced {
        id: SymbolId,
        from: SymbolKindTag,
        to: SymbolKindTag,
    },
    /// Existing entry wins; the new one was dropped on the floor.
    Kept(SymbolId),
    /// Two Common symbols with the same name were coalesced: size grew to
    /// the max and alignment grew to the stricter of the two.
    CommonCoalesced { id: SymbolId },
    /// Inserting an Undefined whose slot currently holds a LazyArchive.
    /// The caller (Sprint 8 resolver) must fetch the named archive member
    /// and re-insert its symbols. The LazyArchive stays in place.
    PendingArchiveFetch {
        id: SymbolId,
        archive: ArchiveId,
        member: MemberId,
    },
    /// Inserting an Undefined whose slot currently holds a LazyObject
    /// (from `--start-lib`). Caller loads the object and re-inserts.
    PendingObjectLoad { id: SymbolId, origin: InputId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertError {
    /// Two distinct strong `Defined` entries collided. Sprint 8 surfaces
    /// this as a user-facing `duplicate symbol` diagnostic.
    DuplicateStrong {
        name: Istr,
        first: SymbolId,
        second: Box<Symbol>,
    },
    /// Alias chain would cycle back to itself or exceed the depth cap.
    AliasCycle { name: Istr },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `lookup` returned `None` for this name.
    Unknown(Istr),
    /// Alias chain cycled or exceeded `MAX_ALIAS_DEPTH`.
    AliasCycle { start: Istr },
}

/// Maximum hops through alias chains before we call it a cycle. Real
/// `N_INDR` chains are almost always a single hop; 32 is generous.
pub const MAX_ALIAS_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub id: SymbolId,
    pub from: SymbolKindTag,
    pub to: SymbolKindTag,
    pub cause: TransitionCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionCause {
    Inserted,
    Replaced,
    CommonCoalesced,
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    pub interner: StringInterner,
    symbols: Vec<Symbol>,
    by_name: HashMap<Istr, SymbolId>,
    transitions: Vec<Transition>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, name: &str) -> Istr {
        self.interner.intern(name)
    }

    pub fn lookup(&self, name: Istr) -> Option<SymbolId> {
        self.by_name.get(&name).copied()
    }

    pub fn lookup_str(&self, name: &str) -> Option<SymbolId> {
        self.interner.get(name).and_then(|name| self.lookup(name))
    }

    pub fn get(&self, id: SymbolId) -> &Symbol {
        &self.symbols[id.0 as usize]
    }

    pub fn iter(&self) -> impl Iterator<Item = (SymbolId, &Symbol)> {
        self.symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (SymbolId(i as u32), s))
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn transitions(&self) -> &[Transition] {
        &self.transitions
    }

    /// Back-patch a `Symbol::Defined`'s `atom` and `value` fields. The
    /// atomization pass (Sprint 9) uses this to replace the `AtomId(0)`
    /// placeholder seeded at resolution time with the real atom handle
    /// and the symbol's atom-relative offset. No-op for non-Defined
    /// entries; silently ignored so an Alias or DylibImport that shadows
    /// a previously-Defined slot doesn't panic.
    pub fn bind_atom(&mut self, id: SymbolId, atom: AtomId, value: u64) {
        if let Symbol::Defined {
            atom: a, value: v, ..
        } = &mut self.symbols[id.0 as usize]
        {
            *a = atom;
            *v = value;
        }
    }

    /// Insert a symbol, running the resolution matrix. See Sprint 7's
    /// `.docs/sprints/sprint07.md` for the full matrix.
    pub fn insert(&mut self, sym: Symbol) -> Result<InsertOutcome, InsertError> {
        let name = sym.name();

        // Vacant slot: just store it.
        let Some(&existing_id) = self.by_name.get(&name) else {
            let id = self.push_new(sym.clone());
            self.transitions.push(Transition {
                id,
                from: sym.kind(),
                to: sym.kind(),
                cause: TransitionCause::Inserted,
            });
            return Ok(InsertOutcome::Inserted(id));
        };

        let existing_kind = self.symbols[existing_id.0 as usize].kind();
        let new_kind = sym.kind();

        // Alias insertions have their own rules (cycle detection).
        if new_kind == SymbolKindTag::Alias {
            return self.insert_alias_over(existing_id, sym);
        }

        // Resolve the existing × new pair via the matrix.
        use SymbolKindTag::*;
        let action = match (existing_kind, new_kind) {
            // --- existing Undefined ---
            (Undefined, Undefined) => Action::Keep,
            (Undefined, Defined | Common | DylibImport | LazyArchive | LazyObject) => {
                Action::Replace
            }

            // --- existing Defined (strong vs weak resolved inline) ---
            (Defined, Undefined)
            | (Defined, Common)
            | (Defined, DylibImport)
            | (Defined, LazyArchive)
            | (Defined, LazyObject) => Action::Keep,
            (Defined, Defined) => self.defined_vs_defined(existing_id, &sym)?,

            // --- existing Common ---
            (Common, Undefined) => Action::Keep,
            (Common, Defined) => Action::Replace,
            (Common, Common) => Action::CoalesceCommon,
            (Common, DylibImport) | (Common, LazyArchive) | (Common, LazyObject) => Action::Keep,

            // --- existing DylibImport ---
            (DylibImport, Undefined) => Action::Keep,
            (DylibImport, Defined) => Action::Replace,
            (DylibImport, Common)
            | (DylibImport, DylibImport)
            | (DylibImport, LazyArchive)
            | (DylibImport, LazyObject) => Action::Keep,

            // --- existing LazyArchive ---
            (LazyArchive, Undefined) => Action::PendingArchiveFetch,
            (LazyArchive, Defined)
            | (LazyArchive, Common)
            | (LazyArchive, DylibImport)
            | (LazyArchive, LazyObject) => Action::Replace,
            (LazyArchive, LazyArchive) => Action::Keep,

            // --- existing LazyObject ---
            (LazyObject, Undefined) => Action::PendingObjectLoad,
            (LazyObject, Defined)
            | (LazyObject, Common)
            | (LazyObject, DylibImport)
            | (LazyObject, LazyArchive) => Action::Replace,
            (LazyObject, LazyObject) => Action::Keep,

            // --- existing Alias: a direct form replaces it ---
            (Alias, _) => Action::Replace,

            // Shouldn't hit — Alias insertions diverged above.
            (_, Alias) => unreachable!(),
        };

        Ok(self.apply_action(existing_id, sym, existing_kind, new_kind, action))
    }

    fn defined_vs_defined(
        &self,
        existing_id: SymbolId,
        new: &Symbol,
    ) -> Result<Action, InsertError> {
        let existing = &self.symbols[existing_id.0 as usize];
        match (existing.is_strong_defined(), new.is_strong_defined()) {
            (true, true) => Err(InsertError::DuplicateStrong {
                name: new.name(),
                first: existing_id,
                second: Box::new(new.clone()),
            }),
            (false, true) => Ok(Action::Replace), // strong over weak
            (true, false) => Ok(Action::Keep),    // strong keeps its seat
            (false, false) => Ok(Action::Keep),   // first weak wins
        }
    }

    fn apply_action(
        &mut self,
        id: SymbolId,
        sym: Symbol,
        from: SymbolKindTag,
        to: SymbolKindTag,
        action: Action,
    ) -> InsertOutcome {
        match action {
            Action::Keep => InsertOutcome::Kept(id),
            Action::Replace => {
                self.symbols[id.0 as usize] = sym;
                self.transitions.push(Transition {
                    id,
                    from,
                    to,
                    cause: TransitionCause::Replaced,
                });
                InsertOutcome::Replaced { id, from, to }
            }
            Action::CoalesceCommon => {
                self.coalesce_common(id, sym);
                self.transitions.push(Transition {
                    id,
                    from,
                    to,
                    cause: TransitionCause::CommonCoalesced,
                });
                InsertOutcome::CommonCoalesced { id }
            }
            Action::PendingArchiveFetch => {
                let Symbol::LazyArchive {
                    archive, member, ..
                } = self.symbols[id.0 as usize]
                else {
                    unreachable!("PendingArchiveFetch requires LazyArchive in slot")
                };
                InsertOutcome::PendingArchiveFetch {
                    id,
                    archive,
                    member,
                }
            }
            Action::PendingObjectLoad => {
                let Symbol::LazyObject { origin, .. } = self.symbols[id.0 as usize] else {
                    unreachable!("PendingObjectLoad requires LazyObject in slot")
                };
                InsertOutcome::PendingObjectLoad { id, origin }
            }
        }
    }

    fn coalesce_common(&mut self, id: SymbolId, incoming: Symbol) {
        let slot = &mut self.symbols[id.0 as usize];
        let (
            Symbol::Common {
                size: a_size,
                align_pow2: a_align,
                ..
            },
            Symbol::Common {
                size: b_size,
                align_pow2: b_align,
                ..
            },
        ) = (slot.clone(), incoming)
        else {
            unreachable!("coalesce_common requires two Common entries");
        };
        if let Symbol::Common {
            size, align_pow2, ..
        } = slot
        {
            *size = a_size.max(b_size);
            *align_pow2 = a_align.max(b_align);
        }
    }

    fn push_new(&mut self, sym: Symbol) -> SymbolId {
        let id = SymbolId(self.symbols.len() as u32);
        let name = sym.name();
        self.symbols.push(sym);
        self.by_name.insert(name, id);
        id
    }

    fn insert_alias_over(
        &mut self,
        existing_id: SymbolId,
        sym: Symbol,
    ) -> Result<InsertOutcome, InsertError> {
        let Symbol::Alias { name, aliased } = &sym else {
            unreachable!("insert_alias_over called with non-Alias symbol");
        };
        if self.alias_would_cycle(*name, *aliased) {
            return Err(InsertError::AliasCycle { name: *name });
        }
        let from = self.symbols[existing_id.0 as usize].kind();
        self.symbols[existing_id.0 as usize] = sym;
        self.transitions.push(Transition {
            id: existing_id,
            from,
            to: SymbolKindTag::Alias,
            cause: TransitionCause::Replaced,
        });
        Ok(InsertOutcome::Replaced {
            id: existing_id,
            from,
            to: SymbolKindTag::Alias,
        })
    }

    /// Walk alias chains to a concrete (non-Alias) symbol. Used by Sprint 8
    /// during name resolution and by `-why_live` to trace where a symbol
    /// ultimately points. Returns `AliasCycle` if the chain loops or
    /// exceeds `MAX_ALIAS_DEPTH`.
    pub fn resolve_chain(&self, name: Istr) -> Result<(SymbolId, &Symbol), ResolveError> {
        let mut current = name;
        for _ in 0..MAX_ALIAS_DEPTH {
            let Some(id) = self.by_name.get(&current).copied() else {
                return Err(ResolveError::Unknown(name));
            };
            let sym = &self.symbols[id.0 as usize];
            match sym {
                Symbol::Alias { aliased, .. } => current = *aliased,
                _ => return Ok((id, sym)),
            }
        }
        Err(ResolveError::AliasCycle { start: name })
    }

    /// Check whether adding an alias `new_name → target` would create a
    /// cycle. Returns true if walking the existing chain from `target`
    /// reaches `new_name` within `MAX_ALIAS_DEPTH` steps.
    fn alias_would_cycle(&self, new_name: Istr, target: Istr) -> bool {
        // A self-loop (`_foo → _foo`) is the shortest cycle.
        if new_name == target {
            return true;
        }
        let mut current = target;
        for _ in 0..MAX_ALIAS_DEPTH {
            if current == new_name {
                return true;
            }
            let Some(id) = self.by_name.get(&current).copied() else {
                return false;
            };
            match &self.symbols[id.0 as usize] {
                Symbol::Alias { aliased, .. } => current = *aliased,
                _ => return false,
            }
        }
        // Exceeded the depth cap — treat as a cycle.
        true
    }
}

/// Internal matrix verdict — what `insert()` decided to do before actually
/// performing the operation.
enum Action {
    Keep,
    Replace,
    CoalesceCommon,
    PendingArchiveFetch,
    PendingObjectLoad,
}

// ---------------------------------------------------------------------------
// Seeding: turn `Inputs` into `SymbolTable` entries.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SeedReport {
    /// Fetches queued by (LazyArchive, Undefined) insertions. Sprint 8's
    /// fixed-point loop drains this.
    pub pending_fetches: Vec<PendingFetch>,
    /// Duplicate-strong-defined errors encountered during seeding.
    /// Collected rather than short-circuited so the user sees all of them
    /// in one pass.
    pub duplicates: Vec<InsertError>,
    /// `(name, origin)` for every reference to an external name seen in
    /// an object file. Drives the "referenced by" lines in undefined-
    /// symbol diagnostics. Multi-input references accumulate.
    pub referrers: ReferrerLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingFetch {
    pub id: SymbolId,
    pub archive: ArchiveId,
    pub member: MemberId,
}

/// Tracks which inputs reference each external name. A single name can
/// appear as a Defined, Undefined, or Common in multiple inputs; we keep
/// one entry per (name, origin) pair in insertion order.
#[derive(Debug, Default, Clone)]
pub struct ReferrerLog {
    entries: HashMap<Istr, Vec<InputId>>,
}

impl ReferrerLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: Istr, origin: InputId) {
        let list = self.entries.entry(name).or_default();
        if !list.contains(&origin) {
            list.push(origin);
        }
    }

    pub fn get(&self, name: Istr) -> &[InputId] {
        self.entries.get(&name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn extend_from(&mut self, other: &ReferrerLog) {
        for (&name, origins) in &other.entries {
            for &origin in origins {
                self.add(name, origin);
            }
        }
    }
}

impl SeedReport {
    fn record_outcome(&mut self, outcome: InsertOutcome) {
        if let InsertOutcome::PendingArchiveFetch {
            id,
            archive,
            member,
        } = outcome
        {
            self.pending_fetches.push(PendingFetch {
                id,
                archive,
                member,
            });
        }
    }

    fn record_error(&mut self, err: InsertError) {
        self.duplicates.push(err);
    }

    pub fn has_errors(&self) -> bool {
        !self.duplicates.is_empty()
    }
}

#[derive(Debug)]
pub enum SeedError {
    Read(ReadError),
    Archive(ArchiveError),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::Read(e) => write!(f, "{e}"),
            SeedError::Archive(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SeedError {}

impl From<ReadError> for SeedError {
    fn from(e: ReadError) -> Self {
        SeedError::Read(e)
    }
}

impl From<ArchiveError> for SeedError {
    fn from(e: ArchiveError) -> Self {
        SeedError::Archive(e)
    }
}

/// Seed LazyArchive entries for every symbol defined in every archive's
/// symbol index. Do this before object seeding so undefined references
/// in objects correctly trigger `PendingArchiveFetch`.
pub fn seed_archives(
    inputs: &Inputs,
    table: &mut SymbolTable,
    report: &mut SeedReport,
) -> Result<(), SeedError> {
    for (ai_idx, ai) in inputs.archives.iter().enumerate() {
        let archive = Archive::open(&ai.path, &ai.bytes)?;
        let archive_id = ArchiveId(ai_idx as u32);
        let Some(idx) = archive.symbol_index() else {
            // Archives without a symbol index are legal (clang produces
            // them occasionally). They require -all_load to pull anything.
            continue;
        };
        for entry in &idx.entries {
            let name = table.intern(&entry.name);
            let sym = Symbol::LazyArchive {
                name,
                archive: archive_id,
                member: MemberId(entry.member_header_offset),
            };
            match table.insert(sym) {
                Ok(outcome) => report.record_outcome(outcome),
                Err(e) => report.record_error(e),
            }
        }
    }
    Ok(())
}

/// Seed one object's externals into the table. Private-extern symbols
/// (`N_PEXT`) participate in resolution but stay hidden from dylib
/// exports. Local symbols, stabs, and debug entries are skipped.
pub fn seed_object(
    inputs: &Inputs,
    input_id: InputId,
    table: &mut SymbolTable,
    report: &mut SeedReport,
) -> Result<(), SeedError> {
    let obj = inputs.object_file(input_id)?;
    for input_sym in &obj.symbols {
        if input_sym.stab_kind().is_some() {
            continue;
        }
        // Only externals and private-externals participate.
        if !input_sym.is_ext() && !input_sym.is_private_ext() {
            continue;
        }
        let Ok(name_str) = obj.symbol_name(input_sym) else {
            continue;
        };
        let name = table.intern(name_str);
        report.referrers.add(name, input_id);
        let Some(sym) = symbolize_input(name, input_sym, input_id) else {
            continue;
        };
        match table.insert(sym) {
            Ok(outcome) => report.record_outcome(outcome),
            Err(e) => report.record_error(e),
        }
    }
    Ok(())
}

/// Seed every regular export from a dylib as a `DylibImport`. Re-exports
/// and stub+resolver terminals map to `DylibImport` too — they behave
/// like imports from the consumer's perspective.
pub fn seed_dylib(
    inputs: &Inputs,
    dylib_id: DylibId,
    table: &mut SymbolTable,
    report: &mut SeedReport,
) -> Result<(), SeedError> {
    let di = inputs.dylib(dylib_id);
    let entries = di.file.exports.entries().map_err(SeedError::Read)?;
    for entry in entries {
        let name = table.intern(&entry.name);
        let sym = Symbol::DylibImport {
            name,
            dylib: dylib_id,
            ordinal: di.ordinal,
            weak_import: entry.weak_def(),
        };
        match table.insert(sym) {
            Ok(outcome) => report.record_outcome(outcome),
            Err(e) => report.record_error(e),
        }
    }
    Ok(())
}

/// Seed every input in a single pass. Order is archives → objects → dylibs
/// so lazy-archive promotion works correctly (undefineds in objects hit
/// pre-seeded LazyArchive slots and trigger `PendingArchiveFetch`).
pub fn seed_all(inputs: &Inputs, table: &mut SymbolTable) -> Result<SeedReport, SeedError> {
    let mut report = SeedReport::default();
    seed_archives(inputs, table, &mut report)?;
    for i in 0..inputs.objects.len() {
        seed_object(inputs, InputId(i as u32), table, &mut report)?;
    }
    for i in 0..inputs.dylibs.len() {
        seed_dylib(inputs, DylibId(i as u32), table, &mut report)?;
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Fixed-point fetch loop.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FetchError {
    Read(ReadError),
    Archive(ArchiveError),
    MemberNotFound {
        archive: ArchiveId,
        member: MemberId,
    },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Read(e) => write!(f, "{e}"),
            FetchError::Archive(e) => write!(f, "{e}"),
            FetchError::MemberNotFound { archive, member } => write!(
                f,
                "archive #{} has no member at ar_hdr offset 0x{:x}",
                archive.0, member.0
            ),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<ReadError> for FetchError {
    fn from(e: ReadError) -> Self {
        FetchError::Read(e)
    }
}

impl From<ArchiveError> for FetchError {
    fn from(e: ArchiveError) -> Self {
        FetchError::Archive(e)
    }
}

impl From<SeedError> for FetchError {
    fn from(e: SeedError) -> Self {
        match e {
            SeedError::Read(r) => FetchError::Read(r),
            SeedError::Archive(a) => FetchError::Archive(a),
        }
    }
}

#[derive(Debug, Default)]
pub struct DrainReport {
    pub fetched_members: usize,
    pub loaded_paths: Vec<PathBuf>,
    pub duplicates: Vec<InsertError>,
    pub referrers: ReferrerLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ArchiveMemberKey {
    archive: ArchiveId,
    member: MemberId,
}

#[derive(Clone, Copy)]
struct ArchiveMemberLoadJob<'a> {
    index: usize,
    key: ArchiveMemberKey,
    archive_path: &'a Path,
    archive_bytes: &'a [u8],
    archive_load_order: usize,
}

struct LoadedArchiveMember {
    key: ArchiveMemberKey,
    archive_load_order: usize,
    logical_path: PathBuf,
    bytes: Vec<u8>,
    parsed: ObjectFile,
}

fn make_archive_member_jobs<'a>(
    inputs: &'a Inputs,
    keys: Vec<ArchiveMemberKey>,
) -> Vec<ArchiveMemberLoadJob<'a>> {
    keys.into_iter()
        .enumerate()
        .map(|(index, key)| {
            let archive = &inputs.archives[key.archive.0 as usize];
            ArchiveMemberLoadJob {
                index,
                key,
                archive_path: &archive.path,
                archive_bytes: &archive.bytes,
                archive_load_order: archive.load_order,
            }
        })
        .collect()
}

fn load_archive_members_parallel(
    inputs: &Inputs,
    keys: Vec<ArchiveMemberKey>,
) -> Vec<(ArchiveMemberKey, Result<LoadedArchiveMember, FetchError>)> {
    let jobs = make_archive_member_jobs(inputs, keys);
    if jobs.is_empty() {
        return Vec::new();
    }
    let job_count = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(jobs.len())
        .max(1);
    if job_count == 1 {
        return jobs
            .into_iter()
            .map(load_archive_member_job)
            .map(|(_, key, result)| (key, result))
            .collect();
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let (tx, rx) = mpsc::channel();
    let mut results = thread::scope(|scope| {
        for _ in 0..job_count {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            scope.spawn(move || loop {
                let Some(job) = queue
                    .lock()
                    .expect("archive member load queue mutex poisoned")
                    .pop_front()
                else {
                    break;
                };
                tx.send(load_archive_member_job(job))
                    .expect("archive member load receiver should stay live");
            });
        }
        drop(tx);
        rx.into_iter().collect::<Vec<_>>()
    });
    results.sort_by_key(|(index, _, _)| *index);
    results
        .into_iter()
        .map(|(_, key, result)| (key, result))
        .collect()
}

fn load_archive_member_job(
    job: ArchiveMemberLoadJob<'_>,
) -> (
    usize,
    ArchiveMemberKey,
    Result<LoadedArchiveMember, FetchError>,
) {
    let result = (|| {
        let archive = Archive::open(job.archive_path, job.archive_bytes)?;
        let member =
            archive
                .member_at_offset(job.key.member.0)
                .ok_or(FetchError::MemberNotFound {
                    archive: job.key.archive,
                    member: job.key.member,
                })?;
        let logical_path =
            PathBuf::from(format!("{}({})", job.archive_path.display(), member.name));
        let bytes = member.body.to_vec();
        let parsed = ObjectFile::parse(&logical_path, &bytes)?;
        Ok(LoadedArchiveMember {
            key: job.key,
            archive_load_order: job.archive_load_order,
            logical_path,
            bytes,
            parsed,
        })
    })();
    (job.index, job.key, result)
}

fn archive_member_key(pending: PendingFetch) -> ArchiveMemberKey {
    ArchiveMemberKey {
        archive: pending.archive,
        member: pending.member,
    }
}

fn archive_member_is_fetched(inputs: &Inputs, key: ArchiveMemberKey) -> bool {
    inputs.archives[key.archive.0 as usize]
        .fetched
        .contains(&key.member.0)
}

/// Shared ingest: copy one archive member's body into a fresh
/// `ObjectInput`, mark it fetched, and seed its symbols. Callers either
/// respond to a demand-driven `PendingFetch` or force-pull the member.
fn ingest_loaded_member(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    loaded: LoadedArchiveMember,
    report: &mut DrainReport,
) -> Result<Vec<PendingFetch>, FetchError> {
    if archive_member_is_fetched(inputs, loaded.key) {
        return Ok(Vec::new());
    }

    inputs.archives[loaded.key.archive.0 as usize]
        .fetched
        .insert(loaded.key.member.0);
    let input_id = InputId(inputs.objects.len() as u32);
    inputs.objects.push(ObjectInput {
        path: loaded.logical_path,
        load_order: loaded.archive_load_order,
        archive_member_offset: Some(loaded.key.member.0),
        bytes: loaded.bytes,
        parsed: loaded.parsed,
    });
    report.fetched_members += 1;
    report
        .loaded_paths
        .push(inputs.objects[input_id.0 as usize].path.clone());

    let mut sub_report = SeedReport::default();
    seed_object(inputs, input_id, table, &mut sub_report)?;
    report.duplicates.extend(sub_report.duplicates);
    report.referrers.extend_from(&sub_report.referrers);
    Ok(sub_report.pending_fetches)
}

fn load_and_ingest_member(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    key: ArchiveMemberKey,
    report: &mut DrainReport,
) -> Result<Vec<PendingFetch>, FetchError> {
    if archive_member_is_fetched(inputs, key) {
        return Ok(Vec::new());
    }
    let loaded = load_archive_members_parallel(inputs, vec![key])
        .into_iter()
        .next()
        .expect("single archive member load should produce one result")
        .1?;
    ingest_loaded_member(inputs, table, loaded, report)
}

/// Pull `pending`'s member only if the symbol slot is still a
/// `LazyArchive` (i.e., a strong Defined hasn't superseded it). Returns
/// any new `PendingFetch` entries triggered by the inserted member.
fn fetch_and_ingest_one(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    pending: PendingFetch,
    report: &mut DrainReport,
) -> Result<Vec<PendingFetch>, FetchError> {
    let slot_is_still_lazy = matches!(table.get(pending.id), Symbol::LazyArchive { .. });
    if !slot_is_still_lazy {
        return Ok(Vec::new());
    }
    load_and_ingest_member(inputs, table, archive_member_key(pending), report)
}

/// Pull every member of one archive (bypasses demand tracking). Respects
/// `ArchiveInput::fetched` for deduplication so it's safe to combine with
/// demand-driven fetching.
pub fn force_load_archive(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    archive_id: ArchiveId,
    report: &mut DrainReport,
) -> Result<(), FetchError> {
    let member_offsets: Vec<u32> = {
        let ai = &inputs.archives[archive_id.0 as usize];
        let archive = Archive::open(&ai.path, &ai.bytes)?;
        archive
            .object_members()
            .map(|m| m.header_offset as u32)
            .collect()
    };
    let keys = member_offsets
        .into_iter()
        .map(|offset| ArchiveMemberKey {
            archive: archive_id,
            member: MemberId(offset),
        })
        .collect();
    let mut queue: Vec<PendingFetch> = Vec::new();
    for (_, loaded) in load_archive_members_parallel(inputs, keys) {
        let new = ingest_loaded_member(inputs, table, loaded?, report)?;
        queue.extend(new);
    }
    while let Some(p) = queue.pop() {
        let new = fetch_and_ingest_one(inputs, table, p, report)?;
        queue.extend(new);
    }
    Ok(())
}

/// Pull every member of every registered archive — the `-all_load`
/// semantic.
pub fn force_load_all(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    report: &mut DrainReport,
) -> Result<(), FetchError> {
    for i in 0..inputs.archives.len() {
        force_load_archive(inputs, table, ArchiveId(i as u32), report)?;
    }
    Ok(())
}

/// Look up an archive by path for `-force_load <path>`. Returns `None` if
/// no registered archive matches; diagnostic surface lives in Sprint 19's
/// CLI layer.
pub fn find_archive_by_path(inputs: &Inputs, path: &std::path::Path) -> Option<ArchiveId> {
    inputs
        .archives
        .iter()
        .position(|a| a.path == path)
        .map(|i| ArchiveId(i as u32))
}

// ---------------------------------------------------------------------------
// Unresolved classification.
// ---------------------------------------------------------------------------

/// Policy for handling Undefined symbols that remain after the fixed
/// point. Maps to the CLI `-undefined <treatment>` flag (Sprint 19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UndefinedTreatment {
    /// Undefineds are errors. The default, matching Apple `ld`.
    #[default]
    Error,
    /// Undefineds produce warnings; left in the table as Undefined.
    Warning,
    /// Undefineds are silently accepted; left in the table as Undefined.
    Suppress,
    /// Undefineds are promoted to flat-lookup DylibImport entries — dyld
    /// searches every loaded dylib at runtime.
    DynamicLookup,
}

/// `n_desc`-style special ordinal: `-2` (two's-complement u16 = 0xFFFE)
/// tells dyld to use flat-namespace lookup. Sprint 15 emits this into
/// `LC_DYLD_INFO` bind opcodes.
pub const FLAT_LOOKUP_ORDINAL: u16 = 0xFFFE;

/// Sentinel DylibId used for dynamic-lookup promotions before a real
/// dylib registry is bound. Sprint 15 interprets `DylibId::INVALID`
/// when emitting bind opcodes.
impl DylibId {
    pub const INVALID: DylibId = DylibId(u32::MAX);
}

#[derive(Debug, Default)]
pub struct ClassificationReport {
    /// Strong undefineds that triggered errors under `Error` treatment.
    pub errors: Vec<Unresolved>,
    /// Strong undefineds that produced warnings under `Warning` treatment and
    /// were promoted to flat-lookup imports for final emission.
    pub warnings: Vec<Unresolved>,
    /// Strong undefineds that were silently accepted under `Suppress` and
    /// were promoted to flat-lookup imports for final emission.
    pub suppressed: Vec<Unresolved>,
    /// Undefineds promoted to flat-lookup DylibImport entries.
    pub promoted_to_dynamic: Vec<SymbolId>,
    /// Weak references that remain unresolved — always accepted.
    pub weak: Vec<Unresolved>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    pub name: Istr,
    pub id: SymbolId,
}

// ---------------------------------------------------------------------------
// Levenshtein distance — used for did-you-mean hints.
// ---------------------------------------------------------------------------

/// Classic dynamic-programming edit distance. O(m·n) time, O(n) space.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut row: Vec<usize> = (0..=n).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            let new_val = (row[j + 1] + 1).min(row[j] + 1).min(prev + cost);
            prev = row[j + 1];
            row[j + 1] = new_val;
        }
    }
    row[n]
}

/// Return up to `max` candidate names from `table` within `budget` edits
/// of `query`. Sorted by ascending distance, ties broken by name.
pub fn did_you_mean(table: &SymbolTable, query: &str, budget: usize, max: usize) -> Vec<String> {
    let mut hits: Vec<(usize, String)> = table
        .iter()
        .filter_map(|(_, s)| {
            let candidate = table.interner.resolve(s.name());
            if candidate == query {
                return None;
            }
            let d = levenshtein(query, candidate);
            if d <= budget {
                Some((d, candidate.to_string()))
            } else {
                None
            }
        })
        .collect();
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    hits.dedup_by(|a, b| a.1 == b.1);
    hits.into_iter().take(max).map(|(_, n)| n).collect()
}

// ---------------------------------------------------------------------------
// Diagnostic formatters — produce afs-as-style text for the driver to
// emit. Sprint 8 writes to String; Sprint 19's CLI layer owns stderr.
// ---------------------------------------------------------------------------

/// Format the full undefined-symbol diagnostic block, one entry per
/// unresolved name: the error line, every referrer, and an optional
/// did-you-mean hint.
fn format_undefined_diagnostic_with_level(
    table: &SymbolTable,
    inputs: &Inputs,
    referrers: &ReferrerLog,
    unresolved: &[Unresolved],
    level: &str,
) -> String {
    let mut out = String::new();
    for u in unresolved {
        let name = table.interner.resolve(u.name);
        out.push_str(&format!("afs-ld: {level}: undefined symbol: {name}\n"));
        for origin in referrers.get(u.name) {
            if let Some(oi) = inputs.objects.get(origin.0 as usize) {
                out.push_str(&format!("      referenced by {}\n", oi.path.display()));
            }
        }
        let suggestions = did_you_mean(table, name, 3, 3);
        if !suggestions.is_empty() {
            out.push_str(&format!(
                "  Hint: did you mean {}?\n",
                suggestions
                    .iter()
                    .map(|s| format!("{s:?}"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
    }
    out
}

pub fn format_undefined_diagnostic(
    table: &SymbolTable,
    inputs: &Inputs,
    referrers: &ReferrerLog,
    unresolved: &[Unresolved],
) -> String {
    format_undefined_diagnostic_with_level(table, inputs, referrers, unresolved, "error")
}

pub fn format_undefined_warning_diagnostic(
    table: &SymbolTable,
    inputs: &Inputs,
    referrers: &ReferrerLog,
    unresolved: &[Unresolved],
) -> String {
    format_undefined_diagnostic_with_level(table, inputs, referrers, unresolved, "warning")
}

/// Format a `DuplicateStrong` insertion error for user consumption. Needs
/// the incumbent symbol (from the table) plus the losing second symbol
/// carried in the error itself.
pub fn format_duplicate_diagnostic(
    table: &SymbolTable,
    inputs: &Inputs,
    err: &InsertError,
) -> String {
    let InsertError::DuplicateStrong {
        name,
        first,
        second,
    } = err
    else {
        return String::new();
    };
    let name_str = table.interner.resolve(*name);
    let mut out = String::new();
    out.push_str(&format!("afs-ld: error: duplicate symbol {name_str}\n"));
    if let Symbol::Defined { origin, .. } = table.get(*first) {
        if let Some(oi) = inputs.objects.get(origin.0 as usize) {
            out.push_str(&format!("  defined in {}\n", oi.path.display()));
        }
    }
    if let Symbol::Defined { origin, .. } = second.as_ref() {
        if let Some(oi) = inputs.objects.get(origin.0 as usize) {
            out.push_str(&format!("  also in {}\n", oi.path.display()));
        }
    }
    out
}

/// After the fixed-point loop, walk the table and classify every remaining
/// `Undefined`. Weak references always pass through cleanly.
pub fn classify_unresolved(
    table: &mut SymbolTable,
    treatment: UndefinedTreatment,
) -> ClassificationReport {
    let mut report = ClassificationReport::default();

    fn promote_to_flat_lookup(table: &mut SymbolTable, id: SymbolId, name: Istr) {
        table.symbols[id.0 as usize] = Symbol::DylibImport {
            name,
            dylib: DylibId::INVALID,
            ordinal: FLAT_LOOKUP_ORDINAL,
            weak_import: true,
        };
        table.transitions.push(Transition {
            id,
            from: SymbolKindTag::Undefined,
            to: SymbolKindTag::DylibImport,
            cause: TransitionCause::Replaced,
        });
    }

    // Collect undefineds before mutating — avoids double-borrow grief.
    let undefs: Vec<(SymbolId, Istr, bool)> = table
        .iter()
        .filter_map(|(id, s)| match s {
            Symbol::Undefined { name, weak_ref, .. } => Some((id, *name, *weak_ref)),
            _ => None,
        })
        .collect();

    for (id, name, weak_ref) in undefs {
        if weak_ref {
            report.weak.push(Unresolved { name, id });
            continue;
        }
        match treatment {
            UndefinedTreatment::Error => {
                report.errors.push(Unresolved { name, id });
            }
            UndefinedTreatment::Warning => {
                report.warnings.push(Unresolved { name, id });
                promote_to_flat_lookup(table, id, name);
                report.promoted_to_dynamic.push(id);
            }
            UndefinedTreatment::Suppress => {
                report.suppressed.push(Unresolved { name, id });
                promote_to_flat_lookup(table, id, name);
                report.promoted_to_dynamic.push(id);
            }
            UndefinedTreatment::DynamicLookup => {
                promote_to_flat_lookup(table, id, name);
                report.promoted_to_dynamic.push(id);
            }
        }
    }

    report
}

/// Drive the fetch queue to a fixed point. Each fetched member's own
/// undefined references may trigger additional pending fetches — drain
/// those too until the queue is empty.
pub fn drain_fetches(
    inputs: &mut Inputs,
    table: &mut SymbolTable,
    initial: Vec<PendingFetch>,
) -> Result<DrainReport, FetchError> {
    let mut queue = initial;
    let mut prepared = HashMap::new();
    let mut report = DrainReport::default();
    while let Some(p) = queue.pop() {
        let key = archive_member_key(p);
        let slot_is_still_lazy = matches!(table.get(p.id), Symbol::LazyArchive { .. });
        if !slot_is_still_lazy || archive_member_is_fetched(inputs, key) {
            prepared.remove(&key);
            continue;
        }
        // Parse siblings ahead of time, but only ingest the current stack
        // entry after re-checking its lazy slot. This keeps member order stable.
        if !prepared.contains_key(&key) {
            preparse_pending_fetches(inputs, table, p, &queue, &mut prepared);
        }
        let Some(loaded) = prepared.remove(&key) else {
            continue;
        };
        let loaded = loaded?;
        let slot_is_still_lazy = matches!(table.get(p.id), Symbol::LazyArchive { .. });
        if !slot_is_still_lazy || archive_member_is_fetched(inputs, key) {
            continue;
        }
        let new_pending = ingest_loaded_member(inputs, table, loaded, &mut report)?;
        queue.extend(new_pending);
    }
    Ok(report)
}

fn preparse_pending_fetches(
    inputs: &Inputs,
    table: &SymbolTable,
    current: PendingFetch,
    queue: &[PendingFetch],
    prepared: &mut HashMap<ArchiveMemberKey, Result<LoadedArchiveMember, FetchError>>,
) {
    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    for pending in std::iter::once(&current).chain(queue.iter().rev()) {
        let key = archive_member_key(*pending);
        if prepared.contains_key(&key)
            || archive_member_is_fetched(inputs, key)
            || !matches!(table.get(pending.id), Symbol::LazyArchive { .. })
            || !seen.insert(key)
        {
            continue;
        }
        keys.push(key);
    }
    for (key, result) in load_archive_members_parallel(inputs, keys) {
        prepared.insert(key, result);
    }
}

/// Turn a wire-form `InputSymbol` into a resolver-side `Symbol`. Returns
/// `None` for kinds the resolver does not track (currently: aliases with
/// unresolved target strx — Sprint 8's resolver defers those for now).
fn symbolize_input(
    name: Istr,
    input_sym: &crate::symbol::InputSymbol,
    origin: InputId,
) -> Option<Symbol> {
    use crate::symbol::SymKind;
    match input_sym.kind() {
        SymKind::Undef => {
            if let Some(size) = input_sym.common_size() {
                let align_pow2 = input_sym.common_align_pow2().unwrap_or(0);
                Some(Symbol::Common {
                    name,
                    origin,
                    size,
                    align_pow2,
                })
            } else {
                Some(Symbol::Undefined {
                    name,
                    origin,
                    weak_ref: input_sym.weak_ref(),
                })
            }
        }
        SymKind::Abs | SymKind::Sect => Some(Symbol::Defined {
            name,
            origin,
            // AtomId(0) is a placeholder; Sprint 9's atomization pass
            // replaces these with real atom handles in-place.
            atom: AtomId(0),
            value: input_sym.value(),
            weak: input_sym.weak_def(),
            private_extern: input_sym.is_private_ext(),
            no_dead_strip: input_sym.no_dead_strip(),
        }),
        SymKind::Indirect => {
            // Sprint 8 does not wire indirect-strx lookups yet — Sprint 9's
            // atomization pass (which has the string table at hand) will
            // rewrite these. For now, skip.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interner_dedups_same_string() {
        let mut s = StringInterner::new();
        let a = s.intern("_main");
        let b = s.intern("_main");
        assert_eq!(a, b);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn interner_distinguishes_different_strings() {
        let mut s = StringInterner::new();
        let a = s.intern("_main");
        let b = s.intern("_helper");
        assert_ne!(a, b);
        assert_eq!(s.resolve(a), "_main");
        assert_eq!(s.resolve(b), "_helper");
    }

    #[test]
    fn interner_handles_are_stable_u32() {
        let mut s = StringInterner::new();
        let a = s.intern("_a");
        let b = s.intern("_b");
        let c = s.intern("_c");
        assert_eq!(a.as_u32(), 0);
        assert_eq!(b.as_u32(), 1);
        assert_eq!(c.as_u32(), 2);
    }

    #[test]
    fn opaque_ids_are_distinguishable() {
        let a = InputId(0);
        let b = InputId(1);
        assert_ne!(a, b);
        assert_eq!(a.as_u32(), 0);
        // Different newtypes with the same inner value are NOT compatible
        // (we test this via the module's type system at compile time).
    }

    #[test]
    fn interner_large_workload() {
        let mut s = StringInterner::new();
        for i in 0..1000 {
            let name = format!("_sym_{i}");
            let h1 = s.intern(&name);
            let h2 = s.intern(&name);
            assert_eq!(h1, h2);
        }
        assert_eq!(s.len(), 1000);
    }

    // ---- Symbol variant tests ----

    fn n(i: u32) -> Istr {
        Istr(i)
    }

    #[test]
    fn symbol_kind_tags_match_variants() {
        let undef = Symbol::Undefined {
            name: n(0),
            origin: InputId(0),
            weak_ref: false,
        };
        assert_eq!(undef.kind(), SymbolKindTag::Undefined);

        let defined = Symbol::Defined {
            name: n(1),
            origin: InputId(0),
            atom: AtomId(0),
            value: 0,
            weak: false,
            private_extern: false,
            no_dead_strip: false,
        };
        assert_eq!(defined.kind(), SymbolKindTag::Defined);
        assert!(defined.is_strong_defined());
        assert!(!defined.is_weak_defined());

        let weak = Symbol::Defined {
            name: n(2),
            origin: InputId(0),
            atom: AtomId(0),
            value: 0,
            weak: true,
            private_extern: false,
            no_dead_strip: false,
        };
        assert!(weak.is_weak_defined());
        assert!(!weak.is_strong_defined());

        assert_eq!(
            Symbol::Common {
                name: n(3),
                origin: InputId(0),
                size: 8,
                align_pow2: 3
            }
            .kind(),
            SymbolKindTag::Common
        );
        assert_eq!(
            Symbol::DylibImport {
                name: n(4),
                dylib: DylibId(0),
                ordinal: 1,
                weak_import: false
            }
            .kind(),
            SymbolKindTag::DylibImport
        );
        assert_eq!(
            Symbol::LazyArchive {
                name: n(5),
                archive: ArchiveId(0),
                member: MemberId(0)
            }
            .kind(),
            SymbolKindTag::LazyArchive
        );
        assert_eq!(
            Symbol::LazyObject {
                name: n(6),
                origin: InputId(0)
            }
            .kind(),
            SymbolKindTag::LazyObject
        );
        assert_eq!(
            Symbol::Alias {
                name: n(7),
                aliased: n(0)
            }
            .kind(),
            SymbolKindTag::Alias
        );
    }

    #[test]
    fn symbol_name_returns_istr_across_variants() {
        let sym = Symbol::Common {
            name: n(42),
            origin: InputId(0),
            size: 16,
            align_pow2: 4,
        };
        assert_eq!(sym.name(), n(42));
    }

    // ----------------- SymbolTable & insertion matrix tests -----------------

    fn undef(t: &mut SymbolTable, name: &str) -> Symbol {
        Symbol::Undefined {
            name: t.intern(name),
            origin: InputId(0),
            weak_ref: false,
        }
    }

    fn defined_strong(t: &mut SymbolTable, name: &str) -> Symbol {
        Symbol::Defined {
            name: t.intern(name),
            origin: InputId(0),
            atom: AtomId(0),
            value: 0x100,
            weak: false,
            private_extern: false,
            no_dead_strip: false,
        }
    }

    fn defined_weak(t: &mut SymbolTable, name: &str) -> Symbol {
        Symbol::Defined {
            name: t.intern(name),
            origin: InputId(0),
            atom: AtomId(0),
            value: 0x200,
            weak: true,
            private_extern: false,
            no_dead_strip: false,
        }
    }

    fn common(t: &mut SymbolTable, name: &str, size: u64, align: u8) -> Symbol {
        Symbol::Common {
            name: t.intern(name),
            origin: InputId(0),
            size,
            align_pow2: align,
        }
    }

    fn dylib_import(t: &mut SymbolTable, name: &str, ordinal: u16) -> Symbol {
        Symbol::DylibImport {
            name: t.intern(name),
            dylib: DylibId(0),
            ordinal,
            weak_import: false,
        }
    }

    fn lazy_archive(t: &mut SymbolTable, name: &str) -> Symbol {
        Symbol::LazyArchive {
            name: t.intern(name),
            archive: ArchiveId(7),
            member: MemberId(42),
        }
    }

    fn lazy_object(t: &mut SymbolTable, name: &str) -> Symbol {
        Symbol::LazyObject {
            name: t.intern(name),
            origin: InputId(5),
        }
    }

    fn alias_sym(t: &mut SymbolTable, name: &str, target: &str) -> Symbol {
        let name_i = t.intern(name);
        let target_i = t.intern(target);
        Symbol::Alias {
            name: name_i,
            aliased: target_i,
        }
    }

    // ---- vacant-slot insertions ----

    #[test]
    fn vacant_insert_records_inserted_outcome() {
        let mut t = SymbolTable::new();
        let sym = defined_strong(&mut t, "_main");
        match t.insert(sym).unwrap() {
            InsertOutcome::Inserted(id) => {
                assert_eq!(id, SymbolId(0));
                assert!(matches!(t.get(id), Symbol::Defined { .. }));
            }
            other => panic!("expected Inserted, got {other:?}"),
        }
        assert_eq!(t.transitions().len(), 1);
        assert_eq!(t.transitions()[0].cause, TransitionCause::Inserted);
    }

    // ---- existing Undefined ----

    #[test]
    fn undefined_kept_under_undefined() {
        let mut t = SymbolTable::new();
        let a = undef(&mut t, "_x");
        let b = undef(&mut t, "_x");
        t.insert(a).unwrap();
        let out = t.insert(b).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    #[test]
    fn undefined_replaced_by_definition() {
        let mut t = SymbolTable::new();
        let first = undef(&mut t, "_x");
        t.insert(first).unwrap();
        let incoming = defined_strong(&mut t, "_x");
        let out = t.insert(incoming).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn undefined_replaced_by_common() {
        let mut t = SymbolTable::new();
        let first = undef(&mut t, "_x");
        t.insert(first).unwrap();
        let c = common(&mut t, "_x", 8, 3);
        let out = t.insert(c).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn undefined_replaced_by_dylib_import() {
        let mut t = SymbolTable::new();
        let first = undef(&mut t, "_x");
        t.insert(first).unwrap();
        let di = dylib_import(&mut t, "_x", 1);
        let out = t.insert(di).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn undefined_replaced_by_lazy_archive() {
        let mut t = SymbolTable::new();
        let first = undef(&mut t, "_x");
        t.insert(first).unwrap();
        let la = lazy_archive(&mut t, "_x");
        let out = t.insert(la).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn undefined_replaced_by_lazy_object() {
        let mut t = SymbolTable::new();
        let first = undef(&mut t, "_x");
        t.insert(first).unwrap();
        let lo = lazy_object(&mut t, "_x");
        let out = t.insert(lo).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    // ---- existing Defined ----

    #[test]
    fn strong_defined_keeps_under_undefined() {
        let mut t = SymbolTable::new();
        let existing = defined_strong(&mut t, "_x");
        t.insert(existing).unwrap();
        let newer = undef(&mut t, "_x");
        let out = t.insert(newer).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    #[test]
    fn two_strong_defined_is_duplicate_error() {
        let mut t = SymbolTable::new();
        let first = defined_strong(&mut t, "_x");
        t.insert(first).unwrap();
        let second = defined_strong(&mut t, "_x");
        let err = t.insert(second).unwrap_err();
        assert!(matches!(err, InsertError::DuplicateStrong { .. }));
    }

    #[test]
    fn strong_keeps_under_weak() {
        let mut t = SymbolTable::new();
        let strong = defined_strong(&mut t, "_x");
        t.insert(strong).unwrap();
        let weaker = defined_weak(&mut t, "_x");
        let out = t.insert(weaker).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    #[test]
    fn weak_replaced_by_strong() {
        let mut t = SymbolTable::new();
        let weak = defined_weak(&mut t, "_x");
        t.insert(weak).unwrap();
        let strong = defined_strong(&mut t, "_x");
        let out = t.insert(strong).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
        assert!(t.get(SymbolId(0)).is_strong_defined());
    }

    #[test]
    fn two_weak_defined_first_wins() {
        let mut t = SymbolTable::new();
        let first = defined_weak(&mut t, "_x");
        let Symbol::Defined {
            value: first_val, ..
        } = first
        else {
            unreachable!()
        };
        t.insert(first).unwrap();
        let second = defined_weak(&mut t, "_x");
        let out = t.insert(second).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
        if let Symbol::Defined { value, .. } = t.get(SymbolId(0)) {
            assert_eq!(*value, first_val);
        }
    }

    #[test]
    fn defined_keeps_under_common() {
        let mut t = SymbolTable::new();
        let strong = defined_strong(&mut t, "_x");
        t.insert(strong).unwrap();
        let c = common(&mut t, "_x", 8, 3);
        let out = t.insert(c).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    #[test]
    fn defined_keeps_under_dylib_import() {
        let mut t = SymbolTable::new();
        let strong = defined_strong(&mut t, "_x");
        t.insert(strong).unwrap();
        let di = dylib_import(&mut t, "_x", 1);
        let out = t.insert(di).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    #[test]
    fn defined_keeps_under_lazy_archive() {
        let mut t = SymbolTable::new();
        let strong = defined_strong(&mut t, "_x");
        t.insert(strong).unwrap();
        let la = lazy_archive(&mut t, "_x");
        let out = t.insert(la).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    // ---- existing Common ----

    #[test]
    fn common_replaced_by_definition() {
        let mut t = SymbolTable::new();
        let c = common(&mut t, "_x", 8, 3);
        t.insert(c).unwrap();
        let def = defined_strong(&mut t, "_x");
        let out = t.insert(def).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn common_coalesces_to_larger_size_and_stricter_alignment() {
        let mut t = SymbolTable::new();
        let a = common(&mut t, "_x", 8, 2);
        t.insert(a).unwrap();
        let b = common(&mut t, "_x", 16, 5);
        let out = t.insert(b).unwrap();
        assert!(matches!(out, InsertOutcome::CommonCoalesced { .. }));
        if let Symbol::Common {
            size, align_pow2, ..
        } = t.get(SymbolId(0))
        {
            assert_eq!(*size, 16);
            assert_eq!(*align_pow2, 5);
        }
    }

    #[test]
    fn common_kept_under_dylib_import() {
        let mut t = SymbolTable::new();
        let c = common(&mut t, "_x", 8, 3);
        t.insert(c).unwrap();
        let di = dylib_import(&mut t, "_x", 2);
        let out = t.insert(di).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    // ---- existing DylibImport ----

    #[test]
    fn dylib_import_replaced_by_local_definition() {
        let mut t = SymbolTable::new();
        let di = dylib_import(&mut t, "_printf", 1);
        t.insert(di).unwrap();
        let def = defined_strong(&mut t, "_printf");
        let out = t.insert(def).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn dylib_import_keeps_under_another_import() {
        let mut t = SymbolTable::new();
        let first = dylib_import(&mut t, "_printf", 1);
        t.insert(first).unwrap();
        let second = dylib_import(&mut t, "_printf", 2);
        let out = t.insert(second).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    // ---- existing LazyArchive ----

    #[test]
    fn lazy_archive_under_undefined_yields_pending_fetch() {
        let mut t = SymbolTable::new();
        let lazy = lazy_archive(&mut t, "_hidden");
        t.insert(lazy).unwrap();
        let want = undef(&mut t, "_hidden");
        match t.insert(want).unwrap() {
            InsertOutcome::PendingArchiveFetch {
                archive, member, ..
            } => {
                assert_eq!(archive, ArchiveId(7));
                assert_eq!(member, MemberId(42));
            }
            other => panic!("expected PendingArchiveFetch, got {other:?}"),
        }
    }

    #[test]
    fn lazy_archive_replaced_by_defined() {
        let mut t = SymbolTable::new();
        let lazy = lazy_archive(&mut t, "_f");
        t.insert(lazy).unwrap();
        let def = defined_strong(&mut t, "_f");
        let out = t.insert(def).unwrap();
        assert!(matches!(out, InsertOutcome::Replaced { .. }));
    }

    #[test]
    fn two_lazy_archives_first_wins() {
        let mut t = SymbolTable::new();
        let first = lazy_archive(&mut t, "_f");
        t.insert(first).unwrap();
        let name = t.intern("_f");
        let second = Symbol::LazyArchive {
            name,
            archive: ArchiveId(99),
            member: MemberId(99),
        };
        let out = t.insert(second).unwrap();
        assert!(matches!(out, InsertOutcome::Kept(_)));
    }

    // ---- existing LazyObject ----

    #[test]
    fn lazy_object_under_undefined_yields_pending_load() {
        let mut t = SymbolTable::new();
        let lazy = lazy_object(&mut t, "_f");
        t.insert(lazy).unwrap();
        let want = undef(&mut t, "_f");
        match t.insert(want).unwrap() {
            InsertOutcome::PendingObjectLoad { origin, .. } => {
                assert_eq!(origin, InputId(5));
            }
            other => panic!("expected PendingObjectLoad, got {other:?}"),
        }
    }

    // ---- Alias path ----

    #[test]
    fn alias_inserts_into_vacant_slot() {
        let mut t = SymbolTable::new();
        let al = alias_sym(&mut t, "_old_name", "_new_name");
        let out = t.insert(al).unwrap();
        assert!(matches!(out, InsertOutcome::Inserted(_)));
    }

    #[test]
    fn direct_definition_replaces_alias() {
        let mut t = SymbolTable::new();
        let al = alias_sym(&mut t, "_alias", "_target");
        t.insert(al).unwrap();
        let def = defined_strong(&mut t, "_alias");
        let out = t.insert(def).unwrap();
        assert!(matches!(
            out,
            InsertOutcome::Replaced {
                from: SymbolKindTag::Alias,
                to: SymbolKindTag::Defined,
                ..
            }
        ));
    }

    #[test]
    fn self_loop_alias_rejected() {
        let mut t = SymbolTable::new();
        let u = undef(&mut t, "_foo");
        t.insert(u).unwrap();
        let looped = alias_sym(&mut t, "_foo", "_foo");
        let err = t.insert(looped).unwrap_err();
        assert!(matches!(err, InsertError::AliasCycle { .. }));
    }

    #[test]
    fn two_step_alias_cycle_rejected() {
        let mut t = SymbolTable::new();
        let a_to_b = alias_sym(&mut t, "_a", "_b");
        t.insert(a_to_b).unwrap();
        let u = undef(&mut t, "_b");
        t.insert(u).unwrap();
        let loop_back = alias_sym(&mut t, "_b", "_a");
        let err = t.insert(loop_back).unwrap_err();
        assert!(matches!(err, InsertError::AliasCycle { .. }));
    }

    #[test]
    fn resolve_chain_walks_to_concrete_target() {
        let mut t = SymbolTable::new();
        let defined = defined_strong(&mut t, "_target");
        t.insert(defined).unwrap();
        let al = alias_sym(&mut t, "_alias", "_target");
        t.insert(al).unwrap();
        let name = t.intern("_alias");
        let (_, sym) = t.resolve_chain(name).unwrap();
        assert!(matches!(sym, Symbol::Defined { .. }));
    }

    #[test]
    fn resolve_chain_unknown_name_errors() {
        let t = SymbolTable::new();
        let err = t.resolve_chain(Istr(99)).unwrap_err();
        assert!(matches!(err, ResolveError::Unknown(_)));
    }

    // ---- Transition log ----

    #[test]
    fn kept_entries_do_not_record_transitions() {
        let mut t = SymbolTable::new();
        let strong = defined_strong(&mut t, "_x");
        t.insert(strong).unwrap();
        let before = t.transitions().len();
        let weaker = defined_weak(&mut t, "_x");
        t.insert(weaker).unwrap();
        assert_eq!(t.transitions().len(), before);
    }

    #[test]
    fn replace_records_transition_with_from_and_to() {
        let mut t = SymbolTable::new();
        let u = undef(&mut t, "_x");
        t.insert(u).unwrap();
        let d = defined_strong(&mut t, "_x");
        t.insert(d).unwrap();
        let last = t.transitions().last().unwrap();
        assert_eq!(last.from, SymbolKindTag::Undefined);
        assert_eq!(last.to, SymbolKindTag::Defined);
        assert_eq!(last.cause, TransitionCause::Replaced);
    }

    #[test]
    fn common_coalesce_records_its_own_cause() {
        let mut t = SymbolTable::new();
        let a = common(&mut t, "_x", 8, 3);
        t.insert(a).unwrap();
        let b = common(&mut t, "_x", 16, 5);
        t.insert(b).unwrap();
        assert_eq!(
            t.transitions().last().unwrap().cause,
            TransitionCause::CommonCoalesced
        );
    }
}
