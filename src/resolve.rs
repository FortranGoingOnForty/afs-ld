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

use std::collections::HashMap;
use std::rc::Rc;

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
            (false, true) => Ok(Action::Replace),     // strong over weak
            (true, false) => Ok(Action::Keep),        // strong keeps its seat
            (false, false) => Ok(Action::Keep),       // first weak wins
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
                let Symbol::LazyArchive { archive, member, .. } = self.symbols[id.0 as usize]
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
                let Symbol::LazyObject { origin, .. } = self.symbols[id.0 as usize]
                else {
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
            size,
            align_pow2,
            ..
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
}
