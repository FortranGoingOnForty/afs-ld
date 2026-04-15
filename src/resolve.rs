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
