# Sprint 4: Static Archives (`ar`)

## Prerequisites
Sprints 1–3 — Mach-O reading complete.

## Goals
Read static archives (`.a`) including the BSD, System V, and GNU-thin variants. Support lazy member fetching: a member is only parsed when an undefined symbol names it. This is the mechanism by which `libarmfortas_rt.a` gets pulled in.

Closeout note: the force-load surface landed in the resolver as
`resolve::force_load_archive` / `resolve::force_load_all`, and one-level
nested archives are expanded through the fetched-member path with provenance
chains such as `outer.a(inner.a)(foo.o)`. `--dump-archive` now intentionally
prints the same member listing shape as `ar -t`, and parity is checked
against both generated archives and `libarmfortas_rt.a` when available.

## Deliverables

### 1. Archive format recognizer
`afs-ld/src/archive.rs`:

```rust
pub struct Archive<'a> {
    pub path: PathBuf,
    pub flavor: Flavor,         // Bsd, Sysv, GnuThin
    pub symdef: SymbolIndex,    // names → member offsets
    pub members: Vec<Member<'a>>,
}

pub enum Flavor { Bsd, Sysv, GnuThin }
```

Detection by magic: `!<arch>\n` for all flavors; thin archives use `!<thin>\n`. BSD vs SysV distinguished by the first entry: `#1/<N>` BSD extended filenames vs `//` SysV long-name string table.

### 2. Header parsing
Each member preceded by a 60-byte `ar_hdr`:
```
char name[16];   // "#1/<N>" on BSD, or "//" string-table index on SysV, or "foo.o/" on SysV short
char date[12];
char uid[6];
char gid[6];
char mode[8];
char size[10];
char fmag[2];    // "`\n"
```

Parse field-by-field with tight bounds checks. Size is a decimal ASCII integer, not a C literal.

### 3. Name decoding
- BSD: name field `#1/<N>`, real name is the first N bytes of the member body (body shrinks accordingly).
- SysV: name field holds a byte offset into the `//` string table.
- SysV short: `foo.o/ ` — slash-terminated, space-padded.
- GNU-thin: member body is zero bytes; the name encodes a path relative to the archive. afs-ld `mmap`s the external file.

Names stored canonical (null-stripped, slash-stripped).

### 4. Symbol index
SysV `/` member or BSD `__.SYMDEF` / `__.SYMDEF SORTED` member. BSD layout:
```
uint32 ranlib_count
ranlib[ranlib_count] { uint32 strx; uint32 offset; }
uint32 stringsize
char strings[stringsize]
```

SysV: big-endian `nsyms: u32`, then `nsyms` big-endian `u32` offsets, then packed null-terminated strings.

`SymbolIndex` exposes `fn members_defining(name: &str) -> impl Iterator<Item = MemberRef>`.

### 5. Lazy fetch API
```rust
impl<'a> Archive<'a> {
    pub fn fetch(&mut self, name: &str) -> Option<ObjectFile>;
}
```

Returns `None` if the archive does not define `name`. Fetching an archive member memoizes: a second lookup for the same member returns a cached handle. The resolution pass (Sprint 8) is the only caller.

### 6. `-force_load` / `-all_load` support (semantics, not CLI yet)
Implemented via the resolver-level helpers
`resolve::force_load_archive` / `resolve::force_load_all`, which pre-fetch
archive members against the live linker input registry. Sprint 19 wires the
CLI surface.

### 7. Archive-of-archives
Rare but legal: member can be another `.a`. Recurse one level. If a sub-archive defines `name`, the outer `fetch` returns the sub-member's object file and records a provenance chain for diagnostics.

## Testing Strategy
- Fixtures in `tests/corpus/archives/`:
  - `libbsd.a` made by Apple `ar` (BSD flavor, extended filenames).
  - `libsysv.a` made by GNU `ar` on Linux (for cross-check).
  - `libthin.a` made by `ar --thin` (GNU-thin).
  - `libmulti.a` containing several members each defining one or more symbols.
- `cargo test -p afs-ld test_archive_bsd` verifies BSD index → correct member for each name.
- Symbol-defining-two-members scenario: archive picks the one whose member comes first (ld's traditional rule).
- Missing-symbol lookup returns `None`, does not error.
- Thin-archive member file missing on disk produces a path-qualified diagnostic.

## Definition of Done
- All three archive flavors read.
- `libarmfortas_rt.a` (built by parent workspace) parses and every runtime symbol is findable by name.
- Archive-of-archives works one level deep.
- Differential: `ar -t libarmfortas_rt.a` output matches our `--dump-archive` output.
