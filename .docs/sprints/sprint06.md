# Sprint 6: TAPI TBD Text Stubs

## Prerequisites
Sprint 5 — binary dylib reader works.

## Goals
Read `.tbd` files (TAPI text dylib stubs). On modern SDKs `libSystem`, `libc++`, and `CoreFoundation` ship only as `.tbd` — linking without this sprint means no system libraries, full stop.

## Deliverables

### 1. Minimal YAML subset
TBD is YAML with a well-defined schema. We implement only the subset TAPI emits, not a general YAML parser:

- Flow scalars (plain, single-quoted, double-quoted).
- Flow sequences: `[ a, b, c ]`.
- Block sequences: `- item`.
- Block mappings: `key: value`.
- Multi-document files with `---` / `...`.
- Tags: `!tapi-tbd`.
- Version directives: `%YAML 1.2`.

No anchors, no aliases, no complex types, no folded scalars. If a real `.tbd` in the wild uses features outside the subset, the parser fails loudly with line/column.

### 2. TBD schema
`afs-ld/src/macho/tbd.rs`:

```rust
pub struct Tbd {
    pub tbd_version: u32,      // 3 or 4
    pub targets: Vec<Target>,  // arch + platform
    pub install_name: String,
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
    pub parent_umbrella: Vec<Scoped<String>>,
    pub allowable_clients: Vec<Scoped<String>>,
    pub reexported_libraries: Vec<Scoped<String>>,
    pub exports: Vec<Scoped<Exports>>,
    pub reexports: Vec<Scoped<Exports>>,
}

pub struct Target { pub arch: Arch, pub platform: Platform }
pub struct Scoped<T> { pub targets: Vec<Target>, pub value: T }
pub struct Exports {
    pub symbols: Vec<String>,
    pub weak_symbols: Vec<String>,
    pub thread_local_symbols: Vec<String>,
    pub objc_classes: Vec<String>,
    pub objc_eh_types: Vec<String>,
    pub objc_ivars: Vec<String>,
}
```

v3 and v4 both supported; v4 is what modern Xcode ships.

### 3. Materialize into DylibFile
`Tbd::into_dylib_file(tbd: Tbd, for_target: Target) -> DylibFile`. Filters scoped entries to only those matching `arm64 / macos`. Produces the same `DylibFile` surface Sprint 5 produces, so downstream code doesn't care about source format.

### 4. SDK search implementation
Integrate with `-syslibroot`. Search order for `-l<name>`:
1. `${SDK}/usr/lib/lib<name>.tbd`
2. `${SDK}/usr/lib/lib<name>.dylib`
3. `${SDK}/usr/local/lib/lib<name>.tbd`
4. `${SDK}/usr/local/lib/lib<name>.dylib`
5. `-L<dir>` entries in order, same four suffixes.

For frameworks (`-framework Foo`): `${SDK}/System/Library/Frameworks/Foo.framework/Foo.{tbd,dylib}`.

### 5. Platform/arch filtering
`Target { arch: Arm64, platform: MacOS }` is what armfortas cares about. If the TBD has no matching target, produce a clear diagnostic: "`<path>` does not export for arm64-macos".

## Testing Strategy
- Fixtures: copies of `${SDK}/usr/lib/libSystem.tbd`, `libc++.tbd`, `libobjc.tbd` checked into `tests/corpus/tbd/` (small, just headers of exported symbols — confirm they're not under a license that forbids redistribution; if so, generate equivalent fixtures).
- Parse `libSystem.tbd`, assert that `_dyld_stub_binder`, `_malloc`, `_free`, `_printf` are all in exports.
- Verify `DylibFile` produced is byte-level equivalent (in the fields we populate) to one produced by loading an actual `libSystem.dylib` from an older SDK.
- Malformed YAML: missing `install_name`, tabs in indentation, unterminated quoted scalar — each with a precise diagnostic.

## Definition of Done
- Can read a modern Xcode `libSystem.tbd` and enumerate its exports.
- SDK + `-l` + `-framework` resolution picks the right file on a real toolchain.
- Differential test: hello-world link with `libSystem.tbd` produces the same bind entries as with a binary dylib (on older SDKs where both exist).
