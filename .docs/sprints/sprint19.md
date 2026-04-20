# Sprint 19: CLI Surface + Diagnostics (`-map`, `-why_live`)

## Prerequisites
Sprints 18–18.5 — executable and dylib milestones reached.

## Goals
Full `ld`-compatible CLI surface for the flags armfortas already uses and those fortsh is likely to invoke. Includes the two diagnostics surfaces we declared launch-blocking: `-map` (text link map) and `-why_live` (dead-strip reason chain). No polish-tier deferral.

## Deliverables

### 1. Full flag list
Recognized:

**Inputs/outputs**:
- `-o <path>`
- positional `<input>`
- `-l<name>` / `-l <name>`
- `-L <dir>`
- `-framework <name>`
- `-weak_framework <name>`
- `-force_load <archive>`
- `-all_load`
- `-ObjC` (skippable no-op unless inputs have ObjC — they won't from armfortas today)

**Target & platform**:
- `-arch arm64`
- `-syslibroot <path>`
- `-platform_version macos <min> <sdk>`

**Output kind**:
- (default) executable
- `-dylib`
- `-r` (relocatable — deferred; errors for now)
- `-bundle` (deferred; errors for now)

**Entry & startup**:
- `-e <symbol>` (default `_main` for executables)

**Runtime search paths**:
- `-rpath <path>`
- `-install_name <path>` (dylib only)
- `-compatibility_version <v>` (dylib only)
- `-current_version <v>` (dylib only)

**Symbol handling**:
- `-undefined <error|warning|suppress|dynamic_lookup>` (default: error)
- `-exported_symbols_list <file>`
- `-unexported_symbols_list <file>`
- `-exported_symbol <sym>`
- `-unexported_symbol <sym>`
- `-x` (strip locals)
- `-S` (strip debug)

**Layout & output metadata**:
- `-no_uuid`
- `-dead_strip` (gates Sprint 23 pass)
- `-icf=safe` / `-icf=none` (gates Sprint 24 pass)
- `-fixup_chains` / `-no_fixup_chains`

**Diagnostics**:
- `-map <path>`: emit text link map
- `-why_live <symbol>`: print dead-strip reason chain
- `-t` / `-trace`: print input file paths as they are loaded
- `-v` / `--version`
- `-h` / `--help`

**Passthrough / compat**:
- `-Wl,<comma-separated>`: normalize into separate flags.
- Unknown flags: error with suggestion (Levenshtein-3 over the list above).

### 2. `-map <path>` output format
Text file mirroring ld's link map:
```
# Path: <output path>
# Arch: arm64
# Object files:
[  0] linker synthesized
[  1] hello.o
[  2] libarmfortas_rt.a(runtime.o)
...

# Sections:
# Address          Size         Segment   Section
0x100003f9c        0x00000018   __TEXT    __text
0x100003fb4        0x00000024   __TEXT    __stubs
...

# Symbols:
# Address          Size         File    Name
0x100003f9c        0x00000014   [  1]   _main
0x100003fb0        0x00000004   [  1]   .alt_entry_of_main
0x100003fb4        0x0000000c   linker  _printf (stub)
...

# Dead stripped:
<file>               <symbol>
[  2]                _unused_helper
```

### 3. `-why_live <symbol>` output
Walks the live-edge graph from Sprint 23 backward from the named symbol to a root:
```
_main is live because:
  _main is in -e _main (GC root)

_afs_write_char is live because:
  _afs_write_char is reachable from _afs_print
  _afs_print is reachable from _main
  _main is in -e _main (GC root)
```

When used before `-dead_strip` has been applied, the diagnostic explains that `-dead_strip` was not requested. Multiple `-why_live` names allowed.

### 4. Exported / unexported symbols files
Each line of the file is a symbol name. Wildcards: `*` matches any chars, `?` matches one. Used to adjust the final export trie and to mark symbols `N_PEXT` when `-unexported_symbol` is set. Consumed by Sprint 14's symbol-table construction (which this sprint amends).

### 5. CLI parser
`afs-ld/src/args.rs`:
- Hand-rolled, no clap.
- Streaming argv scan.
- Error messages cite the flag, the invalid value, and the expected format.
- `-Wl,-map,foo.txt` normalized to `-map foo.txt` before dispatch.

### 6. `-t` trace output
As each input file is loaded:
```
afs-ld: loading hello.o
afs-ld: loading libarmfortas_rt.a
afs-ld: loading libarmfortas_rt.a(io.o)
afs-ld: loading /usr/lib/libSystem.tbd
```

## Testing Strategy
- One test per flag: parse the flag, assert `LinkOptions` field set correctly.
- Error-message snapshot tests for every invalid-flag case.
- `-map` differential: produce a map, compare shape (not exact byte) to `ld`'s map on hello-world.
- `-why_live _main` produces a root-only explanation.
- `-why_live <transitively-reachable-sym>` produces a chain.
- `-Wl,-map,foo.txt` parsed identically to `-map foo.txt`.

## Definition of Done
- Every flag listed above parses and wires correctly.
- `-map` produces human-readable output covering object files, sections, symbols, dead-stripped entries.
- `-why_live` produces a coherent chain on fixtures with dead-strip enabled.
- Unknown-flag errors include a did-you-mean suggestion.
- CLI surface passes a snapshot test against the `--help` output.

## Remaining Flag Slices
- [x] `-Wl,<comma-separated>` normalization
- [x] `-map <path>`
- [x] `-t` / `-trace`
- [x] `-v` / `--version`
- [x] `-h` / `--help`
- [x] `-why_live <symbol>`
