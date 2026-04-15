# Sprint 1: MH_OBJECT Header & Load Commands

## Prerequisites
Sprint 0 — crate, harness, references in place.

## Goals
Read a Mach-O relocatable object file: parse the header and every load command afs-as emits. End state: given any `.o` in `afs-as/tests/corpus/`, afs-ld can pretty-print its structure and round-trip-compare it to a golden.

## Deliverables

### 1. Mach-O constants
`afs-ld/src/macho/constants.rs`: duplicate the constants afs-as uses. Numeric literals only, no imports from afs-as.

```rust
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
pub const CPU_TYPE_ARM64: u32 = 0x0100000C;
pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_DYSYMTAB: u32 = 0x0B;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
// ... plus LC_MAIN, LC_DYLD_INFO_ONLY, LC_DYLD_CHAINED_FIXUPS,
//         LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_CODE_SIGNATURE,
//         LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
//         LC_REEXPORT_DYLIB, LC_RPATH, LC_UUID, LC_SOURCE_VERSION.
```

### 2. Header parser
`afs-ld/src/macho/reader.rs`:

```rust
pub struct MachHeader64 {
    pub magic: u32, pub cputype: u32, pub cpusubtype: u32,
    pub filetype: u32, pub ncmds: u32, pub sizeofcmds: u32,
    pub flags: u32, pub reserved: u32,
}

pub fn parse_header(bytes: &[u8]) -> Result<MachHeader64, ReadError>;
```

Validate: magic matches MH_MAGIC_64, cputype matches CPU_TYPE_ARM64, `ncmds * 8 <= sizeofcmds`, `32 + sizeofcmds <= bytes.len()`. Clear, sourced diagnostics via `src/diag.rs`.

### 3. Load-command dispatcher
`LoadCommand` enum with variants for each command afs-as emits:

```rust
pub enum LoadCommand {
    Segment64(Segment64),
    Symtab(SymtabCmd),
    Dysymtab(DysymtabCmd),
    BuildVersion(BuildVersionCmd),
    LinkerOptimizationHint(LohCmd),
    // placeholders for later sprints:
    DyldInfoOnly, DyldChainedFixups, Main, FunctionStarts,
    DataInCode, CodeSignature, IdDylib, LoadDylib, LoadWeakDylib,
    ReexportDylib, Rpath, Uuid, SourceVersion,
    Unknown { cmd: u32, cmdsize: u32, data: Vec<u8> },
}

pub fn parse_commands(header: &MachHeader64, bytes: &[u8]) -> Result<Vec<LoadCommand>, ReadError>;
```

Exhaustive matching. Unknown commands preserved (not erased) so round-trips survive.

### 4. Segment + section header parsing (metadata only — contents in Sprint 2)
Decode `segment_command_64` (72 bytes) + N `section_64` structs (80 bytes each). Store:
- segname (fixed 16 bytes, null-padded)
- sectname (fixed 16 bytes, null-padded)
- addr, size, offset, align (as log2), reloff, nreloc, flags, reserved1, reserved2, reserved3

### 5. LC_BUILD_VERSION + LC_LINKER_OPTIMIZATION_HINT
Decode platform (PLATFORM_MACOS = 1), minos, sdk, ntools, tool records. Decode the LOH blob as raw bytes (interpretation in Sprint 25).

### 6. Pretty-printer
`afs-ld/src/bin/dump.rs` (optional subcommand `afs-ld --dump <path>`): otool-like output. Used by the round-trip harness.

## Testing Strategy
- Round-trip test: for every `.o` in `afs-as/tests/corpus/`, parse, serialize back into the same byte layout (no reshuffling in this sprint — just read+echo), compare.
- Malformed-input tests: truncated header, wrong magic, wrong cputype, `ncmds` lying about `sizeofcmds`, unaligned commands. Each must produce a specific diagnostic, never a panic.
- Differential: `otool -lV` against our dumper for the full corpus. Diff must be zero after whitespace normalization.

## Definition of Done
- All afs-as corpus `.o` files parse cleanly.
- Every load command afs-as emits is represented in `LoadCommand`.
- Malformed-input fuzz finds no panics.
- Round-trip byte-level equality on the full corpus.
- `otool -lV` and our dumper agree after whitespace normalization.
