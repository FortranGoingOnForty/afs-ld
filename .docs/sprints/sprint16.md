# Sprint 16: LC_FUNCTION_STARTS & LC_DATA_IN_CODE

## Prerequisites
Sprint 14 — `__LINKEDIT` layout sequencing; Sprint 11 — atoms placed.

## Goals
Emit the two small `__LINKEDIT` blobs used by debuggers, disassemblers, and the dynamic loader: `LC_FUNCTION_STARTS` (delta-encoded entry points) and `LC_DATA_IN_CODE` (markers for data embedded in `__text`).

## Deliverables

### 1. LC_FUNCTION_STARTS

Format: a single stream of ULEB128 deltas. First ULEB = offset from the Mach-O header to the first function entry. Each subsequent ULEB = delta from the previous entry. A terminating `0` ends the stream. 8-byte aligned.

Source: every atom in `__TEXT,__text` plus `.alt_entry` chain members. Exclude atoms from `__stubs` and `__stub_helper` — ld doesn't list those.

### 2. LC_DATA_IN_CODE

Format: a packed array of:
```
struct data_in_code_entry {
    uint32 offset;    // from Mach-O header
    uint16 length;    // bytes
    uint16 kind;      // DICE_KIND_DATA=1, _JUMP_TABLE8=2, _JUMP_TABLE16=3,
                      //           _JUMP_TABLE32=4, _ABS_JUMP_TABLE32=5
}
```

Source: per-input `LC_DATA_IN_CODE` blocks. Remap each entry's offset from its input-section base to the final output VM address. Entries sorted by offset.

afs-as doesn't emit jump tables today, but we preserve whatever the input has so future C/Objective-C objects with jump tables survive linking.

### 3. Sorting determinism

Function starts: strictly ascending by VM address. Data-in-code: strictly ascending by output offset. Ties resolved by input command-line order.

### 4. Integration with `__LINKEDIT` layout (Sprint 14)

Both blobs get file offsets assigned after chained fixups / classic dyld-info but before the symbol table. Pointed at by their respective load commands with `dataoff / datasize`.

## Testing Strategy

- Differential: function starts list byte-identical between afs-ld and `ld` on every staging fixture.
- Data-in-code: fixture with a jump table input; entries survive linking with correct remapped offsets.
- Empty output: fixtures with no functions produce zero-byte LC_FUNCTION_STARTS (actually: ld still emits a terminator? check) and absent LC_DATA_IN_CODE when no input had data-in-code.

## Definition of Done

- LC_FUNCTION_STARTS parity with `ld` on every staging fixture.
- LC_DATA_IN_CODE entries remapped correctly across linking.
- Both blobs placed in the right `__LINKEDIT` slot per Sprint 14.
