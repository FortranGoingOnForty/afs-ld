# Sprint 22: Code Signature (Ad-Hoc)

## Prerequisites
Sprints 10, 14 — segment layout and `__LINKEDIT` finalized.

## Goals
Emit a valid ad-hoc `LC_CODE_SIGNATURE`. On macOS 11+, arm64 binaries without a signature are killed by the kernel at exec time; without this sprint every afs-ld output requires manual `codesign -s -` to run. This is existence-blocking, not optional.

## Deliverables

### 1. SuperBlob structure
`LC_CODE_SIGNATURE` points to a code-signing blob in `__LINKEDIT`:

```
struct CS_SuperBlob {
    u32 magic;           // CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
    u32 length;          // total blob size including this header
    u32 count;           // number of index entries
    // then count × CS_BlobIndex { u32 type; u32 offset; }
    // then each blob inlined at its offset
}
```

For ad-hoc: two inner blobs — the CodeDirectory and an empty Requirements set. Entitlements absent.

### 2. CodeDirectory
```
struct CS_CodeDirectory {
    u32 magic;                  // CSMAGIC_CODEDIRECTORY = 0xfade0c02
    u32 length;
    u32 version;                // 0x20400 (modern)
    u32 flags;                  // CS_ADHOC = 0x2
    u32 hashOffset;             // from this struct's start to the main hash array
    u32 identOffset;            // to the null-terminated identifier
    u32 nSpecialSlots;          // 2 (info plist + requirements); 0 when absent
    u32 nCodeSlots;             // pages × 1
    u32 codeLimit;              // file offset of end-of-signed-data
    u8  hashSize;               // 32 for SHA-256
    u8  hashType;               // CS_HASHTYPE_SHA256 = 2
    u8  platform;               // 0 for no platform binary
    u8  pageSize;               // log2(page) = 12 for 4 KiB
    u32 spare2;
    u32 scatterOffset;          // 0
    u32 teamOffset;             // 0
    u32 spare3;
    u64 codeLimit64;            // 0 unless codeLimit > 4 GiB
    u64 execSegBase;
    u64 execSegLimit;
    u64 execSegFlags;           // CS_EXECSEG_MAIN_BINARY = 0x1 for executables
}
```

After the struct:
- `identifier\0` — we use the install-name for dylibs, the output binary basename for executables.
- Special slots (filled with zeroes for ad-hoc): `nSpecialSlots` × 32 bytes of zero before the main slots.
- Main slots: one SHA-256 per 4 KiB page of signed data, followed in file order.

### 3. Signed data range
Signing covers file bytes `[0, codeLimit)`. `codeLimit` is set to `LC_CODE_SIGNATURE.dataoff` (the start of the signature blob itself). The signature never signs itself.

### 4. Page hashing
- Page size 4 KiB (not 16 KiB — code-signing pageSize is independent of VM page size).
- SHA-256 over each 4 KiB chunk; the final chunk is hashed over whatever bytes remain (not padded).
- Hashes concatenated at `hashOffset`.

### 5. Requirements blob
```
struct CS_RequirementsBlob {
    u32 magic;    // CSMAGIC_REQUIREMENTS = 0xfade0c01
    u32 length;   // 12
    u32 count;    // 0
}
```

Minimum legal empty requirements.

### 6. SHA-256 implementation
Hand-rolled. Standard 64-round SHA-256 from FIPS 180-4. ~200 LoC in Rust. Unit-tested against known vectors (empty string, "abc", "a"×1M, NIST test vectors).

### 7. Layout recomputation
The signature blob size depends on `codeLimit`, which depends on its own file offset. Two-pass approach:

1. Compute layout excluding signature; know exactly the signature's start offset.
2. Compute signature size = SuperBlob header + indices + CodeDirectory header + ident + special slots + (ceil(codeLimit / 4096) × 32 bytes hash) + Requirements blob.
3. Reserve that many bytes at the signature offset.
4. Write all other data.
5. Hash pages and write signature in place.

### 8. Platform binary opt-out
Ad-hoc signatures from third-party tools are not platform binaries; `platform = 0`, `flags = CS_ADHOC`.

### 9. Validation
After writing, validate with `codesign -v <binary>`. Expected: zero output, exit 0.

## Testing Strategy
- Sign hello-world, then `./hello` (no manual `codesign` step). Expect "Hello, World!".
- `codesign -dv <binary>` reports `Signature=adhoc`.
- SHA-256 unit tests against NIST vectors.
- Mutate a single byte in the binary post-sign, re-run, expect kernel kill ("Killed: 9") — proves the signature is real and the kernel is checking it.
- Dylib ad-hoc sign: `dlopen` of `libfoo.dylib` from Sprint 18.5 still works.

## Definition of Done
- `./hello` runs directly (no `codesign -s -` needed).
- `codesign -v` clean on every afs-ld output.
- Dylib loading via `dlopen` works on Sprint 18.5 fixtures.
- SHA-256 passes NIST test vectors.
- Tampering detected by the kernel (confidence check).
