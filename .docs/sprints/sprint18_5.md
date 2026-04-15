# Sprint 18.5: HELLO LIBRARY MILESTONE (Dylib)

## Prerequisites
Sprint 18 — executable path works end-to-end.

## Goals
Validate `MH_DYLIB` output end-to-end. afs-ld emits a dylib that `dlopen`/`dlsym` can load and a minimal C or Fortran harness can call into. Proves that every dylib-specific decision in Sprints 10–17 is actually correct.

## Deliverables

### 1. Staging fixture
`tests/corpus/hello_library/`:
- `foo.f90`: module exporting a single `foo_add(a, b) -> c` interoperable procedure.
- `foo.o`: assembled object.
- `caller.c`: `int main() { void *h = dlopen("./libfoo.dylib", RTLD_NOW); int (*f)(int,int) = dlsym(h, "foo_add"); printf("%d\n", f(2, 3)); }`.
- Expected runtime output: `5`.

### 2. Dylib link invocation
```
afs-ld -dylib foo.o libarmfortas_rt.a \
  -lSystem -syslibroot "$(xcrun --show-sdk-path)" \
  -install_name @rpath/libfoo.dylib \
  -compatibility_version 1.0 -current_version 1.0.0 \
  -no_uuid -platform_version macos 11.0 14.0 \
  -o libfoo.dylib
```

### 3. Validation checklist
- `file libfoo.dylib` → `Mach-O 64-bit dynamically linked shared library arm64`.
- `otool -lV libfoo.dylib` shows `LC_ID_DYLIB` with install-name `@rpath/libfoo.dylib`, `current_version = 1.0.0`, `compat_version = 1.0.0`. No `__PAGEZERO`, no `LC_MAIN`.
- Export trie contains `_foo_add` (Fortran name-mangled per armfortas convention, or `bind(C)` if used).
- `dlopen("./libfoo.dylib", RTLD_NOW)` returns non-null.
- `dlsym(h, "foo_add")` returns the function address.
- Calling `foo_add(2, 3)` returns `5`.

### 4. Differential
Link the same inputs with `ld -dylib` and afs-ld. Compare load commands, export trie contents, indirect symbol table. Tolerated diffs same as Sprint 18.

### 5. `-rpath` interaction
`caller` is linked against `libfoo.dylib` with `@rpath` indirection. Sprint 19 will wire the full `-rpath` CLI; this sprint validates that an install-name of `@rpath/...` is correctly emitted and that the binary's `DYLD_PRINT_LIBRARIES=1` output shows dyld resolving `@rpath` via the `LC_RPATH` entries of the caller.

### 6. `dladdr`/`backtrace` in the dylib
When `foo_add` calls into `libarmfortas_rt`, `backtrace_symbols()` should return readable names — proves the symbol table partitioning for a dylib is correct and the Sprint 17 unwind info is wired into dyld's unwinder.

## Testing Strategy
- `tests/hello_library.rs`: builds and `dlopen`s the dylib, calls `foo_add`, asserts the return.
- `tests/hello_library_nm.rs`: runs `nm -D` on the dylib, asserts `_foo_add` appears as external.
- Differential harness with `ld -dylib` on the same inputs.

## Definition of Done
- `libfoo.dylib` loads via `dlopen` and exports `_foo_add`.
- Calling the exported function returns the expected value.
- Differential parity with `ld` on the staging fixture.
- `otool -lV` shows correct dylib-specific load commands with no `__PAGEZERO` or `LC_MAIN`.
- Post-sprint audit passes.
