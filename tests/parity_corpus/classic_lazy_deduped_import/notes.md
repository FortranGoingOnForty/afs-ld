Classic lazy-binding dedupe parity case lifted from the existing `linker_run`
matrix. This strengthens the Sprint 27 corpus around repeated imports of the
same symbol, while still comparing the Apple-parity dyld-info streams and stub
surfaces instead of only command IDs.
