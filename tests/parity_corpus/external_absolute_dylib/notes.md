External absolute-symbol parity case. Separate objects define two fixed symbols,
and a third object references both. Data bytes, symbol records, exports, and
partitions are compared with Apple `ld` under dead stripping.

Apple `ld` rejects a cross-object indirect alias whose target is absolute, so
this differential fixture defines both values directly. The afs-ld-only
`linker_run_emits_aliases_to_absolute_symbols` regression retains coverage for
the supported cross-object alias form.
