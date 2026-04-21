Mixed text-plus-const dylib export parity case lifted from the existing
`linker_run` export matrix. This expands the Sprint 27 corpus to cover export
surfaces where one exported symbol lives in `__TEXT,__const` rather than only
code, initialized data, or BSS.
