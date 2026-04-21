LOH Apple-parity dylib case lifted from the Sprint 25 parity probes. This
keeps the dedicated matrix honest about the current Apple `ld` behavior for
dylib outputs too: preserve `ADRP+ADD` text and omit
`LC_LINKER_OPTIMIZATION_HINT`.
