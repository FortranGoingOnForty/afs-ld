LOH Apple-parity executable case lifted from the Sprint 25 parity probes.
This keeps the dedicated matrix honest about the current Apple `ld` behavior:
preserve `ADRP+LDR` text and omit `LC_LINKER_OPTIMIZATION_HINT` from the final
binary.
