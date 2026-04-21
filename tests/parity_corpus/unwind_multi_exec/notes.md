Multi-function unwind-info parity case lifted from the existing Apple `ld`
probe. This keeps the Sprint 27 corpus honest about rebased `__unwind_info`
bytes when more than one function contributes unwind metadata.
