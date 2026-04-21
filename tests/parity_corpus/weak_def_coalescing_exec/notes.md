Weak-definition coalescing parity case. The executable links two dylibs that
both export the same weak definition, and the final image plus runtime
resolution should follow the same winner Apple `ld` chooses.
