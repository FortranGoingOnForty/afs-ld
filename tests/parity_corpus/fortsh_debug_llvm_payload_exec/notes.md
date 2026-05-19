Fortsh-derived Sprint 29 size/parity regression. The full fortsh link exposed
that afs-ld preserved final-output `__DWARF` and `__LLVM` payload sections while
Apple `ld` omitted them. This focused executable keeps that behavior in the
parity corpus and also covers global symbols whose definitions live only in the
dropped payload sections.
