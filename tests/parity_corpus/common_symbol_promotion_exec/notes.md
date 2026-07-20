Common-symbol promotion parity case. Two objects contribute different sizes and
alignments for `_shared`, which is referenced by both an ADRP+ADD pair and an
ADRP+load pair. The link also retains an unreferenced common and lets a strong
data definition override another tentative definition. Section contents,
symbol records, and decoded page references are compared with Apple `ld`.
