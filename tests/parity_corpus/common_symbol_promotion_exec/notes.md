Common-symbol promotion parity case. Two objects contribute different sizes and
alignments for `_shared`, which is referenced by both an ADRP+ADD pair and an
ADRP+load pair. The link also retains an unreferenced common and lets a strong
data definition override another tentative definition. Section contents,
symbol records, and decoded page references are compared with Apple `ld`.

tolerated:
  - region: __TEXT,__text bytes 0x0-0x3 reason: "layout-dependent ADRP immediate; page-ref checks validate the _shared ADD target"
  - region: __TEXT,__text bytes 0x8-0xb reason: "layout-dependent ADRP immediate; page-ref checks validate the _shared load target"
