.section __TEXT,__text,regular,pure_instructions
.globl _loh_probe
.globl _target
_loh_probe:
Lloh0:
    adrp x0, _target@PAGE
Lloh1:
    add x0, x0, _target@PAGEOFF
    ret
_target:
    ret
.loh AdrpAdd Lloh0, Lloh1
.subsections_via_symbols
