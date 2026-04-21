.text
.globl _main
.p2align 2
_main:
    ret

.section __TEXT,__text2,regular,pure_instructions
.globl _helper
.p2align 2
_helper:
    b Ldispatch
    .p2align 2
Ltable:
    .data_region jt32
    .long Lcase0-Ltable
    .long Lcase1-Ltable
    .end_data_region
Ldispatch:
    ret
Lcase0:
    ret
Lcase1:
    ret
.subsections_via_symbols
