.text
.globl _main
.p2align 2
_main:
    mov w0, #0
    b Ldispatch
    .p2align 2
Ltable:
    .data_region jt32
    .long Lcase0-Ltable
    .long Lcase1-Ltable
    .end_data_region
Ldispatch:
    cmp w0, #0
    b.eq Lcase0
    b Lcase1
Lcase0:
    mov w0, #1
    ret
Lcase1:
    mov w0, #2
    ret
.subsections_via_symbols
