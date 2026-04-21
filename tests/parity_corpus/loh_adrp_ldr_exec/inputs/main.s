.section __TEXT,__text,regular,pure_instructions
.globl _main
.globl _target
_main:
Lloh0:
    adrp x0, _target@PAGE
Lloh1:
    ldr x1, [x0, _target@PAGEOFF]
    mov w0, #0
    ret
    .p2align 3
_target:
    .quad 0x1122334455667788
.loh AdrpLdr Lloh0, Lloh1
.subsections_via_symbols
