.section __TEXT,__text,regular,pure_instructions
.globl _main
.globl _target
_main:
Lloh0:
    adrp x0, _target@PAGE
Lloh1:
    add x0, x0, _target@PAGEOFF
    mov w0, #0
    ret
_target:
    ret
.loh AdrpAdd Lloh0, Lloh1
.subsections_via_symbols
