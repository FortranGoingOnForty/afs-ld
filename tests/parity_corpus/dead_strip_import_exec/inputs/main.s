.section __TEXT,__text,regular,pure_instructions
.globl _main
_main:
    mov w0, #0
    ret

.globl _unused
_unused:
    bl _puts
    mov w0, #0
    ret
.subsections_via_symbols
