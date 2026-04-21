.section __TEXT,__text,regular,pure_instructions
.globl _main
_main:
    bl _write
    bl _close
    bl _read
    ret
.subsections_via_symbols
