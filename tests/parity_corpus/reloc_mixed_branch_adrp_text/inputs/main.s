        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .globl _helper
        _main:
            adrp x0, _target@PAGE
            add x0, x0, _target@PAGEOFF
            bl _helper
            ret
        _helper:
            ret
        .space 0xff0
        _target:
            .quad 0x99
        .subsections_via_symbols
