        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            add x0, x0, _target@PAGEOFF
            ret
        .space 0x4ff4
        _target:
            .quad 0
        .subsections_via_symbols
