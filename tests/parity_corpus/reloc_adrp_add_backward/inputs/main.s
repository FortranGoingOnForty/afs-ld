        .section __TEXT,__text,regular,pure_instructions
        _target:
            .quad 0x55
        .space 0x4ff8
        .globl _main
        _main:
            adrp x0, _target@PAGE
            add x0, x0, _target@PAGEOFF
            ret
        .subsections_via_symbols
