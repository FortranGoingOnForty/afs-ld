        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .globl _main
        _main:
            bl _helper
            ret
        .section __TEXT,__const
        .p2align 3
        _delta:
            .quad _helper - _main
        .subsections_via_symbols
