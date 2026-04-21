        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            ret
        _helper:
            ret
        .subsections_via_symbols
