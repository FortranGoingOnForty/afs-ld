        .section __TEXT,__text,regular,pure_instructions
        .globl _touch
        _touch:
            ret
        .zerofill __DATA,__bss,_global_bss,16,3
        .subsections_via_symbols
