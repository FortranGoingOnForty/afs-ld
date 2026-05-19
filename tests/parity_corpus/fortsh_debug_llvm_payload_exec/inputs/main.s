        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .p2align 2
_main:
        mov w0, #0
        ret

        .section __DWARF,__debug_info,regular,debug
        .globl _fortsh_debug_payload
_fortsh_debug_payload:
        .byte 0x46, 0x53, 0x48, 0x44

        .section __LLVM,__bitcode
        .globl _fortsh_bitcode_payload
_fortsh_bitcode_payload:
        .byte 0x46, 0x53, 0x48, 0x42

        .subsections_via_symbols
