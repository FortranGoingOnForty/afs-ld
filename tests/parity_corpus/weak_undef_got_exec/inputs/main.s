.text
.globl _main
.p2align 2
_main:
    adrp x8, _afs_ld_intentionally_missing_weak_4f6f0f3b@GOTPAGE
    ldr x8, [x8, _afs_ld_intentionally_missing_weak_4f6f0f3b@GOTPAGEOFF]
    cmp x8, #0
    cset w0, ne
    ret
.weak_reference _afs_ld_intentionally_missing_weak_4f6f0f3b
.subsections_via_symbols
