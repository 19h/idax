// Minimal AArch64 Linux fixture for IDA register-value tracking tests.

.text
.global _start
.type _start, %function
_start:
    mov x29, #0
    mov x0, #0x1234
    movk x0, #0xabcd, lsl #32
    sub sp, sp, #32
    add x1, sp, #16
    bl target
    add sp, sp, #32
    mov x8, #93
    svc #0

.type target, %function
target:
    add x0, x0, #1
    ret

.global multi_value
.type multi_value, %function
multi_value:
    cbz x3, multi_left
    mov x2, #0x11
    b multi_join
multi_left:
    mov x2, #0x22
.global multi_join
multi_join:
    add x4, x2, #0
    ret
