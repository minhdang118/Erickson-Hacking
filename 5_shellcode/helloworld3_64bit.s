BITS 64                                 ; Tell nasm this is 64-bit code.

jmp short one                           ; Jump down to a call at the end.

two:
; ssize_t write(int fd, const void *buf, size_t count);
    pop rcx                             ; Pop the return address (string ptr) into rcx.
    xor rax, rax                        ; Zero out full 64 bits of rax register.
    mov al, 4                           ; Write syscall #4 to the low byte of rax.
    xor rbx, rbx                        ; Zero out rbx.
    inc rbx                             ; Increment rbx to 1, STDOUT file descriptor.
    xor rdx, rdx                        ; Zero out rdx.
    mov dl, 15                          ; Length of the string
    int 0x80                             ; Do syscall: write(1, string, 14)

; void _exit(int status);
    mov al, 1                           ; Exit syscall #1, the top 7 bytes are still zero.
    dec rbx                             ; Decrement rbx back down to 0 for status = 0.
    int 0x80                            ; Do syscall: exit(0)

one:
    call two                            ; Call back upwards to avoid null bytes
    db "Hello, world!", 0x0a, 0x0d      ; with newline and carriage return bytes.
    