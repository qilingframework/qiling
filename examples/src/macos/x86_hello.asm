; /usr/local/bin/nasm -f macho 32.asm && ld -macmacos_version_min 10.7.0 -o 32 32.o && ./32

global start

section .text
start:
    push    dword msg.len
    push    dword msg
    push    dword 1
    mov     eax, 4
    sub     esp, 4
    int     0x80
    add     esp, 16

    push    dword 0
    mov     eax, 1
    sub     esp, 12
    int     0x80

section .data

msg:    db      "Hello, world!", 10
.len:   equ     $ - msg
