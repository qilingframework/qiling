.data
mystring:       .asciiz "Hello World!\n"
.text
        .global __start
__start:
        li      $a0,    0
        la      $a1,    mystring
        li      $a2,    13
        li      $v0,    4004
        syscall
        li      $a0,    3
        li      $v0,    4001
        syscall

# as hello_mips32.s -o hello_mips32.o
# ld hello_mips32.o -o hello_mips32
