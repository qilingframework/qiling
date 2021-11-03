# riscv${bit}-unknown-elf-as hello_riscv.s -o hello_riscv.o
# riscv${bit}-unknown-elf-ld hello_riscv.o -o hello_riscv

.global _start

_start: addi  a0, x0, 1
        la    a1, helloriscv
        addi  a2, x0, 13    
        addi  a7, x0, 64    
        ecall
        addi    a0, x0, 0
        addi    a7, x0, 93
        ecall

.data
helloriscv:      .ascii "Hello RISCV!\n"
