[OS]
stacksize = 0x21000

[ARM]
stackaddress = 0xfff0d000

[MIPS]
stackaddress = 0x7ff0d000
stacksize = 0x30000
loadbse = 0x0000004fef000
interp_base = 0x00000047ba000
mmap_start = 0x774bf000

[ARM64]
stackaddress = 0x7ffffffde000

[X86]
stackaddress = 0xfffdd000

[X8664]
stackaddress = 0x7ffffffde000

[SHELLCODER]
ram_size = 0xa00000
entry_point = 0x1000000

[OS64]
EMU_END = 0xffffffffffffffff
loadbase = 0x7ffbf0100000
interp_base = 0x7ffff7dd5000
mmap_start = 0x7fffb7dd6000


[OS32]
EMU_END = 0x8fffffff
loadbase = 0x56555000
interp_base = 0xfb7d3000
mmap_start = 0xf7bd6000
