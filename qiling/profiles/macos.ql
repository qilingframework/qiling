[LOADER]
slide          = 0x0000000000000000
dyld_slide     = 0x0000000500000000

[ARM64]
stackaddress = 0x0000000160503000
stacksize = 0x21000
vmmap_trap_address = 0x4000000f4000
mmapaddress = 0x7ffbf0100000

[X8664]
stackaddress = 0x7ffcf0000000
stacksize = 0x19a00000
vmmap_trap_address = 0x4000000f4000
mmapaddress = 0x7ffbf0100000

[SHELLCODER]
ram_size = 0xa00000
entry_point = 0x1000000

[OS64]
EMU_END = 0xffffffffffffffff

[OS32]
EMU_END = 0x8fffffff
