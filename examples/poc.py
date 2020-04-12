from unicorn import *
from unicorn.mips_const import *

code_addr = 0x1000
code_len = 0x1000

code = '''
    nop
	nop
	nop
	nop
    li $v0, 1
    bnez    $v0, loc_4007D8
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
loc_4007D8:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
'''
code = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02$\x0b\x00@\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
code_len = len(code)
def hook(uc, addr, size, data):
    print(hex(addr))

print("--------------round 1-----------------")

uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

uc.mem_map(code_addr, 0x1000)
uc.mem_write(code_addr, code)

uc.hook_add(UC_HOOK_CODE, hook)

uc.emu_start(code_addr, code_addr + code_len)

print("--------------round 2-----------------")

uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

uc.mem_map(code_addr, 0x1000)
uc.mem_write(code_addr, code)

uc.hook_add(UC_HOOK_CODE, hook)

uc.emu_start(code_addr, code_addr + code_len, count = 6)
print("-------restore and run----------")

old_regs = uc.context_save()
uc.context_restore(old_regs)
pc = uc.reg_read(UC_MIPS_REG_PC)
uc.emu_start(pc, code_addr + code_len)


