#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import sys

from unicorn import *
from unicorn.mips_const import *

from capstone import *
from capstone.mips_const import *

from keystone import *
from keystone.mips_const import *

from struct import pack
import os

import string

from qiling.loader.elf import *
from qiling.os.linux.mips32el_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *
from qiling.arch.filetype import *

# memory address where emulation starts
QL_MIPSEL_LINUX_PREDEFINE_STACKADDRESS = 0x7ff0d000
QL_MIPSEL_LINUX_PREDEFINE_STACKSIZE = 0x30000

QL_SHELLCODE_ADDR = 0x0f000000
QL_SHELLCODE_LEN = 0x1000
QL_SHELLCODE_INIT = 0

QL_MIPSEL_EMU_END = 0x8fffffff

linux_syscall_numb_list = []
linux_syscall_func_list = []

def init_syscall_table(ql):
    for i in MIPS32EL_LINUX_SYSCALL:
        linux_syscall_numb_list.append(i[0])
        linux_syscall_func_list.append(i[1])

def hook_syscall(ql, intno):
    syscall_num = ql.uc.reg_read(UC_MIPS_REG_V0)
    param0 = ql.uc.reg_read(UC_MIPS_REG_A0)
    param1 = ql.uc.reg_read(UC_MIPS_REG_A1)
    param2 = ql.uc.reg_read(UC_MIPS_REG_A2)
    param3 = ql.uc.reg_read(UC_MIPS_REG_A3)
    param4 = ql.uc.reg_read(UC_MIPS_REG_SP)
    param4 = param4 + 0x10
    param5 = ql.uc.reg_read(UC_MIPS_REG_SP)
    param5 = param5 + 0x14
    pc = ql.uc.reg_read(UC_MIPS_REG_PC)

    if intno != 0x11:
        raise QlErrorExecutionStop("[!] got interrupt 0x%x ???" %intno)

    if any(linux_syscall_numb == syscall_num for linux_syscall_numb in ql.posix_syscall_numb_list):
        linux_syscall_index = ql.posix_syscall_numb_list.index(syscall_num)
        LINUX_SYSCALL_FUNC_NAME = ql.posix_syscall_func_list[linux_syscall_index].__name__
        LINUX_SYSCALL_FUNC = ql.posix_syscall_func_list[linux_syscall_index]
    elif any(linux_syscall_numb == syscall_num for linux_syscall_numb in linux_syscall_numb_list):
        linux_syscall_index = linux_syscall_numb_list.index(syscall_num)
        LINUX_SYSCALL_FUNC_NAME = linux_syscall_func_list[linux_syscall_index]
        LINUX_SYSCALL_FUNC = eval(linux_syscall_func_list[linux_syscall_index])
    else:
        LINUX_SYSCALL_FUNC_NAME = None
        LINUX_SYSCALL_FUNC = None

    if LINUX_SYSCALL_FUNC != None:
        try:
            LINUX_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            ql.nprint("[!] SYSCALL: ", LINUX_SYSCALL_FUNC_NAME)
            ql.nprint("[-] ERROR: %s" % (e))
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                if ql.debug_stop:
                    ql.nprint("[-] Stopped due to ql.debug_stop is True")
                    raise QlErrorSyscallError("[!] Syscall Implenetation Error")
    else:
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num,  syscall_num))
        if ql.debug_stop:
            ql.nprint("[-] Stopped due to ql.debug_stop is True")
            ql.uc.emu_stop()

def hook_shellcode(uc, addr, shellcode, ql):
    '''
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
	nop
	nop
	nop

	sw $ra, -8($sp)
	sw $a0, -12($sp)
	sw $a1, -16($sp)
	sw $a2, -20($sp)
	sw $a3, -24($sp)
	sw $v0, -28($sp)
	sw $v1, -32($sp)
	sw $t0, -36($sp)

	slti $a2, $zero, -1
lab1:
	bltzal $a2, lab1

	addu $a1, $ra, 140
	addu $t0, $ra, 60
	lw $a0, -4($sp)
	li $a2, 8
	jal $t0
	nop

	lw $ra, -8($sp)
	lw $a0, -12($sp)
	lw $a1, -16($sp)
	lw $a2, -20($sp)
	lw $a3, -24($sp)
	lw $v0, -28($sp)
	lw $v1, -32($sp)
	lw $t0, -36($sp)
	j 0
	nop


 my_mem_cpy:
	move    $a3, $zero
	move    $a3, $zero
	b       loc_400804
	nop

 loc_4007D8:
	move    $v0, $a3
	move    $v1, $a1
	addu    $v1, $v0
	move    $v0, $a3
	addu    $v0, $a0, $v0
	lb      $v1, 0($v1)
	sb      $v1, 0($v0)
	addiu   $a3, 1

 loc_400804:
	move    $v0, $a3
	move    $v1, $a2
	sltu    $v0, $v1
	bnez    $v0, loc_4007D8
	nop
	nop
	jr      $ra
	nop

 store_code:
	nop
    '''
    global QL_SHELLCODE_INIT
    if QL_SHELLCODE_INIT == 0:
        uc.mem_map(QL_SHELLCODE_ADDR, QL_SHELLCODE_LEN)
        QL_SHELLCODE_INIT = 1

    store_code = uc.mem_read(addr, 8)
    sc = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\xff\xbf\xaf\xf4\xff\xa4\xaf\xf0\xff\xa5\xaf\xec\xff\xa6\xaf\xe8\xff\xa7\xaf\xe4\xff\xa2\xaf\xe0\xff\xa3\xaf\xdc\xff\xa8\xaf\xff\xff\x06(\xff\xff\xd0\x04\x8c\x00\xe5'<\x00\xe8'\xfc\xff\xa4\x8f\x08\x00\x06$\t\xf8\x00\x01\x00\x00\x00\x00\xf8\xff\xbf\x8f\xf4\xff\xa4\x8f\xf0\xff\xa5\x8f\xec\xff\xa6\x8f\xe8\xff\xa7\x8f\xe4\xff\xa2\x8f\xe0\xff\xa3\x8f\xdc\xff\xa8\x8f\x00\x00\x00\x08\x00\x00\x00\x00%8\x00\x00%8\x00\x00\t\x00\x00\x10\x00\x00\x00\x00%\x10\xe0\x00%\x18\xa0\x00!\x18b\x00%\x10\xe0\x00!\x10\x82\x00\x00\x00c\x80\x00\x00C\xa0\x01\x00\xe7$%\x10\xe0\x00%\x18\xc0\x00+\x10C\x00\xf4\xff@\x14\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xe0\x03\x00\x00\x00\x00".replace(b'\x00\x00\x00\x08', ql.pack32(0x08000000 ^ (addr // 4)), 1)
    sc = shellcode + sc[len(shellcode) :] + store_code

    uc.mem_write(QL_SHELLCODE_ADDR, sc)
    uc.mem_write(addr, b'\x00\x00\xc0\x0b\x00\x00\x00\x00')
    sp = uc.reg_read(UC_MIPS_REG_SP)
    uc.mem_write(sp - 4, ql.pack32(addr))


def ql_syscall_mips32el_set_thread_area(ql, sta_area, null0, null1, null2, null3, null4):
    ql.nprint ("set_thread_area(0x%x)" % sta_area)
    uc = ql.uc 
    pc = uc.reg_read(UC_MIPS_REG_PC)
    CONFIG3_ULR = (1 << 13)
    uc.reg_write(UC_MIPS_REG_CP0_CONFIG3, CONFIG3_ULR)
    uc.reg_write(UC_MIPS_REG_CP0_USERLOCAL, sta_area)
    hook_shellcode(uc, pc + 4, bytes.fromhex('2510000025380000'), ql)


def loader_file(ql):
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_MIPSEL_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_MIPSEL_LINUX_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv, env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))
    

def loader_shellcode(ql):
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x200000 - 0x1000
    ql.uc.mem_write(ql.stack_address, ql.shellcoder) 


def runner(ql):
    ql.uc.reg_write(UC_MIPS_REG_SP, ql.new_stack)
    ql_setup(ql)
    init_syscall_table(ql)
    ql.hook_intr(hook_syscall)
    if (ql.until_addr == 0):
        ql.until_addr = QL_MIPSEL_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError as e:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop('[!] Emulation Stopped')

    if ql.internal_exception != None:
        raise ql.internal_exception
